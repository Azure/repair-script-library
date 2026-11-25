#########################################################################################################
#
# .SYNOPSIS
#   Repairs the MANA (Microsoft Azure Network Adapter) driver on an offline Windows OS disk. v1.0.0
#
# .DESCRIPTION
#   Runs on a repair VM against the source VM's OS disk attached as a data disk, and fixes the MANA driver
#   problems win-detect-mana-readiness reports:
#
#     mana-driver-missing             No MANA driver package is in the offline driver store. Repair adds the
#                                     repair VM's own MANA driver packages to the offline image with DISM's
#                                     offline servicing (Add-WindowsDriver -Path), which keeps the package's
#                                     signature check and does not touch the running repair VM.
#     mana-device-not-bound:<device>  Windows has already seen this MANA device but has no driver for it, so
#                                     Plug and Play treats it as configured and would never install a driver
#                                     staged later. Repair sets CONFIGFLAG_REINSTALL on the device instance so
#                                     the staged driver is installed at the next boot.
#     mana-driver-disabled:<service>  A MANA driver service has Start=4 (disabled). Repair sets it back to 3
#                                     (demand start, the value the MANA packages install).
#     mana-driver-binary-missing:<s>  Repaired when a staged package provides the service: the devices bound to
#                                     it are flagged for reinstall, which copies the binary back.
#     mana-device-no-driver:<device>  A seen MANA device that no staged package supports. Repaired only when a
#                                     package this run adds lists the device's hardware ID.
#     mana-bus-driver-missing         Some MANA packages are staged but not the VF bus driver, or not the Net-class
#     mana-ethernet-driver-missing    Ethernet driver. Repair adds the repair VM's package that provides it.
#     mana-driver-service-missing:<s> A seen MANA device is still bound to a service whose key was deleted. Repaired
#                                     when a staged package provides the service, by reinstalling the device.
#
#   Packages are added first, then the disk is reassessed and the registry changes are planned from what is
#   actually staged: service names come from the INF files, and DISM can refuse a package (for example on a guest
#   whose drivers were removed with pnputil /uninstall, which can leave a device bound to the removed copy). A
#   refused package is recorded and reported; the repair completes only if the reassessment finds no MANA
#   problem left, and otherwise stops before any registry change with a Rollback command for the packages.
#
#   Mode=Report (default) makes no changes and prints the plan. Mode=Repair applies it, writes a rollback
#   manifest and a .reg export of every key it changes, and verifies the result by reassessing the disk.
#   Mode=Rollback undoes a Repair using its manifest. The manifest records the control set Repair changed, and
#   Rollback restores that exact control set. It accepts only the changes Repair can make: Start 4 -> 3 on a MANA
#   service and the reinstall bit on a MANA device, both verified against the attached disk.
#
#   Problems with the synthetic network driver (netvsc) mean the VM has no network at all; they are reported
#   but never changed by this script. An installation that cannot be fully read, an architecture mismatch, a
#   build older than Windows Server 2016, or a repair VM without MANA drivers make Repair refuse before any
#   change.
#
#   Emits one machine-readable JSON line prefixed with [MANA-REPAIR-JSON].
#
# .PARAMETER Mode
#   Report (default), Repair, or Rollback.
#
# .PARAMETER OsDriveLetter
#   Optional drive letter selecting one offline Windows installation, for example F or F:.
#
# .PARAMETER BackupFile
#   Full path to the rollback manifest (mana-repair-manifest.json) written by Repair. Required for Rollback.
#
# .NOTES
#   Requires the --run-on-repair option. Driver service names come from the MANA packages' INF files.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n problemVM --run-id win-fix-mana-driver --run-on-repair --parameters Mode=Repair
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('Report', 'Repair', 'Rollback')][string]$Mode = 'Report',
    [Parameter(Mandatory = $false)][ValidatePattern('^[A-Za-z]:?$')][string]$OsDriveLetter = '',
    [Parameter(Mandatory = $false)][string]$BackupFile = ''
)

. .\src\windows\common\setup\init.ps1

$scriptName = 'win-fix-mana-driver'
$manifestSchema = 'win-fix-mana-driver/1'

# SERVICE_DEMAND_START, the start type the MANA packages install. SERVICE_DISABLED is 4.
$demandStart = 3
$serviceDisabled = 4
# CONFIGFLAG_REINSTALL: Plug and Play installs the device again at the next boot.
$reinstallFlag = 0x20
# Windows Server 2016. Older builds have no MANA driver support.
$minimumBuild = 14393
$servicePattern = '^[A-Za-z0-9_.-]{1,64}$'
$devicePattern = '^(PCI|MANA_BUS)\\[A-Za-z0-9&_.-]{1,200}\\[A-Za-z0-9&_.-]{1,200}$'
$registryKeyPattern = '^(Services\\[A-Za-z0-9_.-]{1,64}|Enum\\(PCI|MANA_BUS)\\[A-Za-z0-9&_.-]{1,200}\\[A-Za-z0-9&_.-]{1,200})$'
$publishedDriverPattern = '^oem\d+\.inf$'
$controlSetPattern = '^ControlSet\d{3}$'

function Get-ManaRepairPlan {
    # Turns an assessment into the actions Repair would take, the reasons it must refuse, and problems this
    # script deliberately leaves alone. Pure: reads nothing and changes nothing.
    Param(
        [Parameter(Mandatory = $true)]$Assessment,
        [AllowEmptyCollection()][object[]]$RepairVmPackages = @(),
        [string]$RepairVmArchitecture
    )

    $actions = @()
    $blockers = @()
    $outOfScope = @()
    $devices = @($Assessment.manaDevices | Where-Object { $_ })
    $flagged = @{}
    $deviceActions = [System.Collections.Generic.List[object]]::new()
    $addFlag = {
        Param($device)
        if ($flagged.ContainsKey($device.path)) { return }
        $flagged[$device.path] = $true
        $deviceActions.Add([pscustomobject]@{ type = 'ReinstallDevice'; device = $device.path; from = [int]$device.configFlags; to = ([int]$device.configFlags -bor $reinstallFlag) })
    }

    ForEach ($unknown in @($Assessment.unknowns)) { $blockers += "assessment-incomplete:$unknown" }

    $problems = @($Assessment.problems)
    $incomingPackages = @()
    $missingProblems = @($problems | Where-Object { $_ -in 'mana-driver-missing', 'mana-bus-driver-missing', 'mana-ethernet-driver-missing' })
    if ($missingProblems.Count) {
        $packages = @($RepairVmPackages)
        if ($packages.Count -and $missingProblems -notcontains 'mana-driver-missing') {
            # A partially populated store: add only the repair VM packages that provide the missing function.
            $ids = Get-ManaFunctionId
            $needed = @()
            if ($missingProblems -contains 'mana-bus-driver-missing') {
                $bus = @($packages | Where-Object { Test-ManaPackageCoverage -Packages @($_) -Id $ids.vfBus })
                if ($bus.Count) { $needed += $bus } else { $blockers += 'repair-vm-has-no-mana-driver:mana-bus-driver-missing' }
            }
            if ($missingProblems -contains 'mana-ethernet-driver-missing') {
                $net = @($packages | Where-Object { Test-ManaPackageCoverage -Packages @($_) -Id $ids.ethernet -Class 'Net' })
                if ($net.Count) { $needed += $net } else { $blockers += 'repair-vm-has-no-mana-driver:mana-ethernet-driver-missing' }
            }
            $seen = @{}
            $packages = @($needed | Where-Object { -not $seen.ContainsKey($_.package) -and ($seen[$_.package] = $true) })
        }
        $build = 0
        if (@($RepairVmPackages).Count -eq 0) { $blockers += 'repair-vm-has-no-mana-driver' }
        elseif ($packages.Count -eq 0) { }   # the missing function is already named in the blockers
        elseif (-not $Assessment.architecture -or -not $RepairVmArchitecture -or $Assessment.architecture -ne $RepairVmArchitecture) {
            $blockers += "architecture-mismatch:$($Assessment.architecture)-vs-$RepairVmArchitecture"
        }
        elseif (-not [int]::TryParse("$($Assessment.currentBuild)", [ref]$build) -or $build -lt $minimumBuild) {
            $blockers += "unsupported-os-build:$($Assessment.currentBuild)"
        }
        else {
            $incomingPackages = $packages
            ForEach ($pkg in $packages) {
                $actions += [pscustomobject]@{ type = 'AddDriverPackage'; inf = $pkg.inf; package = $pkg.package; driverVer = $pkg.driverVer; source = $pkg.infPath }
            }
        }
    }
    $providedServices = @(@($Assessment.manaPackages) + @($incomingPackages) | ForEach-Object { $_.services })

    ForEach ($problem in $problems) {
        if ($missingProblems -contains $problem) { continue }
        if ($problem -match '^mana-driver-disabled:(.+)$') {
            $service = $Matches[1]
            if ($service -notmatch $servicePattern) { $blockers += "unexpected-service-name:$service"; continue }
            $actions += [pscustomobject]@{ type = 'EnableService'; service = $service; from = $serviceDisabled; to = $demandStart }
        }
        elseif ($problem -match '^mana-device-not-bound:(.+)$') {
            $path = $Matches[1]
            $device = @($devices | Where-Object { $_.path -eq $path }) | Select-Object -First 1
            if ($path -notmatch $devicePattern -or -not $device) { $blockers += "unexpected-device:$path"; continue }
            & $addFlag $device
        }
        elseif ($problem -match '^mana-device-no-driver:(.+)$') {
            # Only the packages this repair adds can supply a driver; whether DISM really staged it is checked
            # by reassessing the disk after the packages are added.
            $path = $Matches[1]
            $incoming = @($incomingPackages)
            $device = @($devices | Where-Object { $_.path -eq $path }) | Select-Object -First 1
            if ($path -notmatch $devicePattern -or -not $device) { $blockers += "unexpected-device:$path"; continue }
            if (-not (Test-ManaDeviceDriverStaged -DevicePath $path -Packages $incoming)) { $blockers += "no-driver-to-install:$path"; continue }
            if (-not ([int]$device.configFlags -band $reinstallFlag)) { & $addFlag $device }
        }
        elseif ($problem -match '^mana-driver-(?:binary|service)-missing:(.+)$') {
            # Reinstalling the devices bound to the service recreates it and copies its binary from the staged package.
            $service = $Matches[1]
            if ($providedServices -notcontains $service) { $blockers += $problem; continue }
            ForEach ($device in @($devices | Where-Object { $_.service -eq $service -and -not ([int]$_.configFlags -band $reinstallFlag) })) {
                & $addFlag $device
            }
        }
        else {
            $outOfScope += $problem
        }
    }
    $actions += @($deviceActions)

    return [pscustomobject]@{ actions = $actions; blockers = $blockers; outOfScope = $outOfScope }
}

function Test-ManaRollbackManifest {
    # Validates a manifest before Rollback touches anything. Returns the reasons it is unusable; empty means usable.
    # Only the changes Repair can make are accepted: Start 4 -> 3 on a service in $Targets.services, and setting the
    # reinstall bit in ConfigFlags on a device in $Targets.devices. $Targets lists the MANA services and devices found
    # in the manifest's control set on the attached disk (see Get-ManaRollbackTarget).
    Param([Parameter(Mandatory = $true)]$Manifest, [Parameter(Mandatory = $true)]$Offline, $Targets)

    $reasons = @()
    if ($Manifest.schema -ne $manifestSchema) { $reasons += "unexpected schema '$($Manifest.schema)'" }
    if ("$($Manifest.guest.buildNumber)" -ne "$($Offline.BuildNumber)" -or "$($Manifest.guest.computerName)" -ne "$($Offline.GuestComputerName)") {
        $reasons += 'the manifest was written for a different Windows installation'
    }
    $changes = @($Manifest.registryChanges | Where-Object { $_ })
    if ($changes.Count -and "$($Manifest.controlSet)" -notmatch $controlSetPattern) { $reasons += "invalid control set '$($Manifest.controlSet)'" }
    elseif ($changes.Count -and (-not $Targets -or -not $Targets.controlSetFound)) { $reasons += "control set '$($Manifest.controlSet)' is not present on the attached disk" }
    $services = @($Targets.services)
    $devices = @($Targets.devices)
    ForEach ($change in $changes) {
        $before = -1; $after = -1
        if (-not [int]::TryParse("$($change.before)", [ref]$before) -or -not [int]::TryParse("$($change.after)", [ref]$after) -or $before -lt 0 -or $after -lt 0) {
            $reasons += "invalid before/after values for $($change.key)"
            continue
        }
        if ("$($change.key)" -notmatch $registryKeyPattern) { $reasons += "invalid registry key '$($change.key)'"; continue }
        if ("$($change.key)" -match '^Services\\(.+)$') {
            $service = $Matches[1]
            if ("$($change.name)" -ne 'Start') { $reasons += "invalid value name '$($change.name)' for $($change.key)" }
            elseif ($before -ne $serviceDisabled -or $after -ne $demandStart) { $reasons += "unexpected Start change $before -> $after for $($change.key)" }
            elseif ($services -notcontains $service) { $reasons += "$service is not a MANA driver service on the attached disk" }
        }
        else {
            $device = "$($change.key)" -replace '^Enum\\', ''
            if ("$($change.name)" -ne 'ConfigFlags') { $reasons += "invalid value name '$($change.name)' for $($change.key)" }
            elseif (($before -band $reinstallFlag) -or $after -ne ($before -bor $reinstallFlag)) { $reasons += "unexpected ConfigFlags change $before -> $after for $($change.key)" }
            elseif ($devices -notcontains $device) { $reasons += "$device is not a MANA device on the attached disk" }
        }
    }
    ForEach ($driver in @($Manifest.addedDrivers)) {
        if ("$($driver.publishedName)" -notmatch $publishedDriverPattern) { $reasons += "invalid published driver name '$($driver.publishedName)'" }
    }
    return $reasons
}

function Get-ManaRollbackTarget {
    # The MANA services and device instances in control set $ControlSet of the attached disk, read with the in-memory
    # offreg reader: the only registry targets a manifest may name.
    Param([Parameter(Mandatory = $true)][string]$WindowsRoot, [Parameter(Mandatory = $true)][string]$ControlSet)

    $targets = [pscustomobject]@{ controlSetFound = $false; services = @(); devices = @() }
    if ($ControlSet -notmatch $controlSetPattern) { return $targets }
    $system = Open-OfflineRegistryReader -Path "$WindowsRoot\System32\config\SYSTEM"
    try {
        if ($null -eq $system.GetSubKeyNames($ControlSet)) { return $targets }
        $targets.controlSetFound = $true
        $devices = @(Get-OfflineManaDevice -Reader $system -ControlSet $ControlSet)
        $targets.devices = @($devices | ForEach-Object { $_.path })
        $packageServices = @((Get-OfflineDriverPackage -WindowsRoot $WindowsRoot -InfPrefix 'mana').packages | ForEach-Object { $_.services })
        $targets.services = @(@($packageServices) + @($devices | ForEach-Object { "$($_.service)" }) | Where-Object { $_ -match $servicePattern } | Sort-Object -Unique)
    }
    finally { $system.Dispose() }
    return $targets
}

function Get-OfflineManaDriverEntry {
    # Third-party drivers in the offline image whose original INF is a MANA package, keyed by published name.
    Param([Parameter(Mandatory = $true)][string]$ImageRoot)

    $entries = @{}
    ForEach ($driver in @(Get-WindowsDriver -Path $ImageRoot -ErrorAction Stop)) {
        if ("$($driver.OriginalFileName)" -match '\\mana[^\\]*\.inf$') {
            $entries["$($driver.Driver)".ToLowerInvariant()] = [pscustomobject]@{
                publishedName = "$($driver.Driver)".ToLowerInvariant()
                inf           = [System.IO.Path]::GetFileName("$($driver.OriginalFileName)")
                version       = "$($driver.Version)"
            }
        }
    }
    return $entries
}

function Set-OfflineRegistryDword {
    # Writes DWORD values under control set $ControlSet of the offline SYSTEM hive inside one mount, and reads each
    # back. -RequireCurrent also requires $ControlSet to be the one Select\Current boots (Repair); Rollback restores
    # the control set its manifest names, whichever is current. Each change carries the value it expects to find. A
    # required change whose value differs stops everything before the first write; an Optional change whose value
    # differs is skipped and returned in Skipped. A failure after the first write does not throw: every value written
    # is in Applied, including one whose read-back failed, and the failure is in Error, so the caller can record
    # what Rollback must undo before it stops.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Changes and BackupDirectory are used inside the Invoke-WithHive script block, which PSScriptAnalyzer cannot see through.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Runs non-interactively under az vm repair run; Mode=Report is the dry run and every write passes Assert-OfflineTarget.')]
    Param(
        [Parameter(Mandatory = $true)][object[]]$Changes,
        [Parameter(Mandatory = $true)][string]$ControlSet,
        [switch]$RequireCurrent,
        [string]$BackupDirectory
    )

    if ($ControlSet -notmatch $controlSetPattern) { throw "Invalid control set '$ControlSet'. No changes were made." }
    Invoke-WithHive 'SYSTEM' {
        $current = Get-OfflineSystemRootPath -Strict:$RequireCurrent
        if ($RequireCurrent -and (Split-Path -Path $current -Leaf) -ne $ControlSet) {
            throw "The offline SYSTEM hive now boots $(Split-Path -Path $current -Leaf), not the assessed $ControlSet. No changes were made."
        }
        $root = "$(Split-Path -Path $current -Parent)\$ControlSet"
        if ((Get-OfflineHiveKeyState -HiveKey $root) -ne 'Present') { throw "The offline control set '$ControlSet' is not present. No changes were made." }
        $apply = @()
        $skipped = @()
        ForEach ($change in $Changes) {
            $path = "$root\$($change.key)"
            if ((Get-OfflineHiveKeyState -HiveKey $path) -ne 'Present') { throw "The offline key '$path' is not present. No changes were made." }
            $current = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).$($change.name)
            if ($null -eq $current) { $current = 0 }
            if ([int]$current -ne [int]$change.from) {
                if ($change.optional) { $skipped += $change; continue }
                throw "$($change.key)\$($change.name) is $current, expected $($change.from). No changes were made."
            }
            $apply += [pscustomobject]@{ change = $change; path = $path }
        }
        if ($BackupDirectory) {
            ForEach ($item in $apply) {
                $target = Join-Path $BackupDirectory (($item.change.key -replace '[\\&]', '_') + '-before.reg')
                $output = & reg.exe export ($item.path -replace '^(HK[A-Z_]+):\\', '$1\') $target /y 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target -PathType Leaf)) {
                    throw "Could not back up $($item.change.key) to '$target'; no changes were made. reg export: $(($output | Out-String).Trim())"
                }
            }
        }
        $applied = [System.Collections.Generic.List[object]]::new()
        $failure = $null
        ForEach ($item in $apply) {
            try {
                [void](Assert-OfflineTarget -Path $item.path -Action "set the offline $($item.change.key)\$($item.change.name) value")
                Set-ItemProperty -LiteralPath $item.path -Name $item.change.name -Value ([int]$item.change.to) -Type DWord -ErrorAction Stop
            }
            catch {
                $failure = "Could not set $($item.change.key)\$($item.change.name): $($_.Exception.Message)"
                Log-Warning "Could not set $($item.change.key)\$($item.change.name) after $($applied.Count) earlier change(s): $($_.Exception.Message)"
                break
            }
            # Recorded as soon as the write succeeds, so Rollback can undo it even if the read-back below fails.
            $applied.Add($item.change)
            try {
                $readBack = (Get-ItemProperty -LiteralPath $item.path -Name $item.change.name -ErrorAction Stop).$($item.change.name)
                if ([int]$readBack -ne [int]$item.change.to) { throw "it reads $readBack after writing $($item.change.to)" }
            }
            catch {
                $failure = "Verification failed for $($item.change.key)\$($item.change.name): $($_.Exception.Message)"
                Log-Warning "$failure ($($applied.Count) change(s) written, including this one)"
                break
            }
        }
        return [pscustomobject]@{ Applied = @($applied); Skipped = $skipped; Error = $failure }
    }
}

function Save-ManaManifest {
    Param([Parameter(Mandatory = $true)]$Manifest, [Parameter(Mandatory = $true)][string]$Path)
    $Manifest.updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $Manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding Ascii -ErrorAction Stop
}

$status = $STATUS_ERROR
$report = [ordered]@{ schemaVersion = '1.0'; scenario = 'mana-readiness'; producedBy = $scriptName; mode = $Mode; outcome = 'Failed' }
try {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
    . .\src\windows\common\helpers\ManaReadiness.ps1
    Import-Module Dism -ErrorAction Stop

    $discoveryParameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($OsDriveLetter)) { $discoveryParameters.WindowsDrive = $OsDriveLetter }
    $offline = Get-OfflineWindowsDisk @discoveryParameters
    Write-OfflineRepairLog
    if ([string]::IsNullOrWhiteSpace($OsDriveLetter) -and @($offline.Candidates).Count -gt 1) {
        $candidateDrives = @($offline.Candidates | ForEach-Object { $_.Drive }) -join ', '
        throw "Found $(@($offline.Candidates).Count) Windows installations ($candidateDrives). Refusing to guess; re-run with OsDriveLetter=<drive>."
    }
    $windowsRoot = $offline.WindowsPath
    $imageRoot = "$($offline.WindowsDrive.TrimEnd(':')):\"
    Log-Output "START: $scriptName Mode=$Mode on $windowsRoot ($($offline.ProductName) build $($offline.BuildNumber))"

    if ($Mode -eq 'Rollback') {
        if ([string]::IsNullOrWhiteSpace($BackupFile) -or -not [System.IO.Path]::IsPathRooted($BackupFile) -or -not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
            throw "Mode=Rollback requires BackupFile=<full path> to the mana-repair-manifest.json written by Repair. Not found: '$BackupFile'."
        }
        $manifest = Get-Content -LiteralPath $BackupFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $targets = Get-ManaRollbackTarget -WindowsRoot $windowsRoot -ControlSet "$($manifest.controlSet)"
        $reasons = @(Test-ManaRollbackManifest -Manifest $manifest -Offline $offline -Targets $targets)
        if ($reasons.Count) { throw "BackupFile '$BackupFile' cannot be used: $($reasons -join '; '). No changes were made." }

        # Check everything before changing anything: a published name can be reused by another driver, so only
        # names that still belong to a MANA package are removed.
        $present = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
        $toRemove = @()
        ForEach ($driver in @($manifest.addedDrivers)) {
            $name = "$($driver.publishedName)".ToLowerInvariant()
            if ($present.ContainsKey($name)) { $toRemove += $name }
            elseif (@(Get-WindowsDriver -Path $imageRoot -ErrorAction Stop | Where-Object { "$($_.Driver)".ToLowerInvariant() -eq $name }).Count) {
                throw "$name is no longer a MANA driver package in the offline image. No changes were made."
            }
        }
        # A reinstall flag the guest already used at boot has been cleared by Plug and Play; there is nothing to undo.
        $registryChanges = @($manifest.registryChanges | ForEach-Object {
                [pscustomobject]@{ key = $_.key; name = $_.name; from = [int]$_.after; to = [int]$_.before; optional = ($_.name -eq 'ConfigFlags') }
            })
        if ($registryChanges.Count) {
            $result = Set-OfflineRegistryDword -Changes $registryChanges -ControlSet "$($manifest.controlSet)"
            ForEach ($change in @($result.Applied)) { Log-Output "Restored $($manifest.controlSet)\$($change.key)\$($change.name) to $($change.to)." }
            ForEach ($change in @($result.Skipped)) { Log-Warning "Left $($change.key)\$($change.name) unchanged: it no longer holds the value Repair wrote (Plug and Play has already used the reinstall flag)." }
            if ($result.Error) { throw "Rollback stopped: $($result.Error). The driver packages were not removed." }
        }
        ForEach ($name in $toRemove) {
            [void](Assert-OfflineTarget -Path $windowsRoot -Action "remove the offline MANA driver package $name")
            Remove-WindowsDriver -Path $imageRoot -Driver $name -ErrorAction Stop | Out-Null
            Log-Output "Removed offline driver package $name."
        }
        $remaining = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
        $notRemoved = @($toRemove | Where-Object { $remaining.ContainsKey($_) })
        if ($notRemoved.Count) { throw "Rollback verification failed: $($notRemoved -join ', ') is still in the offline image." }
        $report.outcome = 'RolledBack'
        $report.backupFile = $BackupFile
    }
    else {
        $before = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
        ForEach ($warning in $before.readWarnings) { Log-Warning $warning }
        Log-Output "Before: verdict $($before.verdict). Problems: $(@($before.problems) -join '; '). Unknown: $(@($before.unknowns) -join '; ')"

        $repairVmPackages = @()
        if (@($before.problems | Where-Object { $_ -in 'mana-driver-missing', 'mana-bus-driver-missing', 'mana-ethernet-driver-missing' }).Count) {
            $source = Get-OfflineDriverPackage -WindowsRoot $env:SystemRoot -InfPrefix 'mana'
            $repairVmPackages = @($source.packages | ForEach-Object {
                    $_ | Add-Member -NotePropertyName infPath -NotePropertyValue (Join-Path "$env:SystemRoot\System32\DriverStore\FileRepository\$($_.package)" $_.inf) -PassThru
                })
        }
        $plan = Get-ManaRepairPlan -Assessment $before -RepairVmPackages $repairVmPackages -RepairVmArchitecture $env:PROCESSOR_ARCHITECTURE
        ForEach ($action in $plan.actions) {
            switch ($action.type) {
                'AddDriverPackage' { Log-Output "PLAN: add driver package $($action.inf) ($($action.driverVer)) from the repair VM" }
                'EnableService' { Log-Output "PLAN: set $($action.service) Start $($action.from) -> $($action.to)" }
                'ReinstallDevice' { Log-Output ("PLAN: flag {0} for reinstall at next boot (ConfigFlags 0x{1:X} -> 0x{2:X})" -f $action.device, $action.from, $action.to) }
            }
        }
        ForEach ($blocker in $plan.blockers) { Log-Warning "BLOCKED: $blocker" }
        ForEach ($item in $plan.outOfScope) { Log-Warning "NOT CHANGED (out of scope for this script): $item" }
        $report.before = [ordered]@{ verdict = $before.verdict; problems = @($before.problems); unknowns = @($before.unknowns) }
        $report.plan = $plan

        if ($Mode -eq 'Report') {
            $report.outcome = 'Report'
            Log-Output "Report only: $(@($plan.actions).Count) change(s) planned, $(@($plan.blockers).Count) blocker(s). No changes were made."
        }
        elseif (@($plan.blockers).Count) {
            throw "Repair refused: $(@($plan.blockers) -join '; '). No changes were made."
        }
        elseif (@($plan.actions).Count -eq 0) {
            $report.outcome = 'NoChangeNeeded'
            Log-Output 'NoChangeNeeded: no MANA driver problem to repair.'
        }
        else {
            $evidenceRoot = Join-Path $env:PUBLIC "Desktop\mana-repair-$(Get-Date -Format yyyyMMddHHmmss)-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
            New-Item -Path $evidenceRoot -ItemType Directory -ErrorAction Stop | Out-Null
            $manifestPath = Join-Path $evidenceRoot 'mana-repair-manifest.json'
            $manifest = [ordered]@{
                schema          = $manifestSchema
                createdAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
                updatedAtUtc    = $null
                state           = 'in-progress'
                controlSet      = "$($before.controlSet)"
                guest           = [ordered]@{ buildNumber = "$($offline.BuildNumber)"; computerName = "$($offline.GuestComputerName)"; productName = "$($offline.ProductName)" }
                addedDrivers    = @()
                registryChanges = @()
            }
            Save-ManaManifest -Manifest $manifest -Path $manifestPath

            # Packages first: if DISM fails, no registry value has been changed. A package that cannot be added is
            # recorded and skipped rather than abandoning the others: on a guest whose MANA drivers were removed,
            # DISM can refuse the RDMA package (mana_ib) because a device is still bound to the removed copy, while
            # the Ethernet packages install normally. The reassessment below decides whether the result is usable.
            $packageActions = @($plan.actions | Where-Object type -eq 'AddDriverPackage')
            $failedPackages = @()
            if ($packageActions.Count) {
                $existing = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
                ForEach ($action in $packageActions) {
                    [void](Assert-OfflineTarget -Path $windowsRoot -Action "add the MANA driver package $($action.inf) to the offline image")
                    try {
                        Add-WindowsDriver -Path $imageRoot -Driver $action.source -ErrorAction Stop | Out-Null
                    }
                    catch {
                        $failedPackages += [ordered]@{ inf = $action.inf; error = $_.Exception.Message.Trim() }
                        Log-Warning "Could not add $($action.inf) to the offline image: $($_.Exception.Message.Trim())"
                    }
                    # Recorded whether or not DISM reported success, so Rollback knows every package now present.
                    $added = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
                    $new = @($added.Values | Where-Object { -not $existing.ContainsKey($_.publishedName) })
                    $existing = $added
                    if ($new.Count) {
                        $manifest.addedDrivers = @($manifest.addedDrivers) + @($new | ForEach-Object { [ordered]@{ publishedName = $_.publishedName; inf = $_.inf; version = $_.version } })
                        Save-ManaManifest -Manifest $manifest -Path $manifestPath
                        Log-Output "Added $($action.inf) to the offline image as $(@($new | ForEach-Object { $_.publishedName }) -join ', ')."
                    }
                }
                $report.failedPackages = $failedPackages
                if ($failedPackages.Count -eq $packageActions.Count) {
                    throw "No MANA driver package could be added to the offline image. No registry value was changed. Roll back any partial DISM state with Mode=Rollback BackupFile='$manifestPath'."
                }
            }

            # Re-plan the registry changes from the disk as it is now. Service names come from the INF files, so a
            # leftover disabled service only becomes visible once its package is staged, and a package DISM
            # refused must not be assumed present.
            $registryPlan = $plan
            if ($packageActions.Count) {
                $staged = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
                if ("$($staged.controlSet)" -ne $manifest.controlSet) {
                    throw "The active control set changed from $($manifest.controlSet) to $($staged.controlSet) while packages were added. No registry value was changed. Roll back the added packages with Mode=Rollback BackupFile='$manifestPath'."
                }
                $registryPlan = Get-ManaRepairPlan -Assessment $staged -RepairVmArchitecture $env:PROCESSOR_ARCHITECTURE
                if (@($registryPlan.blockers).Count) {
                    throw "After adding the driver packages the repair cannot be completed: $(@($registryPlan.blockers) -join '; '). No registry value was changed. Roll back the added packages with Mode=Rollback BackupFile='$manifestPath'."
                }
                ForEach ($action in @($registryPlan.actions)) {
                    if ($action.type -eq 'EnableService') { Log-Output "PLAN (after staging): set $($action.service) Start $($action.from) -> $($action.to)" }
                    elseif ($action.type -eq 'ReinstallDevice') { Log-Output ("PLAN (after staging): flag {0} for reinstall at next boot (ConfigFlags 0x{1:X} -> 0x{2:X})" -f $action.device, $action.from, $action.to) }
                }
            }

            $registryChanges = @($registryPlan.actions | ForEach-Object {
                    if ($_.type -eq 'EnableService') { [pscustomobject]@{ key = "Services\$($_.service)"; name = 'Start'; from = $_.from; to = $_.to } }
                    elseif ($_.type -eq 'ReinstallDevice') { [pscustomobject]@{ key = "Enum\$($_.device)"; name = 'ConfigFlags'; from = $_.from; to = $_.to } }
                })
            if ($registryChanges.Count) {
                $result = Set-OfflineRegistryDword -Changes $registryChanges -BackupDirectory $evidenceRoot -ControlSet $manifest.controlSet -RequireCurrent
                $manifest.registryChanges = @($result.Applied | ForEach-Object { [ordered]@{ key = $_.key; name = $_.name; before = $_.from; after = $_.to } })
                Save-ManaManifest -Manifest $manifest -Path $manifestPath
                if ($result.Error) { throw "$($result.Error). Every value written is in the manifest; roll back with Mode=Rollback BackupFile='$manifestPath'." }
                ForEach ($change in @($result.Applied)) { Log-Output "Set $($manifest.controlSet)\$($change.key)\$($change.name) to $($change.to) (read back)." }
            }
            $manifest.state = 'applied'
            Save-ManaManifest -Manifest $manifest -Path $manifestPath

            $after = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
            $report.after = [ordered]@{ verdict = $after.verdict; problems = @($after.problems); unknowns = @($after.unknowns) }
            $report.backupFile = $manifestPath
            $remaining = @($after.problems | Where-Object { $_ -match '^mana-' })
            if ($remaining.Count -or @($after.unknowns).Count) {
                throw "Verification failed after repair: $(@($remaining + $after.unknowns) -join '; '). Roll back with Mode=Rollback BackupFile='$manifestPath'."
            }
            $report.outcome = 'Repaired'
            $optionalDevices = @($after.optionalDevicesWithoutDriver)
            $report.optionalDevicesWithoutDriver = $optionalDevices
            if (@($failedPackages).Count -or $optionalDevices.Count) {
                $report.outcome = 'RepairedWithWarnings'
                if (@($failedPackages).Count) {
                    Log-Warning "Not added: $(@($failedPackages | ForEach-Object { $_.inf }) -join ', ')."
                }
                ForEach ($device in $optionalDevices) {
                    Log-Warning "No driver for the non-Ethernet MANA function $device (for example RDMA). Networking does not depend on it."
                }
            }
            Log-Output "VERIFIED: after repair the verdict is $($after.verdict). Rollback manifest: $manifestPath"
        }
    }
    $status = $STATUS_SUCCESS
}
catch {
    Log-Error $_.Exception.Message
    $report.error = $_.Exception.Message
}
finally {
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) { Clear-OfflineDriveLetter }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) { Write-OfflineRepairLog }
    Log-Output "[MANA-REPAIR-JSON]$($report | ConvertTo-Json -Depth 6 -Compress)"
}
return $status
