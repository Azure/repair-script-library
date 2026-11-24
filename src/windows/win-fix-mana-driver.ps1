#########################################################################################################
#
# .SYNOPSIS
#   Repairs the MANA (Microsoft Azure Network Adapter) driver on an offline Windows OS disk. v1.0.0
#
# .DESCRIPTION
#   Runs on a repair VM against the source VM's OS disk attached as a data disk, and fixes the two problems
#   win-detect-mana-readiness reports for the MANA driver:
#
#     mana-driver-disabled:<service>  A MANA driver service has Start=4 (disabled). Repair sets it back to 3
#                                     (demand start, the value Windows installs), so Plug and Play can load the
#                                     driver when the MANA virtual function appears.
#     mana-driver-missing             No MANA driver package is in the offline driver store. Repair adds the
#                                     repair VM's own MANA driver packages to the offline image with DISM's
#                                     offline servicing (Add-WindowsDriver -Path), which keeps the package's
#                                     signature check and does not touch the running repair VM.
#
#   Mode=Report (default) makes no changes and prints the plan. Mode=Repair applies it, writes a rollback
#   manifest and a .reg export of every service key it changes, and verifies the result by reassessing the
#   disk. Mode=Rollback undoes a Repair using its manifest.
#
#   Problems with the synthetic network driver (netvsc) mean the VM has no network at all; they are reported
#   but never changed by this script. A missing MANA driver binary, an installation that cannot be fully read,
#   an architecture mismatch, a build older than Windows Server 2016, or a repair VM without MANA drivers make
#   Repair refuse before any change.
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
# Windows Server 2016. Older builds have no MANA driver support.
$minimumBuild = 14393
$servicePattern = '^[A-Za-z0-9_.-]{1,64}$'
$publishedDriverPattern = '^oem\d+\.inf$'

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

    ForEach ($unknown in @($Assessment.unknowns)) { $blockers += "assessment-incomplete:$unknown" }

    ForEach ($problem in @($Assessment.problems)) {
        if ($problem -match '^mana-driver-disabled:(.+)$') {
            $service = $Matches[1]
            if ($service -notmatch $servicePattern) { $blockers += "unexpected-service-name:$service"; continue }
            $actions += [pscustomobject]@{ type = 'EnableService'; service = $service; from = $serviceDisabled; to = $demandStart }
        }
        elseif ($problem -eq 'mana-driver-missing') {
            $packages = @($RepairVmPackages)
            if ($packages.Count -eq 0) { $blockers += 'repair-vm-has-no-mana-driver'; continue }
            if (-not $Assessment.architecture -or -not $RepairVmArchitecture -or $Assessment.architecture -ne $RepairVmArchitecture) {
                $blockers += "architecture-mismatch:$($Assessment.architecture)-vs-$RepairVmArchitecture"
                continue
            }
            $build = 0
            if (-not [int]::TryParse("$($Assessment.currentBuild)", [ref]$build) -or $build -lt $minimumBuild) {
                $blockers += "unsupported-os-build:$($Assessment.currentBuild)"
                continue
            }
            ForEach ($pkg in $packages) {
                $actions += [pscustomobject]@{ type = 'AddDriverPackage'; inf = $pkg.inf; package = $pkg.package; driverVer = $pkg.driverVer; source = $pkg.infPath }
            }
        }
        elseif ($problem -match '^mana-driver-binary-missing:') {
            # The service points at a file that is gone: a damaged installation, not a configuration this script owns.
            $blockers += $problem
        }
        else {
            $outOfScope += $problem
        }
    }

    return [pscustomobject]@{ actions = $actions; blockers = $blockers; outOfScope = $outOfScope }
}

function Test-ManaRollbackManifest {
    # Validates a manifest before Rollback touches anything. Returns the reasons it is unusable; empty means usable.
    Param([Parameter(Mandatory = $true)]$Manifest, [Parameter(Mandatory = $true)]$Offline)

    $reasons = @()
    if ($Manifest.schema -ne $manifestSchema) { $reasons += "unexpected schema '$($Manifest.schema)'" }
    if ("$($Manifest.guest.buildNumber)" -ne "$($Offline.BuildNumber)" -or "$($Manifest.guest.computerName)" -ne "$($Offline.GuestComputerName)") {
        $reasons += 'the manifest was written for a different Windows installation'
    }
    ForEach ($change in @($Manifest.serviceChanges)) {
        if ("$($change.service)" -notmatch $servicePattern) { $reasons += "invalid service name '$($change.service)'" }
        $before = -1
        if (-not [int]::TryParse("$($change.before)", [ref]$before) -or $before -lt 0 -or $before -gt 4) { $reasons += "invalid Start value '$($change.before)' for $($change.service)" }
    }
    ForEach ($driver in @($Manifest.addedDrivers)) {
        if ("$($driver.publishedName)" -notmatch $publishedDriverPattern) { $reasons += "invalid published driver name '$($driver.publishedName)'" }
    }
    return $reasons
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

function Set-OfflineServiceStart {
    # Sets Start on offline services inside one SYSTEM hive mount and reads each value back. Every change is
    # gated: the expected current value must still be there, or nothing is written.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Changes and BackupDirectory are used inside the Invoke-WithHive script block, which PSScriptAnalyzer cannot see through.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Runs non-interactively under az vm repair run; Mode=Report is the dry run and every write passes Assert-OfflineTarget.')]
    Param(
        [Parameter(Mandatory = $true)][object[]]$Changes,
        [string]$BackupDirectory
    )

    Invoke-WithHive 'SYSTEM' {
        $root = Get-OfflineSystemRootPath -Strict
        $paths = @{}
        ForEach ($change in $Changes) {
            $path = "$root\Services\$($change.service)"
            if ((Get-OfflineHiveKeyState -HiveKey $path) -ne 'Present') { throw "The offline service key '$path' is not present. No changes were made." }
            $current = (Get-ItemProperty -LiteralPath $path -Name Start -ErrorAction Stop).Start
            if ($current -ne $change.from) { throw "$($change.service) Start is $current, expected $($change.from). No changes were made." }
            $paths[$change.service] = $path
        }
        if ($BackupDirectory) {
            ForEach ($change in $Changes) {
                $target = Join-Path $BackupDirectory "$($change.service)-before.reg"
                $output = & reg.exe export ($paths[$change.service] -replace '^(HK[A-Z_]+):\\', '$1\') $target /y 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target -PathType Leaf)) {
                    throw "Could not back up $($change.service) to '$target'; no changes were made. reg export: $(($output | Out-String).Trim())"
                }
            }
        }
        ForEach ($change in $Changes) {
            [void](Assert-OfflineTarget -Path $paths[$change.service] -Action "set the offline $($change.service) Start value")
            Set-ItemProperty -LiteralPath $paths[$change.service] -Name Start -Value $change.to -Type DWord -ErrorAction Stop
            $readBack = (Get-ItemProperty -LiteralPath $paths[$change.service] -Name Start -ErrorAction Stop).Start
            if ($readBack -ne $change.to) { throw "Verification failed: $($change.service) Start reads $readBack after writing $($change.to)." }
        }
        return $true
    } | Out-Null
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
        $reasons = @(Test-ManaRollbackManifest -Manifest $manifest -Offline $offline)
        if ($reasons.Count) { throw "BackupFile '$BackupFile' cannot be used: $($reasons -join '; '). No changes were made." }

        # Check everything before changing anything: a published name can be reused by another driver after a
        # rollback elsewhere, so only names that still belong to a MANA package are removed.
        $present = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
        $toRemove = @()
        ForEach ($driver in @($manifest.addedDrivers)) {
            $name = "$($driver.publishedName)".ToLowerInvariant()
            if ($present.ContainsKey($name)) { $toRemove += $name }
            elseif (@(Get-WindowsDriver -Path $imageRoot -ErrorAction Stop | Where-Object { "$($_.Driver)".ToLowerInvariant() -eq $name }).Count) {
                throw "$name is no longer a MANA driver package in the offline image. No changes were made."
            }
        }
        $serviceChanges = @($manifest.serviceChanges | ForEach-Object { [pscustomobject]@{ service = $_.service; from = $demandStart; to = [int]$_.before } })
        if ($serviceChanges.Count) { Set-OfflineServiceStart -Changes $serviceChanges }
        ForEach ($name in $toRemove) {
            [void](Assert-OfflineTarget -Path $windowsRoot -Action "remove the offline MANA driver package $name")
            Remove-WindowsDriver -Path $imageRoot -Driver $name -ErrorAction Stop | Out-Null
            Log-Output "Removed offline driver package $name."
        }
        $remaining = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
        $notRemoved = @($toRemove | Where-Object { $remaining.ContainsKey($_) })
        if ($notRemoved.Count) { throw "Rollback verification failed: $($notRemoved -join ', ') is still in the offline image." }
        ForEach ($change in $serviceChanges) { Log-Output "Restored $($change.service) Start to $($change.to)." }
        $report.outcome = 'RolledBack'
        $report.backupFile = $BackupFile
    }
    else {
        $before = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
        ForEach ($warning in $before.readWarnings) { Log-Warning $warning }
        Log-Output "Before: verdict $($before.verdict). Problems: $(@($before.problems) -join '; '). Unknown: $(@($before.unknowns) -join '; ')"

        $repairVmPackages = @()
        if (@($before.problems) -contains 'mana-driver-missing') {
            $source = Get-OfflineDriverPackage -WindowsRoot $env:SystemRoot -InfPrefix 'mana'
            $repairVmPackages = @($source.packages | ForEach-Object {
                    $_ | Add-Member -NotePropertyName infPath -NotePropertyValue (Join-Path "$env:SystemRoot\System32\DriverStore\FileRepository\$($_.package)" $_.inf) -PassThru
                })
        }
        $plan = Get-ManaRepairPlan -Assessment $before -RepairVmPackages $repairVmPackages -RepairVmArchitecture $env:PROCESSOR_ARCHITECTURE
        ForEach ($action in $plan.actions) {
            if ($action.type -eq 'EnableService') { Log-Output "PLAN: set $($action.service) Start $($action.from) -> $($action.to)" }
            else { Log-Output "PLAN: add driver package $($action.inf) ($($action.driverVer)) from the repair VM" }
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
                schema         = $manifestSchema
                createdAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
                updatedAtUtc   = $null
                state          = 'in-progress'
                guest          = [ordered]@{ buildNumber = "$($offline.BuildNumber)"; computerName = "$($offline.GuestComputerName)"; productName = "$($offline.ProductName)" }
                serviceChanges = @()
                addedDrivers   = @()
            }
            Save-ManaManifest -Manifest $manifest -Path $manifestPath

            $serviceActions = @($plan.actions | Where-Object type -eq 'EnableService')
            if ($serviceActions.Count) {
                Set-OfflineServiceStart -Changes $serviceActions -BackupDirectory $evidenceRoot
                $manifest.serviceChanges = @($serviceActions | ForEach-Object { [ordered]@{ service = $_.service; before = $_.from; after = $_.to } })
                Save-ManaManifest -Manifest $manifest -Path $manifestPath
                ForEach ($action in $serviceActions) { Log-Output "Set $($action.service) Start to $($action.to) (read back)." }
            }

            $packageActions = @($plan.actions | Where-Object type -eq 'AddDriverPackage')
            if ($packageActions.Count) {
                $existing = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
                ForEach ($action in $packageActions) {
                    [void](Assert-OfflineTarget -Path $windowsRoot -Action "add the MANA driver package $($action.inf) to the offline image")
                    Add-WindowsDriver -Path $imageRoot -Driver $action.source -ErrorAction Stop | Out-Null
                    $added = Get-OfflineManaDriverEntry -ImageRoot $imageRoot
                    $new = @($added.Values | Where-Object { -not $existing.ContainsKey($_.publishedName) })
                    $existing = $added
                    $manifest.addedDrivers = @($manifest.addedDrivers) + @($new | ForEach-Object { [ordered]@{ publishedName = $_.publishedName; inf = $_.inf; version = $_.version } })
                    Save-ManaManifest -Manifest $manifest -Path $manifestPath
                    Log-Output "Added $($action.inf) to the offline image as $(@($new | ForEach-Object { $_.publishedName }) -join ', ')."
                }
            }
            $manifest.state = 'applied'
            Save-ManaManifest -Manifest $manifest -Path $manifestPath

            $after = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
            $report.after = [ordered]@{ verdict = $after.verdict; problems = @($after.problems); unknowns = @($after.unknowns) }
            $report.backupFile = $manifestPath
            $remaining = @($after.problems | Where-Object { $_ -match '^mana-driver-(missing|disabled)' })
            if ($remaining.Count -or @($after.unknowns).Count) {
                throw "Verification failed after repair: $(@($remaining + $after.unknowns) -join '; '). Roll back with Mode=Rollback BackupFile='$manifestPath'."
            }
            $report.outcome = 'Repaired'
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
