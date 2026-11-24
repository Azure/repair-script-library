<#
.SYNOPSIS
    Read-only assessment of whether an offline Windows installation is ready for MANA (Microsoft Azure
    Network Adapter) hosts. Shared by win-detect-mana-readiness and win-fix-mana-driver.

.DESCRIPTION
    Reads the attached disk only: hives through the in-memory offreg reader in OfflineRepairCommon.ps1 (no hive is
    loaded into the registry and nothing is mounted under HKLM) and INF files in the offline driver store. MANA service names come
    from the AddService directives of the MANA driver packages, never from a hard-coded list.

    Get-ManaOfflineAssessment returns one finding per installation with verdict READY / NOT_READY / UNKNOWN.
    A fact that could not be established is unknown, never missing. Functions here never log: read problems
    are returned in the finding's readWarnings for the calling script to log.

.NOTES
    Name:     ManaReadiness.ps1
    Requires: OfflineRepairCommon.ps1 (for Open-OfflineRegistryReader).

.VERSION
    v1.0: Initial version.
#>
function Get-InfLineWithoutComment {
    # A semicolon starts a comment unless it is inside a quoted string.
    Param([string]$Line)

    $inQuotes = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        if ($Line[$i] -eq '"') { $inQuotes = -not $inQuotes }
        elseif ($Line[$i] -eq ';' -and -not $inQuotes) { return $Line.Substring(0, $i) }
    }
    return $Line
}

function Get-InfDriverFact {
    # Returns the services a driver package installs, the binaries it copies, and its DriverVer.
    # %token% references are expanded from the [Strings] section; unresolved tokens are kept verbatim.
    Param([AllowEmptyCollection()][string[]]$Lines)

    $strings = @{}
    $entries = @()
    $section = ''
    ForEach ($raw in $Lines) {
        $line = (Get-InfLineWithoutComment -Line $raw).Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLowerInvariant(); continue }
        if ($line -notmatch '^([^=]+?)\s*=\s*(.*)$') { continue }
        $key = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if ($section -eq 'strings') { $strings[$key.Trim('"').ToLowerInvariant()] = $value.Trim('"') }
        $entries += [pscustomobject]@{ Section = $section; Key = $key; Value = $value }
    }

    $expand = {
        Param([string]$Text)
        [regex]::Replace($Text, '%([^%]+)%', {
                Param($m)
                $name = $m.Groups[1].Value.ToLowerInvariant()
                if ($strings.ContainsKey($name)) { return $strings[$name] }
                return $m.Value
            })
    }

    $services = @()
    $binaries = @()
    $hardwareIds = @()
    $driverVer = $null
    $class = $null
    ForEach ($entry in $entries) {
        if ($entry.Key -ieq 'AddService') {
            # AddService = name,flags,install-section. An empty name is the null service and installs nothing.
            $name = (& $expand ($entry.Value -split ',')[0]).Trim().Trim('"')
            if ($name -and $services -notcontains $name) { $services += $name }
        }
        elseif ($entry.Key -ieq 'ServiceBinary') {
            $leaf = [regex]::Match((& $expand $entry.Value).Trim('"'), '[^\\]+$').Value
            if ($leaf -and $binaries -notcontains $leaf) { $binaries += $leaf }
        }
        elseif ($entry.Section -eq 'version' -and $entry.Key -ieq 'DriverVer') {
            $driverVer = (& $expand $entry.Value).Trim()
        }
        elseif ($entry.Section -eq 'version' -and $entry.Key -ieq 'Class') {
            $class = (& $expand $entry.Value).Trim().Trim('"')
        }
        elseif ($entry.Section -ne 'strings') {
            # Model lines: <description> = <install-section>, <hardware-id>[, <compatible-id>...]
            ForEach ($part in @($entry.Value -split ',' | Select-Object -Skip 1)) {
                $id = (& $expand $part).Trim().Trim('"').ToUpperInvariant()
                if ($id -match '^[A-Z0-9_]+\\VEN_[^\s,]+$' -and $hardwareIds -notcontains $id) { $hardwareIds += $id }
            }
        }
    }

    return [pscustomobject]@{ services = $services; serviceBinaries = $binaries; hardwareIds = $hardwareIds; driverVer = $driverVer; class = $class }
}

function Get-OfflineDriverPackage {
    # Driver packages staged in the offline driver store whose INF name starts with $InfPrefix.
    # repositoryFound distinguishes "no package" from "could not look".
    Param([string]$WindowsRoot, [string]$InfPrefix)

    $repository = "$WindowsRoot\System32\DriverStore\FileRepository"
    $result = [pscustomobject]@{ repositoryFound = $false; packages = @() }
    if (-not (Test-Path -LiteralPath $repository -PathType Container)) { return $result }
    $result.repositoryFound = $true

    ForEach ($dir in @(Get-ChildItem -LiteralPath $repository -Directory -Filter "$InfPrefix*.inf_*" -ErrorAction Stop)) {
        $infName = $dir.Name -replace '\.inf_.*$', '.inf'
        $infPath = Join-Path $dir.FullName $infName
        if (-not (Test-Path -LiteralPath $infPath -PathType Leaf)) { continue }
        $facts = Get-InfDriverFact -Lines @(Get-Content -LiteralPath $infPath -ErrorAction Stop)
        $result.packages += [pscustomobject]@{
            package         = $dir.Name
            inf             = $infName
            driverVer       = $facts.driverVer
            services        = $facts.services
            serviceBinaries = $facts.serviceBinaries
            hardwareIds     = $facts.hardwareIds
            class           = $facts.class
        }
    }
    return $result
}

function Resolve-ManaServiceBinaryPath {
    # Maps a service ImagePath to its location on the attached disk. Returns $null for a form that
    # cannot be mapped safely, so the caller reports unknown instead of checking the repair VM's C:.
    Param([string]$WindowsRoot, [string]$ServiceName, [string]$ImagePath)

    if ([string]::IsNullOrWhiteSpace($ImagePath)) {
        # Kernel drivers without an ImagePath load from System32\drivers\<service>.sys.
        return "$WindowsRoot\System32\drivers\$ServiceName.sys"
    }
    $path = $ImagePath.Trim().Trim('"') -replace '^\\\?\?\\', ''
    if ($path -match '^(?i)(?:\\SystemRoot|%SystemRoot%|[A-Z]:\\Windows)\\(.+)$') { return "$WindowsRoot\$($Matches[1])" }
    if ($path -match '^(?i)(System32\\.+)$') { return "$WindowsRoot\$($Matches[1])" }
    return $null
}

function Get-OfflineServiceState {
    # Reads one service from the offline SYSTEM hive. present is $false only when the key is absent.
    Param($Reader, [string]$ControlSet, [string]$ServiceName, [string]$WindowsRoot)

    $key = "$ControlSet\Services\$ServiceName"
    $state = [ordered]@{ name = $ServiceName; present = $null; start = $null; imagePath = $null; binaryPresent = $null; readError = $null }
    try {
        $state.start = $Reader.ReadDword($key, 'Start')
        $state.imagePath = $Reader.ReadString($key, 'ImagePath')
        $type = $Reader.ReadDword($key, 'Type')
        $state.present = ($null -ne $state.start) -or ($null -ne $type) -or ($null -ne $state.imagePath)
    }
    catch {
        $state.readError = $_.Exception.Message
        return $state
    }

    if ($state.present) {
        $binary = Resolve-ManaServiceBinaryPath -WindowsRoot $WindowsRoot -ServiceName $ServiceName -ImagePath $state.imagePath
        if ($binary) { $state.binaryPresent = [bool](Test-Path -LiteralPath $binary -PathType Leaf) }
    }
    return $state
}

function Test-ManaDeviceDriverStaged {
    # True when one of $Packages lists a hardware ID that matches the device at $DevicePath (BUS\ID\instance).
    # An INF ID matches the device ID exactly or as a prefix ending at an '&' boundary, the way PCI IDs nest.
    Param([Parameter(Mandatory = $true)][string]$DevicePath, [AllowEmptyCollection()][object[]]$Packages = @())

    $parts = $DevicePath.ToUpperInvariant() -split '\\'
    if ($parts.Count -lt 3) { return $false }
    $deviceId = "$($parts[0])\$($parts[1])"
    ForEach ($pkg in @($Packages | Where-Object { $_ })) {
        ForEach ($hwid in @($pkg.hardwareIds)) {
            if ($deviceId -eq $hwid -or $deviceId.StartsWith("$hwid&")) { return $true }
        }
    }
    return $false
}

function Get-ManaDriveAssessment {
    # Turns the facts for one installation into problems, unknowns and a verdict.
    Param($Finding)

    # SERVICE_DISABLED. Any other start type lets Plug and Play load the driver when its device appears.
    $serviceDisabled = 4
    $problems = @()
    $unknowns = @()

    $netvsc = $Finding.netvsc
    if (-not $netvsc -or $netvsc.readError -or $null -eq $netvsc.present) { $unknowns += 'netvsc-state-unknown' }
    elseif (-not $netvsc.present) { $problems += 'synthetic-nic-driver-missing' }
    else {
        if ($netvsc.start -eq $serviceDisabled) { $problems += 'synthetic-nic-driver-disabled' }
        if ($netvsc.binaryPresent -eq $false) { $problems += 'synthetic-nic-driver-binary-missing' }
        elseif ($null -eq $netvsc.binaryPresent) { $unknowns += 'netvsc-binary-unknown' }
    }

    if (-not $Finding.driverStoreFound) { $unknowns += 'driver-store-unreadable' }
    elseif (@($Finding.manaPackages).Count -eq 0) { $problems += 'mana-driver-missing' }

    # CONFIGFLAG_REINSTALL: Plug and Play installs the device again at the next boot, copying the driver
    # binaries from the staged package and rewriting the service.
    $reinstallFlag = 0x20
    $devices = @($Finding.manaDevices | Where-Object { $_ })
    $stagedServices = @($Finding.manaPackages | ForEach-Object { $_.services })
    $netStaged = @($Finding.manaPackages | Where-Object { $_ -and "$($_.class)" -eq 'Net' }).Count -gt 0
    $optional = @()
    if ($Finding.Contains('manaDevicesRead') -and $Finding.manaDevicesRead -eq $false) { $unknowns += 'mana-devices-unknown' }
    ForEach ($device in $devices) {
        if ($device.service) { continue }
        if (Test-ManaDeviceDriverStaged -DevicePath $device.path -Packages $Finding.manaPackages) {
            # A device Windows has already seen keeps its instance key. Without a driver and without the reinstall
            # flag, Plug and Play treats it as configured and never installs the driver staged for it.
            if (-not ([int]$device.configFlags -band $reinstallFlag)) { $problems += "mana-device-not-bound:$($device.path)" }
        }
        elseif ($netStaged -and $device.path -match '^(?i)MANA_BUS\\') {
            # With a Net-class MANA package staged the Ethernet function is covered, so another MANA_BUS child left
            # without a driver is a non-Ethernet function (RDMA, for example): reported, but networking still works.
            $optional += $device.path
        }
        else {
            $problems += "mana-device-no-driver:$($device.path)"
        }
    }
    ForEach ($svc in @($Finding.manaServices)) {
        if ($svc.readError) { $unknowns += "mana-service-unknown:$($svc.name)"; continue }
        if (-not $svc.present) { continue }   # installed by Plug and Play when the MANA VF first appears
        if ($svc.start -eq $serviceDisabled) { $problems += "mana-driver-disabled:$($svc.name)" }
        if ($svc.binaryPresent -eq $false) {
            # Installing a staged package copies the binary back, so a missing binary is only a problem while
            # no staged package provides the service or a device bound to it will not be reinstalled.
            $bound = @($devices | Where-Object { $_.service -eq $svc.name })
            $pending = ($stagedServices -contains $svc.name) -and
                (@($bound | Where-Object { -not ([int]$_.configFlags -band $reinstallFlag) }).Count -eq 0)
            if (-not $pending) { $problems += "mana-driver-binary-missing:$($svc.name)" }
        }
    }

    $verdict = if ($problems.Count) { 'NOT_READY' } elseif ($unknowns.Count) { 'UNKNOWN' } else { 'READY' }
    return [pscustomobject]@{ verdict = $verdict; problems = $problems; unknowns = $unknowns; optionalDevicesWithoutDriver = $optional }
}

function Get-OverallVerdict {
    # One broken installation makes the disk not ready; otherwise any unknown blocks a READY claim.
    Param([AllowEmptyCollection()][string[]]$Verdicts)

    if (-not $Verdicts -or $Verdicts.Count -eq 0) { return 'UNKNOWN' }
    if ($Verdicts -contains 'NOT_READY') { return 'NOT_READY' }
    if ($Verdicts -contains 'UNKNOWN') { return 'UNKNOWN' }
    return 'READY'
}


function Get-OfflineManaDevice {
    # MANA device instances Windows has already enumerated: the VF (PCI\VEN_1414&DEV_00BA) and the devices its bus
    # driver creates (MANA_BUS\...). Each carries the bound service, if any, and its ConfigFlags.
    Param([Parameter(Mandatory = $true)]$Reader, [Parameter(Mandatory = $true)][string]$ControlSet)

    $devices = @()
    ForEach ($bus in 'PCI', 'MANA_BUS') {
        $busKey = "$ControlSet\Enum\$bus"
        $ids = $Reader.GetSubKeyNames($busKey)
        ForEach ($id in @($ids)) {
            if (-not $id) { continue }
            if ($bus -eq 'PCI' -and $id -notmatch '^(?i)VEN_1414&DEV_00BA') { continue }
            ForEach ($instance in @($Reader.GetSubKeyNames("$busKey\$id"))) {
                if (-not $instance) { continue }
                $key = "$busKey\$id\$instance"
                $flags = $Reader.ReadDword($key, 'ConfigFlags')
                $devices += [pscustomobject]@{
                    path        = "$bus\$id\$instance"
                    service     = $Reader.ReadString($key, 'Service')
                    configFlags = $(if ($null -eq $flags) { 0 } else { [int]$flags })
                }
            }
        }
    }
    return $devices
}

function Get-ManaOfflineAssessment {
    # Gathers every MANA readiness fact for the Windows installation at $WindowsRoot (e.g. F:\Windows).
    Param([Parameter(Mandatory = $true)][string]$WindowsRoot)

    $finding = [ordered]@{
        windowsRoot      = $WindowsRoot
        productName      = $null
        currentBuild     = $null
        displayVersion   = $null
        architecture     = $null
        controlSet       = $null
        systemHiveRead   = $false
        netvsc           = $null
        driverStoreFound = $false
        manaPackages     = @()
        manaServices     = @()
        manaDevices      = @()
        manaDevicesRead  = $false
        mellanoxPackages = @()
        verdict          = 'UNKNOWN'
        problems         = @()
        unknowns         = @()
        optionalDevicesWithoutDriver = @()
        readWarnings     = @()
    }

    try {
        $software = Open-OfflineRegistryReader -Path "$WindowsRoot\System32\config\SOFTWARE"
        try {
            $versionKey = 'Microsoft\Windows NT\CurrentVersion'
            $finding.productName = $software.ReadString($versionKey, 'ProductName')
            $finding.currentBuild = $software.ReadString($versionKey, 'CurrentBuild')
            $finding.displayVersion = $software.ReadString($versionKey, 'DisplayVersion')
        }
        finally { $software.Dispose() }
    }
    catch {
        $finding.readWarnings += "could not read the OS version from the SOFTWARE hive: $($_.Exception.Message)"
    }

    $mana = Get-OfflineDriverPackage -WindowsRoot $WindowsRoot -InfPrefix 'mana'
    $finding.driverStoreFound = $mana.repositoryFound
    $finding.manaPackages = @($mana.packages)
    # Mellanox packages are informational; their long hardware-ID lists would only bloat the evidence line.
    $finding.mellanoxPackages = @((Get-OfflineDriverPackage -WindowsRoot $WindowsRoot -InfPrefix 'mlx').packages |
            Select-Object package, inf, driverVer)

    try {
        $system = Open-OfflineRegistryReader -Path "$WindowsRoot\System32\config\SYSTEM"
        try {
            $current = $system.ReadDword('Select', 'Current')
            if ($null -eq $current) { throw 'Select\Current is missing from the SYSTEM hive.' }
            $controlSet = 'ControlSet{0:D3}' -f $current
            $finding.controlSet = $controlSet
            $finding.architecture = $system.ReadString("$controlSet\Control\Session Manager\Environment", 'PROCESSOR_ARCHITECTURE')
            $finding.netvsc = Get-OfflineServiceState -Reader $system -ControlSet $controlSet -ServiceName 'netvsc' -WindowsRoot $WindowsRoot
            $serviceNames = @($finding.manaPackages | ForEach-Object { $_.services } | Select-Object -Unique)
            $finding.manaServices = @($serviceNames | ForEach-Object {
                    Get-OfflineServiceState -Reader $system -ControlSet $controlSet -ServiceName $_ -WindowsRoot $WindowsRoot
                })
            $finding.manaDevices = @(Get-OfflineManaDevice -Reader $system -ControlSet $controlSet)
            $finding.manaDevicesRead = $true
            $finding.systemHiveRead = $true
        }
        finally { $system.Dispose() }
    }
    catch {
        $finding.readWarnings += "could not read the SYSTEM hive: $($_.Exception.Message)"
    }

    $assessment = Get-ManaDriveAssessment -Finding $finding
    $finding.verdict = $assessment.verdict
    $finding.problems = @($assessment.problems)
    $finding.unknowns = @($assessment.unknowns)
    $finding.optionalDevicesWithoutDriver = @($assessment.optionalDevicesWithoutDriver)
    if (-not $finding.systemHiveRead) { $finding.unknowns += 'system-hive-unreadable' }
    return $finding
}
