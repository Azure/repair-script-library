#########################################################################################################
#
# .SYNOPSIS
#   Read-only check of whether a Windows OS disk is ready for MANA (Microsoft Azure Network Adapter) hosts. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. Reports whether the
#   guest has what it needs to keep networking when its host moves from Mellanox to MANA hardware:
#
#     - the synthetic network driver (netvsc), which carries traffic whenever no accelerated VF is
#       usable. If it is missing or disabled the VM has no network at all.
#     - a MANA driver package in the driver store, so Plug and Play can bind the MANA VF when it
#       appears, and no MANA service disabled in the active control set.
#
#   Makes NO changes to the attached OS disk. Hives are read with the Offline Registry Library
#   (offreg.dll) in memory: nothing is mounted under HKLM, no hive or log is written, and reg.exe is
#   never used. A disk that is offline is brought online read-only and returned to offline and writable
#   when the check ends, so a later repair script finds it exactly as attached. A disk that is offline
#   because its disk ID collides with the repair VM's own disk is left untouched and reported. A disk
#   that Windows had already onlined writable before this script ran is reported in riskIndicators,
#   not changed.
#
#   A missing MANA driver loses accelerated networking but, as long as netvsc is healthy, the VM still
#   reaches the network through the synthetic adapter. problems tells the two cases apart.
#
#   Emits one machine-readable JSON line prefixed with [MANA-EVIDENCE-JSON], with the same verdict
#   vocabulary as linux-detect-mana-readiness: READY, NOT_READY or UNKNOWN. A fact that could not be
#   established is reported as unknown, never as missing.
#
# .RESOLVES
#   Nothing. Detection only.
#
# .NOTES
#   Requires the --run-on-repair option. Driver service names are read from the AddService directives
#   of the MANA packages found in the driver store, not from a hard-coded list.
#
# .PARAMETER OsDriveLetter
#   [Optional] Restrict inspection to one drive letter (e.g. F). Default: inspect every Windows
#   installation found on attached data disks.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n problemVM --run-id win-detect-mana-readiness --run-on-repair --verbose
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][string]$OsDriveLetter = ''
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v3.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = 'win-detect-mana-readiness'
$logFile = "$env:PUBLIC\Desktop\$scriptName.log"
$evidenceRoot = "$env:PUBLIC\Desktop\mana-evidence-$scriptStartTime"

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
    $driverVer = $null
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
    }

    return [pscustomobject]@{ services = $services; serviceBinaries = $binaries; driverVer = $driverVer }
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
        }
    }
    return $result
}

function Resolve-OfflineImagePath {
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
        $binary = Resolve-OfflineImagePath -WindowsRoot $WindowsRoot -ServiceName $ServiceName -ImagePath $state.imagePath
        if ($binary) { $state.binaryPresent = [bool](Test-Path -LiteralPath $binary -PathType Leaf) }
    }
    return $state
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

    ForEach ($svc in @($Finding.manaServices)) {
        if ($svc.readError) { $unknowns += "mana-service-unknown:$($svc.name)"; continue }
        if (-not $svc.present) { continue }   # installed by Plug and Play when the MANA VF first appears
        if ($svc.start -eq $serviceDisabled) { $problems += "mana-driver-disabled:$($svc.name)" }
        if ($svc.binaryPresent -eq $false) { $problems += "mana-driver-binary-missing:$($svc.name)" }
    }

    $verdict = if ($problems.Count) { 'NOT_READY' } elseif ($unknowns.Count) { 'UNKNOWN' } else { 'READY' }
    return [pscustomobject]@{ verdict = $verdict; problems = $problems; unknowns = $unknowns }
}

function Get-OverallVerdict {
    # One broken installation makes the disk not ready; otherwise any unknown blocks a READY claim.
    Param([AllowEmptyCollection()][string[]]$Verdicts)

    if (-not $Verdicts -or $Verdicts.Count -eq 0) { return 'UNKNOWN' }
    if ($Verdicts -contains 'NOT_READY') { return 'NOT_READY' }
    if ($Verdicts -contains 'UNKNOWN') { return 'UNKNOWN' }
    return 'READY'
}

$overallStatus = $STATUS_SUCCESS
$findings = @()

try {
    Log-Output "START: Running script $scriptName (read-only)" | Tee-Object -FilePath $logFile -Append
    New-Item -Path $evidenceRoot -ItemType Directory -Force | Out-Null
    Log-Output "Evidence directory: $evidenceRoot" | Tee-Object -FilePath $logFile -Append

    if ($OsDriveLetter) {
        $osDrives = @($OsDriveLetter.TrimEnd(':'))
    }
    else {
        $osDrives = @(Get-Windows-OsDrives-v3 -ReadOnly)
    }

    if ($osDrives.Count -eq 0) {
        $collided = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsOffline -and "$($_.OfflineReason)" -eq 'Collision' })
        if ($collided.Count) {
            throw "Disk $(($collided | ForEach-Object { $_.Number }) -join ', ') is offline because its disk ID matches another disk on this repair VM, so it cannot be read without rewriting its disk ID. Recreate the repair VM from a different image (az vm repair create chooses one to avoid this) and run the check again."
        }
        throw "No Windows installation found on any attached data disk. Confirm the source OS disk is attached with 'Get-Disk | Select Number,BusType,IsBoot,IsSystem,IsOffline,IsReadOnly'."
    }

    ForEach ($drive in $osDrives) {
        Log-Output "--- Inspecting ${drive}: ---" | Tee-Object -FilePath $logFile -Append
        $windowsRoot = "${drive}:\Windows"

        $diskReadOnly = $null
        $partition = Get-Partition -DriveLetter $drive -ErrorAction SilentlyContinue
        if ($partition) {
            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
            if ($disk) { $diskReadOnly = [bool]$disk.IsReadOnly }
        }

        $finding = [ordered]@{
            osDrive          = $drive
            diskReadOnly     = $diskReadOnly
            productName      = $null
            currentBuild     = $null
            displayVersion   = $null
            controlSet       = $null
            systemHiveRead   = $false
            netvsc           = $null
            driverStoreFound = $false
            manaPackages     = @()
            manaServices     = @()
            mellanoxPackages = @()
            verdict          = 'UNKNOWN'
            problems         = @()
            unknowns         = @()
        }

        try {
            $software = Open-OfflineRegistryReader -Path "$windowsRoot\System32\config\SOFTWARE"
            try {
                $versionKey = 'Microsoft\Windows NT\CurrentVersion'
                $finding.productName = $software.ReadString($versionKey, 'ProductName')
                $finding.currentBuild = $software.ReadString($versionKey, 'CurrentBuild')
                $finding.displayVersion = $software.ReadString($versionKey, 'DisplayVersion')
            }
            finally { $software.Dispose() }
        }
        catch {
            Log-Warning "${drive}: could not read the OS version from the SOFTWARE hive: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
        }
        if ($finding.productName) {
            Log-Output "${drive}: $($finding.productName) build $($finding.currentBuild) $($finding.displayVersion)" | Tee-Object -FilePath $logFile -Append
        }

        $mana = Get-OfflineDriverPackage -WindowsRoot $windowsRoot -InfPrefix 'mana'
        $finding.driverStoreFound = $mana.repositoryFound
        $finding.manaPackages = @($mana.packages)
        $finding.mellanoxPackages = @((Get-OfflineDriverPackage -WindowsRoot $windowsRoot -InfPrefix 'mlx').packages)
        ForEach ($pkg in $finding.manaPackages) {
            Log-Output "${drive}: MANA package $($pkg.package) DriverVer=$($pkg.driverVer) services=$($pkg.services -join ',')" | Tee-Object -FilePath $logFile -Append
        }

        try {
            $system = Open-OfflineRegistryReader -Path "$windowsRoot\System32\config\SYSTEM"
            try {
                $current = $system.ReadDword('Select', 'Current')
                if ($null -eq $current) { throw 'Select\Current is missing from the SYSTEM hive.' }
                $controlSet = 'ControlSet{0:D3}' -f $current
                $finding.controlSet = $controlSet
                $finding.netvsc = Get-OfflineServiceState -Reader $system -ControlSet $controlSet -ServiceName 'netvsc' -WindowsRoot $windowsRoot
                $serviceNames = @($finding.manaPackages | ForEach-Object { $_.services } | Select-Object -Unique)
                $finding.manaServices = @($serviceNames | ForEach-Object {
                        Get-OfflineServiceState -Reader $system -ControlSet $controlSet -ServiceName $_ -WindowsRoot $windowsRoot
                    })
                $finding.systemHiveRead = $true
            }
            finally { $system.Dispose() }
        }
        catch {
            Log-Warning "${drive}: could not read the SYSTEM hive: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
        }

        $assessment = Get-ManaDriveAssessment -Finding $finding
        $finding.verdict = $assessment.verdict
        $finding.problems = @($assessment.problems)
        $finding.unknowns = @($assessment.unknowns)
        if (-not $finding.systemHiveRead) { $finding.unknowns += 'system-hive-unreadable' }

        if ($finding.verdict -eq 'READY') {
            Log-Output "${drive}: READY for MANA hosts." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "${drive}: $($finding.verdict). Problems: $($finding.problems -join '; '). Unknown: $($finding.unknowns -join '; ')" | Tee-Object -FilePath $logFile -Append
        }
        $findings += $finding
    }

    $verdict = Get-OverallVerdict -Verdicts @($findings | ForEach-Object { $_.verdict })
    $problems = @($findings | ForEach-Object { $_.problems } | Select-Object -Unique)
    $riskIndicators = @()
    if (@($findings | Where-Object { $_.diskReadOnly -eq $false }).Count) { $riskIndicators += 'disk-already-online-writable' }
    if (@($findings | Where-Object { @($_.mellanoxPackages).Count -and -not @($_.manaPackages).Count }).Count) { $riskIndicators += 'mellanox-driver-only' }

    $evidence = [ordered]@{
        schemaVersion  = '1.0'
        scenario       = 'mana-readiness'
        producedBy     = $scriptName
        producedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
        verdict        = $verdict
        problems       = (($problems | ForEach-Object { "$_;" }) -join '')
        riskIndicators = (($riskIndicators | ForEach-Object { "$_;" }) -join '')
        os             = [ordered]@{ family = 'windows' }
        guest          = $findings
        evidencePath   = $evidenceRoot
    }

    $json = $evidence | ConvertTo-Json -Depth 8 -Compress
    $json | Out-File -FilePath (Join-Path $evidenceRoot 'evidence.json') -Encoding Ascii
    Log-Output "[MANA-EVIDENCE-JSON]$json" | Tee-Object -FilePath $logFile -Append
    Log-Output "END: verdict $verdict. Evidence at $evidenceRoot" | Tee-Object -FilePath $logFile -Append
}
catch {
    $overallStatus = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
}
finally {
    # Leave every disk exactly as attached, so a later repair script can bring it online writable.
    $notRestored = @(Restore-Disk-Partitions-v3)
    if ($notRestored.Count) {
        $overallStatus = $STATUS_ERROR
        Log-Error "Disk $($notRestored -join ', ') could not be returned to offline and writable. Before running a repair script, run diskpart: select disk <n>, offline disk, attributes disk clear readonly." | Tee-Object -FilePath $logFile -Append
    }
}

return $overallStatus
