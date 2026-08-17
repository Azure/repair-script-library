<#
.SYNOPSIS
    Safely updates a registry value on a validated Windows OS disk attached to a repair VM.

.DESCRIPTION
    This script runs from a rescue VM to modify registry values on attached faulty OS disks.
    It performs the following steps:
    1. Stops any nested guest VM to ensure the attached disk is not in use.
    2. Identifies attached repair targets while excluding the repair VM's protected disks.
    3. Validates a Windows partition by requiring both an OS loader and the requested hive.
    4. Creates a binary hive backup, then loads the requested hive (skips the partition if load fails).
    5. Determines the active ControlSet (if using the SYSTEM hive) from the Select key.
    6. Reads the current value of the specified registry property (if it exists).
    7. Updates and verifies the specified property, creating a missing path only when explicitly requested.
    8. Unloads the registry hive cleanly.

    This resolves non-boot issues caused by registry misconfiguration (e.g., enabling RDP,
    changing service startup type, disabling problematic drivers).

.PARAMETER rootKey
    Root registry hive for offline mount. Valid values: HKLM and HKU.

.PARAMETER hive
    Standard offline hive file name under Windows\System32\config. Valid values:
    SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, COMPONENTS, and DRIVERS.

.PARAMETER controlSet
    Optional control set number for SYSTEM hive updates. Valid values: 1 or 2.
    If omitted for SYSTEM hive, the script uses Select\Current.

.PARAMETER relativePath
    Registry path relative to the loaded offline hive root.

.PARAMETER propertyName
    Registry property name to create or update.

.PARAMETER propertyValue
    Registry property value to write. Empty values are accepted only for string-based types.

.PARAMETER propertyType
    Registry value type. Valid values: String, ExpandString, Binary, DWord, MultiString, Qword, Unknown.
    If omitted, defaults to DWord.

.PARAMETER createPathIfMissing
    Optional Boolean. Defaults to false. Set to true only when the registry path is expected
    to be absent and should be created; this prevents path typos from silently creating keys.

.NOTES
    Name:    win-update-registry.ps1
    Version: 1.3
    Author:  Tony Mocanu / Tony.Mocanu@Microsoft.com

.VERSION
    v1.3: [August 2026] - Restricted offline hive mounts to HKLM and HKU.
                          - Uses native command exit codes as the authoritative load/unload result.
                          - Creates the hive backup before loading and rolls back failed writes.
                          - Requires explicit opt-in before creating a missing registry path.
                          - Aligns repair-host disk exclusion and Windows target validation with
                            win-sac-onLatest, win-LKGC, GA_offlinefixer, and win-chkdsk-fs-corruption.
                          - Verifies temporary mounts by access path and cleans up failed assignments.
                          - Uses typed temporary-mount records for Windows PowerShell 5.1 compatibility.
                          - Resolves the active ControlSet independently for each attached Windows disk.
                          - Reads back and verifies the requested registry value before reporting success.
        v1.2: [Jul 2026] - Updated the script
                       - Fixed DEP-01: Added Get-PSCallStack fallback when PSScriptRoot is empty
                         (e.g. when az vm repair run delivers the script as a ScriptBlock).
                         Emits a clear diagnostic and returns before constructing any helper paths.
    v1.1: [May 2026] - Fixed Get-VM failure when Hyper-V module is not available on host.
                       - Added guarded nested VM validation with safe fallback logging.
                       - Added explicit runtime parameter validation for rootKey, propertyType, controlSet, and required inputs.
                       - Updated helper import to Get-Disk-Partitions-v2 and aligned partition processing flow.
                       - Added rescue OS drive exclusion to avoid modifying the running rescue VM hive.
                       - Added per-partition reg load failure handling (skip bad partition, continue others).
                       - Added structured step-by-step logging, timestamped desktop log output, and final status tracking.
                       - Improved error handling to continue processing partitions safely and report aggregate result.
    v1.0: Initial version

.LINK
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty

.SCENARIO_RECREATION
    To recreate a testable scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Load the SYSTEM hive from the attached disk (replace F with actual drive letter):
reg load HKLM\TESTBREAK F:\Windows\System32\config\SYSTEM
    3. Set a known registry value to a "broken" state, e.g. disable RDP:
Set-ItemProperty -Path "HKLM:\TESTBREAK\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections -Type DWord -Value 1
    4. Verify value is set to 1 (broken):
Get-ItemProperty -Path "HKLM:\TESTBREAK\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections
    5. Unload the hive:
reg unload HKLM\TESTBREAK
    6. Run the script with parameters to fix it (set fDenyTSConnections back to 0).
    7. Reload the hive and verify the value is now 0.

.EXAMPLE
    az vm repair run -g sourceRG -n problemVM --run-id win-update-registry --run-on-repair --parameters rootKey=HKLM hive=SYSTEM controlSet=1 relativePath='Control\Terminal` Server' propertyName=fDenyTSConnections propertyValue=0 propertyType=dword

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "$([Environment]::GetFolderPath('Desktop'))\update-registry_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "Successfully modified registry key" and return code 0 ($STATUS_SUCCESS).
    2. Manually reload the hive and confirm the value was written (replace F with the attached disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections
reg unload HKLM\VERIFY
    3. For local testing, uncomment the DEBUG variables block below the init section,
    set them to the desired test values, run the script, then re-comment before deploying.
#>

# Initialization (no Param() block to avoid ParserErrors and argument transformation failures)

# ==============================================================================
# 1. DEPENDENCY PATH VALIDATION & INITIALIZATION (DEP-01)
# ==============================================================================
# $PSScriptRoot can be empty when invoked through ScriptBlock execution.
# Fall back to call stack script attribution to resolve the originating file directory.
$resolvedScriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    $resolvedScriptRoot = Split-Path -Parent (Get-PSCallStack | Where-Object { $_.ScriptName } | Select-Object -First 1).ScriptName
}
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    Write-Error "Cannot determine script directory: PSScriptRoot is empty and call stack provides no path."
    return 1
}

$initPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\setup\init.ps1'
$partitionsHelperPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'

if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

if (-not (Test-Path -Path $partitionsHelperPath -PathType Leaf)) {
    Log-Error "Missing required dependency: $partitionsHelperPath"
    return $STATUS_ERROR
}

. $partitionsHelperPath

if (-not (Get-Command -Name Get-Disk-Partitions -CommandType Function -ErrorAction SilentlyContinue)) {
    Log-Error "Dependency did not define the required Get-Disk-Partitions function: $partitionsHelperPath"
    return $STATUS_ERROR
}

# DEBUG: Uncomment below to test locally without --parameters
# $rootKey = 'HKLM'
# $hive = 'System'
# $controlSet = '1'
# $relativePath = 'Control\Terminal Server'
# $propertyName = 'fDenyTSConnections'
# $propertyValue = '1'
# $propertyType = 'dword'
# $createPathIfMissing = $false

# Parameter Validation (variables injected by az vm repair run --parameters)
if (-not $rootKey) { $rootKey = "HKLM" }
if (-not $hive) { $hive = "System" }
if (-not $propertyType) { $propertyType = "" }

$createPathIfMissingText = if ($null -eq $createPathIfMissing) { '' } else { ([string]$createPathIfMissing).Trim() }
if ([string]::IsNullOrEmpty($createPathIfMissingText)) {
    $createPathIfMissing = $false
}
elseif ($createPathIfMissingText -match '^(?i:true|1)$') {
    $createPathIfMissing = $true
}
elseif ($createPathIfMissingText -match '^(?i:false|0)$') {
    $createPathIfMissing = $false
}
else {
    Log-Error "Invalid createPathIfMissing '$createPathIfMissingText'. Valid values: true, false, 1, 0."
    return $STATUS_ERROR
}

$validRootKeys = @("HKLM", "HKU")
if ($rootKey -notin $validRootKeys) {
    Log-Error "Invalid rootKey '$rootKey'. Valid values: $($validRootKeys -join ', ')"
    return $STATUS_ERROR
}

$validHives = @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', 'DRIVERS')
if ($hive -notin $validHives) {
    Log-Error "Invalid hive '$hive'. Valid values: $($validHives -join ', ')"
    return $STATUS_ERROR
}

$validPropertyTypes = @("", "String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")
if ($propertyType -notin $validPropertyTypes) {
    Log-Error "Invalid propertyType '$propertyType'. Valid values: $($validPropertyTypes -join ', ')"
    return $STATUS_ERROR
}

if ($controlSet) {
    if ($controlSet -notin @(1, 2)) {
        Log-Error "Invalid controlSet '$controlSet'. Valid values: 1, 2"
        return $STATUS_ERROR
    }
    if ($hive -ine 'SYSTEM') {
        Log-Error "controlSet is valid only when hive is SYSTEM."
        return $STATUS_ERROR
    }
}

if ([string]::IsNullOrEmpty($relativePath)) {
    Log-Error "relativePath parameter is required."
    return $STATUS_ERROR
}

if ([string]::IsNullOrEmpty($propertyName)) {
    Log-Error "propertyName parameter is required."
    return $STATUS_ERROR
}

if ($null -eq $propertyValue) {
    Log-Error "propertyValue parameter is required."
    return $STATUS_ERROR
}
if ([string]::IsNullOrEmpty([string]$propertyValue) -and
    $propertyType -notin @('String', 'ExpandString', 'MultiString')) {
    Log-Error "An empty propertyValue requires propertyType String, ExpandString, or MultiString."
    return $STATUS_ERROR
}

$registryProviderRoot = if ($rootKey -eq 'HKLM') {
    'Registry::HKEY_LOCAL_MACHINE'
}
else {
    'Registry::HKEY_USERS'
}

# Log Configuration
$logDir = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($logDir) -or -not (Test-Path -LiteralPath $logDir)) {
    $logDir = 'C:\Users\Public\Desktop'
    if (-not (Test-Path -LiteralPath $logDir)) {
        $null = New-Item -ItemType Directory -Path $logDir -Force
    }
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\update-registry_$timestamp.log"

function Write-DesktopLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Message
    )

    $text = if ($null -eq $Message) { '' } else { ($Message | Out-String).TrimEnd() }
    $line = "$(Get-Date -Format o) [$Level] $text"
    Add-Content -Path $logFile -Value $line
}

function Write-InfoLog {
    param([string]$Message)
    Log-Info $Message
    Write-DesktopLog -Level 'INFO' -Message $Message
}

function Write-WarningLog {
    param([string]$Message)
    Log-Warning $Message
    Write-DesktopLog -Level 'WARN' -Message $Message
}

function Write-ErrorLog {
    param([string]$Message)
    Log-Error $Message
    Write-DesktopLog -Level 'ERROR' -Message $Message
}

function Write-OutputLog {
    param([AllowNull()]$Message)
    Log-Output $Message
    Write-DesktopLog -Level 'OUTPUT' -Message $Message
}

function Get-UpdateRegistryFileSha256 {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = $null
    $sha256 = $null
    try {
        $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
    }
    finally {
        if ($sha256) { $sha256.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Test-UpdateRegistryValue {
    param(
        [AllowNull()]$ActualValue,
        [AllowNull()]$ExpectedValue,
        [Parameter(Mandatory = $true)][string]$Type
    )

    switch -Regex ($Type) {
        '^(?i:DWord|Qword)$' {
            try { return [decimal]$ActualValue -eq [decimal]$ExpectedValue }
            catch { return $false }
        }
        '^(?i:Binary)$' {
            $actualItems = @($ActualValue)
            $expectedItems = @($ExpectedValue)
            if ($actualItems.Count -ne $expectedItems.Count) { return $false }
            for ($index = 0; $index -lt $actualItems.Count; $index++) {
                try {
                    if ([byte]$actualItems[$index] -ne [byte]$expectedItems[$index]) { return $false }
                }
                catch { return $false }
            }
            return $true
        }
        '^(?i:MultiString)$' {
            $actualItems = @($ActualValue)
            $expectedItems = @($ExpectedValue)
            if ($actualItems.Count -ne $expectedItems.Count) { return $false }
            for ($index = 0; $index -lt $actualItems.Count; $index++) {
                if ([string]$actualItems[$index] -cne [string]$expectedItems[$index]) { return $false }
            }
            return $true
        }
        default {
            return [string]$ActualValue -ceq [string]$ExpectedValue
        }
    }
}

function Get-UpdateRegistryAvailableDriveLetter {
    $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter)
    foreach ($candidateLetter in @('Z','Y','X','W','V','U','T','S','R','Q')) {
        if ($candidateLetter -notin $usedLetters -and -not (Test-Path -LiteralPath "${candidateLetter}:\")) {
            return $candidateLetter
        }
    }

    return $null
}

function Test-UpdateRegistryDataPartition {
    param([Parameter(Mandatory = $true)][object]$Partition)

    if ($Partition.IsHidden) { return $false }

    $gptType = ([string]$Partition.GptType).Trim().Trim('{', '}')
    if ($gptType) {
        return $gptType -ieq 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
    }

    return ([string]$Partition.Type) -notmatch 'Reserved|System'
}

function Invoke-UpdateRegistryDiskPart {
    param(
        [Parameter(Mandatory = $true)][string[]]$Commands,
        [Parameter(Mandatory = $true)][string]$Operation
    )

    $output = $Commands | diskpart.exe 2>&1
    foreach ($line in @($output)) {
        if ($line) { Write-InfoLog "[diskpart][$Operation] $line" }
    }
}

function Get-UpdateRegistryDiskIdentity {
    param([Parameter(Mandatory = $true)][int]$DiskNumber)

    $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
    if ([string]$disk.PartitionStyle -eq 'MBR') {
        $signature = [uint32]$disk.Signature
        return [pscustomobject]@{
            PartitionStyle = 'MBR'
            Value = $signature.ToString('X8')
            DiskPartValue = $signature.ToString('X8')
        }
    }
    if ([string]$disk.PartitionStyle -eq 'GPT') {
        $diskGuid = ([guid]$disk.Guid).ToString('D')
        return [pscustomobject]@{
            PartitionStyle = 'GPT'
            Value = $diskGuid
            DiskPartValue = $diskGuid
        }
    }

    throw "Disk $DiskNumber has unsupported partition style '$($disk.PartitionStyle)'."
}

function Set-UpdateRegistryTemporarySourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    if ($Record.PartitionStyle -ne 'MBR') {
        throw 'Temporary source disk identities are permitted only for MBR disks.'
    }
    Invoke-UpdateRegistryDiskPart -Operation 'collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
        'online disk'
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw "Disk $($Record.DiskNumber) could not be brought online with its verified temporary identity."
    }
}

function Restore-UpdateRegistrySourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-UpdateRegistryDiskPart -Operation 'collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        'offline disk'
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if (-not $restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw "Disk $($Record.DiskNumber) did not return to its original offline identity."
    }
}

function Set-UpdateRegistryTemporaryRepairIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-UpdateRegistryDiskPart -Operation 'repair-host-collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw 'The repair VM OS disk did not retain a verified temporary GPT identity.'
    }
}

function Restore-UpdateRegistryRepairIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-UpdateRegistryDiskPart -Operation 'repair-host-collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw 'The repair VM OS disk did not return to its original GPT identity.'
    }
}

# Status Tracking
$script_final_status = $STATUS_ERROR
$temporaryMounts = @()
$collisionDiskRecords = @()
$gptCollisionDiskNumbers = @()
$repairDiskIdentityRecord = $null

try {
    Write-InfoLog "START: Running script win-update-registry.ps1"
    Write-InfoLog "Log file path: $logFile"
    Write-InfoLog "Parameters: rootKey=$rootKey, hive=$hive, controlSet=$controlSet, relativePath=$relativePath, propertyName=$propertyName, propertyValue=$propertyValue, propertyType=$propertyType, createPathIfMissing=$createPathIfMissing"

    $processedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $changedCount = 0

    # Step 1 - Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-InfoLog "Stopping nested guest VM $guestHyperVVirtualMachineName"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-WarningLog "Failed to stop nested guest VM $guestHyperVVirtualMachineName, will continue but may have limited success"
                    }
                }
            }
            else {
                Write-InfoLog "No running nested guest VM, continuing"
            }
        }
        else {
            Write-InfoLog "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-WarningLog "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Step 2 - Identify every repair-host disk before touching attached disks.
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $rescueOsPartition = Get-Partition -DriveLetter $rescueDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $rescueOsPartition -or $null -eq $rescueOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the repair VM OS disk from $($env:SystemDrive)."
    }
    $rescueDiskNumber = [int]$rescueOsPartition.DiskNumber
    $repairDiskIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $rescueDiskNumber

    $protectedDiskNumbers = @($rescueDiskNumber)
    $protectedDiskNumbers += @(Get-Disk -ErrorAction Stop |
        Where-Object { $_.IsBoot -or $_.IsSystem } |
        Select-Object -ExpandProperty Number)
    $pageFileDriveLetters = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ([string]$_.Name -match '^([A-Za-z]):\\') { $matches[1] }
        } | Select-Object -Unique)
    foreach ($pageFileDriveLetter in $pageFileDriveLetters) {
        $pageFilePartition = Get-Partition -DriveLetter $pageFileDriveLetter -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($pageFilePartition) { $protectedDiskNumbers += [int]$pageFilePartition.DiskNumber }
    }
    $protectedDiskNumbers = @($protectedDiskNumbers | Sort-Object -Unique)
    Write-InfoLog "Protected repair-host disk numbers: $($protectedDiskNumbers -join ', ')"

    $azureVirtualDiskNumbers = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
        Where-Object { $_.Model -like 'Microsoft Virtual Disk*' } |
        ForEach-Object { [int]$_.Index })
    $attachedDisks = @(Get-Disk -ErrorAction Stop | Where-Object {
        $_.Number -in $azureVirtualDiskNumbers -and $_.Number -notin $protectedDiskNumbers
    })
    if ($attachedDisks.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: No attached Microsoft virtual disk was found.'
    }

    # Preserve source identities when an attached clone collides with the repair disk.
    foreach ($collisionDisk in @($attachedDisks | Where-Object {
        $_.IsOffline -and [string]$_.OfflineReason -eq 'Collision'
    })) {
        $originalIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $collisionDisk.Number
        if ($originalIdentity.PartitionStyle -eq 'GPT') {
            if ($repairDiskIdentity.PartitionStyle -ne 'GPT' -or
                $repairDiskIdentity.Value -ine $originalIdentity.Value) {
                throw "Disk $($collisionDisk.Number) has an unverified GPT identity collision."
            }
            if (-not $repairDiskIdentityRecord) {
                $temporaryRepairGuid = ([guid]::NewGuid()).ToString('D')
                $repairDiskIdentityRecord = [pscustomobject]@{
                    DiskNumber = $rescueDiskNumber
                    PartitionStyle = 'GPT'
                    OriginalValue = $repairDiskIdentity.Value
                    OriginalDiskPartValue = $repairDiskIdentity.DiskPartValue
                    TemporaryValue = $temporaryRepairGuid
                    TemporaryDiskPartValue = $temporaryRepairGuid
                }
                Write-WarningLog 'Temporarily changing only the repair VM OS disk GPT identity; the source identity remains unchanged.'
                Set-UpdateRegistryTemporaryRepairIdentity -Record $repairDiskIdentityRecord
            }

            $gptCollisionDiskNumbers += [int]$collisionDisk.Number
            Invoke-UpdateRegistryDiskPart -Operation 'source-gpt-online' -Commands @(
                "select disk $($collisionDisk.Number)"
                'online disk'
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $releasedDisk = Get-Disk -Number $collisionDisk.Number -ErrorAction Stop
            $releasedIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $collisionDisk.Number
            if ($releasedDisk.IsOffline -or $releasedIdentity.Value -ine $originalIdentity.Value) {
                throw "Disk $($collisionDisk.Number) could not be onlined with its original GPT identity unchanged."
            }
            continue
        }

        do {
            $temporaryValue = ([Convert]::ToUInt32(([guid]::NewGuid().ToString('N').Substring(0, 8)), 16)).ToString('X8')
        } while ($temporaryValue -eq '00000000' -or $temporaryValue -ieq $originalIdentity.Value)
        $identityRecord = [pscustomobject]@{
            DiskNumber = [int]$collisionDisk.Number
            PartitionStyle = 'MBR'
            OriginalValue = $originalIdentity.Value
            OriginalDiskPartValue = $originalIdentity.DiskPartValue
            TemporaryValue = $temporaryValue
            TemporaryDiskPartValue = $temporaryValue
        }
        $collisionDiskRecords += $identityRecord
        Set-UpdateRegistryTemporarySourceIdentity -Record $identityRecord
    }

    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    $partitionList = @(Get-Disk-Partitions)
    $targetDiskGroups = @($partitionList |
        Where-Object {
            [int]$_.DiskNumber -in $attachedDiskNumbers -and
            [int]$_.DiskNumber -notin $protectedDiskNumbers
        } |
        Group-Object DiskNumber)
    if ($targetDiskGroups.Count -eq 0) {
        throw 'The partition helper returned no partitions from an attached repair disk.'
    }

    # Step 3 - Validate exactly one Windows partition per attached physical disk.
    $validatedPartitions = @()
    foreach ($targetDiskGroup in $targetDiskGroups) {
        $diskNumber = [int]$targetDiskGroup.Name
        $diskPartitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop)
        $targetPartition = $null
        $targetDriveLetter = $null

        foreach ($candidatePartition in @($diskPartitions | Sort-Object Size -Descending)) {
            if (-not (Test-UpdateRegistryDataPartition -Partition $candidatePartition)) { continue }

            $candidateLetter = [string]$candidatePartition.DriveLetter
            if (-not $candidateLetter -or $candidateLetter -eq [char]0) {
                $candidateLetter = Get-UpdateRegistryAvailableDriveLetter
                if (-not $candidateLetter) {
                    throw "No temporary drive letter is available to inspect Disk $diskNumber."
                }
                $mountTracked = $false
                try {
                    Invoke-UpdateRegistryDiskPart -Operation 'os-probe-assign' -Commands @(
                        "select disk $diskNumber"
                        "select partition $($candidatePartition.PartitionNumber)"
                        "assign letter=$candidateLetter"
                    )
                    Update-HostStorageCache -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    if (-not (Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container)) {
                        throw "Temporary mount ${candidateLetter}: failed for Disk $diskNumber Partition $($candidatePartition.PartitionNumber)."
                    }
                    $temporaryMounts += [pscustomobject]@{
                        DiskNumber = [int]$diskNumber
                        PartitionNumber = [int]$candidatePartition.PartitionNumber
                        DriveLetter = [string]$candidateLetter
                    }
                    $mountTracked = $true
                }
                catch {
                    if (-not $mountTracked) {
                        Invoke-UpdateRegistryDiskPart -Operation 'failed-os-probe-cleanup' -Commands @(
                            "select disk $diskNumber"
                            "select partition $($candidatePartition.PartitionNumber)"
                            "remove letter=$candidateLetter noerr"
                        )
                        Update-HostStorageCache -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        if (Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container) {
                            throw "Failed temporary mount ${candidateLetter}: could not be removed from Disk $diskNumber Partition $($candidatePartition.PartitionNumber)."
                        }
                    }
                    throw
                }
            }

            $requestedHivePath = "${candidateLetter}:\Windows\System32\config\$hive"
            $winloadExe = "${candidateLetter}:\Windows\System32\winload.exe"
            $winloadEfi = "${candidateLetter}:\Windows\System32\winload.efi"
            if ((Test-Path -LiteralPath $requestedHivePath -PathType Leaf) -and
                ((Test-Path -LiteralPath $winloadExe -PathType Leaf) -or
                 (Test-Path -LiteralPath $winloadEfi -PathType Leaf))) {
                $targetPartition = $candidatePartition
                $targetDriveLetter = $candidateLetter
                break
            }
        }

        if (-not $targetPartition) {
            Write-WarningLog "Skipping Disk $diskNumber because no Windows loader and requested hive '$hive' were found."
            $skippedCount++
            continue
        }
        $validatedPartitions += [pscustomobject]@{
            DiskNumber = $diskNumber
            PartitionNumber = [int]$targetPartition.PartitionNumber
            DriveLetter = $targetDriveLetter
        }
        Write-InfoLog "Validated Windows target on Disk $diskNumber Partition $($targetPartition.PartitionNumber) at ${targetDriveLetter}:"
    }

    if ($validatedPartitions.Count -eq 0) {
        throw 'No attached Windows OS disk passed loader and requested-hive validation.'
    }

    Write-InfoLog 'Scanning validated Windows partitions for requested registry updates'

    foreach ($partition in $validatedPartitions) {
            if (-not $partition -or -not $partition.DriveLetter) { continue }

            $drive = $partition.DriveLetter
            $processedCount++

            $regPath = $drive + ':\Windows\System32\config\'
            if (-not (Test-Path $regPath)) {
                Write-InfoLog "No Registry found on $drive, skipping"
                $skippedCount++
                continue
            }

            $hiveSourcePath = "$($drive):\Windows\System32\config\$($hive)"
            $backupFile = Join-Path $logDir "backup-$hive-$drive-$timestamp.hiv"
            try {
                if (-not (Test-Path -LiteralPath $hiveSourcePath -PathType Leaf)) {
                    throw "Hive file not found for backup: $hiveSourcePath"
                }
                $sourceHash = Get-UpdateRegistryFileSha256 -LiteralPath $hiveSourcePath
                Copy-Item -LiteralPath $hiveSourcePath -Destination $backupFile -Force -ErrorAction Stop
                $backupHash = Get-UpdateRegistryFileSha256 -LiteralPath $backupFile
                if ($backupHash -ine $sourceHash) {
                    throw "Hive backup hash mismatch for drive $drive."
                }
                Write-InfoLog "Created hive backup before load: $backupFile"
            }
            catch {
                Write-ErrorLog "Failed to create a hive backup for drive ${drive}: $($_.Exception.Message)"
                $failedCount++
                continue
            }

            # Step 4 - Load requested registry hive from attached disk
            $mountName = "broken$($hive)$($drive)"
            $nativeMountPath = "$rootKey\$mountName"
            $providerMountPath = "$registryProviderRoot\$mountName"
            if (Test-Path -LiteralPath $providerMountPath) {
                Write-WarningLog "Removing stale repair hive mount: $nativeMountPath"
                $preUnloadResult = & reg.exe unload $nativeMountPath 2>&1 | Out-String
                $preUnloadExitCode = $LASTEXITCODE
                Write-OutputLog "stale reg unload exit code: $preUnloadExitCode"
                Write-OutputLog "stale reg unload output: $preUnloadResult"
                if ($preUnloadExitCode -ne 0) {
                    Write-ErrorLog "Failed to remove stale hive mount '$nativeMountPath'. Skipping drive $drive."
                    $failedCount++
                    continue
                }
            }
            Write-InfoLog "Loading $hive hive from $($drive):"
            $loadResult = & reg.exe load $nativeMountPath $hiveSourcePath 2>&1 | Out-String
            $loadExitCode = $LASTEXITCODE
            Write-OutputLog "reg load exit code: $loadExitCode"
            Write-OutputLog "reg load output: $loadResult"

            # If reg load failed, skip this partition entirely
            if ($loadExitCode -ne 0) {
                Write-WarningLog "Failed to load $hive hive from $($drive), skipping partition"
                $failedCount++
                continue
            }

            $restoreRequired = $false
            $writeAttempted = $false

            try {
                # Step 5 - Determine the active ControlSet if using the SYSTEM hive
                if ($hive -eq "system") {
                    Write-InfoLog "Using a SYSTEM hive, determining Control Set"
                    $effectiveControlSet = $controlSet
                    if (-not $effectiveControlSet -or $effectiveControlSet -eq "") {
                        $effectiveControlSet = (Get-ItemProperty -Path "$providerMountPath\Select" -Name Current -ErrorAction Stop).Current
                    }
                    if ([int]$effectiveControlSet -lt 1) {
                        throw "SYSTEM hive Select contains an invalid Current control-set reference: $effectiveControlSet."
                    }
                    $controlSetText = 'ControlSet{0:D3}' -f [int]$effectiveControlSet
                    Write-InfoLog "Using $controlSetText"
                    $controlSetText += "\"
                }
                else {
                    $controlSetText = ""
                    Write-InfoLog "Not using a SYSTEM hive, targeting $hive directly"
                }

                # Step 6 - Read current value of the specified property
                $propPath = "$providerMountPath\$($controlSetText)$($relativePath)"
                Write-InfoLog "Target registry path: $propPath"
                $currentValue = Get-ItemProperty -Path $propPath -Name $propertyName -ErrorAction SilentlyContinue
                if ($currentValue) {
                    Write-OutputLog "Current value of '$propertyName': $($currentValue.$propertyName)"
                }
                else {
                    Write-InfoLog "Property '$propertyName' not found at path (will be created)"
                }

                # Step 7 - Create path if needed, then set the property value
                if ($propertyType -eq "") { $propertyType = "dword" }
                $writeAttempted = $true

                if (-not (Test-Path $propPath)) {
                    if (-not $createPathIfMissing) {
                        throw "Registry path does not exist: $propPath. Set createPathIfMissing=true only if creation is intended."
                    }
                    Write-InfoLog "Registry path does not exist, creating: $propPath"
                    New-Item -Path $propPath -Force -ErrorAction Stop | Out-Null
                }

                $modifiedKey = Set-ItemProperty -Path $propPath -Name $propertyName -Type $propertyType -Value $propertyValue -Force -ErrorAction Stop -PassThru
                $verifiedProperty = Get-ItemProperty -Path $propPath -Name $propertyName -ErrorAction Stop
                $verifiedValue = $verifiedProperty.$propertyName
                if (-not (Test-UpdateRegistryValue -ActualValue $verifiedValue -ExpectedValue $propertyValue -Type $propertyType)) {
                    throw "Post-write verification failed for '$propertyName' at '$propPath'."
                }
                Write-OutputLog "Successfully modified registry key"
                Write-OutputLog "Updated '$propertyName' to '$propertyValue' (type '$propertyType') at '$propPath'"
                Write-OutputLog "Verified '$propertyName' persisted as '$verifiedValue'"
                Write-OutputLog $modifiedKey

                $script_final_status = $STATUS_SUCCESS
                $changedCount++
            }
            catch {
                Write-ErrorLog "Failed to modify registry hive on $($drive): $($_.Exception.Message)"
                Write-ErrorLog "Will attempt rollback from backup after unloading hive."
                $script_final_status = $STATUS_ERROR
                $failedCount++
                $restoreRequired = $writeAttempted
            }
            finally {
                # Step 8 - Unload the registry hive cleanly
                Write-InfoLog "Unloading registry hive from $($drive)"
                $unloadSuccess = $false
                for ($attempt = 1; $attempt -le 3; $attempt++) {
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    $unloadResult = & reg.exe unload $nativeMountPath 2>&1 | Out-String
                    $unloadExitCode = $LASTEXITCODE
                    Write-OutputLog "reg unload attempt $attempt exit code: $unloadExitCode"
                    Write-OutputLog "reg unload attempt $attempt output: $unloadResult"

                    if ($unloadExitCode -eq 0) {
                        $unloadSuccess = $true
                        break
                    }

                    if ($attempt -lt 3) {
                        Write-WarningLog "Unload attempt $attempt failed for drive $drive. Retrying."
                    }
                }

                if (-not $unloadSuccess) {
                    Write-ErrorLog "Failed to unload hive after retries for drive $drive"
                    $failedCount++
                    $script_final_status = $STATUS_ERROR
                }

                if ($restoreRequired -and $backupFile) {
                    if ($unloadSuccess) {
                        try {
                            Copy-Item -LiteralPath $backupFile -Destination $hiveSourcePath -Force -ErrorAction Stop
                            $restoredHash = Get-UpdateRegistryFileSha256 -LiteralPath $hiveSourcePath
                            if ($restoredHash -ine $backupHash) {
                                throw "Restored hive hash does not match the verified backup."
                            }
                            Write-WarningLog "Rollback applied from backup: $backupFile"
                        }
                        catch {
                            Write-ErrorLog "Rollback failed for drive $drive using backup '$backupFile': $($_.Exception.Message)"
                            $script_final_status = $STATUS_ERROR
                        }
                    }
                    else {
                        Write-ErrorLog "Rollback skipped because hive unload did not succeed for drive $drive"
                    }
                }
            }
        }

    Write-InfoLog "Summary: processed=$processedCount skipped=$skippedCount failed=$failedCount changed=$changedCount"

    if ($changedCount -gt 0 -and $failedCount -eq 0) {
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        $script_final_status = $STATUS_ERROR
        Write-ErrorLog "Registry update did not complete successfully on every validated target."
    }
}
catch {
    Write-ErrorLog "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    foreach ($mount in @($temporaryMounts | Sort-Object DiskNumber, PartitionNumber -Unique)) {
        try {
            Invoke-UpdateRegistryDiskPart -Operation 'mount-cleanup' -Commands @(
                "select disk $($mount.DiskNumber)"
                "select partition $($mount.PartitionNumber)"
                "remove letter=$($mount.DriveLetter) noerr"
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            if (Test-Path -LiteralPath "$($mount.DriveLetter):\" -PathType Container) {
                throw 'Temporary drive letter removal could not be verified.'
            }
        }
        catch {
            Write-ErrorLog "Failed to remove temporary letter $($mount.DriveLetter): $($_.Exception.Message)"
            $script_final_status = $STATUS_ERROR
        }
    }

    $identityRestorationFailed = $false
    if ($repairDiskIdentityRecord) {
        foreach ($diskNumber in @($gptCollisionDiskNumbers | Sort-Object -Unique)) {
            try {
                Invoke-UpdateRegistryDiskPart -Operation 'source-before-repair-host-restore' -Commands @(
                    "select disk $diskNumber"
                    'offline disk'
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                $sourceDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
                $sourceIdentity = Get-UpdateRegistryDiskIdentity -DiskNumber $diskNumber
                if (-not $sourceDisk.IsOffline -or
                    $sourceIdentity.Value -ine $repairDiskIdentityRecord.OriginalValue) {
                    throw "Source Disk $diskNumber was not offline with its unchanged original GPT identity."
                }
            }
            catch {
                $identityRestorationFailed = $true
                Write-ErrorLog "CRITICAL: Could not safely offline source Disk ${diskNumber}: $($_.Exception.Message)"
            }
        }
        if (-not $identityRestorationFailed) {
            try {
                Restore-UpdateRegistryRepairIdentity -Record $repairDiskIdentityRecord
                Write-InfoLog 'Repair VM OS disk GPT identity restored and verified.'
            }
            catch {
                $identityRestorationFailed = $true
                Write-ErrorLog "CRITICAL: Failed to restore the repair VM OS disk identity: $($_.Exception.Message)"
            }
        }
    }

    foreach ($identityRecord in @($collisionDiskRecords | Sort-Object DiskNumber -Descending)) {
        try {
            Restore-UpdateRegistrySourceIdentity -Record $identityRecord
            Write-InfoLog "Disk $($identityRecord.DiskNumber) original MBR identity restored and verified."
        }
        catch {
            $identityRestorationFailed = $true
            Write-ErrorLog "CRITICAL: Failed to restore Disk $($identityRecord.DiskNumber) identity: $($_.Exception.Message)"
        }
    }
    if ($identityRestorationFailed) { $script_final_status = $STATUS_ERROR }

    Write-InfoLog "Final status: $script_final_status"
    Write-InfoLog "Script ended at $(Get-Date)"
    Write-InfoLog "Log file path: $logFile"
}

return $script_final_status
