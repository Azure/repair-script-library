<#
.SYNOPSIS
    VMAgent Offline Fixer - Restores Guest Agent registry keys and binaries from a rescue VM.

.DESCRIPTION
    This script runs from a rescue VM to repair a broken Azure Guest Agent on an attached OS disk.
    It performs the following steps:
    1. Uses the shared repair-library partition helper to locate the faulty OS drive.
    2. Loads the SYSTEM registry hive from the target disk into HKLM\BROKENSYSTEM.
    3. Creates and verifies a binary backup of the SYSTEM hive before loading it.
     4. Validates the same-disk BCD loader and repairs unknown device mappings before registry writes.
     5. Identifies and validates the existing boot-referenced ControlSets from the Select key.
     6. Exports healthy service keys (WindowsAzureGuestAgent, WindowsAzureTelemetryService, RdAgent)
         from the rescue VM and injects them into every boot-referenced ControlSet on the target hive.
     7. Verifies both required services use automatic startup and have non-empty ImagePath values.
     8. Stages the complete WindowsAzure repository from the rescue VM and verifies the exact
         executables referenced by both required services. The existing repository is restored
         if activation fails.
     9. Releases handles, reloads the persisted SYSTEM hive, and verifies the required service keys.
         If processing fails, restores and hash-verifies SYSTEM, Agent files, and any changed BCD.

.NOTES
    Name:    GA_offlinefixer.ps1
    Version: 1.3
    Original Author: Daniel Munoz L (damunozl@microsoft.com)
    Modified by: Tony.Mocanu@Microsoft.com

.VERSION
    v1.3: [August 2026] - Stages and atomically replaces the complete WindowsAzure repository.
                        - Verifies both required service executables in the staged repository.
                                                - Follows the Microsoft Learn offline VM Agent registry and binary-copy procedure.
                                                - Aligns disk safety, rollback accounting, and rescue service restoration with
                                                    win-LKGC and win-sac-onLatest.
                                                - Validates the same-disk Gen1/Gen2 BCD store before Guest Agent changes.
                                                - Repairs and verifies only unknown loader device/osdevice mappings.
                                                - Restores the verified BCD backup after any later transaction failure.
                                                - Reloads the persisted on-disk SYSTEM hive and re-verifies required services.
                                                - Writes GA-OfflineRepair-Verification.json to correlate the repaired disk after restore.
                                                - Uses a PowerShell 3-compatible streaming SHA-256 implementation.
                                                - Emits structured telemetry only through the local VMRepair logger.
                                                - Performs no IMDS lookup or other telemetry network request.
                        - Preserves unrelated content in the target WindowsAzure folder.
                        - Stages and validates replacement files before moving the existing Agent folder.
                        - Rolls back the Agent folder and SYSTEM hive after partial repair failures.
                        - Bounds file-copy retries to avoid client repair jobs appearing stuck.
                        - Unloads only stale repair hives that actually exist.
                        - Uses the same partition discovery and collision handling as win-sac-onLatest.
                        - Preserves the Gen2 source GPT GUID by temporarily changing only the
                        - matching disposable repair VM OS disk GUID.
                        - Temporarily changes and restores source identity only for Gen1 MBR disks.
                        - Identifies and excludes the rescue VM OS disk by physical disk number.
                        - Requires an attached Microsoft virtual disk before service or disk disruption.
                        - Groups candidates by physical disk and validates winload plus the SYSTEM hive.
                        - Temporarily mounts unlettered Windows partition candidates and cleans them up.
                        - Detects collision-offlined attached disks before target discovery.
                        - Restores and verifies the original WSearch service state.
                        - No longer stops Windows Defender on the rescue VM.
                        - Makes fallback hive copy-back part of per-disk success accounting.
                        - Removes the unnecessary Azure Instance Metadata Service request.
                        - Validates the WindowsAzure robocopy source and staged destination content.
                        - Updated the script (current)
                        - Aligned nested VM detection with win-LKGC guard pattern.
                        - Skips Get-VM safely when Hyper-V module is unavailable.
                        - Fixed relative path evaluation bug for helper files.
                        - Updated the script again (current)
                        - Fixed breaking exception when the Hyper-V module is not installed on the host.
                        - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.2: [May 2026] - Updated the script
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v0.1: Initial commit. This was the version 1.0 of the script.

.SCENARIO_RECREATION
    Use only on a disposable test VM with a snapshot or recoverable OS disk.
    Run GA_offlinefixer_testbreaker.ps1 on the healthy test VM before detaching its OS disk:
.\GA_offlinefixer_testbreaker.ps1 -Mode Break -ConfirmDestructiveTest
    The breaker exports both required service keys and moves the complete WindowsAzure repository
    into a timestamped backup. It intentionally preserves the Agent SOFTWARE keys and C:\Packages.
    To undo the test without running the offline fixer:
.\GA_offlinefixer_testbreaker.ps1 -Mode Restore -BackupPath 'C:\GAOfflineRepairTestBackups\<timestamp>'
    After creating the test state, shut down the VM, run the offline fixer through VM Repair,
    restore the repaired OS disk, boot the VM, and complete the .VERIFICATION checks below.

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-GA-fix --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "$env:USERPROFILE\Desktop\GA_offlinefixer_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "VMAgent offline repair completed" and return code 0 ($STATUS_SUCCESS).
    This verifies only the offline registry and file repair. Agent readiness must be verified after restore and boot.
    2. Reload the SYSTEM hive and verify agent service keys exist (replace F with disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
$defaultSet = 'ControlSet{0:D3}' -f (Get-ItemProperty -Path 'HKLM:\VERIFY\Select').Default
Get-ItemProperty -Path "HKLM:\VERIFY\$defaultSet\Services\WindowsAzureGuestAgent" -Name Start, ImagePath
Get-ItemProperty -Path "HKLM:\VERIFY\$defaultSet\Services\RdAgent" -Name Start, ImagePath
reg unload HKLM\VERIFY
    Expected: ImagePath values are populated and Start is 2 for both services.
    3. Verify the WindowsAzure repository was copied to the target disk:
Get-ChildItem F:\WindowsAzure -Force
    Expected: The exact executables referenced by both service ImagePath values are present and non-empty.
    4. After az vm repair restore, verify that the repaired disk was actually reattached:
Get-Content C:\ProgramData\GA-OfflineRepair-Verification.json
    Expected: ScriptVersion is 1.3 and PersistedSystemHiveVerified is true.
#>

# Initialization (path-validated)
# $PSScriptRoot is empty when RunCommand executes scripts as a ScriptBlock (Invoke-Expression / [ScriptBlock]::Create).
# Fall back to the call stack, which PowerShell still attributes to the originating file path.
$resolvedScriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    $resolvedScriptRoot = Split-Path -Parent (Get-PSCallStack | Where-Object { $_.ScriptName } | Select-Object -First 1).ScriptName
}
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    Write-Error "Cannot determine script directory: PSScriptRoot is empty and call stack provides no path."
    return 1
}

$initPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\setup\init.ps1'
$diskPartitionsPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'
if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

if (-not (Test-Path -Path $diskPartitionsPath -PathType Leaf)) {
    Log-Error "Missing required dependency: $diskPartitionsPath"
    return $STATUS_ERROR
}

. $diskPartitionsPath

if (-not (Get-Command -Name Get-Disk-Partitions -CommandType Function -ErrorAction SilentlyContinue)) {
    Log-Error "Dependency did not define the required Get-Disk-Partitions function: $diskPartitionsPath"
    return $STATUS_ERROR
}

# Log Configuration (desktop log standard)
$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath)) {
    $desktopPath = Join-Path $env:PUBLIC 'Desktop'
}

$logDir = Join-Path $desktopPath 'RepairLogs'
if (-not (Test-Path -LiteralPath $logDir)) {
    $null = New-Item -ItemType Directory -Path $logDir -Force
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logDir "GA_offlinefixer_$timestamp.log"

if (-not (Test-Path -LiteralPath $logFile)) {
    $null = New-Item -Path $logFile -ItemType File -Force
}

function Write-DesktopLogLine {
    param([string]$Message)
    if ($null -ne $Message) {
        Add-Content -LiteralPath $logFile -Value ("[{0}] {1}" -f (Get-Date -Format 's'), $Message)
    }
}

$script:_origLogInfo    = (Get-Command Log-Info    -ErrorAction SilentlyContinue).ScriptBlock
$script:_origLogWarning = (Get-Command Log-Warning -ErrorAction SilentlyContinue).ScriptBlock
$script:_origLogError   = (Get-Command Log-Error   -ErrorAction SilentlyContinue).ScriptBlock
$script:_origLogOutput  = (Get-Command Log-Output  -ErrorAction SilentlyContinue).ScriptBlock

if ($script:_origLogInfo) {
    function Write-GaInfo {
        param([string]$Message)
        & $script:_origLogInfo $Message
        Write-DesktopLogLine "[INFO] $Message"
    }
}
if ($script:_origLogWarning) {
    function Write-GaWarning {
        param([string]$Message)
        & $script:_origLogWarning $Message
        Write-DesktopLogLine "[WARN] $Message"
    }
}
if ($script:_origLogError) {
    function Write-GaError {
        param([string]$Message)
        & $script:_origLogError $Message
        Write-DesktopLogLine "[ERROR] $Message"
    }
}
if ($script:_origLogOutput) {
    function Write-GaOutput {
        param([string]$Message)
        & $script:_origLogOutput $Message
        Write-DesktopLogLine "[OUTPUT] $Message"
    }
}

$script:RepairScriptVersion = '1.3'
$script:ExecutionStarted = Get-Date
$script:OperationCount = 0

function Write-GaTelemetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Operation', 'Success', 'Error')]
        [string]$Event,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [hashtable]$Properties = @{}
    )

    $payload = [ordered]@{
        Event = $Event
        Message = $Message
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RepairScriptVersion = $script:RepairScriptVersion
        Properties = $Properties
    }
    $json = $payload | ConvertTo-Json -Compress -Depth 8
    if ($Event -eq 'Error') {
        Write-GaError "[Telemetry] $json" | Out-Null
    }
    else {
        Write-GaInfo "[Telemetry] $json" | Out-Null
    }
}

function Invoke-CriticalCommand {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $script:OperationCount++
    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        foreach ($line in @($output)) {
            Write-GaInfo "$Description :: $line"
        }
    }

    Write-GaTelemetry -Event Operation -Message $Description -Properties @{
        Command = $Command
        ExitCode = "$exitCode"
        Success = ($exitCode -eq 0)
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = @($output)
    }
}

function Get-GaFileSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

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

function Get-GaServiceExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetDriveLetter
    )

    $expandedImagePath = [Environment]::ExpandEnvironmentVariables($ImagePath).Trim()
    $executablePath = if ($expandedImagePath.StartsWith('"')) {
        ($expandedImagePath -split '"')[1]
    }
    else {
        ($expandedImagePath -split '\s+')[0]
    }

    if ([string]::IsNullOrWhiteSpace($executablePath) -or $executablePath -notmatch '^[A-Za-z]:\\') {
        throw "Service ImagePath '$ImagePath' does not contain an absolute executable path."
    }

    return ($executablePath -replace '^[A-Za-z]:', "${TargetDriveLetter}:")
}

function Get-AvailableTempDriveLetter {
    $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter)

    foreach ($letter in @('Z','Y','X','W','V','U','T','S','R','Q')) {
        if ($letter -notin $usedLetters -and -not (Test-Path -LiteralPath "${letter}:\")) {
            return $letter
        }
    }

    return $null
}

function Invoke-GaDiskPart {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Commands,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $output = $Commands | diskpart.exe 2>&1
    foreach ($line in @($output)) {
        if ($line) { Write-GaInfo "diskpart $Operation :: $line" }
    }
}

function Invoke-GaBcdEdit {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $script:OperationCount++
    $output = & bcdedit.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    foreach ($line in @($output)) {
        if ($line) { Write-GaInfo "bcdedit $Operation :: $line" }
    }
    Write-GaTelemetry -Event Operation -Message "bcdedit $Operation" -Properties @{
        ExitCode = "$exitCode"
        Success = ($exitCode -eq 0)
    }
    return [pscustomobject]@{
        Output = @($output)
        ExitCode = $exitCode
        Success = ($exitCode -eq 0)
    }
}

function Get-GaDiskIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber
    )

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

function Set-GaTemporarySourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    if ($Record.PartitionStyle -ne 'MBR') {
        throw 'Temporary source disk identities are permitted only for the Gen1 MBR path.'
    }

    Invoke-GaDiskPart -Operation 'collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
        'online disk'
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-GaDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw "Disk $($Record.DiskNumber) could not be brought online with its verified temporary identity."
    }
}

function Restore-GaOriginalSourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    if ($Record.PartitionStyle -ne 'MBR') {
        throw 'Source disk identity restoration is permitted only for the Gen1 MBR path.'
    }

    Invoke-GaDiskPart -Operation 'collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        'offline disk'
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-GaDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if (-not $restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw "Disk $($Record.DiskNumber) did not return to its original offline identity."
    }
}

function Set-GaTemporaryRepairDiskIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-GaDiskPart -Operation 'repair-host-collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-GaDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw 'The repair VM OS disk did not retain a verified temporary GPT identity.'
    }
}

function Restore-GaRepairDiskIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-GaDiskPart -Operation 'repair-host-collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-GaDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw 'The repair VM OS disk did not return to its original GPT identity.'
    }
}

# Status Tracking
$script_final_status = $STATUS_ERROR
$serviceStates = @{}  # Track original service states for restoration
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0
$temporaryOsMounts = @()
$collisionDiskRecords = @()
$gptCollisionDiskNumbers = @()
$repairDiskIdentityRecord = $null
$successMessage = $null

# Local execution context for diagnostic logging. No data is transmitted off-box.
$vmMetadata = @{
    OSVersion = $null
    HostName = $env:COMPUTERNAME
}

try {
    # Capture OS version from rescue VM
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($osInfo) {
            $vmMetadata.OSVersion = "$($osInfo.Caption) $($osInfo.Version)"
        }
    }
    catch {
        Write-GaWarning "OS metadata discovery failed: $($_.Exception.Message)"
    }

    # Create metadata context string for logging
    $metadataContext = "[Host:$($vmMetadata.HostName)"
    if ($vmMetadata.OSVersion) { $metadataContext += " OS:$($vmMetadata.OSVersion)" }
    $metadataContext += "]"

    Write-GaInfo "Starting VMAgent Offline Fixer... $metadataContext"
    Write-GaInfo "Desktop log file path: $logFile"
    Write-GaInfo "[script_start] Script=GA_offlinefixer Version=$($script:RepairScriptVersion)"
    Write-GaTelemetry -Event Start -Message 'Starting VMAgent offline repair' -Properties @{
        ScriptName = 'GA_offlinefixer.ps1'
        ScriptVersion = $script:RepairScriptVersion
        ExecutionMode = 'REPAIR_VM_ONLY'
        HostName = $vmMetadata.HostName
        OSVersion = $vmMetadata.OSVersion
        DesktopLog = $logFile
        NetworkTelemetry = $false
    }
    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-GaInfo "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-GaWarning "Failed to stop nested guest VM, will continue but may have limited success"
                    }
                }
            }
        } else {
            Write-GaInfo "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-GaWarning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Clean up stale hive mounts from previous failed runs
    Write-GaInfo "Cleaning up any stale registry hive mounts..."
    $staleHivePaths = @(
        & reg.exe query HKLM 2>$null
        & reg.exe query HKU 2>$null
    ) | Where-Object {
        $_ -match '^HKEY_LOCAL_MACHINE\\(?:BROKENSYSTEM|BROKENSW)(?:_[C-Z])?$' -or
        $_ -match '^HKEY_USERS\\(?:BROKENSYSTEM|BROKENSYS|BROKENSW)(?:_[C-Z])?$'
    }
    foreach ($staleHivePath in $staleHivePaths) {
        Write-GaInfo "Unloading stale repair hive $staleHivePath..."
        & reg.exe unload $staleHivePath 2>$null
    }

    # Log any externally loaded hives (diagnostic)
    $hklmKeys = & reg.exe query HKLM 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    $hkuKeys = & reg.exe query HKU 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    if ($hklmKeys) { Write-GaInfo "Loaded HKLM hives: $($hklmKeys -join ', ')" }
    if ($hkuKeys) { Write-GaInfo "Loaded HKU hives: $($hkuKeys -join ', ')" }

    # Identify the rescue OS disk before stopping services or touching any disk.
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $rescueOsPartition = Get-Partition -DriveLetter $rescueDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $rescueOsPartition -or $null -eq $rescueOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the rescue VM OS disk from $($env:SystemDrive)."
    }
    $rescueDiskNum = [int]$rescueOsPartition.DiskNumber
    $repairDiskIdentity = Get-GaDiskIdentity -DiskNumber $rescueDiskNum
    Write-GaInfo "Rescue VM OS disk identified as physical Disk $rescueDiskNum ($($repairDiskIdentity.PartitionStyle))."

    # Azure rescue VMs can place the pagefile on a separate temporary resource disk.
    # Windows treats that disk as critical even though it is not the rescue OS disk.
    $protectedDiskNumbers = @($rescueDiskNum)
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
        if ($pageFilePartition) {
            $protectedDiskNumbers += [int]$pageFilePartition.DiskNumber
        }
    }
    $protectedDiskNumbers = @($protectedDiskNumbers | Sort-Object -Unique)
    Write-GaInfo "Protected rescue disk numbers excluded from repair: $($protectedDiskNumbers -join ', ')."

    $azureVirtualDiskNumbers = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
        Where-Object { $_.Model -like 'Microsoft Virtual Disk*' } |
        ForEach-Object { [int]$_.Index })
    $attachedDisks = @(Get-Disk -ErrorAction Stop | Where-Object {
        $_.Number -in $azureVirtualDiskNumbers -and $_.Number -notin $protectedDiskNumbers
    })
    if ($attachedDisks.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: No attached Microsoft virtual disk was found. No service or disk changes were attempted.'
    }

    $collisionDisks = @($attachedDisks | Where-Object {
        $_.IsOffline -and [string]$_.OfflineReason -eq 'Collision'
    })
    foreach ($collisionDisk in $collisionDisks) {
        $originalIdentity = Get-GaDiskIdentity -DiskNumber $collisionDisk.Number
        if ($originalIdentity.PartitionStyle -eq 'GPT') {
            if ($repairDiskIdentity.PartitionStyle -ne 'GPT' -or $repairDiskIdentity.Value -ine $originalIdentity.Value) {
                throw "Disk $($collisionDisk.Number) reports a GPT identity collision, but its GUID does not match the repair VM OS disk. Refusing an unverified identity change."
            }

            if (-not $repairDiskIdentityRecord) {
                $temporaryRepairGuid = ([guid]::NewGuid()).ToString('D')
                $repairDiskIdentityRecord = [pscustomobject]@{
                    DiskNumber = $rescueDiskNum
                    PartitionStyle = 'GPT'
                    OriginalValue = $repairDiskIdentity.Value
                    OriginalDiskPartValue = $repairDiskIdentity.DiskPartValue
                    TemporaryValue = $temporaryRepairGuid
                    TemporaryDiskPartValue = $temporaryRepairGuid
                }

                Write-GaWarning 'Temporarily changing only the repair VM OS disk GPT identity. The attached source disk GUID will remain unchanged.'
                Set-GaTemporaryRepairDiskIdentity -Record $repairDiskIdentityRecord
            }

            $gptCollisionDiskNumbers += [int]$collisionDisk.Number
            Invoke-GaDiskPart -Operation 'source-gpt-online' -Commands @(
                "select disk $($collisionDisk.Number)"
                'online disk'
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $releasedDisk = Get-Disk -Number $collisionDisk.Number -ErrorAction Stop
            $sourceIdentityAfterRelease = Get-GaDiskIdentity -DiskNumber $collisionDisk.Number
            if ($releasedDisk.IsOffline -or
                [string]$releasedDisk.OfflineReason -eq 'Collision' -or
                $sourceIdentityAfterRelease.Value -ine $originalIdentity.Value) {
                throw "Disk $($collisionDisk.Number) could not be onlined with its original GPT identity unchanged."
            }

            Write-GaInfo "Disk $($collisionDisk.Number) collision released; source GPT identity remains $($originalIdentity.Value)."
            continue
        }

        do {
            $temporaryValue = ([Convert]::ToUInt32(([guid]::NewGuid().ToString('N').Substring(0, 8)), 16)).ToString('X8')
        } while ($temporaryValue -eq '00000000' -or $temporaryValue -ieq $originalIdentity.Value)

        $record = [pscustomobject]@{
            DiskNumber = [int]$collisionDisk.Number
            PartitionStyle = $originalIdentity.PartitionStyle
            OriginalValue = $originalIdentity.Value
            OriginalDiskPartValue = $originalIdentity.DiskPartValue
            TemporaryValue = $temporaryValue
            TemporaryDiskPartValue = $temporaryValue
        }
        $collisionDiskRecords += $record

        Write-GaWarning "Disk $($record.DiskNumber) is offline due to an identity collision. Applying a temporary MBR identity for this repair run."
        Set-GaTemporarySourceIdentity -Record $record
        Write-GaInfo "Disk $($record.DiskNumber) is online with a verified temporary MBR identity."
    }

    $attachedDisks = @($attachedDisks | ForEach-Object { Get-Disk -Number $_.Number -ErrorAction Stop })
    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    Write-GaInfo "Attached repair candidate disk numbers: $($attachedDiskNumbers -join ', ')"

    $partitionlist = @(Get-Disk-Partitions)
    if ($partitionlist.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }

    $discoveredDiskNumbers = @($partitionlist | Select-Object -ExpandProperty DiskNumber -Unique)
    Write-GaInfo "Get-Disk-Partitions discovered disk numbers: $($discoveredDiskNumbers -join ', ')"
    $targetDiskGroups = @($partitionlist |
        Where-Object {
            [int]$_.DiskNumber -in $attachedDiskNumbers -and
            [int]$_.DiskNumber -notin $protectedDiskNumbers
        } |
        Group-Object DiskNumber)
    if ($targetDiskGroups.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: The shared partition helper returned no partitions from an attached repair disk.'
    }

    # Pause indexing while attached hives are modified. Defender remains running.
    Write-GaInfo "Stopping Windows Search temporarily to reduce attached-disk file locks..."
    foreach ($svc in @('WSearch')) {
        try {
            $svcObj = Get-Service -Name $svc -ErrorAction Stop
            if ($svcObj) {
                $serviceStates[$svc] = [string]$svcObj.Status
                Write-GaInfo "Captured original state of $svc : $($svcObj.Status)"
                if ($svcObj.Status -ne 'Stopped') {
                    Stop-Service -Name $svc -ErrorAction Stop
                    $svcObj.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                    Write-GaInfo "$svc stopped temporarily."
                }
            }
        }
        catch {
            throw "Could not safely capture or stop $svc before disk repair: $($_.Exception.Message)"
        }
    }

    # Step 1 - Find one validated Windows volume on each attached physical disk.
    $targetWindowsVolumes = @()
    $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
    foreach ($diskGroup in $targetDiskGroups) {
        $diskNumber = [int]$diskGroup.Name
        $diskPartitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop)
        if ($diskPartitions.Count -eq 0) {
            Write-GaWarning "Attached repair Disk $diskNumber has no partitions."
            $skippedCount++
            continue
        }
        $targetVolume = $null

        foreach ($candidate in @($diskPartitions | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne [char]0 })) {
            $candidateLetter = [string]$candidate.DriveLetter
            $winloadExe = "${candidateLetter}:\Windows\System32\winload.exe"
            $winloadEfi = "${candidateLetter}:\Windows\System32\winload.efi"
            $systemHive = "${candidateLetter}:\Windows\System32\config\SYSTEM"
            if (((Test-Path -LiteralPath $winloadExe -PathType Leaf) -or
                    (Test-Path -LiteralPath $winloadEfi -PathType Leaf)) -and
                (Test-Path -LiteralPath $systemHive -PathType Leaf)) {
                $targetVolume = [pscustomobject]@{
                    DiskNumber = $diskNumber
                    PartitionNumber = [int]$candidate.PartitionNumber
                    DriveLetter = $candidateLetter
                    TemporaryMount = $false
                }
                break
            }
        }

        if (-not $targetVolume) {
            $unletteredCandidates = @($diskPartitions | Where-Object {
                (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0) -and
                (([string]$_.GptType).Trim().Trim('{', '}') -ine $efiGptType)
            } | Sort-Object Size -Descending)

            foreach ($candidate in $unletteredCandidates) {
                $candidateLetter = Get-AvailableTempDriveLetter
                if (-not $candidateLetter) {
                    throw "No temporary drive letter is available to inspect unlettered partitions on Disk $diskNumber."
                }

                Invoke-GaDiskPart -Operation 'os-assign' -Commands @(
                    "select disk $diskNumber"
                    "select partition $($candidate.PartitionNumber)"
                    "assign letter=$candidateLetter"
                )
                Start-Sleep -Seconds 2

                $mounted = Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container
                $probeMount = [pscustomobject]@{
                    DiskNumber = $diskNumber
                    PartitionNumber = [int]$candidate.PartitionNumber
                    DriveLetter = $candidateLetter
                    TemporaryMount = $true
                }
                if ($mounted) {
                    $temporaryOsMounts += $probeMount
                }
                $winloadExe = "${candidateLetter}:\Windows\System32\winload.exe"
                $winloadEfi = "${candidateLetter}:\Windows\System32\winload.efi"
                $systemHive = "${candidateLetter}:\Windows\System32\config\SYSTEM"
                if ($mounted -and
                    ((Test-Path -LiteralPath $winloadExe -PathType Leaf) -or
                        (Test-Path -LiteralPath $winloadEfi -PathType Leaf)) -and
                    (Test-Path -LiteralPath $systemHive -PathType Leaf)) {
                    $targetVolume = $probeMount
                    break
                }

                Invoke-GaDiskPart -Operation 'os-probe-remove' -Commands @(
                    "select disk $diskNumber"
                    "select partition $($candidate.PartitionNumber)"
                    "remove letter=$candidateLetter noerr"
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                $probePartition = Get-Partition -DiskNumber $diskNumber -PartitionNumber $candidate.PartitionNumber -ErrorAction Stop
                if ([string]$probePartition.DriveLetter -ieq $candidateLetter) {
                    throw "Temporary letter ${candidateLetter}: could not be removed from Disk $diskNumber Partition $($candidate.PartitionNumber)."
                }
                $temporaryOsMounts = @($temporaryOsMounts | Where-Object {
                    -not ($_.DiskNumber -eq $diskNumber -and
                        $_.PartitionNumber -eq $candidate.PartitionNumber -and
                        $_.DriveLetter -ieq $candidateLetter)
                })
            }
        }

        if ($targetVolume) {
            $targetWindowsVolumes += $targetVolume
            Write-GaInfo "Validated Windows target on Disk $diskNumber Partition $($targetVolume.PartitionNumber) at $($targetVolume.DriveLetter):."
        }
        else {
            $skippedCount++
            Write-GaWarning "Disk $diskNumber has no partition containing both a Windows loader and SYSTEM hive."
        }
    }

    if ($targetWindowsVolumes.Count -eq 0) {
        throw 'No attached Windows OS disk passed loader and SYSTEM hive validation.'
    }

    $fixedDisks = @()
    $failedDisks = @()

    foreach ($targetVolume in $targetWindowsVolumes) {
        $processedCount++
        $diskb = [string]$targetVolume.DriveLetter
        Write-GaInfo "Processing validated target Disk $($targetVolume.DiskNumber) on letter $($diskb):"
        Write-GaTelemetry -Event Operation -Message 'Starting Guest Agent repair on validated disk' -Properties @{
            DiskNumber = "$($targetVolume.DiskNumber)"
            PartitionNumber = "$($targetVolume.PartitionNumber)"
            DriveLetter = $diskb
        }
        # Step 2 - Load the SYSTEM registry hive from the target disk
        $hiveName = "BROKENSYSTEM_$diskb"
        $hiveSource = "$($diskb):\Windows\System32\config\SYSTEM"
        $hiveCopy = $null
        $backupFile = $null
        $restoreHiveBackup = $false
        $diskProcessedSuccessfully = $false
        $diskChangesCompleted = $false
        $targetAgentFolder = $null
        $targetAgentBackup = $null
        $existingAgentMoved = $false
        $agentFolderActivated = $false
        $bcdPath = $null
        $bcdBackup = $null
        $bcdWriteStarted = $false
        $bcdBackupRestored = $false
        & reg.exe unload "HKLM\$hiveName" 2>$null
        [System.GC]::Collect()
        Start-Sleep -Seconds 1

        try {
            $diskNumber = [int]$targetVolume.DiskNumber
            $diskPartitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop)
            $efiParts = @($diskPartitions | Where-Object {
                ([string]$_.GptType).Trim().Trim('{', '}') -ieq $efiGptType
            })
            $isGen2Disk = $efiParts.Count -gt 0
            $bcdCandidates = if ($isGen2Disk) { $efiParts } else { $diskPartitions }
            Write-GaInfo "Disk ${diskNumber}: validating $(if ($isGen2Disk) { 'Gen2/UEFI' } else { 'Gen1/BIOS' }) BCD before Guest Agent changes."

            foreach ($bcdCandidate in $bcdCandidates) {
                $candidateLetter = $null
                $letterAssignedByScript = $false
                if ($bcdCandidate.DriveLetter -and $bcdCandidate.DriveLetter -ne [char]0) {
                    $candidateLetter = [string]$bcdCandidate.DriveLetter
                }
                else {
                    $candidateLetter = Get-AvailableTempDriveLetter
                    if (-not $candidateLetter) { continue }
                    Invoke-GaDiskPart -Operation 'bcd-assign' -Commands @(
                        "select disk $diskNumber"
                        "select partition $($bcdCandidate.PartitionNumber)"
                        "assign letter=$candidateLetter"
                    )
                    Start-Sleep -Seconds 2
                    $letterAssignedByScript = Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container
                    if ($letterAssignedByScript) {
                        $temporaryOsMounts += [pscustomobject]@{
                            DiskNumber = $diskNumber
                            PartitionNumber = [int]$bcdCandidate.PartitionNumber
                            DriveLetter = $candidateLetter
                            TemporaryMount = $true
                        }
                    }
                }

                $candidateBcdPath = if ($isGen2Disk) {
                    "${candidateLetter}:\EFI\Microsoft\Boot\BCD"
                }
                else {
                    "${candidateLetter}:\Boot\BCD"
                }
                if ($candidateLetter -and (Test-Path -LiteralPath $candidateBcdPath -PathType Leaf)) {
                    $bcdPath = $candidateBcdPath
                    Write-GaInfo "Disk ${diskNumber}: selected BCD store $bcdPath."
                    break
                }

                if ($letterAssignedByScript) {
                    Invoke-GaDiskPart -Operation 'bcd-probe-remove' -Commands @(
                        "select disk $diskNumber"
                        "select partition $($bcdCandidate.PartitionNumber)"
                        "remove letter=$candidateLetter noerr"
                    )
                    Update-HostStorageCache -ErrorAction SilentlyContinue
                    $temporaryOsMounts = @($temporaryOsMounts | Where-Object {
                        -not ($_.DiskNumber -eq $diskNumber -and
                            $_.PartitionNumber -eq [int]$bcdCandidate.PartitionNumber -and
                            $_.DriveLetter -ieq $candidateLetter)
                    })
                }
            }

            if (-not $bcdPath) {
                throw "Disk $diskNumber has no generation-appropriate BCD store. No Guest Agent changes were attempted."
            }

            $bootManagerQuery = Invoke-GaBcdEdit -Arguments @('/store', $bcdPath, '/enum', 'bootmgr', '/v') -Operation 'query-bootmgr'
            if (-not $bootManagerQuery.Success) {
                throw "Could not enumerate boot manager from $bcdPath."
            }
            $defaultLine = $bootManagerQuery.Output | Select-String -Pattern '^\s*default\s+' | Select-Object -First 1
            if (-not $defaultLine -or $defaultLine -notmatch '\{([^}]+)\}') {
                throw "Could not identify the default Windows loader in $bcdPath."
            }
            $defaultLoaderId = $matches[0]
            if ($defaultLoaderId -notmatch '^(?i)\{[0-9a-f\-]{36}\}$') {
                throw "Default BCD loader identifier '$defaultLoaderId' is invalid."
            }

            $loaderQuery = Invoke-GaBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultLoaderId, '/v') -Operation 'validate-loader'
            $loaderText = $loaderQuery.Output -join "`n"
            $loaderPathMatch = [regex]::Match($loaderText, '(?im)^\s*path\s+(.+?)\s*$')
            $loaderDeviceMatch = [regex]::Match($loaderText, '(?im)^\s*device\s+(.+?)\s*$')
            $loaderOsDeviceMatch = [regex]::Match($loaderText, '(?im)^\s*osdevice\s+(.+?)\s*$')
            $loaderSystemRootMatch = [regex]::Match($loaderText, '(?im)^\s*systemroot\s+(.+?)\s*$')
            if (-not $loaderQuery.Success -or -not $loaderPathMatch.Success -or
                -not $loaderDeviceMatch.Success -or -not $loaderOsDeviceMatch.Success -or
                -not $loaderSystemRootMatch.Success) {
                throw "Default loader $defaultLoaderId is missing required mapping elements."
            }

            $originalLoaderPath = $loaderPathMatch.Groups[1].Value.Trim()
            $originalLoaderSystemRoot = $loaderSystemRootMatch.Groups[1].Value.Trim()
            if ($originalLoaderPath -notmatch '(?i)^\\Windows\\System32\\winload\.(exe|efi)$') {
                throw "Default loader $defaultLoaderId references unsupported path '$originalLoaderPath'."
            }
            $resolvedLoaderFile = Join-Path -Path "${diskb}:\" -ChildPath $originalLoaderPath.TrimStart('\')
            if (-not (Test-Path -LiteralPath $resolvedLoaderFile -PathType Leaf)) {
                throw "Default loader references '$originalLoaderPath', but '$resolvedLoaderFile' does not exist."
            }

            $repairLoaderDevice = $loaderDeviceMatch.Groups[1].Value.Trim() -match '(?i)^unknown$'
            $repairLoaderOsDevice = $loaderOsDeviceMatch.Groups[1].Value.Trim() -match '(?i)^unknown$'
            if ($repairLoaderDevice -or $repairLoaderOsDevice) {
                $bcdBackup = $bcdPath + '.GA.bak.' + $timestamp
                Copy-Item -LiteralPath $bcdPath -Destination $bcdBackup -Force -ErrorAction Stop
                if (-not (Test-Path -LiteralPath $bcdBackup -PathType Leaf) -or
                    (Get-Item -LiteralPath $bcdBackup -Force -ErrorAction Stop).Length -ne
                    (Get-Item -LiteralPath $bcdPath -Force -ErrorAction Stop).Length) {
                    throw "BCD backup verification failed for '$bcdBackup'."
                }
                Write-GaInfo "Disk ${diskNumber}: BCD backup created and verified at $bcdBackup."

                $validatedWindowsPartition = "partition=${diskb}:"
                $bcdWriteStarted = $true
                if ($repairLoaderDevice) {
                    $setDevice = Invoke-GaBcdEdit -Arguments @('/store', $bcdPath, '/set', $defaultLoaderId, 'device', $validatedWindowsPartition) -Operation 'repair-loader-device'
                    if (-not $setDevice.Success) { throw "Could not repair device for loader $defaultLoaderId." }
                }
                if ($repairLoaderOsDevice) {
                    $setOsDevice = Invoke-GaBcdEdit -Arguments @('/store', $bcdPath, '/set', $defaultLoaderId, 'osdevice', $validatedWindowsPartition) -Operation 'repair-loader-osdevice'
                    if (-not $setOsDevice.Success) { throw "Could not repair osdevice for loader $defaultLoaderId." }
                }

                $verifyLoader = Invoke-GaBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultLoaderId, '/v') -Operation 'verify-loader-mapping'
                $verifyText = $verifyLoader.Output -join "`n"
                $verifyPath = [regex]::Match($verifyText, '(?im)^\s*path\s+(.+?)\s*$')
                $verifyDevice = [regex]::Match($verifyText, '(?im)^\s*device\s+(.+?)\s*$')
                $verifyOsDevice = [regex]::Match($verifyText, '(?im)^\s*osdevice\s+(.+?)\s*$')
                $verifySystemRoot = [regex]::Match($verifyText, '(?im)^\s*systemroot\s+(.+?)\s*$')
                if (-not $verifyLoader.Success -or -not $verifyPath.Success -or
                    -not $verifyDevice.Success -or -not $verifyOsDevice.Success -or
                    -not $verifySystemRoot.Success -or
                    $verifyDevice.Groups[1].Value.Trim() -match '(?i)^unknown$' -or
                    $verifyOsDevice.Groups[1].Value.Trim() -match '(?i)^unknown$' -or
                    $verifyPath.Groups[1].Value.Trim() -ine $originalLoaderPath -or
                    $verifySystemRoot.Groups[1].Value.Trim() -ine $originalLoaderSystemRoot) {
                    throw "Loader mapping repair verification failed for $defaultLoaderId."
                }
                Write-GaInfo "Disk ${diskNumber}: BCD loader mapping repaired and verified."
            }
            else {
                Write-GaInfo "Disk ${diskNumber}: BCD loader mapping validated without changes."
            }
        }
        catch {
            Write-GaError "BCD preflight failed for Disk $($targetVolume.DiskNumber): $($_.Exception.Message)"
            if ($bcdWriteStarted -and $bcdBackup -and (Test-Path -LiteralPath $bcdBackup -PathType Leaf)) {
                try {
                    Copy-Item -LiteralPath $bcdBackup -Destination $bcdPath -Force -ErrorAction Stop
                    $bcdBackupRestored = $true
                    Write-GaWarning "Restored BCD backup after failed preflight: $bcdBackup"
                }
                catch {
                    Write-GaError "CRITICAL: Failed to restore BCD backup '$bcdBackup': $($_.Exception.Message)"
                }
            }
            $failedDisks += $diskb
            $failedCount++
            continue
        }

        try {
            $backupFile = "$($diskb):\SYSTEM_before_GA_changes_$diskb.hiv"
            Write-GaInfo "Creating binary SYSTEM hive backup at $backupFile..."
            Copy-Item -LiteralPath $hiveSource -Destination $backupFile -Force -ErrorAction Stop
            $sourceHiveHash = Get-GaFileSha256 -LiteralPath $hiveSource
            $backupHiveHash = Get-GaFileSha256 -LiteralPath $backupFile
            if ($sourceHiveHash -ne $backupHiveHash) {
                throw "Source and backup SHA256 hashes differ."
            }
            Write-GaInfo "Binary SYSTEM hive backup created and verified for $($diskb):."
        }
        catch {
            Write-GaError "Failed to create and verify SYSTEM hive backup for $($diskb):: $($_.Exception.Message)"
            $failedDisks += $diskb
            $failedCount++
            continue
        }

        Write-GaInfo "Loading SYSTEM hive from $($diskb): as $hiveName..."
        $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Retry once after a short wait
            Write-GaWarning "First reg load attempt failed for $($diskb):, retrying in 5 seconds..."
            Start-Sleep -Seconds 5
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            # Fallback: use esentutl.exe /y to copy locked hive via Windows Backup API semantics
            Write-GaWarning "Direct load failed. Trying esentutl copy fallback for $($diskb):..."
            $hiveCopy = "$env:TEMP\SYSTEM_COPY_$diskb"
            try {
                $esentResult = & esentutl.exe /y $hiveSource /d $hiveCopy /o 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $hiveCopy)) {
                    Write-GaInfo "Hive copied successfully to $hiveCopy via esentutl"
                    $loadResult = & reg.exe load "HKLM\$hiveName" $hiveCopy 2>&1
                }
                else {
                    Write-GaWarning "esentutl copy failed for $($diskb): $esentResult"
                }
            }
            catch {
                Write-GaWarning "esentutl fallback failed for $($diskb):: $($_.Exception.Message)"
            }
        }
        if ($LASTEXITCODE -ne 0) {
            Write-GaError "Failed to load Registry Hive from $($diskb): $loadResult"
            if ($hiveCopy -and (Test-Path $hiveCopy)) { Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue }
            $failedDisks += $diskb
            $failedCount++
            continue
        }
        Start-Sleep -Seconds 2

        try {
            # Step 4 - Identify existing boot-referenced ControlSets from the Select key.
            $selectPath = "Registry::HKLM\$hiveName\Select"
            $selectConfiguration = Get-ItemProperty -Path $selectPath -ErrorAction Stop
            $defaultSetID = [int]$selectConfiguration.Default
            if ($defaultSetID -lt 1) {
                throw "SYSTEM hive Select contains an invalid Default control-set reference: $defaultSetID."
            }

            $primarySet = 'ControlSet{0:D3}' -f $defaultSetID
            $targetControlSets = @(@(
                [int]$selectConfiguration.Current
                [int]$selectConfiguration.Default
                [int]$selectConfiguration.LastKnownGood
            ) | Where-Object { $_ -gt 0 } | Sort-Object -Unique | ForEach-Object {
                'ControlSet{0:D3}' -f $_
            })
            foreach ($targetControlSet in $targetControlSets) {
                if (-not (Test-Path -Path "Registry::HKLM\$hiveName\$targetControlSet\Services")) {
                    throw "SYSTEM hive Select references missing or incomplete $targetControlSet."
                }
            }

            if ($primarySet -notin $targetControlSets) {
                throw "Default control set $primarySet was not included in the validated repair targets."
            }
            Write-GaInfo "Validated boot-referenced ControlSets: $($targetControlSets -join ', ') (Default=$primarySet)"

            # Step 5 - Export healthy service keys and inject into every boot-referenced ControlSet.
            $requiredAgentServices = @('WindowsAzureGuestAgent', 'RdAgent')
            $services = @("WindowsAzureGuestAgent", "WindowsAzureTelemetryService", "RdAgent")

            foreach ($service in $services) {
                $regFile = "$($diskb):\$service.reg"
                # Check if service key exists on the rescue VM before attempting export
                $rescueServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
                if (-not (Test-Path -Path $rescueServiceKey)) {
                    if ($service -in $requiredAgentServices) {
                        throw "Required service '$service' was not found in the rescue VM registry."
                    }
                    Write-GaWarning "Optional service '$service' was not found in the rescue VM registry; skipping it."
                    continue
                }
                # Export healthy key from the current Rescue VM
                $serviceExportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("export", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service", "$regFile", "/y") -Description "reg export service $service"

                if ($serviceExportResult.ExitCode -eq 0 -and (Test-Path $regFile)) {
                    $originalContent = Get-Content $regFile
                    foreach ($targetControlSet in $targetControlSets) {
                        Write-GaInfo "Updating $service in $targetControlSet on $($diskb):..."
                        $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$targetControlSet"
                        $content | Set-Content $regFile
                        $importResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("import", $regFile) -Description "reg import $service into $targetControlSet ($diskb)"
                        if ($importResult.ExitCode -ne 0) {
                            throw "Failed to import $service into $targetControlSet for $($diskb): $($importResult.Output -join '; ')"
                        }
                    }
                    Remove-Item $regFile -Force
                }
                else {
                    $serviceExportText = $serviceExportResult.Output -join '; '
                    throw ("Failed to export service key for " + $service + " - " + $serviceExportText)
                }
            }

            # Step 6 - Validate required service configuration in every updated ControlSet.
            $targetServiceConfigurations = @{}
            foreach ($targetControlSet in $targetControlSets) {
                foreach ($requiredService in $requiredAgentServices) {
                    $servicePath = "Registry::HKLM\$hiveName\$targetControlSet\Services\$requiredService"
                    $serviceConfiguration = Get-ItemProperty -Path $servicePath -ErrorAction Stop
                    if ([string]::IsNullOrWhiteSpace([string]$serviceConfiguration.ImagePath)) {
                        throw "Required service '$requiredService' has an empty ImagePath in $targetControlSet."
                    }
                    if ([int]$serviceConfiguration.Start -ne 2) {
                        throw "Required service '$requiredService' is not configured for automatic startup in ${targetControlSet} (Start=$($serviceConfiguration.Start))."
                    }

                    if ($targetControlSet -eq $primarySet) {
                        $targetServiceConfigurations[$requiredService] = $serviceConfiguration
                    }
                    Write-GaInfo "Validated $requiredService in ${targetControlSet}: Start=2, ImagePath=$($serviceConfiguration.ImagePath)"
                }
            }
            # Step 7 - Stage and activate the complete, internally consistent Agent repository.
            $sourcePath = "C:\WindowsAzure"
            $destPath = "$($diskb):\WindowsAzure"
            $backupPath = "$($diskb):\WindowsazurefaultyGAbackup"

            if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
                throw "The rescue VM Agent repository does not exist: $sourcePath"
            }

            $targetAgentFolder = $destPath
            $stagingAgentFolder = "$($diskb):\.GA_WindowsAzure_repair_$([guid]::NewGuid().ToString('N'))"

            try {
                Write-GaInfo "Staging the complete VM Agent repository $sourcePath at $stagingAgentFolder..."
                $restoreCopyResult = Invoke-CriticalCommand -Command "robocopy.exe" -Arguments @(
                    $sourcePath, $stagingAgentFolder, '/E', '/COPY:DAT', '/DCOPY:DAT',
                    '/XJ', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP'
                ) -Description "robocopy complete WindowsAzure repository ($diskb)"
                if ($restoreCopyResult.ExitCode -ge 8) {
                    throw "Failed to stage the VM Agent repository on $($diskb): $($restoreCopyResult.Output -join '; ')"
                }

                $stagedLogsPath = Join-Path $stagingAgentFolder 'Logs'
                if (Test-Path -LiteralPath $stagedLogsPath) {
                    Remove-Item -LiteralPath $stagedLogsPath -Recurse -Force -ErrorAction Stop
                }

                foreach ($requiredService in $requiredAgentServices) {
                    $sourceExecutable = Get-GaServiceExecutablePath `
                        -ImagePath ([string]$targetServiceConfigurations[$requiredService].ImagePath) `
                        -TargetDriveLetter 'C'
                    $sourceAgentPrefix = $sourcePath.TrimEnd('\') + '\'
                    if (-not $sourceExecutable.StartsWith($sourceAgentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "Required service '$requiredService' points outside the rescue VM Agent repository: $sourceExecutable"
                    }

                    $relativeExecutable = $sourceExecutable.Substring($sourceAgentPrefix.Length)
                    $stagedExecutable = Join-Path $stagingAgentFolder $relativeExecutable
                    if (-not (Test-Path -LiteralPath $stagedExecutable -PathType Leaf)) {
                        throw "Required executable for service '$requiredService' was not found in the staged copy: $stagedExecutable"
                    }
                    $stagedExecutableInfo = Get-Item -LiteralPath $stagedExecutable -ErrorAction Stop
                    if ($stagedExecutableInfo.Length -le 0) {
                        throw "Required executable for service '$requiredService' is empty in the staged copy: $stagedExecutable"
                    }
                    Write-GaInfo "Validated staged $requiredService executable ($($stagedExecutableInfo.Length) bytes)."
                }

                if (Test-Path -LiteralPath $destPath) {
                    $null = New-Item -Path $backupPath -ItemType Directory -Force
                    $targetAgentBackup = Join-Path $backupPath "WindowsAzure_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                    Write-GaInfo "Moving the existing WindowsAzure repository to $targetAgentBackup..."
                    Move-Item -LiteralPath $destPath -Destination $targetAgentBackup -ErrorAction Stop
                    $existingAgentMoved = $true
                }

                Move-Item -LiteralPath $stagingAgentFolder -Destination $destPath -ErrorAction Stop
                $agentFolderActivated = $true
                Write-GaInfo "Activated the validated complete VM Agent repository at $destPath."
            }
            catch {
                $activationError = $_
                if (Test-Path -LiteralPath $stagingAgentFolder) {
                    Remove-Item -LiteralPath $stagingAgentFolder -Recurse -Force -ErrorAction SilentlyContinue
                }
                if ($existingAgentMoved -and $targetAgentBackup) {
                    if (Test-Path -LiteralPath $targetAgentFolder) {
                        Remove-Item -LiteralPath $targetAgentFolder -Recurse -Force -ErrorAction Stop
                    }
                    Move-Item -LiteralPath $targetAgentBackup -Destination $targetAgentFolder -ErrorAction Stop
                    $agentFolderActivated = $false
                    Write-GaWarning "Restored the original VM Agent repository after replacement failed."
                }
                throw $activationError
            }

            $diskChangesCompleted = $true
        }
        catch {
            Write-GaError "Failed to process $($diskb):: $($_.Exception.Message)"
            $restoreHiveBackup = $true
            $diskProcessedSuccessfully = $false
        }
        finally {
            # Step 8 - Release handles and safely unload the registry hive
            Write-GaInfo "Unloading registry hive $hiveName..."
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 3

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("unload", "HKLM\$hiveName") -Description "reg unload $hiveName attempt $i"
                if ($unloadResult.ExitCode -eq 0) { $unloaded = $true; break }
                Write-GaWarning "Unload attempt $i for $hiveName failed, retrying..."
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Write-GaError "Could not unload $hiveName hive - marking Disk $diskb as failed."
                $failedDisks += $diskb
            }

            if ($restoreHiveBackup -and $backupFile -and (Test-Path -LiteralPath $backupFile)) {
                if ($unloaded) {
                    Write-GaWarning "Repair processing failed; restoring the original SYSTEM hive from $backupFile."
                    try {
                        $expectedHiveHash = Get-GaFileSha256 -LiteralPath $backupFile
                        Copy-Item -LiteralPath $backupFile -Destination $hiveSource -Force -ErrorAction Stop
                        $actualHiveHash = Get-GaFileSha256 -LiteralPath $hiveSource
                        if ($actualHiveHash -ne $expectedHiveHash) {
                            throw "SYSTEM hive rollback verification failed: backup and restored hashes differ."
                        }
                        Write-GaInfo "Original SYSTEM hive restored and verified for $($diskb):."
                    }
                    catch {
                        Write-GaError "Failed to restore the original SYSTEM hive on $($diskb):: $($_.Exception.Message)"
                        $failedDisks += $diskb
                    }
                }
                else {
                    Write-GaError "Original SYSTEM hive for $($diskb): cannot be restored because $hiveName did not unload."
                    $failedDisks += $diskb
                }
            }
            # If direct loading failed, persist the fallback hive only after every repair check passed.
            elseif ($hiveCopy -and (Test-Path $hiveCopy)) {
                if ($unloaded) {
                    Write-GaInfo "Copying modified hive back to $hiveSource..."
                    try {
                        $expectedHiveHash = Get-GaFileSha256 -LiteralPath $hiveCopy
                        Copy-Item -LiteralPath $hiveCopy -Destination $hiveSource -Force -ErrorAction Stop
                        $actualHiveHash = Get-GaFileSha256 -LiteralPath $hiveSource
                        if ($actualHiveHash -ne $expectedHiveHash) {
                            throw "Hive copy-back verification failed: source and destination SHA256 hashes differ."
                        }
                        Write-GaInfo "Successfully copied and verified the modified hive back to $($diskb):"
                    }
                    catch {
                        Write-GaError "Failed to copy modified hive back to $($diskb):: $($_.Exception.Message)"
                        $failedDisks += $diskb
                    }
                }
                else {
                    Write-GaError "Modified fallback hive for $($diskb): cannot be copied back because $hiveName did not unload."
                    $failedDisks += $diskb
                }
            }

            if ($hiveCopy -and (Test-Path -LiteralPath $hiveCopy)) {
                Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue
            }

            $diskProcessedSuccessfully = $diskChangesCompleted -and ($diskb -notin $failedDisks)
            if ($diskProcessedSuccessfully) {
                $verificationHiveName = "GAVERIFY_$diskb"
                $verificationHiveLoaded = $false
                try {
                    & reg.exe unload "HKLM\$verificationHiveName" 2>$null | Out-Null
                    $verificationLoad = & reg.exe load "HKLM\$verificationHiveName" $hiveSource 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "Could not reload persisted SYSTEM hive: $($verificationLoad -join '; ')"
                    }
                    $verificationHiveLoaded = $true

                    foreach ($targetControlSet in $targetControlSets) {
                        foreach ($requiredService in $requiredAgentServices) {
                            $persistedServicePath = "Registry::HKLM\$verificationHiveName\$targetControlSet\Services\$requiredService"
                            $persistedConfiguration = Get-ItemProperty -Path $persistedServicePath -ErrorAction Stop
                            if ([int]$persistedConfiguration.Start -ne 2 -or
                                [string]::IsNullOrWhiteSpace([string]$persistedConfiguration.ImagePath)) {
                                throw "Persisted verification failed for $requiredService in $targetControlSet."
                            }
                        }
                    }
                    Write-GaInfo "Reloaded persisted SYSTEM hive and verified required Agent services for $($diskb):."
                }
                catch {
                    Write-GaError "Persisted SYSTEM verification failed for $($diskb):: $($_.Exception.Message)"
                    if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                    $diskProcessedSuccessfully = $false
                }
                finally {
                    if ($verificationHiveLoaded) {
                        [System.GC]::Collect()
                        [System.GC]::WaitForPendingFinalizers()
                        $verificationUnload = & reg.exe unload "HKLM\$verificationHiveName" 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            Write-GaError "Could not unload verification hive $verificationHiveName`: $($verificationUnload -join '; ')"
                            if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                            $diskProcessedSuccessfully = $false
                        }
                    }
                }
            }

            if ($diskProcessedSuccessfully) {
                try {
                    $verificationMarkerPath = "$($diskb):\ProgramData\GA-OfflineRepair-Verification.json"
                    $targetIdentity = Get-GaDiskIdentity -DiskNumber $targetVolume.DiskNumber
                    [ordered]@{
                        CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                        ScriptVersion = $script:RepairScriptVersion
                        DiskNumberOnRepairVm = [int]$targetVolume.DiskNumber
                        DiskPartitionStyle = $targetIdentity.PartitionStyle
                        DiskIdentityDuringRepair = $targetIdentity.Value
                        WindowsPartition = "$($diskb):"
                        ControlSets = @($targetControlSets)
                        RequiredServices = @($requiredAgentServices)
                        AgentFolder = $targetAgentFolder
                        BcdPath = $bcdPath
                        BcdMappingChanged = [bool]$bcdWriteStarted
                        PersistedSystemHiveVerified = $true
                    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $verificationMarkerPath -Encoding UTF8 -ErrorAction Stop
                    Write-GaInfo "Wrote post-restore correlation marker: $verificationMarkerPath"
                }
                catch {
                    Write-GaError "Could not write the repair correlation marker on $($diskb):: $($_.Exception.Message)"
                    if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                    $diskProcessedSuccessfully = $false
                }
            }

            if (-not $diskProcessedSuccessfully -and $diskChangesCompleted -and
                $backupFile -and (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
                try {
                    $expectedHiveHash = Get-GaFileSha256 -LiteralPath $backupFile
                    Copy-Item -LiteralPath $backupFile -Destination $hiveSource -Force -ErrorAction Stop
                    $actualHiveHash = Get-GaFileSha256 -LiteralPath $hiveSource
                    if ($actualHiveHash -ne $expectedHiveHash) {
                        throw 'SYSTEM hive rollback verification failed after a late transaction failure.'
                    }
                    Write-GaWarning "Restored original SYSTEM hive because the complete transaction did not finish for $($diskb):."
                }
                catch {
                    Write-GaError "CRITICAL: Failed to restore SYSTEM after a late transaction failure on $($diskb):: $($_.Exception.Message)"
                    if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                }
            }

            if (-not $diskProcessedSuccessfully -and $agentFolderActivated -and $targetAgentFolder) {
                try {
                    if (Test-Path -LiteralPath $targetAgentFolder) {
                        Remove-Item -LiteralPath $targetAgentFolder -Recurse -Force -ErrorAction Stop
                    }
                    if ($existingAgentMoved -and $targetAgentBackup) {
                        if (-not (Test-Path -LiteralPath $targetAgentBackup -PathType Container)) {
                            throw "Original VM Agent backup is missing: $targetAgentBackup"
                        }
                        Move-Item -LiteralPath $targetAgentBackup -Destination $targetAgentFolder -ErrorAction Stop
                        Write-GaWarning "Restored the original VM Agent repository because registry persistence did not complete."
                    }
                    else {
                        Write-GaWarning "Removed the newly introduced VM Agent repository because registry persistence did not complete."
                    }
                    $agentFolderActivated = $false
                }
                catch {
                    Write-GaError "Failed to roll back the VM Agent repository on $($diskb):: $($_.Exception.Message)"
                    if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                }
            }

            if (-not $diskProcessedSuccessfully -and $bcdWriteStarted -and
                -not $bcdBackupRestored -and $bcdBackup -and
                (Test-Path -LiteralPath $bcdBackup -PathType Leaf)) {
                try {
                    Copy-Item -LiteralPath $bcdBackup -Destination $bcdPath -Force -ErrorAction Stop
                    $bcdBackupRestored = $true
                    Write-GaWarning "Restored BCD backup because Guest Agent processing did not complete: $bcdBackup"
                }
                catch {
                    Write-GaError "CRITICAL: Failed to restore BCD backup '$bcdBackup': $($_.Exception.Message)"
                    if ($diskb -notin $failedDisks) { $failedDisks += $diskb }
                }
            }

            if ($diskProcessedSuccessfully) {
                $fixedDisks += $diskb
                $changedCount++
            }
            else {
                if ($diskb -notin $failedDisks) {
                    $failedDisks += $diskb
                }
                $failedCount++
            }
        }
    }

    if ($failedDisks.Count -gt 0) {
        Write-GaError "Processing failed on disks: $($failedDisks -join ', ')"
        throw "One or more disks failed backup, hive processing, unload, or copy-back validation: $($failedDisks -join ', '). Please review logs."
    }

    Write-GaInfo "Processing summary: processed=$processedCount skipped=$skippedCount failed=$failedCount changed=$changedCount"
    if ($fixedDisks.Count -gt 0) {
        $successMessage = "VMAgent offline repair completed on drives: $($fixedDisks -join ', '). Agent readiness must be verified after restore and boot. | Host=$($vmMetadata.HostName)"
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }

}
catch {
    $errorMessage = $_.Exception.Message
    Write-GaError "SCRIPT FAILED: $errorMessage"
    Write-GaTelemetry -Event Error -Message 'VMAgent offline repair failed' -Properties @{
        Error = $errorMessage
    }
    $script_final_status = $STATUS_ERROR
}
finally {
    foreach ($mount in @($temporaryOsMounts | Sort-Object DiskNumber, PartitionNumber -Unique)) {
        try {
            Write-GaInfo "Removing temporary OS letter $($mount.DriveLetter): from Disk $($mount.DiskNumber) Partition $($mount.PartitionNumber)."
            Invoke-GaDiskPart -Operation 'os-cleanup' -Commands @(
                "select disk $($mount.DiskNumber)"
                "select partition $($mount.PartitionNumber)"
                "remove letter=$($mount.DriveLetter) noerr"
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $cleanedPartition = Get-Partition -DiskNumber $mount.DiskNumber -PartitionNumber $mount.PartitionNumber -ErrorAction Stop
            if ([string]$cleanedPartition.DriveLetter -ieq [string]$mount.DriveLetter) {
                throw "Temporary drive letter removal could not be verified."
            }
            Write-GaInfo "Temporary OS letter $($mount.DriveLetter): removal verified."
        }
        catch {
            Write-GaError "Failed to remove temporary OS letter $($mount.DriveLetter): $($_.Exception.Message)"
            $script_final_status = $STATUS_ERROR
        }
    }

    $identityRestorationFailed = $false

    if ($repairDiskIdentityRecord) {
        foreach ($diskNumber in @($gptCollisionDiskNumbers | Sort-Object -Unique)) {
            try {
                Invoke-GaDiskPart -Operation 'source-before-repair-host-restore' -Commands @(
                    "select disk $diskNumber"
                    'offline disk'
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                $sourceDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
                $sourceIdentity = Get-GaDiskIdentity -DiskNumber $diskNumber
                if (-not $sourceDisk.IsOffline -or $sourceIdentity.Value -ine $repairDiskIdentityRecord.OriginalValue) {
                    throw "Source Disk $diskNumber was not offline with its unchanged original GPT identity."
                }
                Write-GaInfo "Source Disk $diskNumber is offline with its original GPT identity verified before repair host restoration."
            }
            catch {
                $identityRestorationFailed = $true
                Write-GaError "CRITICAL: Could not safely offline and verify source Disk ${diskNumber}: $($_.Exception.Message)"
            }
        }

        if (-not $identityRestorationFailed) {
            try {
                Restore-GaRepairDiskIdentity -Record $repairDiskIdentityRecord
                Write-GaInfo 'Repair VM OS disk GPT identity restored and verified.'
            }
            catch {
                $identityRestorationFailed = $true
                Write-GaError "CRITICAL: Failed to restore the repair VM OS disk identity: $($_.Exception.Message)"
            }
        }
    }

    foreach ($identityRecord in @($collisionDiskRecords | Sort-Object DiskNumber -Descending)) {
        try {
            Restore-GaOriginalSourceIdentity -Record $identityRecord
            Write-GaInfo "Disk $($identityRecord.DiskNumber) is offline with its verified original MBR identity restored."
        }
        catch {
            $identityRestorationFailed = $true
            Write-GaError "CRITICAL: Failed to restore original identity on Disk $($identityRecord.DiskNumber): $($_.Exception.Message)"
        }
    }

    if ($identityRestorationFailed) {
        $script_final_status = $STATUS_ERROR
    }

    # Log local execution context only; this script performs no telemetry upload.
    if ($vmMetadata.OSVersion) {
        Write-GaInfo "Execution Context - Host: $($vmMetadata.HostName), OS: $($vmMetadata.OSVersion)"
    }

    # Restore original service states
    Write-GaInfo "Restoring original service states..."
    foreach ($svc in $serviceStates.Keys) {
        try {
            $originalState = $serviceStates[$svc]
            Write-GaInfo "Restoring $svc to state: $originalState"
            if ($originalState -eq 'Running') {
                Start-Service -Name $svc -ErrorAction Stop
                $restoredService = Get-Service -Name $svc -ErrorAction Stop
                $restoredService.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
            elseif ($originalState -eq 'Stopped') {
                Stop-Service -Name $svc -Force -ErrorAction Stop
            }
            $restoredState = [string](Get-Service -Name $svc -ErrorAction Stop).Status
            if ($restoredState -ne $originalState) {
                throw "$svc restoration verification failed: expected $originalState, found $restoredState."
            }
            Write-GaInfo "$svc restored and verified in state $restoredState."
        }
        catch {
            Write-GaError "Failed to restore $svc to state $originalState : $($_.Exception.Message)"
            $script_final_status = $STATUS_ERROR
        }
    }

    if ($script_final_status -eq $STATUS_SUCCESS -and $successMessage) {
        Write-GaOutput $successMessage
    }

    $durationSeconds = [math]::Round(((Get-Date) - $script:ExecutionStarted).TotalSeconds, 3)
    $finalTelemetryProperties = @{
        FinalStatus = "$script_final_status"
        DurationSeconds = "$durationSeconds"
        Operations = "$($script:OperationCount)"
        DisksProcessed = "$processedCount"
        DisksChanged = "$changedCount"
        DisksSkipped = "$skippedCount"
        DisksFailed = "$failedCount"
    }
    if ($script_final_status -eq $STATUS_SUCCESS) {
        Write-GaTelemetry -Event Success -Message 'VMAgent offline repair completed successfully' -Properties $finalTelemetryProperties
    }
    else {
        Write-GaTelemetry -Event Error -Message 'VMAgent offline repair completed with errors' -Properties $finalTelemetryProperties
    }

    Write-GaInfo "[final_status] Status=$script_final_status"
    Write-GaInfo "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount operations=$($script:OperationCount)"
    Write-GaInfo "Execution ended at $(Get-Date)"
    Write-GaInfo "Desktop log file path: $logFile"
}

return $script_final_status