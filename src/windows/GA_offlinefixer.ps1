<#
.SYNOPSIS
    VMAgent Offline Fixer - Restores Guest Agent registry keys and binaries from a rescue VM.

.DESCRIPTION
    This script runs from a rescue VM to repair a broken Azure Guest Agent on an attached OS disk.
    It performs the following steps:
    1. Uses the shared repair-library partition helper to locate the faulty OS drive.
    2. Loads the SYSTEM registry hive from the target disk into HKLM\BROKENSYSTEM.
    3. Creates and verifies a binary backup of the SYSTEM hive before loading it.
    4. Identifies the primary and backup ControlSets (001/002) from the Select key.
    5. Exports healthy service keys (WindowsAzureGuestAgent, WindowsAzureTelemetryService, RdAgent)
       from the rescue VM and injects them into both ControlSets on the target hive.
     6. Verifies both required services use automatic startup and have non-empty ImagePath values.
     7. Copies the latest GuestAgent installation folder, or the documented ImagePath folder fallback,
         into a staging directory and verifies the exact executables referenced by both required services.
         The existing Agent folder is restored if activation fails.
    8. Releases handles and safely unloads the registry hive (with retry logic).
         If processing fails, restores and hash-verifies the original SYSTEM hive.

.NOTES
    Name:    GA_offlinefixer.ps1
    Version: 1.3
    Original Author: Daniel Munoz L (damunozl@microsoft.com)
    Modified by: Tony.Mocanu@Microsoft.com

.VERSION
    v1.3: [August 2026] - Copies only the newest versioned GuestAgent installation folder.
                        - Uses the WindowsAzureGuestAgent ImagePath folder as a fallback.
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
                        - Validates WindowsAzure xcopy source and destination content.
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
    The breaker exports both required service keys and moves C:\WindowsAzure into a timestamped
    backup. It intentionally preserves the Agent SOFTWARE keys and C:\Packages because those
    artifacts are outside this fixer's documented offline recovery scope.
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
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\WindowsAzureGuestAgent" -Name ImagePath
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\RdAgent" -Name ImagePath
reg unload HKLM\VERIFY
    Expected: ImagePath values are populated and Start is 2 for both services.
    3. Verify GuestAgent binaries were copied to the target disk:
Get-ChildItem F:\WindowsAzure\GuestAgent_*
    Expected: The exact executables referenced by both service ImagePath values are present and non-empty.
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
    function Log-Info {
        param([string]$Message)
        & $script:_origLogInfo $Message
        Write-DesktopLogLine "[INFO] $Message"
    }
}
if ($script:_origLogWarning) {
    function Log-Warning {
        param([string]$Message)
        & $script:_origLogWarning $Message
        Write-DesktopLogLine "[WARN] $Message"
    }
}
if ($script:_origLogError) {
    function Log-Error {
        param([string]$Message)
        & $script:_origLogError $Message
        Write-DesktopLogLine "[ERROR] $Message"
    }
}
if ($script:_origLogOutput) {
    function Log-Output {
        param([string]$Message)
        & $script:_origLogOutput $Message
        Write-DesktopLogLine "[OUTPUT] $Message"
    }
}

function Invoke-CriticalCommand {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        foreach ($line in @($output)) {
            Log-Info "$Description :: $line"
        }
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = @($output)
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
        if ($line) { Log-Info "diskpart $Operation :: $line" }
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
        Log-Warning "OS metadata discovery failed: $($_.Exception.Message)"
    }

    # Create metadata context string for logging
    $metadataContext = "[Host:$($vmMetadata.HostName)"
    if ($vmMetadata.OSVersion) { $metadataContext += " OS:$($vmMetadata.OSVersion)" }
    $metadataContext += "]"

    Log-Info "Starting VMAgent Offline Fixer... $metadataContext"
    Log-Info "Desktop log file path: $logFile"
    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Log-Warning "Failed to stop nested guest VM, will continue but may have limited success"
                    }
                }
            }
        } else {
            Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Log-Warning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Clean up stale hive mounts from previous failed runs
    Log-Info "Cleaning up any stale registry hive mounts..."
    $staleHivePaths = @(
        & reg.exe query HKLM 2>$null
        & reg.exe query HKU 2>$null
    ) | Where-Object {
        $_ -match '^HKEY_LOCAL_MACHINE\\(?:BROKENSYSTEM|BROKENSW)(?:_[C-Z])?$' -or
        $_ -match '^HKEY_USERS\\(?:BROKENSYSTEM|BROKENSYS|BROKENSW)(?:_[C-Z])?$'
    }
    foreach ($staleHivePath in $staleHivePaths) {
        Log-Info "Unloading stale repair hive $staleHivePath..."
        & reg.exe unload $staleHivePath 2>$null
    }

    # Log any externally loaded hives (diagnostic)
    $hklmKeys = & reg.exe query HKLM 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    $hkuKeys = & reg.exe query HKU 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    if ($hklmKeys) { Log-Info "Loaded HKLM hives: $($hklmKeys -join ', ')" }
    if ($hkuKeys) { Log-Info "Loaded HKU hives: $($hkuKeys -join ', ')" }

    # Identify the rescue OS disk before stopping services or touching any disk.
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $rescueOsPartition = Get-Partition -DriveLetter $rescueDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $rescueOsPartition -or $null -eq $rescueOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the rescue VM OS disk from $($env:SystemDrive)."
    }
    $rescueDiskNum = [int]$rescueOsPartition.DiskNumber
    $repairDiskIdentity = Get-GaDiskIdentity -DiskNumber $rescueDiskNum
    Log-Info "Rescue VM OS disk identified as physical Disk $rescueDiskNum ($($repairDiskIdentity.PartitionStyle))."

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
    Log-Info "Protected rescue disk numbers excluded from repair: $($protectedDiskNumbers -join ', ')."

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

                Log-Warning 'Temporarily changing only the repair VM OS disk GPT identity. The attached source disk GUID will remain unchanged.'
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

            Log-Info "Disk $($collisionDisk.Number) collision released; source GPT identity remains $($originalIdentity.Value)."
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

        Log-Warning "Disk $($record.DiskNumber) is offline due to an identity collision. Applying a temporary MBR identity for this repair run."
        Set-GaTemporarySourceIdentity -Record $record
        Log-Info "Disk $($record.DiskNumber) is online with a verified temporary MBR identity."
    }

    $attachedDisks = @($attachedDisks | ForEach-Object { Get-Disk -Number $_.Number -ErrorAction Stop })
    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    Log-Info "Attached repair candidate disk numbers: $($attachedDiskNumbers -join ', ')"

    $partitionlist = @(Get-Disk-Partitions)
    if ($partitionlist.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }

    $discoveredDiskNumbers = @($partitionlist | Select-Object -ExpandProperty DiskNumber -Unique)
    Log-Info "Get-Disk-Partitions discovered disk numbers: $($discoveredDiskNumbers -join ', ')"
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
    Log-Info "Stopping Windows Search temporarily to reduce attached-disk file locks..."
    foreach ($svc in @('WSearch')) {
        try {
            $svcObj = Get-Service -Name $svc -ErrorAction Stop
            if ($svcObj) {
                $serviceStates[$svc] = [string]$svcObj.Status
                Log-Info "Captured original state of $svc : $($svcObj.Status)"
                if ($svcObj.Status -ne 'Stopped') {
                    Stop-Service -Name $svc -ErrorAction Stop
                    $svcObj.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                    Log-Info "$svc stopped temporarily."
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
            Log-Warning "Attached repair Disk $diskNumber has no partitions."
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
            Log-Info "Validated Windows target on Disk $diskNumber Partition $($targetVolume.PartitionNumber) at $($targetVolume.DriveLetter):."
        }
        else {
            $skippedCount++
            Log-Warning "Disk $diskNumber has no partition containing both a Windows loader and SYSTEM hive."
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
        Log-Info "Processing validated target Disk $($targetVolume.DiskNumber) on letter $($diskb):"
        # Step 2 - Load the SYSTEM registry hive from the target disk
        $hiveName = "BROKENSYSTEM_$diskb"
        $hiveSource = "$($diskb):\Windows\System32\config\SYSTEM"
        $hiveCopy = $null
        $backupFile = $null
        $restoreHiveBackup = $false
        $diskProcessedSuccessfully = $false
        $diskChangesCompleted = $false
        & reg.exe unload "HKLM\$hiveName" 2>$null
        [System.GC]::Collect()
        Start-Sleep -Seconds 1

        try {
            $backupFile = "$($diskb):\SYSTEM_before_GA_changes_$diskb.hiv"
            Log-Info "Creating binary SYSTEM hive backup at $backupFile..."
            Copy-Item -LiteralPath $hiveSource -Destination $backupFile -Force -ErrorAction Stop
            $sourceHiveHash = (Get-FileHash -LiteralPath $hiveSource -Algorithm SHA256 -ErrorAction Stop).Hash
            $backupHiveHash = (Get-FileHash -LiteralPath $backupFile -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($sourceHiveHash -ne $backupHiveHash) {
                throw "Source and backup SHA256 hashes differ."
            }
            Log-Info "Binary SYSTEM hive backup created and verified for $($diskb):."
        }
        catch {
            Log-Error "Failed to create and verify SYSTEM hive backup for $($diskb):: $($_.Exception.Message)"
            $failedDisks += $diskb
            $failedCount++
            continue
        }

        Log-Info "Loading SYSTEM hive from $($diskb): as $hiveName..."
        $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Retry once after a short wait
            Log-Warning "First reg load attempt failed for $($diskb):, retrying in 5 seconds..."
            Start-Sleep -Seconds 5
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            # Fallback: use esentutl.exe /y to copy locked hive via Windows Backup API semantics
            Log-Warning "Direct load failed. Trying esentutl copy fallback for $($diskb):..."
            $hiveCopy = "$env:TEMP\SYSTEM_COPY_$diskb"
            try {
                $esentResult = & esentutl.exe /y $hiveSource /d $hiveCopy /o 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $hiveCopy)) {
                    Log-Info "Hive copied successfully to $hiveCopy via esentutl"
                    $loadResult = & reg.exe load "HKLM\$hiveName" $hiveCopy 2>&1
                }
                else {
                    Log-Warning "esentutl copy failed for $($diskb): $esentResult"
                }
            }
            catch {
                Log-Warning "esentutl fallback failed for $($diskb):: $($_.Exception.Message)"
            }
        }
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Failed to load Registry Hive from $($diskb): $loadResult"
            if ($hiveCopy -and (Test-Path $hiveCopy)) { Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue }
            $failedDisks += $diskb
            $failedCount++
            continue
        }
        Start-Sleep -Seconds 2

        try {
            # Step 4 - Identify the primary and backup ControlSets from the Select key
            $selectPath = "Registry::HKLM\$hiveName\Select"
            $defaultSetID = (Get-ItemProperty -path $selectPath).default
            $primarySet = "ControlSet00$defaultSetID"
            $otherSet = if ($primarySet -eq "ControlSet001") { "ControlSet002" } else { "ControlSet001" }

            Log-Info "Primary ControlSet identified: $primarySet"
            # Step 5 - Export healthy service keys and inject into both ControlSets
            $services = @("WindowsAzureGuestAgent", "WindowsAzureTelemetryService", "RdAgent")

            foreach ($service in $services) {
                $regFile = "$($diskb):\$service.reg"
                # Check if service key exists on the rescue VM before attempting export
                $rescueServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
                if (-not (Test-Path -Path $rescueServiceKey)) {
                    Log-Warning "Service '$service' not found on rescue VM registry - skipping (not present on this OS version)"
                    continue
                }
                # Export healthy key from the current Rescue VM
                $serviceExportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("export", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service", "$regFile", "/y") -Description "reg export service $service"

                if ($serviceExportResult.ExitCode -eq 0 -and (Test-Path $regFile)) {
                    $originalContent = Get-Content $regFile

                    # Update Primary Set
                    Log-Info "Updating $service in $primarySet on $($diskb):..."
                    $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$primarySet"
                    $content | Set-Content $regFile
                    $primaryImportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("import", $regFile) -Description "reg import $service into $primarySet ($diskb)"
                    if ($primaryImportResult.ExitCode -ne 0) {
                        throw "Failed to import $service into $primarySet for $($diskb): $($primaryImportResult.Output -join '; ')"
                    }

                    # Update Secondary Set (if it exists on disk)
                    if (Test-Path "Registry::HKLM\$hiveName\$otherSet") {
                        Log-Info "Updating $service in backup $otherSet on $($diskb):..."
                        $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$otherSet"
                        $content | Set-Content $regFile
                        $secondaryImportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("import", $regFile) -Description "reg import $service into $otherSet ($diskb)"
                        if ($secondaryImportResult.ExitCode -ne 0) {
                            throw "Failed to import $service into $otherSet for $($diskb): $($secondaryImportResult.Output -join '; ')"
                        }
                    }
                    Remove-Item $regFile -Force
                }
                else {
                    $serviceExportText = $serviceExportResult.Output -join '; '
                    throw ("Failed to export service key for " + $service + " - " + $serviceExportText)
                }
            }

            # Step 6 - Validate the required service configuration written to the target hive.
            $requiredAgentServices = @('WindowsAzureGuestAgent', 'RdAgent')
            $targetServiceConfigurations = @{}
            foreach ($requiredService in $requiredAgentServices) {
                $servicePath = "Registry::HKLM\$hiveName\$primarySet\Services\$requiredService"
                $serviceConfiguration = Get-ItemProperty -Path $servicePath -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace([string]$serviceConfiguration.ImagePath)) {
                    throw "Required service '$requiredService' has an empty ImagePath in $primarySet."
                }
                if ([int]$serviceConfiguration.Start -ne 2) {
                    throw "Required service '$requiredService' is not configured for automatic startup in ${primarySet} (Start=$($serviceConfiguration.Start))."
                }

                $targetServiceConfigurations[$requiredService] = $serviceConfiguration
                Log-Info "Validated $requiredService configuration in ${primarySet}: Start=2, ImagePath=$($serviceConfiguration.ImagePath)"
            }
            $afterImagePath = [string]$targetServiceConfigurations['WindowsAzureGuestAgent'].ImagePath

            # Step 7 - Copy only the current VM Agent installation folder.
            $sourcePath = "C:\WindowsAzure"
            $destPath = "$($diskb):\WindowsAzure"
            $backupPath = "$($diskb):\WindowsazurefaultyGAbackup"

            $guestAgentCandidates = @(Get-ChildItem -LiteralPath $sourcePath -Directory -Force -ErrorAction Stop |
                ForEach-Object {
                    if ($_.Name -match '^GuestAgent_(.+)$') {
                        $parsedVersion = $null
                        if ([version]::TryParse($matches[1], [ref]$parsedVersion)) {
                            [pscustomobject]@{
                                Directory = $_
                                Version = $parsedVersion
                            }
                        }
                    }
                } | Sort-Object Version -Descending)

            $sourceAgentFolder = $null
            if ($guestAgentCandidates.Count -gt 0) {
                $sourceAgentFolder = $guestAgentCandidates[0].Directory
                Log-Info "Selected latest VM Agent installation folder $($sourceAgentFolder.Name)."
            }
            else {
                $expandedImagePath = [Environment]::ExpandEnvironmentVariables($afterImagePath).Trim()
                $imageExecutable = if ($expandedImagePath.StartsWith('"')) {
                    ($expandedImagePath -split '"')[1]
                }
                else {
                    ($expandedImagePath -split '\s+')[0]
                }
                if (-not [string]::IsNullOrWhiteSpace($imageExecutable)) {
                    $imageFolder = Split-Path -Parent $imageExecutable
                    if (Test-Path -LiteralPath $imageFolder -PathType Container) {
                        $sourceAgentFolder = Get-Item -LiteralPath $imageFolder -ErrorAction Stop
                        Log-Warning "No versioned GuestAgent folder was found; using ImagePath folder '$imageFolder'."
                    }
                }
            }

            if (-not $sourceAgentFolder) {
                throw "No GuestAgent installation folder was found under '$sourcePath' or through ImagePath '$afterImagePath'."
            }

            $null = New-Item -Path $destPath -ItemType Directory -Force
            $targetAgentFolder = Join-Path $destPath $sourceAgentFolder.Name
            $stagingAgentFolder = Join-Path $destPath ('.GA_repair_{0}_{1}' -f $sourceAgentFolder.Name, [guid]::NewGuid().ToString('N'))
            $targetAgentBackup = $null
            $existingAgentMoved = $false

            try {
                Log-Info "Staging VM Agent folder $($sourceAgentFolder.FullName) at $stagingAgentFolder..."
                $restoreCopyResult = Invoke-CriticalCommand -Command "robocopy.exe" -Arguments @(
                    $sourceAgentFolder.FullName, $stagingAgentFolder, '/E', '/COPY:DAT', '/DCOPY:DAT',
                    '/XJ', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP'
                ) -Description "robocopy VM Agent $($sourceAgentFolder.Name) ($diskb)"
                if ($restoreCopyResult.ExitCode -ge 8) {
                    throw "Failed to stage VM Agent folder on $($diskb): $($restoreCopyResult.Output -join '; ')"
                }

                foreach ($requiredService in $requiredAgentServices) {
                    $targetExecutable = Get-GaServiceExecutablePath `
                        -ImagePath ([string]$targetServiceConfigurations[$requiredService].ImagePath) `
                        -TargetDriveLetter $diskb
                    $targetAgentPrefix = $targetAgentFolder.TrimEnd('\') + '\'
                    if (-not $targetExecutable.StartsWith($targetAgentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "Required service '$requiredService' points outside the selected Agent folder: $targetExecutable"
                    }

                    $relativeExecutable = $targetExecutable.Substring($targetAgentPrefix.Length)
                    $stagedExecutable = Join-Path $stagingAgentFolder $relativeExecutable
                    if (-not (Test-Path -LiteralPath $stagedExecutable -PathType Leaf)) {
                        throw "Required executable for service '$requiredService' was not found in the staged copy: $stagedExecutable"
                    }
                    $stagedExecutableInfo = Get-Item -LiteralPath $stagedExecutable -ErrorAction Stop
                    if ($stagedExecutableInfo.Length -le 0) {
                        throw "Required executable for service '$requiredService' is empty in the staged copy: $stagedExecutable"
                    }
                    Log-Info "Validated staged $requiredService executable ($($stagedExecutableInfo.Length) bytes)."
                }

                if (Test-Path -LiteralPath $targetAgentFolder) {
                    $null = New-Item -Path $backupPath -ItemType Directory -Force
                    $targetAgentBackup = Join-Path $backupPath "$($sourceAgentFolder.Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                    Log-Info "Moving existing $($sourceAgentFolder.Name) folder to $targetAgentBackup..."
                    Move-Item -LiteralPath $targetAgentFolder -Destination $targetAgentBackup -ErrorAction Stop
                    $existingAgentMoved = $true
                }

                Move-Item -LiteralPath $stagingAgentFolder -Destination $targetAgentFolder -ErrorAction Stop
                Log-Info "Activated validated VM Agent folder at $targetAgentFolder."
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
                    Log-Warning "Restored the original VM Agent folder after replacement failed."
                }
                throw $activationError
            }

            $diskChangesCompleted = $true
        }
        catch {
            Log-Error "Failed to process $($diskb):: $($_.Exception.Message)"
            $restoreHiveBackup = $true
            $diskProcessedSuccessfully = $false
        }
        finally {
            # Step 8 - Release handles and safely unload the registry hive
            Log-Info "Unloading registry hive $hiveName..."
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 3

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("unload", "HKLM\$hiveName") -Description "reg unload $hiveName attempt $i"
                if ($unloadResult.ExitCode -eq 0) { $unloaded = $true; break }
                Log-Warning "Unload attempt $i for $hiveName failed, retrying..."
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Log-Error "Could not unload $hiveName hive - marking Disk $diskb as failed."
                $failedDisks += $diskb
            }

            if ($restoreHiveBackup -and $backupFile -and (Test-Path -LiteralPath $backupFile)) {
                if ($unloaded) {
                    Log-Warning "Repair processing failed; restoring the original SYSTEM hive from $backupFile."
                    try {
                        $expectedHiveHash = (Get-FileHash -LiteralPath $backupFile -Algorithm SHA256 -ErrorAction Stop).Hash
                        Copy-Item -LiteralPath $backupFile -Destination $hiveSource -Force -ErrorAction Stop
                        $actualHiveHash = (Get-FileHash -LiteralPath $hiveSource -Algorithm SHA256 -ErrorAction Stop).Hash
                        if ($actualHiveHash -ne $expectedHiveHash) {
                            throw "SYSTEM hive rollback verification failed: backup and restored hashes differ."
                        }
                        Log-Info "Original SYSTEM hive restored and verified for $($diskb):."
                    }
                    catch {
                        Log-Error "Failed to restore the original SYSTEM hive on $($diskb):: $($_.Exception.Message)"
                        $failedDisks += $diskb
                    }
                }
                else {
                    Log-Error "Original SYSTEM hive for $($diskb): cannot be restored because $hiveName did not unload."
                    $failedDisks += $diskb
                }
            }
            # If direct loading failed, persist the fallback hive only after every repair check passed.
            elseif ($hiveCopy -and (Test-Path $hiveCopy)) {
                if ($unloaded) {
                    Log-Info "Copying modified hive back to $hiveSource..."
                    try {
                        $expectedHiveHash = (Get-FileHash -LiteralPath $hiveCopy -Algorithm SHA256 -ErrorAction Stop).Hash
                        Copy-Item -LiteralPath $hiveCopy -Destination $hiveSource -Force -ErrorAction Stop
                        $actualHiveHash = (Get-FileHash -LiteralPath $hiveSource -Algorithm SHA256 -ErrorAction Stop).Hash
                        if ($actualHiveHash -ne $expectedHiveHash) {
                            throw "Hive copy-back verification failed: source and destination SHA256 hashes differ."
                        }
                        Log-Info "Successfully copied and verified the modified hive back to $($diskb):"
                    }
                    catch {
                        Log-Error "Failed to copy modified hive back to $($diskb):: $($_.Exception.Message)"
                        $failedDisks += $diskb
                    }
                }
                else {
                    Log-Error "Modified fallback hive for $($diskb): cannot be copied back because $hiveName did not unload."
                    $failedDisks += $diskb
                }
            }

            if ($hiveCopy -and (Test-Path -LiteralPath $hiveCopy)) {
                Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue
            }

            $diskProcessedSuccessfully = $diskChangesCompleted -and ($diskb -notin $failedDisks)
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
        Log-Error "Processing failed on disks: $($failedDisks -join ', ')"
        throw "One or more disks failed backup, hive processing, unload, or copy-back validation: $($failedDisks -join ', '). Please review logs."
    }

    Log-Info "Processing summary: processed=$processedCount skipped=$skippedCount failed=$failedCount changed=$changedCount"
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
    Log-Error "SCRIPT FAILED: $errorMessage"
    $script_final_status = $STATUS_ERROR
}
finally {
    foreach ($mount in @($temporaryOsMounts | Sort-Object DiskNumber, PartitionNumber -Unique)) {
        try {
            Log-Info "Removing temporary OS letter $($mount.DriveLetter): from Disk $($mount.DiskNumber) Partition $($mount.PartitionNumber)."
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
            Log-Info "Temporary OS letter $($mount.DriveLetter): removal verified."
        }
        catch {
            Log-Error "Failed to remove temporary OS letter $($mount.DriveLetter): $($_.Exception.Message)"
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
                Log-Info "Source Disk $diskNumber is offline with its original GPT identity verified before repair host restoration."
            }
            catch {
                $identityRestorationFailed = $true
                Log-Error "CRITICAL: Could not safely offline and verify source Disk ${diskNumber}: $($_.Exception.Message)"
            }
        }

        if (-not $identityRestorationFailed) {
            try {
                Restore-GaRepairDiskIdentity -Record $repairDiskIdentityRecord
                Log-Info 'Repair VM OS disk GPT identity restored and verified.'
            }
            catch {
                $identityRestorationFailed = $true
                Log-Error "CRITICAL: Failed to restore the repair VM OS disk identity: $($_.Exception.Message)"
            }
        }
    }

    foreach ($identityRecord in @($collisionDiskRecords | Sort-Object DiskNumber -Descending)) {
        try {
            Restore-GaOriginalSourceIdentity -Record $identityRecord
            Log-Info "Disk $($identityRecord.DiskNumber) is offline with its verified original MBR identity restored."
        }
        catch {
            $identityRestorationFailed = $true
            Log-Error "CRITICAL: Failed to restore original identity on Disk $($identityRecord.DiskNumber): $($_.Exception.Message)"
        }
    }

    if ($identityRestorationFailed) {
        $script_final_status = $STATUS_ERROR
    }

    # Log local execution context only; this script performs no telemetry upload.
    if ($vmMetadata.OSVersion) {
        Log-Info "Execution Context - Host: $($vmMetadata.HostName), OS: $($vmMetadata.OSVersion)"
    }

    # Restore original service states
    Log-Info "Restoring original service states..."
    foreach ($svc in $serviceStates.Keys) {
        try {
            $originalState = $serviceStates[$svc]
            Log-Info "Restoring $svc to state: $originalState"
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
            Log-Info "$svc restored and verified in state $restoredState."
        }
        catch {
            Log-Error "Failed to restore $svc to state $originalState : $($_.Exception.Message)"
            $script_final_status = $STATUS_ERROR
        }
    }

    if ($script_final_status -eq $STATUS_SUCCESS -and $successMessage) {
        Log-Output $successMessage
    }

    Log-Info "Execution ended at $(Get-Date)"
    Log-Info "Desktop log file path: $logFile"
}

return $script_final_status
