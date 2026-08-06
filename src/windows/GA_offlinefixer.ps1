<#
.SYNOPSIS
    VMAgent Offline Fixer - Restores Guest Agent registry keys and binaries from a rescue VM.

.DESCRIPTION
    This script runs from a rescue VM to repair a broken Azure Guest Agent on an attached OS disk.
    It performs the following steps:
    1. Enumerates partitions only on validated attached repair disks to locate the faulty OS drive.
    2. Loads the SYSTEM registry hive from the target disk into HKLM\BROKENSYSTEM.
    3. Creates and verifies a binary backup of the SYSTEM hive before loading it.
    4. Identifies the primary and backup ControlSets (001/002) from the Select key.
    5. Exports healthy service keys (WindowsAzureGuestAgent, WindowsAzureTelemetryService, RdAgent)
       from the rescue VM and injects them into both ControlSets on the target hive.
    6. Verifies the ImagePath value was written correctly.
    7. Copies the latest GuestAgent installation folder from the rescue VM to the attached disk.
    8. Releases handles and safely unloads the registry hive (with retry logic).

.NOTES
    Name:    GA_offlinefixer.ps1
    Version: 1.3
    Original Author: Daniel Munoz L (damunozl@microsoft.com)
    Modified by: Tony.Mocanu@Microsoft.com

.VERSION
    v1.3: [August 2026] - Copies only the newest versioned GuestAgent installation folder.
                        - Uses the WindowsAzureGuestAgent ImagePath folder as a fallback.
                        - Preserves unrelated content in the target WindowsAzure folder.
                        - Bounds file-copy retries to avoid client repair jobs appearing stuck.
                        - Unloads only stale repair hives that actually exist.
                        - Avoids broad helper disk onlining and full registry text exports.
                        - Temporarily resolves attached-disk identity collisions and restores the
                        - exact original MBR signature or GPT GUID before returning.
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
    To recreate a testable broken Guest Agent scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Load the SYSTEM hive from the attached disk (replace F with actual drive letter):
reg load HKLM\TESTBREAK F:\Windows\System32\config\SYSTEM
    3. Delete or corrupt the Guest Agent service keys:
Remove-Item -Path "HKLM:\TESTBREAK\ControlSet001\Services\WindowsAzureGuestAgent" -Recurse -Force
Remove-Item -Path "HKLM:\TESTBREAK\ControlSet001\Services\RdAgent" -Recurse -Force
    4. Unload the hive:
reg unload HKLM\TESTBREAK
    5. Optionally rename/remove GuestAgent binary folders on the target disk:
Get-ChildItem F:\WindowsAzure\GuestAgent_* | Rename-Item -NewName { $_.Name + '_BACKUP' }
    6. Run the script. It should restore service keys from the rescue VM and copy binaries.
    7. Verify via the .VERIFICATION steps below.

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-GA-fix --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "$env:USERPROFILE\Desktop\GA_offlinefixer_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "VMAgent Fix completed and verified successfully." and return code 0 ($STATUS_SUCCESS).
    2. Reload the SYSTEM hive and verify agent service keys exist (replace F with disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\WindowsAzureGuestAgent" -Name ImagePath
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\RdAgent" -Name ImagePath
reg unload HKLM\VERIFY
    Expected: ImagePath values are populated for both services.
    3. Verify GuestAgent binaries were copied to the target disk:
Get-ChildItem F:\WindowsAzure\GuestAgent_*
    Expected: One or more GuestAgent folders present.
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
if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

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

# Status Tracking
$script_final_status = $STATUS_ERROR
$serviceStates = @{}  # Track original service states for restoration
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0
$temporaryOsMounts = @()
$temporaryDiskIdentities = @()
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
    Log-Info "Rescue VM OS disk identified as physical Disk $rescueDiskNum."

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
        $diskNumber = [int]$collisionDisk.Number
        $partitionStyle = [string]$collisionDisk.PartitionStyle
        if ($partitionStyle -notin @('GPT', 'MBR')) {
            throw "Disk $diskNumber has identity collision with unsupported partition style '$partitionStyle'."
        }

        $identityRecord = [pscustomobject]@{
            DiskNumber = $diskNumber
            PartitionStyle = $partitionStyle
            OriginalGuid = [string]$collisionDisk.Guid
            OriginalSignature = $collisionDisk.Signature
            OriginalIsOffline = [bool]$collisionDisk.IsOffline
            TemporaryGuid = $null
            TemporarySignature = $null
        }
        $temporaryDiskIdentities += $identityRecord

        if ($partitionStyle -eq 'GPT') {
            if ([string]::IsNullOrWhiteSpace($identityRecord.OriginalGuid)) {
                throw "Cannot preserve the original GPT GUID for collision Disk $diskNumber."
            }
            do {
                $identityRecord.TemporaryGuid = ([guid]::NewGuid()).ToString('B')
            } while (Get-Disk -ErrorAction Stop | Where-Object {
                [string]$_.Guid -ieq [string]$identityRecord.TemporaryGuid
            })
            Log-Warning "Disk $diskNumber has a GPT identity collision. Assigning a temporary GUID for offline repair."
            Set-Disk -Number $diskNumber -Guid $identityRecord.TemporaryGuid -ErrorAction Stop
        }
        else {
            if ($null -eq $identityRecord.OriginalSignature) {
                throw "Cannot preserve the original MBR signature for collision Disk $diskNumber."
            }
            do {
                $signatureBytes = New-Object byte[] 4
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($signatureBytes)
                $identityRecord.TemporarySignature = [BitConverter]::ToUInt32($signatureBytes, 0)
            } while ($identityRecord.TemporarySignature -eq 0 -or (Get-Disk -ErrorAction Stop | Where-Object {
                $_.PartitionStyle -eq 'MBR' -and $_.Signature -eq $identityRecord.TemporarySignature
            }))
            Log-Warning "Disk $diskNumber has an MBR identity collision. Assigning a temporary signature for offline repair."
            Set-Disk -Number $diskNumber -Signature $identityRecord.TemporarySignature -ErrorAction Stop
        }

        Set-Disk -Number $diskNumber -IsOffline $false -ErrorAction Stop
        Set-Disk -Number $diskNumber -IsReadOnly $false -ErrorAction Stop
        Update-HostStorageCache -ErrorAction SilentlyContinue
        $updatedCollisionDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
        $temporaryIdentityVerified = if ($partitionStyle -eq 'GPT') {
            [string]$updatedCollisionDisk.Guid -ieq [string]$identityRecord.TemporaryGuid
        }
        else {
            [uint32]$updatedCollisionDisk.Signature -eq [uint32]$identityRecord.TemporarySignature
        }
        if (-not $temporaryIdentityVerified -or $updatedCollisionDisk.IsOffline) {
            throw "Temporary identity activation could not be verified for collision Disk $diskNumber."
        }
        Log-Info "Disk $diskNumber temporary identity applied and disk brought online. Original identity will be restored during cleanup."
    }
    $attachedDisks = @($attachedDisks | ForEach-Object { Get-Disk -Number $_.Number -ErrorAction Stop })
    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    Log-Info "Attached repair candidate disk numbers: $($attachedDiskNumbers -join ', ')"

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

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    # Cycle only verified attached Microsoft virtual disks to release file handles.
    Log-Info "Cycling attached disks offline/online to release file locks..."
    $attachedDisks | Where-Object { -not $_.IsOffline } | ForEach-Object {
        $dnum = $_.Number
        Log-Info "Cycling disk $dnum offline/online..."
        Set-Disk -Number $dnum -IsOffline $true -ErrorAction Stop
        Start-Sleep -Seconds 2
        Set-Disk -Number $dnum -IsOffline $false -ErrorAction Stop
        Set-Disk -Number $dnum -IsReadOnly $false -ErrorAction Stop
    }
    Start-Sleep -Seconds 3

    # Step 1 - Find one validated Windows volume on each attached physical disk.
    $targetWindowsVolumes = @()
    $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
    foreach ($diskNumber in $attachedDiskNumbers) {
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

            # Step 6 - Verify the ImagePath value was written correctly
            $wagaPath = "HKLM\$hiveName\$primarySet\Services\WindowsAzureGuestAgent"
            $afterImagePath = (Get-ItemProperty -Path "Registry::$wagaPath" -ErrorAction SilentlyContinue).ImagePath
            if ([string]::IsNullOrWhiteSpace($afterImagePath)) {
                Log-Warning "Verification Warning on $($diskb): VMAgent ImagePath is empty after injection."
            }
            else {
                Log-Info "Verification Success on $($diskb):: ImagePath is now $afterImagePath"
            }

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
                $expandedImagePath = [Environment]::ExpandEnvironmentVariables([string]$afterImagePath).Trim()
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
            if (Test-Path -LiteralPath $targetAgentFolder) {
                $null = New-Item -Path $backupPath -ItemType Directory -Force
                $targetAgentBackup = Join-Path $backupPath "$($sourceAgentFolder.Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                Log-Info "Moving existing $($sourceAgentFolder.Name) folder to $targetAgentBackup..."
                Move-Item -LiteralPath $targetAgentFolder -Destination $targetAgentBackup -ErrorAction Stop
            }

            Log-Info "Copying VM Agent folder $($sourceAgentFolder.FullName) to $targetAgentFolder..."
            $restoreCopyResult = Invoke-CriticalCommand -Command "robocopy.exe" -Arguments @(
                $sourceAgentFolder.FullName, $targetAgentFolder, '/E', '/COPY:DAT', '/DCOPY:DAT',
                '/XJ', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP'
            ) -Description "robocopy VM Agent $($sourceAgentFolder.Name) ($diskb)"
            if ($restoreCopyResult.ExitCode -ge 8) {
                throw "Failed to copy VM Agent folder to $($diskb): $($restoreCopyResult.Output -join '; ')"
            }
            $sourceAgentFile = Get-ChildItem -LiteralPath $sourceAgentFolder.FullName -File -Recurse -Force -ErrorAction Stop |
                Select-Object -First 1
            if (-not $sourceAgentFile) {
                throw "Source VM Agent folder '$($sourceAgentFolder.FullName)' contains no files."
            }
            $relativeAgentFile = $sourceAgentFile.FullName.Substring($sourceAgentFolder.FullName.Length).TrimStart('\')
            if (-not (Test-Path -LiteralPath (Join-Path $targetAgentFolder $relativeAgentFile) -PathType Leaf)) {
                throw "VM Agent folder copy verification failed for '$relativeAgentFile'."
            }

            $diskChangesCompleted = $true
        }
        catch {
            Log-Error "Failed to process $($diskb):: $($_.Exception.Message)"
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

            # If we used the copy fallback, copy the modified hive back to the original location
            if ($hiveCopy -and (Test-Path $hiveCopy)) {
                if ($unloaded) {
                    Log-Info "Copying modified hive back to $hiveSource..."
                    try {
                        $expectedHiveHash = (Get-FileHash -LiteralPath $hiveCopy -Algorithm SHA256 -ErrorAction Stop).Hash
                        Copy-Item -Path $hiveCopy -Destination $hiveSource -Force -ErrorAction Stop
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
        $successMessage = "VMAgent Fix completed and verified successfully on drives: $($fixedDisks -join ', ') | Host=$($vmMetadata.HostName)"
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

    foreach ($identityRecord in @($temporaryDiskIdentities)) {
        try {
            $diskNumber = [int]$identityRecord.DiskNumber
            Log-Info "Restoring original $($identityRecord.PartitionStyle) identity on Disk $diskNumber."
            Set-Disk -Number $diskNumber -IsOffline $true -ErrorAction Stop
            if ($identityRecord.PartitionStyle -eq 'GPT') {
                Set-Disk -Number $diskNumber -Guid $identityRecord.OriginalGuid -ErrorAction Stop
            }
            else {
                Set-Disk -Number $diskNumber -Signature ([uint32]$identityRecord.OriginalSignature) -ErrorAction Stop
            }
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $restoredDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
            $identityRestored = if ($identityRecord.PartitionStyle -eq 'GPT') {
                [string]$restoredDisk.Guid -ieq [string]$identityRecord.OriginalGuid
            }
            else {
                [uint32]$restoredDisk.Signature -eq [uint32]$identityRecord.OriginalSignature
            }
            if (-not $identityRestored) {
                throw "Original disk identity verification failed."
            }
            Log-Info "Original $($identityRecord.PartitionStyle) identity restored and verified on Disk $diskNumber; disk left offline for repair restore."
        }
        catch {
            Log-Error "CRITICAL: Failed to restore original identity on Disk $($identityRecord.DiskNumber): $($_.Exception.Message)"
            $script_final_status = $STATUS_ERROR
        }
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
