<#
.SYNOPSIS
    Safely sets IgnoreAllFailures on the validated default Windows boot loader of an attached OS disk.

.DESCRIPTION
    This script runs from a rescue VM to modify the BCD store on an attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
    2. Excludes the repair VM disk and validates a same-disk, generation-appropriate BCD store and Windows loader.
    3. Identifies the explicit default Windows loader from the BCD boot manager and validates its path.
    4. Creates and verifies a BCD backup before making any change.
    5. Sets bootstatuspolicy to IgnoreAllFailures without changing the default boot selection.
    6. Verifies the policy and restores the backup if the BCD transaction fails.

    This resolves VMs stuck in Automatic Repair loops caused by failed boot, failed shutdown,
    or failed checkpoint errors.

.NOTES
    Name:    win-ignoreAllFailures.ps1
    Version: 1.3
    Author:  Microsoft Azure Compute Support

.VERSION
    v1.3: [August 2026] - Validates temporary EFI mounts before tracking them for cleanup.
                           - Excludes null and empty drive letters from mounted partition scans.
                           - Aligns BCD target validation and no-boot protections with the proven repair scripts.
                           - Excludes repair-host critical disks and preserves source disk identities across collisions.
                           - Restores and verifies every temporary GPT or MBR identity before reporting success.
                           - Verifies DiskPart mounts by access path to avoid stale Get-Partition drive-letter data.
                           - Probes unlettered non-EFI partitions and cleans up every temporary OS mount.
    v1.2: [May 2026] - Updated the script
                       - Added guarded nested VM handling to prevent Get-VM failures when Hyper-V module is unavailable.
                       - Switched partition discovery from inline CIM enumeration to shared Get-Disk-Partitions-v2 helper.
                       - Added .SYNOPSIS header and aligned metadata versioning/documentation with current script behavior.
    v1.1: [Apr 2026] - Enhanced CIM logic for disk enumeration and partition discovery
    v1.0: Initial commit - Sets BCD boot status policy to IgnoreAllFailures to break Automatic Repair loops
        
.SCENARIO_RECREATION
    To recreate a testable scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Find the attached disk's drive letter and locate the BCD store:
       Gen1: <drive>:\boot\bcd  |  Gen2: <drive>:\efi\microsoft\boot\bcd
    3. Remove or reset the bootstatuspolicy to simulate an Automatic Repair loop (replace <bcdpath> with your actual BCD path):
bcdedit /store <bcdpath> /deletevalue {default} bootstatuspolicy
    4. Verify bootstatuspolicy is absent:
bcdedit /store <bcdpath> /enum {default}
    Expected: No bootstatuspolicy line in the output.
    5. Run the script. It should set bootstatuspolicy to IgnoreAllFailures.
    6. Verify the change:
bcdedit /store <bcdpath> /enum {default}
    Expected: bootstatuspolicy = IgnoreAllFailures.

.EXAMPLE
    # Deploy and run on rescue VM
    az vm repair run -g <resource-group> -n <vm-name> --run-id win-ignoreAllFailures --run-on-repair
    
    # Verify BCD changes
    Get-ChildItem "$env:USERPROFILE\Desktop\ignoreAllFailures_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content

.VERIFICATION
    1. Check the log file for success:
    Get-ChildItem "$env:USERPROFILE\Desktop\ignoreAllFailures_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
       Expected: "BCD AFTER CHANGE" section shows bootstatuspolicy = IgnoreAllFailures, return code 0.
    2. Manually verify the BCD store on the attached disk (replace F with the BCD partition letter):
       bcdedit /store F:\boot\bcd /enum
       or for EFI:
       bcdedit /store F:\efi\microsoft\boot\bcd /enum
       Expected: bootstatuspolicy set to IgnoreAllFailures on the default entry.
#>

# Initialization (no Param() block to avoid ParserErrors on legacy PowerShell engines)
# $PSScriptRoot can be empty when invoked through ScriptBlock execution.
# Fall back to call stack script attribution to resolve the originating file directory.
$resolvedScriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    $originFrame = Get-PSCallStack -ErrorAction SilentlyContinue |
        Where-Object { $_.ScriptName } |
        Select-Object -First 1

    if ($originFrame -and $originFrame.ScriptName) {
        $resolvedScriptRoot = Split-Path -Parent $originFrame.ScriptName
    }
}

if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    Write-Error 'Cannot determine script directory: PSScriptRoot is empty and call stack provides no path.'
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

$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath) -or -not (Test-Path $desktopPath)) {
    $desktopPath = Join-Path $env:USERPROFILE 'Desktop'
}
if (-not (Test-Path $desktopPath)) {
    $desktopPath = 'C:\Windows\Temp'
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $desktopPath "ignoreAllFailures_$timestamp.log"
if (-not (Test-Path $logFile)) { $null = New-Item -ItemType File -Path $logFile -Force }

$successReport = New-Object System.Collections.Generic.List[string]
$script_final_status = $STATUS_ERROR
$assignedEfiLetters = @()  # Track EFI partition drive letters for cleanup
$assignedOsLetters = @()   # Track Windows partition drive letters for cleanup
$processedDisks = 0
$skippedDisks = 0
$failedDisks = 0
$changedDisks = 0
$collisionDiskRecords = @()
$gptCollisionDiskNumbers = @()
$repairDiskIdentityRecord = $null

function Get-FormattedOutput {
    param([string]$text)
    $time = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
    return "[Output $time]$text"
}

function Write-ScriptLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    switch ($Level) {
        'Info' { Log-Info $Message }
        'Warning' { Log-Warning $Message }
        'Error' { Log-Error $Message }
    }

    Add-Content -Path $logFile -Value (Get-FormattedOutput $Message)
}

function Add-CommandOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Header,
        [Parameter(Mandatory = $true)]
        [object[]]$Output
    )

    $successReport.Add((Get-FormattedOutput $Header))
    foreach ($line in $Output) {
        if ($null -ne $line -and -not [string]::IsNullOrWhiteSpace([string]$line)) {
            $successReport.Add((Get-FormattedOutput ([string]$line)))
        }
    }
}

function Get-NextFreeDriveLetter {
    $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter)
    $letters = 90..69 | ForEach-Object { [char]$_ } 
    foreach ($letter in $letters) {
        if ($letter -notin $usedLetters -and -not (Test-Path -LiteralPath "${letter}:\")) { return $letter }
    }

    return $null
}

function Invoke-IgnoreAllFailuresDiskPart {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Commands,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $output = $Commands | diskpart.exe 2>&1
    foreach ($line in @($output)) {
        if ($line) { Write-ScriptLog -Message "[diskpart][$Operation] $line" }
    }
}

function Get-IgnoreAllFailuresDiskIdentity {
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

function Set-IgnoreAllFailuresTemporarySourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    if ($Record.PartitionStyle -ne 'MBR') {
        throw 'Temporary source disk identities are permitted only for the Gen1 MBR path.'
    }
    Invoke-IgnoreAllFailuresDiskPart -Operation 'collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
        'online disk'
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    $currentIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $Record.DiskNumber
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw "Disk $($Record.DiskNumber) could not be brought online with its verified temporary identity."
    }
}

function Restore-IgnoreAllFailuresSourceIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-IgnoreAllFailuresDiskPart -Operation 'collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        'offline disk'
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    $restoredIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $Record.DiskNumber
    if (-not $restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw "Disk $($Record.DiskNumber) did not return to its original offline identity."
    }
}

function Set-IgnoreAllFailuresTemporaryRepairIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-IgnoreAllFailuresDiskPart -Operation 'repair-host-collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    $currentIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $Record.DiskNumber
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw 'The repair VM OS disk did not retain a verified temporary GPT identity.'
    }
}

function Restore-IgnoreAllFailuresRepairIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)

    Invoke-IgnoreAllFailuresDiskPart -Operation 'repair-host-collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    $restoredIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $Record.DiskNumber
    if ($restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw 'The repair VM OS disk did not return to its original GPT identity.'
    }
}

try {
    Write-ScriptLog -Message "Starting IgnoreAllFailures script..."
    Write-ScriptLog -Message "Desktop log file: $logFile"

    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-ScriptLog -Message "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-ScriptLog -Level Warning -Message "Failed to stop nested guest VM $($guestHyperVVirtualMachine.VMName): $($_.Exception.Message). Continuing, but operations may have limited success."
                    }
                }
            }
        } else {
            Write-ScriptLog -Message "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-ScriptLog -Level Warning -Message "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }
    
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $rescueOsPartition = Get-Partition -DriveLetter $rescueDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $rescueOsPartition -or $null -eq $rescueOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the repair VM OS disk from $($env:SystemDrive)."
    }
    $rescueDiskNumber = [int]$rescueOsPartition.DiskNumber
    $repairDiskIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $rescueDiskNumber

    $protectedDiskNumbers = @($rescueDiskNumber)
    $protectedDiskNumbers += @(Get-Disk -ErrorAction Stop |
        Where-Object { $_.IsBoot -or $_.IsSystem } |
        Select-Object -ExpandProperty Number)
    $pageFileDriveLetters = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ([string]$_.Name -match '^([A-Za-z]):\\') { $matches[1] }
        } | Select-Object -Unique)
    foreach ($pageFileDriveLetter in $pageFileDriveLetters) {
        $pageFilePartition = Get-Partition -DriveLetter $pageFileDriveLetter -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pageFilePartition) { $protectedDiskNumbers += [int]$pageFilePartition.DiskNumber }
    }
    $protectedDiskNumbers = @($protectedDiskNumbers | Sort-Object -Unique)
    Write-ScriptLog -Message "Protected repair-host disk numbers: $($protectedDiskNumbers -join ', ')"

    $azureVirtualDiskNumbers = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
        Where-Object { $_.Model -like 'Microsoft Virtual Disk*' } |
        ForEach-Object { [int]$_.Index })
    $attachedDisks = @(Get-Disk -ErrorAction Stop | Where-Object {
        $_.Number -in $azureVirtualDiskNumbers -and $_.Number -notin $protectedDiskNumbers
    })
    if ($attachedDisks.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: No attached Microsoft virtual disk was found.'
    }

    foreach ($collisionDisk in @($attachedDisks | Where-Object { $_.IsOffline -and [string]$_.OfflineReason -eq 'Collision' })) {
        $originalIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $collisionDisk.Number
        if ($originalIdentity.PartitionStyle -eq 'GPT') {
            if ($repairDiskIdentity.PartitionStyle -ne 'GPT' -or $repairDiskIdentity.Value -ine $originalIdentity.Value) {
                throw "Disk $($collisionDisk.Number) reports an unverified GPT identity collision."
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
                Write-ScriptLog -Level Warning -Message 'Temporarily changing only the repair VM OS disk GPT identity; the source disk identity remains unchanged.'
                Set-IgnoreAllFailuresTemporaryRepairIdentity -Record $repairDiskIdentityRecord
            }
            $gptCollisionDiskNumbers += [int]$collisionDisk.Number
            Invoke-IgnoreAllFailuresDiskPart -Operation 'source-gpt-online' -Commands @(
                "select disk $($collisionDisk.Number)"
                'online disk'
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $releasedDisk = Get-Disk -Number $collisionDisk.Number -ErrorAction Stop
            $releasedIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $collisionDisk.Number
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
        Set-IgnoreAllFailuresTemporarySourceIdentity -Record $identityRecord
    }

    $partitionlist = @(Get-Disk-Partitions)
    if ($partitionlist.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }
    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    $targetDiskGroups = @($partitionlist |
        Where-Object { [int]$_.DiskNumber -in $attachedDiskNumbers -and [int]$_.DiskNumber -notin $protectedDiskNumbers } |
        Group-Object DiskNumber)
    if ($targetDiskGroups.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: No secondary disk was returned by the partition helper.'
    }

    Write-ScriptLog -Message "Starting deep scan for BCD files..."

    forEach ($diskGroup in $targetDiskGroups) {
        $processedDisks++

        $currentDiskBcdPath = $null
        $currentDiskOsDrive = $null
        
        # EFI Mounter Logic
        # Filter for hidden partitions: check for null/empty DriveLetter or DriveLetter -eq 0
        $diskPartitions = @(Get-Partition -DiskNumber $diskGroup.Name -ErrorAction Stop)
        $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
        $efiPartitions = @($diskPartitions | Where-Object { ([string]$_.GptType).Trim().Trim('{', '}') -ieq $efiGptType })
        $isGen2Disk = $efiPartitions.Count -gt 0
        $hiddenPartitions = @($diskPartitions | Where-Object {
            (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0) -and
            (($isGen2Disk -and ([string]$_.GptType).Trim().Trim('{', '}') -ieq $efiGptType) -or
             (-not $isGen2Disk -and $_.Type -eq 'System'))
        })
        foreach ($part in $hiddenPartitions) {
            $newLetter = Get-NextFreeDriveLetter
            if (-not $newLetter) {
                Write-ScriptLog -Level Warning -Message "Disk $($diskGroup.Name): no temporary drive letter is available for EFI partition $($part.PartitionNumber)"
                continue
            }
            Write-ScriptLog -Message "Mounting hidden EFI partition on Disk $($diskGroup.Name) to $newLetter`:"
            $mountTracked = $false
            try {
                Invoke-IgnoreAllFailuresDiskPart -Operation 'bcd-assign' -Commands @(
                    "select disk $($diskGroup.Name)"
                    "select partition $($part.PartitionNumber)"
                    "assign letter=$newLetter"
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                if (-not (Test-Path -LiteralPath "${newLetter}:\" -PathType Container)) {
                    throw "Disk $($diskGroup.Name): temporary EFI mount on ${newLetter}: could not be verified."
                }
                $assignedEfiLetters += @{ Letter = $newLetter; DiskNumber = $diskGroup.Name; PartitionNumber = $part.PartitionNumber }
                $mountTracked = $true
            }
            catch {
                if (-not $mountTracked) {
                    Invoke-IgnoreAllFailuresDiskPart -Operation 'failed-bcd-assign-cleanup' -Commands @(
                        "select disk $($diskGroup.Name)"
                        "select partition $($part.PartitionNumber)"
                        "remove letter=$newLetter noerr"
                    )
                    Update-HostStorageCache -ErrorAction SilentlyContinue
                }
                throw
            }
        }

        $currentDrives = @(
            @(Get-Partition -DiskNumber $diskGroup.Name -ErrorAction Stop |
                Where-Object { $_.DriveLetter -and $_.DriveLetter -ne [char]0 } |
                Select-Object -ExpandProperty DriveLetter)
            @($assignedEfiLetters |
                Where-Object { [int]$_.DiskNumber -eq [int]$diskGroup.Name } |
                Select-Object -ExpandProperty Letter)
        ) | Sort-Object -Unique
        foreach ($drive in $currentDrives) {
            $driveStr = "$($drive):"
            if ($null -eq $currentDiskBcdPath) {
                $candidateBcdPath = if ($isGen2Disk) {
                    "$driveStr\efi\microsoft\boot\bcd"
                }
                else {
                    "$driveStr\boot\bcd"
                }
                if (Test-Path -LiteralPath $candidateBcdPath -PathType Leaf) {
                    $currentDiskBcdPath = $candidateBcdPath
                }
            }
            if (-not $currentDiskOsDrive) {
                $systemHivePath = "$driveStr\windows\system32\config\SYSTEM"
                if ((Test-Path -LiteralPath $systemHivePath -PathType Leaf) -and
                    ((Test-Path -LiteralPath "$driveStr\windows\system32\winload.exe" -PathType Leaf) -or
                     (Test-Path -LiteralPath "$driveStr\windows\system32\winload.efi" -PathType Leaf))) {
                    $currentDiskOsDrive = [string]$drive
                }
            }
        }

        if (-not $currentDiskOsDrive) {
            $unletteredOsCandidates = @($diskPartitions | Where-Object {
                (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0) -and
                ([string]$_.GptType).Trim().Trim('{', '}') -ine $efiGptType -and
                $_.Type -ne 'System'
            } | Sort-Object Size -Descending)

            Write-ScriptLog -Message "Disk $($diskGroup.Name): probing $($unletteredOsCandidates.Count) unlettered non-EFI partition(s) for Windows"
            foreach ($osCandidate in $unletteredOsCandidates) {
                $osLetter = Get-NextFreeDriveLetter
                if (-not $osLetter) {
                    Write-ScriptLog -Level Warning -Message "Disk $($diskGroup.Name): no temporary drive letter is available for Windows partition probing"
                    break
                }

                $osMountTracked = $false
                try {
                    Invoke-IgnoreAllFailuresDiskPart -Operation 'os-assign' -Commands @(
                        "select disk $($diskGroup.Name)"
                        "select partition $($osCandidate.PartitionNumber)"
                        "assign letter=$osLetter"
                    )
                    Update-HostStorageCache -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    $osMounted = Test-Path -LiteralPath "${osLetter}:\" -PathType Container
                    $systemHivePath = "${osLetter}:\Windows\System32\config\SYSTEM"
                    $hasSystemHive = $osMounted -and (Test-Path -LiteralPath $systemHivePath -PathType Leaf)
                    $hasWindowsLoader = $osMounted -and
                        ((Test-Path -LiteralPath "${osLetter}:\Windows\System32\winload.exe" -PathType Leaf) -or
                         (Test-Path -LiteralPath "${osLetter}:\Windows\System32\winload.efi" -PathType Leaf))

                    Write-ScriptLog -Message "Disk $($diskGroup.Name): checked temporary ${osLetter}: for Windows; mounted=$osMounted systemHive=$hasSystemHive loader=$hasWindowsLoader"
                    if ($hasSystemHive -and $hasWindowsLoader) {
                        $assignedOsLetters += @{ Letter = $osLetter; DiskNumber = $diskGroup.Name; PartitionNumber = $osCandidate.PartitionNumber }
                        $osMountTracked = $true
                        $currentDiskOsDrive = [string]$osLetter
                        break
                    }
                }
                finally {
                    if (-not $osMountTracked) {
                        Invoke-IgnoreAllFailuresDiskPart -Operation 'os-probe-remove' -Commands @(
                            "select disk $($diskGroup.Name)"
                            "select partition $($osCandidate.PartitionNumber)"
                            "remove letter=$osLetter noerr"
                        )
                        Update-HostStorageCache -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        if (Test-Path -LiteralPath "${osLetter}:\" -PathType Container) {
                            throw "Disk $($diskGroup.Name): temporary OS probe letter ${osLetter}: could not be removed."
                        }
                    }
                }
            }
        }

        if ($currentDiskBcdPath -and $currentDiskOsDrive) {
            Write-ScriptLog -Message "Disk $($diskGroup.Name): candidate BCD store found at $currentDiskBcdPath"
            $bcdout = bcdedit /store $currentDiskBcdPath /enum bootmgr /v 2>&1
            Add-CommandOutput -Header "--- BCD BOOTMGR OUTPUT (Disk $($diskGroup.Name)) ---" -Output $bcdout

            if ($LASTEXITCODE -ne 0) {
                $failedDisks++
                Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to query bootmgr from BCD store at $currentDiskBcdPath (exit code $LASTEXITCODE)"
                continue
            }

            $defaultLine = $bcdout | Select-String -Pattern '^\s*default\s+' | Select-Object -First 1
            
            if ($defaultLine -and ($defaultLine -match '\{([^}]+)\}')) {
                $defaultId = $matches[0]
                if ($defaultId -notmatch '^(?i)\{[0-9a-f\-]{36}\}$') {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): default BCD loader identifier '$defaultId' is invalid"
                    continue
                }
                
                $beforeRaw = bcdedit /store $currentDiskBcdPath /enum $defaultId 2>&1
                Add-CommandOutput -Header "--- BCD BEFORE CHANGE (Disk $($diskGroup.Name)) ---" -Output $beforeRaw
                if ($LASTEXITCODE -ne 0) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to read BCD entry $defaultId before change (exit code $LASTEXITCODE)"
                    continue
                }

                $loaderText = $beforeRaw -join "`n"
                $loaderPathMatch = [regex]::Match($loaderText, '(?im)^\s*path\s+(.+?)\s*$')
                $loaderSystemRootMatch = [regex]::Match($loaderText, '(?im)^\s*systemroot\s+(.+?)\s*$')
                if (-not $loaderPathMatch.Success -or -not $loaderSystemRootMatch.Success) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): default loader $defaultId is missing path or systemroot; refusing BCD changes"
                    continue
                }

                $loaderPath = $loaderPathMatch.Groups[1].Value.Trim()
                $loaderSystemRoot = $loaderSystemRootMatch.Groups[1].Value.Trim()
                $expectedLoaderPath = if ($isGen2Disk) { '\Windows\System32\winload.efi' } else { '\Windows\System32\winload.exe' }
                if ($loaderPath -ine $expectedLoaderPath -or
                    $loaderSystemRoot -ine '\Windows') {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): default loader $defaultId has unsupported path or systemroot; refusing BCD changes"
                    continue
                }

                $resolvedLoaderPath = Join-Path -Path "${currentDiskOsDrive}:\" -ChildPath $loaderPath.TrimStart('\')
                if (-not (Test-Path -LiteralPath $resolvedLoaderPath -PathType Leaf)) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): default loader $defaultId does not resolve to '$resolvedLoaderPath'; refusing BCD changes"
                    continue
                }

                $bcdBackupPath = $currentDiskBcdPath + '.IgnoreAllFailures.bak.' + $timestamp
                $bcdWriteStarted = $false
                try {
                    Copy-Item -LiteralPath $currentDiskBcdPath -Destination $bcdBackupPath -Force -ErrorAction Stop
                    $sourceLength = (Get-Item -LiteralPath $currentDiskBcdPath -Force -ErrorAction Stop).Length
                    $backupLength = (Get-Item -LiteralPath $bcdBackupPath -Force -ErrorAction Stop).Length
                    if ($sourceLength -le 0 -or $backupLength -ne $sourceLength) {
                        throw "BCD backup verification failed at '$bcdBackupPath'."
                    }
                    Write-ScriptLog -Message "Disk $($diskGroup.Name): verified BCD backup created at $bcdBackupPath"

                    $bcdWriteStarted = $true
                    $setPolicyOutput = bcdedit /store $currentDiskBcdPath /set $defaultId bootstatuspolicy IgnoreAllFailures 2>&1
                    $setPolicyExitCode = $LASTEXITCODE
                    Add-CommandOutput -Header "--- BCD SET BOOTSTATUSPOLICY OUTPUT (Disk $($diskGroup.Name)) ---" -Output $setPolicyOutput
                    if ($setPolicyExitCode -ne 0) {
                        throw "Failed to set bootstatuspolicy IgnoreAllFailures on $defaultId (exit code $setPolicyExitCode)."
                    }

                    $afterRaw = bcdedit /store $currentDiskBcdPath /enum $defaultId /v 2>&1
                    $afterExitCode = $LASTEXITCODE
                    Add-CommandOutput -Header "--- BCD AFTER CHANGE (Disk $($diskGroup.Name)) ---" -Output $afterRaw
                    if ($afterExitCode -ne 0 -or ($afterRaw -join "`n") -notmatch '(?im)^\s*bootstatuspolicy\s+IgnoreAllFailures\s*$') {
                        throw "Post-change verification failed for default loader $defaultId."
                    }

                    $changedDisks++
                    $script_final_status = $STATUS_SUCCESS
                    Write-ScriptLog -Message "Disk $($diskGroup.Name): successfully set and verified bootstatuspolicy IgnoreAllFailures for validated default entry $defaultId"
                }
                catch {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): BCD transaction failed: $($_.Exception.Message)"
                    if ($bcdWriteStarted -and (Test-Path -LiteralPath $bcdBackupPath -PathType Leaf)) {
                        try {
                            Copy-Item -LiteralPath $bcdBackupPath -Destination $currentDiskBcdPath -Force -ErrorAction Stop
                            if ((Get-Item -LiteralPath $currentDiskBcdPath -Force -ErrorAction Stop).Length -ne $backupLength) {
                                throw 'Restored BCD length does not match the verified backup.'
                            }
                            Write-ScriptLog -Level Warning -Message "Disk $($diskGroup.Name): restored the verified BCD backup after transaction failure"
                        }
                        catch {
                            Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): CRITICAL BCD rollback failure: $($_.Exception.Message)"
                        }
                    }
                }
            }
            else {
                $failedDisks++
                Write-ScriptLog -Level Warning -Message "Disk $($diskGroup.Name): unable to identify the explicit default loader from boot manager"
            }
        }
        else {
            $skippedDisks++
            Write-ScriptLog -Message "Disk $($diskGroup.Name): skipped because BCD store or OS loader was not found"
        }
    }
}
catch {
    Write-ScriptLog -Level Error -Message "An error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    if ($assignedOsLetters.Count -gt 0) {
        Write-ScriptLog -Message "Cleaning up temporarily assigned Windows partition drive letters..."
        foreach ($osMount in $assignedOsLetters) {
            try {
                Invoke-IgnoreAllFailuresDiskPart -Operation 'os-remove' -Commands @(
                    "select disk $($osMount.DiskNumber)"
                    "select partition $($osMount.PartitionNumber)"
                    "remove letter=$($osMount.Letter) noerr"
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                if (Test-Path -LiteralPath "$($osMount.Letter):\" -PathType Container) {
                    throw 'Temporary Windows partition drive letter removal could not be verified.'
                }
            }
            catch {
                Write-ScriptLog -Level Error -Message "Failed to remove temporary Windows partition letter $($osMount.Letter): $($_.Exception.Message)"
                $script_final_status = $STATUS_ERROR
            }
        }
    }

    # Cleanup: Remove temporarily assigned EFI drive letters to avoid leaving orphaned mounts on rescue host
    if ($assignedEfiLetters.Count -gt 0) {
        Write-ScriptLog -Message "Cleaning up temporarily assigned EFI partition drive letters..."
        foreach ($efiMount in $assignedEfiLetters) {
            try {
                Write-ScriptLog -Message "Removing drive letter $($efiMount.Letter): from EFI partition (Disk $($efiMount.DiskNumber))"
                Invoke-IgnoreAllFailuresDiskPart -Operation 'bcd-remove' -Commands @(
                    "select disk $($efiMount.DiskNumber)"
                    "select partition $($efiMount.PartitionNumber)"
                    "remove letter=$($efiMount.Letter) noerr"
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                if (Test-Path -LiteralPath "$($efiMount.Letter):\" -PathType Container) {
                    throw 'Temporary EFI drive letter removal could not be verified.'
                }
            }
            catch {
                Write-ScriptLog -Level Warning -Message "Failed to remove drive letter $($efiMount.Letter): from EFI partition, but continuing cleanup: $($_.Exception.Message)"
                $script_final_status = $STATUS_ERROR
            }
        }
    }

    $identityRestorationFailed = $false
    if ($repairDiskIdentityRecord) {
        foreach ($diskNumber in @($gptCollisionDiskNumbers | Sort-Object -Unique)) {
            try {
                Invoke-IgnoreAllFailuresDiskPart -Operation 'source-before-repair-host-restore' -Commands @(
                    "select disk $diskNumber"
                    'offline disk'
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                $sourceDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
                $sourceIdentity = Get-IgnoreAllFailuresDiskIdentity -DiskNumber $diskNumber
                if (-not $sourceDisk.IsOffline -or $sourceIdentity.Value -ine $repairDiskIdentityRecord.OriginalValue) {
                    throw "Source Disk $diskNumber was not offline with its unchanged original GPT identity."
                }
            }
            catch {
                $identityRestorationFailed = $true
                Write-ScriptLog -Level Error -Message "CRITICAL: Could not safely offline source Disk ${diskNumber}: $($_.Exception.Message)"
            }
        }
        if (-not $identityRestorationFailed) {
            try {
                Restore-IgnoreAllFailuresRepairIdentity -Record $repairDiskIdentityRecord
                Write-ScriptLog -Message 'Repair VM OS disk GPT identity restored and verified.'
            }
            catch {
                $identityRestorationFailed = $true
                Write-ScriptLog -Level Error -Message "CRITICAL: Failed to restore the repair VM OS disk identity: $($_.Exception.Message)"
            }
        }
    }

    foreach ($identityRecord in @($collisionDiskRecords | Sort-Object DiskNumber -Descending)) {
        try {
            Restore-IgnoreAllFailuresSourceIdentity -Record $identityRecord
            Write-ScriptLog -Message "Disk $($identityRecord.DiskNumber) original MBR identity restored and verified."
        }
        catch {
            $identityRestorationFailed = $true
            Write-ScriptLog -Level Error -Message "CRITICAL: Failed to restore Disk $($identityRecord.DiskNumber) identity: $($_.Exception.Message)"
        }
    }
    if ($identityRestorationFailed) { $script_final_status = $STATUS_ERROR }
    
    # Final logging of report via Log-Info (NOT Write-Output)
    if ($successReport.Count -gt 0) {
        foreach ($reportLine in $successReport) {
            Write-ScriptLog -Message $reportLine
        }
    }

    if ($changedDisks -eq 0 -or $failedDisks -gt 0) {
        $script_final_status = $STATUS_ERROR
    }

    Write-ScriptLog -Message "Summary: processed=$processedDisks, skipped=$skippedDisks, failed=$failedDisks, changed=$changedDisks"
    Write-ScriptLog -Message "Script completed with status: $script_final_status"
    Write-ScriptLog -Message "Desktop log file: $logFile"
}

# Proper return for Azure Telemetry
return $script_final_status
