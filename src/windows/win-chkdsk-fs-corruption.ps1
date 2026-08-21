<#
.SYNOPSIS
    Detects attached Windows OS disks from a repair VM and safely repairs verified
    NTFS file system corruption with CHKDSK.

.DESCRIPTION
    This script runs from a rescue VM to check and repair NTFS file system corruption
    on the validated Windows partition of each attached faulty OS disk.

    It performs the following steps:
    1. Identifies and excludes repair-host OS, boot, system, and pagefile disks.
    2. Enumerates attached partitions via Get-Disk-Partitions and validates Windows targets.
    3. Temporarily mounts eligible unlettered data partitions and restores all mount state.
    4. Queries the Windows partition dirty bit using fsutil and Win32_Volume data.
    5. Runs CHKDSK /f when the dirty bit is set and verifies that it is cleared.
    6. Preserves source disk identity across GPT and MBR collision handling.

    This resolves VMs stuck at boot showing "Scanning and repairing drive" or
    "Checking file system on C:" messages. Running CHKDSK from a rescue VM avoids
    interruptions that occur when the OS runs it during boot.

.PARAMETER None
    This script does not accept custom parameters. It automatically processes the
    validated Windows partition on each attached target OS disk.

.EXECUTION_CONTEXT
    This is a repair-VM-only script. Run it through the VMRepair workflow against an
    attached copy of the affected Windows OS disk. It refuses to process the repair
    VM's OS, boot, system, and pagefile disks.

.SCENARIO_RECREATION
    Use only a disposable test VM and take an OS disk snapshot before injecting the
    test state. Setting the dirty bit exercises this script's detection and CHKDSK
    path; it does not create arbitrary NTFS metadata corruption.

    From Azure Cloud Shell or an authenticated PowerShell terminal, set and verify
    the dirty bit through Azure Run Command:

    az vm run-command invoke `
        --resource-group <resource-group> `
        --name <disposable-test-vm> `
        --command-id RunPowerShellScript `
        Start-Process -FilePath "fsutil.exe" -ArgumentList "dirty query C:" -Wait -NoNewWindow
        Start-Process -FilePath "fsutil.exe" -ArgumentList "dirty set C:" -Wait -NoNewWindow
        Start-Process -FilePath "fsutil.exe" -ArgumentList "dirty query C:" -Wait -NoNewWindow

    The final query should report that C: is dirty. The exact message can vary with
    the guest OS display language. Do not reboot the test VM after setting the bit,
    because startup CHKDSK may consume and clear the test condition before the repair
    script runs.

    Next, use the normal VMRepair create/attach workflow and run this script on the
    repair VM:

    az vm repair run `
        --resource-group <resource-group> `
        --name <disposable-test-vm> `
        --run-id win-chkdsk-fs-corruption `
        --run-on-repair

    Expected repair log sequence:
    1. The attached Windows disk and NTFS partition are validated.
    2. The dirty bit is reported as set.
    3. CHKDSK /f runs and returns an accepted exit code.
    4. The dirty bit is re-queried and verified clear.
    5. Temporary drive letters and disk identities are restored.

.VERIFICATION
    After restoring and starting the disposable test VM, verify the volume state:

    fsutil.exe dirty query C:

    Expected: C: is not dirty. Also confirm that the repair log reports final status
    success, Failed=0, and Repaired=1 for the single attached test OS disk.

.EXAMPLE
    .\win-chkdsk-fs-corruption.ps1

.NOTES
    Name:    win-chkdsk-fs-corruption.ps1
    Version: 1.3
    Author:  Tony.Mocanu@Microsoft.com

.VERSION
        v1.3: [August 2026] - Aligned physical disk discovery and collision handling with
                          win-sac-on, win-LKGC, and GA_offlinefixer.
                        - Excludes repair-host critical disks and validates Windows targets.
                        - Supports safe temporary mounts and preserves source disk identities.
                        - Verifies native exit codes and the cleared NTFS dirty bit.
                        - Restricts CHKDSK to the validated Windows partition.
                        - Emits CHKDSK evidence while keeping DiskPart diagnostics out of
                          result output.
                                                - Emits structured VMRepair telemetry for lifecycle, target validation,
                                                    CHKDSK outcomes, and every catch block.
                                                - Adds ShouldProcess support to disk identity mutation helpers.
    v1.2: [July 2026]   - Refactored logging to support desktop-first paths with SYSTEM fallback.
                        - Aligned dependency path validation and added explicit loop summaries.
    v1.1: [May 2026]    - Guarded nested VM discovery when Hyper-V is unavailable.
                        - Added Gen2 unlettered EFI fallback and dynamic letter assignment.
    v1.0: Initial commit.

.LINK
    https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error
#>

[CmdletBinding()]
param()

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

# ==============================================================================
# 2. SYSTEM-SAFE LOG CONFIGURATION (LOG-01, DOC-01)
# ==============================================================================
# Attempt to resolve the standard User Desktop first (LOG-01)
$logDir = [Environment]::GetFolderPath('Desktop')

# Secure fallback to system-wide TEMP directories if Desktop is empty/SYSTEM profile (DOC-01)
if ([string]::IsNullOrEmpty($logDir)) {
    $logDir = $env:TEMP
    if ([string]::IsNullOrEmpty($logDir)) {
        $logDir = "C:\Windows\Temp"
    }
}

if (-not (Test-Path -Path $logDir)) {
    $null = New-Item -ItemType Directory -Path $logDir -Force
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path -Path $logDir -ChildPath "chkdsk-repair_$timestamp.log"

# Unified logging helper to ensure stdout and physical file are consistently fed
function Write-ScriptLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'OUTPUT')]
        [string]$Level = 'INFO'
    )
    $formattedMsg = "[$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')] [$Level] $Message"

    # Direct to correct stream or custom framework logger
    switch ($Level) {
        'ERROR' {
            if (Get-Command Log-Error -ErrorAction SilentlyContinue) { Log-Error $Message }
            else { Write-Error $formattedMsg }
        }
        'WARNING' {
            if (Get-Command Log-Warning -ErrorAction SilentlyContinue) { Log-Warning $Message }
            else { Write-Warning $formattedMsg }
        }
        'OUTPUT' {
            if (Get-Command Log-Output -ErrorAction SilentlyContinue) { Log-Output $Message }
            else { Write-Information $formattedMsg -InformationAction Continue }
        }
        Default {
            if (Get-Command Log-Info -ErrorAction SilentlyContinue) { Log-Info $Message }
            else { Write-Information $formattedMsg -InformationAction Continue }
        }
    }

    # Write to local physical file
    $formattedMsg | Out-File -FilePath $logFile -Append -Encoding utf8
}

$script:RepairScriptVersion = '1.3'
$script:ExecutionStarted = Get-Date

function Write-ChkdskTelemetry {
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
    $level = if ($Event -eq 'Error') { 'ERROR' } else { 'INFO' }
    Write-ScriptLog -Message "[Telemetry] $json" -Level $level
}

function Write-ChkdskCatchTelemetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CatchName,

        [string]$Stage = '',

        [string]$DiskNumber = '',

        [string]$TargetDrive = '',

        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    Write-ChkdskTelemetry -Event Error -Message "Catch block: $CatchName" -Properties @{
        CoverageCategory = 'CatchBlock'
        CatchName = $CatchName
        Stage = $Stage
        DiskNumber = $DiskNumber
        TargetDrive = $TargetDrive
        Error = $ErrorMessage
    }
}

function Get-ChkdskAvailableTempDriveLetter {
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

function Test-ChkdskDataPartition {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Partition
    )

    if ($Partition.IsHidden) {
        return $false
    }

    $gptType = ([string]$Partition.GptType).Trim().Trim('{', '}')
    if ($gptType) {
        return $gptType -ieq 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
    }

    return ([string]$Partition.Type) -notmatch 'Reserved|System'
}

function Get-ChkdskDiskIdentity {
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

function Invoke-ChkdskDiskPart {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Commands,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $output = $Commands | diskpart 2>&1
    foreach ($outputLine in @($output)) {
        if ($outputLine) {
            Write-ScriptLog "[diskpart][$Operation] $outputLine" 'INFO'
        }
    }
}

function Set-ChkdskTemporarySourceDiskIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Record
    )

    if ($Record.PartitionStyle -ne 'MBR') {
        throw 'Temporary source disk identities are permitted only for MBR disks.'
    }

    if (-not $PSCmdlet.ShouldProcess("Disk $($Record.DiskNumber)", 'Assign a temporary MBR identity and online the disk')) {
        return
    }

    Invoke-ChkdskDiskPart -Operation 'collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
        'online disk'
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-ChkdskDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw "Disk $($Record.DiskNumber) could not be brought online with its verified temporary identity."
    }
}

function Restore-ChkdskSourceDiskIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Record
    )

    Invoke-ChkdskDiskPart -Operation 'collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        'offline disk'
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-ChkdskDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if (-not $restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw "Disk $($Record.DiskNumber) did not return to its original offline identity."
    }
}

function Set-ChkdskTemporaryRepairDiskIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Record
    )

    if (-not $PSCmdlet.ShouldProcess("Repair host Disk $($Record.DiskNumber)", 'Assign a temporary GPT identity')) {
        return
    }

    Invoke-ChkdskDiskPart -Operation 'repair-host-collision-prepare' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.TemporaryDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $currentIdentity = Get-ChkdskDiskIdentity -DiskNumber $Record.DiskNumber
    $currentDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($currentDisk.IsOffline -or $currentIdentity.Value -ine $Record.TemporaryValue) {
        throw 'The repair VM OS disk did not retain a verified temporary GPT identity.'
    }
}

function Restore-ChkdskRepairDiskIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Record
    )

    Invoke-ChkdskDiskPart -Operation 'repair-host-collision-restore' -Commands @(
        "select disk $($Record.DiskNumber)"
        "uniqueid disk id=$($Record.OriginalDiskPartValue)"
    )
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $restoredIdentity = Get-ChkdskDiskIdentity -DiskNumber $Record.DiskNumber
    $restoredDisk = Get-Disk -Number $Record.DiskNumber -ErrorAction Stop
    if ($restoredDisk.IsOffline -or $restoredIdentity.Value -ine $Record.OriginalValue) {
        throw 'The repair VM OS disk did not return to its original GPT identity.'
    }
}

# ==============================================================================
# 3. CORE REPAIR LOGIC
# ==============================================================================
$script_final_status = $STATUS_ERROR
$temporaryMounts = @()
$collisionDiskRecords = @()
$gptCollisionDiskNumbers = @()
$repairDiskIdentityRecord = $null
$processedCount = 0
$skippedCount = 0
$fixedCount = 0
$failedCount = 0
$targetDiskCount = 0

try {
    Write-ScriptLog "Script execution started. Logging active at: $logFile" "INFO"
    Write-ChkdskTelemetry -Event Start -Message 'Starting CHKDSK file-system repair' -Properties @{
        ScriptName = 'win-chkdsk-fs-corruption.ps1'
        ScriptVersion = $script:RepairScriptVersion
        ExecutionMode = 'REPAIR_VM_ONLY'
        LogFile = $logFile
    }

    # Stop nested guest VM if running (Only calls Hyper-V cmdlets after validation - DEP-02)
    $hyperVModuleAvailable = @(Get-Module -ListAvailable -Name 'Hyper-V').Count -gt 0
    if ($hyperVModuleAvailable -and (Get-Command -Name 'Get-VM' -ErrorAction SilentlyContinue)) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine) {
            if ($guestHyperVVirtualMachine.State -eq 'Running') {
                Write-ScriptLog "Stopping nested guest VM: $($guestHyperVVirtualMachine.VMName)" "INFO"
                try {
                    Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-ScriptLog "Failed to stop nested guest VM '$($guestHyperVVirtualMachine.VMName)' via Stop-VM: $errorMessage. Continuing but with limited raw write access risks." "WARNING"
                    Write-ChkdskCatchTelemetry -CatchName 'NestedVmStop' -Stage 'Preflight' -TargetDrive $env:SystemDrive -ErrorMessage $errorMessage
                }
            }
        }
    }
    # No Hyper-V support means there is no nested guest to stop.
    else {
        Write-ScriptLog "Hyper-V module/cmdlets not available on this host -> skipping nested VM discovery" "INFO"
    }

    # Identify every disk that belongs to the repair host before touching attached disks.
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $rescueOsPartition = Get-Partition -DriveLetter $rescueDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $rescueOsPartition -or $null -eq $rescueOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the repair VM OS disk from $($env:SystemDrive)."
    }
    $rescueDiskNumber = [int]$rescueOsPartition.DiskNumber
    $repairDiskIdentity = Get-ChkdskDiskIdentity -DiskNumber $rescueDiskNumber

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
        if ($pageFilePartition) {
            $protectedDiskNumbers += [int]$pageFilePartition.DiskNumber
        }
    }
    $protectedDiskNumbers = @($protectedDiskNumbers | Sort-Object -Unique)
    Write-ScriptLog "Protected repair-host disk numbers: $($protectedDiskNumbers -join ', ')." 'INFO'

    $azureVirtualDiskNumbers = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
        Where-Object { $_.Model -like 'Microsoft Virtual Disk*' } |
        ForEach-Object { [int]$_.Index })
    $attachedDisks = @(Get-Disk -ErrorAction Stop | Where-Object {
        $_.Number -in $azureVirtualDiskNumbers -and $_.Number -notin $protectedDiskNumbers
    })
    if ($attachedDisks.Count -eq 0) {
        throw 'REPAIR-ONLY SCRIPT: No attached Microsoft virtual disk was found.'
    }

    # Match the tested SAC/LKGC collision path so source disk identities are preserved.
    $collisionDisks = @($attachedDisks | Where-Object {
        $_.IsOffline -and [string]$_.OfflineReason -eq 'Collision'
    })
    foreach ($collisionDisk in $collisionDisks) {
        $originalIdentity = Get-ChkdskDiskIdentity -DiskNumber $collisionDisk.Number
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
                Write-ScriptLog 'Temporarily changing only the repair VM OS disk GPT identity; the source identity remains unchanged.' 'WARNING'
                Write-ChkdskTelemetry -Event Operation -Message 'Preparing GPT collision resolution' -Properties @{
                    CoverageCategory = 'Safety'
                    Operation = 'RepairHostTemporaryIdentity'
                    SourceDiskNumber = [string]$collisionDisk.Number
                    RepairDiskNumber = [string]$rescueDiskNumber
                }
                Set-ChkdskTemporaryRepairDiskIdentity -Record $repairDiskIdentityRecord
            }

            $gptCollisionDiskNumbers += [int]$collisionDisk.Number
            Invoke-ChkdskDiskPart -Operation 'source-gpt-online' -Commands @(
                "select disk $($collisionDisk.Number)"
                'online disk'
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $releasedDisk = Get-Disk -Number $collisionDisk.Number -ErrorAction Stop
            $releasedIdentity = Get-ChkdskDiskIdentity -DiskNumber $collisionDisk.Number
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
        Set-ChkdskTemporarySourceDiskIdentity -Record $identityRecord
    }

    $attachedDiskNumbers = @($attachedDisks | Select-Object -ExpandProperty Number)
    $partitionList = @(Get-Disk-Partitions)
    if ($partitionList.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }
    $targetDiskGroups = @($partitionList |
        Where-Object {
            [int]$_.DiskNumber -in $attachedDiskNumbers -and
            [int]$_.DiskNumber -notin $protectedDiskNumbers
        } |
        Group-Object DiskNumber)
    if ($targetDiskGroups.Count -eq 0) {
        throw 'The partition helper returned no partitions from an attached repair disk.'
    }

    foreach ($targetDiskGroup in $targetDiskGroups) {
        $diskNumber = [int]$targetDiskGroup.Name
        $diskPartitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop)
        $targetWindowsPartition = $null
        $targetWindowsDriveLetter = $null

        # Prove this is a Windows OS disk before checking any volume on it.
        foreach ($partition in @($diskPartitions | Sort-Object Size -Descending)) {
            if (-not (Test-ChkdskDataPartition -Partition $partition)) { continue }

            $candidateLetter = [string]$partition.DriveLetter
            if (-not $candidateLetter -or $candidateLetter -eq [char]0) {
                $candidateLetter = Get-ChkdskAvailableTempDriveLetter
                if (-not $candidateLetter) {
                    throw "No temporary drive letter is available to inspect Disk $diskNumber."
                }
                Invoke-ChkdskDiskPart -Operation 'os-probe-assign' -Commands @(
                    "select disk $diskNumber"
                    "select partition $($partition.PartitionNumber)"
                    "assign letter=$candidateLetter"
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container)) {
                    throw "Temporary mount ${candidateLetter}: failed for Disk $diskNumber Partition $($partition.PartitionNumber)."
                }
                $temporaryMounts += [pscustomobject]@{
                    DiskNumber = $diskNumber
                    PartitionNumber = [int]$partition.PartitionNumber
                    DriveLetter = $candidateLetter
                }
            }

            $systemHive = "${candidateLetter}:\Windows\System32\config\SYSTEM"
            $winloadExe = "${candidateLetter}:\Windows\System32\winload.exe"
            $winloadEfi = "${candidateLetter}:\Windows\System32\winload.efi"
            if ((Test-Path -LiteralPath $systemHive -PathType Leaf) -and
                ((Test-Path -LiteralPath $winloadExe -PathType Leaf) -or
                 (Test-Path -LiteralPath $winloadEfi -PathType Leaf))) {
                $targetWindowsPartition = $partition
                $targetWindowsDriveLetter = $candidateLetter
                break
            }
        }

        if (-not $targetWindowsPartition) {
            Write-ScriptLog "Skipping Disk $diskNumber because no Windows loader and SYSTEM hive were found." 'WARNING'
            $skippedCount++
            continue
        }
        $targetDiskCount++

        $partition = $targetWindowsPartition
        $driveLetter = $targetWindowsDriveLetter
        Write-ScriptLog "Validated Windows target on Disk $diskNumber Partition $($partition.PartitionNumber) at ${driveLetter}:." 'INFO'
        Write-ChkdskTelemetry -Event Operation -Message 'Validated Windows repair target' -Properties @{
            CoverageCategory = 'TargetValidation'
            DiskNumber = [string]$diskNumber
            PartitionNumber = [string]$partition.PartitionNumber
            TargetDrive = "${driveLetter}:"
        }

        try {
            $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
            if ([string]$volume.FileSystem -ine 'NTFS') {
                throw "Validated Windows partition ${driveLetter}: uses '$($volume.FileSystem)', not NTFS."
            }

            $processedCount++
            $letter = "${driveLetter}:"
            Write-ScriptLog "Checking validated target Disk $diskNumber Partition $($partition.PartitionNumber) at $letter" 'INFO'

            $fsutilOutput = & fsutil.exe dirty query $letter 2>&1
            $fsutilExitCode = $LASTEXITCODE
            foreach ($fsutilLine in @($fsutilOutput)) {
                if ($fsutilLine) { Write-ScriptLog "[fsutil] $fsutilLine" 'OUTPUT' }
            }
            if ($fsutilExitCode -ne 0) {
                throw "fsutil dirty query failed for $letter with exit code $fsutilExitCode."
            }

            # Win32_Volume exposes a locale-independent Boolean dirty-bit value.
            $volumeState = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$letter'" -ErrorAction Stop |
                Select-Object -First 1
            if ($null -eq $volumeState -or $null -eq $volumeState.DirtyBitSet) {
                throw "Could not obtain a reliable dirty-bit state for $letter."
            }

            if (-not [bool]$volumeState.DirtyBitSet) {
                Write-ScriptLog "$letter dirty bit is not set; CHKDSK /f is not required." 'INFO'
                Write-ChkdskTelemetry -Event Success -Message 'CHKDSK repair not required' -Properties @{
                    CoverageCategory = 'RepairOutcome'
                    Outcome = 'NoOp'
                    DiskNumber = [string]$diskNumber
                    TargetDrive = $letter
                    DirtyBitSet = $false
                }
                continue
            }

            Write-ScriptLog "$letter dirty bit is set; executing CHKDSK /f." 'WARNING'
            Write-ChkdskTelemetry -Event Operation -Message 'Starting CHKDSK repair' -Properties @{
                CoverageCategory = 'RepairOperation'
                Operation = 'ChkdskFix'
                DiskNumber = [string]$diskNumber
                TargetDrive = $letter
                DirtyBitSet = $true
            }
            $chkdskResults = & chkdsk.exe $letter /f 2>&1
            $chkdskExitCode = $LASTEXITCODE
            foreach ($resultLine in @($chkdskResults)) {
                if ($resultLine -and ([string]$resultLine).Trim()) {
                    ([string]$resultLine) | Out-File -FilePath $logFile -Append -Encoding utf8
                }
            }

            $summaryLines = @($chkdskResults | Where-Object {
                ([string]$_).Trim() -match '(Windows has scanned|Windows made corrections|Windows has made corrections|found no problems|corrected errors|failed to transfer|could not fix|total disk space|KB in bad sectors|No further action)'
            })
            foreach ($summaryLine in $summaryLines) {
                Write-ScriptLog "[chkdsk] $(([string]$summaryLine).Trim())" 'OUTPUT'
            }
            Write-ScriptLog "[chkdsk] Drive=$letter ExitCode=$chkdskExitCode SummaryLines=$($summaryLines.Count)" 'OUTPUT'

            if ($chkdskExitCode -notin @(0, 1, 2)) {
                Write-ScriptLog "CHKDSK failed on $letter with exit code $chkdskExitCode." 'ERROR'
                Write-ChkdskTelemetry -Event Error -Message 'CHKDSK returned an unsupported exit code' -Properties @{
                    CoverageCategory = 'RepairOutcome'
                    Outcome = 'Failed'
                    DiskNumber = [string]$diskNumber
                    TargetDrive = $letter
                    ExitCode = $chkdskExitCode
                }
                $failedCount++
                continue
            }

            $repairedVolumeState = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$letter'" -ErrorAction Stop |
                Select-Object -First 1
            if ($null -eq $repairedVolumeState -or $null -eq $repairedVolumeState.DirtyBitSet -or
                [bool]$repairedVolumeState.DirtyBitSet) {
                Write-ScriptLog "CHKDSK returned exit code $chkdskExitCode, but $letter still reports a dirty or unknown state." 'ERROR'
                Write-ChkdskTelemetry -Event Error -Message 'CHKDSK post-repair dirty-bit verification failed' -Properties @{
                    CoverageCategory = 'RepairOutcome'
                    Outcome = 'VerificationFailed'
                    DiskNumber = [string]$diskNumber
                    TargetDrive = $letter
                    ExitCode = $chkdskExitCode
                }
                $failedCount++
                continue
            }

            $fixedCount++
            Write-ScriptLog "CHKDSK completed on $letter with exit code $chkdskExitCode and a verified clear dirty bit." 'INFO'
            Write-ChkdskTelemetry -Event Success -Message 'CHKDSK repair completed and verified' -Properties @{
                CoverageCategory = 'RepairOutcome'
                Outcome = 'Repaired'
                DiskNumber = [string]$diskNumber
                TargetDrive = $letter
                ExitCode = $chkdskExitCode
                DirtyBitSet = $false
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            $failedCount++
            Write-ScriptLog "Failed processing validated Windows partition on Disk ${diskNumber}: $errorMessage" 'ERROR'
            Write-ChkdskCatchTelemetry -CatchName 'WindowsPartitionProcessing' -Stage 'DiscoveryOrRepair' -DiskNumber "$diskNumber" -TargetDrive "${driveLetter}:" -ErrorMessage $errorMessage
        }
    }

    if ($targetDiskCount -eq 0) {
        throw 'No attached Windows OS disk passed loader and SYSTEM hive validation.'
    }
    if ($failedCount -gt 0) {
        throw "CHKDSK failed on $failedCount partition(s)."
    }

    Write-ScriptLog "SCRIPT FINISHED PROPERLY, WINDOWS_PARTITIONS=$processedCount, REPAIRED=$fixedCount, FAILED=$failedCount" 'OUTPUT'
    $script_final_status = $STATUS_SUCCESS
}
catch {
    $errorMessage = $_.Exception.Message
    Write-ScriptLog "An unhandled execution crash occurred: $errorMessage" "ERROR"
    Write-ChkdskCatchTelemetry -CatchName 'UnhandledExecution' -Stage 'Main' -ErrorMessage $errorMessage
    $script_final_status = $STATUS_ERROR
}
finally {
    foreach ($mount in @($temporaryMounts | Sort-Object DiskNumber, PartitionNumber -Unique)) {
        try {
            Invoke-ChkdskDiskPart -Operation 'mount-cleanup' -Commands @(
                "select disk $($mount.DiskNumber)"
                "select partition $($mount.PartitionNumber)"
                "remove letter=$($mount.DriveLetter) noerr"
            )
            Update-HostStorageCache -ErrorAction SilentlyContinue
            $cleanedPartition = Get-Partition -DiskNumber $mount.DiskNumber -PartitionNumber $mount.PartitionNumber -ErrorAction Stop
            if ([string]$cleanedPartition.DriveLetter -ieq [string]$mount.DriveLetter) {
                throw 'Temporary drive letter removal could not be verified.'
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-ScriptLog "Failed to remove temporary letter $($mount.DriveLetter): $errorMessage" 'ERROR'
            Write-ChkdskCatchTelemetry -CatchName 'TemporaryMountCleanup' -Stage 'Cleanup' -DiskNumber "$($mount.DiskNumber)" -TargetDrive "$($mount.DriveLetter):" -ErrorMessage $errorMessage
            $script_final_status = $STATUS_ERROR
        }
    }

    $identityRestorationFailed = $false
    if ($repairDiskIdentityRecord) {
        foreach ($diskNumber in @($gptCollisionDiskNumbers | Sort-Object -Unique)) {
            try {
                Invoke-ChkdskDiskPart -Operation 'source-before-repair-host-restore' -Commands @(
                    "select disk $diskNumber"
                    'offline disk'
                )
                Update-HostStorageCache -ErrorAction SilentlyContinue
                $sourceDisk = Get-Disk -Number $diskNumber -ErrorAction Stop
                $sourceIdentity = Get-ChkdskDiskIdentity -DiskNumber $diskNumber
                if (-not $sourceDisk.IsOffline -or
                    $sourceIdentity.Value -ine $repairDiskIdentityRecord.OriginalValue) {
                    throw "Source Disk $diskNumber was not offline with its unchanged original GPT identity."
                }
            }
            catch {
                $errorMessage = $_.Exception.Message
                $identityRestorationFailed = $true
                Write-ScriptLog "CRITICAL: Could not safely offline source Disk ${diskNumber}: $errorMessage" 'ERROR'
                Write-ChkdskCatchTelemetry -CatchName 'SourceGptOffline' -Stage 'IdentityRestore' -DiskNumber "$diskNumber" -ErrorMessage $errorMessage
            }
        }

        if (-not $identityRestorationFailed) {
            try {
                Restore-ChkdskRepairDiskIdentity -Record $repairDiskIdentityRecord
                Write-ScriptLog 'Repair VM OS disk GPT identity restored and verified.' 'INFO'
            }
            catch {
                $errorMessage = $_.Exception.Message
                $identityRestorationFailed = $true
                Write-ScriptLog "CRITICAL: Failed to restore the repair VM OS disk identity: $errorMessage" 'ERROR'
                Write-ChkdskCatchTelemetry -CatchName 'RepairDiskIdentityRestore' -Stage 'IdentityRestore' -DiskNumber "$($repairDiskIdentityRecord.DiskNumber)" -ErrorMessage $errorMessage
            }
        }
    }

    foreach ($identityRecord in @($collisionDiskRecords | Sort-Object DiskNumber -Descending)) {
        try {
            Restore-ChkdskSourceDiskIdentity -Record $identityRecord
            Write-ScriptLog "Disk $($identityRecord.DiskNumber) original MBR identity restored and verified." 'INFO'
        }
        catch {
            $errorMessage = $_.Exception.Message
            $identityRestorationFailed = $true
            Write-ScriptLog "CRITICAL: Failed to restore Disk $($identityRecord.DiskNumber) identity: $errorMessage" 'ERROR'
            Write-ChkdskCatchTelemetry -CatchName 'SourceMbrIdentityRestore' -Stage 'IdentityRestore' -DiskNumber "$($identityRecord.DiskNumber)" -ErrorMessage $errorMessage
        }
    }
    if ($identityRestorationFailed) {
        $script_final_status = $STATUS_ERROR
    }

    Write-ScriptLog "Partition Summary: Processed=$processedCount | Skipped=$skippedCount | Fixed=$fixedCount | Failed=$failedCount" 'INFO'
    Write-ScriptLog "Final script status: $script_final_status" "INFO"
    $completionEvent = if ($script_final_status -eq $STATUS_SUCCESS) { 'Success' } else { 'Error' }
    Write-ChkdskTelemetry -Event $completionEvent -Message 'CHKDSK repair script completed' -Properties @{
        CoverageCategory = 'ScriptOutcome'
        Status = [string]$script_final_status
        Processed = $processedCount
        Skipped = $skippedCount
        Repaired = $fixedCount
        Failed = $failedCount
        DurationMilliseconds = [int64]((Get-Date) - $script:ExecutionStarted).TotalMilliseconds
    }
    Write-ScriptLog "Script finalized. Destination log package details: $logFile" "INFO"
}

# Ensure the status gets exited safely (ERR-01)
return $script_final_status
