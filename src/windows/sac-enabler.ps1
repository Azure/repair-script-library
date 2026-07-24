<#
.SYNOPSIS
    Enables SAC and Serial Console boot settings on attached Windows disks, including BIOS and UEFI layouts.

.DESCRIPTION
    This script runs only from a repair VM to enable SAC/EMS on an attached OS disk's BCD store.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
       OS detection accepts either winload.exe or winload.efi.
    1a. For Gen2 disks where the EFI partition has no drive letter, uses diskpart to
        temporarily assign one so the BCD store can be accessed.
    2. Identifies the default boot entry GUID from the BCD bootmgr displayorder.
       If the default entry cannot be determined, the script logs an explicit warning.
    3. Logs the BCD configuration before any changes are made.
    4. Enables the boot menu with a 5-second timeout (displaybootmenu, timeout).
    5. Enables Boot EMS on the boot manager (bootems yes).
    6. Enables EMS on the default OS entry (ems ON).
    7. Configures EMS settings for serial console (EMSPORT:1, EMSBAUDRATE:115200).
    8. Logs the BCD configuration after changes for verification.

.NOTES
    Name:        sac-enabler.ps1
    Author:      Tony.Mocanu@Microsoft.com
    Requirement: Azure repair VM with an attached Windows OS disk
    DeployMode:  az vm repair run (with --run-on-repair)
    
    .VERSION
    v1.4: [July 2026]  - Restricted execution to repair VM mode (current).
                         - Uses Get-Disk-Partitions to enumerate Azure virtual disks.
                         - Detects repair vs. standard context from secondary disks returned by the helper.
                         - Mounts unlettered Gen2 Windows and EFI partitions temporarily.
                         - Probes unlettered partitions directly instead of assuming GPT metadata or size.
                         - Journals temporary mounts and removes only identity-matched stale mounts.
                         - Keeps dual logs on the repair host; does not write to the attached OS disk.
                         - Refuses BCD changes when a repair VM context is not detected.
                         - Fails closed if the repair VM OS disk cannot be identified.
                         - Filters out the repair VM OS disk before processing attached disks.
    v1.3: [July 2026]  - Added execution context detection and dual-logging.
                         - Detected rescue VM mode vs standard mode for context-aware error messages.
                         - Dual-logs to desktop and plugin directory for az vm repair auto-collection.
                         - **NEW SAFETY: Pre-flight checks, BCD backup, and post-change verification.
                         - **NEW SAFETY: Validates GUID format before making BCD edits.
                         - **NEW SAFETY: Verifies EMS was actually enabled after bcdedit commands.
                         - Added .ROLLBACK_RECOVERY section with disaster recovery instructions.
                         - Identified the Log-* wrapper pattern for shared-helper consolidation.
    v1.2: [May 2026]   - Fixed breaking exception when the Hyper-V module is not installed on the host.
                         - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.1: [May 2026]   - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v0.1: [Initial]    - Initial commit. Version 1.0 of the script.
    
    .EXECUTION_CONTEXT
    This script is classified as repair-VM-only. It detects repair context when the helper returns
    at least one disk other than the repair VM OS disk and refuses BCD changes when none exists.
    Use: az vm repair run -g <rg> -n <vm> --run-id win-sac-on --run-on-repair
    The repair VM OS disk is identified from $env:SystemDrive and excluded from all BCD operations.

.SCENARIO_RECREATION
    To recreate a testable scenario on a repair VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a repair VM.
    2. The BCD store is on the System Reserved (Gen1) or EFI (Gen2) partition, which
       may not have a drive letter. Find it by scanning all volumes (run as Admin):
Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { $d = $_.DriveLetter; @("$d`:\boot\bcd","$d`:\efi\microsoft\boot\bcd") | Where-Object { Test-Path $_ } | ForEach-Object { Write-Output "FOUND: $_" } }
       If nothing is found, the partition has no drive letter. For System Reserved (Gen1):
Get-Partition | Where-Object { -not $_.DriveLetter -and $_.Size -lt 1GB } | Format-Table DiskNumber, PartitionNumber, Size, Type
Set-Partition -DiskNumber <disk> -PartitionNumber <part> -NewDriveLetter S
       For EFI partitions (Gen2), Set-Partition won't work -- use diskpart instead:
              diskpart
              select disk <disk>
              select partition <part>
              assign letter=S
              exit
       Then check: Test-Path S:\boot\bcd  or  Test-Path S:\efi\microsoft\boot\bcd

       Example with two attached disks (from Disk Management):
         Disk 2 (Gen1): System Reserved (F:) 500 MB  |  Windows (G:) 126 GB
           -> BCD already accessible at F:\boot\bcd
         Disk 3 (Gen2): 450 MB (no letter)  |  EFI (no letter) 99 MB  |  Windows (H:) 126 GB
           -> EFI partitions are protected; use diskpart to assign a letter:
              diskpart
              select disk 3
              select partition 2
              assign letter=S
              exit
           -> BCD at S:\efi\microsoft\boot\bcd

    3. Once you have the BCD path, disable SAC/EMS to simulate a broken VM:

       Gen1 example (F:\boot\bcd):
bcdedit /store F:\boot\bcd /ems "{default}" OFF
bcdedit /store F:\boot\bcd /set "{bootmgr}" bootems no
bcdedit /store F:\boot\bcd /set "{bootmgr}" displaybootmenu no

       Gen2 example (S:\efi\microsoft\boot\bcd):
bcdedit /store S:\efi\microsoft\boot\bcd /ems "{default}" OFF
bcdedit /store S:\efi\microsoft\boot\bcd /set "{bootmgr}" bootems no
bcdedit /store S:\efi\microsoft\boot\bcd /set "{bootmgr}" displaybootmenu no

    4. Verify EMS is disabled:
bcdedit /store F:\boot\bcd /enum "{default}"
bcdedit /store S:\efi\microsoft\boot\bcd /enum "{default}"
    Expected: ems = No or absent, bootems = No or absent.
    5. Run the script. It should enable ems, bootems, displaybootmenu, and emssettings.
    6. Verify all SAC settings are now enabled (see .VERIFICATION section).

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-sac-on --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\sac-enabler_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "BCD AFTER SAC ENABLE" section present and return code 0 ($STATUS_SUCCESS).
    2. Manually verify the BCD store (replace drive letters with the ones found in step 2):

       Gen1 (System Reserved on F:):
bcdedit /store F:\boot\bcd /enum "{default}"
bcdedit /store F:\boot\bcd /enum "{bootmgr}"

       Gen2 (EFI partition -- use diskpart to assign a letter if needed, e.g. P:):
bcdedit /store P:\efi\microsoft\boot\bcd /enum "{default}"
bcdedit /store P:\efi\microsoft\boot\bcd /enum "{bootmgr}"

    Expected: ems = Yes on the OS entry, bootems = Yes on bootmgr,
    displaybootmenu = Yes, timeout = 5, EMSPORT = 1, EMSBAUDRATE = 115200.

    NOTE: For Gen2 disks, the script automatically assigns a temporary drive letter
    to the EFI System Partition via diskpart if Get-Disk-Partitions did not assign one.
    The temporary letter is removed after processing. Before each assignment, ownership
    is journaled under ProgramData so an exact stale mount can be removed on the next run.

.ROLLBACK_RECOVERY
    IF THE VM FAILS TO BOOT AFTER az vm repair restore:
    
    1. Boot the VM from the Windows installation media or attach to a repair VM.
    2. Locate the BCD backup file created by the script:
    - From repair VM: Look in the mounted disk for *.backup-* files
       - Example path: F:\boot\bcd.backup-20260724-153022 (or S:\efi\microsoft\boot\bcd.backup-...)
    3. Restore the BCD from backup:
       Gen1 (System Reserved):
       bcdedit /store F:\boot\bcd /import F:\boot\bcd.backup-20260724-153022
       
       Gen2 (EFI partition with assigned letter):
       bcdedit /store S:\efi\microsoft\boot\bcd /import S:\efi\microsoft\boot\bcd.backup-20260724-153022
    
    4. Verify the BCD was restored:
       bcdedit /store F:\boot\bcd /enum "{default}" | findstr /I "ems"
       Expected: ems = No (or absent)
    
    5. Boot the VM. It should start normally without SAC/EMS enabled.
    
    ALTERNATIVE (if BCD restore doesn't work):
    - Use sfc /scannow from Windows Recovery Environment to repair system files
    - Use bcdboot.exe to rebuild the BCD store from scratch
    - See internal troubleshooting guide: azure-vm-dump-issues.md
#>

# Initialization (path-validated)
$initPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\setup\init.ps1'
$diskPartitionsPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'

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

function Get-SacExecutionContext {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$TargetDiskGroups
    )

    if ($TargetDiskGroups.Count -gt 0) {
        return 'REPAIR_VM'
    }

    return 'STANDARD_VM'
}

function Get-AvailableTempDriveLetter {
    $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter)
    foreach ($letter in @('Z','Y','X','W','V','U','T','S','R','Q')) {
        if ($letter -notin $usedLetters -and -not (Test-Path -Path "${letter}:\")) {
            return $letter
        }
    }

    return $null
}

function Test-SacGptType {
    param(
        [AllowNull()]
        [object]$ActualType,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedType
    )

    $actual = ([string]$ActualType).Trim().Trim('{', '}')
    $expected = $ExpectedType.Trim().Trim('{', '}')
    return $actual -eq $expected
}

$script:SacTempMountStateDirectory = Join-Path -Path $env:ProgramData -ChildPath 'AzureVmRepair\SacEnabler\TempMounts'

function Get-SacDiskIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber
    )

    $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
    if (-not $disk) { return $null }

    $identityParts = @($disk.UniqueId, $disk.SerialNumber, $disk.Location) | Where-Object {
        -not [string]::IsNullOrWhiteSpace("$_")
    }
    if ($identityParts.Count -eq 0) { return $null }

    return ($identityParts -join '|')
}

function Register-SacTemporaryMount {
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $true)][char]$DriveLetter,
        [Parameter(Mandatory = $true)][ValidateSet('Windows', 'EFI')][string]$Kind
    )

    $diskIdentity = Get-SacDiskIdentity -DiskNumber $DiskNumber
    if (-not $diskIdentity) {
        Log-Warning "Disk ${DiskNumber}: temporary $Kind mount ownership cannot be persisted because the disk has no stable identity. Runtime finally cleanup will still be attempted."
        return $null
    }

    New-Item -Path $script:SacTempMountStateDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    $statePath = Join-Path -Path $script:SacTempMountStateDirectory -ChildPath (([guid]::NewGuid().ToString('N')) + '.json')
    $state = [ordered]@{
        DiskIdentity   = $diskIdentity
        DiskNumber     = $DiskNumber
        PartitionNumber = $PartitionNumber
        DriveLetter    = "$DriveLetter"
        Kind           = $Kind
        CreatedUtc     = [DateTime]::UtcNow.ToString('o')
    }
    $state | ConvertTo-Json | Set-Content -Path $statePath -Encoding UTF8 -ErrorAction Stop
    return $statePath
}

function Complete-SacTemporaryMountCleanup {
    param(
        [AllowNull()][string]$StatePath,
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $true)][char]$DriveLetter
    )

    if (-not $StatePath) { return }

    $partition = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -ErrorAction SilentlyContinue
    if (-not $partition -or "$($partition.DriveLetter)" -ne "$DriveLetter") {
        Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue
    }
    else {
        Log-Warning "Temporary letter ${DriveLetter}: remains on Disk $DiskNumber Partition $PartitionNumber. Ownership state retained for the next run."
    }
}

function Clear-SacStaleTemporaryMounts {
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$TargetDiskNumbers
    )

    if (-not (Test-Path -Path $script:SacTempMountStateDirectory -PathType Container)) { return }

    $targetIdentities = @{}
    foreach ($targetDiskNumber in $TargetDiskNumbers) {
        $identity = Get-SacDiskIdentity -DiskNumber $targetDiskNumber
        if ($identity) { $targetIdentities[$identity] = $targetDiskNumber }
    }

    foreach ($stateFile in @(Get-ChildItem -Path $script:SacTempMountStateDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $state = Get-Content -Path $stateFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $requiredValues = @($state.DiskIdentity, $state.PartitionNumber, $state.DriveLetter, $state.Kind)
            if (@($requiredValues | Where-Object { [string]::IsNullOrWhiteSpace("$_") }).Count -gt 0) {
                throw 'The ownership record is incomplete.'
            }

            if (-not $targetIdentities.ContainsKey("$($state.DiskIdentity)")) {
                Log-Warning "Discarding stale temporary-mount state '$($stateFile.Name)': its disk is not an attached repair target. No drive letter was removed."
                Remove-Item -Path $stateFile.FullName -Force -ErrorAction SilentlyContinue
                continue
            }

            $currentDiskNumber = [int]$targetIdentities["$($state.DiskIdentity)"]
            $partitionNumber = [int]$state.PartitionNumber
            $driveLetter = [char]("$($state.DriveLetter)")
            $partition = Get-Partition -DiskNumber $currentDiskNumber -PartitionNumber $partitionNumber -ErrorAction SilentlyContinue
            if (-not $partition -or "$($partition.DriveLetter)" -ne "$driveLetter") {
                Log-Info "Removing resolved temporary-mount state '$($stateFile.Name)'; the recorded letter is no longer assigned."
                Remove-Item -Path $stateFile.FullName -Force -ErrorAction SilentlyContinue
                continue
            }

            Log-Warning "Recovering stale $($state.Kind) letter ${driveLetter}: from Disk $currentDiskNumber Partition $partitionNumber."
            $removeOutput = @("select disk $currentDiskNumber", "select partition $partitionNumber", "remove letter=$driveLetter") | diskpart 2>&1
            foreach ($line in @($removeOutput)) { if ($line) { Log-Output "[diskpart][stale-cleanup] $line" } }
            Complete-SacTemporaryMountCleanup -StatePath $stateFile.FullName -DiskNumber $currentDiskNumber -PartitionNumber $partitionNumber -DriveLetter $driveLetter
        }
        catch {
            Log-Warning "Could not process temporary-mount state '$($stateFile.FullName)': $($_.Exception.Message). No drive letter was removed from this record."
        }
    }
}

# ===========================================
# Logging Setup (Dual-Write: Desktop + Plugin Directory)
# ===========================================
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Desktop log (for local inspection)
$desktopLogDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$desktopLogFile = Join-Path -Path $desktopLogDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)

# Plugin directory log (for az vm repair auto-collection)
$pluginLogDir = 'C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\'
$pluginLogFile = Join-Path -Path $pluginLogDir -ChildPath ("{0}_{1}.log" -f $scriptName, $runTimestamp)

# Ensure directories exist
foreach ($logDirectory in @($desktopLogDir, $pluginLogDir)) {
    if (-not (Test-Path -Path $logDirectory -PathType Container)) {
        try {
            New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            # Plugin dir may not be creatable; continue with desktop log only
            if ($logDirectory -eq $pluginLogDir) {
                [Console]::Error.WriteLine("[Warning] Could not create plugin log directory '$logDirectory': $($_.Exception.Message). Will use desktop log only.")
            } else {
                throw
            }
        }
    }
}

# Initialize log files
@($desktopLogFile, $pluginLogFile) | Where-Object { -not (Test-Path -Path $_ -PathType Leaf) } | ForEach-Object {
    try {
        New-Item -Path $_ -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        # Log creation failure is not critical; logging will append if file doesn't exist
    }
}

# For backward compatibility with existing Log-* function references
$logFilePath = $desktopLogFile


# ===========================================
# Log Wrapper Functions (Consolidation Note)
# ===========================================
# These wrappers remain local so the repair script stays self-contained while dual-writing
# to repair-host locations. Logs are not written to the attached customer OS disk.

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock

function Write-DesktopLogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [PSObject[]]$Message
    )

    try {
        $renderedMessage = ($Message | ForEach-Object { "$_" }) -join ' '
        $line = "[{0} {1}]{2}" -f $Level, (Get-Date), $renderedMessage
        
        # Write to both log files (desktop and plugin directory)
        Add-Content -Path $desktopLogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        if (Test-Path -Path $pluginLogDir -PathType Container) {
            Add-Content -Path $pluginLogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        if ($script:OriginalLogWarning) {
            & $script:OriginalLogWarning -message "Failed to append to log files: $($_.Exception.Message)"
        }
        else {
            [Console]::Error.WriteLine("[Warning $(Get-Date)]Failed to append to log files: $($_.Exception.Message)")
        }
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-DesktopLogLine -Level 'Output' -Message $message
}

function Log-Info {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogInfo -message $message
    Write-DesktopLogLine -Level 'Info' -Message $message
}

function Log-Warning {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogWarning -message $message
    Write-DesktopLogLine -Level 'Warning' -Message $message
}

function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-DesktopLogLine -Level 'Error' -Message $message
}

function Log-Debug {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogDebug -message $message
    Write-DesktopLogLine -Level 'Debug' -Message $message
}

$logFile = $logFilePath
Log-Info "Dual logging initialized - Desktop: $desktopLogFile | Plugin: $pluginLogFile"
Log-Info "Script classification: REPAIR_VM_ONLY"

# Status Tracking
$script_final_status = $STATUS_ERROR
$failureReason = 'Script could not find a valid attached OS disk to enable SAC. Verify the disk is attached to the repair VM.'
$detectedExecutionContext = 'UNDETERMINED'
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

Log-Info "Starting repair-only SAC enabler. Logs: $logFile"

try {
    # Check if the Hyper-V module is available before performing nested VM checks
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

    # Step 1 - Enumerate partitions to locate the BCD store and OS loader
    $partitionlist = @(Get-Disk-Partitions)
    if ($partitionlist.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }

    $discoveredDiskNumbers = @($partitionlist | Select-Object -ExpandProperty DiskNumber -Unique)
    Log-Info "Get-Disk-Partitions discovered disk numbers: $($discoveredDiskNumbers -join ', ')"
    $repairDrive = $env:SystemDrive -replace ':', ''
    Log-Info 'Enumerating partitions to enable SAC...'
    
    # SAFETY CHECK: Ensure we're not operating on the repair VM's own disk
    $repairOsPartition = Get-Partition -DriveLetter $repairDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $repairOsPartition -or $null -eq $repairOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the repair VM OS disk from $($env:SystemDrive)."
    }

    $repairDiskNumber = [int]$repairOsPartition.DiskNumber
    Log-Info "Repair VM OS disk identified as Disk $repairDiskNumber"

    $targetDiskGroups = @($partitionlist | Group-Object DiskNumber | Where-Object { [int]$_.Name -ne $repairDiskNumber })
    $detectedExecutionContext = Get-SacExecutionContext -TargetDiskGroups $targetDiskGroups
    Log-Info "Detected execution context: $detectedExecutionContext"

    if ($detectedExecutionContext -ne 'REPAIR_VM') {
        Log-Error "[STANDARD_VM] REPAIR-ONLY SCRIPT: The helper returned no secondary disk."
        Log-Error "[STANDARD_VM] Run this script with az vm repair run and --run-on-repair. No BCD changes were attempted."
        $script_final_status = $STATUS_ERROR
        $failureReason = 'Standard VM context detected, or the repair VM has no accessible attached Windows OS disk.'
    }
    else
    {
    $targetDiskNumbers = @($targetDiskGroups | ForEach-Object { [int]$_.Name })
    Clear-SacStaleTemporaryMounts -TargetDiskNumbers $targetDiskNumbers

    foreach ( $partitionGroup in $targetDiskGroups )
    {
        $processedCount++
        $diskChanged = $false
        $diskFailed = $false
        $diskNumber = $partitionGroup.Name
        $isBcdPath = $false
        $bcdPath = ''
        $isOsPath = $false
        $tempEfiLetter = $null
        $tempEfiDiskNum = $null
        $tempEfiPartNum = $null
        $tempOsLetter = $null
        $tempOsDiskNum = $null
        $tempOsPartNum = $null
        $tempOsStatePath = $null
        $tempEfiStatePath = $null
        $bcdBackup = $null
        
        Log-Info "Processing Disk $diskNumber"
        
        try {

        # Scan each drive for BCD store and Windows OS loader
        ForEach ($drive in $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ })
        {
            # The repair disk was filtered out above; retain this drive-level safety check.
            if ($drive -eq $repairDrive) { continue }

            if ( -not $isBcdPath )
            {
                $bcdPath = $drive + ':\boot\bcd'
                $isBcdPath = Test-Path $bcdPath
                if ( -not $isBcdPath )
                {
                    $bcdPath = $drive + ':\efi\microsoft\boot\bcd'
                    $isBcdPath = Test-Path $bcdPath
                } 
            }        
            if (-not $isOsPath)
            {
                $winloadExePath = $drive + ':\windows\system32\winload.exe'
                $winloadEfiPath = $drive + ':\windows\system32\winload.efi'
                $isOsPath = (Test-Path $winloadExePath) -or (Test-Path $winloadEfiPath)
            }
        }

        # Gen2 fallback: probe unlettered partitions directly for a Windows loader.
        if (-not $isOsPath)
        {
            $diskNum = [int]$partitionGroup.Name
            $diskPartitions = @(Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue)
            foreach ($partition in $diskPartitions) {
                $driveDescription = if ($partition.DriveLetter) { "$($partition.DriveLetter):" } else { '<none>' }
                $sizeMb = [math]::Round($partition.Size / 1MB)
                Log-Info "Disk $diskNum partition $($partition.PartitionNumber): drive=$driveDescription sizeMB=$sizeMb type=$($partition.Type) gptType=$($partition.GptType)"
            }

            $unletteredOsCandidates = @($diskPartitions | Where-Object {
                -not $_.DriveLetter -or $_.DriveLetter -eq [char]0
            } | Sort-Object Size -Descending)
            Log-Info "Disk ${diskNum}: probing $($unletteredOsCandidates.Count) unlettered partition(s) for a Windows loader."

            foreach ($osCandidate in $unletteredOsCandidates)
            {
                $candidateLetter = Get-AvailableTempDriveLetter
                if (-not $candidateLetter) {
                    Log-Warning "No available drive letter for an unlettered Windows partition on Disk $diskNum"
                    break
                }

                $candidatePartNum = $osCandidate.PartitionNumber
                Log-Info "Assigning temp letter ${candidateLetter}: to Disk $diskNum Partition $candidatePartNum (Windows candidate)..."
                $tempOsStatePath = Register-SacTemporaryMount -DiskNumber $diskNum -PartitionNumber $candidatePartNum -DriveLetter $candidateLetter -Kind Windows
                $dpOsAssign = @("select disk $diskNum", "select partition $candidatePartNum", "assign letter=$candidateLetter")
                $dpOsAssignOut = $dpOsAssign | diskpart 2>&1
                foreach ($line in @($dpOsAssignOut)) { if ($line) { Log-Output "[diskpart][os-assign] $line" } }
                $tempOsLetter = $candidateLetter
                $tempOsDiskNum = $diskNum
                $tempOsPartNum = $candidatePartNum
                Start-Sleep -Seconds 2

                $winloadExePath = "${candidateLetter}:\windows\system32\winload.exe"
                $winloadEfiPath = "${candidateLetter}:\windows\system32\winload.efi"
                $isOsPath = (Test-Path -Path $winloadExePath) -or (Test-Path -Path $winloadEfiPath)
                if ($isOsPath) {
                    Log-Info "Found Windows OS partition at ${candidateLetter}: on Disk $diskNum"
                    break
                }

                Log-Info "No Windows loader found at ${candidateLetter}:, removing letter..."
                $dpOsRemove = @("select disk $diskNum", "select partition $candidatePartNum", "remove letter=$candidateLetter")
                $dpOsRemoveOut = $dpOsRemove | diskpart 2>&1
                foreach ($line in @($dpOsRemoveOut)) { if ($line) { Log-Output "[diskpart][os-remove] $line" } }
                Complete-SacTemporaryMountCleanup -StatePath $tempOsStatePath -DiskNumber $diskNum -PartitionNumber $candidatePartNum -DriveLetter $candidateLetter
                $tempOsLetter = $null
                $tempOsDiskNum = $null
                $tempOsPartNum = $null
                $tempOsStatePath = $null
            }
        }

        # Gen2 EFI fallback: if OS found but no BCD, discover unlettered EFI partition
        if (-not $isBcdPath -and $isOsPath)
        {
            $diskNum = [int]$partitionGroup.Name
            if ($diskNum -ne $repairDiskNumber)
            {
                Log-Info "Disk ${diskNum}: OS found but no BCD - checking for unlettered EFI partition (Gen2)..."
                $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
                $efiParts = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue | Where-Object {
                    (Test-SacGptType -ActualType $_.GptType -ExpectedType $efiGptType) -and
                    (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0)
                }
                if ($efiParts)
                {
                    $tempLetter = Get-AvailableTempDriveLetter
                    if ($tempLetter)
                    {
                        foreach ($ep in $efiParts)
                        {
                            $pn = $ep.PartitionNumber
                            Log-Info "Assigning temp letter ${tempLetter}: to Disk $diskNum Partition $pn (EFI)..."
                            $tempEfiStatePath = Register-SacTemporaryMount -DiskNumber $diskNum -PartitionNumber $pn -DriveLetter $tempLetter -Kind EFI
                            $dpLines = @("select disk $diskNum", "select partition $pn", "assign letter=$tempLetter")
                            $dpAssignOut = $dpLines | diskpart 2>&1
                            foreach ($line in @($dpAssignOut)) { if ($line) { Log-Output "[diskpart][assign] $line" } }
                            $tempEfiLetter = $tempLetter
                            $tempEfiDiskNum = $diskNum
                            $tempEfiPartNum = $pn
                            Start-Sleep -Seconds 2
                            $bcdPath = "${tempLetter}:\efi\microsoft\boot\bcd"
                            $isBcdPath = Test-Path $bcdPath
                            if ($isBcdPath)
                            {
                                Log-Info "Found Gen2 BCD store at $bcdPath"
                                break
                            }
                            else
                            {
                                Log-Info "No BCD at $bcdPath, removing letter..."
                                $dpRemove = @("select disk $diskNum", "select partition $pn", "remove letter=$tempLetter")
                                $dpRemoveOut = $dpRemove | diskpart 2>&1
                                foreach ($line in @($dpRemoveOut)) { if ($line) { Log-Output "[diskpart][remove] $line" } }
                                Complete-SacTemporaryMountCleanup -StatePath $tempEfiStatePath -DiskNumber $diskNum -PartitionNumber $pn -DriveLetter $tempLetter
                                $tempEfiLetter = $null
                                $tempEfiDiskNum = $null
                                $tempEfiPartNum = $null
                                $tempEfiStatePath = $null
                            }
                        }
                    }
                    else
                    {
                        Log-Warning "No available drive letter for EFI partition on Disk $diskNum"
                    }
                }
            }
        }

        # Apply SAC changes if both BCD and OS loader were found
        if ( $isBcdPath -and $isOsPath )
        {
            # Step 2 - Identify the default boot entry GUID
            $bcdout = bcdedit /store $bcdPath /enum bootmgr /v
            $defaultLine = $bcdout | Select-String 'displayorder' | Select-Object -First 1

            if (-not $defaultLine)
            {
                $failureReason = "Could not locate a displayorder entry in boot manager output for $bcdPath."
                Log-Warning "Could not locate a displayorder entry in boot manager output for $bcdPath. Unable to determine the default boot entry."
                $diskFailed = $true
            }
            elseif ($defaultLine -match '\{([^}]+)\}') {
                $defaultId = $matches[0]
                
                # VALIDATION: Confirm we have a valid GUID
                if ($defaultId -notmatch '^\{[0-9a-f\-]{36}\}$') {
                    Log-Error "Invalid boot entry GUID format: $defaultId. This may indicate a corrupted BCD store."
                    $diskFailed = $true
                }
                else
                {
                    # VALIDATION: Backup BCD store before any modifications
                    $bcdBackup = $bcdPath + '.backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
                    try {
                        Copy-Item -Path $bcdPath -Destination $bcdBackup -Force -ErrorAction Stop
                        Log-Info "BCD backup created at: $bcdBackup"
                    }
                    catch {
                        Log-Warning "Could not create BCD backup: $($_.Exception.Message). Proceeding with caution."
                    }

                    # Step 3 - Log BCD configuration before changes
                    Log-Output "--- BCD BEFORE SAC ENABLE ---"
                    $beforeBcd = bcdedit /store $bcdPath /enum $defaultId
                    foreach ($line in $beforeBcd) { if ($line.Trim()) { Log-Output $line } }

                    # Steps 4-7 - Enable boot menu, Boot EMS, EMS on OS entry, and EMS serial settings
                    Log-Info "Applying SAC and EMS configurations to BCD: $bcdPath"
                    $setBootMenuOut = bcdedit /store $bcdPath /set "{bootmgr}" displaybootmenu yes 2>&1
                    foreach ($line in @($setBootMenuOut)) { if ($line) { Log-Output "[bcdedit][displaybootmenu] $line" } }

                    $setTimeoutOut = bcdedit /store $bcdPath /set "{bootmgr}" timeout 5 2>&1
                    foreach ($line in @($setTimeoutOut)) { if ($line) { Log-Output "[bcdedit][timeout] $line" } }

                    $setBootEmsOut = bcdedit /store $bcdPath /set "{bootmgr}" bootems yes 2>&1
                    foreach ($line in @($setBootEmsOut)) { if ($line) { Log-Output "[bcdedit][bootems] $line" } }

                    $setEmsOut = bcdedit /store $bcdPath /ems $defaultId ON 2>&1
                    foreach ($line in @($setEmsOut)) { if ($line) { Log-Output "[bcdedit][ems] $line" } }

                    $setEmsSettingsOut = bcdedit /store $bcdPath /emssettings EMSPORT:1 EMSBAUDRATE:115200 2>&1
                    foreach ($line in @($setEmsSettingsOut)) { if ($line) { Log-Output "[bcdedit][emssettings] $line" } }

                    # VALIDATION: Verify BCD changes were applied successfully
                    Log-Info "Verifying BCD changes..."
                    $verifyBcd = bcdedit /store $bcdPath /enum $defaultId
                    $emsEnabled = $verifyBcd | Select-String 'ems' | Select-String 'Yes'
                    if (-not $emsEnabled) {
                        Log-Error "CRITICAL: EMS verification failed! BCD may be corrupted. Restore from backup: $bcdBackup"
                        $diskFailed = $true
                    }
                    else {
                        # Step 8 - Log BCD configuration after changes for verification
                        Log-Output "--- BCD AFTER SAC ENABLE ---"
                        $afterBcd = bcdedit /store $bcdPath /enum $defaultId
                        foreach ($line in $afterBcd) { if ($line.Trim()) { Log-Output $line } }
                        
                        $script_final_status = $STATUS_SUCCESS
                        $diskChanged = $true
                    }
                }
            }
            else
            {
                $failureReason = "Displayorder entry was found but no boot entry GUID could be parsed for $bcdPath."
                Log-Warning "Displayorder entry was found but no boot entry GUID could be parsed for $bcdPath. Raw line: $($defaultLine.Line)"
                $diskFailed = $true
            }
        }
        else {
            Log-Info "Disk $diskNumber skipped: no valid BCD + OS loader combination was found."
        }
        } catch {
            $diskFailed = $true
            $failureReason = "Disk $diskNumber failed with exception: $($_.Exception.Message)"
            Log-Error $failureReason
            if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
                Log-Error "Disk $diskNumber failure context: $($_.InvocationInfo.PositionMessage)"
            }
        } finally {

        # Clean up temporary EFI drive letter if one was assigned
        if ($tempEfiLetter)
        {
            Log-Info "Removing temp letter ${tempEfiLetter}: from Disk $tempEfiDiskNum Partition $tempEfiPartNum"
            $dpClean = @("select disk $tempEfiDiskNum", "select partition $tempEfiPartNum", "remove letter=$tempEfiLetter")
            $dpCleanOut = $dpClean | diskpart 2>&1
            foreach ($line in @($dpCleanOut)) { if ($line) { Log-Output "[diskpart][cleanup] $line" } }
            Complete-SacTemporaryMountCleanup -StatePath $tempEfiStatePath -DiskNumber $tempEfiDiskNum -PartitionNumber $tempEfiPartNum -DriveLetter $tempEfiLetter
        }

        if ($tempOsLetter)
        {
            Log-Info "Removing temp letter ${tempOsLetter}: from Disk $tempOsDiskNum Partition $tempOsPartNum"
            $dpOsClean = @("select disk $tempOsDiskNum", "select partition $tempOsPartNum", "remove letter=$tempOsLetter")
            $dpOsCleanOut = $dpOsClean | diskpart 2>&1
            foreach ($line in @($dpOsCleanOut)) { if ($line) { Log-Output "[diskpart][os-cleanup] $line" } }
            Complete-SacTemporaryMountCleanup -StatePath $tempOsStatePath -DiskNumber $tempOsDiskNum -PartitionNumber $tempOsPartNum -DriveLetter $tempOsLetter
        }

        if ($diskChanged) { $changedCount++ }
        elseif ($diskFailed) { $failedCount++ }
        else { $skippedCount++ }
        }
    }
    }

    if ($script_final_status -ne $STATUS_SUCCESS) {
        Log-Error "[$detectedExecutionContext] FAILED: $failureReason"
    }
}
catch {
    Log-Error "[$detectedExecutionContext] An error occurred: $($_.Exception.Message)"
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Log-Error "Failure context: $($_.InvocationInfo.PositionMessage)"
    }
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Detected execution context: $detectedExecutionContext"
    Log-Info "Desktop log: $desktopLogFile"
    if (Test-Path -Path $pluginLogFile -PathType Leaf) {
        Log-Info "Plugin log (auto-collected): $pluginLogFile"
    }
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
