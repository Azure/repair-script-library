<#
.SYNOPSIS
    Enables SAC and Serial Console boot settings on attached Windows disks, including BIOS and UEFI layouts.

.DESCRIPTION
    This script must be run from a repair VM only to enable SAC/EMS on an attached OS disk's BCD store.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
       OS detection accepts either winload.exe or winload.efi.
    1a. For Gen2 disks where the EFI partition has no drive letter, uses diskpart to
        temporarily assign one so the BCD store can be accessed.
    2. Identifies and validates the Windows Boot Loader entry referenced by the BCD bootmgr default element.
        The script fails closed if the entry's loader path does not resolve on the discovered Windows partition.
    3. Logs the BCD configuration before any changes are made.
    4. Enables the boot menu with a 5-second timeout (displaybootmenu, timeout).
    5. Enables Boot EMS on Boot Manager (bootems yes).
    6. Enables EMS on the default OS entry (ems ON).
    7. Configures EMS settings for serial console (EMSPORT:1, EMSBAUDRATE:115200).
    8. Logs the BCD configuration after changes for verification.

.NOTES
    Name:        sac-enabler.ps1
    Author:      Tony.Mocanu@Microsoft.com
    Last Modified: 2026-08-05
    Version:     1.5.1
    Requirement: Azure repair VM with an attached Windows OS disk
    DeployMode:  az vm repair run (with --run-on-repair)
    
    .VERSION
    v1.5.1: [August 2026] - Avoids comparing guest BCD drive letters with repair-VM mount letters.
                            - Uses VM generation when selecting the detected loader path for logging.
    v1.5: [August 2026] - Validates loader mapping before BCD writes and verifies mapping invariance afterward.
                          - Requires and verifies a BCD backup before applying SAC settings.
                          - Restores the backup if path, device, osdevice, or systemroot changes unexpectedly.
    v1.4: [August 2026] - Added VMRepairMint telemetry, structured before-state capture, and Gen1/Gen2 discovery telemetry.
                          - Added explicit winload.exe and winload.efi detection.
                          - Added explicit displayorder and boot entry GUID failure diagnostics.
    Update [July 2026]  - Restricted execution to repair VM mode.
                         - Uses Get-Disk-Partitions to enumerate Azure virtual disks.
                         - Detects repair vs. standard context from secondary disks returned by the helper.
                         - Mounts unlettered Gen2 Windows and EFI partitions temporarily.
                         - Probes unlettered partitions directly instead of assuming GPT metadata or size.
                         - Refuses BCD changes when a repair VM context is not detected.
                         - Fails closed if the repair VM OS disk cannot be identified.
                         - Filters out the repair VM OS disk before processing attached disks.
    Update: [July 2026]  - Added execution context detection and dual-logging.
                         - Detected rescue VM mode versus standard mode for context-aware error messages.
                         - Logs to both the desktop and the plugin directory for automatic collection by az vm repair.
                         - **NEW SAFETY: Pre-flight checks, BCD backup, and post-change verification.
                         - **NEW SAFETY: Validates GUID format before making BCD edits.
                         - **NEW SAFETY: Verifies EMS was actually enabled after bcdedit commands.
                         - Added .ROLLBACK_RECOVERY section with disaster recovery instructions.
                         - Annotated Log-* wrapper pattern with consolidation note.
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
    The temporary letter is removed after processing.

.ROLLBACK_RECOVERY
    IF THE VM FAILS TO BOOT AFTER RUNNING az vm repair restore:
    
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
    
    ALTERNATIVE (if BCD restore does not work):
    - Use sfc /scannow from Windows Recovery Environment to repair system files
    - Use bcdboot.exe to rebuild the BCD store from scratch
    - See internal troubleshooting guide: azure-vm-dump-issues.md

.LINK
    https://github.com/Azure/repair-script-library
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

# ===========================================
# Logging Setup (Dual-Write: Desktop + Plugin Directory)
# ===========================================
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Desktop log (for local inspection)
$desktopLogDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$desktopLogFile = Join-Path -Path $desktopLogDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)

# Plugin directory log (for automatic collection by az vm repair)
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
# NOTE: This Log-* wrapper pattern (duplicated across sac-enabler.ps1 and other scripts)
# should be consolidated into a shared helper module (e.g., common\helpers\Logging-Helper.ps1)
# to avoid duplication. All scripts should source a single centralized logging provider.

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

# Structured telemetry is written through the existing dual-write logging path.
$script:RepairScriptVersion = '1.5.1'
$script:ExecutionStarted = Get-Date
$script:OperationCount = 0
$script:LastCommand = $null

function Write-SacTelemetry {
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
        Log-Error "[Telemetry] $json" | Out-Null
    }
    else {
        Log-Info "[Telemetry] $json" | Out-Null
    }
}

function Invoke-SacBcdEdit {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $script:OperationCount++
    $script:LastCommand = 'bcdedit.exe ' + ($Arguments -join ' ')
    $output = & bcdedit.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    Write-SacTelemetry -Event Operation -Message 'Applied bcdedit command' -Properties @{
        Operation = $Operation
        Command = $script:LastCommand
        ExitCode = $exitCode
        Success = ($exitCode -eq 0)
    } | Out-Null

    foreach ($line in @($output)) {
        if ($line) { Log-Output "[bcdedit][$Operation] $line" | Out-Null }
    }

    return [pscustomobject]@{
        Output = @($output)
        ExitCode = $exitCode
        Success = ($exitCode -eq 0)
    }
}

$logFile = $logFilePath
Log-Info "Dual logging initialized: Desktop: $desktopLogFile | Plugin: $pluginLogFile"
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
Log-Info "Build marker: v1.5.1-offline-drive-mapping-fix"

# VMRepairMint telemetry marker
Log-Info "[script_start] Script=sac-enabler Version=$($script:RepairScriptVersion)"

Write-SacTelemetry -Event Start -Message 'script_start' -Properties @{
    ScriptName = 'sac-enabler.ps1'
    ScriptVersion = $script:RepairScriptVersion
    BuildMarker = 'v1.5.1-offline-drive-mapping-fix'
    StartTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
}

$hostOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
Write-SacTelemetry -Event Start -Message 'Starting SAC/EMS enablement' -Properties @{
    OSVersion = if ($hostOs) { $hostOs.Version } else { [Environment]::OSVersion.Version.ToString() }
    OSCaption = if ($hostOs) { $hostOs.Caption } else { 'Unknown' }
    VMGeneration = 'PendingTargetDiskDiscovery'
    ExecutionMode = 'REPAIR_VM_ONLY'
    DesktopLog = $desktopLogFile
    PluginLog = $pluginLogFile
}

try {
    # Optional: Clean up orphaned temp drive letters from previous failed runs
    # This helps prevent lingering mount points from blocking EFI partition access
    $orphanedLetters = @()
    try {
        Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and -not $_.DriveType -eq 'Unknown' } | ForEach-Object {
            $letter = $_.DriveLetter
            $volumePath = "${letter}:\"
            if (-not (Test-Path -Path $volumePath)) {
                $orphanedLetters += $letter
            }
        }
        if ($orphanedLetters.Count -gt 0) {
            Log-Info "Found potentially orphaned drive letters (may be harmless): $($orphanedLetters -join ', '). Continuing..."
        }
    }
    catch {
        # Orphan detection is optional; don't block on failure
        Log-Debug "Orphan detection encountered a noncritical error: $($_.Exception.Message)"
    }
    
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
                    Log-Warning "Failed to stop the nested guest VM; continuing, but the repair may have limited success."
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
    foreach ( $partitionGroup in $targetDiskGroups )
    {
        $processedCount++
        $diskChanged = $false
        $diskFailed = $false
        $diskNumber = $partitionGroup.Name
        $isBcdPath = $false
        $bcdPath = ''
        $isOsPath = $false
        $windowsDrive = $null
        $detectedLoaderPath = $null
        $tempEfiLetter = $null
        $tempEfiDiskNum = $null
        $tempEfiPartNum = $null
        $tempOsLetter = $null
        $tempOsDiskNum = $null
        $tempOsPartNum = $null
        $bcdBackup = $null
        
        Log-Info "Processing Disk $diskNumber"
        
        try {

        # Discover the Windows partition and select the BCD store from the
        # same target disk. Get-Disk-Partitions-v2.ps1 remains unchanged.
        $diskNum = [int]$partitionGroup.Name
        $diskPartitions = @(Get-Partition -DiskNumber $diskNum -ErrorAction Stop)
        $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
        $efiParts = @($diskPartitions | Where-Object {
            Test-SacGptType -ActualType $_.GptType -ExpectedType $efiGptType
        })
        $isGen2Disk = $efiParts.Count -gt 0

        Log-Info "Disk ${diskNum}: generation detection result = $(if ($isGen2Disk) { 'Gen2/UEFI' } else { 'Gen1/BIOS' })"
        Write-SacTelemetry -Event Operation -Message 'Target disk generation detected' -Properties @{
            DiskNumber = $diskNum
            VMGeneration = if ($isGen2Disk) { 'V2' } else { 'V1' }
            EfiPartitionCount = $efiParts.Count
        }

        foreach ($partition in $diskPartitions) {
            $displayLetter = if ($partition.DriveLetter -and $partition.DriveLetter -ne [char]0) {
                "$($partition.DriveLetter):"
            }
            else {
                '<none>'
            }
            Log-Info "Disk $diskNum Partition $($partition.PartitionNumber): drive=$displayLetter size=$($partition.Size) type=$($partition.Type) gptType=$($partition.GptType)"
        }

        # Locate Windows on every currently mounted partition of this disk.
        # Once detected, $isOsPath is never reset to false.
        foreach ($partition in @($diskPartitions | Where-Object {
            $_.DriveLetter -and $_.DriveLetter -ne [char]0
        })) {
            $drive = [string]$partition.DriveLetter
            if ($drive -eq $repairDrive) { continue }

            $winloadExePath = "${drive}:\Windows\System32\winload.exe"
            $winloadEfiPath = "${drive}:\Windows\System32\winload.efi"
            $hasWinloadExe = Test-Path -LiteralPath $winloadExePath -PathType Leaf
            $hasWinloadEfi = Test-Path -LiteralPath $winloadEfiPath -PathType Leaf

            Log-Info "Disk ${diskNum}: checking ${drive}: for Windows loader; winload.exe=$hasWinloadExe winload.efi=$hasWinloadEfi"

            if ($hasWinloadExe -or $hasWinloadEfi) {
                $isOsPath = $true
                $windowsDrive = $drive
                $detectedLoaderPath = if ($isGen2Disk -and $hasWinloadEfi) {
                    '\Windows\System32\winload.efi'
                }
                elseif ($hasWinloadExe) {
                    '\Windows\System32\winload.exe'
                }
                else {
                    '\Windows\System32\winload.efi'
                }
                Log-Info "Disk ${diskNum}: Windows loader confirmed on ${windowsDrive}: path=$detectedLoaderPath"
                break
            }
        }

        # Probe unlettered non-EFI partitions only if Windows was not found above.
        if (-not $isOsPath) {
            $unletteredOsCandidates = @($diskPartitions | Where-Object {
                (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0) -and
                -not (Test-SacGptType -ActualType $_.GptType -ExpectedType $efiGptType)
            } | Sort-Object Size -Descending)

            Log-Info "Disk ${diskNum}: probing $($unletteredOsCandidates.Count) unlettered non-EFI partition(s) for Windows."

            foreach ($osCandidate in $unletteredOsCandidates) {
                $candidateLetter = Get-AvailableTempDriveLetter
                if (-not $candidateLetter) {
                    Log-Warning "Disk ${diskNum}: no temporary drive letter is available for OS probing."
                    break
                }

                $candidatePartNum = $osCandidate.PartitionNumber
                Log-Info "Disk ${diskNum}: assigning ${candidateLetter}: to Partition $candidatePartNum for OS probing."
                $dpOsAssign = @(
                    "select disk $diskNum"
                    "select partition $candidatePartNum"
                    "assign letter=$candidateLetter"
                )
                $dpOsAssignOut = $dpOsAssign | diskpart 2>&1
                foreach ($line in @($dpOsAssignOut)) {
                    if ($line) { Log-Output "[diskpart][os-assign] $line" | Out-Null }
                }
                Start-Sleep -Seconds 2

                $mounted = Test-Path -LiteralPath "${candidateLetter}:\" -PathType Container
                $winloadExePath = "${candidateLetter}:\Windows\System32\winload.exe"
                $winloadEfiPath = "${candidateLetter}:\Windows\System32\winload.efi"
                $hasWinloadExe = $mounted -and (Test-Path -LiteralPath $winloadExePath -PathType Leaf)
                $hasWinloadEfi = $mounted -and (Test-Path -LiteralPath $winloadEfiPath -PathType Leaf)

                Log-Info "Disk ${diskNum}: checked temporary ${candidateLetter}:; mounted=$mounted winload.exe=$hasWinloadExe winload.efi=$hasWinloadEfi"

                if ($hasWinloadExe -or $hasWinloadEfi) {
                    $tempOsLetter = $candidateLetter
                    $tempOsDiskNum = $diskNum
                    $tempOsPartNum = $candidatePartNum
                    $isOsPath = $true
                    $windowsDrive = $candidateLetter
                    $detectedLoaderPath = if ($isGen2Disk -and $hasWinloadEfi) {
                        '\Windows\System32\winload.efi'
                    }
                    elseif ($hasWinloadExe) {
                        '\Windows\System32\winload.exe'
                    }
                    else {
                        '\Windows\System32\winload.efi'
                    }
                    Log-Info "Disk ${diskNum}: Windows loader confirmed on temporary ${windowsDrive}: path=$detectedLoaderPath"
                    break
                }

                $dpOsRemove = @(
                    "select disk $diskNum"
                    "select partition $candidatePartNum"
                    "remove letter=$candidateLetter noerr"
                )
                $dpOsRemoveOut = $dpOsRemove | diskpart 2>&1
                foreach ($line in @($dpOsRemoveOut)) {
                    if ($line) { Log-Output "[diskpart][os-remove] $line" | Out-Null }
                }
            }
        }

        if ($isGen2Disk) {
            # Gen2 must use the BCD on the EFI System Partition on this disk.
            foreach ($efiPart in $efiParts) {
                $efiLetter = $null
                $letterAssignedByScript = $false

                if ($efiPart.DriveLetter -and $efiPart.DriveLetter -ne [char]0) {
                    $efiLetter = [string]$efiPart.DriveLetter
                }
                else {
                    $efiLetter = Get-AvailableTempDriveLetter
                    if (-not $efiLetter) {
                        Log-Warning "Disk ${diskNum}: no temporary drive letter is available for EFI Partition $($efiPart.PartitionNumber)."
                        continue
                    }

                    Log-Info "Disk ${diskNum}: assigning ${efiLetter}: to EFI Partition $($efiPart.PartitionNumber)."
                    $dpEfiAssign = @(
                        "select disk $diskNum"
                        "select partition $($efiPart.PartitionNumber)"
                        "assign letter=$efiLetter"
                    )
                    $dpEfiAssignOut = $dpEfiAssign | diskpart 2>&1
                    foreach ($line in @($dpEfiAssignOut)) {
                        if ($line) { Log-Output "[diskpart][efi-assign] $line" | Out-Null }
                    }
                    Start-Sleep -Seconds 2
                    $letterAssignedByScript = Test-Path -LiteralPath "${efiLetter}:\" -PathType Container
                }

                if (-not $efiLetter -or -not (Test-Path -LiteralPath "${efiLetter}:\" -PathType Container)) {
                    Log-Warning "Disk ${diskNum}: EFI Partition $($efiPart.PartitionNumber) could not be mounted."
                    continue
                }

                $candidateBcdPath = "${efiLetter}:\EFI\Microsoft\Boot\BCD"
                Log-Info "Disk ${diskNum}: probing EFI BCD candidate $candidateBcdPath"

                if (Test-Path -LiteralPath $candidateBcdPath -PathType Leaf) {
                    $bcdPath = $candidateBcdPath
                    $isBcdPath = $true
                    Log-Info "Disk ${diskNum}: selected Gen2 EFI BCD store: $bcdPath"
                    if ($letterAssignedByScript) {
                        $tempEfiLetter = $efiLetter
                        $tempEfiDiskNum = $diskNum
                        $tempEfiPartNum = $efiPart.PartitionNumber
                    }
                    break
                }

                Log-Warning "Disk ${diskNum}: no BCD store found at $candidateBcdPath."
                if ($letterAssignedByScript) {
                    $dpEfiRemove = @(
                        "select disk $diskNum"
                        "select partition $($efiPart.PartitionNumber)"
                        "remove letter=$efiLetter noerr"
                    )
                    $dpEfiRemoveOut = $dpEfiRemove | diskpart 2>&1
                    foreach ($line in @($dpEfiRemoveOut)) {
                        if ($line) { Log-Output "[diskpart][efi-remove] $line" | Out-Null }
                    }
                }
            }
        }
        else {
            # Gen1 uses the BCD from a mounted System Reserved partition.
            foreach ($partition in @($diskPartitions | Where-Object {
                $_.DriveLetter -and $_.DriveLetter -ne [char]0
            })) {
                $drive = [string]$partition.DriveLetter
                if ($drive -eq $repairDrive) { continue }
                $candidateBcdPath = "${drive}:\Boot\BCD"
                $candidateExists = Test-Path -LiteralPath $candidateBcdPath -PathType Leaf
                Log-Info "Disk ${diskNum}: checking Gen1 BCD candidate $candidateBcdPath; exists=$candidateExists"
                if ($candidateExists) {
                    $bcdPath = $candidateBcdPath
                    $isBcdPath = $true
                    Log-Info "Disk ${diskNum}: selected Gen1 BCD store: $bcdPath"
                    break
                }
            }
        }

        Log-Info "Disk ${diskNum}: final discovery state isBcdPath=$isBcdPath isOsPath=$isOsPath bcdPath=$bcdPath"
        if (-not $isBcdPath) {
            Log-Warning "Disk ${diskNum}: no generation-appropriate BCD store was found."
        }
        if (-not $isOsPath) {
            Log-Warning "Disk ${diskNum}: no Windows loader was found."
        }

        # Apply SAC changes if both BCD and OS loader were found
        if ( $isBcdPath -and $isOsPath )
        {
            # Step 2 - Identify the default boot entry GUID
            $bootMgrQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', 'bootmgr', '/v') -Operation 'query-bootmgr'
            if (-not $bootMgrQuery.Success) {
                $failureReason = "Could not enumerate boot manager from $bcdPath. Exit code: $($bootMgrQuery.ExitCode)."
                Log-Warning $failureReason
                $diskFailed = $true
                continue
            }

            $bcdout = $bootMgrQuery.Output
            $defaultLine = $bcdout | Select-String -Pattern '^\s*default\s+' | Select-Object -First 1

            if (-not $defaultLine)
            {
                $failureReason = "Could not locate the default Windows Boot Loader entry in boot manager output for $bcdPath."
                Log-Warning "$failureReason The script will not fall back to the first displayorder entry."
                $diskFailed = $true
            }
            elseif ($defaultLine -match '\{([^}]+)\}') {
                $defaultId = $matches[0]
                
                # VALIDATION: Confirm we have a valid GUID
                if ($defaultId -notmatch '^(?i)\{[0-9a-f\-]{36}\}$') {
                    Log-Error "Invalid boot entry GUID format: $defaultId. This may indicate a corrupted BCD store."
                    $diskFailed = $true
                }
                else
                {
                    # Validate the selected Windows Boot Loader before any BCD write.
                    $selectedLoaderQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultId, '/v') -Operation 'validate-selected-loader'
                    if (-not $selectedLoaderQuery.Success) {
                        throw "Unable to enumerate selected loader $defaultId from $bcdPath. No BCD changes were made."
                    }

                    $selectedLoaderText = $selectedLoaderQuery.Output -join "`n"
                    $selectedPathMatch = [regex]::Match($selectedLoaderText, '(?im)^\s*path\s+(.+?)\s*$')
                    $selectedDeviceMatch = [regex]::Match($selectedLoaderText, '(?im)^\s*device\s+(.+?)\s*$')
                    $selectedOsDeviceMatch = [regex]::Match($selectedLoaderText, '(?im)^\s*osdevice\s+(.+?)\s*$')
                    $selectedSystemRootMatch = [regex]::Match($selectedLoaderText, '(?im)^\s*systemroot\s+(.+?)\s*$')

                    if (-not $selectedPathMatch.Success) {
                        throw "Selected loader $defaultId has no path element. No BCD changes were made."
                    }
                    if (-not $selectedDeviceMatch.Success) {
                        throw "Selected loader $defaultId has no device element. No BCD changes were made."
                    }
                    if (-not $selectedOsDeviceMatch.Success) {
                        throw "Selected loader $defaultId has no osdevice element. No BCD changes were made."
                    }
                    if (-not $selectedSystemRootMatch.Success) {
                        throw "Selected loader $defaultId has no systemroot element. No BCD changes were made."
                    }

                    $originalLoaderPath = $selectedPathMatch.Groups[1].Value.Trim()
                    $originalDevice = $selectedDeviceMatch.Groups[1].Value.Trim()
                    $originalOsDevice = $selectedOsDeviceMatch.Groups[1].Value.Trim()
                    $originalSystemRoot = $selectedSystemRootMatch.Groups[1].Value.Trim()

                    if ($originalLoaderPath -notmatch '(?i)^\\Windows\\System32\\winload\.(exe|efi)$') {
                        throw "Selected entry $defaultId does not reference winload.exe or winload.efi. Path: $originalLoaderPath. No BCD changes were made."
                    }
                    if ($originalDevice -match '(?i)^unknown$') {
                        throw "Selected loader $defaultId has device=unknown. Separate BCD repair is required; no BCD changes were made."
                    }
                    if ($originalOsDevice -match '(?i)^unknown$') {
                        throw "Selected loader $defaultId has osdevice=unknown. Separate BCD repair is required; no BCD changes were made."
                    }

                    # Offline BCD output uses the guest's drive-letter namespace (commonly C:),
                    # while the repair VM mounts that partition under a temporary letter.
                    # Validate identity by resolving the BCD loader path on the discovered partition.
                    $resolvedLoaderFile = Join-Path -Path "${windowsDrive}:\" -ChildPath $originalLoaderPath.TrimStart('\')
                    if (-not (Test-Path -LiteralPath $resolvedLoaderFile -PathType Leaf)) {
                        throw "Selected BCD entry references '$originalLoaderPath', but '$resolvedLoaderFile' does not exist. No BCD changes were made."
                    }

                    Write-SacTelemetry -Event Operation -Message 'Selected loader mapping validated' -Properties @{
                        DiskNumber = $diskNumber
                        BcdPath = $bcdPath
                        LoaderGuid = $defaultId
                        WindowsDrive = $windowsDrive
                        DetectedLoaderPath = $detectedLoaderPath
                        BcdLoaderPath = $originalLoaderPath
                        Device = $originalDevice
                        OsDevice = $originalOsDevice
                        SystemRoot = $originalSystemRoot
                    }

                    # VALIDATION: Backup BCD store before any modifications
                    $bcdBackup = $bcdPath + '.backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
                    try {
                        Copy-Item -LiteralPath $bcdPath -Destination $bcdBackup -Force -ErrorAction Stop

                        if (-not (Test-Path -LiteralPath $bcdBackup -PathType Leaf)) {
                            throw "Expected backup file was not created: $bcdBackup"
                        }
                        $bcdLength = (Get-Item -LiteralPath $bcdPath -ErrorAction Stop).Length
                        $backupLength = (Get-Item -LiteralPath $bcdBackup -ErrorAction Stop).Length
                        if ($backupLength -ne $bcdLength) {
                            throw "Backup size $backupLength does not match BCD store size $bcdLength."
                        }

                        Log-Info "BCD backup created at: $bcdBackup"

                        Write-SacTelemetry -Event Operation -Message 'BCD backup created' -Properties @{
                            DiskNumber = $diskNumber
                            BcdPath = $bcdPath
                            BackupPath = $bcdBackup
                        }
                    }
                    catch {
                        Write-SacTelemetry -Event Error -Message 'BCD backup creation failed' -Properties @{
                            DiskNumber = $diskNumber
                            BcdPath = $bcdPath
                            BackupPath = $bcdBackup
                            Error = $_.Exception.Message
                        }
                        throw "Could not create and verify BCD backup for '$bcdPath'. No BCD changes were made. Error: $($_.Exception.Message)"
                    }

                    # Step 3 - Log BCD configuration before changes
                    Log-Output "--- BCD BEFORE SAC ENABLE ---"
                    $beforeQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultId, '/v') -Operation 'before-state'
                    if (-not $beforeQuery.Success) {
                        throw "Unable to capture the BCD before-state for $defaultId. Exit code: $($beforeQuery.ExitCode)."
                    }
                    $beforeBcd = $beforeQuery.Output
                    $beforeLoaderText = $beforeBcd -join "`n"
                    $beforeBootMgrText = $bootMgrQuery.Output -join "`n"
                    $beforeEmsEnabled = $beforeLoaderText -match '(?im)^\s*ems\s+Yes\s*$'
                    $beforeBootEmsEnabled = $beforeBootMgrText -match '(?im)^\s*bootems\s+Yes\s*$'
                    $beforeBootMenuEnabled = $beforeBootMgrText -match '(?im)^\s*displaybootmenu\s+Yes\s*$'

                    Write-SacTelemetry -Event Operation -Message 'Before-state captured' -Properties @{
                        DiskNumber = $diskNumber
                        VMGeneration = if ($isGen2Disk) { 'V2' } else { 'V1' }
                        BcdPath = $bcdPath
                        LoaderGuid = $defaultId
                        EMS = if ($beforeEmsEnabled) { 'Yes' } else { 'NoOrAbsent' }
                        BootEms = if ($beforeBootEmsEnabled) { 'Yes' } else { 'NoOrAbsent' }
                        DisplayBootMenu = if ($beforeBootMenuEnabled) { 'Yes' } else { 'NoOrAbsent' }
                    }

                    foreach ($line in $beforeBcd) { if (-not [string]::IsNullOrWhiteSpace([string]$line)) { Log-Output $line } }

                    # Steps 4-7 - Enable boot menu, Boot EMS, EMS on OS entry, and EMS serial settings
                    Log-Info "Applying SAC and EMS configurations to BCD: $bcdPath"
                    # Execute each command independently. Do not collect command results in a
                    # shared pipeline because repository Log-* helpers write to the success stream.
                    $operationDefinitions = @(
                        @{ Name = 'displaybootmenu'; Arguments = @('/store', $bcdPath, '/set', '{bootmgr}', 'displaybootmenu', 'yes') }
                        @{ Name = 'timeout'; Arguments = @('/store', $bcdPath, '/set', '{bootmgr}', 'timeout', '5') }
                        @{ Name = 'bootems'; Arguments = @('/store', $bcdPath, '/set', '{bootmgr}', 'bootems', 'yes') }
                        @{ Name = 'ems'; Arguments = @('/store', $bcdPath, '/ems', $defaultId, 'ON') }
                        @{ Name = 'emssettings'; Arguments = @('/store', $bcdPath, '/emssettings', 'EMSPORT:1', 'EMSBAUDRATE:115200') }
                    )

                    foreach ($operationDefinition in $operationDefinitions) {
                        $operationResult = Invoke-SacBcdEdit -Arguments $operationDefinition.Arguments -Operation $operationDefinition.Name
                        if (-not $operationResult.Success) {
                            throw "bcdedit operation '$($operationDefinition.Name)' failed with exit code $($operationResult.ExitCode). BCD backup: $bcdBackup"
                        }
                    }

                    # SAC changes must not alter the selected loader's boot mapping.
                    $mappingVerificationQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultId, '/v') -Operation 'verify-loader-mapping'
                    if (-not $mappingVerificationQuery.Success) {
                        throw "Unable to verify loader mapping after SAC changes. BCD backup: $bcdBackup"
                    }

                    $mappingVerificationText = $mappingVerificationQuery.Output -join "`n"
                    $afterPathMatch = [regex]::Match($mappingVerificationText, '(?im)^\s*path\s+(.+?)\s*$')
                    $afterDeviceMatch = [regex]::Match($mappingVerificationText, '(?im)^\s*device\s+(.+?)\s*$')
                    $afterOsDeviceMatch = [regex]::Match($mappingVerificationText, '(?im)^\s*osdevice\s+(.+?)\s*$')
                    $afterSystemRootMatch = [regex]::Match($mappingVerificationText, '(?im)^\s*systemroot\s+(.+?)\s*$')
                    $mappingUnchanged = $afterPathMatch.Success -and
                        $afterDeviceMatch.Success -and
                        $afterOsDeviceMatch.Success -and
                        $afterSystemRootMatch.Success -and
                        ($afterPathMatch.Groups[1].Value.Trim() -ieq $originalLoaderPath) -and
                        ($afterDeviceMatch.Groups[1].Value.Trim() -ieq $originalDevice) -and
                        ($afterOsDeviceMatch.Groups[1].Value.Trim() -ieq $originalOsDevice) -and
                        ($afterSystemRootMatch.Groups[1].Value.Trim() -ieq $originalSystemRoot)

                    if (-not $mappingUnchanged) {
                        $afterPath = if ($afterPathMatch.Success) { $afterPathMatch.Groups[1].Value.Trim() } else { '<missing>' }
                        $afterDevice = if ($afterDeviceMatch.Success) { $afterDeviceMatch.Groups[1].Value.Trim() } else { '<missing>' }
                        $afterOsDevice = if ($afterOsDeviceMatch.Success) { $afterOsDeviceMatch.Groups[1].Value.Trim() } else { '<missing>' }
                        $afterSystemRoot = if ($afterSystemRootMatch.Success) { $afterSystemRootMatch.Groups[1].Value.Trim() } else { '<missing>' }
                        Log-Error 'BCD loader mapping changed unexpectedly.'
                        Log-Error "Before: path=$originalLoaderPath device=$originalDevice osdevice=$originalOsDevice systemroot=$originalSystemRoot"
                        Log-Error "After: path=$afterPath device=$afterDevice osdevice=$afterOsDevice systemroot=$afterSystemRoot"

                        Copy-Item -LiteralPath $bcdBackup -Destination $bcdPath -Force -ErrorAction Stop
                        Write-SacTelemetry -Event Error -Message 'BCD loader mapping changed and backup restored' -Properties @{
                            DiskNumber = $diskNumber
                            BcdPath = $bcdPath
                            BackupPath = $bcdBackup
                            LoaderGuid = $defaultId
                            BeforePath = $originalLoaderPath
                            AfterPath = $afterPath
                            BeforeDevice = $originalDevice
                            AfterDevice = $afterDevice
                            BeforeOsDevice = $originalOsDevice
                            AfterOsDevice = $afterOsDevice
                            BeforeSystemRoot = $originalSystemRoot
                            AfterSystemRoot = $afterSystemRoot
                        }
                        throw 'BCD loader mapping changed unexpectedly. The original BCD backup was restored.'
                    }

                    # Verify every setting requested by the repair.
                    Log-Info 'Verifying BCD changes...'
                    $verifyLoaderQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', $defaultId) -Operation 'verify-loader'
                    $verifyBootMgrQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', '{bootmgr}') -Operation 'verify-bootmgr'
                    $verifyEmsSettingsQuery = Invoke-SacBcdEdit -Arguments @('/store', $bcdPath, '/enum', '{emssettings}') -Operation 'verify-emssettings'

                    $verifyLoaderText = $verifyLoaderQuery.Output -join "`n"
                    $verifyBootMgrText = $verifyBootMgrQuery.Output -join "`n"
                    $verifyEmsSettingsText = $verifyEmsSettingsQuery.Output -join "`n"

                    $emsEnabled = $verifyLoaderText -match '(?im)^\s*ems\s+Yes\s*$'
                    $bootEmsEnabled = $verifyBootMgrText -match '(?im)^\s*bootems\s+Yes\s*$'
                    $bootMenuEnabled = $verifyBootMgrText -match '(?im)^\s*displaybootmenu\s+Yes\s*$'
                    $timeoutConfigured = $verifyBootMgrText -match '(?im)^\s*timeout\s+5\s*$'
                    # BCDEdit may label these fields as EMSPORT/EMSBAUDRATE or port/baudrate.
                    $portConfigured = $verifyEmsSettingsText -match '(?im)^\s*(?:emsport|port)\s+1\s*$'
                    $baudConfigured = $verifyEmsSettingsText -match '(?im)^\s*(?:emsbaudrate|baudrate)\s+115200\s*$'

                    $verificationPassed = $verifyLoaderQuery.Success -and
                        $verifyBootMgrQuery.Success -and
                        $verifyEmsSettingsQuery.Success -and
                        $emsEnabled -and $bootEmsEnabled -and $bootMenuEnabled -and
                        $timeoutConfigured -and $portConfigured -and $baudConfigured

                    Write-SacTelemetry -Event Operation -Message 'Post-change BCD verification completed' -Properties @{
                        DiskNumber = $diskNumber
                        BcdPath = $bcdPath
                        LoaderGuid = $defaultId
                        EmsEnabled = $emsEnabled
                        BootEmsEnabled = $bootEmsEnabled
                        BootMenuEnabled = $bootMenuEnabled
                        TimeoutConfigured = $timeoutConfigured
                        PortConfigured = $portConfigured
                        BaudConfigured = $baudConfigured
                        VerificationPassed = $verificationPassed
                    }

                    if (-not $verificationPassed) {
                        Write-SacTelemetry -Event Error -Message 'BCD verification failed' -Properties @{
                            DiskNumber = $diskNumber
                            BcdPath = $bcdPath
                            BackupPath = $bcdBackup
                            EmsEnabled = $emsEnabled
                            BootEmsEnabled = $bootEmsEnabled
                            BootMenuEnabled = $bootMenuEnabled
                            TimeoutConfigured = $timeoutConfigured
                            PortConfigured = $portConfigured
                            BaudConfigured = $baudConfigured
                        }
                        Log-Error "CRITICAL: SAC/EMS verification failed. Restore from backup if needed: $bcdBackup"
                        Log-Error "Verification state: ems=$emsEnabled bootems=$bootEmsEnabled displaybootmenu=$bootMenuEnabled timeout=$timeoutConfigured port=$portConfigured baud=$baudConfigured"
                        $failureReason = "Post-change BCD verification failed for Disk $diskNumber."
                        $diskFailed = $true
                    }
                    else {
                        Log-Output '--- BCD AFTER SAC ENABLE ---'
                        foreach ($line in $verifyLoaderQuery.Output) { if (-not [string]::IsNullOrWhiteSpace([string]$line)) { Log-Output $line } }
                        foreach ($line in $verifyBootMgrQuery.Output) { if (-not [string]::IsNullOrWhiteSpace([string]$line)) { Log-Output $line } }
                        foreach ($line in $verifyEmsSettingsQuery.Output) { if (-not [string]::IsNullOrWhiteSpace([string]$line)) { Log-Output $line } }
                        $diskChanged = $true
                    }
                }
            }
            else
            {
                $failureReason = "The default Windows Boot Loader entry was found, but no GUID could be parsed for $bcdPath."
                Log-Warning "$failureReason Raw line: $($defaultLine.Line)"
                $diskFailed = $true
            }
        }
        else {
            Log-Info "Disk $diskNumber skipped: no valid combination of BCD store and OS loader was found."
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
            $dpClean = @("select disk $tempEfiDiskNum", "select partition $tempEfiPartNum", "remove letter=$tempEfiLetter noerr")
            $dpCleanOut = $dpClean | diskpart 2>&1
            foreach ($line in @($dpCleanOut)) { if ($line) { Log-Output "[diskpart][cleanup] $line" } }
        }

        if ($tempOsLetter)
        {
            Log-Info "Removing temp letter ${tempOsLetter}: from Disk $tempOsDiskNum Partition $tempOsPartNum"
            $dpOsClean = @("select disk $tempOsDiskNum", "select partition $tempOsPartNum", "remove letter=$tempOsLetter noerr")
            $dpOsCleanOut = $dpOsClean | diskpart 2>&1
            foreach ($line in @($dpOsCleanOut)) { if ($line) { Log-Output "[diskpart][os-cleanup] $line" } }
        }

        if ($diskFailed) { $failedCount++ }
        elseif ($diskChanged) { $changedCount++ }
        else { $skippedCount++ }
        }
    }
    }

    if ($failedCount -gt 0 -or $changedCount -eq 0) {
        $script_final_status = $STATUS_ERROR
    }
    else {
        $script_final_status = $STATUS_SUCCESS
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
    $durationSeconds = [math]::Round(((Get-Date) - $script:ExecutionStarted).TotalSeconds, 3)
    if ($script_final_status -eq $STATUS_SUCCESS) {
        Write-SacTelemetry -Event Success -Message 'SAC/EMS repair completed successfully' -Properties @{
            OperationsPerformed = $script:OperationCount
            DurationSeconds = $durationSeconds
            DisksProcessed = $processedCount
            DisksChanged = $changedCount
            DisksSkipped = $skippedCount
            DisksFailed = $failedCount
            BootEmsEnabled = $true
            EmsEnabled = $true
        }
    }
    else {
        Write-SacTelemetry -Event Error -Message 'SAC/EMS repair completed with errors' -Properties @{
            OperationsPerformed = $script:OperationCount
            DurationSeconds = $durationSeconds
            DisksProcessed = $processedCount
            DisksChanged = $changedCount
            DisksSkipped = $skippedCount
            DisksFailed = $failedCount
            FailureReason = $failureReason
            LastCommand = $script:LastCommand
        }
    }

# VMRepairMint telemetry marker
Log-Info "[final_status] Status=$script_final_status"

Write-SacTelemetry -Event Operation -Message 'final_status' -Properties @{
    FinalStatus = $script_final_status
    DurationSeconds = $durationSeconds
    DisksProcessed = $processedCount
    DisksChanged = $changedCount
    DisksSkipped = $skippedCount
    DisksFailed = $failedCount
}

    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Detected execution context: $detectedExecutionContext"
    Log-Info "Desktop log: $desktopLogFile"
    if (Test-Path -Path $pluginLogFile -PathType Leaf) {
        Log-Info "Plugin log (auto-collected): $pluginLogFile"
    }
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
