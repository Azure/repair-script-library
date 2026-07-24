<#
.SYNOPSIS
    Enables SAC and Serial Console boot settings on attached Windows disks, including BIOS and UEFI layouts.

.DESCRIPTION
    This script runs from a rescue VM to enable SAC/EMS on an attached OS disk's BCD store.
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
    Requirement: Azure rescue VM with attached Windows OS disk OR standard VM with local modifications
    DeployMode:  az vm repair run (with --run-on-repair)
    
    .VERSION
    v1.3: [July 2026]  - Added execution context detection and dual-logging (current)
                         - Detects rescue VM mode vs standard mode for context-aware error messages.
                         - Dual-logs to desktop and plugin directory for az vm repair auto-collection.
                         - **NEW SAFETY: Pre-flight checks, BCD backup, and post-change verification.
                         - **NEW SAFETY: Validates GUID format before making BCD edits.
                         - **NEW SAFETY: Verifies EMS was actually enabled after bcdedit commands.
                         - Added .ROLLBACK_RECOVERY section with disaster recovery instructions.
                         - Annotated Log-* wrapper pattern with consolidation note.
    v1.2: [May 2026]   - Fixed breaking exception when the Hyper-V module is not installed on the host.
                         - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.1: [May 2026]   - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v0.1: [Initial]    - Initial commit. Version 1.0 of the script.
    
    .MODE_DETECTION
    This script can run in two modes:
    - RESCUE_VM: Running from a rescue VM with the target OS disk attached as a secondary disk.
                 Use: az vm repair run -g <rg> -n <vm> --run-id win-sac-enabler --run-on-repair
    - STANDARD_VM: Running directly on the target VM (not recommended; use rescue mode for safety).
                   Useful for testing or direct remediation if rescue VM access is unavailable.

.SCENARIO_RECREATION
    To recreate a testable scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
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
    az vm repair run -g <rg> -n <vm> --run-id win-sac-enabler --run-on-repair

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
    IF THE VM FAILS TO BOOT AFTER az vm repair restore:
    
    1. Boot the VM from the Windows installation media or attach to a rescue VM.
    2. Locate the BCD backup file created by the script:
       - From rescue VM: Look in the mounted disk for *.backup-* files
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

# ===========================================
# Execution Context Detection
# ===========================================
function Test-RescueVmMode {
    <#
    .SYNOPSIS
        Detects if the script is running in rescue VM mode (attached OS disk) or standard mode (local VM).
    .DESCRIPTION
        Rescue VM mode: The target OS disk is attached as a secondary disk to a rescue VM.
                        Get-Disk will show multiple disks, rescue disk is at index 0.
        Standard mode:  The script runs on the actual target VM.
                        Only one disk (or all disks are the OS disk).
    #>
    try {
        $disks = @(Get-Disk -ErrorAction Stop | Where-Object { $_.OperationalStatus -eq 'Online' })
        
        if ($disks.Count -lt 2) {
            return $false  # Standard mode: only one disk (or one online disk)
        }
        
        # Check if multiple OS drives are detected (unlikely on rescue, likely on standard)
        $osDriveLetters = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ -eq $env:SystemDrive[0] })
        
        # Rescue mode: typically has multiple disks but only one local OS drive (the rescue VM's own)
        # Standard mode: has the target disk with its own OS boot structures
        return ($disks.Count -ge 2)
    }
    catch {
        # If we can't determine, assume we might be in rescue mode (safer assumption)
        return $true
    }
}

$isRescueVmMode = Test-RescueVmMode
$executionContext = if ($isRescueVmMode) { 'RESCUE_VM' } else { 'STANDARD_VM' }

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
@($desktopLogDir, $pluginLogDir) | ForEach-Object {
    if (-not (Test-Path -Path $_ -PathType Container)) {
        try {
            New-Item -Path $_ -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            # Plugin dir may not be creatable; continue with desktop log only
            if ($_ -eq $pluginLogDir) {
                [Console]::Error.WriteLine("[Warning] Could not create plugin log directory: $_. Will use desktop log only.")
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

$logFile = $logFilePath
Log-Info "Dual logging initialized - Desktop: $desktopLogFile | Plugin: $pluginLogFile"
Log-Info "Execution mode: $executionContext"

# Status Tracking
$script_final_status = $STATUS_ERROR
$contextAwareFailureReason = @{
    RESCUE_VM = 'Script could not find a valid attached OS disk to enable SAC. Verify the disk is properly attached to the rescue VM.'
    STANDARD_VM = 'Script could not find a valid OS disk. Running on the local VM instead of rescue mode may limit disk detection.'
}
$failureReason = $contextAwareFailureReason[$executionContext]
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

Log-Info "Starting SAC enabler in $executionContext mode. Logs: $logFile"

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
        Log-Debug "Orphan detection encountered an error (non-critical): $($_.Exception.Message)"
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
                    Log-Warning "Failed to stop nested guest VM, will continue but may have limited success"
                }
            }
        }
    } else {
        Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
    }

    # Step 1 - Enumerate partitions to locate the BCD store and OS loader
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    Log-Info 'Enumerating partitions to enable SAC...'
    
    # SAFETY CHECK: Ensure we're not operating on the rescue VM's own disk
    $rescueDiskNum = (Get-Partition -DriveLetter $rescueDrive -ErrorAction SilentlyContinue | Select-Object -First 1).DiskNumber
    Log-Info "Rescue VM OS disk identified as Disk $rescueDiskNum"
    
    $targetDisksFound = @($partitionlist | Group-Object DiskNumber | Where-Object { [int]$_.Name -ne $rescueDiskNum })
    if ($targetDisksFound.Count -eq 0 -and $executionContext -eq 'RESCUE_VM') {
        Log-Error "CRITICAL SAFETY CHECK FAILED: No secondary disks found in rescue VM mode."
        Log-Error "This script requires an attached OS disk (different from the rescue VM's own disk)."
        $script_final_status = $STATUS_ERROR
        $failureReason = "No secondary disks found. Rescue VM must have an attached target OS disk."
    }
    else
    {
        if ($executionContext -eq 'STANDARD_VM') {
            Log-Warning "Running in STANDARD_VM mode. Changes will be applied to the local VM's boot configuration."
            Log-Warning "SAFETY RISK: If changes corrupt BCD, the VM may not boot after restart."
            Log-Warning "Ensure you have recovery/rollback capability before proceeding."
        }

    foreach ( $partitionGroup in $partitionlist | Group-Object DiskNumber )
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
        $bcdBackup = $null
        
        Log-Info "Processing Disk $diskNumber"
        
        # SAFETY: Skip if this is the rescue VM's own disk in rescue mode
        if ($executionContext -eq 'RESCUE_VM' -and [int]$diskNumber -eq $rescueDiskNum) {
            Log-Warning "Disk $diskNumber is the rescue VM's own disk. Skipping for safety."
            $skippedCount++
            continue
        }

        try {

        # Scan each drive for BCD store and Windows OS loader
        ForEach ($drive in $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter )
        {
            # Skip the rescue VM's own OS drive
            if ($drive -eq $rescueDrive) { continue }

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

        # Gen2 EFI fallback: if OS found but no BCD, discover unlettered EFI partition
        if (-not $isBcdPath -and $isOsPath)
        {
            $diskNum = [int]$partitionGroup.Name
            $rescueDiskNum = (Get-Partition -DriveLetter $rescueDrive -ErrorAction SilentlyContinue | Select-Object -First 1).DiskNumber
            if ($diskNum -ne $rescueDiskNum)
            {
                Log-Info "Disk ${diskNum}: OS found but no BCD - checking for unlettered EFI partition (Gen2)..."
                $efiGptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
                $efiParts = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue | Where-Object {
                    $_.GptType -eq $efiGptType -and (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0)
                }
                if ($efiParts)
                {
                    # Find an available drive letter (Z downward to avoid conflicts)
                    $usedLetters = @()
                    Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { $usedLetters += $_.DriveLetter }
                    $tempLetter = $null
                    foreach ($l in @('Z','Y','X','W','V','U','T','S','R','Q')) {
                        if ($l -notin $usedLetters) { $tempLetter = $l; break }
                    }
                    if ($tempLetter)
                    {
                        foreach ($ep in $efiParts)
                        {
                            $pn = $ep.PartitionNumber
                            Log-Info "Assigning temp letter ${tempLetter}: to Disk $diskNum Partition $pn (EFI)..."
                            $dpLines = @("select disk $diskNum", "select partition $pn", "assign letter=$tempLetter")
                            $dpAssignOut = $dpLines | diskpart 2>&1
                            foreach ($line in @($dpAssignOut)) { if ($line) { Log-Output "[diskpart][assign] $line" } }
                            Start-Sleep -Seconds 2
                            $bcdPath = "${tempLetter}:\efi\microsoft\boot\bcd"
                            $isBcdPath = Test-Path $bcdPath
                            if ($isBcdPath)
                            {
                                Log-Info "Found Gen2 BCD store at $bcdPath"
                                $tempEfiLetter = $tempLetter
                                $tempEfiDiskNum = $diskNum
                                $tempEfiPartNum = $pn
                                break
                            }
                            else
                            {
                                Log-Info "No BCD at $bcdPath, removing letter..."
                                $dpRemove = @("select disk $diskNum", "select partition $pn", "remove letter=$tempLetter")
                                $dpRemoveOut = $dpRemove | diskpart 2>&1
                                foreach ($line in @($dpRemoveOut)) { if ($line) { Log-Output "[diskpart][remove] $line" } }
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
        }

        if ($diskChanged) { $changedCount++ }
        elseif ($diskFailed) { $failedCount++ }
        else { $skippedCount++ }
        }
    }
    }

    if ($script_final_status -ne $STATUS_SUCCESS) {
        if ($executionContext -eq 'STANDARD_VM') {
            Log-Error "[$executionContext] FAILED: $failureReason"
            Log-Error "[$executionContext] Note: This script is optimized for RESCUE_VM mode. Consider running from a rescue VM for better disk detection."
        } else {
            Log-Error "[$executionContext] FAILED: $failureReason"
        }
    }
}
catch {
    Log-Error "An error occurred: $($_.Exception.Message)"
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Log-Error "Failure context: $($_.InvocationInfo.PositionMessage)"
    }
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Execution mode: $executionContext"
    Log-Info "Desktop log: $desktopLogFile"
    if (Test-Path -Path $pluginLogFile -PathType Leaf) {
        Log-Info "Plugin log (auto-collected): $pluginLogFile"
    }
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
