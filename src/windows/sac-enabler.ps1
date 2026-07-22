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
    Name:    sac-enabler.ps1
    Author:  Tony.Mocanu@Microsoft.com
    
    .VERSION
    v1.3: [May 2026] - Updated the script again (current)
                       - Fixed breaking exception when the Hyper-V module is not installed on the host.
                       - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.2: [May 2026] - Updated the script
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v0.1: Initial commit. This was the version 1.0 of the script.

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

# Script-level logging: mirror Log-* output to desktop and plugin log files.
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runOutputDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$logFilePath = Join-Path -Path $runOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)
$pluginLogDir = 'C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension'
$pluginLogPath = Join-Path -Path $pluginLogDir -ChildPath ("{0}_{1}.log" -f $scriptName, $runTimestamp)
$script:RunLogTargets = @()

if (-not (Test-Path -Path $runOutputDir -PathType Container)) {
    New-Item -Path $runOutputDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -Path $pluginLogDir -PathType Container)) {
    New-Item -Path $pluginLogDir -ItemType Directory -Force | Out-Null
}

$script:RunLogTargets += $logFilePath
$script:RunLogTargets += $pluginLogPath

foreach ($targetLogPath in $script:RunLogTargets) {
    if (-not (Test-Path -Path $targetLogPath -PathType Leaf)) {
        New-Item -Path $targetLogPath -ItemType File -Force | Out-Null
    }
}

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock

function Write-RunLogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [PSObject[]]$Message
    )

    try {
        $renderedMessage = ($Message | ForEach-Object { "$_" }) -join ' '
        $line = "[{0} {1}]{2}" -f $Level, (Get-Date), $renderedMessage
        foreach ($targetLogPath in $script:RunLogTargets) {
            Add-Content -Path $targetLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        if ($script:OriginalLogWarning) {
            & $script:OriginalLogWarning -message "Failed to append to one or more run logs: $($_.Exception.Message)"
        }
        else {
            [Console]::Error.WriteLine("[Warning $(Get-Date)]Failed to append to one or more run logs: $($_.Exception.Message)")
        }
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-RunLogLine -Level 'Output' -Message $message
}

function Log-Info {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogInfo -message $message
    Write-RunLogLine -Level 'Info' -Message $message
}

function Log-Warning {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogWarning -message $message
    Write-RunLogLine -Level 'Warning' -Message $message
}

function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-RunLogLine -Level 'Error' -Message $message
}

function Log-Debug {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogDebug -message $message
    Write-RunLogLine -Level 'Debug' -Message $message
}

function Remove-StaleEfiTempLetters {
    $candidateLetters = @('Z','Y','X','W','V','U','T','S','R','Q')
    $rescueDrive = ($env:SystemDrive -replace ':', '').ToUpperInvariant()
    $rescueDisk = Get-Partition -DriveLetter $rescueDrive -ErrorAction SilentlyContinue | Select-Object -First 1
    $rescueDiskNum = $null
    if ($rescueDisk) {
        $rescueDiskNum = $rescueDisk.DiskNumber
    }

    $efiGptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $staleParts = Get-Partition -ErrorAction SilentlyContinue | Where-Object {
        $_.GptType -eq $efiGptType -and
        $_.DriveLetter -and
        ($_.DriveLetter.ToString().ToUpperInvariant() -in $candidateLetters) -and
        ($null -eq $rescueDiskNum -or $_.DiskNumber -ne $rescueDiskNum)
    }

    foreach ($part in $staleParts) {
        $letter = $part.DriveLetter.ToString().ToUpperInvariant()
        $probePath = "${letter}:\efi\microsoft\boot\bcd"
        if (-not (Test-Path -Path $probePath)) {
            continue
        }

        Log-Warning "Found possible stale EFI temp letter ${letter}: on Disk $($part.DiskNumber) Partition $($part.PartitionNumber). Removing..."
        $dpRemove = @(
            "select disk $($part.DiskNumber)",
            "select partition $($part.PartitionNumber)",
            "remove letter=$letter"
        )
        $dpOut = $dpRemove | diskpart 2>&1
        foreach ($line in @($dpOut)) {
            if ($line) {
                Log-Output "[diskpart][stale-cleanup] $line"
            }
        }
    }
}

$logFile = $logFilePath
Log-Info "Desktop plain text log initialized: $logFilePath"
Log-Info "Plugin log initialized: $pluginLogPath"

# Status Tracking
$script_final_status = $STATUS_ERROR
$failureReason = 'Script could not find a valid OS disk to enable SAC.'
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

Log-Info "Starting SAC enabler. Desktop log: $logFile"
Log-Info "Run logs: $($script:RunLogTargets -join ', ')"
Remove-StaleEfiTempLetters

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
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    Log-Info 'Enumerating partitions to enable SAC...'

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
        Log-Info "Processing Disk $diskNumber"

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

                # Step 3 - Log BCD configuration before changes
                Log-Output "--- BCD BEFORE SAC ENABLE ---"
                $beforeBcd = bcdedit /store $bcdPath /enum $defaultId
                foreach ($line in $beforeBcd) { if ($line.Trim()) { Log-Output $line } }

                # Steps 4-7 - Enable boot menu, Boot EMS, EMS on OS entry, and EMS serial settings
                Log-Info "Applying SAC and EMS configurations..."
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

                # Step 8 - Log BCD configuration after changes for verification
                Log-Output "--- BCD AFTER SAC ENABLE ---"
                $afterBcd = bcdedit /store $bcdPath /enum $defaultId
                foreach ($line in $afterBcd) { if ($line.Trim()) { Log-Output $line } }
                
                $script_final_status = $STATUS_SUCCESS
                $diskChanged = $true
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
        }
        catch {
            $diskFailed = $true
            $failureReason = "Disk $diskNumber failed with exception: $($_.Exception.Message)"
            Log-Error $failureReason
            if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
                Log-Error "Disk $diskNumber failure context: $($_.InvocationInfo.PositionMessage)"
            }
        }
        finally {

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

    if ($script_final_status -ne $STATUS_SUCCESS) {
        Log-Error "FAILED: $failureReason"
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
    Log-Info "Desktop log file: $logFile"
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
