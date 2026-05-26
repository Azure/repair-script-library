<#
.SYNOPSIS
    Enables Special Administration Console (SAC) and Serial Console boot settings.

.DESCRIPTION
    This script runs from a rescue VM to enable SAC/EMS on an attached OS disk's BCD store.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
    1a. For Gen2 disks where the EFI partition has no drive letter, uses diskpart to
        temporarily assign one so the BCD store can be accessed.
    2. Identifies the default boot entry GUID from the BCD bootmgr displayorder.
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
bcdedit /store F:\boot\bcd /enum "{bootmgr}"
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

# Initialization
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

# Log Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\sac-enabler_$timestamp.log"

# Status Tracking
$script_final_status = $STATUS_ERROR

try {
    # Check if the Hyper-V module is available before performing nested VM checks
    if (Get-Module -ListAvailable -Name Hyper-V) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine) {
            if ($guestHyperVVirtualMachine.State -eq 'Running') {
                Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)" | Tee-Object -FilePath $logFile -Append
                try {
                    Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                }
                catch {
                    Log-Warning "Failed to stop nested guest VM, will continue but may have limited success" | Tee-Object -FilePath $logFile -Append
                }
            }
        }
    } else {
        Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation." | Tee-Object -FilePath $logFile -Append
    }

    # Step 1 - Enumerate partitions to locate the BCD store and OS loader
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    Log-Info 'Enumerating partitions to enable SAC...' | Tee-Object -FilePath $logFile -Append

    foreach ( $partitionGroup in $partitionlist | group DiskNumber )
    {
        $isBcdPath = $false
        $bcdPath = ''
        $isOsPath = $false

        # Scan each drive for BCD store and Windows OS loader
        ForEach ($drive in $partitionGroup.Group | select -ExpandProperty DriveLetter )
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
                $isOsPath = Test-Path ($drive + ':\windows\system32\winload.exe')
            }
        }

        # Gen2 EFI fallback: if OS found but no BCD, discover unlettered EFI partition
        $tempEfiLetter = $null
        $tempEfiDiskNum = $null
        $tempEfiPartNum = $null
        if (-not $isBcdPath -and $isOsPath)
        {
            $diskNum = [int]$partitionGroup.Name
            $rescueDiskNum = (Get-Partition -DriveLetter $rescueDrive -ErrorAction SilentlyContinue | Select-Object -First 1).DiskNumber
            if ($diskNum -ne $rescueDiskNum)
            {
                Log-Info "Disk ${diskNum}: OS found but no BCD - checking for unlettered EFI partition (Gen2)..." | Tee-Object -FilePath $logFile -Append
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
                            Log-Info "Assigning temp letter ${tempLetter}: to Disk $diskNum Partition $pn (EFI)..." | Tee-Object -FilePath $logFile -Append
                            $dpLines = @("select disk $diskNum", "select partition $pn", "assign letter=$tempLetter")
                            $dpLines | diskpart | Out-Null
                            Start-Sleep -Seconds 2
                            $bcdPath = "${tempLetter}:\efi\microsoft\boot\bcd"
                            $isBcdPath = Test-Path $bcdPath
                            if ($isBcdPath)
                            {
                                Log-Info "Found Gen2 BCD store at $bcdPath" | Tee-Object -FilePath $logFile -Append
                                $tempEfiLetter = $tempLetter
                                $tempEfiDiskNum = $diskNum
                                $tempEfiPartNum = $pn
                                break
                            }
                            else
                            {
                                Log-Info "No BCD at $bcdPath, removing letter..." | Tee-Object -FilePath $logFile -Append
                                $dpRemove = @("select disk $diskNum", "select partition $pn", "remove letter=$tempLetter")
                                $dpRemove | diskpart | Out-Null
                            }
                        }
                    }
                    else
                    {
                        Log-Warning "No available drive letter for EFI partition on Disk $diskNum" | Tee-Object -FilePath $logFile -Append
                    }
                }
            }
        }

        # Apply SAC changes if both BCD and OS loader were found
        if ( $isBcdPath -and $isOsPath )
        {
            # Step 2 - Identify the default boot entry GUID
            $bcdout = bcdedit /store $bcdPath /enum bootmgr /v
            $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
            
            if ($defaultLine -match '\{([^}]+)\}') {
                $defaultId = $matches[0]

                # Step 3 - Log BCD configuration before changes
                Log-Output "--- BCD BEFORE SAC ENABLE ---" | Tee-Object -FilePath $logFile -Append
                $beforeBcd = bcdedit /store $bcdPath /enum $defaultId
                foreach ($line in $beforeBcd) { if ($line.Trim()) { Log-Output $line | Tee-Object -FilePath $logFile -Append } }

                # Steps 4-7 - Enable boot menu, Boot EMS, EMS on OS entry, and EMS serial settings
                Log-Info "Applying SAC and EMS configurations..." | Tee-Object -FilePath $logFile -Append
                bcdedit /store $bcdPath /set "{bootmgr}" displaybootmenu yes | Out-Null
                bcdedit /store $bcdPath /set "{bootmgr}" timeout 5 | Out-Null
                bcdedit /store $bcdPath /set "{bootmgr}" bootems yes | Out-Null
                bcdedit /store $bcdPath /ems $defaultId ON | Out-Null
                $res = bcdedit /store $bcdPath /emssettings EMSPORT:1 EMSBAUDRATE:115200

                Log-Output "Result: $res" | Tee-Object -FilePath $logFile -Append

                # Step 8 - Log BCD configuration after changes for verification
                Log-Output "--- BCD AFTER SAC ENABLE ---" | Tee-Object -FilePath $logFile -Append
                $afterBcd = bcdedit /store $bcdPath /enum $defaultId
                foreach ($line in $afterBcd) { if ($line.Trim()) { Log-Output $line | Tee-Object -FilePath $logFile -Append } }
                
                $script_final_status = $STATUS_SUCCESS
            }
        }

        # Clean up temporary EFI drive letter if one was assigned
        if ($tempEfiLetter)
        {
            Log-Info "Removing temp letter ${tempEfiLetter}: from Disk $tempEfiDiskNum Partition $tempEfiPartNum" | Tee-Object -FilePath $logFile -Append
            $dpClean = @("select disk $tempEfiDiskNum", "select partition $tempEfiPartNum", "remove letter=$tempEfiLetter")
            $dpClean | diskpart | Out-Null
        }
    }

    if ($script_final_status -ne $STATUS_SUCCESS) {
        Log-Error "FAILED: Script could not find a valid OS disk to enable SAC." | Tee-Object -FilePath $logFile -Append
    }
}
catch {
    Log-Error "An error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}

return $script_final_status
