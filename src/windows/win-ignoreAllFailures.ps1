<#
.SYNOPSIS
    win-ignoreAllFailures.ps1 (v1.2) - Sets BCD bootstatuspolicy to IgnoreAllFailures to break Automatic Repair loops.

.DESCRIPTION
    This script runs from a rescue VM to modify the BCD store on an attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
    2. Identifies the default boot entry GUID from the BCD bootmgr displayorder.
    3. Logs the BCD configuration before any changes are made.
    4. Sets the default boot entry to the identified GUID.
    5. Sets bootstatuspolicy to IgnoreAllFailures on the default entry.
    6. Logs the BCD configuration after changes for verification.

    This resolves VMs stuck in Automatic Repair loops caused by failed boot, failed shutdown,
    or failed checkpoint errors.

.NOTES
    Name:    win-ignoreAllFailures.ps1
    Version: 1.2
    Author:  Tony.Mocanu@Microsoft.com

.VERSION
    v1.2: [May 2026] - Updated the script (current)
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
    az vm repair run -g <rg> -n <vm> --run-id win-ignoreAllFailures --run-on-repair

.VERIFICATION
    1. Check the log file for success:
       Get-ChildItem "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\ignoreAllFailures_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
       Expected: "BCD AFTER CHANGE" section shows bootstatuspolicy = IgnoreAllFailures, return code 0.
    2. Manually verify the BCD store on the attached disk (replace F with the BCD partition letter):
       bcdedit /store F:\boot\bcd /enum
       or for EFI:
       bcdedit /store F:\efi\microsoft\boot\bcd /enum
       Expected: bootstatuspolicy set to IgnoreAllFailures on the default entry.
#>

# Initialization (no Param() block to avoid ParserErrors on legacy PowerShell engines)
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\ignoreAllFailures_$timestamp.log"

$successReport = New-Object System.Collections.Generic.List[string]
$script_final_status = $STATUS_ERROR

function Get-FormattedOutput {
    param([string]$text)
    $time = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
    return "[Output $time]$text"
}

function Get-NextFreeDriveLetter {
    $usedLetters = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    $letters = 90..69 | ForEach-Object { [char]$_ } 
    foreach ($letter in $letters) {
        if ($letter -notin $usedLetters) { return $letter }
    }
}

try {
    Log-Info "Starting IgnoreAllFailures script..." | Tee-Object -FilePath $logFile -Append

    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
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
    }
    catch {
        Log-Warning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    }
    
    $partitionlist = Get-Disk-Partitions

    $rescueDrive = $env:SystemDrive -replace ':', ''
    Log-Info "Starting deep scan for BCD files..." | Tee-Object -FilePath $logFile -Append

    forEach ($diskGroup in $partitionlist | Group-Object DiskNumber) {
        if ($diskGroup.Group.DriveLetter -contains $rescueDrive) { continue }
        
        $currentDiskBcdPath = $null
        $currentDiskOsFound = $false
        
        # EFI Mounter Logic
        $hiddenPartitions = Get-Partition -DiskNumber $diskGroup.Name | Where-Object { $_.DriveLetter -eq 0 -and ($_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -or $_.Type -eq "System") }
        foreach ($part in $hiddenPartitions) {
            $newLetter = Get-NextFreeDriveLetter
            Log-Info "Mounting hidden EFI partition on Disk $($diskGroup.Name) to $newLetter`:" | Tee-Object -FilePath $logFile -Append
            $part | Set-Partition -NewDriveLetter $newLetter -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        $currentDrives = Get-Partition -DiskNumber $diskGroup.Name | Where-Object { $_.DriveLetter -ne 0 } | Select-Object -ExpandProperty DriveLetter
        foreach ($drive in $currentDrives) {
            $driveStr = "$($drive):"
            if ($null -eq $currentDiskBcdPath) {
                if (Test-Path "$driveStr\boot\bcd") { $currentDiskBcdPath = "$driveStr\boot\bcd" }
                elseif (Test-Path "$driveStr\efi\microsoft\boot\bcd") { $currentDiskBcdPath = "$driveStr\efi\microsoft\boot\bcd" }
            }
            if ($currentDiskOsFound -eq $false) {
                if (Test-Path "$driveStr\windows\system32\winload.exe") { $currentDiskOsFound = $true }
                elseif (Test-Path "$driveStr\windows\system32\winload.efi") { $currentDiskOsFound = $true }
            }
        }

        if ($currentDiskBcdPath -and $currentDiskOsFound) {
            $bcdout = bcdedit /store $currentDiskBcdPath /enum bootmgr /v
            $defaultLine = $bcdout | Select-String 'displayorder' | Select-Object -First 1
            
            if ($defaultLine -and ($defaultLine -match '\{([^}]+)\}')) {
                $defaultId = $matches[0]
                
                $successReport.Add((Get-FormattedOutput "--- BCD BEFORE CHANGE ---"))
                $beforeLines = (bcdedit /store $currentDiskBcdPath /enum $defaultId) -split "`r`n"
                foreach ($line in $beforeLines) { if($line) { $successReport.Add((Get-FormattedOutput $line)) } }
                
                bcdedit /store $currentDiskBcdPath /default $defaultId | Out-Null
                $null = bcdedit /store $currentDiskBcdPath /set $defaultId bootstatuspolicy IgnoreAllFailures
                
                $successReport.Add((Get-FormattedOutput "--- BCD AFTER CHANGE ---"))
                $afterLines = (bcdedit /store $currentDiskBcdPath /enum $defaultId) -split "`r`n"
                foreach ($line in $afterLines) { if($line) { $successReport.Add((Get-FormattedOutput $line)) } }
                
                $script_final_status = $STATUS_SUCCESS
            }
        }
    }
}
catch {
    Log-Error "An error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    # Final logging of report via Log-Info (NOT Write-Output)
    if ($successReport.Count -gt 0) {
        foreach ($reportLine in $successReport) {
            Log-Info $reportLine | Tee-Object -FilePath $logFile -Append
        }
    }
    Log-Info "Script completed with status: $script_final_status" | Tee-Object -FilePath $logFile -Append
}

# Proper return for Azure Telemetry
return $script_final_status
