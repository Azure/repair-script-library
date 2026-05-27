<#
.SYNOPSIS
    Runs chkdsk to fix file system corruption on an attached rescue disk.

.DESCRIPTION
    This script runs from a rescue VM to check and repair NTFS file system corruption
    on all partitions of the attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions.
    2. For each partition with a drive letter, queries the NTFS dirty bit using fsutil.
    3. If the dirty bit is set, runs chkdsk /f to repair file system errors.
    4. Logs full chkdsk output to the log file; only shows key summary lines
       (result, errors/fixes, disk space) in stdout to avoid log truncation.

    This resolves VMs stuck at boot showing "Scanning and repairing drive" or
    "Checking file system on C:" messages. Running chkdsk from a rescue VM avoids
    interruptions that occur when the OS runs it during boot.

.NOTES
    Name:    win-chkdsk-fs-corruption.ps1
    Version: 1.1
    Author:  Tony.Mocanu@Microsoft.com

.VERSION
    v1.1: [May 2026] - Updated the script again (current)
                       - Fixed breaking exception when the Hyper-V module is not installed on the host.
                       - Added explicit checking via Get-Module before executing nested VM discovery.
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v1.0: Initial commit. This was the version 1.0 of the script.

.LINK
    https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error

.SCENARIO_RECREATION
    To recreate a testable dirty-bit scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Set the dirty bit on the attached partition (replace F with actual drive letter):
fsutil dirty set F:
    3. Verify the dirty bit is set:
fsutil dirty query F:
    Expected: "Volume - F: is Dirty"
    4. Run the script. It should detect the dirty bit and run chkdsk /f.
    5. After the script completes, verify the dirty bit was cleared:
fsutil dirty query F:
    Expected: "Volume - F: is NOT Dirty"

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-chkdsk-fs-corruption --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\chkdsk-repair_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "All partitions processed successfully." and return code 0 ($STATUS_SUCCESS).
    2. Verify the dirty bit was cleared on the attached disk (replace F with the disk letter):
fsutil dirty query F:
    Expected: "Volume - F: is NOT Dirty"
#>

# Initialization
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

# Log Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\chkdsk-repair_$timestamp.log"

# Status Tracking
$script_final_status = $STATUS_SUCCESS

try {
    Log-Info "Script execution started. Report: $logFile"

    # Stop nested guest VM if running (only when Hyper-V module/cmdlets are available)
    $hyperVModuleAvailable = @(Get-Module -ListAvailable -Name 'Hyper-V').Count -gt 0
    if ($hyperVModuleAvailable -and (Get-Command -Name 'Get-VM' -ErrorAction SilentlyContinue)) {
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
    }
    else {
        Log-Info "Hyper-V module/cmdlets not available on this host -> skipping nested VM discovery"
    }

    # Step 1 - Enumerate attached partitions
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''

    if ($null -eq $partitionlist -or $partitionlist.Count -eq 0) {
        Log-Warning "No partitions found to check."
    }
    else {
        foreach ($partition in $partitionlist) {
            if ($partition -and $partition.DriveLetter) {
                # Skip the rescue VM's own OS drive
                if ($partition.DriveLetter -eq $rescueDrive) {
                    Log-Info "Skipping rescue VM system drive $rescueDrive (own OS)"
                    continue
                }

                $letter = $partition.DriveLetter
                if ($letter -notmatch ":") { $letter = "$letter" + ":" }
                
                Log-Info "Checking drive: $letter"
                
                # Step 2 - Query the NTFS dirty bit using fsutil
                $dirtyFlag = fsutil dirty query $letter
                Log-Output "FSUTIL Output: $dirtyFlag"

                # Step 3 - If dirty bit is set, run chkdsk /f to repair file system errors
                if ($dirtyFlag -notmatch "NOT Dirty") {
                    Log-Warning "$letter dirty bit set -> running chkdsk /f"
                    
                    # Capture all chkdsk output
                    $chkdskResults = chkdsk $letter /f 2>&1

                    # Write full output to log file only (not stdout) for detailed review
                    foreach ($line in $chkdskResults) {
                        $str = $line.ToString()
                        if ($str.Trim()) {
                            Add-Content -Path $logFile -Value $str
                        }
                    }

                    # Extract only the key summary lines for stdout
                    # Keep: result lines, error/fix lines, and the final disk space summary block
                    $summaryLines = @()
                    $inSummary = $false
                    foreach ($line in $chkdskResults) {
                        $str = $line.ToString().Trim()
                        if (-not $str) { continue }
                        # Start capturing disk space summary at "total disk space"
                        if ($str -match 'total disk space') { $inSummary = $true }
                        if ($inSummary) {
                            $summaryLines += $str
                            continue
                        }
                        # Keep important result/action lines, skip verbose progress
                        if ($str -match '(no problems|correcting|replacing|deleting|recovering|inserting|truncating|adjusting|resetting|Windows has|No further action|Cleaning up|could not fix|Errors detected|corrupt|found no)') {
                            $summaryLines += $str
                        }
                    }

                    foreach ($sl in $summaryLines) {
                        Log-Output $sl
                    }
                }
                else {
                    Log-Info "$letter dirty bit not set -> skipping"
                }
            }
        }
    }
    Log-Info "All partitions processed successfully."
}
catch {
    Log-Error "An error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)"
}

# THE FIX: Return must be outside the try/catch/finally blocks
return $script_final_status
