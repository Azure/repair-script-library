<#
.SYNOPSIS
    Modifies a registry value on an OS disk attached to a Rescue VM as a data disk.

.DESCRIPTION
    This script runs from a rescue VM to modify registry values on attached faulty OS disks.
    It performs the following steps:
    1. Stops any nested guest VM to ensure the attached disk is not in use.
    2. Brings the attached disk online and enumerates its partitions via Get-Disk-Partitions.
    3. Locates the Windows partition by checking for the registry config path (skips the rescue VM's own OS drive).
    4. Loads the specified registry hive from the attached disk (skips the partition if load fails).
    5. Determines the active ControlSet (if using the SYSTEM hive) from the Select key.
    6. Reads the current value of the specified registry property (if it exists).
    7. Creates the registry path if it does not exist, then sets the specified property value.
    8. Unloads the registry hive cleanly.

    This resolves non-boot issues caused by registry misconfiguration (e.g., enabling RDP,
    changing service startup type, disabling problematic drivers).

.NOTES
    Name:    win-update-registry.ps1
    Author:  Tony Mocanu / Tony.Mocanu@Microsoft.com

.VERSION
    v1.1: [May 2026] - Updated the script (current)
                       - Fixed Get-VM failure when Hyper-V module is not available on host.
                       - Added guarded nested VM validation with safe fallback logging.
                       - Added explicit runtime parameter validation for rootKey, propertyType, controlSet, and required inputs.
                       - Updated helper import to Get-Disk-Partitions-v2 and aligned partition processing flow.
                       - Added rescue OS drive exclusion to avoid modifying the running rescue VM hive.
                       - Added per-partition reg load failure handling (skip bad partition, continue others).
                       - Added structured step-by-step logging, timestamped CSE log output, and final status tracking.
                       - Improved error handling to continue processing partitions safely and report aggregate result.
    v1.0: Initial version

.LINK
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty

.SCENARIO_RECREATION
    To recreate a testable scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Load the SYSTEM hive from the attached disk (replace F with actual drive letter):
reg load HKLM\TESTBREAK F:\Windows\System32\config\SYSTEM
    3. Set a known registry value to a "broken" state, e.g. disable RDP:
Set-ItemProperty -Path "HKLM:\TESTBREAK\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections -Type DWord -Value 1
    4. Verify value is set to 1 (broken):
Get-ItemProperty -Path "HKLM:\TESTBREAK\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections
    5. Unload the hive:
reg unload HKLM\TESTBREAK
    6. Run the script with parameters to fix it (set fDenyTSConnections back to 0).
    7. Reload the hive and verify the value is now 0.

.EXAMPLE
    az vm repair run -g sourceRG -n problemVM --run-id win-update-registry --run-on-repair --parameters rootKey=HKLM hive=SYSTEM controlSet=1 relativePath='Control\Terminal` Server' propertyName=fDenyTSConnections propertyValue=0 propertyType=dword

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\update-registry_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "Successfully modified registry key" and return code 0 ($STATUS_SUCCESS).
    2. Manually reload the hive and confirm the value was written (replace F with the attached disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections
reg unload HKLM\VERIFY
    3. For local testing, uncomment the DEBUG variables block below the init section,
    set them to the desired test values, run the script, then re-comment before deploying.
#>

# Initialization (no Param() block to avoid ParserErrors and argument transformation failures)
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

# DEBUG: Uncomment below to test locally without --parameters
# $rootKey = 'HKLM'
# $hive = 'System'
# $controlSet = '1'
# $relativePath = 'Control\Terminal Server'
# $propertyName = 'fDenyTSConnections'
# $propertyValue = '1'
# $propertyType = 'dword'

# Parameter Validation (variables injected by az vm repair run --parameters)
if (-not $rootKey) { $rootKey = "HKLM" }
if (-not $hive) { $hive = "System" }
if (-not $propertyType) { $propertyType = "" }

$validRootKeys = @("HKLM", "HKCC", "HKCR", "HKCU", "HKU")
if ($rootKey -notin $validRootKeys) {
    Log-Error "Invalid rootKey '$rootKey'. Valid values: $($validRootKeys -join ', ')"
    return $STATUS_ERROR
}

$validPropertyTypes = @("", "String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")
if ($propertyType -notin $validPropertyTypes) {
    Log-Error "Invalid propertyType '$propertyType'. Valid values: $($validPropertyTypes -join ', ')"
    return $STATUS_ERROR
}

if ($controlSet) {
    if ($controlSet -notin @(1, 2)) {
        Log-Error "Invalid controlSet '$controlSet'. Valid values: 1, 2"
        return $STATUS_ERROR
    }
}

if ([string]::IsNullOrEmpty($relativePath)) {
    Log-Error "relativePath parameter is required."
    return $STATUS_ERROR
}

if ([string]::IsNullOrEmpty($propertyName)) {
    Log-Error "propertyName parameter is required."
    return $STATUS_ERROR
}

if ($null -eq $propertyValue) {
    Log-Error "propertyValue parameter is required."
    return $STATUS_ERROR
}

# Log Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\update-registry_$timestamp.log"

# Status Tracking
$script_final_status = $STATUS_ERROR

try {
    Log-Info "START: Running script win-update-registry.ps1" | Tee-Object -FilePath $logFile -Append
    Log-Info "Parameters: rootKey=$rootKey, hive=$hive, controlSet=$controlSet, relativePath=$relativePath, propertyName=$propertyName, propertyValue=$propertyValue, propertyType=$propertyType" | Tee-Object -FilePath $logFile -Append

    # Step 1 - Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Log-Info "Stopping nested guest VM $guestHyperVVirtualMachineName" | Tee-Object -FilePath $logFile -Append
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Log-Warning "Failed to stop nested guest VM $guestHyperVVirtualMachineName, will continue but may have limited success" | Tee-Object -FilePath $logFile -Append
                    }
                }
            }
            else {
                Log-Info "No running nested guest VM, continuing" | Tee-Object -FilePath $logFile -Append
            }
        }
        else {
            Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation." | Tee-Object -FilePath $logFile -Append
        }
    }
    catch {
        Log-Warning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # Step 2 - Bring the attached disk online and enumerate partitions via Get-Disk-Partitions
    $partitionlist = Get-Disk-Partitions

    if ($null -eq $partitionlist -or $partitionlist.Count -eq 0) {
        Log-Error "No partitions found on attached disk." | Tee-Object -FilePath $logFile -Append
        $script_final_status = $STATUS_ERROR
    }
    else {
        # Step 3 - Locate the Windows partition by checking for the registry config path
        Log-Info "Scanning partitions for Windows registry hives" | Tee-Object -FilePath $logFile -Append

        foreach ($partition in $partitionlist) {
            if (-not $partition -or -not $partition.DriveLetter) { continue }

            $drive = $partition.DriveLetter

            # Skip the rescue VM's own OS drive (its hives are locked by the running OS)
            $rescueDrive = $env:SystemDrive -replace ':', ''
            if ($drive -eq $rescueDrive) {
                Log-Info "Skipping rescue VM system drive $drive (own OS)" | Tee-Object -FilePath $logFile -Append
                continue
            }

            $regPath = $drive + ':\Windows\System32\config\'
            if (-not (Test-Path $regPath)) {
                Log-Info "No Registry found on $drive, skipping" | Tee-Object -FilePath $logFile -Append
                continue
            }

            # Step 4 - Load requested registry hive from attached disk
            Log-Info "Loading $hive hive from $($drive):" | Tee-Object -FilePath $logFile -Append
            $loadResult = cmd /c "reg load $($rootKey)\broken$($hive)$($drive) $($drive):\Windows\System32\config\$($hive)" 2>&1
            Log-Output "reg load result: $loadResult" | Tee-Object -FilePath $logFile -Append

            # If reg load failed, skip this partition entirely
            if ($loadResult -match 'ERROR') {
                Log-Warning "Failed to load $hive hive from $($drive), skipping partition: $loadResult" | Tee-Object -FilePath $logFile -Append
                continue
            }

            try {
                # Step 5 - Determine the active ControlSet if using the SYSTEM hive
                if ($hive -eq "system") {
                    Log-Info "Using a SYSTEM hive, determining Control Set" | Tee-Object -FilePath $logFile -Append
                    $controlSetText = "ControlSet00"
                    if (-not $controlSet -or $controlSet -eq "") {
                        $controlSet = (Get-ItemProperty -Path "$($rootKey):\broken$($hive)$($drive)\Select" -Name Current).Current
                    }
                    $controlSetText += $controlSet
                    Log-Info "Using $controlSetText" | Tee-Object -FilePath $logFile -Append
                    $controlSetText += "\"
                }
                else {
                    $controlSetText = ""
                    Log-Info "Not using a SYSTEM hive, targeting $hive directly" | Tee-Object -FilePath $logFile -Append
                }

                # Step 6 - Read current value of the specified property
                $propPath = "$($rootKey):\broken$($hive)$($drive)\$($controlSetText)$($relativePath)"
                Log-Info "Target registry path: $propPath" | Tee-Object -FilePath $logFile -Append
                $currentValue = Get-ItemProperty -Path $propPath -Name $propertyName -ErrorAction SilentlyContinue
                if ($currentValue) {
                    Log-Output "Current value of '$propertyName': $($currentValue.$propertyName)" | Tee-Object -FilePath $logFile -Append
                }
                else {
                    Log-Info "Property '$propertyName' not found at path (will be created)" | Tee-Object -FilePath $logFile -Append
                }

                # Step 7 - Create path if needed, then set the property value
                if ($propertyType -eq "") { $propertyType = "dword" }

                if (Test-Path $propPath) {
                    if (($propertyType -ne "") -and ($propertyType -ne "dword")) {
                        try {
                            $propertyType = (Get-Item -Path $propPath).getValueKind($propertyName)
                        }
                        catch {
                            Log-Warning "Unable to detect existing property type, using '$propertyType': $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
                        }
                    }
                }
                else {
                    Log-Info "Registry path does not exist, creating: $propPath" | Tee-Object -FilePath $logFile -Append
                    New-Item -Path $propPath -Force -ErrorAction Stop | Out-Null
                }

                $modifiedKey = Set-ItemProperty -Path $propPath -Name $propertyName -Type $propertyType -Value $propertyValue -Force -ErrorAction Stop -PassThru
                Log-Output "Successfully modified registry key" | Tee-Object -FilePath $logFile -Append
                Log-Output $modifiedKey | Tee-Object -FilePath $logFile -Append

                $script_final_status = $STATUS_SUCCESS
            }
            catch {
                Log-Error "Failed to modify registry hive on $($drive): $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
                $script_final_status = $STATUS_ERROR
            }
            finally {
                # Step 8 - Unload the registry hive cleanly
                Log-Info "Unloading registry hive from $($drive)" | Tee-Object -FilePath $logFile -Append
                [gc]::Collect()
                $unloadResult = cmd /c "reg unload $($rootKey)\broken$($hive)$($drive)" 2>&1
                Log-Output "reg unload result: $unloadResult" | Tee-Object -FilePath $logFile -Append
            }
        }

        if ($script_final_status -ne $STATUS_SUCCESS) {
            Log-Error "No registry modification was applied on any partition" | Tee-Object -FilePath $logFile -Append
        }
    }
}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}

return $script_final_status
