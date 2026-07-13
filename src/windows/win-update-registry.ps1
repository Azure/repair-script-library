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

.PARAMETER rootKey
    Root registry hive for offline mount. Valid values: HKLM, HKCC, HKCR, HKCU, HKU.

.PARAMETER hive
    Offline hive file name under Windows\System32\config (for example: SYSTEM, SOFTWARE).

.PARAMETER controlSet
    Optional control set number for SYSTEM hive updates. Valid values: 1 or 2.
    If omitted for SYSTEM hive, the script uses Select\Current.

.PARAMETER relativePath
    Registry path relative to the loaded offline hive root.

.PARAMETER propertyName
    Registry property name to create or update.

.PARAMETER propertyValue
    Registry property value to write.

.PARAMETER propertyType
    Registry value type. Valid values: String, ExpandString, Binary, DWord, MultiString, Qword, Unknown.
    If omitted, defaults to DWord.

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
                       - Added structured step-by-step logging, timestamped desktop log output, and final status tracking.
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
Get-ChildItem "$([Environment]::GetFolderPath('Desktop'))\update-registry_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "Successfully modified registry key" and return code 0 ($STATUS_SUCCESS).
    2. Manually reload the hive and confirm the value was written (replace F with the attached disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Control\Terminal Server" -Name fDenyTSConnections
reg unload HKLM\VERIFY
    3. For local testing, uncomment the DEBUG variables block below the init section,
    set them to the desired test values, run the script, then re-comment before deploying.
#>

# Initialization (no Param() block to avoid ParserErrors and argument transformation failures)
$initPath = Join-Path $PSScriptRoot 'src\windows\common\setup\init.ps1'
$diskPartitionsHelperPath = Join-Path $PSScriptRoot 'src\windows\common\helpers\Get-Disk-Partitions-v2.ps1'

if (-not (Test-Path -LiteralPath $initPath)) {
    Write-Error "Missing required helper: $initPath"
    return 1
}

if (-not (Test-Path -LiteralPath $diskPartitionsHelperPath)) {
    Write-Error "Missing required helper: $diskPartitionsHelperPath"
    return 1
}

. $initPath
. $diskPartitionsHelperPath

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
$logDir = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($logDir) -or -not (Test-Path -LiteralPath $logDir)) {
    $logDir = 'C:\Users\Public\Desktop'
    if (-not (Test-Path -LiteralPath $logDir)) {
        $null = New-Item -ItemType Directory -Path $logDir -Force
    }
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\update-registry_$timestamp.log"

function Write-DesktopLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Message
    )

    $text = if ($null -eq $Message) { '' } else { ($Message | Out-String).TrimEnd() }
    $line = "$(Get-Date -Format o) [$Level] $text"
    Add-Content -Path $logFile -Value $line
}

function Write-InfoLog {
    param([string]$Message)
    Log-Info $Message
    Write-DesktopLog -Level 'INFO' -Message $Message
}

function Write-WarningLog {
    param([string]$Message)
    Log-Warning $Message
    Write-DesktopLog -Level 'WARN' -Message $Message
}

function Write-ErrorLog {
    param([string]$Message)
    Log-Error $Message
    Write-DesktopLog -Level 'ERROR' -Message $Message
}

function Write-OutputLog {
    param([AllowNull()]$Message)
    Log-Output $Message
    Write-DesktopLog -Level 'OUTPUT' -Message $Message
}

# Status Tracking
$script_final_status = $STATUS_ERROR

try {
    Write-InfoLog "START: Running script win-update-registry.ps1"
    Write-InfoLog "Log file path: $logFile"
    Write-InfoLog "Parameters: rootKey=$rootKey, hive=$hive, controlSet=$controlSet, relativePath=$relativePath, propertyName=$propertyName, propertyValue=$propertyValue, propertyType=$propertyType"

    $processedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $changedCount = 0

    # Step 1 - Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-InfoLog "Stopping nested guest VM $guestHyperVVirtualMachineName"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-WarningLog "Failed to stop nested guest VM $guestHyperVVirtualMachineName, will continue but may have limited success"
                    }
                }
            }
            else {
                Write-InfoLog "No running nested guest VM, continuing"
            }
        }
        else {
            Write-InfoLog "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-WarningLog "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Step 2 - Bring the attached disk online and enumerate partitions via Get-Disk-Partitions
    $partitionlist = Get-Disk-Partitions

    if ($null -eq $partitionlist -or $partitionlist.Count -eq 0) {
        Write-ErrorLog "No partitions found on attached disk."
        $script_final_status = $STATUS_ERROR
    }
    else {
        # Step 3 - Locate the Windows partition by checking for the registry config path
        Write-InfoLog "Scanning partitions for Windows registry hives"

        foreach ($partition in $partitionlist) {
            if (-not $partition -or -not $partition.DriveLetter) { continue }

            $drive = $partition.DriveLetter
            $processedCount++

            # Skip the rescue VM's own OS drive (its hives are locked by the running OS)
            $rescueDrive = $env:SystemDrive -replace ':', ''
            if ($drive -eq $rescueDrive) {
                Write-InfoLog "Skipping rescue VM system drive $drive (own OS)"
                $skippedCount++
                continue
            }

            $regPath = $drive + ':\Windows\System32\config\'
            if (-not (Test-Path $regPath)) {
                Write-InfoLog "No Registry found on $drive, skipping"
                $skippedCount++
                continue
            }

            # Step 4 - Load requested registry hive from attached disk
            Write-InfoLog "Loading $hive hive from $($drive):"
            $loadResult = & reg.exe load "$($rootKey)\broken$($hive)$($drive)" "$($drive):\Windows\System32\config\$($hive)" 2>&1 | Out-String
            $loadExitCode = $LASTEXITCODE
            Write-OutputLog "reg load exit code: $loadExitCode"
            Write-OutputLog "reg load output: $loadResult"

            # If reg load failed, skip this partition entirely
            if ($loadExitCode -ne 0) {
                Write-WarningLog "Failed to load $hive hive from $($drive), skipping partition"
                $failedCount++
                continue
            }

            $hiveSourcePath = "$($drive):\Windows\System32\config\$($hive)"
            $backupFile = Join-Path $logDir "backup-$hive-$drive-$timestamp.hiv"
            $restoreRequired = $false

            try {
                if (-not (Test-Path -LiteralPath $hiveSourcePath)) {
                    throw "Hive file not found for backup: $hiveSourcePath"
                }
                Copy-Item -LiteralPath $hiveSourcePath -Destination $backupFile -Force -ErrorAction Stop
                Write-InfoLog "Created hive backup before modification: $backupFile"

                # Step 5 - Determine the active ControlSet if using the SYSTEM hive
                if ($hive -eq "system") {
                    Write-InfoLog "Using a SYSTEM hive, determining Control Set"
                    $controlSetText = "ControlSet00"
                    if (-not $controlSet -or $controlSet -eq "") {
                        $controlSet = (Get-ItemProperty -Path "$($rootKey):\broken$($hive)$($drive)\Select" -Name Current).Current
                    }
                    $controlSetText += $controlSet
                    Write-InfoLog "Using $controlSetText"
                    $controlSetText += "\"
                }
                else {
                    $controlSetText = ""
                    Write-InfoLog "Not using a SYSTEM hive, targeting $hive directly"
                }

                # Step 6 - Read current value of the specified property
                $propPath = "$($rootKey):\broken$($hive)$($drive)\$($controlSetText)$($relativePath)"
                Write-InfoLog "Target registry path: $propPath"
                $currentValue = Get-ItemProperty -Path $propPath -Name $propertyName -ErrorAction SilentlyContinue
                if ($currentValue) {
                    Write-OutputLog "Current value of '$propertyName': $($currentValue.$propertyName)"
                }
                else {
                    Write-InfoLog "Property '$propertyName' not found at path (will be created)"
                }

                # Step 7 - Create path if needed, then set the property value
                if ($propertyType -eq "") { $propertyType = "dword" }

                if (Test-Path $propPath) {
                    if (($propertyType -ne "") -and ($propertyType -ne "dword")) {
                        try {
                            $propertyType = (Get-Item -Path $propPath).getValueKind($propertyName)
                        }
                        catch {
                            Write-WarningLog "Unable to detect existing property type, using '$propertyType': $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-InfoLog "Registry path does not exist, creating: $propPath"
                    New-Item -Path $propPath -Force -ErrorAction Stop | Out-Null
                }

                $modifiedKey = Set-ItemProperty -Path $propPath -Name $propertyName -Type $propertyType -Value $propertyValue -Force -ErrorAction Stop -PassThru
                Write-OutputLog "Successfully modified registry key"
                Write-OutputLog "Updated '$propertyName' to '$propertyValue' (type '$propertyType') at '$propPath'"
                Write-OutputLog $modifiedKey

                $script_final_status = $STATUS_SUCCESS
                $changedCount++
            }
            catch {
                Write-ErrorLog "Failed to modify registry hive on $($drive): $($_.Exception.Message)"
                Write-ErrorLog "Will attempt rollback from backup after unloading hive."
                $script_final_status = $STATUS_ERROR
                $failedCount++
                $restoreRequired = $true
            }
            finally {
                # Step 8 - Unload the registry hive cleanly
                Write-InfoLog "Unloading registry hive from $($drive)"
                $unloadSuccess = $false
                for ($attempt = 1; $attempt -le 3; $attempt++) {
                    [gc]::Collect()
                    $unloadResult = & reg.exe unload "$($rootKey)\broken$($hive)$($drive)" 2>&1 | Out-String
                    $unloadExitCode = $LASTEXITCODE
                    Write-OutputLog "reg unload attempt $attempt exit code: $unloadExitCode"
                    Write-OutputLog "reg unload attempt $attempt output: $unloadResult"

                    if ($unloadExitCode -eq 0) {
                        $unloadSuccess = $true
                        break
                    }

                    if ($attempt -lt 3) {
                        Write-WarningLog "Unload attempt $attempt failed for drive $drive. Retrying."
                    }
                }

                if (-not $unloadSuccess) {
                    Write-ErrorLog "Failed to unload hive after retries for drive $drive"
                    $failedCount++
                    $script_final_status = $STATUS_ERROR
                }

                if ($restoreRequired -and $backupFile) {
                    if ($unloadSuccess) {
                        try {
                            Copy-Item -LiteralPath $backupFile -Destination $hiveSourcePath -Force -ErrorAction Stop
                            Write-WarningLog "Rollback applied from backup: $backupFile"
                        }
                        catch {
                            Write-ErrorLog "Rollback failed for drive $drive using backup '$backupFile': $($_.Exception.Message)"
                            $script_final_status = $STATUS_ERROR
                        }
                    }
                    else {
                        Write-ErrorLog "Rollback skipped because hive unload did not succeed for drive $drive"
                    }
                }
            }
        }

        Write-InfoLog "Summary: processed=$processedCount skipped=$skippedCount failed=$failedCount changed=$changedCount"

        if ($script_final_status -ne $STATUS_SUCCESS) {
            Write-ErrorLog "No registry modification was applied on any partition"
        }
    }
}
catch {
    Write-ErrorLog "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    Write-InfoLog "Final status: $script_final_status"
    Write-InfoLog "Script ended at $(Get-Date)"
    Write-InfoLog "Log file path: $logFile"
}

return $script_final_status
