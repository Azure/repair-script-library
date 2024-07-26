. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1


# Check if corrupt CrowdStrike files exist in each drive letter
# Remove any corrupt CrowdStrike files
function RemoveCrowdStrikeFiles
{
    param(
    [Parameter(Mandatory = $true)]
        [Object[]]$Partitionlist
    )

    Log-Info "Removing any corrupt crowdstrike files..."
    $crowdStrikeFileRemoved = $false
    forEach ( $partition in $partitionlist )
    {
        $driveLetter = $partition.DriveLetter
        if ($driveLetter) { # Skip partitions without drive letter
            $driveLetter = ($driveLetter + ":")
            Log-Info "Check Drive letter: $driveLetter"
            $corruptFiles = "$driveLetter\Windows\System32\drivers\CrowdStrike\C-00000291*.sys"

            if (Test-Path -Path $corruptFiles) {
                Log-Info "Found crowdstrike files to cleanup at $corruptFiles, removing..."
                Remove-Item $corruptFiles
                Log-Info "Corrupt crowdstrike files are removed."
                $crowdStrikeFileRemoved = $true
            }
        }
    }

    if ($crowdStrikeFileRemoved) {
        Log-Info "Successfully cleaned up crowdstrike files"
    } else {
        Log-Warning "No bad crowdstrike files found"
    }
}

# Check if registry config files exist in each non system drive letter.
# if registry config files exist in the non system drive letter, load it to the registry hive and then unload it.
function LoadUnloadRegistryHives
{
    param(
    [Parameter(Mandatory = $true)]
        [Object[]]$Partitionlist
    )
    Log-Info "Loading/unloading Registry Hives from registry config files..."

    # System Drive (which is usually C:) should be skipped as it is from the OS disk rather than the Data disk
    Log-Info "Getting system drive..."
    $systemDrive = $Env:SYSTEMDRIVE
    Log-Info "System drive is: $systemDrive"

    $registryConfigFileFound = $false
    forEach ( $partition in $partitionlist )
    {
        $driveLetter = $partition.DriveLetter
        if ($driveLetter) { # Skip partitions without drive letter
            $driveLetter = ($driveLetter + ":")
            Log-Info "Check Drive letter: $driveLetter"
            if ($driveLetter -ne $systemDrive) { # Skip OS disk
                Log-Info "Found non system drive: $driveLetter"

                Log-Info "Checking if registry config files exist from $driveLetter ..."
                $configExistInDrive = $false
                $guidSuffix = "f85afa50-13cc-48e0-8a29-90603a43cfe1" # get a guid online as the reg key suffix in case the reg key name already exist
                $regKeyToFile = @{
                    "HKLM\temp_system_hive_$guidSuffix" = "$driveLetter\windows\system32\config\system"
                    "HKLM\temp_software_hive_$guidSuffix" = "$driveLetter\windows\system32\config\software"
                }

                foreach ($regKey in $regKeyToFile.Keys)
                {
                    $regFile = $regKeyToFile[$regKey]
                    if (Test-Path -Path $regFile) {
                        Log-Info "Found registry config file at $regFile."
                        $configExistInDrive = $true

                        Log-Info "Loading registry hive $regKey from $regFile..."
                        $succeeded = $false
                        $result = reg load $regKey $regFile 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            Log-Error "Load registry hive $regKey from $regFile failed with exit code $LASTEXITCODE. Error: $result"
                            if ($result -Match "corrupt") {
                                try {
                                    FixRegistryCorruptions -RegFile $regFile
                                    Log-Info "Corrupt registry config file $regFile fixed, loading registry hive one more time..."
                                    $result = reg load $regKey $regFile 2>&1
                                    if ($LASTEXITCODE -ne 0) {
                                        Log-Error "Load registry hive $regKey from $regFile after ChkReg fix failed with exit code $LASTEXITCODE. Error: $result"
                                    }
                                    else {
                                        Log-Info "Load registry hive $regKey from $regFile after ChkReg fix succeeded with message: $result"
                                        $succeeded = $true
                                    }
                                }
                                catch {
                                    Log-Error "$_"
                                }                                
                            } 
                        } 
                        else {
                            Log-Info "Load registry hive $regKey from $regFile succeeded with message: $result"
                            $succeeded = $true
                        }
                        
                        if ($succeeded) {
                            if ($regKey -eq "HKLM\temp_software_hive_$guidSuffix") {
                                # Delete regtrans-ms and txr.blf files under config\TxR for Windows Server 2016 or newer version
                                CleanUpRegtransmsAndTxrblfFiles -GuidSuffix $guidSuffix -DriveLetter $driveLetter
                            }
    
                            Log-Info "Unloading registry hive $regKey..."
                            $result = reg unload $regKey 2>&1
                            if ($LASTEXITCODE -ne 0) {
                                Log-Error "Unload registry hive $regKey failed with exit code $LASTEXITCODE. Error: $result"
                            } else {
                                Log-Info "Unload registry hive $regKey succeeded with message: $result"
                            }
                        }

                        $registryConfigFileFound = $true
                    }
                }
                if (!$configExistInDrive) {
                    Log-Info "Registry config files don't exist from $driveLetter"
                }
            }  
            else {
                Log-Info "Skip system drive: $driveLetter"
            }
        }
    }

    if ($registryConfigFileFound) {
        Log-Info "Registry Hives load/unload: done"
    } else {
        Log-Warning "No registry config files found"
    }
}

# Delete regtrans-ms and txr.blf files under config\TxR for Windows Server 2016 or newer version
function CleanUpRegtransmsAndTxrblfFiles 
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$GuidSuffix,
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    Log-Info "Deleting regtrans-ms and txr.blf files under config\TxR for Windows Server 2016 or newer version..."
    Log-Info "Checking Windows Build number..."
    $regKey = "HKLM:\temp_software_hive_$GuidSuffix\Microsoft\Windows NT\CurrentVersion"
    $currentBuild = (Get-ItemProperty $regKey -Name CurrentBuild).CurrentBuild
    Log-Info "CurrentBuild: $currentBuild"
    if ($null -eq $currentBuild) {
        Log-Error "Failed to retrieve the Build Number of the Windows System from the mounted data disk"
        return
    }

    # On Server 2016 and newer, we know that the logs will never replay their changes successfully and so their contents aren't useful.
    # We can safely remove these files in this case.
    if ($currentBuild -ge 14393) # 14393 is the build number of Windows 2016. 
    {
        Log-Info "Trying to Delete regtrans-ms and txr.blf files under config\TxR..."
        $regtransmsFiles = "$DriveLetter\Windows\system32\config\TxR\*.TxR.*.regtrans-ms"
        try 
        {
            Remove-Item $regtransmsFiles  -ErrorAction Stop -Force
             Log-Info "regtrans-ms files under config\TxR removed"
        }
        catch 
        {
            Log-Error "Remove regtrans-ms files under config\TxR failed: Error: $_"
        }

        $txrBlfFiles = "$DriveLetter\Windows\system32\config\TxR\*.TxR.blf"
        try 
        {
            Remove-Item $txrBlfFiles  -ErrorAction Stop -Force
            Log-Info "txr.blf files under config\TxR removed"
        }
        catch 
        {
            Log-Error "Remove txr.blf files under config\TxR failed: Error: $_"
        } 
    } 
    else 
    {
        Log-Info "Skip deleting regtrans-ms and txr.blf files under config\TxR"
    }
}

function FixRegistryCorruptions
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegFile
    )
    Log-Info "Attempting to backup the original registry config file and fix registry config file with chkreg.exe..."
    Log-Info "Making a backup of the original registry config file..."
    $timestamp = Get-Date -Format "yyyyMMddTHHmmssffffZ"
    $copySucceeded = $false
    try {
        $backupFileName = "$RegFile.backup-$timestamp"
        Copy-Item $RegFile -Destination $backupFileName -ErrorAction Stop
        Log-Info "Original registry config file $RegFile is backed up at $backupFileName"
        $regFileLog1 = "$RegFile.LOG1"
        $regFileLog1Backup = "$regFileLog1.backup-$timestamp"
        if (Test-Path $regFileLog1) {
            Copy-Item $regFileLog1 -Destination $regFileLog1Backup -ErrorAction Stop
            Log-Info "Original registry config file $regFileLog1 is backed up at $regFileLog1Backup"
        }
        $regFileLog2 = "$RegFile.LOG2"
        $regFileLog2Backup = "$regFileLog2.backup-$timestamp"
        if (Test-Path $regFileLog2) {
            Copy-Item $regFileLog2 -Destination $regFileLog2Backup -ErrorAction Stop
            Log-Info "Original registry config file $regFileLog2 is backed up at $regFileLog2Backup"
        }
        $copySucceeded = $true
    } 
    catch {
        Log-Error "Copy $RegFile and related files failed: Error: $_"
    }

    if ($copySucceeded) {
        Log-Info "Start fixing registry config file with chkreg.exe as original config file backup succeeded..."
        $result = cmd /c $PSScriptRoot\common\tools\chkreg.exe /F $RegFile /R `2>`&1
        if ($LASTEXITCODE -ne 0) {
            Log-Error "chkreg.exe execution on $RegFile failed with error code: $LASTEXITCODE. Error: $result"
            throw "chkreg.exe execution on $RegFile failed with error code: $LASTEXITCODE. Error: $result"
        }
        else {
            Log-Info "chkreg.exe execution on $RegFile succeeded with message: $result"
        }
    } 
    else {
         Log-Error "Fixing registry config file with chkreg.exe is skipped as original config file backup failed"
         throw "Fixing registry config file with chkreg.exe is skipped as original config file backup failed"
    }
}

$partitionlist = Get-Disk-Partitions
$driveLetters = $partitionlist.DriveLetter
Log-Info "Found drive letters: $driveLetters"

RemoveCrowdStrikeFiles -Partitionlist $partitionlist
LoadUnloadRegistryHives -Partitionlist $partitionlist


return $STATUS_SUCCESS