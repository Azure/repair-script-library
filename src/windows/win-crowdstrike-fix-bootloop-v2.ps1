. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

$partitionlist = Get-Disk-Partitions
$actionTaken = $false

forEach ( $partition in $partitionlist )
{
    $driveLetter = ($partition.DriveLetter + ":")
    $corruptFiles = "$driveLetter\Windows\System32\drivers\CrowdStrike\C-00000291*.sys"

    if (Test-Path -Path $corruptFiles) {
        Log-Info "Found crowdstrike files to cleanup, removing..."
        Remove-Item $corruptFiles
        Log-Info "Corrupt crowdstrike files are removed."

        Log-Info "Loading/unloading registry hives from data disk..."
        $guidSuffix = "f85afa50-13cc-48e0-8a29-90603a43cfe2" # get a guid online as the reg key suffix in case the reg key name already exist
        $regKeyToFile = @{
            "HKLM\temp_system_hive_$guidSuffix" = "$driverletter\windows\system32\config\system"
            "HKLM\temp_software_hive_$guidSuffix" = "$driverletter\windows\system32\config\software"
        }

        foreach ($regKey in $regKeyToFile.Keys)
        {
            $regFile = $regKeyToFile[$regKey]
            Log-Info "Loading registry hive $regKey from $regFile..."
            $result = reg load $regKey $regFile 2>&1
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Load registry hive $regKey from $regFile failed with error: $result"
            } else {
                Log-Info "Load registry hive $regKey from $regFile succeeded with message: $result"
                Log-Info "Unloading registry hive $regKey..."
                $result = reg unload $regKey 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Log-Error "Unload registry hive $regKey failed with error: $result"
                } else {
                    Log-Info "Unload registry hive $regKey succeeded with message: $result"
                }
            }
        }

        Log-Info "Registry hives load/unload: done."
        $actionTaken = $true
    }
}

if ($actionTaken) {
    Log-Info "Successfully cleaned up crowdstrike files and loaded/unloaded the registry hives"
} else {
    Log-Warning "No bad crowdstrike files found"
}

return $STATUS_SUCCESS