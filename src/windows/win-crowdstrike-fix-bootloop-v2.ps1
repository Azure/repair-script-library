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

        Log-Info "Load/unload registry hives from data disk..."

        $result = reg load HKLM\temp_system_hiv $driverletter\windows\system32\config\system
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Load registry hive from $driverletter\windows\system32\config\system failed with error: $result"
            return $STATUS_ERROR
        } else {
            Log-Info "Load registry hive from $driverletter\windows\system32\config\system succeeded: $result"
        }

        $result = reg unload HKLM\temp_system_hiv
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Unload registry hive HKLM\temp_system_hiv failed with error: $result"
            return $STATUS_ERROR
        } else {
            Log-Info "Unload registry hive HKLM\temp_system_hiv succeeded: $result"
        }
 
        $result = reg load HKLM\temp_software_hive $driverletter\windows\system32\config\software
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Load registry hive from $driverletter\windows\system32\config\software failed with error: $result"
            return $STATUS_ERROR
        } else {
            Log-Info "Load registry hive from $driverletter\windows\system32\config\software succeeded: $result"
        }

        $result = reg unload HKLM\temp_software_hive 
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Unload registry hive HKLM\temp_software_hive failed with error: $result"
            return $STATUS_ERROR
        } else {
            Log-Info "Unload registry hive HKLM\temp_software_hive succeeded: $result"
        }

        Log-Info "Registry hives load/unload: done."


        $actionTaken = $true
    }
}

if ($actionTaken) {
    Log-Info "Successfully cleaned up crowdstrike files"
} else {
    Log-Warning "No bad crowdstrike files found"
}

return $STATUS_SUCCESS