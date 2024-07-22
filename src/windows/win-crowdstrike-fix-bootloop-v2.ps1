. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

$partitionlist = Get-Disk-Partitions
$actionTaken = $false

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
    if ($currentBuild -ge 14393) 
    {
        Log-Info "Trying to Delete regtrans-ms and txr.blf files under config\TxR..."
        $regtransmsFiles = "$DriveLetter\Windows\system32\config\TxR\*.TxR.*.regtrans-ms"
        try 
        {
            Remove-Item $regtransmsFiles  -ErrorAction Stop
             Log-Info "regtrans-ms files under config\TxR removed"
        }
        catch 
        {
            Log-Error "Remove regtrans-ms files under config\TxR failed: Error: $_"
        }

        $txrBlfFiles = "$DriveLetter\Windows\system32\config\TxR\*.TxR.blf"
        try 
        {
            Remove-Item $txrBlfFiles  -ErrorAction Stop
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

                if ($regKey -eq "HKLM\temp_software_hive_$guidSuffix") {
                    CleanUpRegtransmsAndTxrblfFiles -GuidSuffix $guidSuffix -DriveLetter $driveLetter
                }

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