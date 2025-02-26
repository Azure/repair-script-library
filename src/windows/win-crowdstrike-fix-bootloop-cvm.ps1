<#
# .SUMMARY
#   Workaround for Confidential VM machines stuck in boot loop due to corrupt crowdstrike falcon sensor 2024-07-19 by removing corrupt crowdstrike files, 
#   loading/unloading the registry hives, and removing regtrans-ms and txr.blf files under config\TxR folder.
#   Check for the corrupt CrowdStrike driver file(s) C-00000291*.sys. If found, delete it. Load the registry hive to check for corruption and if corruption is found, fixes it.
# 
# .RESOLVES
#   Helps recover VMs stuck in a non-boot state due to the faulty CrowdStrike update from July 19th, 2024. This is specific for VMs that have encrypted OSDisk resources, 
#   such as Confidential VMs. 
#
# .PUBLIC DOCS
#   https://techcommunity.microsoft.com/blog/azurecompute/recovery-options-for-azure-virtual-machines-vm-affected-by-crowdstrike-falcon-ag/4196798
#>

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

$partitionlist = Get-Disk-Partitions
$actionTaken = $false

forEach ( $partition in $partitionlist )
{
    $driveLetter = ($partition.DriveLetter + ":")
    $corruptFiles = "$driveLetter\Windows\System32\drivers\CrowdStrike\C-00000291*.sys"

    if (Test-Path -Path $corruptFiles) {
        Log-Info "Found crowdstrike files to cleanup, removing..."
        Remove-Item $corruptFiles
        $actionTaken = $true
    }
}

if ($actionTaken) {
    Log-Info "Successfully cleaned up crowdstrike files"
} else {
    Log-Warning "No bad crowdstrike files found"
}

return $STATUS_SUCCESS
