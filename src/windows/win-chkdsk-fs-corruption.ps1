. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

$partitionlist = Get-Disk-Partitions

forEach ( $partition in $partitionlist )
{
    $driveLetter = ($partition.DriveLetter + ":")
    $dirtyFlag = fsutil dirty query $driveLetter
    If ($dirtyFlag -notmatch "NOT Dirty")
    {
        Log-Info "02 - $driveLetter dirty bit set  -> running chkdsk"
        chkdsk $driveLetter /f
    }
    else
    {
        Log-Info "02 - $driveLetter dirty bit not set  -> skipping chkdsk"
    }
}

return $STATUS_SUCCESS