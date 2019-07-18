. .\src\windows\common\helpers\Get-Disk-Partition.ps1

$partitionlist = Get-Disk-Partitions
Write-Output $partitionlist

forEach ( $partition in $partitionlist )
{
    $driveLetter = ($partition.DriveLetter + ":")
    $dirtyFlag = fsutil dirty query $driveLetter
    If ($dirtyFlag -notmatch "NOT Dirty")
    {
        Write-Output '02 - ' + $driveLetter + ' dirty bit set  -> running chkdsk'
        chkdsk $driveLetter /f
    }
    else
    {
        Write-Output '02 - ' + $driveLetter + ' dirty bit not set  -> skipping chkdsk'
    }
}

return 0