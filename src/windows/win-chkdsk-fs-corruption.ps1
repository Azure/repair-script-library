# .SUMMARY
#   Runs chkdsk to fix file system corruption.
#   Checks if dirty bit has been set and if so, runs a chkdsk.exe on the attached disk.
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error
# 
# .RESOLVES
#   A Windows VM doesn't start. When you check the boot screenshots in Boot diagnostics, you see that the Check Disk process (chkdsk.exe)
#   is running with one of the following messages: 1. Scanning and repairing drive (C:) , 2. Checking file system on C: .
#   If an NTFS error is found in the file system, the dirty bit will set and the disk check application will run to try and fix any corruption. Running it from a rescue VM helps prevent interruptions.

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
