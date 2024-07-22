function Get-Disk-Partitions()
{
	$partitionlist = @()
	$disklist = get-wmiobject Win32_diskdrive |Where-Object {$_.model -like 'Microsoft Virtual Disk'} 
	ForEach ($disk in $disklist)
	{
		$diskID = $disk.index
		$command = @"
		select disk $diskID
		online disk noerr
"@
		$command | diskpart | out-null

		$partitionlist += Get-Partition -DiskNumber $diskID
	}
	return $partitionlist
}
