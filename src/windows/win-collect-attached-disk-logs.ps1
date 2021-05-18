#########################################################################################################
<#
# .SYNOPSIS
#   Collect Windows OS logs from an OS disk attached to a Rescue VM as an Azure Data Disk.
#
# .DESCRIPTION
#   Azure support can normally collect relevant OS logs from an Azure VM by running one of the following:
#       - C:\WindowsAzure\GuestAgent_2.7.41491.<VERSION>\CollectGuestLogs.exe
#       - C:\WindowsAzure\Packages\CollectGuestLogs.exe
#       - invoke-expression (get-childitem -Path c:\windowsazure -Filter CollectGuestLogs.exe -Recurse 
			| sort LastAccessTime -desc | select -first 1).FullName       
#   This will generate a zipped archive of the relevant guest logs. However, this cannot be used if the
#   guest OS is inaccessible (e.g. refusing to boot) or the package is missing. The alternative way to 
#   grab the logs in this situation is to clone the OS disk of the problem VM and attach the clone to a
#   Rescue VM, where we can manually grab the relevant logs. This script helps this process by using 
#   PowerShell to automate the log collection process from an OS disk attached as a data disk to a Rescue 
#	VM. These logs are saved as an archive on the desktop and can then be grabbed from the Rescue VM for analysis.
#
#   https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows#windows-guest-agent-automatic-logs-collection
#   https://docs.microsoft.com/en-us/cli/azure/vm/repair?view=azure-cli-latest
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-collect-attached-disk-logs --verbose --run-on-repair
#>
#########################################################################################################

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1
Log-Output "START: Running script win-collect-attached-disk-logs"

try {
	# Declaring variables    
	$desktopFolderPath = "$env:PUBLIC\Desktop\"
	$logFolderName = "CaseLogs"
	$scriptStartTime = get-date
	$scriptStartTimeUTC = ($scriptStartTime).ToUniversalTime() | ForEach-Object { $_ -replace ":", "." } | ForEach-Object { $_ -replace "/", "-" } | ForEach-Object { $_ -replace " ", "_" }
	$collectedLogArray = @()
	
	#Download GitHub files from https://github.com/Azure/azure-diskinspect-service/tree/master/pyServer/manifests/windows
	$urls = @(
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/windowsupdate"    
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/diagnostic"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/agents"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/aks"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/asc-vmhealth"    
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/eg"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/genspec"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/min-diagnostic"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/monitor-mgmt"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/normal"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/servicefabric"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/site-recovery"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/sql-iaas"    
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/pyServer/manifests/windows/workloadbackup"
	)
	$githubContent = @()

	ForEach ( $url in $urls) {
		try {
			$githubContent += (New-Object System.Net.WebClient).DownloadString($url).Split([Environment]::NewLine)
			Log-Output "Grabbed $($url)"
		}
		catch {        
			Log-Warning "Error for $($url)"
		}    
	}

	# Clean up array for parsing
	$removeDuplicates = $githubContent | Select-Object -uniq
	$removeKeywords = $removeDuplicates | ForEach-Object { $_ -replace "copy,", "" } | ForEach-Object { $_ -replace "diskinfo,", "" } | ForEach-Object { $_ -replace ",noscan", "" } | ForEach-Object { $_ -replace "ll,", "" }
	$logArray = $removeKeywords | Where-Object { $_ -notmatch "/Boot/BCD" } | Where-Object { $_ -notmatch "echo," }  | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object { $_.length }

	# Make sure the disk is online
	Log-Output "#01 - Bringing disk online"
	$disk = get-disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
	$disk | set-disk -IsOffline $false -ErrorAction Stop

	# Handle disk partitions
	$partitionlist = Get-Disk-Partitions
	$partitionGroup = $partitionlist | Group-Object DiskNumber

	Log-Output "#02 - Enumerate partitions for boot config"

	forEach ( $partitionGroup in $partitionlist | Group-Object DiskNumber ) {
		# Reset paths for each part group (disk)
		$isBcdPath = $false
		$bcdPath = ''
		$isOsPath = $false
		$osPath = ''

		# Scan all partitions of a disk for bcd store and os file location 
		ForEach ($drive in $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter ) {      
			# Check if no bcd store was found on the previous partition already
			if ( -not $isBcdPath ) {
				$bcdPath = $drive + ':\boot\bcd'
				$isBcdPath = Test-Path $bcdPath

				# If no bcd was found yet at the default location look for the uefi location too
				if ( -not $isBcdPath ) {
					$bcdPath = $drive + ':\efi\microsoft\boot\bcd'
					$isBcdPath = Test-Path $bcdPath
				} 
			}        

			# Check if os loader was found on the previous partition already
			if (-not $isOsPath) {
				$osPath = $drive + ':\windows\system32\winload.exe'
				$isOsPath = Test-Path $osPath
			}
		}
	
		# Create or get CaseLogs folder on desktop
		if (Test-Path "$($desktopFolderPath)$($logFolderName)") {
			$folder = Get-Item -Path "$($desktopFolderPath)$($logFolderName)"
			Log-Output "#03 - Grabbing folder $($folder)"
		}
		else {
			$folder = New-Item -Path $desktopFolderPath -Name $logFolderName -ItemType "directory"
			Log-Output "#03 - Creating folder $($folder)"
		}

		# Create subfolder named after the current time in UTC
		$subFolder = New-Item -Path $folder.ToString() -Name "$($scriptStartTimeUTC)_UTC" -ItemType "directory"

		# Create log files indicating files successfully and unsuccessfully grabbed by script
		$logFile = "$subfolder\collectedLogFiles.log"
		$failedLogFile = "$subfolder\failedLogFiles.log"

		# If Boot partition found grab bcd store
		if ( $isBcdPath ) {
			$bcdParentFolderName = $bcdPath.Split("\")[-2]
			$bcdFileName = $bcdPath.Split("\")[-1]

			if (Test-Path "$($subFolder.ToString())\$($bcdParentFolderName)") {
				$folder = Get-Item -Path "$($subFolder.ToString())\$($bcdParentFolderName)"
			}
			else {
				$folder = New-Item -Path $subFolder -Name $bcdParentFolderName -ItemType "directory"
			}

			Log-Output "#04 - Copy $($bcdFileName) to $($subFolder.ToString())"
			Copy-Item -Path $bcdPath -Destination "$($folder)\$($bcdFileName)" -Recurse
			$bcdPath | out-file -FilePath $logFile -Append
		}
		else {
			Log-Warning "#04 - Cannot grab $($bcdFileName), make sure disk is attached and partition is online"
			"NOT FOUND: $($bcdFileName)" | out-file -FilePath $failedLogFile -Append
		}
	
		# If Windows partition found grab log files
		if ( $isOsPath ) {
			foreach ($logName in $logArray) {
				$logLocation = "$($drive):$($logName)"; 

				# Confirm file exists
				if (Test-Path $logLocation) {                    
					$itemToCopy = Get-ChildItem $logLocation -Force                    
					foreach ($collectedLog in $itemToCopy) {
						$collectedLogArray += $collectedLog.FullName
					}                                                 
				}
				else {
					"NOT FOUND: $($logLocation)" | out-file -FilePath $failedLogFile -Append
				}
			}

			Log-Output "#05 - Copy Windows OS logs to $($subFolder.ToString())"
			# Copy verified logs to subfolder on Rescue VM desktop
			$collectedLogArray | ForEach-Object {				
				# Retain directory structure while replacing partition letter
				$split = $_ -split '\\'
				$DestFile = $split[1..($split.Length - 1)] -join '\' 
				$DestFile = "$subFolder\$DestFile"
					
				# Confirm if current log is a file or folder prior to copying       
				if (Test-Path -Path $_ -PathType Leaf) {
					$logType = "File";
					$temp = New-Item -Path $DestFile -Type $logType -Force
					Copy-Item -Path $_ -Destination $DestFile
				}
				elseif (Test-Path -Path $_ -PathType Container) {
					$logType = "Directory";
					Copy-Item -Path $_ -Destination $DestFile -Recurse
				}           
				$_ | out-file -FilePath $logFile -Append
			}
		}   
		else {
			Log-Error "END: Can't grab Windows OS logs, make sure disk is attached and partition is online"
			$logArray | ForEach-Object { "NOT FOUND: $($_)" } | out-file -FilePath $failedLogFile -Append
			return $STATUS_ERROR
		}
	}

	# Zip files
	Log-Output "#06 - Creating zipped archive $($subFolder.Name).zip"
	$compress = @{
		Path             = $subFolder
		CompressionLevel = "Fastest"
		DestinationPath  = "$($desktopFolderPath)\$($subFolder.Name).zip"
	}
	Compress-Archive @compress
	Log-Output "END: Please collect zipped log file $($desktopFolderPath)\$($subFolder.Name).zip from Rescue VM desktop"
	return $STATUS_SUCCESS
}

# Log failure scenario
catch {
	Log-Error "END: Script failed on $($logLocation)"   
	throw $_ 
	return $STATUS_ERROR
}