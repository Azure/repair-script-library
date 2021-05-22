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
#	https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/iaas-logs
#   https://docs.microsoft.com/en-us/cli/azure/vm/repair?view=azure-cli-latest
#
# 	Update (May 2021): This script can now work with neighbor VMs on the same network by mapping their drives 
#	to the target VM. However, there are a few caveats:
#		- Does not return the Registry hives because the mapped VMs are still operational. 
#		- If logs are being written to while the script is running and copying them over to the Rescue VM,
			the copied log file may be corrupted. You can try re-running the script or copying the corrupted log
			file manually. 
		- Skips copy of logs if the resulting log has a name too long for Windows to handle.
#
# .PARAMETER fileShareLetter
#   If using a mapped drive, select an available letter for your mapped drive.
# .PARAMETER fileSharePath 
#   If using a mapped drive, enter the private IP address and drive name in UNC format.
# .PARAMETER username
#   If using a mapped drive, enter the username of an account with credentials to access the remote computer.
# .PARAMETER password
#   If using a mapped drive, enter the matching password of an account with credentials to access the remote computer.
#
# .EXAMPLE
#	Copy logs from OS disk attached to Rescue VM as a data disk
#   az vm repair run -g sourceRG -n sourceVM --run-id win-collect-attached-disk-logs --verbose --run-on-repair
#
#	Copy logs from a drive mapped to the Rescue VM as a network drive using the Private IP
#   az vm repair run -g sourceRG -n sourceVM --run-id win-collect-attached-disk-logs --parameters fileShareLetter=Z fileSharePath="\\10.0.0.5\c$" username=azureadmin password=pa$$w0rd!1
#>
#########################################################################################################

# Set the Parameters for the script
Param(
	[Parameter(Mandatory = $false)][string]$fileShareLetter,
	[Parameter(Mandatory = $false)][string]$fileSharePath,
	[Parameter(Mandatory = $false)][string]$username,
	[Parameter(Mandatory = $false)][SecureString]$password
)

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
	$githubContent = @()
	
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
	$logArray = $removeKeywords | Where-Object { $_ -notmatch "/Boot/BCD" } | Where-Object { $_ -notmatch "echo," }  | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object

	# Make sure the disk is online
	Log-Output "#01 - Bringing partition(s) online if present"
	$disk = get-disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
	$disk | set-disk -IsOffline $false -ErrorAction SilentlyContinue
	
	# Handle disk partitions
	$partitionlist = Get-Disk-Partitions
	$partitionGroup = $partitionlist | Group-Object DiskNumber
	$driveLetters = @()
	$fixedDrives = $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter
	# $mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -ne $null } | Select-Object -ExpandProperty Name
	# $mappedDrives = Get-SmbMapping | Select-Object -ExpandProperty "LocalPath" | ForEach-Object { $_ -replace ":", "" }
	# $mappedDrives = Get-CimInstance -Class Win32_NetworkConnection | Select-Object -ExpandProperty "LocalName" | ForEach-Object { $_ -replace ":", "" }

	if ($fileShareLetter -and $fileSharePath -and $username -and $password) {
		# Configure TLS 1.2 security protocol key
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		# Install package and module necessary to work with az vm script
		# More info: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/run-command#restrictions
		# https://github.com/mkellerman/Invoke-CommandAs
		Install-PackageProvider -name NuGet -MinimumVersion 2.8.5.201 -Force
		Install-Module -Name Invoke-CommandAs -Force

		# Map network drive as SYSTEM	
		$ScriptBlock = [scriptblock]::Create("net use $($fileShareLetter): $($fileSharePath) /persistent:no /user:$($username) $($password)")
		Invoke-CommandAs -ScriptBlock $ScriptBlock -AsSystem
	}

	# Grab fileshares if mounted as System
	$mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -ne $null } | Select-Object -ExpandProperty Name

	# Log drive letters
	if ($fixedDrives) {
		Log-Output "Attached volumes: $($fixedDrives -join ", ")"
	}
	
	if ($mappedDrives) {
		Log-Output "Mapped drives: $($mappedDrives -join ", ")"
	}

	# Collect drive letters except for root drive of Rescue VM
	$driveLetters += $fixedDrives
	# Collect drive letters of mapped network drives
	$driveLetters += $mappedDrives
	
	# Create or get CaseLogs folder on desktop
	if (Test-Path "$($desktopFolderPath)$($logFolderName)") {
		$folder = Get-Item -Path "$($desktopFolderPath)$($logFolderName)"
		Log-Output "#02 - Grabbing folder $($folder) to store logs"
	}
	else {
		$folder = New-Item -Path $desktopFolderPath -Name $logFolderName -ItemType "directory"
		Log-Output "#02 - Creating folder $($folder) to store logs"
	}

	# Create subfolder named after the current time in UTC
	$timeFolder = New-Item -Path $folder.ToString() -Name "$($scriptStartTimeUTC)_UTC" -ItemType "directory"	
	
	Log-Output "#03 - Copy log files to $($timeFolder.ToString())"

	# Scan all collected partitions to determine if BCD or OS partition
	ForEach ($drive in $driveLetters ) {
		# Check if BCD store - Gen1
		$bcdPath = $drive + ':\boot\bcd'
		$isBcdPath = Test-Path $bcdPath
		
		# Not found? Check if BCD store - Gen2
		if ( -not $isBcdPath ) {
			$bcdPath = $drive + ':\efi\microsoft\boot\bcd'
			$isBcdPath = Test-Path $bcdPath
		}        
		
		# Check if partition is OS loader					
		$osPath = $drive + ':\windows\system32\winload.exe'
		$isOsPath = Test-Path $osPath
	
		# Create new subfolder with the current drive name
		$subFolder = New-Item -Path $timeFolder.ToString() -Name $drive -ItemType "directory"

		# Create log files indicating files successfully and unsuccessfully grabbed by script
		$logFile = "$timeFolder\collectedLogFiles.log"
		$failedLogFile = "$timeFolder\failedLogFiles.log"
		$treeFile = "$timeFolder\collectedLogFilesTree.log"

		# If Boot partition found grab BCD store
		if ( $isBcdPath ) {
			$bcdParentFolderName = "bcd" 
			$bcdFileName = $bcdPath.Split("\")[-1]

			if (Test-Path "$($subFolder.ToString())\$($bcdParentFolderName)") {
				$folder = Get-Item -Path "$($subFolder.ToString())\$($bcdParentFolderName)"
			}
			else {
				$folder = New-Item -Path $subFolder -Name $bcdParentFolderName -ItemType "directory"
			}

			Log-Output "Copy $($bcdPath) to $($subFolder.ToString())"
			Copy-Item -Path $bcdPath -Destination "$($folder)\$($bcdFileName)" -Recurse
			$bcdPath | out-file -FilePath $logFile -Append
		}
		else {
			Log-Warning "No BCD store on ($drive)"
		}
	
		# If Windows partition found grab log files
		if ( $isOsPath ) {
			foreach ($logName in $logArray) {
				$logLocation = "$($drive):$($logName)" 

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

			Log-Output "Copy Windows OS logs to $($subFolder.ToString())"
			# Copy verified logs to subfolder on Rescue VM desktop
			$collectedLogArray | ForEach-Object {				
				# Retain directory structure while replacing partition letter					
				try {
					$split = $_ -split '\\'
					$DestFile = $split[1..($split.Length - 1)] -join '\' 
					$DestFile = "$subFolder\$DestFile"
					# Confirm if current log is a file or folder prior to copying       
					if (Test-Path -Path $_ -PathType Leaf) {
						$logType = "File"
						$temp = New-Item -Path $DestFile -Type $logType -Force
						Copy-Item -Path $_ -Destination $DestFile -erroraction SilentlyContinue
					}
					elseif (Test-Path -Path $_ -PathType Container) {
						$logType = "Directory"
						Copy-Item -Path $_ -Destination $DestFile -Recurse -erroraction SilentlyContinue
					}           
					$_ | out-file -FilePath $logFile -Append
				}
				catch {
					$_.Exception | out-file -FilePath $failedLogFile -Append
				}
			}
		}   
		else {
			Log-Warning "No OS logs on ($drive)"
		}
	}

	# Include tree of subdirectory
	tree $timeFolder /f /a | out-file -FilePath $treeFile -Append

	# Zip files
	Log-Output "#04 - Creating zipped archive $($timeFolder.Name).zip"
	$compress = @{
		Path             = $timeFolder
		CompressionLevel = "Fastest"
		DestinationPath  = "$($desktopFolderPath)\$($timeFolder.Name).zip"
	}
	Compress-Archive @compress
	Log-Output "END: Please collect zipped log file $($desktopFolderPath)\$($timeFolder.Name).zip from Rescue VM desktop"
	return $STATUS_SUCCESS
}

# Log failure scenario
catch {
	Log-Error "END: Script failed $(if ($logLocation) { "at $($logLocation)" } )"   
	throw $_ 
	return $STATUS_ERROR
}