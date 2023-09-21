#########################################################################################################
<#
# .SYNOPSIS
#   Collect Windows OS logs from an OS disk attached to a Rescue VM as an Azure Data Disk. v0.6.0
#
# .DESCRIPTION
#   Azure support can normally collect relevant OS logs from an Azure VM by running one of the following:
#       - C:\WindowsAzure\GuestAgent_2.7.41491.<VERSION>\CollectGuestLogs.exe
#       - C:\WindowsAzure\Packages\CollectGuestLogs.exe
#       - invoke-expression (get-childitem -Path c:\windowsazure -Filter CollectGuestLogs.exe -Recurse 
#		| sort LastAccessTime -desc | select -first 1).FullName       
#   This will generate a zipped archive of the relevant guest logs. However, this cannot be used if the
#   guest OS is inaccessible (e.g. refusing to boot) or the package is missing. The alternative way to
#   grab the logs in this situation is to clone the OS disk of the problem VM and attach the clone to a
#   Rescue VM, where we can manually grab the relevant logs. This script helps this process by using
#   PowerShell to automate the log collection process from an OS disk attached as a data disk to a Rescue
#	VM. These logs are saved as an archive on the desktop and can then be grabbed from the Rescue VM for analysis.
#
#   https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows#windows-guest-agent-automatic-logs-collection
#   https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/iaas-logs
#   https://docs.microsoft.com/en-us/archive/blogs/kwill/windows-azure-paas-compute-diagnostics-data
#   https://docs.microsoft.com/en-us/cli/azure/vm/repair?view=azure-cli-latest
#
#	Update (Feb 2023): Added partition sizes.
#
#   Update (May 2021): This script can now work with neighbor VMs on the same network by mapping their drives
#   to the target VM. However, there are a few caveats:
#	- Does not return the Registry hives because the mapped VMs' hives are still operational.
#	- If logs are being written to while the script is running and copying them over to the Rescue VM,
#		the copied log file may be corrupted. You can try re-running the script or copying the corrupted log
#		file manually.
#	- Skips copy of logs if the resulting log has a name too long for Windows to handle.
#
# .EXAMPLE
#	<# Copy logs from OS disk attached to Rescue VM as a data disk #>
#   az vm repair run -g sourceRG -n sourceVM --run-id win-collect-attached-disk-logs --verbose --run-on-repair
#
# .EXAMPLE
#	<# Want to copy logs from a VM in the same subnet? Map a Windows OS drive to the Rescue VM as a network drive using the Private IP via "az vm run-command" #>
#	az vm run-command invoke --command-id RunPowerShellScript --name vm --resource-group rg --scripts "net use T: \\10.0.0.5\c$ /persistent:no /user:azureadmin MyPa$$w0rd!" --debug
#   az vm repair run -g sourceRG -n sourceVM --run-id win-collect-attached-disk-logs
#
# .NOTES
#   Author: Ryan McCallum
# 	Testing: Brought script to PowerShell ISE locally. Ran [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12; in session. Converted all "Log-" strings to "Write-", imported Get-Disk-Partitions.ps1 in same file and commented out lines initializing init.ps1 and Get-Disk-Partitions.ps1. Also ran custom-script version 'az vm repair run -g $rg -n $vmName   --run-on-repair --verbose --custom-script-file "C:\Users\rymccall\Github\repair-script-library\src\windows\win-collect-attached-disk-logs.ps1"'. Also ran Invoke-ScriptAnalyzer -Path .\win-collect-attached-disk-logs.ps1  to find recommended updates and Invoke-ScriptAnalyzer -Path .\win-collect-attached-disk-logs.ps1 -Fix to fix them. More info: https://docs.microsoft.com/en-us/powershell/module/psscriptanalyzer/invoke-scriptanalyzer?view=ps-modules
#>
#########################################################################################################

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Declare variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptPath = split-path -path $MyInvocation.MyCommand.Path -parent
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]

$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
$scriptStartTime | Tee-Object -FilePath $logFile -Append
Log-Output "START: Running script win-collect-attached-disk-logs" | Tee-Object -FilePath $logFile -Append

try {
	# Declaring variables
	$desktopFolderPath = "$env:PUBLIC\Desktop\"
	$logFolderName = "CaseLogs"
	$scriptStartTime = Get-Date
	$scriptStartTimeUTC = ($scriptStartTime).ToUniversalTime() | ForEach-Object { $_ -replace ":", "." } | ForEach-Object { $_ -replace "/", "-" } | ForEach-Object { $_ -replace " ", "_" }
	$collectedLogArray = @()
	$githubContent = @()
	$urls = @()
	$removeDuplicates = @()
	$removeKeywords = @()
	$logArray = @()
	$driveLetters = @()

	Log-Output "#01 - Collect log manifest files" | Tee-Object -FilePath $logFile -Append

	# Download Windows manifest files from Github
	# https://github.com/Azure/azure-diskinspect-service/tree/master/pyServer/manifests/windows
	$urls = @(
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/windowsupdate"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/diagnostic"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/asc-vmhealth"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/eg"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/genspec"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/normal"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/site-recovery"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/sql-iaas"
		"https://raw.githubusercontent.com/Azure/azure-diskinspect-service/master/manifests/windows/vmdiagnostic"
	)

	ForEach ( $url in $urls) {
		try {
			$githubContent += (New-Object System.Net.WebClient).DownloadString($url).Split([Environment]::NewLine)
			Log-Output "Grabbed $($url)" | Tee-Object -FilePath $logFile -Append
		}
		catch {
			Log-Warning "Error for $($url)" | Tee-Object -FilePath $logFile -Append
		}
	}

	# Clean up array for parsing
	$removeDuplicates = $githubContent | Select-Object -uniq
	$removeKeywords = $removeDuplicates | ForEach-Object { $_ -replace "copy,", "" } | ForEach-Object { $_ -replace "diskinfo,", "" } | ForEach-Object { $_ -replace ",noscan", "" } | ForEach-Object { $_ -replace "ll,", "" }
	$logArray = $removeKeywords | Where-Object { $_ -notmatch "/Boot/BCD" } | Where-Object { $_ -notmatch "echo," } | Where-Object { ![String]::IsNullOrWhiteSpace($_) } | Sort-Object

	# Make sure the disk is online
	Log-Output "#02 - Bringing partition(s) online if present" | Tee-Object -FilePath $logFile -Append
	$disk = Get-Disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
	$disk | Set-Disk -IsOffline $false -ErrorAction SilentlyContinue

	# Handle disk partitions
	$partitionlist = Get-Disk-Partitions
	$partitionGroup = $partitionlist | Group-Object DiskNumber
	$fixedDrives = $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter

	# Grab fileshares if mounted as System
	$mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -ne $null } | Select-Object -ExpandProperty Name

	# Log drive letters
	if ($fixedDrives) {
		Log-Output "Attached volumes: $($fixedDrives -join ", ")" | Tee-Object -FilePath $logFile -Append
	}
	if ($mappedDrives) {
		Log-Output "Mapped drives: $($mappedDrives -join ", ")" | Tee-Object -FilePath $logFile -Append
	}

	# Collect drive letters except for root drive of Rescue VM
	$driveLetters += $fixedDrives
	# Collect drive letters of mapped network drives
	$driveLetters += $mappedDrives

	# Create or get CaseLogs folder on desktop
	if (Test-Path "$($desktopFolderPath)$($logFolderName)") {
		$folder = Get-Item -Path "$($desktopFolderPath)$($logFolderName)"
	}
	else {
		$folder = New-Item -Path $desktopFolderPath -Name $logFolderName -ItemType "directory"
	}

	# Create subfolder named after the current time in UTC
	$timeFolder = New-Item -Path $folder.ToString() -Name "$($scriptStartTimeUTC)_UTC" -ItemType "directory"

	Log-Output "#03 - Copy log files to $($timeFolder.ToString())" | Tee-Object -FilePath $logFile -Append

	# Scan all collected partitions to determine if BCD or OS partition
	ForEach ($drive in $driveLetters ) {
		if ($drive.ToString() -ne "") {
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
			$logFile = "$timeFolder\collectedLogFiles.csv"
			"sep=," | Out-File -FilePath $logFile -Force
			'"Source Log File","Type","Destination Log File","Number of Destination Files","Size of Destination File(s) [Bytes]"' | Out-File -FilePath $logFile -Append
			$failedLogFile = "$timeFolder\failedLogFiles.log"
			$treeFile = "$timeFolder\collectedLogFilesTree.log"
			$partitionSizeFile = "$timeFolder\partitionSizeFile.log"

			# If Boot partition found grab BCD store
			if ( $isBcdPath ) {
				Log-Output " BCD store on $($drive)" | Tee-Object -FilePath $logFile -Append
				$bcdParentFolderName = "bcd"
				$bcdFileName = $bcdPath.Split("\")[-1]

				if (Test-Path "$($subFolder.ToString())\$($bcdParentFolderName)") {
					$folder = Get-Item -Path "$($subFolder.ToString())\$($bcdParentFolderName)"
				}
				else {
					$folder = New-Item -Path $subFolder -Name $bcdParentFolderName -ItemType "directory"
				}

				Log-Output "Copy $($bcdPath) to $($subFolder.ToString())" | Tee-Object -FilePath $logFile -Append
				Copy-Item -Path $bcdPath -Destination "$($folder)\$($bcdFileName)" -Recurse
				"$($bcdPath)" | Tee-Object -FilePath $logFile -Append
				Log-Output "Print $($bcdPath) to $($subFolder.ToString())" | Tee-Object -FilePath $logFile -Append
				bcdedit /store $bcdPath /enum /v > "$($folder)\$($bcdFileName).txt"
				"$($bcdFileName).txt" | Tee-Object -FilePath $logFile -Append
			}
			else {
				Log-Warning "No BCD store on $($drive)" | Tee-Object -FilePath $logFile -Append
			}

			# If Windows partition found grab log files
			if ( $isOsPath ) {
				Log-Output "OS logs on $($drive)" | Tee-Object -FilePath $logFile -Append
				foreach ($logName in $logArray) {
					$logLocation = "$($drive):$($logName)"

					# Confirm file exists
					if (Test-Path $logLocation) {
						$itemToCopy = Get-ChildItem $logLocation -Force -ErrorAction SilentlyContinue -ErrorVariable getLogItemErrors -WarningAction SilentlyContinue -WarningVariable getLogItemWarnings

						foreach ($collectedLog in $itemToCopy) {
							$collectedLogArray += $collectedLog.FullName
						}
					}
					else {
						"NOT FOUND: $($logLocation)" | Out-File -FilePath $failedLogFile -Append
					}
				}

				Log-Output "Copy Windows OS logs from $($drive) to $($subFolder.ToString())" | Tee-Object -FilePath $logFile -Append
				$collectedLogArray | ForEach-Object {
					# Retain directory structure while replacing partition letter
					try {
						$split = $_ -split '\\'
						$DestFile = $split[1..($split.Length - 1)] -join '\'
						$DestFile = "$($subFolder)\$($DestFile)"

						# Confirm if current log is a file or folder prior to copying
						if (Test-Path -Path $_ -PathType Leaf) {
							$logType = "File"
							New-Item -Path $DestFile -Type $logType -Force -ErrorAction SilentlyContinue -ErrorVariable newItemErrors -WarningAction SilentlyContinue -WarningVariable newItemWarnings | Out-Null
							$copiedItem = Copy-Item -Path $_ -Destination $DestFile -PassThru -Force -ErrorAction SilentlyContinue -ErrorVariable copyErrors -WarningAction SilentlyContinue -WarningVariable copyWarnings
						}
						elseif (Test-Path -Path $_ -PathType Container) {
							$logType = "Directory"
							$copiedItem = Copy-Item -Path $_ -Destination $DestFile -Recurse -PassThru -Force -ErrorAction SilentlyContinue -ErrorVariable copyErrors -WarningAction SilentlyContinue -WarningVariable copyWarnings
						}

						$destNumLogFiles = "$(($copiedItem | Measure-Object -Property length).Count)"
						$destSizeLogFiles = "$(($copiedItem | Get-ChildItem -Recurse -ErrorAction SilentlyContinue -ErrorVariable getChildItemErrors -WarningAction SilentlyContinue -WarningVariable getChildItemWarnings | Measure-Object -Sum Length | Select-Object Sum).sum)"

						# Log any errors
						foreach ($getLogItemWarning in $getLogItemWarnings) {
							"WARNING (thrown during log collection operation): $($getLogItemWarning)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($getLogItemError in $getLogItemErrors) {
							"EXCEPTION (thrown during log collection operation): $($getLogItemError)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($getChildItemWarning in $getChildItemWarnings) {
							"WARNING (thrown during measure operation): $($getChildItemWarning)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($getChildItemError in $getChildItemErrors) {
							"EXCEPTION (thrown during measure operation): $($getChildItemError.Exception.Message)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($newItemError in $newItemErrors) {
							"EXCEPTION (thrown during New-Item operation at destination): $($newItemError.Exception.Message)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($newItemWarning in $newItemWarnings) {
							"WARNING (thrown during New-Item operation at destination): $($newItemWarning)" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($copyError in $copyErrors) {
							"EXCEPTION (thrown during Copy operation to destination): $($copyError.Exception.Message)$(if($getLogItemError -eq "Container cannot be copied onto existing leaf item.") {" - " + $copyError})" | Out-File -FilePath $failedLogFile -Append
						}
						foreach ($copyWarning in $copyWarnings) {
							"WARNING (thrown during Copy operation to destination): $($copyWarning)" | Out-File -FilePath $failedLogFile -Append
						}
						# Print relevant information to log file
						if (Test-Path $DestFile) {
							"`"{0}`",`"{1}`",`"{2}`",`"{3}`",`"{4}`"" -f $_, $logType, $DestFile, $destNumLogFiles, $destSizeLogFiles | Out-File -FilePath $logFile -Append
						}
					}
					catch {
						"FAILED $($split -join '\'): $($_.Exception.Message)" | Out-File -FilePath $failedLogFile -Append
					}
				}

				# Check if Health Signals log exists
				try {
					$TransparentInstallerLog = "$($subFolder)\WindowsAzure\Logs\TransparentInstaller.log"
					if (Test-Path $TransparentInstallerLog) {
						# If so, search log for latest Health Report
						$search = Select-String -Path $TransparentInstallerLog -Pattern "(?<= Microsoft Azure VM Health Report )(.*)"
						$start = $search[-2].Line
						$end = $search[-1].Line

						# Collect log contents
						$logString = Get-Content $TransparentInstallerLog -Raw

						# Grab the Health Report if present and print to JSON file
						$matchResult = $logString -match "(?s)$start(?<content>.*)$end"
						if ($matchResult) {
							$healthSignalsFile = "$($subFolder.ToString())\healthSignals_latest.json"
							$jsonResult = $matches['content']
							$jsonConversion = ConvertFrom-Json $jsonResult
							$jsonConversion | ConvertTo-Json | Tee-Object -FilePath $healthSignalsFile -Append
						}
						else {
							Log-Warning "Could not generate Health Signals log, confirm $($subFolder)\WindowsAzure\Logs\TransparentInstaller.log has Health Signals logged" | Tee-Object -FilePath $logFile -Append
						}
					}
					else {
						Log-Warning "Could not generate Health Signals log, confirm $($subFolder)\WindowsAzure\Logs\TransparentInstaller.log exists" | Tee-Object -FilePath $logFile -Append
					}
				}
				catch {
					Log-Warning "Could not generate Health Signals log, confirm $($subFolder)\WindowsAzure\Logs\TransparentInstaller.log exists" | Tee-Object -FilePath $logFile -Append
				}


			}
			else {
				Log-Warning "No OS logs on $($drive)" | Tee-Object -FilePath $logFile -Append
			}
		}
	}

	# Include tree of subdirectory
	try {
		Log-Output "Generating tree file" | Tee-Object -FilePath $logFile -Append
		tree $timeFolder /f /a | Out-File -FilePath $treeFile -Append
	}
 catch {
		Log-Warning "Could not generate tree file" | Tee-Object -FilePath $logFile -Append
	}

	# Include size of partitions: https://devblogs.microsoft.com/scripting/inventory-drive-types-by-using-powershell/
	try {
		Log-Output "Collecting partition sizes" | Tee-Object -FilePath $logFile -Append
		$hash = @{
			2 = "Removable disk"
			3 = "Fixed local disk"
			4 = "Network disk"
			5 = "Compact disk"
		}
		Get-CimInstance -Class CIM_LogicalDisk | Select-Object @{Name = "Size(GB)"; Expression = { ($_.size / 1gb).tostring("#.###") } }, @{Name = "Free Space(GB)"; Expression = { ($_.freespace / 1gb).tostring("#.###") } }, @{Name = "Free (%)"; Expression = { "{0,6:P0}" -f (($_.freespace / 1gb) / ($_.size / 1gb)) } }, DeviceID, @{Name = "DriveType (Type)"; Expression = { $hash.item([int]$_.DriveType) } } | Where-Object { ($_.DeviceID -split ":")[0] -in $driveLetters } | Format-Table | Out-File -FilePath $partitionSizeFile -Append
	}
	catch {
		Log-Warning "Could not collect partition sizes" | Tee-Object -FilePath $logFile -Append
	}

	# Zip files
	try {
		Log-Output "#04 - Creating zipped archive $($timeFolder.Name).zip" | Tee-Object -FilePath $logFile -Append
		$compress = @{
			Path             = $timeFolder
			CompressionLevel = "Fastest"
			DestinationPath  = "$($desktopFolderPath)$($timeFolder.Name).zip"
		}
		Compress-Archive @compress
		Log-Output "END: Please collect zipped log file $($desktopFolderPath)$($timeFolder.Name).zip from desktop" | Tee-Object -FilePath $logFile -Append
	}
 catch {
		Log-Warning "Could not generate ZIP file, collect logs from CaseFiles folder on desktop instead" | Tee-Object -FilePath $logFile -Append
	}
	return $STATUS_SUCCESS
}

# Log failure scenario
catch {
	Log-Error "END: Script failed $(if ($logLocation) { "at $($logLocation)" } )
	Please confirm a Windows OS disk is attached as a data disk
	You can also map a network drive with:
	az vm run-command invoke --command-id RunPowerShellScript --name vm --resource-group rg --scripts `"net use <DRIVE
	LETTER>: \\<PRIVATE_IP_OF_VM_ON_VNET>\c$ /persistent:no /user:<USERNAME> <PASSWORD>`"" | Tee-Object -FilePath $logFile -Append
	throw $_
	return $STATUS_ERROR
}

$scriptEndTime = get-date -f yyyyMMddHHmmss
$scriptEndTime | Tee-Object -FilePath $logFile -Append
