#########################################################################################################
<#
# .SYNOPSIS
#   Create a troubleshooting user for a nested Hyper-V server on a Rescue VM. v0.1.0
#
# .DESCRIPTION
#   https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/reset-local-password-without-agent
#
# .EXAMPLE
#	<# Create default troubleshooting user #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-create-troubleshooting-user' --verbose --run-on-repair
#
#	<# Create custom troubleshooting user #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-create-troubleshooting-user' --verbose --run-on-repair --parameters username=trblAcct password=welcomeToAzure!1 DC=$true
#
# .NOTES
#   Author: Ryan McCallum
# 	
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
Log-Output "START: Running script win-create-troubleshooting-user" | Tee-Object -FilePath $logFile -Append