######################################################################################################
<#
# .SYNOPSIS
#   Create a troubleshooting user for a nested Hyper-V server on a Rescue VM.
#
# .DESCRIPTION
#   Create a troubleshooting user for a nested Hyper-V server on a Rescue VM. This is useful if you need to troubleshoot an Azure VM but do not have a local account with administrative privileges. This script is intended to be run as part of the Azure VM repair workflow. It will create a local user account on the nested Hyper-V server and add it to the local administrators group. The user account 'azure-recoveryID' will be created with a partially randomized password unless the user specifies a username and password. Both the username and password requirements will match the regular requirements for Azure VMs. Custom usernames must not match the username of an account already on the server. The password will be written to the Azure VM repair log file in plain text so would not recommending the use of a known secure password. The user account and generated files should be deleted by the user when the Azure VM repair workflow completes. 

Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/reset-local-password-without-agent 

Username/password requirements: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/faq#what-are-the-username-requirements-when-creating-a-vm-
#
# .EXAMPLE
#	<# Create default troubleshooting user #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-create-troubleshooting-user' --verbose --run-on-repair
#
#	<# Create custom troubleshooting user #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-create-troubleshooting-user' --verbose --run-on-repair --parameters username='trblAcct' password='welcomeToAzure!1'
#
# .NOTES
#   Author: Ryan McCallum (inspired by Ahmed Fouad)
#
# .VERSION
#   v0.2: Removed encoding params
#   v0.1: Initial commit
#>
#######################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidatePattern("^(([a-zA-Z0-9]|[^/[\]:|+=;,?*%@])){1,19}$")][ValidateScript({ $_ -notin @('1','123','a','actuser','adm','admin','admin1','admin2','administrator','aspnet','backup','console','david','guest','john','owner','root','server','sql','support_388945a0','support','sys','test','test1','test2','test3','user','user1','user2','user3','user4','user5','nul','con','com','lpt') })][string]$username, 
    [Parameter(Mandatory = $false)][ValidatePattern("^.{12,123}$")][ValidateScript({ $notReserved = $_ -notin @('password', 'pa$$word', 'pa$$w0rd', 'pa$$word123', 'pa$$w0rd123', 'password123', '123456', 'admin', 'administrator', 'admin123', 'letmein', 'welcome', 'qwerty', 'abc123', 'abc@123', 'monkey', '123123', 'password1', 'adminadmin', 'sunshine', 'master', 'hannah', 'qazwsx', 'charlie', 'superman', 'iloveyou', 'princess', 'adminadmin123', 'login', 'admin1234', 'welcome123', 'adminadminadmin', 'adminadminadmin123', 'Password!', 'Password1', 'Password22', 'iloveyou!');  $lowercaseMatch = $_ -cmatch "[a-z]+";  $uppercaseMatch = $_ -cmatch "[A-Z]+";  $digitMatch = $_ -match "[0-9]+";  $specialCharMatch = $_ -match "\W";  $conditionsMet = ($lowercaseMatch, $uppercaseMatch, $digitMatch, $specialCharMatch) | Measure-Object -Sum | Select-Object -ExpandProperty Sum; return $notReserved  -and ($conditionsMet -gt 2) })][string]$password
)
    
# Initialize script
 . .\src\windows\common\setup\init.ps1
 . .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Declare variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptPath = split-path -path $MyInvocation.MyCommand.Path -parent
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
$scriptStartTime | Tee-Object -FilePath $logFile -Append
if (!$username) {
    $username = 'azure-recoveryID'
}
if (!$password) {
    $password = "@zurE$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))"
}
Log-Output "START: Running script win-create-troubleshooting-user" | Tee-Object -FilePath $logFile -Append

try {
    
    # Make sure guest VM is shut down if it exists
    $features = get-windowsfeature -ErrorAction Stop
    $hyperv = $features | where Name -eq 'Hyper-V'
    $hypervTools = $features | where Name -eq 'Hyper-V-Tools'
    $hypervPowerShell = $features | where Name -eq 'Hyper-V-Powershell'
    $dhcp = $features | where Name -eq 'DHCP'
    $rsatDhcp = $features | where Name -eq 'RSAT-DHCP'

    if ($hyperv.Installed -and $hypervTools.Installed -and $hypervPowerShell.Installed) {
        $guestHyperVVirtualMachine = Get-VM
        $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
        if ($guestHyperVVirtualMachine) {
            if ($guestHyperVVirtualMachine.State -eq 'Running') {
                Log-Output "#01 - Stopping nested guest VM $guestHyperVVirtualMachineName" | Tee-Object -FilePath $logFile -Append
                Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
            }
        }
        else {
            Log-Output "#01 - No running nested guest VM, continuing script" | Tee-Object -FilePath $logFile -Append
        }
    }

    # Make sure the disk is online
    Log-Output "#02 - Bringing disk online" | Tee-Object -FilePath $logFile -Append
    $disk = get-disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | set-disk -IsOffline $false -ErrorAction Stop

    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | Group-Object DiskNumber

    Log-Output '#03 - enumerate partitions for boot config' | Tee-Object -FilePath $logFile -Append

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

        # If on the OS directory, continue script
        if ( $isOsPath ) {

            Log-Output '#04 - updating local policy files' | Tee-Object -FilePath $logFile -Append         
                        
            # Setup policy files
            $groupPolicyPath = $drive + ':\Windows\System32\GroupPolicy'
            [string]$gpt = 'gpt.ini'
            [string]$gptPath = $groupPolicyPath + "\$($gpt)"
            [string]$ini = 'scripts.ini'
            [string]$ScriptINIPath = $groupPolicyPath + "\Machine\Scripts\$($ini)"
            [string]$scriptName = 'FixAzureVM.cmd'
            [string]$scriptPath = $groupPolicyPath + "\Machine\Scripts\Startup\$($scriptName)"
            
            # check if they already exist and rename
            if (Test-Path -Path $gptPath -ErrorAction SilentlyContinue) {
                Log-Output "Renaming $($gptPath) to '$($gpt).bak'" | Tee-Object -FilePath $logFile -Append  
                try {
                    Rename-Item -Path $gptPath -NewName "$($gpt).bak" -ErrorAction Stop
                } 
                catch {                    
                    $gptBakCount = (Get-ChildItem -Path $gptPath -Filter "$($gpt).bak*" -ErrorAction SilentlyContinue).Count
                    Rename-Item -Path $gptPath -NewName "$($gpt).bak$($gptBakCount + 1)"
                }
                finally {
                    $gptPathRenamed = $true              
                }                     
            }
            if (Test-Path -Path $ScriptINIPath -ErrorAction SilentlyContinue) {
                Log-Output "Renaming $($ScriptINIPath) to '$($ini).bak'" | Tee-Object -FilePath $logFile -Append
                try {
                    Rename-Item -Path $ScriptINIPath -NewName "$($ini).bak" -ErrorAction Stop
                } 
                catch {                    
                    $iniBakCount = (Get-ChildItem -Path $ScriptINIPath -Filter "$($ini).bak*" -ErrorAction SilentlyContinue).Count
                    Rename-Item -Path $ScriptINIPath -NewName "$($ini).bak$($iniBakCount + 1)"
                }
                finally {
                    $ScriptINIPathRenamed = $true              
                }
            }
            if (Test-Path -Path $scriptPath -ErrorAction SilentlyContinue) {
                
                Log-Output "Renaming $($scriptPath) to '$($scriptName).bak'" | Tee-Object -FilePath $logFile -Append
                try {
                    Rename-Item -Path $scriptPath -NewName "$($scriptName).bak" -ErrorAction Stop
                } 
                catch {                    
                    $scriptBakCount = (Get-ChildItem -Path $scriptPath -Filter "$($scriptName).bak*" -ErrorAction SilentlyContinue).Count
                    Rename-Item -Path $scriptPath -NewName "$($scriptName).bak$($scriptBakCount + 1)"
                }
                finally {
                    $scriptPathRenamed = $true              
                }
            }

            # Create new gpt file 
            New-Item -Path $gptPath -ItemType File -Force
            [string]$gptNewContent = "[General]`ngPCFunctionalityVersion=2
         gPCMachineExtensionNames=[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]
         Version=1" 
            Add-Content -Path $gptPath -Value $gptNewContent -Force

            #Create new script.ini file  
            new-item -Path $ScriptINIPath -Force
            [string]$scriptINIContent = "[Startup]
         0CmdLine=$($scriptName)`n0Parameters="
            Add-Content -Path $ScriptINIPath -Value $scriptINIContent -Force
            
            #Create the script file 
            New-Item -Path $scriptPath -Force
            [string]$scriptcontent = "net user " + $username + " " + $password + " /add /Y
       net localgroup administrators " + $username + " /add
       net localgroup 'remote desktop users' " + $username + " /add" 
            Add-Content -Path $scriptPath -Value $scriptcontent -Force

            if ($guestHyperVVirtualMachine) {
                # Bring disk offline
                Log-Output "#05 - Bringing disk offline" | Tee-Object -FilePath $logFile -Append
                $disk | set-disk -IsOffline $true -ErrorAction Stop

                # Start Hyper-V VM
                Log-Output "#06 - Starting VM" | Tee-Object -FilePath $logFile -Append
                start-vm $guestHyperVVirtualMachine -ErrorAction Stop
            }

            Log-Output "END: Start the nested VM and login with the troubleshooting account:" | Tee-Object -FilePath $logFile -Append
            Log-Output "USERNAME: $($username)" | Tee-Object -FilePath $logFile -Append
            Log-Output "PASSWORD: $($password)" | Tee-Object -FilePath $logFile -Append
            Log-Output "Remove the account and the following files after troubleshooting has been completed: " | Tee-Object -FilePath $logFile -Append
            Log-Output "$($gptPath)$(if ($gptPathRenamed) { " and rename $($gptPath).bak to $($gptPath) " })" | Tee-Object -FilePath $logFile -Append
            Log-Output "$($ScriptINIPath)$(if ($ScriptINIPathRenamed) { " and rename $($ScriptINIPath).bak to $($ScriptINIPath) " })" | Tee-Object -FilePath $logFile -Append
            Log-Output "$($scriptPath)$(if ($scriptPathRenamed) { " and rename $($scriptPath).bak to $($scriptPath) " })" | Tee-Object -FilePath $logFile -Append            

            return $STATUS_SUCCESS
        }
    }
}
catch {
    Log-Error "END: Script failed with error: $_" | Tee-Object -FilePath $logFile -Append
    throw $_
    return $STATUS_ERROR
}
finally {
    $scriptEndTime = get-date -f yyyyMMddHHmmss
    $scriptEndTime | Tee-Object -FilePath $logFile -Append
}
