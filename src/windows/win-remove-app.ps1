######################################################################################################
#
# .SYNOPSIS
#   Remove an installed Windows application from the nested Hyper-V machine.
#
# .DESCRIPTION
#   Remove an installed Windows application from the nested Hyper-V machine.This will be helpful if the attached OS disk is from a VM where uninstalling the apps is difficult. When complete, the script will output uninstallable apps and their QUS (Quiet Uninstall String) to the terminal. Copy the QUS to the win-remove-app script to attempt silent uninstall from nested VM.
#   Check if Hyper-V guest VM is shut down and if not, powers it down. Brings disk online to create policy files with steps to automatically uninstall a particular software. Then starts the nested server in Hyper-V. The final log file suggests the user monitor the Hyper-V server to see if the software is removed with recommendations to remove related files after troubleshooting has completed.
# .RESOLVES
#   Certain software may sometimes be difficult to uninstall, especially when RDP access is prevented by the software. This script helps remove the software from the system while in a Rescue VM.
# 
# .EXAMPLE
#	<# Get installed apps #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-get-apps' --verbose --run-on-repair
#
#	<# Remove app based on QUS output #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-remove-app' --parameters uninstallString='{BEF2B9D6-4D36-3799-ADC8-F61F1926092C}' --verbose --run-on-repair
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-remove-app' --parameters uninstallString='"C:\Program Files\Microsoft VS Code\unins000.exe" /SILENT' --verbose --run-on-repair
#
# .NOTES
#   Author: Ryan McCallum
#
# .VERSION
#   v0.1: Initial commit
#
#######################################################################################################

Param(
    [Parameter(Mandatory = $true)][string]$uninstallString = ''
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
$uninstallString = $uninstallString.Trim()
$uninstallScript = if ($uninstallString -like "{*}" ) { "msiexec /x $($uninstallString) REMOVE=ALL REBOOT=R /quiet /qn /forcerestart /l* $($logfile)" } else { $uninstallString }

Log-Output "START: Running script $($scriptName)" | Tee-Object -FilePath $logFile -Append

try {

    # Make sure guest VM is shut down if it exists
    $features = get-windowsfeature -ErrorAction Stop
    $hyperv = $features | Where-Object Name -eq 'Hyper-V'
    $hypervTools = $features | Where-Object Name -eq 'Hyper-V-Tools'
    $hypervPowerShell = $features | Where-Object Name -eq 'Hyper-V-Powershell'

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
    else {
        Log-Output "#01 - No Hyper-V installed, continuing script" | Tee-Object -FilePath $logFile -Append
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
            Add-Content -Path $gptPath -Value $gptNewContent -Force -Encoding Default

            #Create new script.ini file
            new-item -Path $ScriptINIPath -Force
            [string]$scriptINIContent = "[Startup]
         0CmdLine=$($scriptName)`n0Parameters="
            Add-Content -Path $ScriptINIPath -Value $scriptINIContent -Force -Encoding Default

            #Create the script file
            New-Item -Path $scriptPath -Force
            Add-Content -Path $scriptPath -Value $uninstallScript -Force -Encoding Default

            if ($guestHyperVVirtualMachine) {
                # Bring disk offline
                Log-Output "#05 - Bringing disk offline" | Tee-Object -FilePath $logFile -Append
                $disk | set-disk -IsOffline $true -ErrorAction Stop

                # Start Hyper-V VM
                Log-Output "#06 - Starting VM" | Tee-Object -FilePath $logFile -Append
                start-vm $guestHyperVVirtualMachine -ErrorAction Stop
            }

            Log-Output "END: Start the nested VM and login to confirm the app with string $($uninstallString) is removed" | Tee-Object -FilePath $logFile -Append
            Log-Output "The server may reboot to complete the uninstallation" | Tee-Object -FilePath $logFile -Append
            Log-Output "Remove the following files after troubleshooting has been completed: " | Tee-Object -FilePath $logFile -Append
            Log-Output "$($gptPath)$(if ($gptPathRenamed) { " and rename $($gptPath).bak to $($gptPath) " })" | Tee-Object -FilePath $logFile -Append
            Log-Output "$($ScriptINIPath)$(if ($ScriptINIPathRenamed) { " and rename $($ScriptINIPath).bak to $($ScriptINIPath) " })" | Tee-Object -FilePath $logFile -Append
            Log-Output "$($scriptPath)$(if ($scriptPathRenamed) { " and rename $($scriptPath).bak to $($scriptPath) " })" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        } else {
            Log-Output "No OS directory found on $($drive), skipping" | Tee-Object -FilePath $logFile -Append
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
