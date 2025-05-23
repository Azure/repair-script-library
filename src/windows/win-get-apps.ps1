﻿######################################################################################################
#
# .SYNOPSIS
#   Get installed Windows applications for the nested Hyper-V machine.
#
# .DESCRIPTION
#   Get installed Windows applications for the nested Hyper-V machine. This will be helpful if the attached OS disk is from a VM where uninstalling the apps is difficult. When complete, the script will output uninstallable apps and their QUS (Quiet Uninstall String) to the terminal. Copy the QUS to the win-remove-app script to attempt silent uninstall from nested VM.
#   Load the registry SOFTWARE hive of the attached OS disk. Check for installed applications specified in the registry. Prints software and uninstall method to terminal and saves as text file to rescue VM.
# .RESOLVES
#   Easily get a list of installed applications from an attached OS disk (in case the original VM is not easily accessible) in case the user needs to know installed software or needs to know uninstallation method from the offline environment. 
# .EXAMPLE
#	<# Get installed apps #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-get-apps' --verbose --run-on-repair
#
# .NOTES
#   Author: Ryan McCallum
#
# .VERSION
#   v0.1: Initial commit
#
#######################################################################################################

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Declare variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
$scriptStartTime | Tee-Object -FilePath $logFile -Append
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

            Log-Output '#04 - getting apps from registry that can be quietly uninstalled' | Tee-Object -FilePath $logFile -Append

            # Check if partition has Registry path
            $regPath = $drive + ':\Windows\System32\config\'
            $isRegPath = Test-Path $regPath

            if ($isRegPath) {

                Log-Output "Load SOFTWARE registry hive from $($drive)" | Tee-Object -FilePath $logFile -Append

                # Load hive into Rescue VM's registry from attached disk
                reg load 'HKLM\BROKENSOFTWARE' "$($drive):\Windows\System32\config\SOFTWARE"
                    $regLoaded = $true

                # Get the list of installed applications
                $installedApps = Get-ItemProperty "HKLM:\BROKENSOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"  | sort-object DisplayName

                $uninstallableApps = $installedApps | Where-Object { ($_.UninstallString -like "*MsiExec.exe*") -or (![String]::IsNullOrWhiteSpace($_.QuietUninstallString) ) }

                $installedAppsList = $uninstallableApps | Select-Object @{Name="App";Expression={ if ($_.DisplayName) { $_.DisplayName } }}, @{Name="QUS";Expression={ if ($_.UninstallString -like "*MsiExec.exe*") { $_.PSChildName } elseif ( $_.QuietUninstallString ) { $_.QuietUninstallString } else { "No quiet uninstall string, must be uninstalled from live system" } } } | Where-Object { $_.App } | Format-List

                $installedApps | ForEach-Object { $_; "================================================" } | Out-File -FilePath $logFile -Append

                Write-Output "`n"
                Write-Output $installedAppsList
                Write-Output "`n"

                Log-Output "Copy QUS (Quiet Uninstall String) to win-remove-app script to attempt silent uninstall from nested VM" | Tee-Object -FilePath $logFile -Append
                Log-Output "Full output is on the Rescue VM in $($logFile)"

                # Unload hive
                if ($regLoaded) {
                    Log-Output "#05 - Unload attached disk registry hive on $($drive)" | Tee-Object -FilePath $logFile -Append
                    [gc]::Collect()
                    reg unload 'HKLM\BROKENSOFTWARE'
                }
            } else {
                Log-Output "No registry path found on $($drive), skipping" | Tee-Object -FilePath $logFile -Append
            }

            Log-Output "END: List Apps" | Tee-Object -FilePath $logFile -Append
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
