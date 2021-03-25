#########################################################################################################
<#
# .SYNOPSIS
#   Disable Safe Mode if your Windows VM is booting in Safe Mode. Also activates Safe Mode 
#   if you require it (e.g. to uninstall certain software).
#
# .DESCRIPTION
#   Azure VMs do not natively support Safe Mode because RDP access is disabled in Safe Mode. Some users
#   need to boot their VM in Safe Mode for specific reasons (e.g. uninstalling certain software). Other
#   users may find their VM booting into Safe Mode inadvertantly due to user error or misconfiguration,
#   which will disable RDP access until corrected. This script utilizes the az vm repair extension to 
#   clone the VM into a Hyper-V environment using Nested Virtualization and toggle Safe Boot. The user
#   may then access their VM in Safe Mode via the Rescue VM or revert Safe Mode on their Azure VM. They 
#   may then swap the disk using the `az vm repair restore` functionality.
#
#   Testing:
#       1. Copied scripts to newly created Windows Server 2019 Datacenter (Gen 1)
#       2. Ran win-enable-nested-hyperv once to install Hyper-V, restarted, and ran again to create new nested VM
#       3. Ran win-toggle-safe-mode.ps1, worked successfully in toggling Safe Mode
#       4. Set up new VM and ran the following from my local machine, worked successfully (~69 seconds): 
#           az vm repair run -g sourcevm_group -n sourcevm --custom-script-file .\win-toggle-safe-mode.ps1 --verbose --run-on-repair
#       5. Tried on a WS 2016 Gen 2 Azure VM, but was unsuccessful, not compatible with Gen 2 right now
#       6. Tested on WS2012R2, WS2016 Datacenter, and WS2019 Datacenter (Gen 1)
#
#   https://docs.microsoft.com/en-us/cli/azure/ext/vm-repair/vm/repair?view=azure-cli-latest
#   https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-rdp-safe-mode
#
# .PARAMETER safeModeSwitch
#   "On" to enable Safe Mode, "Off" to disable Safe Mode, no parameter to toggle whatever the current state is.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-toggle-safe-mode --verbose --run-on-repair
#   az vm repair run -g sourceRG -n sourceVM --run-id win-toggle-safe-mode --parameters safeModeSwitch=on --verbose --run-on-repair
#   az vm repair run -g sourceRG -n sourceVM --run-id win-toggle-safe-mode --parameters safeModeSwitch=off --verbose --run-on-repair
#>
#########################################################################################################

# Set the Parameters for the script
Param([Parameter(Mandatory = $false)][string]$safeModeSwitch = '')

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1
Log-Output 'START: Running script win-toggle-safe-mode'

try {

    # Make sure guest VM is shut down
    $guestHyperVVirtualMachine = Get-VM
    $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
    if ($guestHyperVVirtualMachine) {
        if ($guestHyperVVirtualMachine.State -eq 'Running') {
            Log-Output "#01 - Stopping nested guest VM $guestHyperVVirtualMachineName"
            Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force   
        }         
    }
    else {
        Log-Output "#01 - No nested guest VM, flipping safeboot switch anyways"
    }  

    # Make sure the disk is online
    Log-Output "#02 - Bringing disk online"
    $disk = get-disk -ErrorAction Stop | where { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | set-disk -IsOffline $false -ErrorAction Stop
 
    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | group DiskNumber

    Log-Output '#03 - enumerate partitions for boot config'

    forEach ( $partitionGroup in $partitionlist | group DiskNumber ) {
        # Reset paths for each part group (disk)
        $isBcdPath = $false
        $bcdPath = ''
        $isOsPath = $false
        $osPath = ''

        # Scan all partitions of a disk for bcd store and os file location 
        ForEach ($drive in $partitionGroup.Group | select -ExpandProperty DriveLetter ) {      
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

        # If both was found grab bcd store
        if ( $isBcdPath -and $isOsPath ) {

            # Get Safe Mode state
            Log-Output "#04 - Checking safeboot flag for $bcdPath"
            $bcdout = bcdedit /store $bcdPath /enum
            $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
            $defaultId = '{' + $defaultLine.ToString().Split('{}')[1] + '}'
            $safeModeIndicator = $bcdout | Select-String 'safeboot' | select -First 1

            if ($safeModeSwitch -eq "on") {
                # Setting flag so VM boots in Safe Mode
                Log-Output "#05 - Configuring safeboot flag for $bcdPath"
                bcdedit /store $bcdPath /set $defaultId safeboot network
            }
            elseif ($safeModeSwitch -eq "off") {
                # Removing flag so VM doesn't boot in Safe Mode   
                Log-Output "#05 - Removing safeboot flag for $bcdPath"             
                bcdedit /store $bcdPath /deletevalue $defaultId safeboot
            }
            else {
                
                # Toggle Mode, check if flag exists
                if ($safeModeIndicator) {                        
                    # Flag exists, delete to take VM out of Safe Mode
                    Log-Output "#05 - Removing safeboot flag for $bcdPath"
                    bcdedit /store $bcdPath /deletevalue $defaultId safeboot
                }
                else {            
                    # Flag doesn't exist, adding so VM boots in Safe Mode
                    Log-Output "#05 - Configuring safeboot flag for $bcdPath"
                    bcdedit /store $bcdPath /set $defaultId safeboot network
                }
            }

            if ($guestHyperVVirtualMachine) {
                # Bring disk offline 
                Log-Output "#06 - Bringing disk offline"
                $disk | set-disk -IsOffline $true -ErrorAction Stop

                # Start Hyper-V VM            
                Log-Output "#07 - Starting VM"
                start-vm $guestHyperVVirtualMachine -ErrorAction Stop
            }

            Log-Output "END: Please verify status of Safe Mode using MSCONFIG.exe"
            return $STATUS_SUCCESS
        }
    }
}
catch {
    
    if ($guestHyperVVirtualMachine) {
        # Bring disk offline again
        Log-Output "#05 - Bringing disk offline to restart Hyper-V VM"
        $disk | set-disk -IsOffline $true -ErrorAction Stop

        # Start Hyper-V VM again
        Log-Output "#06 - Starting VM"
        start-vm $guestHyperVVirtualMachine -ErrorAction Stop
    }

    # Log failure scenario
    Log-Error "END: could not start/stop Safe Mode, BCD store may need to be repaired"
    throw $_
    return $STATUS_ERROR
}
