. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

#########################################################################################################
# Azure VMs do not natively support Safe Mode because RDP access is disabled in Safe Mode. Some users
# need to boot their VM in Safe Mode for specific reasons (e.g. uninstalling certain software). Other
# users may find their VM booting into Safe Mode inadvertantly due to user error or misconfiguration,
# which will disable RDP access until corrected. This script utilizes the az vm repair extension to 
# clone the VM into a Hyper-V environment using Nested Virtualization and toggle Safe Boot. The user
# may then access their VM in Safe Mode via the Rescue VM or revert Safe Mode on their Azure VM. They 
# may then swap the disk using the `az vm repair restore` functionality.
#
# Testing:
# 1. Copied scripts to newly created Windows Server 2019 Datacenter (Gen 1)
# 2. Ran win-enable-nested-hyperv once to install Hyper-V, restarted, and ran again to create new nested VM
# 3. Ran win-toggle-safe-mode.ps1, worked successfully in toggling Safe Mode
# 4. Set up new VM and ran the following from my local machine, worked successfully (~69 seconds): 
#    az vm repair run -g sourcevm_group -n sourcevm --custom-script-file .\win-toggle-safe-mode.ps1 --verbose --run-on-repair
# 5. Tried on a WS 2016 Gen 2 Azure VM, but was unsuccessful, not compatible with Gen 2 right now
#
# https://docs.microsoft.com/en-us/cli/azure/ext/vm-repair/vm/repair?view=azure-cli-latest
# https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-rdp-safe-mode
#########################################################################################################

# Initialize script log variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]

# Initialize script log
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
Log-Output 'START: Running Script win-toggle-safe-mode' | out-file -FilePath $logFile -Append
$scriptStartTime | out-file -FilePath $logFile -Append

try {

    # Make sure guest VM is shut down
    $guestHyperVVirtualMachine = Get-VM
    $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
    if ($guestHyperVVirtualMachine.State -eq 'Running') {
        Log-Info "#01 - Stopping nested guest VM $guestHyperVVirtualMachineName" | out-file -FilePath $logFile -Append
        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force   
    }    

    # Make sure the disk is online
    Log-Info "#02 - Bringing disk online" | out-file -FilePath $logFile -Append
    $disk = get-disk -ErrorAction Stop | where { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | set-disk -IsOffline $false -ErrorAction Stop
 
    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | group DiskNumber

    Log-Info '#03 - enumerate partitions for boot config' | out-file -FilePath $logFile -Append

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
            Log-Info "#04 - Checking safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
            $bcdout = bcdedit /store $bcdPath /enum
            $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
            $defaultId = '{' + $defaultLine.ToString().Split('{}')[1] + '}'
            $safeModeIndicator = $bcdout | Select-String 'safeboot' | select -First 1

            # Check if flag exists
            if ($safeModeIndicator) {                        
                # Flag exists, delete to take VM out of Safe Mode
                Log-Info "#05 - Removing safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
                bcdedit /store $bcdPath /deletevalue $defaultId safeboot         
            }
            else {            
                # Flag doesn't exist, adding so VM boots in Safe Mode
                Log-Info "#05 - Configuring safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
                bcdedit /store $bcdPath /set $defaultId safeboot network
            }

            # Bring disk offline 
            Log-Info "#06 - Bringing disk offline" | out-file -FilePath $logFile -Append
            $disk | set-disk -IsOffline $true -ErrorAction Stop

            # Start Hyper-V VM
            Log-Output "END: Starting VM, please verify status of Safe Mode using MSCONFIG.exe" | out-file -FilePath $logFile -Append
            start-vm $guestHyperVVirtualMachine -ErrorAction Stop

            # Log finish time
            $scriptEndTime = get-date -f yyyyMMddHHmmss
            $scriptEndTime | out-file -FilePath $logFile -Append

            return $STATUS_SUCCESS
        }
    }
}
catch {
    
    # Log failure
    Log-Error "ERROR: Unable to find the BCD Path" | out-file -FilePath $logFile -Append

    # Bring disk offline again
    Log-Info "#05 - Bringing disk offline to restart Hyper-V VM" | out-file -FilePath $logFile -Append
    $disk | set-disk -IsOffline $true -ErrorAction Stop

    # Start Hyper-V VM again
    Log-Output "END: could not start/stop Safe Mode, BCD store may need to be repaired" | out-file -FilePath $logFile -Append
    start-vm $guestHyperVVirtualMachine -ErrorAction Stop

    # Log finish time
    $scriptEndTime = get-date -f yyyyMMddHHmmss
    $scriptEndTime | out-file -FilePath $logFile -Append   

    throw $_ | out-file -FilePath $logFile -Append
    return $STATUS_ERROR
}
