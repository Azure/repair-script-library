#########################################################################################################
#
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
#   Check if Hyper-V guest VM is shut down and if not, powers it down. Brings disk online to check safe mode state. Can toggle Safe Mode 
#   state for the guest VM. Can also enable Directory Services Restore Mode for Domain Controllers.
#
# .RESOLVES
#   VMs in safe mode prevent TermService from starting, disallowing RDP connectivity. This script corrects safe mode boot for VMs to restore RDP connectivity.
#   Can also easily allow nested VMs to enter safe mode for a user's requirements while still being accessible from Hyper-V console.
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
#   az vm repair run -g sourceRG -n sourceVM --run-id win-toggle-safe-mode --parameters safeModeSwitch=off DC=yes --verbose --run-on-repair
#
# .NOTES
#   Author: Ryan McCallum
#
# .VERSION
#   v0.5: [Nov 2025] - Update the script to work with Gen2 Azure VMs and change DC switch to a string for AZ CLI compatibility
#   v0.4: [Feb 2025] - Update the description.
#   v0.3: [July 2023] - Detect if a Domain Controller from the attached OS drive's imported registry
#   v0.2: [Feb 2023] - run with the -DC switch to initiate DSRM (Directory Services Recovery Mode) for Domain Controllers
#   v0.1: Initial commit
#
#########################################################################################################

# Set the Parameters for the script
Param(
    [Parameter(Mandatory = $false)][ValidateSet("On", "Off", IgnoreCase = $true)][string]$safeModeSwitch = '',
    [Parameter(Mandatory = $false)][ValidateSet("Yes", "No", IgnoreCase = $true)][string]$DC = ''
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Declare variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptPath = split-path -path $MyInvocation.MyCommand.Path -parent
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]
$regLoaded = $false
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
$scriptStartTime | Tee-Object -FilePath $logFile -Append

Log-Output "START: Running script win-toggle-safe-mode $(if ($DC -eq 'yes') { 'on Domain Controller' })" | Tee-Object -FilePath $logFile -Append

try {

    # Make sure guest VM is shut down
    $guestHyperVVirtualMachine = Get-VM
    $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
    if ($guestHyperVVirtualMachine) {
        if ($guestHyperVVirtualMachine.State -eq 'Running') {
            Log-Output "#01 - Stopping nested guest VM $guestHyperVVirtualMachineName" | Tee-Object -FilePath $logFile -Append
            Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
        }
    }
    else {
        Log-Output "#01 - No running nested guest VM, flipping safeboot switch anyways" | Tee-Object -FilePath $logFile -Append
    }

    # Make sure the disk is online
    Log-Output "#02 - Bringing disk online" | Tee-Object -FilePath $logFile -Append
    $disk = get-disk -ErrorAction Stop | where { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | set-disk -IsOffline $false -ErrorAction Stop

    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | group DiskNumber

    Log-Output '#03 - enumerate partitions for boot config' | Tee-Object -FilePath $logFile -Append

    forEach ( $partitionGroup in $partitionlist | group DiskNumber ) {
        # Reset paths for each part group (disk)
        $isBcdPath = $false
        $bcdPath = ''
        $isOsPath = $false
        $osPath = ''
        $osDrive = ''

        # Scan all partitions of a disk for bcd store and os file location

        # Build a list of candidate roots: drive letters (C, D, ...) and, if no letter,
        # the first access path (typically a volume GUID like \\?\Volume{...}\).
        $driveCandidates = @()
        foreach ($partition in $partitionGroup.Group) {
            if ($partition.DriveLetter) {
                $driveCandidates += $partition.DriveLetter
            }
            elseif ($partition.AccessPaths) {
                $driveCandidates += ($partition.AccessPaths | Select-Object -First 1)
            }
        }

        ForEach ($drive in $driveCandidates) {

            # Normalise root path for both drive letters and volume GUID access paths
            if ($drive -match '^[A-Za-z]$') {
                $root = "$drive`:"
            }
            else {
                $root = $drive.TrimEnd('\')
            }

            # Check if no bcd store was found on the previous partition already
            if ( -not $isBcdPath ) {
                $bcdPath = "${root}\boot\bcd"
                $isBcdPath = Test-Path $bcdPath

                # If no bcd was found yet at the default location look for the uefi location too
                if ( -not $isBcdPath ) {
                    $bcdPath = "${root}\efi\microsoft\boot\bcd"
                    $isBcdPath = Test-Path $bcdPath
                }
            }

            # Check if os loader was found on the previous partition already
            if (-not $isOsPath) {
                $osPath = "${root}\windows\system32\winload.exe"
                $isOsPath = Test-Path $osPath
                if ($isOsPath) {
                    $osDrive = $drive
                }
            }
        }

        # If both was found grab bcd store
        if ( $isBcdPath -and $isOsPath ) {

            # Get Safe Mode state
            Log-Output "#04 - Checking safeboot flag for $bcdPath" | Tee-Object -FilePath $logFile -Append
            $bcdout = bcdedit /store $bcdPath /enum
            $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
            $defaultId = '{' + $defaultLine.ToString().Split('{}')[1] + '}'
            $safeModeIndicator = $bcdout | Select-String 'safeboot' | select -First 1

            # Check if partition has Registry path (use OS partition that contained winload.exe)
            $regPath = $osDrive + ':\Windows\System32\config\'
            $isRegPath = Test-Path $regPath
        
            # If Registry path found and we're enabling safe mode, check if DC
            if ($isRegPath -and ($safeModeSwitch -ne "Off")) {
        
                Log-Output "Load requested Registry hive from $($osDrive)" | Tee-Object -FilePath $logFile -Append
        
                # Load hive into Rescue VM's registry from attached disk
                reg load "HKLM\BROKENSYSTEM" "$($osDrive):\Windows\System32\config\SYSTEM"
                $regLoaded = $true
        
                # Verify the active Control Set if using the System registry and if not already defined (1 is ControlSet001, 2 is ControlSet002)
                $controlSetText = "ControlSet00"
                $controlSet = (Get-ItemProperty -Path "HKLM:\BROKENSYSTEM\Select" -Name Current).Current
                $controlSetText += $controlSet

                # Check if Domain Controller
                try {                
                    $dsaDatabase = Get-ItemPropertyValue -Path "HKLM:\BROKENSYSTEM\$($controlSetText)\Services\NTDS\parameters" -Name "DSA Database file" -ErrorAction Stop
                    $isDC = ![String]::IsNullOrWhiteSpace($dsaDatabase)

                    # If Domain Controller, set the DSRM switch
                    if ($isDC) {                    
                        Log-Output "DSA Database file found in \$($controlSetText)\Services\NTDS\parameters, probably a Domain Controller" | Tee-Object -FilePath $logFile -Append
                    }
                    else {
                        Log-Output "DSA Database file not found in \$($controlSetText)\Services\NTDS\parameters, probably not a Domain Controller" | Tee-Object -FilePath $logFile -Append
                    }
                }
                catch {
                    Log-Output "Error searching for DSA Database file in \$($controlSetText)\Services\NTDS\parameters, probably not a Domain Controller" | Tee-Object -FilePath $logFile -Append
                }               
            }
            
            $safeBootVersion = If ($DC -eq 'yes' -or $isDC) { "dsrepair" } Else { "network" }

            if ($safeModeSwitch -eq "on") {
                # Setting flag so VM boots in Safe Mode
                Log-Output "#05 - Configuring safeboot flag for $bcdPath" | Tee-Object -FilePath $logFile -Append
                bcdedit /store $bcdPath /set $defaultId safeboot $safeBootVersion
            }
            elseif ($safeModeSwitch -eq "off") {
                # Removing flag so VM doesn't boot in Safe Mode
                Log-Output "#05 - Removing safeboot flag for $bcdPath" | Tee-Object -FilePath $logFile -Append
                bcdedit /store $bcdPath /deletevalue $defaultId safeboot
            }
            else {
                # Toggle Mode, check if flag exists
                if ($safeModeIndicator) {
                    # Flag exists, delete to take VM out of Safe Mode
                    Log-Output "#05 - Removing safeboot flag for $bcdPath" | Tee-Object -FilePath $logFile -Append
                    bcdedit /store $bcdPath /deletevalue $defaultId safeboot
                    $safeModeSwitch = "off"
                }
                else {
                    # Flag doesn't exist, adding so VM boots in Safe Mode
                    Log-Output "#05 - Configuring safeboot flag for $bcdPath" | Tee-Object -FilePath $logFile -Append
                    bcdedit /store $bcdPath /set $defaultId safeboot $safeBootVersion
                    $safeModeSwitch = "on"
                }
            }

            # If DC and enabling Safe Mode, set the SecurityLayer key to 0
            if ($isDC -and $safeModeSwitch -eq "on") {
                # Modify the Registry                
                $propertyValue = 0
                $propertyName = "SecurityLayer"
                $propPath = "HKLM:\BROKENSYSTEM\$($controlSetText)\Control\Terminal Server\WinStations\RDP-Tcp"                        

                # Use the same Property Type if reg key exists and no param is passed in, otherwise use DWord
                If ($propertyType -eq "") {
                    $propertyType = "dword"
                }

                if (Test-Path $propPath) {
                    $propertyType = (Get-Item -Path $propPath).getValueKind($propertyName)
                }
                else {
                    # If the path for the new key doesn't exist, create it as well
                    New-Item -Path $propPath -Force -ErrorAction Stop -WarningAction Stop
                }

                # Update the SecurityLayer key
                $previousValueOfKey = Get-ItemPropertyValue -Path $propPath -Name $propertyName
                if ($previousValueOfKey -ne 0) {
                    Log-Output "Modifying Registry key $($propPath) -> $($propertyName) to be $($propertyValue) for login, please reset back to previous value $($previousValueOfKey) after mitigation applied" | Tee-Object -FilePath $logFile -Append
                    $modifiedKey = Set-ItemProperty -Path $propPath -Name $propertyName -type $propertyType -Value $propertyValue -Force -ErrorAction Stop -WarningAction Stop -PassThru
                }
                else {
                    Log-Output "Registry key $($propPath) -> $($propertyName) already set to $($propertyValue) for login" | Tee-Object -FilePath $logFile -Append
                }
            }

            # Unload hive
            if ($regLoaded) {
                Log-Output "Unload attached disk registry hive on $($osDrive)" | Tee-Object -FilePath $logFile -Append
                [gc]::Collect()
                reg unload "HKLM\BROKENSYSTEM"
            }

            if ($guestHyperVVirtualMachine) {
                # Bring disk offline
                Log-Output "#06 - Bringing disk offline" | Tee-Object -FilePath $logFile -Append
                $disk | set-disk -IsOffline $true -ErrorAction Stop

                # Start Hyper-V VM
                Log-Output "#07 - Starting VM" | Tee-Object -FilePath $logFile -Append
                start-vm $guestHyperVVirtualMachine -ErrorAction SilentlyContinue #Sometimes the repair VM doesn't have enough memory to power it on
            }

            Log-Output "END: Please verify status of Safe Mode using MSCONFIG.exe (GUI) or BCDEDIT /enum (shell)" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }
    }
}
catch {

    if ($guestHyperVVirtualMachine) {
        # Bring disk offline again
        Log-Output "#99 - Bringing disk offline to restart Hyper-V VM" | Tee-Object -FilePath $logFile -Append
        $disk | set-disk -IsOffline $true -ErrorAction Stop
    }

    # Log failure scenario
    Log-Error "END: could not start/stop Safe Mode, BCD store may need to be repaired or could not shut down nested Hyper-V VM" | Tee-Object -FilePath $logFile -Append
    throw $_
    return $STATUS_ERROR
}