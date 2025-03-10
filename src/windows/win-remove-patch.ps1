######################################################################################################
#
# .SYNOPSIS
#   Remove an installed Windows patch for the nested Hyper-V server on a Rescue VM.
#
# .DESCRIPTION
#   Remove an installed Windows patch for the nested Hyper-V server on a Rescue VM using DISM. This will be helpful if the attached OS disk is from a VM that is in a nonboot state due to corrupted/failing updates.
#   Accepts a single string parameter from a user that matches a package specified from win-get-patches. Uses DISM to remove that package from the attached OS disk.

# .RESOLVES
#   Removing problematic patches can be difficult when the OS refuses to boot. This will be helpful to run on the repair VM after win-get-patches to attempt removal.
# Public doc: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options?view=windows-11#remove-package
#
# .PARAMETER packageName
#   Name of package that we are uninstalling. Run 'win-get-patches' to get a list of installed/pending packages. Enter
#
# .EXAMPLE
#	<# Get installed patches #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-get-patches' --verbose --run-on-repair
#
#	<# Then remove one of the returned patches #>
#   az vm repair run -g 'sourceRG' -n 'sourceVM' --run-id 'win-remove-patch' --parameters packageName='Package_for_KB1234567~31bf3856ad364e35~amd64~~17763.2090.1.3' --verbose --run-on-repair
#
# .NOTES
#   Author: Ryan McCallum
#
# .VERSION
#   v0.1: Initial commit
#
#######################################################################################################

# Set the Parameters for the script
Param(
    [Parameter(Mandatory = $true)][string]$packageName = ''
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
Log-Output "START: Running script win-remove-patch for $($packageName)" | Tee-Object -FilePath $logFile -Append

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
           Log-Output "#04 - Found OS directory at $($drive), removing patch $($packageName)" | Tee-Object -FilePath $logFile -Append
           $packageName = $packageName.Trim()
           cmd /c "dism /image:$($drive):\ /Remove-Package /PackageName:$($packageName)" | Tee-Object -FilePath $logFile -Append
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
