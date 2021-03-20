. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-rdp-safe-mode

# Initialize script log variables
$scriptStartTime = get-date -f yyyyMMddHHmmss
$scriptPath = split-path -path $MyInvocation.MyCommand.Path -parent
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]

# Initialize script log
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
Log-Info 'START: Running Script win-toggle-safe-mode' | out-file -FilePath $logFile -Append
$scriptStartTime | out-file -FilePath $logFile -Append

# Make sure guest VM is shut down
$guestHyperVVirtualMachine = Get-VM
Log-Info "#01 - Stopping nested guest VM $guestHyperVVirtualMachine.VMName" | out-file -FilePath $logFile -Append
$return = Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force

# Make sure the disk is online
Log-Info "#02 - Bringing disk online" | out-file -FilePath $logFile -Append
$disk = get-disk -ErrorAction Stop | where {$_.FriendlyName -eq 'Msft Virtual Disk'}
$return = $disk | set-disk -IsOffline $false -ErrorAction Stop
 
# Handle disk partitions
$partitionlist = Get-Disk-Partitions
Log-Info $partitionlist | out-file -FilePath $logFile -Append
$partitionGroup = $partitionlist | group DiskNumber | out-file -FilePath $logFile -Append

Log-Info '#03 - enumerate partitions to reconfigure boot cfg' | out-file -FilePath $logFile -Append

forEach ( $partitionGroup in $partitionlist | group DiskNumber )
{
    #reset paths for each part group (disk)
    $isBcdPath = $false
    $bcdPath = ''
    $bcdDrive = ''
    $isOsPath = $false
    $osPath = ''
    $osDrive = ''

    #scan all partitions of a disk for bcd store and os file location 
    ForEach ($drive in $partitionGroup.Group | select -ExpandProperty DriveLetter )
    {      
        #check if no bcd store was found on the previous partition already
        if ( -not $isBcdPath )
        {
            $bcdPath =  $drive + ':\boot\bcd'
            $bcdDrive = $drive + ':'
            $isBcdPath = Test-Path $bcdPath

            #if no bcd was found yet at the default location look for the uefi location too
            if ( -not $isBcdPath )
            {
                $bcdPath =  $drive + ':\efi\microsoft\boot\bcd'
                $bcdDrive = $drive + ':'
                $isBcdPath = Test-Path $bcdPath
            } 
        }        

        #check if os loader was found on the previous partition already
        if (-not $isOsPath)
        {
            $osPath = $drive + ':\windows\system32\winload.exe'
            $isOsPath = Test-Path $osPath
            if ($isOsPath)
            {
                $osDrive = $drive + ':'
            }
        }
    }
        #if both was found grab bcd store
    if ( $isBcdPath -and $isOsPath )
    {
        # Get Safe Mode State
        Log-Info "#04 - Checking safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
        $bcdout = bcdedit /store $bcdPath /enum
        $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
        $defaultId = '{'+$defaultLine.ToString().Split('{}')[1] + '}'
        $safeModeIndicator = $bcdout | Select-String 'safeboot' | select -First 1

        # Check if flag exists
        if ($safeModeIndicator)
        {            
            
            # Flag exists, delete to take VM out of Safe Mode
            Log-Info "#05 - Removing safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
            bcdedit /store $bcdPath /deletevalue $defaultId safeboot
         
        } else {
            
            # Flag doesn't exist, adding so VM boots in Safe Mode
            Log-Info "#05 - Configuring safeboot flag for $bcdPath" | out-file -FilePath $logFile -Append
            bcdedit /store $bcdPath /set $defaultId safeboot network
        }

        # Bring disk offline 
        Log-Info "Bringing disk offline" | out-file -FilePath $logFile -Append
        $return = $disk | set-disk -IsOffline $true -ErrorAction Stop

        # Start Hyper-V VM
        Log-Info "END: Starting VM, please verify Safe Mode w/ Networking using MSCONFIG.exe" | out-file -FilePath $logFile -Append
        $return = start-vm $guestHyperVVirtualMachine -ErrorAction Stop

        return $STATUS_SUCCESS
    }
}

# Log failure to run successfully
Log-Error "Unable to find the BCD Path" | out-file -FilePath $logFile -Append

# Bring disk offline again
Log-Info "Bringing disk offline" | out-file -FilePath $logFile -Append
$return = $disk | set-disk -IsOffline $true -ErrorAction Stop

# Start Hyper-V VM again
Log-Info "END: could not start Safe Mode, BCD store may need to be repaired" | out-file -FilePath $logFile -Append
$return = start-vm $guestHyperVVirtualMachine -ErrorAction Stop

return $STATUS_ERROR
