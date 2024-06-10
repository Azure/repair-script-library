#########################################################################################################
<#
# .SYNOPSIS
#  Modify the registry on an OS disk attached to a Rescue VM as an Azure Data Disk. v0.2.1
#
# .NOTES
#   Author: Ryan McCallum
#   Sources:
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty
#
# .PARAMETER rootKey
#   [Optional] "HKLM" by default. Add shortcut version for other hives if using another hive (e.g. HKEY_CURRENT_USER would be HKCU).
#
# .PARAMETER hive
#   [Optional] "System" to target System Registry (default), "Software" to target Software registry, etc.
#       https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives
#
# .PARAMETER controlSet
#   [Optional] Enter the controlSet manually. Optional as script will normally select the last active Control Set if using the System reg
#       via Get-ItemProperty -Path "HKLM:\brokenSYSTEM\Select" -Name Current.
#
# .PARAMETER relativePath
#   Path to reg key after the hive and control set. Add backticks to escape spaces and surround the string in single quotes.
#   E.G. to target the following key on the Rescue VM:
#       HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp
#   You will just need to enter the following for the relative path:
#       'Control\Terminal` Server\WinStations\RDP-Tcp'
#
# .PARAMETER propertyName
#   Add the name of the property that we are adding or updating.
#
# .PARAMETER propertyType
#   [Optional] Add the type of the property that we are adding or updating. Necessary if a new value,
#   not necessary if updating already existing value. Follows the naming convention of the following doc:
#       https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty
#
# .PARAMETER propertyValue
#   Add the value of the property/entry that we are adding or updating.
#
# .EXAMPLE
#   <# This will run Set-ItemProperty -Path "HKLM:\brokenSystemF\ControlSet001\Control\Terminal Server" -name fDenyTSConnections -type DWORD -Value 0 #>
#   <# Where brokenSystemF is the System hive from the attached OS disk's F: partition #>
#   az vm repair run -g sourceRG -n problemVM --run-id win-update-registry --run-on-repair --parameters rootKey=HKLM hive=SYSTEM controlSet=1 relativePath='Control\Terminal` Server' propertyName=fDenyTSConnections propertyValue=0 propertyType=dword
#
#>
#########################################################################################################

# Set the Parameters for the script
Param(
    [Parameter(Mandatory = $false)][ValidateSet("HKLM", "HKCC", "HKCR", "HKCU", "HKU")][string]$rootKey = "HKLM",
    [Parameter(Mandatory = $false)][string]$hive = "System",
    [Parameter(Mandatory = $false)][ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")][string]$propertyType = "",
    [Parameter(Mandatory = $false)][ValidateSet(1, 2)] [Int]$controlSet,
    [Parameter(Mandatory = $true)][string]$relativePath = "",
    [Parameter(Mandatory = $true)][string]$propertyName = "",
    [Parameter(Mandatory = $true)][string]$propertyValue = ""
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Declare variables
$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptPath = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"
$scriptStartTime | Tee-Object -FilePath $logFile -Append

# Start
Log-Output "START: Running script win-update-registry.ps1" | Tee-Object -FilePath $logFile -Append

try {
    # Declaring variables
    $fixedDrives = @()
    $modifiedKey = @()

    # Make sure guest VM is shut down
    $guestHyperVVirtualMachine = Get-VM -ErrorAction Continue -WarningAction Continue
    $guestHyperVVirtualMachineName = $guestHyperVVirtualMachine.VMName
    if ($guestHyperVVirtualMachine) {
        if ($guestHyperVVirtualMachine.State -eq 'Running') {
            Log-Output "Stopping nested guest VM $guestHyperVVirtualMachineName" | Tee-Object -FilePath $logFile -Append
            try{
                Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
            } catch{
                Log-Warning "Failed to stop nested guest VM $($guestHyperVVirtualMachineName), will continue script but may have limited success" | Tee-Object -FilePath $logFile -Append
            }

        }
    }
    else {
        Log-Output "No running nested guest VM, continuing" | Tee-Object -FilePath $logFile -Append
    }


    # Make sure the disk is online
    Log-Output "Bringing partition(s) online if present" | Tee-Object -FilePath $logFile -Append
    $disk = Get-Disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | Set-Disk -IsOffline $false -ErrorAction SilentlyContinue

    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | Group-Object DiskNumber
    $fixedDrives = $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter

    Log-Output "Determine if partition has Registry hives" | Tee-Object -FilePath $logFile -Append

    # Scan all collected partitions to determine if OS partition
    ForEach ($drive in $fixedDrives) {
        if ($drive.ToString() -ne "") {

            # Check if partition has Registry path
            $regPath = $drive + ':\Windows\System32\config\'
            $isRegPath = Test-Path $regPath

            # If Registry path found, continue script
            if ($isRegPath) {

                Log-Output "Load requested Registry hive from $($drive)" | Tee-Object -FilePath $logFile -Append

                # Load hive into Rescue VM's registry from attached disk
                cmd /c "reg load $($rootKey)\broken$($hive)$($drive) $($drive):\Windows\System32\config\$($hive)" | Tee-Object -FilePath $logFile -Append

                # Verify the active Control Set if using the System registry and if not already defined (1 is ControlSet001, 2 is ControlSet002)
                if ($hive -eq "system") {
                    Log-Output "Using a SYSTEM hive, getting specified Control Set" | Tee-Object -FilePath $logFile -Append
                    $controlSetText = "ControlSet00"
                    if ($controlSet -eq "") {
                        $controlSet = (Get-ItemProperty -Path "$($rootKey):\broken$($hive)$($drive)\Select" -Name Current).Current
                    }
                    $controlSetText += $controlSet
                    Log-Output "Using $($controlSetText)" | Tee-Object -FilePath $logFile -Append
                    $controlSetText += "\"
                }
                else {
                    $controlSetText = ""
                    Log-Output "Not using a SYSTEM hive, using $($hive)" | Tee-Object -FilePath $logFile -Append
                }

                # Report the key
                $propPath = "$($rootKey):\broken$($hive)$($drive)\$($controlSetText)$($relativePath)"
                Log-Output "Checking registry for $($propPath)" | Tee-Object -FilePath $logFile -Append
                Get-ItemProperty -Path $propPath -Name $propertyName -ErrorAction Continue -WarningAction Continue | Tee-Object -FilePath $logFile -Append

                # Modify the Registry
                Log-Output "Modify Registry key $($propPath)" | Tee-Object -FilePath $logFile -Append

                # Use the same Property Type if reg key exists and no param is passed in, otherwise use DWord
                If ($propertyType -eq "") {
                    $propertyType = "dword"
                }

                if (Test-Path $propPath) {
                    $propertyType = (Get-Item -Path $propPath).getValueKind($propertyName)
                }
                else {
                    # If the path for the new key doesn't exist, create it as well
                    New-Item -Path $propPath -Force -ErrorAction Stop -WarningAction Stop | Out-Null
                }
            }

            # Update the key
            $modifiedKey = Set-ItemProperty -Path $propPath -Name $propertyName -type $propertyType -Value $propertyValue -Force -ErrorAction Stop -WarningAction Stop -PassThru
            Log-Output $modifiedKey

            # Unload hive
            Log-Output "Unload attached disk registry hive on $($drive)" | Tee-Object -FilePath $logFile -Append
            [gc]::Collect()
            cmd /c "reg unload $($rootKey)\broken$($hive)$($drive)"
        }
        else {
            Log-Warning "No Registry found on $($drive)" | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Warning "Could not parse drive: $($drive)" | Tee-Object -FilePath $logFile -Append
    }

    Log-Output "END: Script Successful, modified key:" | Tee-Object -FilePath $logFile -Append
    Log-Output $modifiedKey | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS

}
catch {
    Log-Error "END: Script failed with error: $_" | Tee-Object -FilePath $logFile -Append
    throw $_
    return $STATUS_ERROR
}
finally {
    $scriptEndTime = Get-Date -f yyyyMMddHHmmss
    $scriptEndTime | Tee-Object -FilePath $logFile -Append
}
