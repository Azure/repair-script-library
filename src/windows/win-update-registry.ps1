#########################################################################################################
<#
# .SYNOPSIS
#  Modify the registry on an OS disk attached to a Rescue VM as an Azure Data Disk. v0.2.0
#
# .NOTES
#   Author: Ryan McCallum
#   Sources:
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty?view=powershell-7.1
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
#       https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty?view=powershell-7.1
#
# .PARAMETER propertyValue
#   Add the value of the property/entry that we are adding or updating.
#
# .EXAMPLE
#   <# This will run Set-ItemProperty -Path "HKLM:\brokenSystemF\ControlSet001\Control\Terminal Server" -name fDenyTSConnections -type DWORD -Value 0 #>
#   <# Where brokenSystemF is the System hive from the attached OS disk's F: partition #>
#   az vm repair run -g sourceRG -n problemVM --run-id win-update-registry --run-on-repair --parameters rootKey=HKLM hive=SYSTEM controlSet=1
#     relativePath='Control\Terminal` Server' propertyName=fDenyTSConnections propertyValue=0 propertyType=dword
#
#>
#########################################################################################################

# Set the Parameters for the script
Param(
    [Parameter(Mandatory = $false)][ValidateSet("HKLM", "HKCC", "HKCR", "HKCU", "HKU")][string]$rootKey = "HKLM",
    [Parameter(Mandatory = $false)][ValidateSet("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "HARDWARE", "DEFAULT")][string]$hive = "System",
    [Parameter(Mandatory = $false)][ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")][string]$propertyType = "",
    [Parameter(Mandatory = $false)][ValidateSet(1, 2)] [Int]$controlSet,
    [Parameter(Mandatory = $true)][string]$relativePath = "",
    [Parameter(Mandatory = $true)][string]$propertyName = "",
    [Parameter(Mandatory = $true)][string]$propertyValue = ""
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1
Log-Output "START: Running script win-update-registry.ps1"

try {
    # Declaring variables
    $fixedDrives = @()
    $modifiedKey = @()

    # Make sure the disk is online
    Log-Output "Bringing partition(s) online if present"
    $disk = Get-Disk -ErrorAction Stop | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
    $disk | Set-Disk -IsOffline $false -ErrorAction SilentlyContinue

    # Handle disk partitions
    $partitionlist = Get-Disk-Partitions
    $partitionGroup = $partitionlist | Group-Object DiskNumber
    $fixedDrives = $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter

    Log-Output "Determine if partition has Registry hives"

    # Scan all collected partitions to determine if OS partition
    ForEach ($drive in $fixedDrives) {
        if ($drive.ToString() -ne "") {

            # Check if partition has Registry path
            $regPath = $drive + ':\Windows\System32\config\'
            $isRegPath = Test-Path $regPath

            # If Registry path found, continue script
            if ($isRegPath) {

                Log-Output "Load requested Registry hive from $($drive)"

                # Load hive into Rescue VM's registry from attached disk
                reg load "$($rootKey)\broken$($hive)$($drive)" "$($drive):\Windows\System32\config\$($hive)"

                # Verify the active Control Set if using the System registry and if not already defined (1 is ControlSet001, 2 is ControlSet002)
                if ($hive -eq "system") {
                    Log-Output "Using a System registry, getting specified Control Set"
                    $controlSetText = "ControlSet00"
                    if ($controlSet -eq "") {
                        $controlSet = (Get-ItemProperty -Path "$($rootKey):\broken$($hive)$($drive)\Select" -Name Current).Current
                    }
                    $controlSetText += $controlSet
                    $controlSetText += "\"
                }
                else {
                    $controlSetText = ""
                }

                # Modify the Registry
                $propPath = "$($rootKey):\broken$($hive)$($drive)\$($controlSetText)$($relativePath)"
                Log-Output "Modify Registry key $($propPath)"

                # Use the same Property Type if reg key exists and no param is passed in, otherwise use DWord
                If ($propertyType -eq "") {
                    if (Test-Path $propPath) {
                        $propertyType = (Get-Item -Path $propPath).getValueKind($propertyName)
                    }
                    else {
                        # If the path for the new key doesn't exist, create it as well
                        $propertyType = "dword"
                        New-Item -Path $propPath -Force -ErrorAction Stop -WarningAction Stop | Out-Null
                    }
                }

                $modifiedKey += "Drive $($drive)"
                $modifiedKey += Set-ItemProperty -Path $propPath -Name $propertyName -type $propertyType -Value $propertyValue -Force -ErrorAction Stop -WarningAction Stop -PassThru

                # Unload hive
                Log-Output "Unload attached disk registry hive on $($drive)"
                [gc]::Collect()
                reg unload "$($rootKey)\broken$($hive)$($drive)"
            }
            else {
                Log-Warning "No Registry found on $($drive)"
            }
        }
        else {
            Log-Warning "Could not parse drive: $($drive)"
        }
    }
    Log-Output "END: Script Successful, modified key:"
    Log-Output $modifiedKey
    return $STATUS_SUCCESS
}

# Log failure scenario
catch {
    Log-Error "END: Script failed"
    throw $_
    return $STATUS_ERROR
}
