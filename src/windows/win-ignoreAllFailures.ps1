# .SUMMARY
#   Ignore errors if there is a failed boot, failed shutdown, or failed checkpoint. The computer will attempt to boot normally after an error occurs.
#   Reconfigures the Boot Configuration Data settings so the boot status policy is set to IgnoreAllFailures. 
# 
# .RESOLVES
#   If the server is booting into the Windows Error Recovery console or the Automatic Repair console, it may fail to recover the system 
#   and will obscure the actual boot error. This script disables this per recommendation.
#   


. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1


$partitionlist = Get-Disk-Partitions
Log-Info $partitionlist
$partitionGroup = $partitionlist | group DiskNumber 

Log-Info '#03 - enumerate partitions to reconfigure boot cfg'

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

    #if both was found update bcd store
    if ( $isBcdPath -and $isOsPath )
    {
        Log-Info "#04 - setting bcd recovery and default id for $bcdPath"
        $bcdout = bcdedit /store $bcdPath /enum bootmgr /v
        $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
        $defaultId = '{'+$defaultLine.ToString().Split('{}')[1] + '}'
        bcdedit /store $bcdPath /default $defaultId
        bcdedit /store $bcdPath /set $defaultId  bootstatuspolicy IgnoreAllFailures
        return $STATUS_SUCCESS
    }
}

Log-Error "Unable to find the BCD Path"
return $STATUS_ERROR
