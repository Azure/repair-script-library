<#
.SYNOPSIS
    Enables Last Known Good Configuration (LKGC) and logs registry state changes.
    Increment Last Known Good Configuration registry values by 1.
   Public docs: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/start-vm-last-known-good, #     https://support.microsoft.com/en-us/topic/you-receive-error-stop-error-code-0x0000007b-inaccessible-boot-device-after-you-install-windows-updates-7cc844e4-4daf-a71c-cd23-f99b50d53e31
 
 .RESOLVES
   If Windows is not booting correctly due to recently installed software or related changes, modifying the LKGC values 
   can revert the changes to attempt a successful boot.
   If you've recently installed new software or changed some Windows settings, and your Azure Windows virtual machine (VM) stops booting correctly, 
   you might have to start the VM by using the Last Known Good Configuration for troubleshooting. 
   Created by Tony.Mocanu@Microsoft.com
#>

# 1. Import common logic
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

$logFile = "$env:SystemDrive\Repair-LKGC.log"

try {
    Log-Info "Starting AUTO LKGC Script..." | Tee-Object -FilePath $logFile -Append

    # 2. Finder for faulty OS letter
    $diskb = "000"
    $diskarray = "d","q","w","e","r","t","y","u","i","o","p","s","f","g","h","j","k","l","z","x","v","n","m"
    foreach ($diskt in $diskarray) {
        if (Test-Path -Path "$($diskt):\Windows") { $diskb = $diskt; break }
    }

    if ($diskb -eq "000") {
        Log-Error "SCRIPT COULD NOT FIND A RESCUE OS DISK ATTACHED" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # 3. OS Version Peek
    reg.exe load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\software"
    Start-Sleep -Seconds 2
    $productName = (Get-ItemProperty -path 'registry::hklm\BROKENSYSTEM\microsoft\windows nt\currentversion').ProductName
    $winosver = 0
    if ($productName -match '(\d+)') { $winosver = [int]$matches[1] }
    reg.exe unload "HKLM\BROKENSYSTEM"

    # 4. Hive loader
    Log-Info "Loading System hive from $($diskb):..." | Tee-Object -FilePath $logFile -Append
    reg.exe load "HKU\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
    Start-Sleep -Seconds 2

    # 5. Capture "BEFORE" State
    $selectPath = "Registry::HKU\BROKENSYSTEM\Select"
    $before = Get-ItemProperty -path $selectPath
    Log-Info "REGISTRY STATE [BEFORE]: Current=$($before.current), Default=$($before.default), Failed=$($before.failed), LKG=$($before.LastKnownGood)" | Tee-Object -FilePath $logFile -Append

    # 6. Logic Filter
    $alreadySet = $false
    if (($winosver -eq 10) -or ($winosver -ge 2016)) {
        if (($before.current -ge 2) -or ($before.default -ge 2) -or ($before.failed -ge 1) -or ($before.LastKnownGood -ge 2)) { $alreadySet = $true }
    }
    elseif ($winosver -eq 2012) {
        if (($before.current -ge 2) -or ($before.default -ge 2) -or ($before.failed -ge 1) -or ($before.LastKnownGood -ge 3)) { $alreadySet = $true }
    }

    if ($alreadySet) {
        reg.exe unload "HKU\BROKENSYSTEM"
        Log-Warning "LKGC WAS ALREADY SET, NO CHANGES DONE" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # 7. Apply Changes
    Log-Info "Applying LKGC increments..." | Tee-Object -FilePath $logFile -Append
    Set-Itemproperty -path $selectPath -Name 'current' -Type DWORD -value ($before.current + 1)
    Set-Itemproperty -path $selectPath -Name 'default' -Type DWORD -value ($before.default + 1)
    Set-Itemproperty -path $selectPath -Name 'failed' -Type DWORD -value ($before.failed + 1)
    Set-Itemproperty -path $selectPath -Name 'LastKnownGood' -Type DWORD -value ($before.LastKnownGood + 1)

    # 8. Capture "AFTER" State
    $after = Get-ItemProperty -path $selectPath
    Log-Info "REGISTRY STATE [AFTER]:  Current=$($after.current), Default=$($after.default), Failed=$($after.failed), LKG=$($after.LastKnownGood)" | Tee-Object -FilePath $logFile -Append

    # 9. Cleanup
    reg.exe unload "HKU\BROKENSYSTEM"
    Log-Output "SCRIPT FINISHED PROPERLY, LKGC APPLIED" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS

}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    reg.exe unload "HKU\BROKENSYSTEM" 2>$null
    reg.exe unload "HKLM\BROKENSYSTEM" 2>$null
    return $STATUS_ERROR
}
finally {
    Log-Info "Script execution ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}
