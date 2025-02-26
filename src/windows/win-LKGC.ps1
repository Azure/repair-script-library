# Welcome to the AUTO LKGC(Last Known Good Configuration) by Daniel Muñoz L!
# Contact me Daniel Muñoz L : damunozl@microsoft.com if questions.
# .SUMMARY
#   Last Known Good Configuration enabler offline from rescue VM.
#   Increment Last Known Good Configuration registry values by 1.
#   Public docs: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/start-vm-last-known-good, 
#     https://support.microsoft.com/en-us/topic/you-receive-error-stop-error-code-0x0000007b-inaccessible-boot-device-after-you-install-windows-updates-7cc844e4-4daf-a71c-cd23-f99b50d53e31
# 
# .RESOLVES
#   If Windows is not booting correctly due to recently installed software or related changes, modifying the LKGC values 
#   can revert the changes to attempt a successful boot.
#   If you've recently installed new software or changed some Windows settings, and your Azure Windows virtual machine (VM) stops booting correctly, 
#   you might have to start the VM by using the Last Known Good Configuration for troubleshooting. 

out-null
cmd /c color 0A
$host.UI.RawUI.WindowTitle = "                                                                                  --== AUTO LKGC by Daniel Muñoz L ==--"

# Rescue OS variable
$diska='c'

# Finder for faulty OS letter
$diskarray = "d","q","w","e","r","t","y","u","i","o","p","s","f","g","h","j","k","l","z","x","v","n","m"
$diskb="000"
foreach ($diskt in $diskarray)
{
   if (Test-Path -Path "$($diskt):\Windows")
   {
    $diskb=$diskt
    } 
}

# IN CASE OF FINDER FAILURE
if ($diskb -eq "000") {write-output "SCRIPT COULD NOT FIND A RESCUE OS DISK ATTACHED, EXITING";start-sleep 10;Exit}

# OS VER PEEK
reg.exe load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\software"
Start-sleep 3
(Get-ItemProperty -path 'registry::hklm\BROKENSYSTEM\microsoft\windows nt\currentversion').ProductName | %{ [int]$winosver=$_.Split(' ')[1]; }
(Get-ItemProperty -path 'registry::hklm\BROKENSYSTEM\microsoft\windows nt\currentversion').ProductName | %{ [int]$winosver=$_.Split(' ')[2]; }
reg.exe unload "HKLM\BROKENSYSTEM"
Start-sleep 3

# Hive loader into rescue VM
reg.exe load "HKU\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
Start-sleep 3

# Acquiring reg values
$currentreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).current
$defaultreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).default
$failedreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).failed
$lkgcreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).LastKnownGood

# FILTER IF LKGC IS ALREADY THERE FOR Windows 10, Windows Server 2016, and newer versions.
if (($winosver -eq 10) -or ($winosver -ge 2016)) 
{
if ($currentreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($defaultreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($failedreg -ge 1) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($lkgcreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
}

# FILTER IF LKGC IS ALREADY THERE FOR Windows Server 2012 version.
if ($winosver -eq 2012) 
{
# CHECK IF LKGC IS ALREADY THERE AND EXIT IF SO
if ($currentreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($defaultreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($failedreg -ge 1) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
elseif ($lkgcreg -ge 3) {reg.exe unload "HKU\BROKENSYSTEM";write-output "LKGC WAS ALREADY SET, NO CHANGES DONE";start-sleep 5;exit}
}

# Plus 1
$currentreg = $currentreg+1
$defaultreg = $defaultreg+1
$failedreg = $failedreg+1
$lkgcreg = $lkgcreg+1

# ENABLING LKGC
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'current' -Type DWORD -value $currentreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'default' -Type DWORD -value $defaultreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'failed' -Type DWORD -value $failedreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'LastKnownGood' -Type DWORD -value $lkgcreg

# Unload Hive
reg.exe unload "HKU\BROKENSYSTEM"

write-output "          ---------------          SCRIPT FINISHED PROPERLY, LKGC APPLIED          ---------------          "
start-sleep 10
