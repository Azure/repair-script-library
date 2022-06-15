# Welcome to the DHCP SERVICE fixer by Daniel Muñoz L!
# Contact me Daniel Muñoz L : damunozl@microsoft.com if questions.
# REF: https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-rdp-dhcp-disabled#attach-the-os-disk-to-a-recovery-vm

out-null
cmd /c color 0A
$host.UI.RawUI.WindowTitle = "                                                                                  --== DHCP SERVICE Fixer by Daniel Muñoz L ==--"

# Rescue OS variable
$diska='c'

# FINDER FOR FAULTY OS DRIVE
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

# HIVE LOADER
# A Backup of the BROKENSYSTEM was taken and left on $($diskb):\ as regbackupbeforeGAchanges just in case!
reg load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
reg export "HKLM\BROKENSYSTEM" "$($diskb):\regbackupbeforeTSchanges" /y

# APPLYING DHCP FIX TO ENABLE IT
reg add "HKLM\BROKENSYSTEM\ControlSet001\services\DHCP" /v start /t REG_DWORD /d 2 /f
reg add "HKLM\BROKENSYSTEM\ControlSet001\services\DHCP" /v ObjectName /t REG_SZ /d "NT Authority\LocalService" /f
reg add "HKLM\BROKENSYSTEM\ControlSet001\services\DHCP" /v type /t REG_DWORD /d 16 /f
reg add "HKLM\BROKENSYSTEM\ControlSet002\services\DHCP" /v start /t REG_DWORD /d 2 /f
reg add "HKLM\BROKENSYSTEM\ControlSet002\services\DHCP" /v ObjectName /t REG_SZ /d "NT Authority\LocalService" /f
reg add "HKLM\BROKENSYSTEM\ControlSet002\services\DHCP" /v type /t REG_DWORD /d 16 /f

# Unloading HIVE"
reg.exe unload "HKLM\BROKENSYSTEM"

write-output "   --------------   SCRIPT FINISHED PROPERLY, BACKUP OF REGISTRY WAS ADDED AS regbackupbeforeGAchanges FROM ROOT   --------------   "
start-sleep 10
