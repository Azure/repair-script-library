# Welcome to the AUTO SAC ENABLER(SERIAL ACCESS CONSOLE) by Daniel Muñoz L!
# Contact me Daniel Muñoz L : damunozl@microsoft.com if questions.
out-null
cmd /c color 0A
$host.UI.RawUI.WindowTitle = "                                                                                  --== AUTO SAC ENABLER by Daniel Muñoz L ==--"

# Rescue OS variable
$diska='c'

# FINDER FOR FAULTY OS DISK
$diskarray = "q","w","e","r","t","y","u","i","o","p","s","d","f","g","h","j","k","l","z","x","v","n","m"
$diskb="000"
foreach ($diskt in $diskarray)
{
   if (Test-Path -Path "$($diskt):\Windows") {$diskb=$diskt} 
}

# ADDING BCD DRIVE
$diskc="000"
foreach ($diskt in $diskarray)
{
   if ((Test-Path -Path "$($diskt):\efi") -or (Test-Path -Path "$($diskt):\boot")){$diskc=$diskt} 
}

# ADDING BCD PATH
$diskd="000"
foreach ($diskt in $diskarray)
{
   if (Test-Path -Path "$($diskt):\efi") 
      {write-output "VM is GEN2";$diskd="$($diskc):\efi\Microsoft\boot\bcd"}
   elseif (Test-Path -Path "$($diskt):\boot")
      {write-output "VM is GEN1";$diskd="$($diskc):\boot\bcd"}
}

# IN CASE OF FINDER FAILURE WITH MITIGATION REASURE OS DISK IS MOUNTED AS DATA BEFORE CHECKING BOOTMGR
if ($diskb -eq "000") {write-output "SCRIPT COULD NOT FIND A RESCUE OS DISK ATTACHED, EXITING";start-sleep 10;Exit}
if ($diskc -eq "000") {write-output "SCRIPT COULD NOT FIND A BOOT FOLDER, EXITING";start-sleep 10;Exit}

# SAC ENABLE
bcdedit /store "$($diskd)" /set "{bootmgr}" displaybootmenu yes
bcdedit /store "$($diskd)" /set "{bootmgr}" timeout 5
bcdedit /store "$($diskd)" /set "{bootmgr}" bootems yes
bcdedit /store "$($diskd)" /ems "{default}" ON
bcdedit /store "$($diskd)" /emssettings EMSPORT:1 EMSBAUDRATE:115200

write-output "          ---------------          SCRIPT FINISHED PROPERLY, CHANGES APPLIED          ---------------          "
start-sleep 10

