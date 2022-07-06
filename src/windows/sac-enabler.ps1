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

# DETECT IF GEN2
$partboot='000'
$diskd='000'
get-disk > "$($diskb):\txtempvar"
Select-String -Pattern "Msft Virtual Disk" -Path "$($diskb):\txtempvar" -list -SimpleMatch | select-object -First 1 | %{$diskboot=$_.Line.Split('')[0]}

get-partition -disknumber $diskboot > "$($diskb):\txtempvar"
Select-String -Pattern "System" -Path "$($diskb):\txtempvar" -list -SimpleMatch | select-object -First 1 | %{$partboot=$_.Line.Split('')[0]}

Get-Partition -DiskNumber $diskboot -PartitionNumber $partboot | Set-Partition -NewDriveLetter z

	if ($partboot -ne '000') {write-output "VM is GEN2";$diskd="z:\efi\Microsoft\boot\bcd"}

# DETECT IF GEN1
if ($diskd -eq '000')
{
	foreach ($diskt in $diskarray)
	{
	   	if (Test-Path -Path "$($diskt):\boot")
      	{write-output "VM is GEN1";$diskd="$($diskt):\boot\bcd"}
	}
}

# IN CASE OF FINDER FAILURE WITH MITIGATION REASURE OS DISK IS MOUNTED AS DATA BEFORE CHECKING BOOTMGR
if ($diskb -eq "000") {write-output "SCRIPT COULD NOT FIND A RESCUE OS DISK ATTACHED, EXITING";start-sleep 10;Exit}

# SAC ENABLE
bcdedit /store "$($diskd)" /set "{bootmgr}" displaybootmenu yes
bcdedit /store "$($diskd)" /set "{bootmgr}" timeout 5
bcdedit /store "$($diskd)" /set "{bootmgr}" bootems yes
bcdedit /store "$($diskd)" /ems "{default}" ON
bcdedit /store "$($diskd)" /emssettings EMSPORT:1 EMSBAUDRATE:115200

Remove-Item -force "$($diskb):\txtempvar"

write-output "          ---------------          SCRIPT FINISHED PROPERLY, CHANGES APPLIED          ---------------          "
start-sleep 10
