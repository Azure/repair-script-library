# Welcome to the AUTO SAC(SERIAL ACCESS CONSOLE) AND OS DUMP ENABLER by Daniel Muñoz L!!
# Contact me Daniel Muñoz L : damunozl@microsoft.com if questions.
out-null
cmd /c color 0A
$host.UI.RawUI.WindowTitle = "                                                                                  --== AUTO SAC AND OS DUMP ENABLER by Daniel Muñoz L ==--"

# Rescue OS variable
$diska='C'

# FINDER FOR FAULTY OS DISK
$diskarray = "Q","W","E","R","T","Y","U","I","O","P","S","D","F","G","H","J","K","L","Z","X","V","N","M"
$diskb="000"
foreach ($diskt in $diskarray)
{
   if (Test-Path -Path "$($diskt):\Windows") {$diskb=$diskt} 
}

# IN CASE OF FINDER FAILURE WITH MITIGATION REASURE IF OS DISK EXIST AND IS MOUNTED AS DATADISK BEFORE PROCEDING
if ($diskb -eq "000") {write-output "SCRIPT COULD NOT FIND A RESCUE OS DISK ATTACHED, EXITING";start-sleep 10;Exit}

# DETECT IF GEN2
$partboot='777'
$diskd='000'
$disknumber=$_

Get-WmiObject Win32_DiskDrive | ForEach-Object {
  $disk = $_
  $partitions = "ASSOCIATORS OF " +
                "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
  Get-WmiObject -Query $partitions | ForEach-Object {
    $partition = $_
    $drives = "ASSOCIATORS OF " +
              "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
              "WHERE AssocClass = Win32_LogicalDiskToPartition"
    Get-WmiObject -Query $drives | ForEach-Object {
      New-Object -Type PSCustomObject -Property @{
        X = $_.DeviceID
        Y  = $partition.diskindex
      }
    }
  }
} > "$($diskb):\txtemp"

Select-String -Pattern "$($diskb)" -Path "$($diskb):\txtemp" -List -CaseSensitive | select-object -First 1 | %{$disknumber=$_.Line.Split('')[0]}

get-partition -disknumber $disknumber > "$($diskb):\txtempvar"
Select-String -Pattern "System" -Path "$($diskb):\txtempvar" -list -SimpleMatch | select-object -First 1 | %{$partboot=$_.Line.Split('')[0]}
Get-Partition -DiskNumber $disknumber -PartitionNumber $partboot | Set-Partition -NewDriveLetter z

	if (Test-Path -Path "Z:\efi\Microsoft") {write-output "VM is GEN2";$diskd="Z:\efi\Microsoft\boot\bcd"}

# DETECT IF GEN1
if ($diskd -eq '000')
{
	foreach ($diskt in $diskarray)
	{
	   	if (Test-Path -Path "$($diskt):\boot\bcd")
      	{write-output "VM is GEN1";$diskd="$($diskt):\boot\bcd"}
	}
}

# SAC ENABLE
bcdedit /store "$($diskd)" /set "{bootmgr}" displaybootmenu yes
bcdedit /store "$($diskd)" /set "{bootmgr}" timeout 5
bcdedit /store "$($diskd)" /set "{bootmgr}" bootems yes
bcdedit /store "$($diskd)" /ems "{default}" ON
bcdedit /store "$($diskd)" /emssettings EMSPORT:1 EMSBAUDRATE:115200

Remove-Item -force "$($diskb):\txtempvar"

# Hive loader into rescue VM
reg.exe load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
Start-sleep 3

# ENABLE OS DUMP
REG ADD "HKLM\BROKENSYSTEM\ControlSet001\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 1 /f
REG ADD "HKLM\BROKENSYSTEM\ControlSet001\Control\CrashControl" /v DumpFile /t REG_EXPAND_SZ /d "%SystemRoot%\MEMORY.DMP" /f
REG ADD "HKLM\BROKENSYSTEM\ControlSet001\Control\CrashControl" /v NMICrashDump /t REG_DWORD /d 1 /f

REG ADD "HKLM\BROKENSYSTEM\ControlSet002\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 1 /f
REG ADD "HKLM\BROKENSYSTEM\ControlSet002\Control\CrashControl" /v DumpFile /t REG_EXPAND_SZ /d "%SystemRoot%\MEMORY.DMP" /f
REG ADD "HKLM\BROKENSYSTEM\ControlSet002\Control\CrashControl" /v NMICrashDump /t REG_DWORD /d 1 /f

reg unload "HKLM\BROKENSYSTEM"

write-output "          ---------------          SCRIPT FINISHED PROPERLY, CHANGES APPLIED          ---------------          "
start-sleep 10
