# Welcome to the VM Azure Agent Offline fixer by Daniel Muñoz L!
# Contact me Daniel Muñoz L : damunozl@microsoft.com if questions.
out-null
cmd /c color 0A
$host.UI.RawUI.WindowTitle = "                                                                                  --== VMAgent Offline Fixer by Daniel Muñoz L ==--"

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
reg export "HKLM\BROKENSYSTEM" "$($diskb):\regbackupbeforeGAchanges" /y

# EXPORTING GOOD VMAGENT REGS FROM RESCUE VM
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureGuestAgent" "$($diskb):\WAGA.reg" /y
# Telemetry service was merged into rdagent so you can expect an error from wats
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureTelemetryService" "$($diskb):\WATS.reg"  /y
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RdAgent" "$($diskb):\RdAgent.reg" /y

# MODIFYING REG FILES WITH GOOD REG KEYS
# WAAGENT MODIFICATIONS
(gc "$($diskb):\waga.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\waga.reg"

# TELEMETRY MODIFICATIONS
# Telemetry service was merged into rdagent so an error might be expected from wats key
(gc "$($diskb):\wats.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\wats.reg"
(gc "$($diskb):\wats.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\wats.reg"
(gc "$($diskb):\wats.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\wats.reg"

# RDAGENT MODIFICATIONS
(gc "$($diskb):\RdAgent.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\RdAgent.reg"
(gc "$($diskb):\RdAgent.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\RdAgent.reg"
(gc "$($diskb):\RdAgent.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\RdAgent.reg"

# ADDING REG FILES IN %diskb% DRIVE
regedit /s "$($diskb):\WATS.reg"
regedit /s "$($diskb):\WAGA.reg"
regedit /s "$($diskb):\RdAgent.reg"

# BACKUP TAKEN ON FOLDER $($diskb):\WindowsazurefaultyGAbackup"
mkdir "$($diskb):\WindowsazurefaultyGAbackup"
xcopy "$($diskb):\WindowsAzure" "$($diskb):\WindowsazurefaultyGAbackup" /e /h /y

# RESTORING VMAgent BIN FILES
del "$($diskb):\WindowsAzure" -force -recurse
mkdir "$($diskb):\WindowsAzure"
xcopy "$($diska):\WindowsAzure" "$($diskb):\WindowsAzure" /e /h /y
del "$($diskb):\WindowsAzure\logs" -force -recurse

# Unloading HIVE"
reg.exe unload "HKLM\BROKENSYSTEM"
del "$($diskb):\rdagent.reg" -force
del "$($diskb):\waga.reg" -force
del "$($diskb):\wats.reg" -force

write-output "   --------------   SCRIPT FINISHED PROPERLY, BACKUP OF PREVIOUS GA IS IN ROOT AS WindowsazurefaultyGAbackup folder and registry backup as regbackupbeforeGAchanges   --------------   "
start-sleep 10
