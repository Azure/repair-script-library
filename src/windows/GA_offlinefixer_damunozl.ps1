# Contact me Daniel Muñoz L : damunozl@microsoft.com if support is required.
# Echo off null outputs
out-null

# Change color, title and welcome
cmd /c color 0A
$title="                                                                                  --== VMAgent Fixer by Daniel Muñoz L ==--"
$host.UI.RawUI.WindowTitle = $Title
# Welcome to the VMAgent fixer by Daniel Muñoz L!"
# ***** THIS SCRIPT MUST RUN IN AN ELEVATED CMD WITH ADMIN CREDENTIALS *****"

# Rescue OS variable
$diska='c'

# FINDER FOR FAULTY OS DRIVE
if (Test-Path -Path 'l:\Windows') {
  $diskb='l'
} else {
if (Test-Path -Path 'i:\Windows') {
  $diskb='i'
} else {
if (Test-Path -Path 'g:\Windows') {
  $diskb='g'
} else {
if (Test-Path -Path 'j:\Windows') {
  $diskb='j'
} else {
if (Test-Path -Path 'k:\Windows') {
  $diskb='k'
} else {
if (Test-Path -Path 'f:\Windows') {
  $diskb='f'
} else {
if (Test-Path -Path 'h:\Windows') {
  $diskb='h'
} else {	
"Path doesn't exist."
}}}}}}}


# HIVE LOADER
# A Backup of the BROKENSYSTEM was taken and left on $($diskb):\ as regbackupbeforeGAchanges just in case!
reg load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
reg export "HKLM\BROKENSYSTEM" "$($diskb):\regbackupbeforeGAchanges" /y


# EXPORTING GOOD VMAGENT REGS FROM RESCUE VM
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureGuestAgent" "$($diskb):\WAGA.reg" /y
# Telemetry service was merged into rdagent so an error might be displayed for wats
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureTelemetryService" "$($diskb):\WATS.reg"  /y
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RdAgent" "$($diskb):\RdAgent.reg" /y

# MODIFYING REG FILES WITH GOOD REG KEYS
# WAAGENT MODIFICATIONS
(gc "$($diskb):\waga.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\waga.reg"

# TELEMETRY MODIFICATIONS
# Telemetry service was merged into rdagent so an error might be displayed for wats
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

