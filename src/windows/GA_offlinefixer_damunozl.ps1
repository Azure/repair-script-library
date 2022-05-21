# Contact me Daniel Muñoz L : damunozl@microsoft.com if support is required.
# Echo off null outputs
out-null

# Change color
cmd /c color 0A

# Change title of console
$title="                                                                                  --== VMAgent Fixer by Daniel Muñoz L ==--"
$host.UI.RawUI.WindowTitle = $Title

# Clear Screen
Clear-Host

Write-Output "Welcome to the VMAgent fixer by Daniel Muñoz L!"
Write-output ""
Write-Output "***** THIS SCRIPT MUST RUN IN AN ELEVATED CMD WITH ADMIN CREDENTIALS *****"
Write-output ""
# get-psdrive -psprovider filesystem

# Rescue OS variable
$diska='c'

# Finder for faulty OS letter
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


# Hive loader into rescue VM
reg load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"
reg export "HKLM\BROKENSYSTEM" "$($diskb):\regbackupbeforeGAchanges" /y
Write-output ""
write-output "A Backup of the BROKENSYSTEM was taken and left on $($diskb):\ as regbackupbeforeGAchanges just in case!"

# EXPORTING GOOD VMAGENT REGS!
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureGuestAgent" "$($diskb):\WAGA.reg" /y
# Telemetry service was merged into rdagent so an error might be displayed for wats
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WindowsAzureTelemetryService" "$($diskb):\WATS.reg"  /y
reg export "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RdAgent" "$($diskb):\RdAgent.reg" /y

# MODIFYING REG FILES!
(gc "$($diskb):\waga.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\waga.reg"
(gc "$($diskb):\waga.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\waga.reg"
Write-output "                                   -----------============-----------"
# Telemetry service was merged into rdagent so an error might be displayed for wats
(gc "$($diskb):\wats.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\wats.reg"
(gc "$($diskb):\wats.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\wats.reg"
(gc "$($diskb):\wats.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\wats.reg"
Write-output "                                   -----------============-----------"
(gc "$($diskb):\RdAgent.reg") -replace 'LocalSystem', 'notyet' | Out-File "$($diskb):\RdAgent.reg"
(gc "$($diskb):\RdAgent.reg") -replace 'system', 'BROKENSYSTEM' | Out-File "$($diskb):\RdAgent.reg"
(gc "$($diskb):\RdAgent.reg") -replace 'notyet', 'localsystem' | Out-File "$($diskb):\RdAgent.reg"
Write-output "                                   -----------============-----------"
Write-output "ADDING REG FILES IN %diskb% DRIVE!"
regedit /s "$($diskb):\WATS.reg"
regedit /s "$($diskb):\WAGA.reg"
regedit /s "$($diskb):\RdAgent.reg"
Write-output ""
Write-output "RESTORING VMAgent BIN FILES!"
mkdir "$($diskb):\WindowsazurefaultyGAbackup"
xcopy "$($diskb):\WindowsAzure" "$($diskb):\WindowsazurefaultyGAbackup" /e /h /y
Write-output ""
Write-output "BACKUP TAKEN ON FOLDER $($diskb):\WindowsazurefaultyGAbackup"
Write-output ""
del "$($diskb):\WindowsAzure" -force -recurse
mkdir "$($diskb):\WindowsAzure"
xcopy "$($diska):\WindowsAzure" "$($diskb):\WindowsAzure" /e /h /y
Write-output ""
Write-output "VMAgent FILES RESTORED!"
Write-output ""
del "$($diskb):\WindowsAzure\logs" -force -recurse
Write-output ""
Write-output "A Backup was created on the following folder $($diskb)\WindowsazurefaultyGAbackup in case the folder existed."
Write-output "Unloading HIVE"
reg.exe unload "HKLM\BROKENSYSTEM"
del "$($diskb):\rdagent.reg" -force
del "$($diskb):\waga.reg" -force
del "$($diskb):\wats.reg" -force

Write-output "IF FOR SOME REASON THE SCRIPT FAILED AT SOME POINT, PLEASE DO NOT ATTEMPT TO RUN THE SCRIPT AGAIN."
Write-output "REASONS WHY THE SCRIPT COULD HAVE FAILED:"
Write-output ""
Write-output "* Drive letters swapped. (This could affect the troubleshooter VM)"
Write-output "* Used colon character, extra blank spaces and/or typos when the drive letter(s) was/were typed."
Write-output "* Windows directories have different names from the standard(example: c:\windows)"
Write-output ""
Write-output "I hope this script fixes the VMAgent accordingly. :)"
Write-output ""
