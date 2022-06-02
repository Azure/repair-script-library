# Contact me Daniel Muñoz L : damunozl@microsoft.com if support is required.
# Echo off null outputs
out-null

# Change color
cmd /c color 0A

# Change title of console
$title="                                                                                  --== AUTO LKGC by Daniel Muñoz L ==--"
$host.UI.RawUI.WindowTitle = $Title

# "Welcome to the AUTO LKGC(Last Known Good Configuration) by Daniel Muñoz L!"

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

# cmd version
# for /f "tokens=3 " %a in ('reg query "HKU\BROKENSYSTEM\select" /v "current" ^|findstr /ri "DWORD"') do echo=%a
# for /f "tokens=4 delims=x " %a in ('reg query "HKU\BROKENSYSTEM\select" /v "current" ^|findstr /ri "DWORD"') do echo=%a
# for /f "tokens=4 delims=x " %a in ('reg query "HKU\BROKENSYSTEM\select" /v "current" ^|findstr /ri "DWORD"') do set current=%a

# OS VER PEEK
reg load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\software"
(Get-ItemProperty -path 'registry::hklm\BROKENSYSTEM\microsoft\windows nt\currentversion').ProductName | %{ [int]$winosver=$_.Split(' ')[1]; }
(Get-ItemProperty -path 'registry::hklm\BROKENSYSTEM\microsoft\windows nt\currentversion').ProductName | %{ [int]$winosver=$_.Split(' ')[2]; }
reg.exe unload "HKLM\BROKENSYSTEM"

# Hive loader into rescue VM
reg load "HKU\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM"

# Acquiring reg values
$currentreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).current
$defaultreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).default
$failedreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).failed
$lkgcreg = (Get-ItemProperty -path Registry::HKU\BROKENSYSTEM\Select).LastKnownGood

# FILTER IF LKGC IS ALREADY THERE FOR Windows 10, Windows Server 2016, and newer versions.
if (($winosver -eq 10) -or ($winosver -ge 2016)) 
{
if ($currentreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($defaultreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($failedreg -ge 1) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($lkgcreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";exit}
}

# FILTER IF LKGC IS ALREADY THERE FOR Windows Server 2012 version.
if ($winosver -eq 2012) 
{
# CHECK IF LKGC IS ALREADY THERE
if ($currentreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($defaultreg -ge 2) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($failedreg -ge 1) {reg.exe unload "HKU\BROKENSYSTEM";exit}
elseif ($lkgcreg -ge 3) {reg.exe unload "HKU\BROKENSYSTEM";exit}
}

# Plus 1
$currentreg = $currentreg+1
$defaultreg = $defaultreg+1
$failedreg = $failedreg+1
$lkgcreg = $lkgcreg+1

# Adding new registries to enable LKGC
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'current' -Type DWORD -value $currentreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'default' -Type DWORD -value $defaultreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'failed' -Type DWORD -value $failedreg
Set-Itemproperty -path Registry::HKU\BROKENSYSTEM\Select -Name 'LastKnownGood' -Type DWORD -value $lkgcreg

# Unload Hive
reg.exe unload "HKU\BROKENSYSTEM"
