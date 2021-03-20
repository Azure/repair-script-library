 . .\src\windows\common\setup\init.ps1
<#
.SYNOPSIS
    This script will change the dump configuration without requiring a reboot.

    Prerequisites (Links below):     
    Kdbgctrl.exe (From the Debugging Tools for Windows.)
 
 
.NOTES
    Name: win-dumpconfigurator.ps1
    Author: Microsoft CSS
    Version: 1.1
    Created: 2021-Mar-1
 
 
.EXAMPLE
    ./win-dumpconfigurator.ps1 -DumpType full -DumpFile C:\Dumps\Memory.dmp -DedicatedDumpFile D:\dd.sys
 
 
.LINK
    Debugging Tools for Windows -- https://docs.microsoft.com/en-us/windows-insider/flight-hub/
#>
Param(
[parameter()] [switch]$OneDump,
[parameter()] [ValidateSet("active", "automatic", "full", "kernel", "mini" )] [string]$DumpType,
[parameter()] [string]$DumpFile,
[parameter()] [string]$DedicatedDumpFile="C:\DedicatedDumpFile.sys",
[parameter()] [string]$VMName,
[parameter()] [string]$ResourceGroup)


if (!$DumpType) 
{
    Write-Host "DumpType, VMname, and Resource group *MUST* all be specified. "
    Write-Output "Valid dump types include active, automatic, full, kernel, or mini."
    break
}

## Add any registry prereqs to the script
## For example, if you want to use a DedicatedDumpFile, you'll need to make sure the key exists.
$CrashCtrlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
$CrashDumpEnabledValue = "CrashDumpEnabled"
$CrashDumpEnabledData = (Get-ItemProperty -Path $CrashCtrlPath).$CrashDumpEnabledValue

if (!$CrashDumpEnabledData) 
{
    Log-Output "Getting the value of $CrashDumpEnabledValue failed. Verify the key is present and contains a value. The default value should be 7."
    Log-Output "Unable to continue, exiting..."
    exit 
}

if ($DumpFile)
{
    Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile
}

if ($DedicatedDumpFile)
{
    Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value $DedicatedDumpFile
}
Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value C:\DedicatedDumpFile.sys
# This is to clear the CrashDumpEnabled Key before kdbgctrl.exe sets it. This is helpful in scenarios where you want to 
# use a DedicatedDump File but you do not wish to change the dump type.
Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value 0
$kdbgctrl_return =   .\src\windows\common\tools\kdbgctrl.exe -sd full
if ($OneDump)
{
 # Restore orignal CrashDumpEnabled value. This is helpful when you might not want to leave a system configured for a 
 # complete dump because of the downtime involved in writing out the dump. Which is to say, change the dump configuration
 # for the next bugcheck only.
    Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value $CrashDumpEnabledValue
}
Log-Output $kdbgctrl_return
return $STATUS_SUCCESS