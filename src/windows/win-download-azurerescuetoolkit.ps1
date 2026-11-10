# Import VM Repair initialization
. $PSScriptRoot/common/setup/init.ps1

Log-Info "Downloading AzureRescueToolkit"

New-Item -Path "C:\Temp" -ItemType Directory -Force

Invoke-WebRequest `
    -Uri "https://raw.githubusercontent.com/AjeetSingh-1/vm-repair-tool/main/AzureRescueToolkit.ps1" `
    -OutFile "C:\Temp\AzureRescueToolkit.ps1"

if (Test-Path "C:\Temp\AzureRescueToolkit.ps1")
{
    Log-Info "Download successful"
    exit $STATUS_SUCCESS
}
else
{
    Log-Error "Download failed"
    exit $STATUS_ERROR
}
