<#
.SYNOPSIS
    Configures a Windows VM to generate a Full Memory Dump without requiring a reboot.
    
.DESCRIPTION
    This script performs the following actions:
    1. Audits current crash control settings (CrashDumpEnabled, NMICrashDump, BootStatusPolicy).
    2. Enables NMICrashDump to allow Azure Portal NMI triggering.
    3. Sets BootStatusPolicy to 'IgnoreShutdownFailures' to ensure automatic reboot after a crash.
    4. Configures a Dedicated Dump File (optional) to ensure space for the dump.
    5. Uses kdbgctrl.exe to apply the 'Full' dump configuration to the live kernel immediately.
    6. Restores original settings if the -OneDump switch is used.

.PARAMETER OneDump
    Switch to restore the original CrashDumpEnabled value after the kernel has been updated.
    Useful for single-event debugging.

.PARAMETER DumpType
    The type of dump to configure (e.g., full, kernel, mini, active, automatic).

.PARAMETER DumpFile
    The target path for the final .dmp file. Defaults to %SystemRoot%\MEMORY.DMP.

.PARAMETER DedicatedDumpFile
    The path to a dedicated dump file (e.g., D:\dd.sys) to preserve space on the OS drive.

.EXAMPLE
    az vm repair run --parameters dumptype=full DedicatedDumpFile="D:\dd.sys"

.NOTES
    Name: win-dumpconfigurator.ps1
    Version: 1.2
    Author: Tony.Mocanu@Microsoft.com
#>

# Initialize standard library logic
. .\src\windows\common\setup\init.ps1

function Get-AuditSnapshot {
    param($Title)
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $MMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $RelPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"
    
    $PFile = (Get-ItemProperty -Path $MMPath -ErrorAction SilentlyContinue).ExistingPageFiles
    $NMI = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).NMICrashDump
    $BSP = (Get-ItemProperty -Path $RelPath -ErrorAction SilentlyContinue).BootStatusPolicy
    
    Log-Output ">>> $Title <<<"
    Log-Output "DumpFile           : $((Get-ItemProperty -Path $Path).DumpFile)"
    Log-Output "CrashDumpEnabled   : $((Get-ItemProperty -Path $Path).CrashDumpEnabled)"
    Log-Output "NMICrashDump       : $(if($null -eq $NMI){"NOT FOUND"}else{$NMI})"
    Log-Output "BootStatusPolicy   : $(if($null -eq $BSP){"NOT FOUND"}else{$BSP})"
    Log-Output "ExistingPageFiles  : $(if($null -eq $PFile){"NOT FOUND"}else{$PFile})"
}

Param(
    [parameter()] [switch]$OneDump,
    [parameter()] [ValidateSet("active", "automatic", "full", "kernel", "mini" )] [string]$DumpType,
    [parameter()] [string]$DumpFile,
    [parameter()] [string]$DedicatedDumpFile
)

try {
    # 1. AUDIT BEFORE
    Get-AuditSnapshot "AUDITING SETTINGS (BEFORE)"

    $CrashCtrlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $initialValue = (Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled

    # 2. SET AZURE PORTAL PREREQUISITES
    Set-ItemProperty -Path $CrashCtrlPath -Name NMICrashDump -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name BootStatusPolicy -Value 1 -Type DWord

    # 3. APPLY PATHS
    if ($DumpFile) { 
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile 
    } else {
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value "%SystemRoot%\MEMORY.DMP"
    }

    if ($DedicatedDumpFile -eq "delete") { 
        Remove-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -ErrorAction SilentlyContinue 
    }
    elseif ($DedicatedDumpFile) { 
        Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value $DedicatedDumpFile 
    }

    # 4. RUN KDBGCTRL TO APPLY LIVE KERNEL CHANGES
    Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value 0
    $toolPath = ".\src\windows\common\tools\kdbgctrl.exe"
    & $toolPath -sd $DumpType | Log-Output

    # 5. RESTORE ORIGINAL IF ONEDUMP USED
    if ($OneDump) { 
        Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value $initialValue 
    }

    # 6. AUDIT AFTER
    Get-AuditSnapshot "VERIFYING UPDATED SETTINGS (AFTER)"
    
    $finalDumpPath = (Get-ItemProperty -Path $CrashCtrlPath).DumpFile
    Log-Output "Success: VM is now configured for a Full Memory Dump."
    Log-Output "The final dump will be generated at: $finalDumpPath"
    Log-Output "Use the NMI button in the Azure Portal to trigger the crash."
    
    return $STATUS_SUCCESS
}
catch {
    Log-Output "Failure: $($_.Exception.Message)"
    return $STATUS_ERROR
}
