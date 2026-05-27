<#
.SYNOPSIS
    Configures Azure VM memory dumps with intelligent placement strategies to work around temporary storage issues - no reboot required.

.DESCRIPTION
    This script runs on the live VM (not a rescue VM) to configure crash dump settings  
    WITHOUT REQUIRING A REBOOT. Includes smart placement strategies to work around  
    Azure VM temporary storage limitations.
    
    It performs the following steps:
    1. Audits current crash control settings using both Registry and WMI (for pagefile accuracy)
    2. Enables NMICrashDump (DWORD 1) to allow NMI triggering from the Azure Portal
    3. Sets BootStatusPolicy to 1 (IgnoreShutdownFailures) for automatic reboot after crash
    4. INTELLIGENTLY configures dump file placement to work around temporary drive issues
    5. Uses dedicated dump files when necessary to ensure reliability on Azure VMs
    6. Uses kdbgctrl.exe to apply the selected dump type to the live kernel immediately
    7. If -OneDump is specified, restores original CrashDumpEnabled after kernel update
    8. NO REBOOT REQUIRED - All changes take effect immediately

.PARAMETER OneDump
    Switch to restore the original CrashDumpEnabled value after the kernel has been updated.
    Useful for single-event debugging.

.PARAMETER DumpType
    The type of dump to configure. Valid values: active, automatic, full, kernel, mini.

.PARAMETER DumpFile
    The target path for the final .dmp file. Defaults to %SystemRoot%\MEMORY.DMP.

.PARAMETER DedicatedDumpFile
    The path to a dedicated dump file (e.g., D:\dd.sys) to preserve space on the OS drive.
    Use "delete" to remove an existing dedicated dump file configuration.

.PARAMETER MovePagefile
    Switch to relocate pagefile from temporary D: drive to persistent storage (C: or F: drive).
    WARNING: This change requires restoration after troubleshooting. The script will log
    detailed restoration instructions including the original pagefile location.

.VERSION
    Name:     win-dumpconfigurator.ps1
    Version:  1.2 (Improved kdbgctrl output handling and verification)
    Author:   Tony.Mocanu@Microsoft.com

.VERSION
    v1.2: [May 2026] - Updated script (current)
                       - Filtered non-actionable kdbgctrl noise from user-facing output.
                       - Added explicit before/after human-readable dump configuration logging.
                       - Added strict post-apply verification and status failure on validation mismatch.
    v1.1: [May 2026] - Updated script
                       - Added intelligent dump placement for Azure temporary storage scenarios.
                       - Added optional pagefile relocation from D: to C: for dump reliability.
                       - Added WMI-based live pagefile auditing and no-reboot workflow.
    v1.0: Initial commit. First working version of the script.
#>

# Initialization
. .\src\windows\common\setup\init.ps1

# DEBUG: Uncomment below to test locally without --parameters
# $DumpType = 'full'
# $DumpFile = 'F:\MEMORY.DMP'
# $DedicatedDumpFile = ''
# $OneDump = 'false'
# $MovePagefile = 'true'

# Parameter Validation
if (-not $DumpType) { $DumpType = 'full' }
$validDumpTypes = @('active', 'automatic', 'full', 'kernel', 'mini')
if ($DumpType -notin $validDumpTypes) {
    throw "Invalid DumpType '$DumpType'. Valid values: $($validDumpTypes -join ', ')"
}

# Logging Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\dumpconfigurator_$timestamp.log"

$script_final_status = $STATUS_ERROR

function Get-DumpTypeLabel {
    param($Value)

    if ($null -eq $Value) { return "NOT FOUND" }

    $intValue = [int]$Value
    switch ($intValue) {
        0 { return "Disabled/None (0)" }
        1 { return "Complete/Full (1)" }
        2 { return "Kernel (2)" }
        3 { return "Small/Minidump (3)" }
        7 { return "Automatic (7)" }
        default { return "Unknown ($intValue)" }
    }
}

function Filter-KdbgctrlOutput {
    param($OutputLines)

    $noisePatterns = @(
        "Dump type from system registry is Invalid",
        "lastError after QueryDosDevice call is 3"
    )

    $allLines = @($OutputLines | ForEach-Object { "$($_)".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $filtered = @()
    $suppressed = @()

    foreach ($line in $allLines) {
        $isNoise = $false
        foreach ($pattern in $noisePatterns) {
            if ($line -like "*$pattern*") {
                $isNoise = $true
                break
            }
        }

        if ($isNoise) {
            $suppressed += $line
        } else {
            $filtered += $line
        }
    }

    return @{
        All        = $allLines
        Filtered   = $filtered
        Suppressed = $suppressed
    }
}

function Get-AuditSnapshot {
    param($Title)
    
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $MMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $RelPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"
    
    # Read core dump settings
    $NMI = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).NMICrashDump
    $BSP = (Get-ItemProperty -Path $RelPath -ErrorAction SilentlyContinue).BootStatusPolicy
    
    # PAGEFILE DETECTION: Query WMI for the active configuration.
    $ConfiguredPageFiles = Get-WmiObject -Class Win32_PageFileSetting -ErrorAction SilentlyContinue | 
                           Select-Object -ExpandProperty Name
    
    Log-Output ">>> $Title <<<"
    $crashDumpEnabled = (Get-ItemProperty -Path $Path).CrashDumpEnabled

    Log-Output "DumpFile           : $((Get-ItemProperty -Path $Path).DumpFile)"
    Log-Output "CrashDumpEnabled   : $(Get-DumpTypeLabel -Value $crashDumpEnabled)"
    Log-Output "NMICrashDump       : $(if($null -eq $NMI){"NOT FOUND"}else{$NMI})"
    Log-Output "BootStatusPolicy   : $(if($null -eq $BSP){"NOT FOUND"}else{$BSP})"
    
    if ($ConfiguredPageFiles) {
        Log-Output "ConfiguredPageFiles (LIVE): $($ConfiguredPageFiles -join ', ')"
    } else {
        # Fallback to registry if WMI returns nothing (unusual)
        $PFile = (Get-ItemProperty -Path $MMPath -ErrorAction SilentlyContinue).ExistingPageFiles
        Log-Output "ExistingPageFiles  : $(if($null -eq $PFile){"NOT FOUND"}else{$PFile})"
    }
}

try {
    # Step 1 - Audit BEFORE
    Get-AuditSnapshot "AUDITING SETTINGS (BEFORE)"

    $CrashCtrlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $initialValue = (Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled
    $dumpTypeMap = @{ 'full' = 1; 'kernel' = 2; 'mini' = 3; 'automatic' = 7; 'active' = 1 }
    $requestedDumpValue = $dumpTypeMap[$DumpType]
    $verificationFailed = $false

    Log-Output "Current dump configuration: $(Get-DumpTypeLabel -Value $initialValue)"
    Log-Output "Requested dump type: $DumpType ($(Get-DumpTypeLabel -Value $requestedDumpValue))"

    # Step 2 - Enable NMI
    Set-ItemProperty -Path $CrashCtrlPath -Name NMICrashDump -Value 1 -Type DWord

    # Step 3 - Configure automatic reboot
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name BootStatusPolicy -Value 1 -Type DWord

    # Step 4 - Pagefile Detection for Smart Placement
    $MMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $currentPFiles = Get-WmiObject -Class Win32_PageFileSetting | Select-Object -ExpandProperty Name
    $pagefileOnTempDrive = $false
    $originalPagefileLocations = $currentPFiles
    $pagefileWasMoved = $false
    
    foreach ($pf in $currentPFiles) {
        if ($pf -like "D:*" -or $pf -like "*D:\*") {
            $pagefileOnTempDrive = $true
            Log-Warning "Pagefile detected on D: drive: $pf"
            break
        }
    }
    
    # INTELLIGENT DUMP PLACEMENT
    if ($DumpFile) {
        if ($pagefileOnTempDrive) {
            if ($DumpFile -like "F:*") {
                Log-Info "Using F: drive, configuring dedicated dump file on C: for reliability."
                Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value "C:\dd.sys"
            }
            elseif ($DumpFile -like "D:*") {
                Log-Warning "D: drive is temporary. Redirecting dump to C: drive."
                $DumpFile = $DumpFile.Replace("D:", "C:")
            }
        }
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile 
    } else {
        if ($pagefileOnTempDrive) {
            Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value "%SystemRoot%\MEMORY.DMP"
            Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value "C:\dd.sys"
        } else {
            Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value "%SystemRoot%\MEMORY.DMP"
        }
    }

    # Step 5 - OPTIONAL PAGEFILE RELOCATION
    if (($MovePagefile -eq $true -or $MovePagefile -eq 'true') -and $pagefileOnTempDrive) {
        Log-Warning "PAGEFILE RELOCATION REQUESTED"
        
        try {
            # FIX: Explicitly target C: if logic loop fails, bypass the WMI free space comparison bug
            $targetDrive = "C:"
            $cDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
            
            if ($null -ne $cDrive) {
                $targetPagefile = "C:\pagefile.sys"
                Log-Info "C: Drive detected via WMI. Procceding with relocation..."
                
                $pageFileSettings = Get-WmiObject -Class Win32_PageFileSetting
                foreach ($pf in $pageFileSettings) {
                    if ($pf.Name -like "D:*" -or $pf.Name -like "*D:\*") { 
                        Log-Info "Deleting current pagefile instance: $($pf.Name)"
                        $pf.Delete() 
                    }
                }
                
                $newPageFile = ([WMIClass]"Win32_PageFileSetting").CreateInstance()
                $newPageFile.Name = $targetPagefile
                $newPageFile.InitialSize = 0
                $newPageFile.MaximumSize = 0
                $putResult = $newPageFile.Put()
                
                if ($putResult) {
                    $pagefileWasMoved = $true
                    Log-Info "Successfully updated WMI configuration to: $targetPagefile"
                }
            } else {
                throw "C: drive could not be verified via WMI. Relocation aborted."
            }
        }
        catch {
            Log-Error "Failed to relocate pagefile: $($_.Exception.Message)"
        }
    }

    # Step 6 - DedicatedDumpFile
    if ($DedicatedDumpFile -eq "delete") { 
        Remove-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -ErrorAction SilentlyContinue 
    }
    elseif ($DedicatedDumpFile) { 
        Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value $DedicatedDumpFile 
    }

    # Step 7 - Apply to LIVE KERNEL
    Log-Info "Applying dump type '$DumpType' via kdbgctrl..."
    Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value 0
    
    $toolPath = ".\src\windows\common\tools\kdbgctrl.exe"
    $kdbgResult = & $toolPath -sd $DumpType 2>&1
    $kdbgExitCode = $LASTEXITCODE
    $parsedKdbg = Filter-KdbgctrlOutput -OutputLines $kdbgResult

    if ($parsedKdbg.Suppressed.Count -gt 0) {
        Log-Debug "Suppressed non-actionable kdbgctrl messages: $($parsedKdbg.Suppressed -join ' | ')"
    }

    if ($kdbgExitCode -ne 0) {
        $verificationFailed = $true
        Log-Error "kdbgctrl failed with exit code $kdbgExitCode. Output: $($parsedKdbg.Filtered -join ' | ')"
    }
    else {
        $successMatched = $false
        foreach ($line in $parsedKdbg.Filtered) {
            if ($line -match '(?i)success|successfully updated dump settings') {
                $successMatched = $true
                break
            }
        }

        if ($successMatched) {
            Log-Output "Successfully updated dump settings to '$DumpType' via kdbgctrl."
        }
        elseif ($parsedKdbg.Filtered.Count -gt 0) {
            Log-Warning "kdbgctrl completed with unexpected output: $($parsedKdbg.Filtered -join ' | ')"
        }
    }

    # Registry Fallback for kdbgctrl
    if ((Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled -eq 0) {
        Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value $dumpTypeMap[$DumpType] -Type DWord
    }

    # Step 8 - OneDump
    if ($OneDump -eq $true -or $OneDump -eq 'true') { 
        Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value $initialValue 
    }

    # Step 10 - Final Audit AFTER
    Get-AuditSnapshot "VERIFYING UPDATED SETTINGS (AFTER)"

    $currentDumpValue = (Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled
    if ($OneDump -eq $true -or $OneDump -eq 'true') {
        Log-Output "OneDump requested. CrashDumpEnabled restored to $(Get-DumpTypeLabel -Value $currentDumpValue)."
    }
    elseif ($currentDumpValue -ne $requestedDumpValue) {
        $verificationFailed = $true
        Log-Error "Dump configuration verification failed. Expected $(Get-DumpTypeLabel -Value $requestedDumpValue), found $(Get-DumpTypeLabel -Value $currentDumpValue)."
    }
    else {
        Log-Output "Verified dump configuration: $(Get-DumpTypeLabel -Value $currentDumpValue)."
    }
    
    if ($pagefileWasMoved) {
        Log-Output "PAGEFILE RELOCATION COMPLETED: Pagefile moved from temporary D: drive."
        Log-Warning "RESTORATION REQUIRED: Restore to $($originalPagefileLocations -join ', ') after debugging."
    }
    
    if ($verificationFailed) {
        Log-Error "Configuration completed with one or more validation errors."
        $script_final_status = $STATUS_ERROR
    }
    else {
        Log-Output "SUCCESS: Configuration applied immediately - NO REBOOT REQUIRED"
        $script_final_status = $STATUS_SUCCESS
    }
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
