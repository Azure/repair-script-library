<#
.SYNOPSIS
    Configures Azure VM memory dumps with intelligent placement strategies to work around temporary storage issues - no reboot required.

.DESCRIPTION
    This script runs on the live VM (not a rescue VM) to configure crash dump settings  
    WITHOUT REQUIRING A REBOOT. Includes smart placement strategies to work around  
    Azure VM temporary storage limitations.
    
    It performs the following steps:
    1. Audits current crash control settings using both Registry and CIM (for pagefile accuracy)
    2. Enables NMICrashDump (DWORD 1) to allow NMI triggering from the Azure Portal
    3. Optionally configures automatic reboot after crash (use -ConfigureAutomaticReboot to enable)
    4. INTELLIGENTLY configures dump file placement to work around temporary drive issues
    5. Uses dedicated dump files when necessary to ensure reliability on Azure VMs
    6. Uses kdbgctrl.exe to apply the selected dump type to the live kernel immediately
    7. If -OneDump is specified, restores original CrashDumpEnabled after kernel update
    8. Validates C: drive free space (minimum 20%) before pagefile relocation to prevent VM crashes
    9. NO REBOOT REQUIRED - All changes take effect immediately

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
    detailed restoration instructions including the original pagefile location and
    explicit CIM commands to restore it.

.PARAMETER ConfigureAutomaticReboot
    Switch to configure automatic reboot after system crash (BootStatusPolicy=1).
    By default, automatic reboot is NOT configured. Enable this parameter to opt-in.
    Useful for production systems, but may not be desired on Citrix VMs or other
    specialized environments.

.PARAMETER EnableDebugDefaults
    Applies local test defaults only when set to true and only for values not provided
    by runtime parameters.

.EXAMPLE
    .\win-dumpconfigurator.ps1 -DumpType kernel -DumpFile "%SystemRoot%\MEMORY.DMP" -ConfigureAutomaticReboot true
    Configures kernel dump collection and enables automatic reboot after a crash.

.EXAMPLE
    .\win-dumpconfigurator.ps1 -DumpType full -DedicatedDumpFile "delete" -OneDump true
    Applies full dump for a single capture cycle and removes an existing dedicated dump file setting.

.VERSION
    Name:     win-dumpconfigurator.ps1
    Version:  1.3 (Critical fixes, safety enhancements, and PowerShell 7 compatibility)
    Author:   Michael.Smith@microsoft.com for v1.0, Tony.Mocanu@Microsoft.com for the rest.

.VERSION
    v1.3: [July 2026] - CRITICAL FIXES & SAFETY ENHANCEMENTS (current)
                       - FIXED: Changed [switch] parameters to [string] for CLI compatibility
                       - FIXED: Added early parameter validation to catch invalid parameters before execution
                       - FIXED: Migrated all Get-WmiObject to Get-CimInstance (PowerShell 7 compatibility)
                       - FIXED: Added guard for empty $DumpFile path
                       - FIXED: Corrected typo 'Procceding' → 'Proceeding'
                       - FIXED: Added missing Step 9 in output (numbering now 1-11)
                       - IMPROVED: Better error messaging for invalid parameters via CLI
                       - IMPROVED: Added comprehensive warnings about pagefile relocation destructiveness
                       - IMPROVED: Added C: drive free space validation before relocation (20% minimum required)
                       - IMPROVED: Added local test defaults documentation for local testing without CLI parameters
                       - IMPROVED: Added explicit CIM restore commands for pagefile rollback guidance
                       - IMPROVED: Dual-wrote plain text logs to desktop and script-local collected folder
    v1.2: [May 2026] - Updated script
                       - Added Michael.Smith@microsoft.com as co-author (v1.0 creator)
                       - Changed log file location to $env:PUBLIC\Desktop for uniformity with other scripts
                       - Made automatic reboot configuration optional via -ConfigureAutomaticReboot parameter
                       - Filtered non-actionable kdbgctrl noise from user-facing output.
                       - Added explicit before/after human-readable dump configuration logging.
                       - Added strict post-apply verification and status failure on validation mismatch.
    v1.1: [May 2026] - Updated script
                       - Added intelligent dump placement for Azure temporary storage scenarios.
                       - Added optional pagefile relocation from D: to C: for dump reliability.
                       - Added CIM-based live pagefile auditing and no-reboot workflow.
    v1.0: Initial commit. First working version of the script.
#>

Param(
    [Parameter(Mandatory = $false)]
    [string]$DumpType = '',

    [Parameter(Mandatory = $false)]
    [string]$DumpFile = '',

    [Parameter(Mandatory = $false)]
    [string]$DedicatedDumpFile = '',

    [Parameter(Mandatory = $false)]
    [string]$OneDump = '',

    [Parameter(Mandatory = $false)]
    [string]$MovePagefile = '',

    [Parameter(Mandatory = $false)]
    [string]$ConfigureAutomaticReboot = '',

    [Parameter(Mandatory = $false)]
    [string]$EnableDebugDefaults = ''
)

# Initialization
$initScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\setup\init.ps1'
if (-not (Test-Path -Path $initScriptPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initScriptPath"
    return 1
}

. $initScriptPath

# Script-level logging: create desktop and collected plain text logs that mirror Log-* output.
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktopRunOutputDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$collectedRunOutputDir = Join-Path -Path $PSScriptRoot -ChildPath ("logs\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$runOutputDir = $collectedRunOutputDir
$desktopLogFilePath = Join-Path -Path $desktopRunOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)
$collectedLogFilePath = Join-Path -Path $collectedRunOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)
$script:LogFilePaths = @($desktopLogFilePath, $collectedLogFilePath)

foreach ($outputDir in @($desktopRunOutputDir, $collectedRunOutputDir)) {
    if (-not (Test-Path -Path $outputDir -PathType Container)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }
}

foreach ($path in $script:LogFilePaths) {
    if (-not (Test-Path -Path $path -PathType Leaf)) {
        New-Item -Path $path -ItemType File -Force | Out-Null
    }
}

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock

function Write-RunLogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [PSObject[]]$Message
    )

    try {
        $renderedMessage = ($Message | ForEach-Object { "$_" }) -join ' '
        $line = "[{0} {1}]{2}" -f $Level, (Get-Date), $renderedMessage
        foreach ($path in $script:LogFilePaths) {
            try {
                Add-Content -Path $path -Value $line -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                Write-Output "[Warning $(Get-Date)]Failed to append to plain text log '$path': $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Output "[Warning $(Get-Date)]Failed to render log line: $($_.Exception.Message)"
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-RunLogLine -Level 'Output' -Message $message
}

function Log-Info {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogInfo -message $message
    Write-RunLogLine -Level 'Info' -Message $message
}

function Log-Warning {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogWarning -message $message
    Write-RunLogLine -Level 'Warning' -Message $message
}

function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-RunLogLine -Level 'Error' -Message $message
}

function Log-Debug {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogDebug -message $message
    Write-RunLogLine -Level 'Debug' -Message $message
}

Log-Info "Plain text log initialized (desktop copy): $desktopLogFilePath"
Log-Info "Plain text log initialized (collected copy): $collectedLogFilePath"

# LOCAL TEST DEFAULTS: Uncomment the variables below to test locally without --parameters
# You can either:
#   1. Uncomment individual variables and run the script
#   2. Uncomment ONLY $EnableDebugDefaults='true' to activate all defaults
# Example:
#   $DumpType = 'full'
#   $OneDump = 'false'
#   $MovePagefile = 'false'
#   $EnableDebugDefaults = 'true
# Then run: .\win-dumpconfigurator.ps1

# Normalize incoming parameter names (vm-repair commonly passes lowercase names).
if (-not $DumpType -and $dumptype) { $DumpType = $dumptype }
if (-not $DumpFile -and $dumpfile) { $DumpFile = $dumpfile }
if (-not $DedicatedDumpFile -and $dedicateddumpfile) { $DedicatedDumpFile = $dedicateddumpfile }
if (-not $OneDump -and $onedump) { $OneDump = $onedump }
if (-not $MovePagefile -and $movepagefile) { $MovePagefile = $movepagefile }
if (-not $ConfigureAutomaticReboot -and $configureautomaticreboot) { $ConfigureAutomaticReboot = $configureautomaticreboot }
if (-not $EnableDebugDefaults -and $enabledebugdefaults) { $EnableDebugDefaults = $enabledebugdefaults }

# Normalize boolean-like string parameters for consistent downstream checks.
$OneDump = "$OneDump".Trim().ToLowerInvariant()
$MovePagefile = "$MovePagefile".Trim().ToLowerInvariant()
$ConfigureAutomaticReboot = "$ConfigureAutomaticReboot".Trim().ToLowerInvariant()
$EnableDebugDefaults = "$EnableDebugDefaults".Trim().ToLowerInvariant()

# Optional local-only defaults for troubleshooting without --parameters.
$debugDefaultsEnabled = $EnableDebugDefaults -eq $true -or $EnableDebugDefaults -eq 'true'
if ($debugDefaultsEnabled) {
    if (-not $DumpType) { $DumpType = 'full' }
    if (-not $DumpFile) { $DumpFile = '%SystemRoot%\Memory.dmp' }
    if (-not $DedicatedDumpFile) { $DedicatedDumpFile = 'Z:\dd.sys' }
    if (-not $OneDump) { $OneDump = 'false' }
    if (-not $MovePagefile) { $MovePagefile = 'true' }
    Log-Info "EnableDebugDefaults is active. Applying local fallback defaults for missing parameters."
}

# === PARAMETER VALIDATION (EARLY FAIL) ===
# Validate all parameters BEFORE any operations
$validDumpTypes = @('active', 'automatic', 'full', 'kernel', 'mini')

# 1. Validate DumpType if provided
$userProvidedDumpType = -not [string]::IsNullOrWhiteSpace("$DumpType")
if (-not $userProvidedDumpType) { 
    $DumpType = 'full' 
} else {
    if ($DumpType -notin $validDumpTypes) {
        throw "Invalid DumpType '$DumpType'. Valid values: $($validDumpTypes -join ', '). Check your --parameters syntax."
    }
}

# 2. Validate OneDump is boolean-compatible
if ($OneDump -notin @('true', 'false', $true, $false, '')) {
    throw "Invalid OneDump '$OneDump'. Must be 'true' or 'false'."
}

# 3. Validate MovePagefile is boolean-compatible
if ($MovePagefile -notin @('true', 'false', $true, $false, '')) {
    throw "Invalid MovePagefile '$MovePagefile'. Must be 'true' or 'false'."
}

# 4. Validate ConfigureAutomaticReboot is boolean-compatible
if ($ConfigureAutomaticReboot -notin @('true', 'false', $true, $false, '')) {
    throw "Invalid ConfigureAutomaticReboot '$ConfigureAutomaticReboot'. Must be 'true' or 'false'."
}

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

function Get-KdbgctrlOutputSummary {
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
    
    # PAGEFILE DETECTION: Query CIM for the active configuration.
    $ConfiguredPageFiles = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue | 
                           Select-Object -ExpandProperty Name
    
    Log-Output ">>> $Title <<<"
    $crashDumpEnabled = (Get-ItemProperty -Path $Path).CrashDumpEnabled

    $currentDumpFile = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).DumpFile
    $currentDedicatedDumpFile = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).DedicatedDumpFile

    Log-Output "DumpFile           : $(if([string]::IsNullOrWhiteSpace("$currentDumpFile")){"NOT FOUND"}else{$currentDumpFile})"
    Log-Output "DedicatedDumpFile  : $(if([string]::IsNullOrWhiteSpace("$currentDedicatedDumpFile")){"NOT FOUND"}else{$currentDedicatedDumpFile})"
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

function Get-PagefileRestoreCommands {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$OriginalPagefileLocations
    )

    $commands = @(
        "Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object { `$_.Name -eq 'C:\pagefile.sys' } | Remove-CimInstance"
    )

    foreach ($location in $OriginalPagefileLocations) {
        if (-not [string]::IsNullOrWhiteSpace($location)) {
            $commands += "New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name='$location'; InitialSize=0; MaximumSize=0 }"
        }
    }

    return $commands
}

function Write-PagefileRestoreGuidance {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$OriginalPagefileLocations
    )

    if (-not $OriginalPagefileLocations -or $OriginalPagefileLocations.Count -eq 0) {
        return
    }

    Log-Warning "RESTORATION REQUIRED: original pagefile settings were $($OriginalPagefileLocations -join ', ')"
    Log-Warning "To restore the original pagefile configuration after debugging, run:"

    foreach ($command in (Get-PagefileRestoreCommands -OriginalPagefileLocations $OriginalPagefileLocations)) {
        Log-Warning "  $command"
    }
}

try {
    # Step 1 - Audit BEFORE
    Get-AuditSnapshot "AUDITING SETTINGS (BEFORE)"

    $CrashCtrlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $crashControlBackupPath = Join-Path -Path $runOutputDir -ChildPath ("CrashControl-backup-{0}.reg" -f $runTimestamp)
    $backupResult = & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" $crashControlBackupPath /y 2>&1
    if ($LASTEXITCODE -eq 0) {
        Log-Info "Created registry backup: $crashControlBackupPath"
    }
    else {
        Log-Warning "Could not create registry backup. Output: $($backupResult -join ' | ')"
    }

    $initialValue = (Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled
    $dumpTypeMap = @{ 'full' = 1; 'kernel' = 2; 'mini' = 3; 'automatic' = 7; 'active' = 1 }
    $requestedDumpValue = $dumpTypeMap[$DumpType]
    $verificationFailed = $false

    Log-Output "Current dump configuration: $(Get-DumpTypeLabel -Value $initialValue)"
    Log-Output "Requested dump type: $DumpType ($(Get-DumpTypeLabel -Value $requestedDumpValue))"
    Log-Output "Requested DumpFile: $(if([string]::IsNullOrWhiteSpace("$DumpFile")){"NOT SPECIFIED"}else{$DumpFile})"
    Log-Output "Requested DedicatedDumpFile: $(if([string]::IsNullOrWhiteSpace("$DedicatedDumpFile")){"NOT SPECIFIED"}else{$DedicatedDumpFile})"

    # Step 2 - Enable NMI
    Set-ItemProperty -Path $CrashCtrlPath -Name NMICrashDump -Value 1 -Type DWord

    # Step 3 - Configure automatic reboot (optional)
    if ($ConfigureAutomaticReboot -eq $true -or $ConfigureAutomaticReboot -eq 'true') {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name BootStatusPolicy -Value 1 -Type DWord
        Log-Info "Automatic reboot on crash configured (BootStatusPolicy=1)."
    }
    else {
        Log-Info "Automatic reboot on crash NOT configured. Use -ConfigureAutomaticReboot to enable."
    }

    # Step 4 - Pagefile Detection for Smart Placement
    $MMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $currentPFiles = Get-CimInstance -ClassName Win32_PageFileSetting | Select-Object -ExpandProperty Name
    $pagefileOnTempDrive = $false
    $originalPagefileLocations = $currentPFiles
    $pagefileWasMoved = $false
    $pagefileScanProcessed = 0
    $pagefileScanTempMatches = 0
    
    foreach ($pf in $currentPFiles) {
        $pagefileScanProcessed++
        Log-Debug "Detected pagefile setting: $pf"
        if ($pf -like "D:*" -or $pf -like "*D:\*") {
            $pagefileOnTempDrive = $true
            $pagefileScanTempMatches++
            Log-Warning "Pagefile detected on D: drive: $pf"
            break
        }
    }
    Log-Info "Pagefile scan summary: processed=$pagefileScanProcessed tempDriveMatches=$pagefileScanTempMatches"
    
    # INTELLIGENT DUMP PLACEMENT
    # Respect explicit user-provided values exactly as passed.
    if ($DumpFile) {
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile
        Log-Info "Applied user-provided DumpFile: $DumpFile"
    }
    else {
        if ($pagefileOnTempDrive) {
            Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value "%SystemRoot%\MEMORY.DMP"
            # Only apply fallback DedicatedDumpFile when user did not provide a value.
            if (-not $DedicatedDumpFile) {
                Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value "C:\dd.sys"
            }
        } else {
            Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value "%SystemRoot%\MEMORY.DMP"
        }
    }

    # Step 5 - OPTIONAL PAGEFILE RELOCATION
    if (($MovePagefile -eq $true -or $MovePagefile -eq 'true') -and $pagefileOnTempDrive) {
        Log-Warning "PAGEFILE RELOCATION REQUESTED"
        Log-Warning "⚠️  IMPORTANT: Pagefile relocation from D: to C: is DESTRUCTIVE and NOT EASILY REVERSIBLE:"
        Log-Warning "    1. If C: drive runs out of space, the VM may crash"
        Log-Warning "    2. To restore pagefile to D: after troubleshooting, manual intervention or script re-run is required"
        Log-Warning "    3. Ensure C: drive has sufficient free space (recommend minimum 50% free) before proceeding"
        Log-Warning "    4. For production VMs, consider scheduling this change during maintenance window"
        Write-PagefileRestoreGuidance -OriginalPagefileLocations $originalPagefileLocations
        
        try {
            # FIX: Explicitly target C: if logic loop fails, bypass the CIM free space comparison bug
            $cDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
            
            if ($null -ne $cDrive) {
                $targetPagefile = "C:\pagefile.sys"
                
                # Validate C: drive has sufficient free space
                $cDriveFreeSpaceGB = [math]::Round($cDrive.FreeSpace / 1GB, 2)
                $cDriveTotalSpaceGB = [math]::Round($cDrive.Size / 1GB, 2)
                $cDriveFreePercent = [math]::Round(($cDrive.FreeSpace / $cDrive.Size) * 100, 0)
                
                Log-Info "C: Drive space status: $cDriveFreeSpaceGB GB free of $cDriveTotalSpaceGB GB ($cDriveFreePercent% free)"
                
                if ($cDriveFreePercent -lt 20) {
                    Log-Error "C: Drive free space is below 20% ($cDriveFreePercent%). Relocation aborted to prevent VM crash."
                    throw "Insufficient C: drive free space. Minimum 20% recommended, current: $cDriveFreePercent%"
                }
                
                Log-Info "C: Drive detected via CIM. Proceeding with relocation..."
                
                $pageFileSettings = Get-CimInstance -ClassName Win32_PageFileSetting
                $pagefileDeleteProcessed = 0
                $pagefileDeleteDeleted = 0
                $pagefileDeleteFailed = 0
                $pagefileDeleteSkipped = 0

                foreach ($pf in $pageFileSettings) {
                    $pagefileDeleteProcessed++
                    if ($pf.Name -like "D:*" -or $pf.Name -like "*D:\*") {
                        try {
                            Log-Info "Deleting current pagefile instance: $($pf.Name)"
                            $pf | Remove-CimInstance -ErrorAction Stop
                            $pagefileDeleteDeleted++
                        }
                        catch {
                            $pagefileDeleteFailed++
                            Log-Warning "Failed to delete pagefile instance '$($pf.Name)': $($_.Exception.Message)"
                        }
                    }
                    else {
                        $pagefileDeleteSkipped++
                    }
                }
                Log-Info "Pagefile delete summary: processed=$pagefileDeleteProcessed deleted=$pagefileDeleteDeleted skipped=$pagefileDeleteSkipped failed=$pagefileDeleteFailed"

                if ($pagefileDeleteFailed -gt 0) {
                    throw "One or more D: pagefile entries could not be removed. See logs for details."
                }

                $newPageFile = New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                    Name = $targetPagefile
                    InitialSize = 0
                    MaximumSize = 0
                } -ErrorAction Stop

                if ($null -ne $newPageFile) {
                    $pagefileWasMoved = $true
                    Log-Info "Successfully updated WMI configuration to: $targetPagefile"
                }
            } else {
                throw "C: drive could not be verified via CIM. Relocation aborted."
            }
        }
        catch {
            Log-Error "Failed to relocate pagefile: $($_.Exception.Message)"
        }
    }

    # Step 6 - DedicatedDumpFile
    if ($DedicatedDumpFile -eq "delete") { 
        Remove-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -ErrorAction SilentlyContinue 
        Log-Info "Applied user request: DedicatedDumpFile deleted."
    }
    elseif ($DedicatedDumpFile) { 
        Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value $DedicatedDumpFile 
        Log-Info "Applied user-provided DedicatedDumpFile: $DedicatedDumpFile"
    }

    # Step 7 - Guard for empty DumpFile (ensure valid path before kdbgctrl)
    if ([string]::IsNullOrEmpty($DumpFile)) {
        Log-Warning "DumpFile is empty. Using Windows default: %SystemRoot%\MEMORY.DMP"
        $DumpFile = "%SystemRoot%\MEMORY.DMP"
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile
    }

    # Step 8 - Apply to LIVE KERNEL
    Log-Info "Applying dump type '$DumpType' via kdbgctrl..."
    Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value 0
    
    $toolPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\tools\kdbgctrl.exe'
    if (-not (Test-Path -Path $toolPath -PathType Leaf)) {
        throw "Missing required dependency: $toolPath"
    }
    $kdbgResult = & $toolPath -sd $DumpType 2>&1
    $kdbgExitCode = $LASTEXITCODE
    $parsedKdbg = Get-KdbgctrlOutputSummary -OutputLines $kdbgResult

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

    # Step 9 - OneDump
    if ($OneDump -eq $true -or $OneDump -eq 'true') { 
        Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value $initialValue 
    }

    # Step 10 - Verification Summary
    Log-Info "Dump configuration task completed."

    # Step 11 - Final Audit AFTER
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

    $effectiveCrashControl = Get-ItemProperty -Path $CrashCtrlPath -ErrorAction SilentlyContinue
    Log-Output "Effective DumpFile: $($effectiveCrashControl.DumpFile)"
    Log-Output "Effective DedicatedDumpFile: $($effectiveCrashControl.DedicatedDumpFile)"
    
    if ($pagefileWasMoved) {
        Log-Output "PAGEFILE RELOCATION COMPLETED: Pagefile moved from temporary D: drive."
        Write-PagefileRestoreGuidance -OriginalPagefileLocations $originalPagefileLocations
    }
    
    if ($verificationFailed) {
        Log-Error "Configuration completed with one or more validation errors."
        $script_final_status = $STATUS_ERROR
    }
    else {
        Log-Output "SUCCESS: Configuration applied immediately - NO REBOOT REQUIRED"
        Log-Info "Desktop log file: $desktopLogFilePath"
        Log-Info "Collected log file: $collectedLogFilePath"
        $script_final_status = $STATUS_SUCCESS
    }
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    if ($crashControlBackupPath -and (Test-Path -Path $crashControlBackupPath -PathType Leaf)) {
        Log-Warning "Rollback available. To restore previous CrashControl values, run: reg import `"$crashControlBackupPath`""
    }
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
