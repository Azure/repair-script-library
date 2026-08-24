<#
.SYNOPSIS
    Configures Azure VM memory dumps with verified backups, transactional pagefile relocation,
    automatic rollback, and operation telemetry - no reboot required.

.DESCRIPTION
    This script runs on the live VM (not a rescue VM) to configure crash dump settings
    WITHOUT REQUIRING A REBOOT. Includes smart placement strategies for Azure temporary
    storage, strict post-apply verification, automatic rollback, and collected operation logs.

    It performs the following steps:
    1. Audits current crash control settings using both Registry and CIM (for pagefile accuracy)
    2. Enables NMICrashDump (DWORD 1) to allow NMI triggering from the Azure Portal
    3. Optionally configures automatic reboot after crash (use -ConfigureAutomaticReboot true to enable)
    4. INTELLIGENTLY configures dump file placement to work around temporary drive issues
    5. Uses dedicated dump files when necessary to ensure reliability on Azure VMs
    6. Uses kdbgctrl.exe to apply the selected dump type to the live kernel immediately
    7. If -OneDump true is specified, restores original CrashDumpEnabled after kernel update
    8. Validates C: drive free space (minimum 20%) before transactional pagefile relocation
    9. Automatically restores pagefile and registry settings when a fatal operation fails
    10. Verifies the effective dump, reboot, and pagefile configuration after changes
    11. Emits lifecycle, operation-duration, success, failure, and rollback telemetry
    12. NO REBOOT REQUIRED - All changes take effect immediately

.PARAMETER OneDump
    String boolean ('true' or 'false'). When true, restores the original CrashDumpEnabled
    value after the kernel has been updated. Useful for single-event debugging.

.PARAMETER DumpType
    The type of dump to configure. Valid values: active, automatic, full, kernel, mini.

.PARAMETER DumpFile
    The target path for the final .dmp file. Defaults to %SystemRoot%\MEMORY.DMP.

.PARAMETER DedicatedDumpFile
    The path to a dedicated dump file (e.g., D:\dd.sys) to preserve space on the OS drive.
    Use "delete" to remove an existing dedicated dump file configuration.

.PARAMETER MovePagefile
    String boolean ('true' or 'false'). When true, relocates the pagefile from temporary
    D: drive to persistent C: storage.
    WARNING: This change requires restoration after troubleshooting. The script will log
    detailed restoration instructions including the original pagefile location and
    explicit CIM commands to restore it.

.PARAMETER ConfigureAutomaticReboot
    String boolean ('true' or 'false'). When true, configures automatic reboot after a
    system crash (BootStatusPolicy=1). By default, automatic reboot is NOT configured.
    Useful for production systems, but may not be desired on Citrix VMs or other
    specialized environments.

.PARAMETER EnableDebugDefaults
    String boolean ('true' or 'false'). Applies local test defaults only when true and
    only for values not provided by runtime parameters.

.EXAMPLE
    .\win-dumpconfigurator.ps1 -DumpType kernel -DumpFile "%SystemRoot%\MEMORY.DMP" -ConfigureAutomaticReboot true
    Configures kernel dump collection and enables automatic reboot after a crash.

.EXAMPLE
    .\win-dumpconfigurator.ps1 -DumpType full -DedicatedDumpFile "delete" -OneDump true
    Applies full dump for a single capture cycle and removes an existing dedicated dump file setting.

.VERSION
    Name:     win-dumpconfigurator.ps1
    Version:  1.3.1 (Safety, rollback, verification, and telemetry enhancements)
    Author:   Michael.Smith@microsoft.com for v1.0, Tony.Mocanu@Microsoft.com for the rest.

.VERSION
    v1.3.1: [August 2026] - SAFETY, ROLLBACK, VERIFICATION & TELEMETRY (current)
                       - DOCUMENTED: Boolean-like parameters require explicit 'true' or 'false' string values
                       - DOCUMENTED: Bare switch syntax now requires an explicit value (for example, -OneDump true)
                       - FIXED: A requested pagefile relocation failure now sets the final script status to error
                       - FIXED: Corrected the EnableDebugDefaults local-test example
                       - FIXED: Registry backup failure now stops execution before any registry mutation
                       - FIXED: DumpFile verification now normalizes expandable environment-variable paths
                       - IMPROVED: Added verified CrashControl and optional Reliability registry backups
                       - IMPROVED: Creates the C: pagefile configuration before removing temporary-drive entries
                       - IMPROVED: Automatically restores pagefile and registry state after fatal failures
                       - IMPROVED: Added strict verification for dump, NMI, reboot, dedicated dump, and pagefile settings
                       - IMPROVED: Added structured lifecycle events, operation timings, counters, and rollback telemetry
                       - TESTED: Added non-destructive induced-failure coverage for pagefile and registry rollback paths
    v1.3: [July 2026] - CRITICAL FIXES & SAFETY ENHANCEMENTS
                       - FIXED: Changed [switch] parameters to explicit 'true'/'false' [string] values for CLI compatibility
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
    [string]$OneDump = 'false',

    [Parameter(Mandatory = $false)]
    [string]$MovePagefile = 'false',

    [Parameter(Mandatory = $false)]
    [string]$ConfigureAutomaticReboot = 'false',

    [Parameter(Mandatory = $false)]
    [string]$EnableDebugDefaults = 'false'
)

# Initialization
$initScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\setup\init.ps1'
if (-not (Test-Path -Path $initScriptPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initScriptPath"
    return 1
}

. $initScriptPath
$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Script-level logging: create desktop and collected plain text logs that mirror Log-* output.
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$publicDesktopPath = Join-Path -Path $env:PUBLIC -ChildPath 'Desktop'
$desktopRunOutputDir = Join-Path -Path $publicDesktopPath -ChildPath ("{0}-run-{1}" -f $scriptName, $runTimestamp)
$collectedLogsBaseDir = Join-Path -Path $PSScriptRoot -ChildPath 'logs'

# In RunCommand scenarios, prefer a shorter collection path under the repair-files root
# to avoid deep nested paths that can fail directory/file creation.
if ($PSScriptRoot -match '^(.*?\\repair-files-\d{14})(\\|$)') {
    $collectedLogsBaseDir = Join-Path -Path $Matches[1] -ChildPath 'plugin-logs'
}

$collectedRunOutputDir = Join-Path -Path $collectedLogsBaseDir -ChildPath ("{0}-run-{1}" -f $scriptName, $runTimestamp)
$runOutputDir = $collectedRunOutputDir
$desktopLogFilePath = Join-Path -Path $desktopRunOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)
$collectedLogFilePath = Join-Path -Path $collectedRunOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)
$script:LogFilePaths = @()

foreach ($outputDir in @($desktopRunOutputDir, $collectedRunOutputDir)) {
    try {
        [System.IO.Directory]::CreateDirectory($outputDir) | Out-Null
    }
    catch {
        Write-Output "[Warning $(Get-Date)]Failed to create log directory '$outputDir': $($_.Exception.Message)"
    }
}

foreach ($path in @($desktopLogFilePath, $collectedLogFilePath)) {
    $parentDir = Split-Path -Path $path -Parent
    try {
        [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null

        if (-not (Test-Path -Path $path -PathType Leaf)) {
            New-Item -Path $path -ItemType File -Force -ErrorAction Stop | Out-Null
        }

        $script:LogFilePaths += $path
    }
    catch {
        Write-Output "[Warning $(Get-Date)]Failed to initialize log file '$path': $($_.Exception.Message)"
    }
}

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock
$script:OperationAttempted = 0
$script:OperationSucceeded = 0
$script:OperationFailed = 0

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

function Write-RunOutput {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-RunLogLine -Level 'Output' -Message $message
}

function Write-RunInformation {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogInfo -message $message
    Write-RunLogLine -Level 'Info' -Message $message
}

function Write-RunWarning {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogWarning -message $message
    Write-RunLogLine -Level 'Warning' -Message $message
}

function Write-RunError {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-RunLogLine -Level 'Error' -Message $message
}

function Write-RunDebug {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogDebug -message $message
    Write-RunLogLine -Level 'Debug' -Message $message
}

function Write-OperationTelemetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Started', 'Succeeded', 'Failed', 'RolledBack')]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [long]$DurationMilliseconds = 0,

        [Parameter(Mandatory = $false)]
        [string]$Detail = ''
    )

    if ($Status -eq 'Started') {
        $script:OperationAttempted++
    }
    elseif ($Status -eq 'Succeeded') {
        $script:OperationSucceeded++
    }
    elseif ($Status -eq 'Failed') {
        $script:OperationFailed++
    }

    $message = "operation=$Operation status=$Status durationMs=$DurationMilliseconds"
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        $message += " detail=$Detail"
    }

    if ($Status -eq 'Failed') {
        Write-RunError $message
    }
    elseif ($Status -eq 'RolledBack') {
        Write-RunWarning $message
    }
    else {
        Write-RunInformation $message
    }
}

Write-RunInformation "event=script_start version=1.3.1 elapsedMs=$($scriptStopwatch.ElapsedMilliseconds)"
Write-RunInformation "Plain text log initialized (desktop copy): $desktopLogFilePath"
Write-RunInformation "Plain text log initialized (collected copy): $collectedLogFilePath"

# LOCAL TEST DEFAULTS: Uncomment the variables below to test locally without --parameters
# You can either:
#   1. Uncomment individual variables and run the script
#   2. Uncomment ONLY $EnableDebugDefaults='true' to activate all defaults
# Example:
#   $DumpType = 'full'
#   $OneDump = 'false'
#   $MovePagefile = 'false'
#   $EnableDebugDefaults = 'true'
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
    Write-RunInformation "EnableDebugDefaults is active. Applying local fallback defaults for missing parameters."
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

    Write-RunOutput ">>> $Title <<<"
    $crashDumpEnabled = (Get-ItemProperty -Path $Path).CrashDumpEnabled

    $currentDumpFile = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).DumpFile
    $currentDedicatedDumpFile = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).DedicatedDumpFile

    Write-RunOutput "DumpFile           : $(if([string]::IsNullOrWhiteSpace("$currentDumpFile")){"NOT FOUND"}else{$currentDumpFile})"
    Write-RunOutput "DedicatedDumpFile  : $(if([string]::IsNullOrWhiteSpace("$currentDedicatedDumpFile")){"NOT FOUND"}else{$currentDedicatedDumpFile})"
    Write-RunOutput "CrashDumpEnabled   : $(Get-DumpTypeLabel -Value $crashDumpEnabled)"
    Write-RunOutput "NMICrashDump       : $(if($null -eq $NMI){"NOT FOUND"}else{$NMI})"
    Write-RunOutput "BootStatusPolicy   : $(if($null -eq $BSP){"NOT FOUND"}else{$BSP})"

    if ($ConfiguredPageFiles) {
        Write-RunOutput "ConfiguredPageFiles (LIVE): $($ConfiguredPageFiles -join ', ')"
    } else {
        # Fallback to registry if WMI returns nothing (unusual)
        $PFile = (Get-ItemProperty -Path $MMPath -ErrorAction SilentlyContinue).ExistingPageFiles
        Write-RunOutput "ExistingPageFiles  : $(if($null -eq $PFile){"NOT FOUND"}else{$PFile})"
    }
}

function Get-PagefileRestoreCommand {
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

    Write-RunWarning "RESTORATION REQUIRED: original pagefile settings were $($OriginalPagefileLocations -join ', ')"
    Write-RunWarning "To restore the original pagefile configuration after debugging, run:"

    foreach ($command in (Get-PagefileRestoreCommand -OriginalPagefileLocations $OriginalPagefileLocations)) {
        Write-RunWarning "  $command"
    }
}

function Invoke-PagefileRollback {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$OriginalPagefileLocations,

        [Parameter(Mandatory = $true)]
        [string]$TargetPagefile
    )

    $rollbackStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-OperationTelemetry -Operation 'PagefileRollback' -Status 'Started'

    try {
        $targetSetting = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -eq $TargetPagefile }
        if ($targetSetting) {
            $targetSetting | Remove-CimInstance -ErrorAction Stop
        }

        $configuredLocations = @(Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue |
                                 Select-Object -ExpandProperty Name)
        foreach ($location in $OriginalPagefileLocations) {
            if (-not [string]::IsNullOrWhiteSpace($location) -and $location -notin $configuredLocations) {
                New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                    Name = $location
                    InitialSize = 0
                    MaximumSize = 0
                } -ErrorAction Stop | Out-Null
            }
        }

        $rollbackStopwatch.Stop()
        Write-OperationTelemetry -Operation 'PagefileRollback' -Status 'RolledBack' -DurationMilliseconds $rollbackStopwatch.ElapsedMilliseconds -Detail "restored=$($OriginalPagefileLocations -join ',')"
        return $true
    }
    catch {
        $rollbackStopwatch.Stop()
        Write-OperationTelemetry -Operation 'PagefileRollback' -Status 'Failed' -DurationMilliseconds $rollbackStopwatch.ElapsedMilliseconds -Detail $_.Exception.Message
        return $false
    }
}

function Invoke-RegistryRollback {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RegistryBackupPaths
    )

    $rollbackStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-OperationTelemetry -Operation 'RegistryRollback' -Status 'Started'

    try {
        foreach ($backupPath in $RegistryBackupPaths) {
            if ([string]::IsNullOrWhiteSpace($backupPath) -or -not (Test-Path -Path $backupPath -PathType Leaf)) {
                continue
            }

            $rollbackResult = & reg.exe import $backupPath 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Registry import failed for '$backupPath': $($rollbackResult -join ' | ')"
            }
        }

        $rollbackStopwatch.Stop()
        Write-OperationTelemetry -Operation 'RegistryRollback' -Status 'RolledBack' -DurationMilliseconds $rollbackStopwatch.ElapsedMilliseconds
        return $true
    }
    catch {
        $rollbackStopwatch.Stop()
        Write-OperationTelemetry -Operation 'RegistryRollback' -Status 'Failed' -DurationMilliseconds $rollbackStopwatch.ElapsedMilliseconds -Detail $_.Exception.Message
        return $false
    }
}

$crashControlBackupPath = ''
$reliabilityBackupPath = ''
$registryChangesApplied = $false
$pagefileWasMoved = $false
$originalPagefileLocations = @()
$targetPagefile = 'C:\pagefile.sys'

try {
    # Step 1 - Audit BEFORE
    Get-AuditSnapshot "AUDITING SETTINGS (BEFORE)"

    $CrashCtrlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $crashControlBackupPath = Join-Path -Path $runOutputDir -ChildPath ("CrashControl-backup-{0}.reg" -f $runTimestamp)
    $backupStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-OperationTelemetry -Operation 'CrashControlBackup' -Status 'Started'
    $backupResult = & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" $crashControlBackupPath /y 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path -Path $crashControlBackupPath -PathType Leaf) -and (Get-Item -Path $crashControlBackupPath).Length -gt 0) {
        $backupStopwatch.Stop()
        Write-OperationTelemetry -Operation 'CrashControlBackup' -Status 'Succeeded' -DurationMilliseconds $backupStopwatch.ElapsedMilliseconds -Detail $crashControlBackupPath
        Write-RunInformation "Created registry backup: $crashControlBackupPath"
    }
    else {
        $backupStopwatch.Stop()
        Write-OperationTelemetry -Operation 'CrashControlBackup' -Status 'Failed' -DurationMilliseconds $backupStopwatch.ElapsedMilliseconds -Detail ($backupResult -join ' | ')
        throw "CrashControl backup could not be verified. No registry changes were applied."
    }

    if ($ConfigureAutomaticReboot -eq 'true') {
        $reliabilityBackupPath = Join-Path -Path $runOutputDir -ChildPath ("Reliability-backup-{0}.reg" -f $runTimestamp)
        $reliabilityBackupStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-OperationTelemetry -Operation 'ReliabilityBackup' -Status 'Started'
        $reliabilityBackupResult = & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" $reliabilityBackupPath /y 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path -Path $reliabilityBackupPath -PathType Leaf) -and (Get-Item -Path $reliabilityBackupPath).Length -gt 0) {
            $reliabilityBackupStopwatch.Stop()
            Write-OperationTelemetry -Operation 'ReliabilityBackup' -Status 'Succeeded' -DurationMilliseconds $reliabilityBackupStopwatch.ElapsedMilliseconds -Detail $reliabilityBackupPath
            Write-RunInformation "Created Reliability registry backup: $reliabilityBackupPath"
        }
        else {
            $reliabilityBackupStopwatch.Stop()
            Write-OperationTelemetry -Operation 'ReliabilityBackup' -Status 'Failed' -DurationMilliseconds $reliabilityBackupStopwatch.ElapsedMilliseconds -Detail ($reliabilityBackupResult -join ' | ')
            throw "Reliability backup could not be verified. Automatic reboot configuration was not changed."
        }
    }

    $initialValue = (Get-ItemProperty -Path $CrashCtrlPath).CrashDumpEnabled
    $dumpTypeMap = @{ 'full' = 1; 'kernel' = 2; 'mini' = 3; 'automatic' = 7; 'active' = 1 }
    $requestedDumpValue = $dumpTypeMap[$DumpType]
    $verificationFailed = $false

    Write-RunOutput "Current dump configuration: $(Get-DumpTypeLabel -Value $initialValue)"
    Write-RunOutput "Requested dump type: $DumpType ($(Get-DumpTypeLabel -Value $requestedDumpValue))"
    Write-RunOutput "Requested DumpFile: $(if([string]::IsNullOrWhiteSpace("$DumpFile")){"NOT SPECIFIED"}else{$DumpFile})"
    Write-RunOutput "Requested DedicatedDumpFile: $(if([string]::IsNullOrWhiteSpace("$DedicatedDumpFile")){"NOT SPECIFIED"}else{$DedicatedDumpFile})"

    # Step 2 - Enable NMI
    $registryChangesApplied = $true
    Set-ItemProperty -Path $CrashCtrlPath -Name NMICrashDump -Value 1 -Type DWord

    # Step 3 - Configure automatic reboot (optional)
    if ($ConfigureAutomaticReboot -eq $true -or $ConfigureAutomaticReboot -eq 'true') {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name BootStatusPolicy -Value 1 -Type DWord
        Write-RunInformation "Automatic reboot on crash configured (BootStatusPolicy=1)."
    }
    else {
        Write-RunInformation "Automatic reboot on crash NOT configured. Use -ConfigureAutomaticReboot true to enable."
    }

    # Step 4 - Pagefile Detection for Smart Placement
    $MMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $currentPFiles = Get-CimInstance -ClassName Win32_PageFileSetting | Select-Object -ExpandProperty Name
    $pagefileOnTempDrive = $false
    $originalPagefileLocations = $currentPFiles
    $pagefileScanProcessed = 0
    $pagefileScanTempMatches = 0

    foreach ($pf in $currentPFiles) {
        $pagefileScanProcessed++
        Write-RunDebug "Detected pagefile setting: $pf"
        if ($pf -like "D:*" -or $pf -like "*D:\*") {
            $pagefileOnTempDrive = $true
            $pagefileScanTempMatches++
            Write-RunWarning "Pagefile detected on D: drive: $pf"
            break
        }
    }
    Write-RunInformation "Pagefile scan summary: processed=$pagefileScanProcessed tempDriveMatches=$pagefileScanTempMatches"

    # INTELLIGENT DUMP PLACEMENT
    # Respect explicit user-provided values exactly as passed.
    if ($DumpFile) {
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile
        Write-RunInformation "Applied user-provided DumpFile: $DumpFile"
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
        Write-RunWarning "PAGEFILE RELOCATION REQUESTED"
        Write-RunWarning "IMPORTANT: Pagefile relocation from D: to C: is DESTRUCTIVE and NOT EASILY REVERSIBLE:"
        Write-RunWarning "    1. If C: drive runs out of space, the VM may crash"
        Write-RunWarning "    2. To restore pagefile to D: after troubleshooting, manual intervention or script re-run is required"
        Write-RunWarning "    3. Ensure C: drive has sufficient free space (recommend minimum 50% free) before proceeding"
        Write-RunWarning "    4. For production VMs, consider scheduling this change during maintenance window"
        Write-PagefileRestoreGuidance -OriginalPagefileLocations $originalPagefileLocations

        $pagefileRelocationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-OperationTelemetry -Operation 'PagefileRelocation' -Status 'Started'
        try {
            # FIX: Explicitly target C: if logic loop fails, bypass the CIM free space comparison bug
            $cDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"

            if ($null -ne $cDrive) {
                # Validate C: drive has sufficient free space
                $cDriveFreeSpaceGB = [math]::Round($cDrive.FreeSpace / 1GB, 2)
                $cDriveTotalSpaceGB = [math]::Round($cDrive.Size / 1GB, 2)
                $cDriveFreePercent = [math]::Round(($cDrive.FreeSpace / $cDrive.Size) * 100, 0)

                Write-RunInformation "C: Drive space status: $cDriveFreeSpaceGB GB free of $cDriveTotalSpaceGB GB ($cDriveFreePercent% free)"

                if ($cDriveFreePercent -lt 20) {
                    Write-RunError "C: Drive free space is below 20% ($cDriveFreePercent%). Relocation aborted to prevent VM crash."
                    throw "Insufficient C: drive free space. Minimum 20% recommended, current: $cDriveFreePercent%"
                }

                Write-RunInformation "C: Drive detected via CIM. Proceeding with relocation..."

                $pageFileSettings = Get-CimInstance -ClassName Win32_PageFileSetting
                $targetPagefileSetting = $pageFileSettings | Where-Object { $_.Name -eq $targetPagefile }
                if (-not $targetPagefileSetting) {
                    New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                        Name = $targetPagefile
                        InitialSize = 0
                        MaximumSize = 0
                    } -ErrorAction Stop | Out-Null
                    Write-RunInformation "Created target pagefile configuration before removing the original: $targetPagefile"
                }

                $pagefileDeleteProcessed = 0
                $pagefileDeleteDeleted = 0
                $pagefileDeleteFailed = 0
                $pagefileDeleteSkipped = 0

                foreach ($pf in $pageFileSettings) {
                    $pagefileDeleteProcessed++
                    if ($pf.Name -like "D:*" -or $pf.Name -like "*D:\*") {
                        try {
                            Write-RunInformation "Deleting current pagefile instance: $($pf.Name)"
                            $pf | Remove-CimInstance -ErrorAction Stop
                            $pagefileDeleteDeleted++
                        }
                        catch {
                            $pagefileDeleteFailed++
                            Write-RunWarning "Failed to delete pagefile instance '$($pf.Name)': $($_.Exception.Message)"
                        }
                    }
                    else {
                        $pagefileDeleteSkipped++
                    }
                }
                Write-RunInformation "Pagefile delete summary: processed=$pagefileDeleteProcessed deleted=$pagefileDeleteDeleted skipped=$pagefileDeleteSkipped failed=$pagefileDeleteFailed"

                if ($pagefileDeleteFailed -gt 0) {
                    throw "One or more D: pagefile entries could not be removed. See logs for details."
                }

                $pagefileWasMoved = $true
                $pagefileRelocationStopwatch.Stop()
                Write-OperationTelemetry -Operation 'PagefileRelocation' -Status 'Succeeded' -DurationMilliseconds $pagefileRelocationStopwatch.ElapsedMilliseconds -Detail "target=$targetPagefile removed=$pagefileDeleteDeleted"
                Write-RunInformation "Successfully updated CIM configuration to: $targetPagefile"
            } else {
                throw "C: drive could not be verified via CIM. Relocation aborted."
            }
        }
        catch {
            $pagefileRelocationStopwatch.Stop()
            Write-OperationTelemetry -Operation 'PagefileRelocation' -Status 'Failed' -DurationMilliseconds $pagefileRelocationStopwatch.ElapsedMilliseconds -Detail $_.Exception.Message
            Write-RunError "Failed to relocate pagefile: $($_.Exception.Message)"
            $rollbackSucceeded = Invoke-PagefileRollback -OriginalPagefileLocations $originalPagefileLocations -TargetPagefile $targetPagefile
            if (-not $rollbackSucceeded) {
                Write-RunError "Automatic pagefile rollback failed. Use the logged restoration commands immediately."
            }
            $verificationFailed = $true
        }
    }

    # Step 6 - DedicatedDumpFile
    if ($DedicatedDumpFile -eq "delete") {
        Remove-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -ErrorAction SilentlyContinue
        Write-RunInformation "Applied user request: DedicatedDumpFile deleted."
    }
    elseif ($DedicatedDumpFile) {
        Set-ItemProperty -Path $CrashCtrlPath -Name DedicatedDumpFile -Value $DedicatedDumpFile
        Write-RunInformation "Applied user-provided DedicatedDumpFile: $DedicatedDumpFile"
    }

    # Step 7 - Guard for empty DumpFile (ensure valid path before kdbgctrl)
    if ([string]::IsNullOrEmpty($DumpFile)) {
        Write-RunWarning "DumpFile is empty. Using Windows default: %SystemRoot%\MEMORY.DMP"
        $DumpFile = "%SystemRoot%\MEMORY.DMP"
        Set-ItemProperty -Path $CrashCtrlPath -Name DumpFile -Value $DumpFile
    }

    # Step 8 - Apply to LIVE KERNEL
    Write-RunInformation "Applying dump type '$DumpType' via kdbgctrl..."
    Set-ItemProperty -Path $CrashCtrlPath -Name CrashDumpEnabled -Value 0

    $toolPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\tools\kdbgctrl.exe'
    if (-not (Test-Path -Path $toolPath -PathType Leaf)) {
        throw "Missing required dependency: $toolPath"
    }
    $kdbgStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-OperationTelemetry -Operation 'KdbgctrlApply' -Status 'Started'
    $kdbgResult = & $toolPath -sd $DumpType 2>&1
    $kdbgExitCode = $LASTEXITCODE
    $parsedKdbg = Get-KdbgctrlOutputSummary -OutputLines $kdbgResult

    if ($parsedKdbg.Suppressed.Count -gt 0) {
        Write-RunDebug "Suppressed non-actionable kdbgctrl messages: $($parsedKdbg.Suppressed -join ' | ')"
    }

    if ($kdbgExitCode -ne 0) {
        $kdbgStopwatch.Stop()
        Write-OperationTelemetry -Operation 'KdbgctrlApply' -Status 'Failed' -DurationMilliseconds $kdbgStopwatch.ElapsedMilliseconds -Detail "exitCode=$kdbgExitCode"
        $verificationFailed = $true
        Write-RunError "kdbgctrl failed with exit code $kdbgExitCode. Output: $($parsedKdbg.Filtered -join ' | ')"
    }
    else {
        $kdbgStopwatch.Stop()
        Write-OperationTelemetry -Operation 'KdbgctrlApply' -Status 'Succeeded' -DurationMilliseconds $kdbgStopwatch.ElapsedMilliseconds -Detail "dumpType=$DumpType"
        $successMatched = $false
        foreach ($line in $parsedKdbg.Filtered) {
            if ($line -match '(?i)success|successfully updated dump settings') {
                $successMatched = $true
                break
            }
        }

        if ($successMatched) {
            Write-RunOutput "Successfully updated dump settings to '$DumpType' via kdbgctrl."
        }
        elseif ($parsedKdbg.Filtered.Count -gt 0) {
            Write-RunWarning "kdbgctrl completed with unexpected output: $($parsedKdbg.Filtered -join ' | ')"
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
    Write-RunInformation "Dump configuration task completed."

    # Step 11 - Final Audit AFTER
    $verificationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-OperationTelemetry -Operation 'PostApplyVerification' -Status 'Started'
    Get-AuditSnapshot "VERIFYING UPDATED SETTINGS (AFTER)"

    $effectiveCrashControl = Get-ItemProperty -Path $CrashCtrlPath -ErrorAction SilentlyContinue
    $currentDumpValue = $effectiveCrashControl.CrashDumpEnabled
    if ($OneDump -eq $true -or $OneDump -eq 'true') {
        if ($currentDumpValue -ne $initialValue) {
            $verificationFailed = $true
            Write-RunError "OneDump verification failed. Expected original value $(Get-DumpTypeLabel -Value $initialValue), found $(Get-DumpTypeLabel -Value $currentDumpValue)."
        }
        else {
            Write-RunOutput "OneDump requested. CrashDumpEnabled restored to $(Get-DumpTypeLabel -Value $currentDumpValue)."
        }
    }
    elseif ($currentDumpValue -ne $requestedDumpValue) {
        $verificationFailed = $true
        Write-RunError "Dump configuration verification failed. Expected $(Get-DumpTypeLabel -Value $requestedDumpValue), found $(Get-DumpTypeLabel -Value $currentDumpValue)."
    }
    else {
        Write-RunOutput "Verified dump configuration: $(Get-DumpTypeLabel -Value $currentDumpValue)."
    }

    if ($effectiveCrashControl.NMICrashDump -ne 1) {
        $verificationFailed = $true
        Write-RunError "NMICrashDump verification failed. Expected 1, found $($effectiveCrashControl.NMICrashDump)."
    }

    $expectedDumpFile = [Environment]::ExpandEnvironmentVariables($DumpFile)
    $actualDumpFile = [Environment]::ExpandEnvironmentVariables("$($effectiveCrashControl.DumpFile)")
    if ($actualDumpFile -ne $expectedDumpFile) {
        $verificationFailed = $true
        Write-RunError "DumpFile verification failed. Expected '$expectedDumpFile', found '$actualDumpFile'."
    }

    if ($DedicatedDumpFile -eq 'delete' -and -not [string]::IsNullOrWhiteSpace("$($effectiveCrashControl.DedicatedDumpFile)")) {
        $verificationFailed = $true
        Write-RunError "DedicatedDumpFile verification failed. The value should have been removed."
    }
    elseif ($DedicatedDumpFile -and $DedicatedDumpFile -ne 'delete' -and $effectiveCrashControl.DedicatedDumpFile -ne $DedicatedDumpFile) {
        $verificationFailed = $true
        Write-RunError "DedicatedDumpFile verification failed. Expected '$DedicatedDumpFile', found '$($effectiveCrashControl.DedicatedDumpFile)'."
    }
    elseif (-not $DedicatedDumpFile -and $pagefileOnTempDrive -and $effectiveCrashControl.DedicatedDumpFile -ne 'C:\dd.sys') {
        $verificationFailed = $true
        Write-RunError "DedicatedDumpFile fallback verification failed. Expected 'C:\dd.sys', found '$($effectiveCrashControl.DedicatedDumpFile)'."
    }

    if ($ConfigureAutomaticReboot -eq 'true') {
        $effectiveBootStatusPolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -ErrorAction SilentlyContinue).BootStatusPolicy
        if ($effectiveBootStatusPolicy -ne 1) {
            $verificationFailed = $true
            Write-RunError "BootStatusPolicy verification failed. Expected 1, found $effectiveBootStatusPolicy."
        }
    }

    if ($pagefileWasMoved) {
        $effectivePagefiles = @(Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        $remainingOriginalPagefiles = @($originalPagefileLocations | Where-Object { $_ -like 'D:*' -and $_ -in $effectivePagefiles })
        if ($targetPagefile -notin $effectivePagefiles -or $remainingOriginalPagefiles.Count -gt 0) {
            $verificationFailed = $true
            Write-RunError "Pagefile relocation verification failed. Current settings: $($effectivePagefiles -join ', ')."
        }
    }

    Write-RunOutput "Effective DumpFile: $($effectiveCrashControl.DumpFile)"
    Write-RunOutput "Effective DedicatedDumpFile: $($effectiveCrashControl.DedicatedDumpFile)"

    if ($pagefileWasMoved) {
        Write-RunOutput "PAGEFILE RELOCATION COMPLETED: Pagefile moved from temporary D: drive."
        Write-PagefileRestoreGuidance -OriginalPagefileLocations $originalPagefileLocations
    }

    $verificationStopwatch.Stop()
    if ($verificationFailed) {
        Write-OperationTelemetry -Operation 'PostApplyVerification' -Status 'Failed' -DurationMilliseconds $verificationStopwatch.ElapsedMilliseconds
    }
    else {
        Write-OperationTelemetry -Operation 'PostApplyVerification' -Status 'Succeeded' -DurationMilliseconds $verificationStopwatch.ElapsedMilliseconds
    }

    if ($verificationFailed) {
        Write-RunError "event=script_failure reason=post_apply_verification"
        Write-RunError "Configuration completed with one or more validation errors."
        $script_final_status = $STATUS_ERROR
    }
    else {
        Write-RunInformation "event=script_success"
        Write-RunOutput "SUCCESS: Configuration applied immediately - NO REBOOT REQUIRED"
        Write-RunInformation "Desktop log file: $desktopLogFilePath"
        Write-RunInformation "Collected log file: $collectedLogFilePath"
        $script_final_status = $STATUS_SUCCESS
    }
}
catch {
    Write-RunError "event=script_failure reason=exception"
    Write-RunError "Failure: $($_.Exception.Message)"
    if ($pagefileWasMoved) {
        $pagefileRollbackSucceeded = Invoke-PagefileRollback -OriginalPagefileLocations $originalPagefileLocations -TargetPagefile $targetPagefile
        if (-not $pagefileRollbackSucceeded) {
            Write-RunError "Automatic pagefile rollback failed. Use the logged restoration commands immediately."
            Write-PagefileRestoreGuidance -OriginalPagefileLocations $originalPagefileLocations
        }
    }

    if ($registryChangesApplied) {
        $registryRollbackSucceeded = Invoke-RegistryRollback -RegistryBackupPaths @($crashControlBackupPath, $reliabilityBackupPath)
        if (-not $registryRollbackSucceeded) {
            if ($crashControlBackupPath -and (Test-Path -Path $crashControlBackupPath -PathType Leaf)) {
                Write-RunWarning "Manual rollback required. Run: reg import `"$crashControlBackupPath`""
            }
            if ($reliabilityBackupPath -and (Test-Path -Path $reliabilityBackupPath -PathType Leaf)) {
                Write-RunWarning "Manual rollback required. Run: reg import `"$reliabilityBackupPath`""
            }
        }
    }
    $script_final_status = $STATUS_ERROR
}
finally {
    $scriptStopwatch.Stop()
    Write-RunInformation "operationSummary attempted=$script:OperationAttempted succeeded=$script:OperationSucceeded failed=$script:OperationFailed"
    Write-RunInformation "event=final_status status=$script_final_status durationSeconds=$([math]::Round($scriptStopwatch.Elapsed.TotalSeconds, 3))"
    Write-RunInformation "Script ended at $(Get-Date)"
}

return $script_final_status
