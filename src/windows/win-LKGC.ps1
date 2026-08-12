<#
.SYNOPSIS
    Restores Last Known Good Configuration (LKGC) on attached Windows OS disks by updating
    Select values in each offline SYSTEM registry hive.

.DESCRIPTION
    This script runs from a rescue VM to activate LKGC on an attached faulty OS disk.
    Utilizes direct .NET Registry APIs to prevent handle locking and eliminate 0xc0000225 corruptions.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions, grouping by DiskNumber to isolate targets.
    2. Creates a safety backup of the target SYSTEM hive before modification.
    3. Loads the SOFTWARE hive temporarily to verify the specific Windows version threshold engine.
    4. Opens the Select key using explicit .NET API frameworks to avoid provider caching.
    5. Evaluates threshold logic metrics via strict AND-logic parameters.
    6. Increments the configuration values (current, default, failed, LastKnownGood) to force LKGC validation.
    7. Unloads the hive safely using a defensive 3x retry loop with explicit garbage collection.

.NOTES
    Name:          win-LKGC.ps1
    Author:        Tony.Mocanu@Microsoft.com
    Last Modified: 2026-08-12
    Version:       1.4
    Requirement:   Azure repair VM with an attached Windows OS disk and the VMRepair common helpers
    DeployMode:    az vm repair run (with --run-on-repair)
    Telemetry:     Emits structured start, success, output, and error events through the VMRepair logger

    Verification:
    1. Check the log file for success:
Get-ChildItem "C:\Users\Public\Desktop\win-LKGC-run-*\win-LKGC-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    2. Confirm the presence of the terminal confirmation string:
       "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE"

    Version history:
    v1.4: [Aug 2026] - Added structured VMRepair telemetry for LKGC restoration.
    v1.3 [Jul 2026] - Partition Architecture Alignment: Refactored the core disk processing
                         loop to group by DiskNumber and map drive properties exactly like the
                         validated sac-enabler.ps1 framework.
    v1.2: [May - Jul 2026] - Production Hardening & Handle Updates

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-LKGC --run-on-repair
.LINK
    How to start Azure Windows VM with Last Known Good Configuration - Virtual Machines | Microsoft Learn
#>

# Initialization (path-validated - matching local file layout)
$initPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\setup\init.ps1'
$diskPartitionsPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'

if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

if (-not (Test-Path -Path $diskPartitionsPath -PathType Leaf)) {
    Log-Error "Missing required dependency: $diskPartitionsPath"
    return $STATUS_ERROR
}

. $diskPartitionsPath

# Script-level logging: create a plain text desktop log that mirrors Log-* output.
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runOutputDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$logFilePath = Join-Path -Path $runOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)

if (-not (Test-Path -Path $runOutputDir -PathType Container)) {
    New-Item -Path $runOutputDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -Path $logFilePath -PathType Leaf)) {
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock

function Write-DesktopLogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [PSObject[]]$Message
    )
    try {
        $renderedMessage = ($Message | ForEach-Object { "$_" }) -join ' '
        $line = "[{0} {1}]{2}" -f $Level, (Get-Date), $renderedMessage
        Add-Content -Path $logFilePath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        if ($script:OriginalLogWarning) {
            & $script:OriginalLogWarning -message "Failed to append to desktop log '$logFilePath': $($_.Exception.Message)"
        }
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-DesktopLogLine -Level 'Output' -Message $message
}
function Log-Info { Param([PSObject[]]$message) & $script:OriginalLogInfo -message $message; Write-DesktopLogLine -Level 'Info' -Message $message }
function Log-Warning { Param([PSObject[]]$message) & $script:OriginalLogWarning -message $message; Write-DesktopLogLine -Level 'Warning' -Message $message }
function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-DesktopLogLine -Level 'Error' -Message $message
}
function Log-Debug { Param([PSObject[]]$message) & $script:OriginalLogDebug -message $message; Write-DesktopLogLine -Level 'Debug' -Message $message }

$script:RepairScriptVersion = '1.3'
$script:ExecutionStarted = Get-Date

function Write-LkgcTelemetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Operation', 'Success', 'Error')]
        [string]$Event,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [hashtable]$Properties = @{}
    )

    $payload = [ordered]@{
        Event = $Event
        Message = $Message
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RepairScriptVersion = $script:RepairScriptVersion
        Properties = $Properties
    }

    $json = $payload | ConvertTo-Json -Compress -Depth 8
    if ($Event -eq 'Error') {
        Log-Error "[Telemetry] $json" | Out-Null
    }
    else {
        Log-Info "[Telemetry] $json" | Out-Null
    }
}

Log-Info "Starting AUTO LKGC Script. Desktop log: $logFilePath"
Log-Info "[script_start] Script=win-LKGC Version=$($script:RepairScriptVersion)"
Write-LkgcTelemetry -Event Start -Message 'Starting LKGC restoration' -Properties @{
    ScriptName = 'win-LKGC.ps1'
    ScriptVersion = $script:RepairScriptVersion
    ExecutionMode = 'REPAIR_VM_ONLY'
    DesktopLog = $logFilePath
}

# Status Tracking
$script_final_status = $STATUS_ERROR
$lkgcAppliedAny = $false
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

try {
    # Check if the Hyper-V module is available before performing nested VM checks
    if (Get-Module -ListAvailable -Name Hyper-V) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine -and $guestHyperVVirtualMachine.State -eq 'Running') {
            Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
            try { Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force } catch { Log-Warning "Failed to stop nested guest VM" }
        }
    } else {
        Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
    }

    # Step 1 - Enumerate and Group partitions matching the sac-enabler architecture
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $fixedDisks = @()

    Log-Info 'Enumerating disk partitions for LKGC analysis...'

    foreach ($partitionGroup in $partitionlist | Group-Object DiskNumber) {
        $processedCount++
        $diskNumber = $partitionGroup.Name
        $targetOSDrive = $null

        Log-Info "Processing Disk $diskNumber"

        # Scan each drive letter within this disk group for a valid Windows OS directory
        foreach ($drive in $partitionGroup.Group | Select-Object -ExpandProperty DriveLetter) {
            if ([string]::IsNullOrWhiteSpace($drive) -or $drive -eq $rescueDrive) {
                $skippedCount++
                continue
            }

            if (Test-Path -Path "$(${drive}):\Windows\System32\config\SYSTEM") {
                $targetOSDrive = $drive
                break
            }
        }

        if (-not $targetOSDrive) {
            Log-Info "Disk $diskNumber skipped: no valid attached OS partition containing \Windows found."
            $skippedCount++
            continue
        }

        Log-Info "Target OS partition successfully matched on letter: $($targetOSDrive):"

        $systemHivePath = "$(${targetOSDrive}):\Windows\System32\config\SYSTEM"
        $systemHiveBackup = "$systemHivePath.LKGC.bak.$runTimestamp"

        try {
            Copy-Item -LiteralPath $systemHivePath -Destination $systemHiveBackup -Force -ErrorAction Stop
            Log-Info "[$targetOSDrive] SYSTEM hive backup created: $systemHiveBackup"
        }
        catch {
            $failedCount++
            Log-Error "[$targetOSDrive] Failed to create SYSTEM hive backup. Skipping disk. Error: $($_.Exception.Message)"
            continue
        }

        # Step 2 - Load the SOFTWARE hive to detect the Windows version
        $swHive = "HKLM\BROKENSW_$targetOSDrive"
        $null = & reg.exe unload $swHive 2>&1
        $swLoad = & reg.exe load $swHive "$(${targetOSDrive}):\Windows\System32\config\software" 2>&1

        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Log-Warning "Failed to load SOFTWARE hive from $($targetOSDrive): $($swLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2
        $productName = (Get-ItemProperty -path "registry::$swHive\microsoft\windows nt\currentversion" -ErrorAction SilentlyContinue).ProductName
        $winosver = 0
        if ($productName -match '(\d+)') { $winosver = [int]$matches[1] }
        $softwareHiveUnloaded = $false
        for ($i = 1; $i -le 3; $i++) {
            $swUnloadOutput = & reg.exe unload $swHive 2>&1
            if ($LASTEXITCODE -eq 0) {
                $softwareHiveUnloaded = $true
                break
            }
            Start-Sleep -Seconds 2
        }
        if (-not $softwareHiveUnloaded) {
            $failedCount++
            Log-Error "[$targetOSDrive] Could not unload $swHive cleanly: $($swUnloadOutput -join ' | '). No SYSTEM hive changes were attempted."
            continue
        }

        # Step 3 - Load the SYSTEM hive from the target disk
        $sysHive = "HKLM\BROKENSYS_$targetOSDrive"
        $null = & reg.exe unload $sysHive 2>&1
        $sysLoad = & reg.exe load $sysHive $systemHivePath 2>&1

        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Log-Warning "Failed to load SYSTEM hive from $($targetOSDrive): $($sysLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2

        $writeAttempted = $false
        $restoreRequired = $false
        $registryProcessingFailed = $false
        $subKeyPath = "BROKENSYS_$targetOSDrive\Select"
        $regKey = $null

        try {
            # Step 4 - Open via direct .NET API to eliminate PowerShell registry caching engine bugs
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $true)
            if ($null -eq $regKey) { throw "Failed to open Select key via explicit .NET path: HKLM:\$subKeyPath" }

            $currentVal    = [int]$regKey.GetValue('current')
            $defaultVal    = [int]$regKey.GetValue('default')
            $failedVal     = [int]$regKey.GetValue('failed')
            $lastKnownGood = [int]$regKey.GetValue('LastKnownGood')

            $before = [PSCustomObject]@{
                Current       = $currentVal
                Default       = $defaultVal
                Failed        = $failedVal
                LastKnownGood = $lastKnownGood
            }

            Write-LkgcTelemetry -Event Operation -Message "Starting LKGC restoration on drive $targetOSDrive" -Properties @{
                DiskNumber   = "$diskNumber"
                TargetDrive  = "$targetOSDrive"
                SelectBefore = "$($before.Current),$($before.Default),$($before.Failed),$($before.LastKnownGood)"
            }

            Log-Info "[$targetOSDrive] REGISTRY STATE [BEFORE]: Current=$currentVal, Default=$defaultVal, Failed=$failedVal, LKG=$lastKnownGood"

            # Step 5 - Evaluate version thresholds using matching AND-logic sequences
            $alreadySet = $false
            if ((($winosver -ge 10) -and ($winosver -lt 100)) -or ($winosver -ge 2016)) {
                if (($currentVal -ge 2) -and ($defaultVal -ge 2) -and ($failedVal -ge 1) -and ($lastKnownGood -ge 2)) { $alreadySet = $true }
            }
            elseif ($winosver -eq 2012) {
                if (($currentVal -ge 2) -and ($defaultVal -ge 2) -and ($failedVal -ge 1) -and ($lastKnownGood -ge 3)) { $alreadySet = $true }
            }

            if ($alreadySet) {
                Log-Warning "[$targetOSDrive] LKGC WAS ALREADY SET, NO CHANGES DONE"
                Log-Info "[$targetOSDrive] LKGC_APPLIED=false"
                Write-LkgcTelemetry -Event Success -Message "LKGC restoration not required on drive $targetOSDrive" -Properties @{
                    DiskNumber  = "$diskNumber"
                    TargetDrive = "$targetOSDrive"
                    Changed     = 'false'
                }
            }
            else {
                # Step 6 - Increment configuration spaces via .NET context
                $writeAttempted = $true
                $regKey.SetValue('current', ($currentVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('default', ($defaultVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('failed', ($failedVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('LastKnownGood', ($lastKnownGood + 1), [Microsoft.Win32.RegistryValueKind]::DWord)

                # Step 7 - Validate downstream configurations
                $afterCurrent = $regKey.GetValue('current')
                $afterDefault = $regKey.GetValue('default')
                $afterFailed  = $regKey.GetValue('failed')
                $afterLKG     = $regKey.GetValue('LastKnownGood')

                if (($afterCurrent -ne ($currentVal + 1)) -or
                    ($afterDefault -ne ($defaultVal + 1)) -or
                    ($afterFailed -ne ($failedVal + 1)) -or
                    ($afterLKG -ne ($lastKnownGood + 1))) {
                    throw 'SYSTEM hive Select values did not match the requested LKGC updates.'
                }

                $after = [PSCustomObject]@{
                    Current       = $afterCurrent
                    Default       = $afterDefault
                    Failed        = $afterFailed
                    LastKnownGood = $afterLKG
                }

                Log-Info "[$targetOSDrive] REGISTRY STATE [AFTER]: Current=$afterCurrent, Default=$afterDefault, Failed=$afterFailed, LKG=$afterLKG"

                $telemetryProperties = @{
                    DiskNumber  = "$diskNumber"
                    TargetDrive = "$targetOSDrive"
                    SelectAfter = "$($after.Current),$($after.Default),$($after.Failed),$($after.LastKnownGood)"
                    Changed     = 'true'
                }

                Log-Output -Message "LKGC APPLIED"
                Write-LkgcTelemetry -Event Success -Message "LKGC registry values updated on drive $targetOSDrive" -Properties $telemetryProperties

                $lkgcAppliedAny = $true
                $changedCount++
                Log-Info "[$targetOSDrive] LKGC_APPLIED=true"
            }

            $fixedDisks += $targetOSDrive
        }
        catch {
            $failedCount++
            $registryProcessingFailed = $true
            if ($writeAttempted) { $restoreRequired = $true }
            Log-Error -Message "[$targetOSDrive] Failed to process registry modifications: $($_.Exception.Message)"
            Write-LkgcTelemetry -Event Error -Message 'Failed to process registry modifications' -Properties @{
                DiskNumber    = "$diskNumber"
                TargetDrive   = "$targetOSDrive"
                WriteAttempted = "$writeAttempted"
                Error = $_.Exception.Message
            }
            Log-Info "[$targetOSDrive] LKGC_APPLIED=false"
        }
        finally {
            if ($null -ne $regKey) {
                try {
                    $regKey.Flush()
                }
                catch {
                    if (-not $registryProcessingFailed) {
                        $failedCount++
                        $registryProcessingFailed = $true
                    }
                    $restoreRequired = $true
                    Log-Error "[$targetOSDrive] Failed to flush the SYSTEM hive Select key: $($_.Exception.Message)"
                }
                finally {
                    try { $regKey.Close() } catch {}
                    try { $regKey.Dispose() } catch {}
                }
            }
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2

            # Step 8 - Unload the registry hive using the 3x safety retry array
            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadOutput = & reg.exe unload $sysHive 2>&1
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Start-Sleep -Seconds 5
            }

            if (-not $unloaded) {
                if (-not $registryProcessingFailed) {
                    $failedCount++
                    $registryProcessingFailed = $true
                }
                $restoreRequired = $true
                Log-Error "Could not unload $sysHive cleanly. The disk will not be reported as successfully processed."
                $fixedDisks = @($fixedDisks | Where-Object { $_ -ne $targetOSDrive })
            }

            if ($restoreRequired) {
                if (-not $unloaded) {
                    Log-Error "[$targetOSDrive] SYSTEM hive backup cannot be restored while $sysHive remains loaded. Manual recovery may be required from $systemHiveBackup."
                }
                else {
                    try {
                        Copy-Item -LiteralPath $systemHiveBackup -Destination $systemHivePath -Force -ErrorAction Stop
                        Log-Warning "[$targetOSDrive] Restored SYSTEM hive backup after the failed write attempt."
                    }
                    catch {
                        Log-Error "[$targetOSDrive] CRITICAL: Failed to restore SYSTEM hive backup '$systemHiveBackup': $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    if ($failedCount -gt 0) {
        throw "LKGC processing failed on $failedCount disk(s). Review the preceding disk errors."
    }
    elseif ($fixedDisks.Count -gt 0 -or $changedCount -gt 0) {
        if ($lkgcAppliedAny) {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE, LKGC APPLIED on drives: $($fixedDisks -join ', ')"
        } else {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=FALSE (NO CHANGES REQUIRED), drives processed: $($fixedDisks -join ', ')"
        }
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached containing \Windows structure."
    }
}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    $durationSeconds = [math]::Round(((Get-Date) - $script:ExecutionStarted).TotalSeconds, 3)
    $finalTelemetryProperties = @{
        FinalStatus    = "$script_final_status"
        DurationSeconds = $durationSeconds
        DisksProcessed = "$processedCount"
        DisksChanged   = "$changedCount"
        DisksSkipped   = "$skippedCount"
        DisksFailed    = "$failedCount"
    }

    if ($script_final_status -eq $STATUS_SUCCESS) {
        Write-LkgcTelemetry -Event Success -Message 'LKGC restoration script completed successfully' -Properties $finalTelemetryProperties
    }
    else {
        Write-LkgcTelemetry -Event Error -Message 'LKGC restoration script completed with errors' -Properties $finalTelemetryProperties
    }

    Log-Info "[final_status] Status=$script_final_status"
    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
