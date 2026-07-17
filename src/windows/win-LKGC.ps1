<#
.SYNOPSIS
    Enables Last Known Good Configuration (LKGC) by incrementing the Select registry values.

.DESCRIPTION
    This script runs from a rescue VM to activate LKGC on an attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the faulty OS drive.
    2. Loads the SOFTWARE hive to detect the Windows version (Win10 / Server 2012 / 2016+).
    3. Loads the SYSTEM hive from the target disk into HKLM\BROKENSYSTEM.
    4. Reads the current Select key values (Current, Default, Failed, LastKnownGood).
    5. Checks whether LKGC has already been applied (version-specific thresholds).
    6. If not already set, increments all four Select values by 1 to trigger LKGC on next boot.
    7. Logs the BEFORE and AFTER registry states for verification.
    8. Unloads the registry hive cleanly.

.NOTES
    Name:    win-LKGC.ps1
    Author:  Tony.Mocanu@Microsoft.com

.VERSION
    v1.4: [Jul 2026] - Production hardening update
                       - Added helper path validation before dot-sourcing.
                       - Switched to desktop log file with explicit startup/completion log path.
                       - Captured critical reg.exe command outputs (no Out-Null suppression).
                       - Added SYSTEM hive backup + rollback-on-failure behavior.
                       - Added processed/skipped/failed/changed summary counters.
    v1.3: [May 2026] - Updated the script (current)
                       - Added LKGC_APPLIED log flag (per disk + overall) and corrected final summary message.
    v1.2: [May 2026] - Updated the script
                       - Fixed Get-VM crash when Hyper-V module is not installed on host (guarded Get-VM).
                       - Fixed false "already set" detection by requiring ALL thresholds (AND instead of OR).
    v1.1: Previous version
    v0.1: Initial commit

.LINK
    https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/start-vm-last-known-good
    https://support.microsoft.com/en-us/topic/you-receive-error-stop-error-code-0x0000007b-inaccessible-boot-device-after-you-install-windows-updates-7cc844e4-4daf-a71c-cd23-f99b50d53e31
#>

# ==============================================================================
# 1. DEPENDENCY PATH VALIDATION & INITIALIZATION (DEP-01)
# ==============================================================================
# $PSScriptRoot can be empty when invoked through ScriptBlock execution.
# Fall back to call stack script attribution to resolve the originating file directory.
$resolvedScriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    $resolvedScriptRoot = Split-Path -Parent (Get-PSCallStack | Where-Object { $_.ScriptName } | Select-Object -First 1).ScriptName
}
if ([string]::IsNullOrEmpty($resolvedScriptRoot)) {
    Write-Error "Cannot determine script directory: PSScriptRoot is empty and call stack provides no path."
    return 1
}

$initPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\setup\init.ps1'
$partitionsHelperPath = Join-Path -Path $resolvedScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'

if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

if (-not (Test-Path -Path $partitionsHelperPath -PathType Leaf)) {
    Log-Error "Missing required dependency: $partitionsHelperPath"
    return $STATUS_ERROR
}

. $partitionsHelperPath

# Log Configuration
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath) -or -not (Test-Path -LiteralPath $desktopPath)) {
    $desktopPath = 'C:\Users\Public\Desktop'
    if (-not (Test-Path -LiteralPath $desktopPath)) {
        $null = New-Item -ItemType Directory -Path $desktopPath -Force
    }
}

$desktopLogFile = Join-Path $desktopPath "LKGC_$timestamp.log"

$pluginLogDir = 'C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension'
if (-not (Test-Path -LiteralPath $pluginLogDir)) {
    $null = New-Item -ItemType Directory -Path $pluginLogDir -Force
}
$pluginLogFile = Join-Path $pluginLogDir "LKGC_$timestamp.log"

function Write-RepairLog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Warning', 'Error', 'Output')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    switch ($Level) {
        'Info'    { Log-Info $Message }
        'Warning' { Log-Warning $Message }
        'Error'   { Log-Error $Message }
        'Output'  { Log-Output $Message }
    }

    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -LiteralPath $desktopLogFile -Value $line

    if ($pluginLogFile -ne $desktopLogFile) {
        Add-Content -LiteralPath $pluginLogFile -Value $line
    }
}

# Status Tracking
$script_final_status = $STATUS_ERROR

# NEW: Track whether LKGC was actually applied anywhere
$lkgcAppliedAny = $false
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

try {
    Write-RepairLog -Level Info -Message "Starting AUTO LKGC Script..."
    Write-RepairLog -Level Info -Message "Desktop log file path: $desktopLogFile"
    Write-RepairLog -Level Info -Message "Plugin log file path: $pluginLogFile"

    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-RepairLog -Level Info -Message "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-RepairLog -Level Warning -Message "Failed to stop nested guest VM, will continue but may have limited success"
                    }
                }
            }
        } else {
            Write-RepairLog -Level Info -Message "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-RepairLog -Level Warning -Message "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Step 1 - Enumerate partitions to locate the faulty OS drive(s)
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $fixedDisks = @()

    foreach ($partition in $partitionlist) {
        if (-not $partition.DriveLetter) {
            $skippedCount++
            continue
        }

        # Skip the rescue VM's own OS drive (its hives are locked by the running OS)
        if ($partition.DriveLetter -eq $rescueDrive) {
            Write-RepairLog -Level Info -Message "Skipping rescue VM system drive $rescueDrive (own OS)"
            $skippedCount++
            continue
        }

        if (-not (Test-Path -Path "$($partition.DriveLetter):\Windows")) {
            $skippedCount++
            continue
        }

        $diskb = $partition.DriveLetter
        $processedCount++
        Write-RepairLog -Level Info -Message "Target OS disk found on letter: $($diskb):"

        $systemHivePath = "$($diskb):\Windows\System32\config\SYSTEM"
        $systemHiveBackup = "$systemHivePath.LKGC.bak.$timestamp"
        try {
            Copy-Item -LiteralPath $systemHivePath -Destination $systemHiveBackup -Force -ErrorAction Stop
            Write-RepairLog -Level Info -Message "[$diskb] SYSTEM hive backup created: $systemHiveBackup"
        }
        catch {
            $failedCount++
            Write-RepairLog -Level Error -Message "[$diskb] Failed to create SYSTEM hive backup. Skipping disk. Error: $($_.Exception.Message)"
            continue
        }

        # Step 2 - Load the SOFTWARE hive to detect the Windows version
        $swHive = "HKLM\BROKENSW_$diskb"
        $swPreUnload = & reg.exe unload $swHive 2>&1
        Write-RepairLog -Level Info -Message "[$diskb] Pre-load SOFTWARE unload output: $($swPreUnload -join ' | ')"
        $swLoad = & reg.exe load $swHive "$($diskb):\Windows\System32\config\software" 2>&1
        Write-RepairLog -Level Info -Message "[$diskb] SOFTWARE load output: $($swLoad -join ' | ')"
        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Write-RepairLog -Level Warning -Message "Failed to load SOFTWARE hive from $($diskb): $($swLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2
        $productName = (Get-ItemProperty -path "registry::$swHive\microsoft\windows nt\currentversion" -ErrorAction SilentlyContinue).ProductName
        $winosver = 0
        if ($productName -match '(\d+)') { $winosver = [int]$matches[1] }
        $swUnload = & reg.exe unload $swHive 2>&1
        Write-RepairLog -Level Info -Message "[$diskb] SOFTWARE unload output: $($swUnload -join ' | ')"

        # Step 3 - Load the SYSTEM hive from the target disk
        $sysHive = "HKLM\BROKENSYS_$diskb"
        $sysPreUnload = & reg.exe unload $sysHive 2>&1
        Write-RepairLog -Level Info -Message "[$diskb] Pre-load SYSTEM unload output: $($sysPreUnload -join ' | ')"
        Write-RepairLog -Level Info -Message "Loading System hive from $($diskb): as $sysHive..."
        $sysLoad = & reg.exe load $sysHive "$($diskb):\Windows\System32\config\SYSTEM" 2>&1
        Write-RepairLog -Level Info -Message "[$diskb] SYSTEM load output: $($sysLoad -join ' | ')"
        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Write-RepairLog -Level Warning -Message "Failed to load SYSTEM hive from $($diskb): $($sysLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2

        $writeAttempted = $false
        $restoreRequired = $false

        try {
            # Step 4 - Read the current Select key values (BEFORE state)
            $selectPath = "Registry::$sysHive\Select"
            $before = Get-ItemProperty -path $selectPath
            Write-RepairLog -Level Info -Message "[$diskb] REGISTRY STATE [BEFORE]: Current=$($before.current), Default=$($before.default), Failed=$($before.failed), LKG=$($before.LastKnownGood)"

            # Step 5 - Check whether LKGC has already been applied (version-specific thresholds)
            # FIXED: Require ALL conditions (AND) so we don't skip incorrectly.
            $alreadySet = $false
            if (($winosver -eq 10) -or ($winosver -ge 2016)) {
                if (
                    ($before.current -ge 2) -and
                    ($before.default -ge 2) -and
                    ($before.failed -ge 1) -and
                    ($before.LastKnownGood -ge 2)
                ) { $alreadySet = $true }
            }
            elseif ($winosver -eq 2012) {
                if (
                    ($before.current -ge 2) -and
                    ($before.default -ge 2) -and
                    ($before.failed -ge 1) -and
                    ($before.LastKnownGood -ge 3)
                ) { $alreadySet = $true }
            }

            if ($alreadySet) {
                Write-RepairLog -Level Warning -Message "[$diskb] LKGC WAS ALREADY SET, NO CHANGES DONE"
                Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=false"
            }
            else {
                # Step 6 - Increment all four Select values by 1 to trigger LKGC on next boot
                Write-RepairLog -Level Info -Message "[$diskb] Applying LKGC increments..."
                $writeAttempted = $true
                Set-ItemProperty -Path $selectPath -Name 'current' -Type DWORD -Value ($before.current + 1) -ErrorAction Stop
                Set-ItemProperty -Path $selectPath -Name 'default' -Type DWORD -Value ($before.default + 1) -ErrorAction Stop
                Set-ItemProperty -Path $selectPath -Name 'failed' -Type DWORD -Value ($before.failed + 1) -ErrorAction Stop
                Set-ItemProperty -Path $selectPath -Name 'LastKnownGood' -Type DWORD -Value ($before.LastKnownGood + 1) -ErrorAction Stop

                # Step 7 - Log the BEFORE and AFTER registry states for verification
                $after = Get-ItemProperty -path $selectPath
                Write-RepairLog -Level Info -Message "[$diskb] REGISTRY STATE [AFTER]: Current=$($after.current), Default=$($after.default), Failed=$($after.failed), LKG=$($after.LastKnownGood)"

                # NEW: mark applied
                $lkgcAppliedAny = $true
                $changedCount++
                Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=true"
            }

            $fixedDisks += $diskb
        }
        catch {
            $failedCount++
            if ($writeAttempted) {
                $restoreRequired = $true
            }
            Write-RepairLog -Level Error -Message "[$diskb] Failed to process: $($_.Exception.Message)"
            Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=false"
        }
        finally {
            # Step 8 - Unload the registry hive cleanly
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadOutput = & reg.exe unload $sysHive 2>&1
                Write-RepairLog -Level Info -Message "[$diskb] SYSTEM unload attempt $i output: $($unloadOutput -join ' | ')"
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Write-RepairLog -Level Warning -Message "Unload attempt $i for $sysHive failed, retrying..."
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Write-RepairLog -Level Warning -Message "Could not unload $sysHive hive - may need manual cleanup"
            }

            if ($restoreRequired) {
                try {
                    Copy-Item -LiteralPath $systemHiveBackup -Destination $systemHivePath -Force -ErrorAction Stop
                    Write-RepairLog -Level Warning -Message "[$diskb] Restored SYSTEM hive from backup due to failure: $systemHiveBackup"
                }
                catch {
                    Write-RepairLog -Level Error -Message "[$diskb] Failed to restore SYSTEM hive backup. Manual recovery may be required. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    if ($processedCount -gt 0) {
        # NEW: final summary reflects whether changes were applied
        if ($lkgcAppliedAny) {
            Write-RepairLog -Level Output -Message "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE, LKGC APPLIED on drives: $($fixedDisks -join ', ')"
        } else {
            Write-RepairLog -Level Output -Message "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=FALSE (NO CHANGES REQUIRED), drives processed: $($fixedDisks -join ', ')"
        }
        Write-RepairLog -Level Output -Message "SUMMARY: processed=$processedCount, skipped=$skippedCount, failed=$failedCount, changed=$changedCount"
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }
}
catch {
    Write-RepairLog -Level Error -Message "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    Write-RepairLog -Level Info -Message "Script execution ended at $(Get-Date)"
    Write-RepairLog -Level Info -Message "Desktop log file saved at: $desktopLogFile"
}

return $script_final_status
