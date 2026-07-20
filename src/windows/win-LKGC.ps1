<#
.SYNOPSIS
    Enables Last Known Good Configuration (LKGC) by incrementing the Select registry values.
.DESCRIPTION
    This script runs from a rescue VM to activate LKGC on an attached faulty OS disk.
    Utilizes direct .NET Registry APIs to prevent handle locking and eliminate 0xc0000225 corruptions.
.EXAMPLE
    az vm repair run -g MyResourceGroup -n BrokenVM --run-id win-LKGC --run-on-repair
    
    Description:
    Executes the LKGC recovery script against an unbootable Windows VM using the Azure CLI 
    repair extension framework. The script executes non-interactively within the context 
    of the dynamically provisioned repair/rescue environment.
.NOTES
    Name:    win-LKGC.ps1
    Author:  Tony.Mocanu@Microsoft.com
    
    OPERATIONAL VERIFICATION:
    To verify successful script execution, validate the following markers:
    1. Log Location: Inspect the generated execution log located at:
       C:\Users\Public\Desktop\LKGC_*.log or C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension
    2. Status Strings: Confirm the presence of the terminal confirmation string:
       "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE"
    3. State Deltas: Verify the logged registry metrics confirm that 'current', 'default', 
       'failed', and 'LastKnownGood' values successfully incremented by 1 from their BEFORE state.
.VERSION
    v1.: [Jul 2026] - Handle Hardening & Audit Update
                       - Resolved PR version ambiguity; unified history baseline.
                       - Removed duplicated Write-RepairLog block; deferred to shared init helper.
                       - Retained .NET Registry API layer ([Microsoft.Win32.Registry]) to prevent handle locks.
    [Jul 2026 update] - Production hardening update
                       - Added helper path validation before dot-sourcing.
                       - Switched to desktop log file with explicit startup/completion log path.
                       - Captured critical reg.exe command outputs (no Out-Null suppression).
                       - Added SYSTEM hive backup + rollback-on-failure behavior.
                       - Added processed/skipped/failed/changed summary counters.
    [May 2026 update] - PR Release Alignment Update
                       - Added LKGC_APPLIED log flag (per disk + overall) and corrected final summary message.
    v1.2: [May 2026] - Logic correction
                       - Fixed false "already set" detection by requiring ALL thresholds (AND instead of OR).
.LINK
    How to start Azure Windows VM with Last Known Good Configuration - Virtual Machines | Microsoft Learn
#>

# Initialization
$scriptRoot = $null
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $scriptRoot = $PSScriptRoot
}
elseif ($MyInvocation.MyCommand.Path) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
else {
    $callerScript = (Get-PSCallStack | Where-Object { $_.ScriptName } | Select-Object -First 1).ScriptName
    if ($callerScript) {
        $scriptRoot = Split-Path -Parent $callerScript
    }
}
if ([string]::IsNullOrWhiteSpace($scriptRoot) -or -not (Test-Path -LiteralPath $scriptRoot -PathType Container)) {
    Write-Error "Unable to determine script root for dependency resolution. Aborting before helper import."
    return 1
}
$initScriptPath = Join-Path $scriptRoot 'src\windows\common\setup\init.ps1'
$diskPartitionsHelperPath = Join-Path $scriptRoot 'src\windows\common\helpers\Get-Disk-Partitions-v2.ps1'
if (-not (Test-Path -LiteralPath $initScriptPath -PathType Leaf)) {
    Write-Error "Required helper missing: $initScriptPath"
    return 1
}
if (-not (Test-Path -LiteralPath $diskPartitionsHelperPath -PathType Leaf)) {
    Write-Error "Required helper missing: $diskPartitionsHelperPath"
    return 1
}
. $initScriptPath
. $diskPartitionsHelperPath

# Global Log Environment Setup (Consumed by the shared Write-RepairLog helper inside init.ps1)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath) -or -not (Test-Path -LiteralPath $desktopPath)) {
    $desktopPath = 'C:\Users\Public\Desktop'
    if (-not (Test-Path -LiteralPath $desktopPath)) {
        $null = New-Item -ItemType Directory -Path $desktopPath -Force
    }
}
$script:desktopLogFile = Join-Path $desktopPath "LKGC_$timestamp.log"
$pluginLogDir = 'C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension'
if (-not (Test-Path -LiteralPath $pluginLogDir)) {
    $null = New-Item -ItemType Directory -Path $pluginLogDir -Force
}
$script:pluginLogFile = Join-Path $pluginLogDir "LKGC_$timestamp.log"

# Status Tracking Variables
$scriptfinalstatus = $STATUS_ERROR
$lkgcAppliedAny = $false
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

try {
    # Note: Write-RepairLog is now safely provided by the centralized src\windows\common\setup\init.ps1
    Write-RepairLog -Level Info -Message "Starting AUTO LKGC Script..."
    Write-RepairLog -Level Info -Message "Desktop log file path: $script:desktopLogFile"
    Write-RepairLog -Level Info -Message "Plugin log file path: $script:pluginLogFile"

    # Guard Get-VM if Hyper-V module is not available on host
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

        # Skip the rescue VM's own OS drive
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
        $subKeyPath = "BROKENSYS_$diskb\Select"
        $regKey = $null

        try {
            # Step 4 - Open via .NET API to completely eliminate PowerShell Registry provider handle caching bugs
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $true)
            if ($null -eq $regKey) {
                throw "Failed to open Select key via explicit .NET engine path: HKLM:\$subKeyPath"
            }

            $currentVal    = [int]$regKey.GetValue('current')
            $defaultVal    = [int]$regKey.GetValue('default')
            $failedVal     = [int]$regKey.GetValue('failed')
            $lastKnownGood = [int]$regKey.GetValue('LastKnownGood')

            Write-RepairLog -Level Info -Message "[$diskb] REGISTRY STATE [BEFORE]: Current=$currentVal, Default=$defaultVal, Failed=$failedVal, LKG=$lastKnownGood"

            # Step 5 - Evaluate threshold triggers using validated AND-logic sequences
            $alreadySet = $false
            if (($winosver -eq 10) -or ($winosver -ge 2016)) {
                if (($currentVal -ge 2) -and ($defaultVal -ge 2) -and ($failedVal -ge 1) -and ($lastKnownGood -ge 2)) { 
                    $alreadySet = $true 
                }
            }
            elseif ($winosver -eq 2012) {
                if (($currentVal -ge 2) -and ($defaultVal -ge 2) -and ($failedVal -ge 1) -and ($lastKnownGood -ge 3)) { 
                    $alreadySet = $true 
                }
            }

            if ($alreadySet) {
                Write-RepairLog -Level Warning -Message "[$diskb] LKGC WAS ALREADY SET, NO CHANGES DONE"
                Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=false"
            }
            else {
                # Step 6 - Increment configuration spaces using distinct DWord parameters
                Write-RepairLog -Level Info -Message "[$diskb] Applying LKGC increments via explicit .NET API framework..."
                $writeAttempted = $true

                $regKey.SetValue('current', ($currentVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('default', ($defaultVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('failed', ($failedVal + 1), [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('LastKnownGood', ($lastKnownGood + 1), [Microsoft.Win32.RegistryValueKind]::DWord)

                # Step 7 - Document downstream registry configuration states
                $afterCurrent = $regKey.GetValue('current')
                $afterDefault = $regKey.GetValue('default')
                $afterFailed  = $regKey.GetValue('failed')
                $afterLKG     = $regKey.GetValue('LastKnownGood')

                Write-RepairLog -Level Info -Message "[$diskb] REGISTRY STATE [AFTER]: Current=$afterCurrent, Default=$afterDefault, Failed=$afterFailed, LKG=$afterLKG"

                $lkgcAppliedAny = $true
                $changedCount++
                Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=true"
            }

            $fixedDisks += $diskb
        }
        catch {
            $failedCount++
            if ($writeAttempted) { $restoreRequired = $true }
            Write-RepairLog -Level Error -Message "[$diskb] Failed to process registry modifications: $($_.Exception.Message)"
            Write-RepairLog -Level Info -Message "[$diskb] LKGC_APPLIED=false"
        }
        finally {
            # CRITICAL: Clean up .NET engine handles, forcing disk subsystem flush before dropping hive structures
            if ($null -ne $regKey) {
                $regKey.Flush()
                $regKey.Close()
                $regKey.Dispose()
            }
            
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2

            # Step 8 - Unload the registry hive using the 3x safety retry array
            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadOutput = & reg.exe unload $sysHive 2>&1
                Write-RepairLog -Level Info -Message "[$diskb] SYSTEM unload attempt $i output: $($unloadOutput -join ' | ')"
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Write-RepairLog -Level Warning -Message "Unload attempt $i for $sysHive failed, retrying..."
                Start-Sleep -Seconds 5
            }
            
            if (-not $unloaded) {
                Write-RepairLog -Level Error -Message "Could not unload $sysHive cleanly. Immediate execution halt required to prevent file errors."
            }

            if ($restoreRequired) {
                try {
                    Copy-Item -LiteralPath $systemHiveBackup -Destination $systemHivePath -Force -ErrorAction Stop
                    Write-RepairLog -Level Warning -Message "[$diskb] Restored SYSTEM hive from backup due to operation error: $systemHiveBackup"
                }
                catch {
                    Write-RepairLog -Level Error -Message "[$diskb] Failed to restore SYSTEM hive backup. Manual volume alignment required. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    if ($processedCount -gt 0) {
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
    $scriptfinalstatus = $STATUS_ERROR
}
finally {
    Write-RepairLog -Level Info -Message "Script execution ended at $(Get-Date)"
    Write-RepairLog -Level Info -Message "Desktop log file saved at: $script:desktopLogFile"
}

return $scriptfinalstatus
