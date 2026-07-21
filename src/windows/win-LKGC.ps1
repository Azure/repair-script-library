<#
.SYNOPSIS
    Enables Last Known Good Configuration (LKGC) by incrementing the Select registry values.

.DESCRIPTION
    This script runs from a rescue VM to activate LKGC on an attached faulty OS disk.
    Utilizes direct .NET Registry APIs to prevent handle locking and eliminate 0xc0000225 corruptions.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the target OS volume.
    2. Creates a safety backup of the target SYSTEM hive before modification.
    3. Loads the SOFTWARE hive temporarily to verify the specific Windows version threshold engine.
    4. Opens the Select key using explicit .NET API frameworks to avoid provider caching.
    5. Evaluates threshold logic metrics via strict AND-logic parameters.
    6. Increments the configuration values (current, default, failed, LastKnownGood) to force LKGC validation.
    7. Unloads the hive safely using a defensive 3x retry loop with explicit garbage collection.

.NOTES
    Name:    win-LKGC.ps1
    Author:  Tony.Mocanu@Microsoft.com

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-LKGC --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "C:\Users\Public\Desktop\win-LKGC-run-*\win-LKGC-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
       Expected: "REGISTRY STATE [AFTER]" section present showing incremented values and summary changed=1.
    2. Confirm the presence of the terminal confirmation string:
       "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE"

.VERSION
    v1.2: [May - Jul 2026] - Production Hardening & Logic Updates
                       - [Jul 2026] Path & Architecture Fix: Synchronized initialization paths and 
                         logging wrapper architecture to match sac-enabler.ps1 framework.
                       - [Jul 2026] Handle Hardening: Refactored registry engine to use direct .NET APIs 
                         ([Microsoft.Win32.Registry]) with explicit .Flush() and .Dispose() to eliminate 
                         0xc0000225 hive corruption.
                       - [Jun 2026] Architecture: Verified version-specific thresholds and logic mappings.
                       - [May 2026] Bug Fixes: Switched from OR to AND logic to fix false "already set" detections. 
                         Guarded Get-VM against missing host modules, and integrated the LKGC_APPLIED tracking flags.
    v1.1: Previous version
    v0.1: Initial commit
.LINK
    How to start Azure Windows VM with Last Known Good Configuration - Virtual Machines | Microsoft Learn
#>

# Initialization (path-validated - exactly matching sac-enabler approach)
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
        else {
            [Console]::Error.WriteLine("[Warning $(Get-Date)]Failed to append to desktop log '$logFilePath': $($_.Exception.Message)")
        }
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-DesktopLogLine -Level 'Output' -Message $message
}

function Log-Info {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogInfo -message $message
    Write-DesktopLogLine -Level 'Info' -Message $message
}

function Log-Warning {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogWarning -message $message
    Write-DesktopLogLine -Level 'Warning' -Message $message
}

function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-DesktopLogLine -Level 'Error' -Message $message
}

function Log-Debug {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogDebug -message $message
    Write-DesktopLogLine -Level 'Debug' -Message $message
}

$logFile = $logFilePath
Log-Info "Desktop plain text log initialized: $logFilePath"

# Status Tracking
$script_final_status = $STATUS_ERROR
$lkgcAppliedAny = $false
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

Log-Info "Starting AUTO LKGC Script. Desktop log: $logFile"

try {
    # Check if the Hyper-V module is available before performing nested VM checks
    if (Get-Module -ListAvailable -Name Hyper-V) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine) {
            if ($guestHyperVVirtualMachine.State -eq 'Running') {
                Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                try {
                    Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                }
                catch {
                    Log-Warning "Failed to stop nested guest VM, will continue but may have limited success"
                }
            }
        }
    } else {
        Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
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
            Log-Info "Skipping rescue VM system drive $rescueDrive (own OS)"
            $skippedCount++
            continue
        }

        if (-not (Test-Path -Path "$($partition.DriveLetter):\Windows")) {
            $skippedCount++
            continue
        }

        $diskb = $partition.DriveLetter
        $processedCount++
        Log-Info "Target OS disk found on letter: $($diskb):"

        $systemHivePath = "$($diskb):\Windows\System32\config\SYSTEM"
        $systemHiveBackup = "$systemHivePath.LKGC.bak.$runTimestamp"
        try {
            Copy-Item -LiteralPath $systemHivePath -Destination $systemHiveBackup -Force -ErrorAction Stop
            Log-Info "[$diskb] SYSTEM hive backup created: $systemHiveBackup"
        }
        catch {
            $failedCount++
            Log-Error "[$diskb] Failed to create SYSTEM hive backup. Skipping disk. Error: $($_.Exception.Message)"
            continue
        }

        # Step 2 - Load the SOFTWARE hive to detect the Windows version
        $swHive = "HKLM\BROKENSW_$diskb"
        $swPreUnload = & reg.exe unload $swHive 2>&1
        Log-Info "[$diskb] Pre-load SOFTWARE unload output: $($swPreUnload -join ' | ')"
        $swLoad = & reg.exe load $swHive "$($diskb):\Windows\System32\config\software" 2>&1
        Log-Info "[$diskb] SOFTWARE load output: $($swLoad -join ' | ')"
        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Log-Warning "Failed to load SOFTWARE hive from $($diskb): $($swLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2
        $productName = (Get-ItemProperty -path "registry::$swHive\microsoft\windows nt\currentversion" -ErrorAction SilentlyContinue).ProductName
        $winosver = 0
        if ($productName -match '(\d+)') { $winosver = [int]$matches[1] }
        $swUnload = & reg.exe unload $swHive 2>&1
        Log-Info "[$diskb] SOFTWARE unload output: $($swUnload -join ' | ')"

        # Step 3 - Load the SYSTEM hive from the target disk
        $sysHive = "HKLM\BROKENSYS_$diskb"
        $sysPreUnload = & reg.exe unload $sysHive 2>&1
        Log-Info "[$diskb] Pre-load SYSTEM unload output: $($sysPreUnload -join ' | ')"
        Log-Info "Loading System hive from $($diskb): as $sysHive..."
        $sysLoad = & reg.exe load $sysHive "$($diskb):\Windows\System32\config\SYSTEM" 2>&1
        Log-Info "[$diskb] SYSTEM load output: $($sysLoad -join ' | ')"
        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Log-Warning "Failed to load SYSTEM hive from $($diskb): $($sysLoad -join ' | ') - skipping"
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

            Log-Info "[$diskb] REGISTRY STATE [BEFORE]: Current=$currentVal, Default=$defaultVal, Failed=$failedVal, LKG=$lastKnownGood"

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
                Log-Warning "[$diskb] LKGC WAS ALREADY SET, NO CHANGES DONE"
                Log-Info "[$diskb] LKGC_APPLIED=false"
            }
            else {
                # Step 6 - Increment configuration spaces using distinct DWord parameters
                Log-Info "[$diskb] Applying LKGC increments via explicit .NET API framework..."
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

                Log-Info "[$diskb] REGISTRY STATE [AFTER]: Current=$afterCurrent, Default=$afterDefault, Failed=$afterFailed, LKG=$afterLKG"

                $lkgcAppliedAny = $true
                $changedCount++
                Log-Info "[$diskb] LKGC_APPLIED=true"
            }

            $fixedDisks += $diskb
        }
        catch {
            $failedCount++
            if ($writeAttempted) { $restoreRequired = $true }
            Log-Error "[$diskb] Failed to process registry modifications: $($_.Exception.Message)"
            Log-Info "[$diskb] LKGC_APPLIED=false"
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
                Log-Info "[$diskb] SYSTEM unload attempt $i output: $($unloadOutput -join ' | ')"
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Log-Warning "Unload attempt $i for $sysHive failed, retrying..."
                Start-Sleep -Seconds 5
            }
            
            if (-not $unloaded) {
                Log-Error "Could not unload $sysHive cleanly. Immediate execution halt required to prevent file errors."
            }

            if ($restoreRequired) {
                try {
                    Copy-Item -LiteralPath $systemHiveBackup -Destination $systemHivePath -Force -ErrorAction Stop
                    Log-Warning "[$diskb] Restored SYSTEM hive from backup due to operation error: $systemHiveBackup"
                }
                catch {
                    Log-Error "[$diskb] Failed to restore SYSTEM hive backup. Manual volume alignment required. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    if ($processedCount -gt 0) {
        if ($lkgcAppliedAny) {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE, LKGC APPLIED on drives: $($fixedDisks -join ', ')"
        } else {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=FALSE (NO CHANGES REQUIRED), drives processed: $($fixedDisks -join ', ')"
        }
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }
}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Desktop log file: $logFile"
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
