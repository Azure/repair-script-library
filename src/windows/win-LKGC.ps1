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

# Initialization
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

# Log Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LKGC_$timestamp.log"

# Status Tracking
$script_final_status = $STATUS_ERROR

# NEW: Track whether LKGC was actually applied anywhere
$lkgcAppliedAny = $false

try {
    Log-Info "Starting AUTO LKGC Script..." | Tee-Object -FilePath $logFile -Append

    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)" | Tee-Object -FilePath $logFile -Append
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Log-Warning "Failed to stop nested guest VM, will continue but may have limited success" | Tee-Object -FilePath $logFile -Append
                    }
                }
            }
        } else {
            Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation." | Tee-Object -FilePath $logFile -Append
        }
    }
    catch {
        Log-Warning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # Step 1 - Enumerate partitions to locate the faulty OS drive(s)
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''
    $fixedDisks = @()

    foreach ($partition in $partitionlist) {
        if (-not $partition.DriveLetter) { continue }

        # Skip the rescue VM's own OS drive (its hives are locked by the running OS)
        if ($partition.DriveLetter -eq $rescueDrive) {
            Log-Info "Skipping rescue VM system drive $rescueDrive (own OS)" | Tee-Object -FilePath $logFile -Append
            continue
        }

        if (-not (Test-Path -Path "$($partition.DriveLetter):\Windows")) { continue }

        $diskb = $partition.DriveLetter
        Log-Info "Target OS disk found on letter: $($diskb):" | Tee-Object -FilePath $logFile -Append

        # Step 2 - Load the SOFTWARE hive to detect the Windows version
        $swHive = "HKLM\BROKENSW_$diskb"
        & reg.exe unload $swHive 2>$null
        $swLoad = & reg.exe load $swHive "$($diskb):\Windows\System32\config\software" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Warning "Failed to load SOFTWARE hive from $($diskb): $swLoad - skipping" | Tee-Object -FilePath $logFile -Append
            continue
        }

        Start-Sleep -Seconds 2
        $productName = (Get-ItemProperty -path "registry::$swHive\microsoft\windows nt\currentversion" -ErrorAction SilentlyContinue).ProductName
        $winosver = 0
        if ($productName -match '(\d+)') { $winosver = [int]$matches[1] }
        & reg.exe unload $swHive 2>$null

        # Step 3 - Load the SYSTEM hive from the target disk
        $sysHive = "HKLM\BROKENSYS_$diskb"
        & reg.exe unload $sysHive 2>$null
        Log-Info "Loading System hive from $($diskb): as $sysHive..." | Tee-Object -FilePath $logFile -Append
        $sysLoad = & reg.exe load $sysHive "$($diskb):\Windows\System32\config\SYSTEM" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Warning "Failed to load SYSTEM hive from $($diskb): $sysLoad - skipping" | Tee-Object -FilePath $logFile -Append
            continue
        }

        Start-Sleep -Seconds 2

        # NEW: per-disk flag
        $lkgcAppliedThisDisk = $false

        try {
            # Step 4 - Read the current Select key values (BEFORE state)
            $selectPath = "Registry::$sysHive\Select"
            $before = Get-ItemProperty -path $selectPath
            Log-Info "[$diskb] REGISTRY STATE [BEFORE]: Current=$($before.current), Default=$($before.default), Failed=$($before.failed), LKG=$($before.LastKnownGood)" | Tee-Object -FilePath $logFile -Append

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
                Log-Warning "[$diskb] LKGC WAS ALREADY SET, NO CHANGES DONE" | Tee-Object -FilePath $logFile -Append
                Log-Info "[$diskb] LKGC_APPLIED=false" | Tee-Object -FilePath $logFile -Append
            }
            else {
                # Step 6 - Increment all four Select values by 1 to trigger LKGC on next boot
                Log-Info "[$diskb] Applying LKGC increments..." | Tee-Object -FilePath $logFile -Append
                Set-Itemproperty -path $selectPath -Name 'current' -Type DWORD -value ($before.current + 1)
                Set-Itemproperty -path $selectPath -Name 'default' -Type DWORD -value ($before.default + 1)
                Set-Itemproperty -path $selectPath -Name 'failed' -Type DWORD -value ($before.failed + 1)
                Set-Itemproperty -path $selectPath -Name 'LastKnownGood' -Type DWORD -value ($before.LastKnownGood + 1)

                # Step 7 - Log the BEFORE and AFTER registry states for verification
                $after = Get-ItemProperty -path $selectPath
                Log-Info "[$diskb] REGISTRY STATE [AFTER]:  Current=$($after.current), Default=$($after.default), Failed=$($after.failed), LKG=$($after.LastKnownGood)" | Tee-Object -FilePath $logFile -Append

                # NEW: mark applied
                $lkgcAppliedThisDisk = $true
                $lkgcAppliedAny = $true
                Log-Info "[$diskb] LKGC_APPLIED=true" | Tee-Object -FilePath $logFile -Append
            }

            $fixedDisks += $diskb
        }
        catch {
            Log-Error "[$diskb] Failed to process: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
            Log-Info "[$diskb] LKGC_APPLIED=false" | Tee-Object -FilePath $logFile -Append
        }
        finally {
            # Step 8 - Unload the registry hive cleanly
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                & reg.exe unload $sysHive 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Log-Warning "Unload attempt $i for $sysHive failed, retrying..." | Tee-Object -FilePath $logFile -Append
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Log-Warning "Could not unload $sysHive hive - may need manual cleanup" | Tee-Object -FilePath $logFile -Append
            }
        }
    }

    if ($fixedDisks.Count -gt 0) {
        # NEW: final summary reflects whether changes were applied
        if ($lkgcAppliedAny) {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE, LKGC APPLIED on drives: $($fixedDisks -join ', ')" | Tee-Object -FilePath $logFile -Append
        } else {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=FALSE (NO CHANGES REQUIRED), drives processed: $($fixedDisks -join ', ')" | Tee-Object -FilePath $logFile -Append
        }
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }
}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script execution ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}

return $script_final_status
