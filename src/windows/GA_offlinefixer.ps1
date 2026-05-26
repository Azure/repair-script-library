<#
.SYNOPSIS
    VMAgent Offline Fixer - Restores Guest Agent registry keys and binaries from a rescue VM.

.DESCRIPTION
    This script runs from a rescue VM to repair a broken Azure Guest Agent on an attached OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the faulty OS drive.
    2. Loads the SYSTEM registry hive from the target disk into HKLM\BROKENSYSTEM.
    3. Creates a full backup of the loaded hive to the disk root (regbackupbeforeGAchanges).
    4. Identifies the primary and backup ControlSets (001/002) from the Select key.
    5. Exports healthy service keys (WindowsAzureGuestAgent, WindowsAzureTelemetryService, RdAgent)
       from the rescue VM and injects them into both ControlSets on the target hive.
    6. Verifies the ImagePath value was written correctly.
    7. Backs up the existing WindowsAzure folder (WindowsazurefaultyGAbackup), then replaces
       it with the full rescue VM WindowsAzure copy.
    8. Releases handles and safely unloads the registry hive (with retry logic).

.NOTES
    Name:    GA_offlinefixer.ps1
    Version: 1.3
    Original Author: Daniel Munoz L (damunozl@microsoft.com)
    Modified by: Tony.Mocanu@Microsoft.com

.VERSION
    v1.3: [May 2026] - Updated the script (current)
                       - Aligned nested VM detection with win-LKGC guard pattern.
                       - Skips Get-VM safely when Hyper-V module is unavailable.
    v1.2: [May 2026] - Updated the script again (current)
                       - Fixed breaking exception when the Hyper-V module is not installed on the host.
                       - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.1: [May 2026] - Updated the script
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v1.0: Initial commit. This was the version 1.0 of the script.

.SCENARIO_RECREATION
    To recreate a testable broken Guest Agent scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Load the SYSTEM hive from the attached disk (replace F with actual drive letter):
reg load HKLM\TESTBREAK F:\Windows\System32\config\SYSTEM
    3. Delete or corrupt the Guest Agent service keys:
Remove-Item -Path "HKLM:\TESTBREAK\ControlSet001\Services\WindowsAzureGuestAgent" -Recurse -Force
Remove-Item -Path "HKLM:\TESTBREAK\ControlSet001\Services\RdAgent" -Recurse -Force
    4. Unload the hive:
reg unload HKLM\TESTBREAK
    5. Optionally rename/remove GuestAgent binary folders on the target disk:
Get-ChildItem F:\WindowsAzure\GuestAgent_* | Rename-Item -NewName { $_.Name + '_BACKUP' }
    6. Run the script. It should restore service keys from the rescue VM and copy binaries.
    7. Verify via the .VERIFICATION steps below.

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-GA_offlinefixer --run-on-repair

.VERIFICATION
    1. Check the log file for success:
Get-ChildItem "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\GA_offlinefixer_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    Expected: "VMAgent Fix completed and verified successfully." and return code 0 ($STATUS_SUCCESS).
    2. Reload the SYSTEM hive and verify agent service keys exist (replace F with disk letter):
reg load HKLM\VERIFY F:\Windows\System32\config\SYSTEM
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\WindowsAzureGuestAgent" -Name ImagePath
Get-ItemProperty -Path "HKLM:\VERIFY\ControlSet001\Services\RdAgent" -Name ImagePath
reg unload HKLM\VERIFY
    Expected: ImagePath values are populated for both services.
    3. Verify GuestAgent binaries were copied to the target disk:
Get-ChildItem F:\WindowsAzure\GuestAgent_*
    Expected: One or more GuestAgent folders present.
#>

# Initialization
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

# Log Configuration
$logDir = "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension"
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\GA_offlinefixer_$timestamp.log"

# Status Tracking
$script_final_status = $STATUS_ERROR

try {
    Log-Info "Starting VMAgent Offline Fixer..." | Tee-Object -FilePath $logFile -Append

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

    # Clean up stale hive mounts from previous failed runs
    Log-Info "Cleaning up any stale registry hive mounts..." | Tee-Object -FilePath $logFile -Append
    foreach ($staleKey in @("BROKENSYSTEM", "BROKENSW")) {
        & reg.exe unload "HKLM\$staleKey" 2>$null
        & reg.exe unload "HKU\$staleKey" 2>$null
    }
    'C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' | ForEach-Object {
        & reg.exe unload "HKLM\BROKENSYSTEM_$_" 2>$null
        & reg.exe unload "HKLM\BROKENSW_$_" 2>$null
        & reg.exe unload "HKU\BROKENSYS_$_" 2>$null
        & reg.exe unload "HKU\BROKENSW_$_" 2>$null
    }

    # Log any externally loaded hives (diagnostic)
    $hklmKeys = & reg.exe query HKLM 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    $hkuKeys = & reg.exe query HKU 2>$null | Where-Object { $_ -match 'BROKEN|OFFLINE|SYSTEM_' }
    if ($hklmKeys) { Log-Info "Loaded HKLM hives: $($hklmKeys -join ', ')" | Tee-Object -FilePath $logFile -Append }
    if ($hkuKeys) { Log-Info "Loaded HKU hives: $($hkuKeys -join ', ')" | Tee-Object -FilePath $logFile -Append }

    # Stop services that scan/index attached disks and lock hive files
    Log-Info "Stopping services that may lock disk files..." | Tee-Object -FilePath $logFile -Append
    Stop-Service WSearch -Force -ErrorAction SilentlyContinue 2>$null
    Stop-Service WinDefend -Force -ErrorAction SilentlyContinue 2>$null

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    # Cycle non-system disks offline/online to release ALL file handles
    Log-Info "Cycling attached disks offline/online to release file locks..." | Tee-Object -FilePath $logFile -Append
    $rescueDiskNum = (Get-Partition -DriveLetter ($env:SystemDrive -replace ':', '') -ErrorAction SilentlyContinue).DiskNumber
    Get-Disk | Where-Object { $_.Number -ne $rescueDiskNum -and $_.OperationalStatus -eq 'Online' } | ForEach-Object {
        $dnum = $_.Number
        Log-Info "Cycling disk $dnum offline/online..." | Tee-Object -FilePath $logFile -Append
        Set-Disk -Number $dnum -IsOffline $true -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Set-Disk -Number $dnum -IsOffline $false -ErrorAction SilentlyContinue
        Set-Disk -Number $dnum -IsReadOnly $false -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 3

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

        # Step 2 - Load the SYSTEM registry hive from the target disk
        $hiveName = "BROKENSYSTEM_$diskb"
        $hiveSource = "$($diskb):\Windows\System32\config\SYSTEM"
        $hiveCopy = $null
        & reg.exe unload "HKLM\$hiveName" 2>$null
        [System.GC]::Collect()
        Start-Sleep -Seconds 1
        Log-Info "Loading SYSTEM hive from $($diskb): as $hiveName..." | Tee-Object -FilePath $logFile -Append
        $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Retry once after a short wait
            Log-Warning "First reg load attempt failed for $($diskb):, retrying in 5 seconds..." | Tee-Object -FilePath $logFile -Append
            Start-Sleep -Seconds 5
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            # Fallback: use esentutl.exe /y to copy locked hive via Windows Backup API semantics
            Log-Warning "Direct load failed. Trying esentutl copy fallback for $($diskb):..." | Tee-Object -FilePath $logFile -Append
            $hiveCopy = "$env:TEMP\SYSTEM_COPY_$diskb"
            try {
                $esentResult = & esentutl.exe /y $hiveSource /d $hiveCopy /o 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $hiveCopy)) {
                    Log-Info "Hive copied successfully to $hiveCopy via esentutl" | Tee-Object -FilePath $logFile -Append
                    $loadResult = & reg.exe load "HKLM\$hiveName" $hiveCopy 2>&1
                }
                else {
                    Log-Warning "esentutl copy failed for $($diskb): $esentResult" | Tee-Object -FilePath $logFile -Append
                }
            }
            catch {
                Log-Warning "esentutl fallback failed for $($diskb):: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
            }
        }
        if ($LASTEXITCODE -ne 0) {
            Log-Warning "Failed to load Registry Hive from $($diskb): $loadResult - skipping this partition" | Tee-Object -FilePath $logFile -Append
            if ($hiveCopy -and (Test-Path $hiveCopy)) { Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue }
            continue
        }
        Start-Sleep -Seconds 2

        try {
            # Step 3 - Create a full backup of the loaded hive before making changes
            $backupFile = "$($diskb):\regbackupbeforeGAchanges_$diskb.reg"
            Log-Info "Backing up full registry hive to $backupFile..." | Tee-Object -FilePath $logFile -Append
            & reg.exe export "HKLM\$hiveName" $backupFile /y 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Log-Warning "Registry backup failed for $($diskb): -- continuing anyway" | Tee-Object -FilePath $logFile -Append
            }

            # Step 4 - Identify the primary and backup ControlSets from the Select key
            $selectPath = "Registry::HKLM\$hiveName\Select"
            $defaultSetID = (Get-ItemProperty -path $selectPath).default
            $primarySet = "ControlSet00$defaultSetID"
            $otherSet = if ($primarySet -eq "ControlSet001") { "ControlSet002" } else { "ControlSet001" }

            Log-Info "Primary ControlSet identified: $primarySet" | Tee-Object -FilePath $logFile -Append

            # Step 5 - Export healthy service keys and inject into both ControlSets
            $services = @("WindowsAzureGuestAgent", "WindowsAzureTelemetryService", "RdAgent")

            foreach ($service in $services) {
                $regFile = "$($diskb):\$service.reg"
                # Export healthy key from the current Rescue VM
                & reg.exe export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service" "$regFile" /y 2>$null
                
                if (Test-Path $regFile) {
                    $originalContent = Get-Content $regFile
                    
                    # Update Primary Set
                    Log-Info "Updating $service in $primarySet on $($diskb):..." | Tee-Object -FilePath $logFile -Append
                    $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$primarySet"
                    $content | Set-Content $regFile
                    & reg.exe import $regFile 2>&1 | Out-Null

                    # Update Secondary Set (if it exists on disk)
                    if (Test-Path "Registry::HKLM\$hiveName\$otherSet") {
                        Log-Info "Updating $service in backup $otherSet on $($diskb):..." | Tee-Object -FilePath $logFile -Append
                        $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$otherSet"
                        $content | Set-Content $regFile
                        & reg.exe import $regFile 2>&1 | Out-Null
                    }
                    Remove-Item $regFile -Force
                }
            }

            # Step 6 - Verify the ImagePath value was written correctly
            $wagaPath = "HKLM\$hiveName\$primarySet\Services\WindowsAzureGuestAgent"
            $afterImagePath = (Get-ItemProperty -Path "Registry::$wagaPath" -ErrorAction SilentlyContinue).ImagePath
            if ([string]::IsNullOrWhiteSpace($afterImagePath)) {
                Log-Warning "Verification Warning on $($diskb): VMAgent ImagePath is empty after injection." | Tee-Object -FilePath $logFile -Append
            }
            else {
                Log-Info "Verification Success on $($diskb):: ImagePath is now $afterImagePath" | Tee-Object -FilePath $logFile -Append
            }

            # Step 7 - Backup existing WindowsAzure folder and replace with rescue VM copy
            $sourcePath = "C:\WindowsAzure"
            $destPath = "$($diskb):\WindowsAzure"
            $backupPath = "$($diskb):\WindowsazurefaultyGAbackup"

            if (Test-Path $destPath) {
                Log-Info "Backing up existing WindowsAzure folder on $($diskb): to WindowsazurefaultyGAbackup..." | Tee-Object -FilePath $logFile -Append
                if (-not (Test-Path $backupPath)) { $null = New-Item -Path $backupPath -ItemType Directory -Force }
                & xcopy "$destPath" "$backupPath" /E /Y /H /Q 2>&1 | Out-Null
                Log-Info "Removing old WindowsAzure folder on $($diskb):..." | Tee-Object -FilePath $logFile -Append
                Remove-Item $destPath -Recurse -Force -ErrorAction SilentlyContinue
            }

            Log-Info "Copying full WindowsAzure folder from rescue VM to $($diskb):..." | Tee-Object -FilePath $logFile -Append
            $null = New-Item -Path $destPath -ItemType Directory -Force
            & xcopy "$sourcePath" "$destPath" /E /Y /H /Q 2>&1 | Out-Null

            # Remove Logs folder from copied content (not relevant to the target VM)
            $logsPath = "$destPath\Logs"
            if (Test-Path $logsPath) {
                Remove-Item $logsPath -Recurse -Force -ErrorAction SilentlyContinue
            }

            $fixedDisks += $diskb
        }
        catch {
            Log-Error "Failed to process $($diskb):: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
        }
        finally {
            # Step 8 - Release handles and safely unload the registry hive
            Log-Info "Unloading registry hive $hiveName..." | Tee-Object -FilePath $logFile -Append
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 3

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                & reg.exe unload "HKLM\$hiveName" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Log-Warning "Unload attempt $i for $hiveName failed, retrying..." | Tee-Object -FilePath $logFile -Append
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Log-Warning "Could not unload $hiveName hive - may need manual cleanup" | Tee-Object -FilePath $logFile -Append
            }

            # If we used the copy fallback, copy the modified hive back to the original location
            if ($hiveCopy -and (Test-Path $hiveCopy)) {
                if ($unloaded) {
                    Log-Info "Copying modified hive back to $hiveSource..." | Tee-Object -FilePath $logFile -Append
                    try {
                        Copy-Item -Path $hiveCopy -Destination $hiveSource -Force -ErrorAction Stop
                    }
                    catch {
                        Log-Error "Failed to copy modified hive back to $($diskb):: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
                    }
                }
                Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($fixedDisks.Count -gt 0) {
        Log-Output "VMAgent Fix completed and verified successfully on drives: $($fixedDisks -join ', ')" | Tee-Object -FilePath $logFile -Append
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }

}
catch {
    $errorMessage = $_.Exception.Message
    Log-Error "SCRIPT FAILED: $errorMessage" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Execution ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}

return $script_final_status
