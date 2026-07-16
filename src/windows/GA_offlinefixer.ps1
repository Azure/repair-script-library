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
    Version: 1.4
    Original Author: Daniel Munoz L (damunozl@microsoft.com)
    Modified by: Tony.Mocanu@Microsoft.com

.VERSION
    v1.4: [May 2026] - Updated the script (current)
                       - Aligned nested VM detection with win-LKGC guard pattern.
                       - Skips Get-VM safely when Hyper-V module is unavailable.
                       - Fixed relative path evaluation bug for helper files.
    v1.3: [May 2026] - Updated the script again (current)
                       - Fixed breaking exception when the Hyper-V module is not installed on the host.
                       - Added explicit checking via Get-Module before executing nested VM discovery.
    v1.2: [May 2026] - Updated the script
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v0.1: Initial commit. This was the version 1.0 of the script.

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
Get-ChildItem "$env:USERPROFILE\Desktop\GA_offlinefixer_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
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
$initScriptPath = Join-Path $PSScriptRoot "common\setup\init.ps1"
$diskHelperPath = Join-Path $PSScriptRoot "common\helpers\Get-Disk-Partitions-v2.ps1"

if (-not (Test-Path -Path $initScriptPath)) {
    Write-Error "Required helper script not found: $initScriptPath"
    return 1
}
if (-not (Test-Path -Path $diskHelperPath)) {
    Write-Error "Required helper script not found: $diskHelperPath"
    return 1
}

. $initScriptPath
. $diskHelperPath

# Log Configuration
$logDir = [Environment]::GetFolderPath('Desktop')
if (-not (Test-Path $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\GA_offlinefixer_$timestamp.log"

function Invoke-CriticalCommand {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        foreach ($line in @($output)) {
            Log-Info "$Description :: $line"
        }
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = @($output)
    }
}

# Status Tracking
$script_final_status = $STATUS_ERROR
$serviceStates = @{}  # Track original service states for restoration
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0

# VM Metadata Capture for Telemetry
$vmMetadata = @{
    OSVersion = $null
    VMSku = $null
    Region = $null
    HostName = $env:COMPUTERNAME
}

try {
    # Capture OS version from rescue VM
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($osInfo) {
            $vmMetadata.OSVersion = "$($osInfo.Caption) $($osInfo.Version)"
        }
    }
    catch {
        Log-Warning "OS metadata discovery failed: $($_.Exception.Message)"
    }

    # Attempt to capture Azure VM metadata from Instance Metadata Service
    try {
        $imdHeaders = @{Metadata = $true }
        $imdUri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        $imdResponse = Invoke-RestMethod -Uri $imdUri -Headers $imdHeaders -ErrorAction SilentlyContinue
        if ($imdResponse) {
            $vmMetadata.VMSku = $imdResponse.compute.vmSize
            $vmMetadata.Region = $imdResponse.compute.location
        }
    }
    catch {
        Log-Warning "Instance metadata discovery failed: $($_.Exception.Message)"
    }

    # Create metadata context string for logging
    $metadataContext = "[Host:$($vmMetadata.HostName)"
    if ($vmMetadata.Region) { $metadataContext += " Region:$($vmMetadata.Region)" }
    if ($vmMetadata.VMSku) { $metadataContext += " SKU:$($vmMetadata.VMSku)" }
    if ($vmMetadata.OSVersion) { $metadataContext += " OS:$($vmMetadata.OSVersion)" }
    $metadataContext += "]"

    Log-Info "Starting VMAgent Offline Fixer... $metadataContext"
    Log-Info "Desktop log file path: $logFile"
    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
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
    }
    catch {
        Log-Warning "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }

    # Clean up stale hive mounts from previous failed runs
    Log-Info "Cleaning up any stale registry hive mounts..."
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
    if ($hklmKeys) { Log-Info "Loaded HKLM hives: $($hklmKeys -join ', ')" }
    if ($hkuKeys) { Log-Info "Loaded HKU hives: $($hkuKeys -join ', ')" }

    # Stop services that scan/index attached disks and lock hive files
    Log-Info "Stopping services that may lock disk files..."
    foreach ($svc in @('WSearch', 'WinDefend')) {
        try {
            $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($svcObj) {
                $serviceStates[$svc] = $svcObj.Status
                Log-Info "Captured original state of $svc : $($svcObj.Status)"
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Log-Warning "Failed to capture state of $svc : $($_.Exception.Message)"
        }
    }

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    # Cycle non-system disks offline/online to release ALL file handles
    Log-Info "Cycling attached disks offline/online to release file locks..."
    $rescueDiskNum = (Get-Partition -DriveLetter ($env:SystemDrive -replace ':', '') -ErrorAction SilentlyContinue).DiskNumber
    Get-Disk | Where-Object { $_.Number -ne $rescueDiskNum -and $_.OperationalStatus -eq 'Online' } | ForEach-Object {
        $dnum = $_.Number
        Log-Info "Cycling disk $dnum offline/online..."
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
    $failedDisks = @()  # Track disks that failed copy-back

    foreach ($partition in $partitionlist) {
        $processedCount++
        if (-not $partition.DriveLetter) { $skippedCount++; continue }
        # Skip the rescue VM's own OS drive (its hives are locked by the running OS)
        if ($partition.DriveLetter -eq $rescueDrive) {
            Log-Info "Skipping rescue VM system drive $rescueDrive (own OS)"
            $skippedCount++
            continue
        }
        if (-not (Test-Path -Path "$($partition.DriveLetter):\Windows")) { $skippedCount++; continue }

        $diskb = $partition.DriveLetter
        Log-Info "Target OS disk found on letter: $($diskb):"
        # Step 2 - Load the SYSTEM registry hive from the target disk
        $hiveName = "BROKENSYSTEM_$diskb"
        $hiveSource = "$($diskb):\Windows\System32\config\SYSTEM"
        $hiveCopy = $null
        $diskProcessedSuccessfully = $false
        & reg.exe unload "HKLM\$hiveName" 2>$null
        [System.GC]::Collect()
        Start-Sleep -Seconds 1
        Log-Info "Loading SYSTEM hive from $($diskb): as $hiveName..."
        $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Retry once after a short wait
            Log-Warning "First reg load attempt failed for $($diskb):, retrying in 5 seconds..."
            Start-Sleep -Seconds 5
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $loadResult = & reg.exe load "HKLM\$hiveName" $hiveSource 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            # Fallback: use esentutl.exe /y to copy locked hive via Windows Backup API semantics
            Log-Warning "Direct load failed. Trying esentutl copy fallback for $($diskb):..."
            $hiveCopy = "$env:TEMP\SYSTEM_COPY_$diskb"
            try {
                $esentResult = & esentutl.exe /y $hiveSource /d $hiveCopy /o 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $hiveCopy)) {
                    Log-Info "Hive copied successfully to $hiveCopy via esentutl"
                    $loadResult = & reg.exe load "HKLM\$hiveName" $hiveCopy 2>&1
                }
                else {
                    Log-Warning "esentutl copy failed for $($diskb): $esentResult"
                }
            }
            catch {
                Log-Warning "esentutl fallback failed for $($diskb):: $($_.Exception.Message)"
            }
        }
        if ($LASTEXITCODE -ne 0) {
            Log-Warning "Failed to load Registry Hive from $($diskb): $loadResult - skipping this partition"
            if ($hiveCopy -and (Test-Path $hiveCopy)) { Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue }
            continue
        }
        Start-Sleep -Seconds 2

        try {
            # Step 3 - Create a full backup of the loaded hive before making changes
            $backupFile = "$($diskb):\regbackupbeforeGAchanges_$diskb.reg"
            Log-Info "Backing up full registry hive to $backupFile..."
            $backupResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("export", "HKLM\$hiveName", $backupFile, "/y") -Description "reg export backup ($diskb)"
            if ($backupResult.ExitCode -ne 0) {
                throw "Registry backup failed for $($diskb): $($backupResult.Output -join '; ')"
            }

            # Step 4 - Identify the primary and backup ControlSets from the Select key
            $selectPath = "Registry::HKLM\$hiveName\Select"
            $defaultSetID = (Get-ItemProperty -path $selectPath).default
            $primarySet = "ControlSet00$defaultSetID"
            $otherSet = if ($primarySet -eq "ControlSet001") { "ControlSet002" } else { "ControlSet001" }

            Log-Info "Primary ControlSet identified: $primarySet"
            # Step 5 - Export healthy service keys and inject into both ControlSets
            $services = @("WindowsAzureGuestAgent", "WindowsAzureTelemetryService", "RdAgent")

            foreach ($service in $services) {
                $regFile = "$($diskb):\$service.reg"
                # Export healthy key from the current Rescue VM
                $serviceExportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("export", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service", "$regFile", "/y") -Description "reg export service $service"
                
                if ($serviceExportResult.ExitCode -eq 0 -and (Test-Path $regFile)) {
                    $originalContent = Get-Content $regFile
                    
                    # Update Primary Set
                    Log-Info "Updating $service in $primarySet on $($diskb):..."
                    $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$primarySet"
                    $content | Set-Content $regFile
                    $primaryImportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("import", $regFile) -Description "reg import $service into $primarySet ($diskb)"
                    if ($primaryImportResult.ExitCode -ne 0) {
                        throw "Failed to import $service into $primarySet for $($diskb): $($primaryImportResult.Output -join '; ')"
                    }

                    # Update Secondary Set (if it exists on disk)
                    if (Test-Path "Registry::HKLM\$hiveName\$otherSet") {
                        Log-Info "Updating $service in backup $otherSet on $($diskb):..."
                        $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\$hiveName\$otherSet"
                        $content | Set-Content $regFile
                        $secondaryImportResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("import", $regFile) -Description "reg import $service into $otherSet ($diskb)"
                        if ($secondaryImportResult.ExitCode -ne 0) {
                            throw "Failed to import $service into $otherSet for $($diskb): $($secondaryImportResult.Output -join '; ')"
                        }
                    }
                    Remove-Item $regFile -Force
                }
                else {
                    $serviceExportText = $serviceExportResult.Output -join '; '
                    throw ("Failed to export service key for " + $service + " - " + $serviceExportText)
                }
            }

            # Step 6 - Verify the ImagePath value was written correctly
            $wagaPath = "HKLM\$hiveName\$primarySet\Services\WindowsAzureGuestAgent"
            $afterImagePath = (Get-ItemProperty -Path "Registry::$wagaPath" -ErrorAction SilentlyContinue).ImagePath
            if ([string]::IsNullOrWhiteSpace($afterImagePath)) {
                Log-Warning "Verification Warning on $($diskb): VMAgent ImagePath is empty after injection."
            }
            else {
                Log-Info "Verification Success on $($diskb):: ImagePath is now $afterImagePath"
            }

            # Step 7 - Backup existing WindowsAzure folder and replace with rescue VM copy
            $sourcePath = "C:\WindowsAzure"
            $destPath = "$($diskb):\WindowsAzure"
            $backupPath = "$($diskb):\WindowsazurefaultyGAbackup"

            if (Test-Path $destPath) {
                Log-Info "Backing up existing WindowsAzure folder on $($diskb): to WindowsazurefaultyGAbackup..."
                if (-not (Test-Path $backupPath)) { $null = New-Item -Path $backupPath -ItemType Directory -Force }
                $backupCopyResult = Invoke-CriticalCommand -Command "xcopy" -Arguments @("$destPath", "$backupPath", "/E", "/Y", "/H", "/Q") -Description "xcopy backup WindowsAzure ($diskb)"
                if ($backupCopyResult.ExitCode -ge 2) {
                    throw "Failed to back up existing WindowsAzure folder on $($diskb): $($backupCopyResult.Output -join '; ')"
                }
                Log-Info "Removing old WindowsAzure folder on $($diskb):..."
                Remove-Item $destPath -Recurse -Force -ErrorAction SilentlyContinue
            }

            Log-Info "Copying full WindowsAzure folder from rescue VM to $($diskb):..."
            $null = New-Item -Path $destPath -ItemType Directory -Force
            $restoreCopyResult = Invoke-CriticalCommand -Command "xcopy" -Arguments @("$sourcePath", "$destPath", "/E", "/Y", "/H", "/Q") -Description "xcopy restore WindowsAzure ($diskb)"
            if ($restoreCopyResult.ExitCode -ge 2) {
                throw "Failed to copy WindowsAzure folder to $($diskb): $($restoreCopyResult.Output -join '; ')"
            }

            # Remove Logs folder from copied content (not relevant to the target VM)
            $logsPath = "$destPath\Logs"
            if (Test-Path $logsPath) {
                Remove-Item $logsPath -Recurse -Force -ErrorAction SilentlyContinue
            }

            $diskProcessedSuccessfully = $true
            $fixedDisks += $diskb
            $changedCount++
        }
        catch {
            Log-Error "Failed to process $($diskb):: $($_.Exception.Message)"
            $diskProcessedSuccessfully = $false
            $failedCount++
        }
        finally {
            # Step 8 - Release handles and safely unload the registry hive
            Log-Info "Unloading registry hive $hiveName..."
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 3

            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadResult = Invoke-CriticalCommand -Command "reg.exe" -Arguments @("unload", "HKLM\$hiveName") -Description "reg unload $hiveName attempt $i"
                if ($unloadResult.ExitCode -eq 0) { $unloaded = $true; break }
                Log-Warning "Unload attempt $i for $hiveName failed, retrying..."
                Start-Sleep -Seconds 5
            }
            if (-not $unloaded) {
                Log-Warning "Could not unload $hiveName hive - may need manual cleanup"
            }

            # If we used the copy fallback, copy the modified hive back to the original location
            if ($hiveCopy -and (Test-Path $hiveCopy)) {
                if ($unloaded) {
                    Log-Info "Copying modified hive back to $hiveSource..."
                    try {
                        Copy-Item -Path $hiveCopy -Destination $hiveSource -Force -ErrorAction Stop
                        Log-Info "Successfully copied modified hive back to $($diskb):"
                    }
                    catch {
                        Log-Error "Failed to copy modified hive back to $($diskb):: $($_.Exception.Message)"
                        $diskProcessedSuccessfully = $false
                        $failedDisks += $diskb
                    }
                }
                Remove-Item $hiveCopy -Force -ErrorAction SilentlyContinue
            }

            # Remove from fixed list if processing failed
            if (-not $diskProcessedSuccessfully) {
                $fixedDisks = @($fixedDisks | Where-Object { $_ -ne $diskb })
                if ($diskb -notin $failedDisks) {
                    $failedDisks += $diskb
                }
            }
        }
    }

    if ($failedDisks.Count -gt 0) {
        Log-Error "Copy-back operation failed on disks: $($failedDisks -join ', ')"
        throw "Hive copy-back failed on one or more disks: $($failedDisks -join ', '). Please review logs."
    }

    Log-Info "Processing summary: processed=$processedCount skipped=$skippedCount failed=$failedCount changed=$changedCount"
    if ($fixedDisks.Count -gt 0) {
        Log-Output "VMAgent Fix completed and verified successfully on drives: $($fixedDisks -join ', ') | Metadata: Host=$($vmMetadata.HostName), Region=$($vmMetadata.Region), SKU=$($vmMetadata.VMSku)"
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached with \Windows."
    }

}
catch {
    $errorMessage = $_.Exception.Message
    Log-Error "SCRIPT FAILED: $errorMessage"
    $script_final_status = $STATUS_ERROR
}
finally {
    # Log execution metadata for Application Insights correlation
    if ($vmMetadata.Region -or $vmMetadata.VMSku -or $vmMetadata.OSVersion) {
        Log-Info "Execution Context - Host: $($vmMetadata.HostName), Region: $($vmMetadata.Region), SKU: $($vmMetadata.VMSku), OS: $($vmMetadata.OSVersion)"
    }

    # Restore original service states
    Log-Info "Restoring original service states..."
    foreach ($svc in $serviceStates.Keys) {
        try {
            $originalState = $serviceStates[$svc]
            Log-Info "Restoring $svc to state: $originalState"
            if ($originalState -eq 'Running') {
                Start-Service -Name $svc -ErrorAction SilentlyContinue
            }
            # If original state was Stopped, service remains stopped (already stopped)
        }
        catch {
            Log-Warning "Failed to restore $svc to state $originalState : $($_.Exception.Message)"
        }
    }

    Log-Info "Execution ended at $(Get-Date)"
    Log-Info "Desktop log file path: $logFile"
}

return $script_final_status
