<#
.SYNOPSIS
    VMAgent Offline Fixer - Comprehensive Version.
    - Fixes Registry and Binaries for Guest Agent and RDAgent.
    - Automatically detects and updates active/backup ControlSets (001 and 002).
    - Implements strict validation and handle releasing for clean hive unloads.
    - Created by Tony.Mocanu@Microsoft.com
#>

# 1. Import common logic
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# Define log path (SystemDrive is safest for SYSTEM account)
$logFile = "$env:SystemDrive\VMAgent-Fix.log"

try {
    Log-Info "Starting VMAgent Offline Fixer..." | Tee-Object -FilePath $logFile -Append

    # 2. Finder for faulty OS letter
    $diskb = "000"
    $diskarray = "d","q","w","e","r","t","y","u","i","o","p","s","f","g","h","j","k","l","z","x","v","n","m"
    foreach ($diskt in $diskarray) {
        if (Test-Path -Path "$($diskt):\Windows") { $diskb = $diskt; break }
    }

    if ($diskb -eq "000") { throw "Could not find a rescue OS disk attached." }
    Log-Info "Target OS disk found on letter: $($diskb):" | Tee-Object -FilePath $logFile -Append

    # 3. Hive Management (Safety Unload & Load)
    & reg.exe unload "HKLM\BROKENSYSTEM" 2>$null
    Log-Info "Loading SYSTEM hive..." | Tee-Object -FilePath $logFile -Append
    $loadResult = & reg.exe load "HKLM\BROKENSYSTEM" "$($diskb):\Windows\System32\config\SYSTEM" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to load Registry Hive: $loadResult" }
    Start-Sleep -Seconds 2

    # 4. Registry Injection - Dual ControlSet Logic
    # Identify which ControlSet is the default boot set
    $selectPath = "Registry::HKLM\BROKENSYSTEM\Select"
    $defaultSetID = (Get-ItemProperty -path $selectPath).default
    $primarySet = "ControlSet00$defaultSetID"
    $otherSet = if ($primarySet -eq "ControlSet001") { "ControlSet002" } else { "ControlSet001" }

    Log-Info "Primary ControlSet identified: $primarySet" | Tee-Object -FilePath $logFile -Append

    $services = @("WindowsAzureGuestAgent", "WindowsAzureTelemetryService", "RdAgent")

    foreach ($service in $services) {
        $regFile = "$($diskb):\$service.reg"
        # Export healthy key from the current Rescue VM
        & reg.exe export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service" "$regFile" /y 2>$null
        
        if (Test-Path $regFile) {
            $originalContent = Get-Content $regFile
            
            # Update Primary Set
            Log-Info "Updating $service in $primarySet..." | Tee-Object -FilePath $logFile -Append
            $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\BROKENSYSTEM\$primarySet"
            $content | Set-Content $regFile
            & reg.exe import $regFile 2>&1 | Out-Null

            # Update Secondary Set (if it exists on disk)
            if (Test-Path "Registry::HKLM\BROKENSYSTEM\$otherSet") {
                Log-Info "Updating $service in backup $otherSet..." | Tee-Object -FilePath $logFile -Append
                $content = $originalContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', "HKEY_LOCAL_MACHINE\BROKENSYSTEM\$otherSet"
                $content | Set-Content $regFile
                & reg.exe import $regFile 2>&1 | Out-Null
            }
            Remove-Item $regFile -Force
        }
    }

    # 5. Strict Verification of Changes
    $wagaPath = "HKLM\BROKENSYSTEM\$primarySet\Services\WindowsAzureGuestAgent"
    $afterImagePath = (Get-ItemProperty -Path "Registry::$wagaPath" -ErrorAction SilentlyContinue).ImagePath
    if ([string]::IsNullOrWhiteSpace($afterImagePath)) {
        throw "Verification Failed: VMAgent ImagePath is empty after injection attempt."
    }
    Log-Info "Verification Success: ImagePath is now $afterImagePath" | Tee-Object -FilePath $logFile -Append

    # 6. Binary Copy (GuestAgent Folders Only)
    Log-Info "Restoring GuestAgent binaries from Troubleshooter..." | Tee-Object -FilePath $logFile -Append
    $sourcePath = "C:\WindowsAzure"
    $destPath = "$($diskb):\WindowsAzure"
    if (-not (Test-Path $destPath)) { New-Item -Path $destPath -ItemType Directory | Out-Null }

    $agentFolders = Get-ChildItem -Path $sourcePath -Directory -Filter "GuestAgent_*"
    foreach ($folder in $agentFolders) {
        Log-Info "Copying $($folder.Name) to target..." | Tee-Object -FilePath $logFile -Append
        Copy-Item -Path $folder.FullName -Destination $destPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 7. Release Handles and Unload
    Log-Info "Releasing registry handles and unloading hive..." | Tee-Object -FilePath $logFile -Append
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 3

    $unloaded = $false
    for ($i=1; $i -le 3; $i++) {
        & reg.exe unload "HKLM\BROKENSYSTEM" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
        Log-Warning "Unload attempt $i failed, retrying..." | Tee-Object -FilePath $logFile -Append
        Start-Sleep -Seconds 5
    }

    if (-not $unloaded) { throw "Critical Failure: Could not unload BROKENSYSTEM hive." }

    Log-Output "VMAgent Fix completed and verified successfully." | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS

}
catch {
    $errorMessage = $_.Exception.Message
    Log-Error "SCRIPT FAILED: $errorMessage" | Tee-Object -FilePath $logFile -Append
    
    # Final emergency attempt to unload hive so disk can detach
    [System.GC]::Collect()
    & reg.exe unload "HKLM\BROKENSYSTEM" 2>$null
    
    return $STATUS_ERROR
}
finally {
    Log-Info "Execution ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}
