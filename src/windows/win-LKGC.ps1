# Welcome to the VM Last Known Good Configuration Fixer by Tony Mocanu!

# .SUMMARY
#    Fixes boot issues by redirecting the Windows 'Select' registry values to the LastKnownGood ControlSet.
#    Backs up the SYSTEM registry hive and modifies the Current/Default pointers.
#    Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/start-vm-last-known-good
# 
# .RESOLVES
#    Resolves "Inaccessible Boot Device" or blue screen loops caused by recent driver or service changes.
#    By reverting to the LastKnownGood configuration, the VM rolls back to the registry state of the last successful login.

# --- INLINED HELPERS ---
$STATUS_SUCCESS = '[STATUS]::SUCCESS'
$STATUS_ERROR = '[STATUS]::ERROR'

Function Log-Output  { Param([PSObject[]]$message) Write-Output "[Output $(Get-Date)]$message" }
Function Log-Info    { Param([PSObject[]]$message) Write-Output "[Info $(Get-Date)]$message" }
Function Log-Warning { Param([PSObject[]]$message) Write-Output "[Warning $(Get-Date)]$message" }
Function Log-Error   { Param([PSObject[]]$message) Write-Output "[Error $(Get-Date)]$message" }

Function Export-RegKey {
    Param($KeyPath)
    # Using the PS Drive created in Step 3
    if (Test-Path $KeyPath) {
        Log-Output "--- Displaying Key: $KeyPath ---"
        $data = Get-ItemProperty -Path $KeyPath | 
                Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | 
                Format-List | Out-String
        
        $data.Split("`n") | ForEach-Object { if ($_ -match '\S') { Log-Output $_.Trim() } }
    } else {
        Log-Output "Key $KeyPath does not exist."
    }
}

Log-Info "Starting LKGC recovery script with Backup and Dynamic Discovery."

try {
    # 1. Identify Target Drive
    $targetDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetDrive) {
        Log-Error "Could not find the attached Windows OS disk."
        Write-Output $STATUS_ERROR
        exit 1
    }

    $configPath = Join-Path $targetDrive "Windows\System32\config"
    $systemHive = Join-Path $configPath "SYSTEM"

    # 2. Backup the Hive & Log Caution
    $backupPath = "$systemHive.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
    Log-Info "Creating backup of SYSTEM hive at: $backupPath"
    Copy-Item -Path $systemHive -Destination $backupPath -Force

    Log-Output "****************************************************************"
    Log-Output "CAUTION: A backup of the SYSTEM hive was created at:"
    Log-Output "$backupPath"
    Log-Output "If this repair is successful and the backup is no longer needed,"
    Log-Output "please manually delete this file from the guest OS."
    Log-Output "****************************************************************"

    # 3. Load Hive
    Log-Info "Loading SYSTEM hive into HKLM\REPAIR_SYSTEM"
    reg load HKLM\REPAIR_SYSTEM "$systemHive" | Out-Null
    
    New-PSDrive -Name REPAIR_REG -PSProvider Registry -Root HKLM\REPAIR_SYSTEM | Out-Null

    # 4. CAPTURING INITIAL STATE (BEFORE)
    $selectPath = "REPAIR_REG:\Select"
    Log-Output ">>> CAPTURING INITIAL REGISTRY STATE (BEFORE) <<<"
    Export-RegKey $selectPath

    # 5. Logic: Point Current to LastKnownGood
    $currentValues = Get-ItemProperty -Path $selectPath
    $valCurrent = $currentValues.Current
    $valLKG     = $currentValues.LastKnownGood

    Log-Info "Analysis -> Current Set: $valCurrent, LastKnownGood Set: $valLKG"

    $targetSet = $valLKG
    
    if ($valCurrent -eq $valLKG) {
        Log-Warning "Current and LKG are already the same ($valCurrent). Incrementing per MS documentation."
        $targetSet = $valLKG + 1
    }

    $targetKeyPath = "REPAIR_REG:\ControlSet00$targetSet"
    if (-not (Test-Path $targetKeyPath)) {
        Log-Error "Target ControlSet00$targetSet NOT found! Falling back to 001."
        $targetSet = 1
    }

    # 6. Apply Changes
    Log-Info "Updating 'Current' and 'Default' to point to ControlSet00$targetSet"
    Set-ItemProperty -Path $selectPath -Name "Current" -Value $targetSet
    Set-ItemProperty -Path $selectPath -Name "Default" -Value $targetSet
    Set-ItemProperty -Path $selectPath -Name "Failed"  -Value $valCurrent 

    # 7. CAPTURING UPDATED STATE (AFTER)
    Log-Output ">>> CAPTURING UPDATED REGISTRY STATE (AFTER) <<<"
    Export-RegKey $selectPath

    Log-Output "Success: VM configured to boot using ControlSet00$targetSet."

    # 8. Cleanup and Unmount
    Set-Location C:\
    Remove-PSDrive REPAIR_REG -Force 
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    
    Start-Sleep -Seconds 2
    reg unload HKLM\REPAIR_SYSTEM | Out-Null
    
    Write-Output $STATUS_SUCCESS
    exit 0

}
catch {
    Log-Error "Critical Failure: $($_.Exception.Message)"
    Set-Location C:\
    if (Get-PSDrive REPAIR_REG -ErrorAction SilentlyContinue) { Remove-PSDrive REPAIR_REG -Force }
    reg unload HKLM\REPAIR_SYSTEM 2>$null
    
    Write-Output $STATUS_ERROR
    exit 1
}
