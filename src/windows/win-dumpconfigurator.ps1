# Welcome to the Azure VHD Preparation/Verification Fixer by Tony Mocanu!
#
# .SUMMARY
#    Configures an offline Windows VHD to troubleshoot and mitigate Blue Screen (BSOD) errors.
#    Sets Memory Dump settings, Boot Status Policy, and disables Recovery Mode.
#    Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-common-blue-screen-error
# 
# .RESOLVES
#    - BSOD loops by forcing the OS to ignore boot failures (BootStatusPolicy)
#    - Missing crash data by enabling Kernel Memory Dumps (CrashControl)
#    - Stuck "Blue Screen" menus by disabling BCD recovery (recoveryenabled)
#    - Memory management issues by ensuring a valid PageFile path

# --- INLINED HELPERS ---
$STATUS_SUCCESS = '[STATUS]::SUCCESS'
$STATUS_ERROR = '[STATUS]::ERROR'
Function Log-Info    { Param([PSObject[]]$message) Write-Output "[Info $(Get-Date)]$message" }
Function Log-Output  { Param([PSObject[]]$message) Write-Output "[Output $(Get-Date)]$message" }
Function Log-Error   { Param([PSObject[]]$message) Write-Output "[Error $(Get-Date)]$message" }

Function Export-RegKey {
    Param($KeyPath, $ValueName)
    $fullPath = "Registry::HKEY_LOCAL_MACHINE\$KeyPath"
    if (Test-Path $fullPath) {
        $val = Get-ItemProperty -Path $fullPath -Name $ValueName -ErrorAction SilentlyContinue
        if ($val) { Log-Output "$ValueName : $($val.$ValueName)" }
        else { Log-Output "$ValueName : NOT FOUND" }
    }
}

Function Export-BCDState {
    Param($bcdPath, $label)
    Log-Output ">>> CHECKING BCD SETTINGS ($label) <<<"
    if (Test-Path $bcdPath) {
        # Checking for recovery and boot policy settings
        bcdedit /store "$bcdPath" /enum | Where-Object { $_ -match "recoveryenabled|bootstatuspolicy" } | ForEach-Object { Log-Output $_.Trim() }
    }
}

try {
    # 1. Identify Target Drive
    $targetDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetDrive) { throw "Target OS disk not found." }
    $systemHive = Join-Path $targetDrive "Windows\System32\config\SYSTEM"

    # 2. Backups
    $timeStamp = Get-Date -Format 'yyyyMMddHHmmss'
    Copy-Item $systemHive -Destination "$systemHive.bak_$timeStamp" -Force
    Log-Info "Backup created: SYSTEM.bak_$timeStamp"

    # 3. Load Hive
    Log-Info "Loading SYSTEM hive..."
    reg load HKLM\OFFLINE_SYSTEM "$systemHive" | Out-Null
    
    $currentSetNum = (Get-ItemProperty -Path "HKLM:\OFFLINE_SYSTEM\Select").Current
    $controlSet = "ControlSet00$currentSetNum"

    # Registry Paths per BSOD Troubleshooting Guide
    $ccPath = "OFFLINE_SYSTEM\$controlSet\Control\CrashControl"
    $ctrlPath = "OFFLINE_SYSTEM\$controlSet\Control"
    $mmPath = "OFFLINE_SYSTEM\$controlSet\Control\Session Manager\Memory Management"

    # --- AUDIT BEFORE ---
    Log-Output ">>> AUDITING BSOD SETTINGS (BEFORE) <<<"
    Export-RegKey $ccPath "CrashDumpEnabled"
    Export-RegKey $ctrlPath "BootStatusPolicy"
    Export-RegKey $mmPath "ExistingPageFiles"

    # 4. Apply Changes
    Log-Info "Applying BSOD mitigation settings..."
    
    # A. Enable Kernel Memory Dump (1) and Overwrite (1)
    Set-ItemProperty -Path "HKLM:\$ccPath" -Name "CrashDumpEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\$ccPath" -Name "Overwrite" -Value 1 -Type DWord

    # B. Set Boot Status Policy to IgnoreAllFailures (1)
    # This prevents the VM from stopping at the recovery menu after a crash
    Set-ItemProperty -Path "HKLM:\$ctrlPath" -Name "BootStatusPolicy" -Value 1 -Type DWord

    # C. Ensure PageFile is set to C: (Prevents dump failures)
    Set-ItemProperty -Path "HKLM:\$mmPath" -Name "ExistingPageFiles" -Value "\??\C:\pagefile.sys" -Type MultiString

    # --- AUDIT AFTER ---
    Log-Output ">>> VERIFYING UPDATED SETTINGS (AFTER) <<<"
    Export-RegKey $ccPath "CrashDumpEnabled"
    Export-RegKey $ctrlPath "BootStatusPolicy"
    Export-RegKey $mmPath "ExistingPageFiles"

    # 5. BCD Settings for BSOD Loops
    $bcdPath = ""
    $possibleBcds = @("$( $targetDrive )Boot\BCD", "$( $targetDrive )EFI\Microsoft\Boot\BCD")
    foreach ($p in $possibleBcds) { if (Test-Path $p) { $bcdPath = $p; break } }

    if ($bcdPath) {
        Export-BCDState $bcdPath "BEFORE"
        # Disable the recovery screen that blocks boot
        bcdedit /store "$bcdPath" /set "{default}" recoveryenabled No
        # Optional: Set boot status policy in BCD as well
        bcdedit /store "$bcdPath" /set "{default}" bootstatuspolicy IgnoreAllFailures
        Export-BCDState $bcdPath "AFTER"
    }

    # 6. Unload & Cleanup
    Set-Location C:\
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 2
    reg unload HKLM\OFFLINE_SYSTEM | Out-Null

    Log-Output "Success: BSOD mitigation settings applied to $targetDrive."
    Write-Output $STATUS_SUCCESS
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    reg unload HKLM\OFFLINE_SYSTEM 2>$null
    Write-Output $STATUS_ERROR
    exit 1
}
