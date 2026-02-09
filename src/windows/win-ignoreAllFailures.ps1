# Welcome to the Azure VHD Preparation/Verification Fixer by Tony Mocanu!

# .SUMMARY
#    Configures an offline Windows VHD to meet the "Verify the VM" Azure requirements.
#    Sets UTC time, SAN Policy, RDP, Power Plan, and BCD integrity.
#    Public doc: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image#verify-the-vm
# 
# .RESOLVES
#    - Time offset/drift issues (RealTimeIsUniversal)
#    - Offline data disks (SanPolicy)
#    - RDP blocked at registry level (fDenyTSConnections)
#    - Slow performance or "Sleeping" VMs (PowerScheme)

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
        bcdedit /store "$bcdPath" /enum | Where-Object { $_ -match "integrityservices|recoveryenabled" } | ForEach-Object { Log-Output $_.Trim() }
    }
}

try {
    # 1. Identify Target Drive
    $targetDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetDrive) { throw "Target OS disk not found." }
    $systemHive = Join-Path $targetDrive "Windows\System32\config\SYSTEM"
    $softwareHive = Join-Path $targetDrive "Windows\System32\config\SOFTWARE"

    # 2. Backups
    $timeStamp = Get-Date -Format 'yyyyMMddHHmmss'
    Copy-Item $systemHive -Destination "$systemHive.bak_$timeStamp" -Force
    Copy-Item $softwareHive -Destination "$softwareHive.bak_$timeStamp" -Force
    Log-Info "Backups created: SYSTEM.bak_$timeStamp and SOFTWARE.bak_$timeStamp"

    # 3. Load Hives
    reg load HKLM\OFFLINE_SYSTEM "$systemHive" | Out-Null
    reg load HKLM\OFFLINE_SOFTWARE "$softwareHive" | Out-Null
    
    $currentSetNum = (Get-ItemProperty -Path "HKLM:\OFFLINE_SYSTEM\Select").Current
    $controlSet = "ControlSet00$currentSetNum"

    # Registry Paths per Microsoft Documentation
    $tzPath = "OFFLINE_SYSTEM\$controlSet\Control\TimeZoneInformation"
    $sanPath = "OFFLINE_SYSTEM\$controlSet\Control"
    $tsPath = "OFFLINE_SYSTEM\$controlSet\Control\Terminal Server"
    $pwrPath = "OFFLINE_SYSTEM\$controlSet\Control\Power\User\PowerSchemes"

    # --- AUDIT BEFORE ---
    Log-Output ">>> AUDITING CURRENT SETTINGS (BEFORE) <<<"
    Export-RegKey $tzPath "RealTimeIsUniversal"
    Export-RegKey $sanPath "SanPolicy"
    Export-RegKey $tsPath "fDenyTSConnections"
    Export-RegKey $pwrPath "ActivePowerScheme"

    # 4. Apply Changes
    Log-Info "Updating registry to match Azure best practices..."
    
    # A. Set UTC Time
    if (!(Test-Path "HKLM:\$tzPath")) { New-Item -Path "HKLM:\$tzPath" -Force | Out-Null }
    Set-ItemProperty -Path "HKLM:\$tzPath" -Name "RealTimeIsUniversal" -Value 1 -Type DWord

    # B. Set SAN Policy to OnlineAll (1)
    Set-ItemProperty -Path "HKLM:\$sanPath" -Name "SanPolicy" -Value 1 -Type DWord

    # C. Enable RDP (fDenyTSConnections = 0)
    Set-ItemProperty -Path "HKLM:\$tsPath" -Name "fDenyTSConnections" -Value 0 -Type DWord

    # D. High Performance Power Plan
    Set-ItemProperty -Path "HKLM:\$pwrPath" -Name "ActivePowerScheme" -Value "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

    # --- AUDIT AFTER ---
    Log-Output ">>> VERIFYING UPDATED SETTINGS (AFTER) <<<"
    Export-RegKey $tzPath "RealTimeIsUniversal"
    Export-RegKey $sanPath "SanPolicy"
    Export-RegKey $tsPath "fDenyTSConnections"
    Export-RegKey $pwrPath "ActivePowerScheme"

    # 5. BCD Integrity & Recovery Settings
    $bcdPath = ""
    $possibleBcds = @("$( $targetDrive )Boot\BCD", "$( $targetDrive )EFI\Microsoft\Boot\BCD")
    foreach ($p in $possibleBcds) { if (Test-Path $p) { $bcdPath = $p; break } }

    if ($bcdPath) {
        Export-BCDState $bcdPath "BEFORE"
        bcdedit /store "$bcdPath" /set "{bootmgr}" integrityservices enable
        bcdedit /store "$bcdPath" /set "{default}" integrityservices enable
        bcdedit /store "$bcdPath" /set "{default}" recoveryenabled No
        Export-BCDState $bcdPath "AFTER"
    }

    # 6. Unload & Cleanup
    Set-Location C:\
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 2
    reg unload HKLM\OFFLINE_SYSTEM | Out-Null
    reg unload HKLM\OFFLINE_SOFTWARE | Out-Null

    Log-Output "Success: VHD verified and updated for Azure."
    Write-Output $STATUS_SUCCESS
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    reg unload HKLM\OFFLINE_SYSTEM 2>$null
    reg unload HKLM\OFFLINE_SOFTWARE 2>$null
    Write-Output $STATUS_ERROR
    exit 1
}
