# Welcome to the VM SAC and Boot Menu Configuration Fixer by Tony Mocanu!
# .SUMMARY
#    Enables Serial Console (SAC), EMS, and the Boot Menu for an offline VM.
#    Modifies the BCD store and the SYSTEM registry hive to ensure the VM is accessible via Serial.
#    Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/serial-console-grub-menu-windows
# 
# .RESOLVES
#    Resolves cases where the VM is stuck at a "Recovery" screen or blue screen that can't be seen.
#    Enabling SAC allows an admin to use the Serial Console to run CMD, restart services, or debug.

# --- INLINED HELPERS ---
$STATUS_SUCCESS = '[STATUS]::SUCCESS'
$STATUS_ERROR = '[STATUS]::ERROR'
Function Log-Info    { Param([PSObject[]]$message) Write-Output "[Info $(Get-Date)]$message" }
Function Log-Output  { Param([PSObject[]]$message) Write-Output "[Output $(Get-Date)]$message" }
Function Log-Error   { Param([PSObject[]]$message) Write-Output "[Error $(Get-Date)]$message" }

# Optimized BCD export to prevent log cutoff
Function Export-BCDState {
    Param($bcdPath, $label)
    Log-Output ">>> CHECKING BCD SETTINGS ($label) <<<"
    if (Test-Path $bcdPath) {
        $bcdData = bcdedit /store "$bcdPath" /enum
        # Filter for only relevant SAC/Boot settings to save space in the Azure output buffer
        $bcdData | Where-Object { $_ -match "displaybootmenu|timeout|ems|emssettings|bootloadersettings" } | ForEach-Object { Log-Output $_.Trim() }
    } else {
        Log-Error "BCD path not found: $bcdPath"
    }
}

Function Export-RegKey {
    Param($KeyPath)
    $fullPath = "Registry::HKEY_LOCAL_MACHINE\$KeyPath"
    if (Test-Path $fullPath) {
        Log-Output "--- Displaying Key: HKLM:\$KeyPath ---"
        $data = Get-ItemProperty -Path $fullPath | 
                Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | 
                Format-List | Out-String
        $data.Split("`n") | ForEach-Object { if ($_ -match '\S') { Log-Output $_.Trim() } }
    }
}

try {
    # 1. Identify Target Drive
    $targetOSDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetOSDrive) { throw "Target OS disk not found." }

    # 2. Locate BCD Store
    $bcdPath = ""
    $possiblePaths = @(
        "$( $targetOSDrive )Boot\BCD",
        "$( $targetOSDrive )EFI\Microsoft\Boot\BCD"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) { $bcdPath = $path; break }
    }

    if (-not $bcdPath) {
        Log-Info "Searching for System Reserved partition..."
        $sysPart = Get-Partition | Where-Object { $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -or $_.IsActive } | Select-Object -First 1
        if ($sysPart) {
            $driveLetter = "Z"
            Set-Partition -InputObject $sysPart -NewDriveLetter $driveLetter
            $bcdPath = "${driveLetter}:\Boot\BCD"
            if (-not (Test-Path $bcdPath)) { $bcdPath = "${driveLetter}:\EFI\Microsoft\Boot\BCD" }
        }
    }

    if (-not (Test-Path $bcdPath)) { throw "Could not locate BCD store." }

    # 3. VERIFY BEFORE
    Export-BCDState $bcdPath "BEFORE"

    # 4. Apply Configuration
    Log-Info "Applying BCD configuration for Serial Console..."
    bcdedit /store "$bcdPath" /set "{bootmgr}" displaybootmenu yes
    bcdedit /store "$bcdPath" /set "{bootmgr}" timeout 10
    bcdedit /store "$bcdPath" /set "{bootmgr}" bootems yes
    bcdedit /store "$bcdPath" /ems "{default}" ON
    bcdedit /store "$bcdPath" /emssettings EMSPORT:1 EMSBAUDRATE:115200

    # 5. VERIFY AFTER
    Export-BCDState $bcdPath "AFTER"

    # 6. Registry Backup & BootStatusPolicy
    $systemHive = Join-Path $targetOSDrive "Windows\System32\config\SYSTEM"
    $backupPath = "$systemHive.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
    Log-Info "Backing up hive to: $backupPath"
    Copy-Item -Path $systemHive -Destination $backupPath -Force

    Log-Output "****************************************************************"
    Log-Output "CAUTION: A backup of the SYSTEM hive was created at:"
    Log-Output "$backupPath"
    Log-Output "****************************************************************"

    reg load HKLM\REPAIR_SYSTEM "$systemHive" | Out-Null
    $currentSet = (Get-ItemProperty -Path "HKLM:\REPAIR_SYSTEM\Select").Current
    $regPath = "REPAIR_SYSTEM\ControlSet00$currentSet\Control"

    Log-Output ">>> CAPTURING REGISTRY (BEFORE) <<<"
    Export-RegKey $regPath

    Log-Info "Setting BootStatusPolicy to 1..."
    Set-ItemProperty -Path "HKLM:\$regPath" -Name "BootStatusPolicy" -Value 1 -Type DWord

    Log-Output ">>> CAPTURING REGISTRY (AFTER) <<<"
    Export-RegKey $regPath

    reg unload HKLM\REPAIR_SYSTEM | Out-Null

    if (Get-PSDrive Z -ErrorAction SilentlyContinue) { Remove-PartitionAccessPath -DriveLetter Z -AccessPath "Z:\" }
    
    Log-Output "Success: SAC and Boot Menu settings are now persistent."
    Write-Output $STATUS_SUCCESS
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    reg unload HKLM\REPAIR_SYSTEM 2>$null
    Write-Output $STATUS_ERROR
    exit 1
}
