# Welcome to the VM Azure Agent Offline fixer by Tony Mocanu!
# .SUMMARY
#    Fixes integrity of files and registry from windows guest agent offline.
#    Backs up registry. Copies installation folder and registry values related to Windows Guest Agent to attached disk.
#    Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/install-vm-agent-offline 
# 
# .RESOLVES
#    The server needs to use the Guest Agent (e.g. for a password reset) but the user is currently unable to because 
#    the Guest Agent is not installed. After performing this fix, the Guest Agent will effectively be installed on the attached OS disk as well.
#    The Azure Virtual Machine Agent (VM Agent) provides useful features, such as local administrator password reset and script pushing.

# --- INLINED HELPERS ---
$STATUS_SUCCESS = '[STATUS]::SUCCESS'
$STATUS_ERROR = '[STATUS]::ERROR'
Function Log-Info { Param([PSObject[]]$message) Write-Output "[Info $(Get-Date)]$message" }
Function Log-Output { Param([PSObject[]]$message) Write-Output "[Output $(Get-Date)]$message" }
Function Log-Error { Param([PSObject[]]$message) Write-Output "[Error $(Get-Date)]$message" }

Function Export-RegKey {
    Param($KeyPath)
    $fullPath = "Registry::HKEY_LOCAL_MACHINE\$KeyPath"
    if (Test-Path $fullPath) {
        Log-Output "--- Displaying Key: HKLM:\$KeyPath ---"
        # Format-List ensures all properties (ImagePath, Start, etc.) are visible
        $data = Get-ItemProperty -Path $fullPath | 
                Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | 
                Format-List | Out-String
        
        $data.Split("`n") | ForEach-Object { if ($_ -match '\S') { Log-Output $_.Trim() } }
    } else {
        Log-Output "Key HKLM:\$KeyPath does not exist."
    }
}

try {
    # 1. Identify Target Drive
    $targetDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetDrive) { throw "Target OS disk not found." }

    # 2. CREATE SYSTEM HIVE BACKUP & LOG CAUTION
    $systemHiveDir = Join-Path $targetDrive "Windows\System32\config"
    $systemHive = Join-Path $systemHiveDir "SYSTEM"
    $backupName = "SYSTEM.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
    $backupPath = Join-Path $systemHiveDir $backupName
    
    Log-Info "Backing up SYSTEM hive to $backupPath"
    Copy-Item -Path $systemHive -Destination $backupPath -Force

    # --- THE CAUTION NOTE ---
    Log-Output "****************************************************************"
    Log-Output "CAUTION: A backup of the SYSTEM hive was created at:"
    Log-Output "$backupPath"
    Log-Output "If this repair is successful and the backup is no longer needed,"
    Log-Output "please manually delete this file from the guest OS."
    Log-Output "****************************************************************"

    # 3. Copy Agent Folder
    $localAzurePath = "C:\WindowsAzure"
    $latestAgentFolder = Get-ChildItem -Path $localAzurePath -Filter "GuestAgent_*" | 
                         Sort-Object Name -Descending | Select-Object -First 1
    
    if (-not $latestAgentFolder) { throw "Could not find GuestAgent folder on Repair VM." }
    
    $destPath = Join-Path $targetDrive "WindowsAzure"
    if (!(Test-Path $destPath)) { New-Item -ItemType Directory -Path $destPath | Out-Null }
    
    Log-Info "Copying $($latestAgentFolder.Name) to target disk."
    Copy-Item -Path $latestAgentFolder.FullName -Destination $destPath -Recurse -Force

    # 4. Load Hive
    Log-Info "Loading hive into HKLM\BROKENSYSTEM"
    reg load HKLM\BROKENSYSTEM "$systemHive" | Out-Null

    $currentSetNum = (Get-ItemProperty -Path "HKLM:\BROKENSYSTEM\Select").Current
    $targetServicesBase = "BROKENSYSTEM\ControlSet00$currentSetNum\Services"

    # 5. Export Initial (Before)
    Log-Output ">>> CAPTURING INITIAL REGISTRY STATE (BEFORE) <<<"
    Export-RegKey "$targetServicesBase\RdAgent"
    Export-RegKey "$targetServicesBase\WindowsAzureGuestAgent"

    # 6. Mirroring Logic
    $servicesToMirror = @("RdAgent", "WindowsAzureGuestAgent")
    $targetImagePathValue = "C:\WindowsAzure\$($latestAgentFolder.Name)\WaAppAgent.exe"

    foreach ($serviceName in $servicesToMirror) {
        Log-Info "Mirroring service: $serviceName"
        $sourceKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$serviceName")
        $destKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetServicesBase, $true).CreateSubKey($serviceName)

        if ($sourceKey) {
            foreach ($valueName in $sourceKey.GetValueNames()) {
                $val = $sourceKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kind = $sourceKey.GetValueKind($valueName)
                
                if ($valueName -eq "ImagePath") {
                    $destKey.SetValue($valueName, $targetImagePathValue, $kind)
                } else {
                    $destKey.SetValue($valueName, $val, $kind)
                }
            }
            $sourceKey.Close()
            $destKey.Close()
        }
    }

    # 7. Export Updated (After)
    Log-Output ">>> CAPTURING UPDATED REGISTRY STATE (AFTER) <<<"
    Export-RegKey "$targetServicesBase\RdAgent"
    Export-RegKey "$targetServicesBase\WindowsAzureGuestAgent"

    # 8. Cleanup
    Set-Location C:\
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 2
    reg unload HKLM\BROKENSYSTEM | Out-Null

    Write-Output $STATUS_SUCCESS
    exit 0
}
catch {
    Log-Error "Failure: $($_.Exception.Message)"
    reg unload HKLM\BROKENSYSTEM 2>$null
    Write-Output $STATUS_ERROR
    exit 1
}
