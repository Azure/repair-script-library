<#
.SYNOPSIS
    Enables Special Administration Console (SAC) and Serial Console boot settings.
.DESCRIPTION
    Configures BCD to enable the boot menu, set a timeout, and turn on EMS/SAC 
    to allow serial console access to the VM.
	Created by Tony.Mocanu@Microsoft.com
#>

# 1. Initialize script and helper functions
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# 2. Set Log Path to Public Desktop
$logFile = "C:\Users\Public\Desktop\sac-enabler-log.txt"

# 3. Execution Logic
$partitionlist = Get-Disk-Partitions
Log-Info '#03 - Enumerate partitions to enable SAC' | Tee-Object -FilePath $logFile -Append

foreach ( $partitionGroup in $partitionlist | group DiskNumber )
{
    $isBcdPath = $false
    $bcdPath = ''
    $isOsPath = $false

    # Discovery Logic (Matches your BCD logic for consistency)
    ForEach ($drive in $partitionGroup.Group | select -ExpandProperty DriveLetter )
    {      
        if ( -not $isBcdPath )
        {
            $bcdPath = $drive + ':\boot\bcd'
            $isBcdPath = Test-Path $bcdPath
            if ( -not $isBcdPath )
            {
                $bcdPath = $drive + ':\efi\microsoft\boot\bcd'
                $isBcdPath = Test-Path $bcdPath
            } 
        }        
        if (-not $isOsPath)
        {
            $isOsPath = Test-Path ($drive + ':\windows\system32\winload.exe')
        }
    }

    # 4. Apply SAC Changes if BCD is found
    if ( $isBcdPath -and $isOsPath )
    {
        # Capture the target ID (usually {default})
        $bcdout = bcdedit /store $bcdPath /enum bootmgr /v
        $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
        
        if ($defaultLine -match '\{([^}]+)\}') {
            $defaultId = $matches[0]

            Log-Output "--- BCD BEFORE SAC ENABLE ---" | Tee-Object -FilePath $logFile -Append
            $beforeBcd = bcdedit /store $bcdPath /enum $defaultId
            foreach ($line in $beforeBcd) { if ($line.Trim()) { Log-Output $line | Tee-Object -FilePath $logFile -Append } }

            Log-Info "Applying SAC and EMS configurations..." | Tee-Object -FilePath $logFile -Append

            # Core Logic from Original Script
            bcdedit /store $bcdPath /set "{bootmgr}" displaybootmenu yes | Out-Null
            bcdedit /store $bcdPath /set "{bootmgr}" timeout 5 | Out-Null
            bcdedit /store $bcdPath /set "{bootmgr}" bootems yes | Out-Null
            bcdedit /store $bcdPath /ems $defaultId ON | Out-Null
            $res = bcdedit /store $bcdPath /emssettings EMSPORT:1 EMSBAUDRATE:115200

            Log-Output "Result: $res" | Tee-Object -FilePath $logFile -Append

            # --- AFTER CHANGE (Line-by-Line Logging) ---
            Log-Output "--- BCD AFTER SAC ENABLE ---" | Tee-Object -FilePath $logFile -Append
            $afterBcd = bcdedit /store $bcdPath /enum $defaultId
            foreach ($line in $afterBcd) { if ($line.Trim()) { Log-Output $line | Tee-Object -FilePath $logFile -Append } }
            
            return $STATUS_SUCCESS
        }
    }
}

Log-Error "FAILED: Script could not find a valid OS disk to enable SAC." | Tee-Object -FilePath $logFile -Append
return $STATUS_ERROR
