<#
.SYNOPSIS
    Ignore errors if there is a failed boot, failed shutdown, or failed checkpoint.
.DESCRIPTION
    Reconfigures the Boot Configuration Data (BCD) settings so the boot status policy 
    is set to IgnoreAllFailures. This prevents the VM from getting stuck in 
    Automatic Repair loops.
    Created by Tony.Mocanu@Microsoft.com
#>

# 1. Initialize script and helper functions
# No Param() block to avoid ParserErrors on legacy PowerShell engines
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# 2. Set Log Path to Public Desktop for persistent reporting
$logFile = "C:\Users\Public\Desktop\bcd-repair-log.txt"

# Ensure directory exists using legacy-friendly syntax
if (-not (Test-Path "C:\Users\Public\Desktop")) {
    $null = New-Item -ItemType Directory -Path "C:\Users\Public\Desktop" -Force
}

# 3. Execution Logic
$partitionlist = Get-Disk-Partitions
Log-Info '#03 - Enumerate partitions to reconfigure boot cfg' | Tee-Object -FilePath $logFile -Append

forEach ( $partitionGroup in $partitionlist | group DiskNumber )
{
    $isBcdPath = $false
    $bcdPath = ''
    $isOsPath = $false

    # Scan partitions for BCD and Windows loader
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

    # If both were found, update the BCD store
    if ( $isBcdPath -and $isOsPath )
    {
        $bcdout = bcdedit /store $bcdPath /enum bootmgr /v
        $defaultLine = $bcdout | Select-String 'displayorder' | select -First 1
        
        # Robust GUID capture
        if ($defaultLine -match '\{([^}]+)\}') {
            $defaultId = $matches[0]
            
            # --- BEFORE CHANGE (Line-by-Line Logging) ---
            Log-Output "--- BCD BEFORE CHANGE ---" | Tee-Object -FilePath $logFile -Append
            $beforeBcd = bcdedit /store $bcdPath /enum $defaultId
            foreach ($line in $beforeBcd) {
                if ($line.Trim()) { 
                    Log-Output $line | Tee-Object -FilePath $logFile -Append 
                }
            }
            
            # Apply Changes
            bcdedit /store $bcdPath /default $defaultId | Out-Null
            $null = bcdedit /store $bcdPath /set $defaultId bootstatuspolicy IgnoreAllFailures
            
            # --- AFTER CHANGE (Line-by-Line Logging) ---
            Log-Output "--- BCD AFTER CHANGE ---" | Tee-Object -FilePath $logFile -Append
            $afterBcd = bcdedit /store $bcdPath /enum $defaultId
            foreach ($line in $afterBcd) {
                if ($line.Trim()) { 
                    Log-Output $line | Tee-Object -FilePath $logFile -Append 
                }
            }
            
            return $STATUS_SUCCESS
        }
    }
}

Log-Error "Unable to find a valid BCD/OS combination" | Tee-Object -FilePath $logFile -Append
return $STATUS_ERROR
