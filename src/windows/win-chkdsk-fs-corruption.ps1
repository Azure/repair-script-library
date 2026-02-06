# .SUMMARY
#   Runs chkdsk to fix file system corruption.
#   Checks if dirty bit has been set and if so, runs a chkdsk.exe on the attached disk.
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error
# 
# .RESOLVES
#   A Windows VM doesn't start. When you check the boot screenshots in Boot diagnostics, you see that the Check Disk process (chkdsk.exe)
#   is running with one of the following messages: 1. Scanning and repairing drive (C:) , 2. Checking file system on C: .
#   If an NTFS error is found in the file system, the dirty bit will set and the disk check application will run to try and fix any corruption. Running it from a rescue VM helps prevent interruptions.

# --- INLINED HELPERS (Required for Logging) ---
$STATUS_SUCCESS = '[STATUS]::SUCCESS'
$STATUS_ERROR = '[STATUS]::ERROR'
Function Log-Info   { Param([PSObject[]]$message) Write-Output "[Info $(Get-Date)]$message" }
Function Log-Output { Param([PSObject[]]$message) Write-Output "[Output $(Get-Date)]$message" }
Function Log-Error  { Param([PSObject[]]$message) Write-Output "[Error $(Get-Date)]$message" }

try {
    # 1. Identify Target OS Drive
    $targetRoot = (Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Root -ne "$($env:SystemDrive)\" -and (Test-Path (Join-Path $_.Root "Windows\System32\config\SYSTEM")) 
    }).Root | Select-Object -First 1

    if (-not $targetRoot) { throw "Target OS disk not found. Ensure the disk is attached to the Repair VM." }
    $driveLetter = $targetRoot.Substring(0,1)

    # 2. Capture BCD Store "Before"
    $bcdPath = Join-Path $targetRoot "Boot\BCD"
    if (!(Test-Path $bcdPath)) { $bcdPath = Join-Path $targetRoot "EFI\Microsoft\Boot\BCD" }

    if (Test-Path $bcdPath) {
        Log-Info "Capturing BCD state before repair from $bcdPath"
        $bcdBefore = bcdedit /store $bcdPath /enum | Out-String
        Log-Output "--- BCD BEFORE REPAIR ---`n$bcdBefore"
    }

    # 3. Disk and Partition Discovery
    $targetPartition = Get-Partition -DriveLetter $driveLetter
    $diskNumber = $targetPartition.DiskNumber
    Log-Info "Target OS disk identified as Disk $diskNumber."

    $partitions = Get-Partition -DiskNumber $diskNumber | Where-Object { $_.DriveLetter }

    foreach ($partition in $partitions) {
        $drive = "$($partition.DriveLetter):"
        Log-Info "Analyzing partition $drive..."

        $dirtyQuery = fsutil dirty query $drive
        if ($dirtyQuery -match "is dirty") {
            Log-Info "Dirty bit is SET for $drive. Starting filtered chkdsk..."
            
            $rawChkdsk = chkdsk $drive /f /x
            $cleanChkdsk = $rawChkdsk | Where-Object { 
                $_ -notmatch "\.\.\." -and $_ -notmatch "%" -and $_ -notmatch "ETA" -and ![string]::IsNullOrWhiteSpace($_)
            } | ForEach-Object { 
                # This line removes extra internal spaces to make the log compact
                $_.Trim() -replace '\s{2,}', ' ' 
            }

            Log-Output "--- CLEAN CHKDSK SUMMARY FOR $drive ---"
            $cleanChkdsk | ForEach-Object { Log-Output $_ }
            Log-Output "---------------------------------------"
        } else {
            Log-Info "Dirty bit NOT set for $drive. Skipping chkdsk."
        }
    }
    
    Log-Output "Completed disk verification on Disk $diskNumber."
    Write-Output $STATUS_SUCCESS
    exit 0
}
catch {
    # This will now work because Log-Error is defined at the top
    Log-Error "Failure: $($_.Exception.Message)"
    Write-Output $STATUS_ERROR
    exit 1
}
