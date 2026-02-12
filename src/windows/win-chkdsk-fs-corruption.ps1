# .SUMMARY
#   Runs chkdsk to fix file system corruption.
#   Checks if dirty bit has been set and if so, runs a chkdsk.exe on the attached disk.
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error
# 
# .RESOLVES
#   A Windows VM doesn't start. When you check the boot screenshots in Boot diagnostics, you see that the Check Disk process (chkdsk.exe)
#   is running with one of the following messages: 1. Scanning and repairing drive (C:) , 2. Checking file system on C: .
#   If an NTFS error is found in the file system, the dirty bit will set and the disk check application will run to try and fix any corruption. Running it from a rescue VM helps prevent interruptions.

# 1. Initialize script and helper functions
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions.ps1

# 2. Set Log Path to Public Desktop
$logDir = "C:\Users\Public\Desktop"
$logFile = "$logDir\chkdsk-repair-log.txt"

if (-not (Test-Path $logDir)) {
    $null = New-Item -ItemType Directory -Path $logDir -Force
}

# Initialize the status variable early
$script_final_status = $STATUS_SUCCESS

try {
    Log-Info "Script execution started. Report: $logFile" | Tee-Object -FilePath $logFile -Append

    # Wrap in @() to prevent the 'op_Addition' error in Get-Disk-Partitions
    $partitionlist = @(Get-Disk-Partitions)

    if ($null -eq $partitionlist -or $partitionlist.Count -eq 0) {
        Log-Warning "No partitions found to check." | Tee-Object -FilePath $logFile -Append
    }
    else {
        foreach ($partition in $partitionlist) {
            if ($partition -and $partition.DriveLetter) {
                
                $letter = $partition.DriveLetter
                if ($letter -notmatch ":") { $letter = "$letter" + ":" }
                
                Log-Info "Checking drive: $letter" | Tee-Object -FilePath $logFile -Append
                
                $dirtyFlag = fsutil dirty query $letter
                Log-Output "FSUTIL Output: $dirtyFlag" | Tee-Object -FilePath $logFile -Append

                if ($dirtyFlag -notmatch "NOT Dirty") {
                    Log-Warning "02 - $letter dirty bit set -> running chkdsk /f" | Tee-Object -FilePath $logFile -Append
                    
                    $chkdskResults = chkdsk $letter /f 2>&1 | Where-Object { 
                        $str = $_.ToString()
                        $str -notmatch "Progress:" -and $str -notmatch "Stage:" -and $str -notmatch "Total:"
                    }

                    foreach ($line in $chkdskResults) {
                        if ($line) {
                            Log-Output $line | Tee-Object -FilePath $logFile -Append
                        }
                    }
                }
                else {
                    Log-Info "02 - $letter dirty bit not set -> skipping" | Tee-Object -FilePath $logFile -Append
                }
            }
        }
    }
    Log-Info "All partitions processed successfully." | Tee-Object -FilePath $logFile -Append
}
catch {
    Log-Error "An error occurred: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    $script_final_status = $STATUS_ERROR
}
finally {
    Log-Info "Script ended at $(Get-Date)" | Tee-Object -FilePath $logFile -Append
}

# THE FIX: Return must be outside the try/catch/finally blocks
return $script_final_status
