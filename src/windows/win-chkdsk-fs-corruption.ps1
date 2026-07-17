<#
.SYNOPSIS
    Runs chkdsk to fix file system corruption on an attached rescue disk.
.DESCRIPTION
    This script runs from a rescue VM to check and repair NTFS file system corruption
    on all partitions of the attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions.
    2. For each partition with a drive letter, queries the NTFS dirty bit using fsutil.
    3. If the dirty bit is set, runs chkdsk /f to repair file system errors.
    4. Logs full chkdsk output to the log file; only shows key summary lines
       (result, errors/fixes, disk space) in stdout to avoid log truncation.

    This resolves VMs stuck at boot showing "Scanning and repairing drive" or
    "Checking file system on C:" messages. Running chkdsk from a rescue VM avoids
    interruptions that occur when the OS runs it during boot.
.PARAMETER None
    This script does not accept custom parameters. It processes all attached non-system partitions automatically.
.EXAMPLE
    .\win-chkdsk-fs-corruption.ps1
.NOTES
    Name:    win-chkdsk-fs-corruption.ps1
    Version: 1.2
    Author:  Tony.Mocanu@Microsoft.com
.VERSION
    v1.2: [July 2026] - Refactored logging to support desktop-first paths with SYSTEM fallback.
                       - Aligned dependency path validation and added explicit loop logging summaries.
    v1.1: [May 2026]  - Fixed breaking exception when the Hyper-V module is not installed on the host.
                       - Added explicit checking via Get-Module before executing nested VM discovery.
                       - Included advanced Gen2 unlettered EFI fallback and dynamic drive-letter assignment.
    v1.0: Initial commit.
.LINK
    https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-check-disk-boot-error
#>

[CmdletBinding()]
param()

# ==============================================================================
# 1. DEPENDENCY PATH VALIDATION & INITIALIZATION (DEP-01)
# ==============================================================================
$initPath = Join-Path -Path $PSScriptRoot -ChildPath "src\windows\common\setup\init.ps1"
if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "[Error] Required helper not found: $initPath"
    return 1
}
. $initPath

$partitionsHelperPath = Join-Path -Path $PSScriptRoot -ChildPath "src\windows\common\helpers\Get-Disk-Partitions-v2.ps1"
if (-not (Test-Path -Path $partitionsHelperPath -PathType Leaf)) {
    if (Get-Command Log-Error -ErrorAction SilentlyContinue) {
        Log-Error "Required helper not found: $partitionsHelperPath"
    } else {
        Write-Error "[Error] Required helper not found: $partitionsHelperPath"
    }
    return $STATUS_ERROR
}
. $partitionsHelperPath

# ==============================================================================
# 2. SYSTEM-SAFE LOG CONFIGURATION (LOG-01, DOC-01)
# ==============================================================================
# Attempt to resolve the standard User Desktop first (LOG-01)
$logDir = [Environment]::GetFolderPath('Desktop')

# Secure fallback to system-wide TEMP directories if Desktop is empty/SYSTEM profile (DOC-01)
if ([string]::IsNullOrEmpty($logDir)) {
    $logDir = $env:TEMP
    if ([string]::IsNullOrEmpty($logDir)) {
        $logDir = "C:\Windows\Temp"
    }
}

if (-not (Test-Path -Path $logDir)) { 
    $null = New-Item -ItemType Directory -Path $logDir -Force 
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path -Path $logDir -ChildPath "chkdsk-repair_$timestamp.log"

# Unified logging helper to ensure stdout and physical file are consistently fed
function Write-ScriptLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'OUTPUT')]
        [string]$Level = 'INFO'
    )
    $formattedMsg = "[$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')] [$Level] $Message"
    
    # Direct to correct stream or custom framework logger
    switch ($Level) {
        'ERROR' {
            if (Get-Command Log-Error -ErrorAction SilentlyContinue) { Log-Error $Message } 
            else { Write-Error $formattedMsg }
        }
        'WARNING' {
            if (Get-Command Log-Warning -ErrorAction SilentlyContinue) { Log-Warning $Message } 
            else { Write-Warning $formattedMsg }
        }
        'OUTPUT' {
            if (Get-Command Log-Output -ErrorAction SilentlyContinue) { Log-Output $Message } 
            else { Write-Output $formattedMsg }
        }
        Default {
            if (Get-Command Log-Info -ErrorAction SilentlyContinue) { Log-Info $Message } 
            else { Write-Output $formattedMsg }
        }
    }

    # Write to local physical file
    $formattedMsg | Out-File -FilePath $logFile -Append -Encoding utf8
}

# ==============================================================================
# 3. CORE REPAIR LOGIC
# ==============================================================================
$script_final_status = $STATUS_SUCCESS

try {
    Write-ScriptLog "Script execution started. Logging active at: $logFile" "INFO"

    # Stop nested guest VM if running (Only calls Hyper-V cmdlets after validation - DEP-02)
    $hyperVModuleAvailable = @(Get-Module -ListAvailable -Name 'Hyper-V').Count -gt 0
    if ($hyperVModuleAvailable -and (Get-Command -Name 'Get-VM' -ErrorAction SilentlyContinue)) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine) {
            if ($guestHyperVVirtualMachine.State -eq 'Running') {
                Write-ScriptLog "Stopping nested guest VM: $($guestHyperVVirtualMachine.VMName)" "INFO"
                try {
                    Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                }
                catch {
                    Write-ScriptLog "Failed to stop nested guest VM, continuing but with limited raw write access risks." "WARNING"
                }
            }
        }
    }
    else {
        Write-ScriptLog "Hyper-V module/cmdlets not available on this host -> skipping nested VM discovery" "INFO"
    }

    # --- Partition Enumeration and CHKDSK ---
    $partitionlist = Get-Disk-Partitions
    $rescueDrive = $env:SystemDrive -replace ':', ''

    $processedCount = 0
    $skippedCount   = 0
    $fixedCount     = 0
    $failedCount    = 0

    if ($null -eq $partitionlist -or $partitionlist.Count -eq 0) {
        Write-ScriptLog "No partitions found to check." "WARNING"
    }
    else {
        # Loop through each partition securely (FE-01: Explicit loop naming, no $_ scope pollution)
        foreach ($partition in $partitionlist) {
            if (-not ($partition -and $partition.DriveLetter)) {
                $skippedCount++
                continue
            }

            # Skip the rescue VM's own OS drive explicitly (SAFE-01 Protection)
            if ($partition.DriveLetter -eq $rescueDrive) {
                Write-ScriptLog "Skipping rescue VM system drive $rescueDrive to protect host state." "INFO"
                $skippedCount++
                continue
            }

            $letter = 'unknown'
            try {
                $letter = "$($partition.DriveLetter):"
                $processedCount++

                Write-ScriptLog "Checking drive: $letter" "INFO"

                # Query the NTFS dirty bit using fsutil (LOG-03: Capture and save command outputs)
                $dirtyFlag = fsutil dirty query $letter
                Write-ScriptLog "FSUTIL Output: $dirtyFlag" "OUTPUT"

                # If dirty bit is set, run chkdsk /f to repair file system errors
                if ($dirtyFlag -notmatch "NOT Dirty") {
                    Write-ScriptLog "$letter dirty bit set -> executing chkdsk /f" "WARNING"

                    # Capture raw stdout & stderr from the system command (LOG-02/LOG-03: No Out-Null suppression)
                    $chkdskResults = chkdsk $letter /f 2>&1
                    $chkdskExitCode = $LASTEXITCODE

                    # Check for unfixable corruption (exit code 3)
                    if ($chkdskExitCode -eq 3) {
                        Write-ScriptLog "CHKDSK reported unfixable corruption on $letter (Exit Code: 3). Disk may need hardware level diagnostics." "ERROR"
                        $script_final_status = $STATUS_ERROR
                        $failedCount++
                    }
                    else {
                        $fixedCount++
                    }

                    # Write full raw chkdsk trace straight into the log file (LOG-01 / LOG-03)
                    foreach ($line in $chkdskResults) {
                        $str = $line.ToString()
                        if ($str.Trim()) {
                            $str | Out-File -FilePath $logFile -Append -Encoding utf8
                        }
                    }

                    # Extract crucial structural logs for immediate stdout summary
                    $summaryLines = @()
                    $inSummary = $false
                    foreach ($line in $chkdskResults) {
                        $str = $line.ToString().Trim()
                        if (-not $str) { continue }
                        if ($str -match 'total disk space') { $inSummary = $true }
                        if ($inSummary) {
                            $summaryLines += $str
                            continue
                        }
                        if ($str -match '(no problems|correcting|replacing|deleting|recovering|inserting|truncating|adjusting|resetting|Windows has|No further action|Cleaning up|could not fix|Errors detected|corrupt|found no)') {
                            $summaryLines += $str
                        }
                    }

                    foreach ($sl in $summaryLines) {
                        Write-ScriptLog $sl "OUTPUT"
                    }
                }
                else {
                    Write-ScriptLog "$letter dirty bit not set -> skipping check" "INFO"
                }
            }
            catch {
                # Ensure loop handles individual processing errors without halting execution (ERR-03)
                Write-ScriptLog "Failed processing partition $letter : $($_.Exception.Message)" "ERROR"
                $script_final_status = $STATUS_ERROR
                $failedCount++
            }
        }
    }
    
    # Loop summary logging (FE-02)
    Write-ScriptLog "Partition Summary: Total Processed=$processedCount | Skipped=$skippedCount | Fixed=$fixedCount | Failed=$failedCount" "INFO"
}
catch {
    Write-ScriptLog "An unhandled execution crash occurred: $($_.Exception.Message)" "ERROR"
    $script_final_status = $STATUS_ERROR
}
finally {
    Write-ScriptLog "Script finalized. Destination log package details: $logFile" "INFO"
}

# Ensure the status gets exited safely (ERR-01)
return $script_final_status
