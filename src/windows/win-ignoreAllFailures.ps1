<#
.SYNOPSIS
    win-ignoreAllFailures.ps1 (v1.2) - Sets BCD bootstatuspolicy to IgnoreAllFailures to break Automatic Repair loops.

.DESCRIPTION
    This script runs from a rescue VM to modify the BCD store on an attached faulty OS disk.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions to locate the BCD store and OS loader.
    2. Identifies the default boot entry GUID from the BCD bootmgr displayorder.
    3. Logs the BCD configuration before any changes are made.
    4. Sets the default boot entry to the identified GUID.
    5. Sets bootstatuspolicy to IgnoreAllFailures on the default entry.
    6. Logs the BCD configuration after changes for verification.

    This resolves VMs stuck in Automatic Repair loops caused by failed boot, failed shutdown,
    or failed checkpoint errors.

.NOTES
    Name:    win-ignoreAllFailures.ps1
    Version: 1.2
    Author:  Microsoft Azure Compute Support

.VERSION
    v1.2: [May 2026] - Updated the script (current)
                       - Added guarded nested VM handling to prevent Get-VM failures when Hyper-V module is unavailable.
                       - Switched partition discovery from inline CIM enumeration to shared Get-Disk-Partitions-v2 helper.
                       - Added .SYNOPSIS header and aligned metadata versioning/documentation with current script behavior.
    v1.1: [Apr 2026] - Enhanced CIM logic for disk enumeration and partition discovery
    v1.0: Initial commit - Sets BCD boot status policy to IgnoreAllFailures to break Automatic Repair loops
        
.SCENARIO_RECREATION
    To recreate a testable scenario on a rescue VM with an attached OS disk:
    1. Create a test VM in Azure and attach its OS disk to a rescue VM.
    2. Find the attached disk's drive letter and locate the BCD store:
       Gen1: <drive>:\boot\bcd  |  Gen2: <drive>:\efi\microsoft\boot\bcd
    3. Remove or reset the bootstatuspolicy to simulate an Automatic Repair loop (replace <bcdpath> with your actual BCD path):
bcdedit /store <bcdpath> /deletevalue {default} bootstatuspolicy
    4. Verify bootstatuspolicy is absent:
bcdedit /store <bcdpath> /enum {default}
    Expected: No bootstatuspolicy line in the output.
    5. Run the script. It should set bootstatuspolicy to IgnoreAllFailures.
    6. Verify the change:
bcdedit /store <bcdpath> /enum {default}
    Expected: bootstatuspolicy = IgnoreAllFailures.

.EXAMPLE
    # Deploy and run on rescue VM
    az vm repair run -g <resource-group> -n <vm-name> --run-id win-ignoreAllFailures --run-on-repair
    
    # Verify BCD changes
    Get-ChildItem "$env:USERPROFILE\Desktop\ignoreAllFailures_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content

.VERIFICATION
    1. Check the log file for success:
    Get-ChildItem "$env:USERPROFILE\Desktop\ignoreAllFailures_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
       Expected: "BCD AFTER CHANGE" section shows bootstatuspolicy = IgnoreAllFailures, return code 0.
    2. Manually verify the BCD store on the attached disk (replace F with the BCD partition letter):
       bcdedit /store F:\boot\bcd /enum
       or for EFI:
       bcdedit /store F:\efi\microsoft\boot\bcd /enum
       Expected: bootstatuspolicy set to IgnoreAllFailures on the default entry.
#>

# Initialization (no Param() block to avoid ParserErrors on legacy PowerShell engines)
# Validate required dependencies before dot-sourcing
$requiredScripts = @(
    '.\src\windows\common\setup\init.ps1',
    '.\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1'
)
foreach ($script in $requiredScripts) {
    if (-not (Test-Path $script)) {
        Write-Error "Required dependency not found: $script"
        exit 1
    }
}
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v2.ps1

$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath) -or -not (Test-Path $desktopPath)) {
    $desktopPath = Join-Path $env:USERPROFILE 'Desktop'
}
if (-not (Test-Path $desktopPath)) {
    $desktopPath = 'C:\Windows\Temp'
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $desktopPath "ignoreAllFailures_$timestamp.log"
if (-not (Test-Path $logFile)) { $null = New-Item -ItemType File -Path $logFile -Force }

$successReport = New-Object System.Collections.Generic.List[string]
$script_final_status = $STATUS_ERROR
$assignedEfiLetters = @()  # Track EFI partition drive letters for cleanup
$processedDisks = 0
$skippedDisks = 0
$failedDisks = 0
$changedDisks = 0

function Get-FormattedOutput {
    param([string]$text)
    $time = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
    return "[Output $time]$text"
}

function Write-ScriptLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    switch ($Level) {
        'Info' { Log-Info $Message }
        'Warning' { Log-Warning $Message }
        'Error' { Log-Error $Message }
    }

    Add-Content -Path $logFile -Value (Get-FormattedOutput $Message)
}

function Add-CommandOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Header,
        [Parameter(Mandatory = $true)]
        [object[]]$Output
    )

    $successReport.Add((Get-FormattedOutput $Header))
    foreach ($line in $Output) {
        if ($null -ne $line -and -not [string]::IsNullOrWhiteSpace([string]$line)) {
            $successReport.Add((Get-FormattedOutput ([string]$line)))
        }
    }
}

function Get-NextFreeDriveLetter {
    $usedLetters = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    $letters = 90..69 | ForEach-Object { [char]$_ } 
    foreach ($letter in $letters) {
        if ($letter -notin $usedLetters) { return $letter }
    }
}

try {
    Write-ScriptLog -Message "Starting IgnoreAllFailures script..."
    Write-ScriptLog -Message "Desktop log file: $logFile"

    # Stop nested guest VM if running
    # Guard Get-VM if Hyper-V module is not available
    try {
        if (Get-Module -ListAvailable -Name Hyper-V) {
            $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($guestHyperVVirtualMachine) {
                if ($guestHyperVVirtualMachine.State -eq 'Running') {
                    Write-ScriptLog -Message "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
                    try {
                        Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force
                    }
                    catch {
                        Write-ScriptLog -Level Warning -Message "Failed to stop nested guest VM, will continue but may have limited success"
                    }
                }
            }
        } else {
            Write-ScriptLog -Message "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
        }
    }
    catch {
        Write-ScriptLog -Level Warning -Message "Nested VM check encountered an error but will be skipped: $($_.Exception.Message)"
    }
    
    $partitionlist = Get-Disk-Partitions

    $rescueDrive = $env:SystemDrive -replace ':', ''
    Write-ScriptLog -Message "Starting deep scan for BCD files..."

    forEach ($diskGroup in $partitionlist | Group-Object DiskNumber) {
        $processedDisks++
        if ($diskGroup.Group.DriveLetter -contains $rescueDrive) {
            $skippedDisks++
            Write-ScriptLog -Message "Skipping rescue host disk $($diskGroup.Name)"
            continue
        }
        
        $currentDiskBcdPath = $null
        $currentDiskOsFound = $false
        
        # EFI Mounter Logic
        # Filter for hidden partitions: check for null/empty DriveLetter or DriveLetter -eq 0
        $hiddenPartitions = Get-Partition -DiskNumber $diskGroup.Name | Where-Object { (-not $_.DriveLetter) -and ($_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -or $_.Type -eq "System") }
        foreach ($part in $hiddenPartitions) {
            $newLetter = Get-NextFreeDriveLetter
            Write-ScriptLog -Message "Mounting hidden EFI partition on Disk $($diskGroup.Name) to $newLetter`:"
            $part | Set-Partition -NewDriveLetter $newLetter -ErrorAction SilentlyContinue
            # Track assigned letter for cleanup in finally block
            $assignedEfiLetters += @{ Letter = $newLetter; DiskNumber = $diskGroup.Name; Partition = $part }
            Start-Sleep -Seconds 2
        }

        $currentDrives = Get-Partition -DiskNumber $diskGroup.Name | Where-Object { $_.DriveLetter -ne 0 } | Select-Object -ExpandProperty DriveLetter
        foreach ($drive in $currentDrives) {
            $driveStr = "$($drive):"
            if ($null -eq $currentDiskBcdPath) {
                if (Test-Path "$driveStr\boot\bcd") { $currentDiskBcdPath = "$driveStr\boot\bcd" }
                elseif (Test-Path "$driveStr\efi\microsoft\boot\bcd") { $currentDiskBcdPath = "$driveStr\efi\microsoft\boot\bcd" }
            }
            if ($currentDiskOsFound -eq $false) {
                if (Test-Path "$driveStr\windows\system32\winload.exe") { $currentDiskOsFound = $true }
                elseif (Test-Path "$driveStr\windows\system32\winload.efi") { $currentDiskOsFound = $true }
            }
        }

        if ($currentDiskBcdPath -and $currentDiskOsFound) {
            Write-ScriptLog -Message "Disk $($diskGroup.Name): candidate BCD store found at $currentDiskBcdPath"
            $bcdout = bcdedit /store $currentDiskBcdPath /enum bootmgr /v 2>&1
            Add-CommandOutput -Header "--- BCD BOOTMGR OUTPUT (Disk $($diskGroup.Name)) ---" -Output $bcdout

            if ($LASTEXITCODE -ne 0) {
                $failedDisks++
                Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to query bootmgr from BCD store at $currentDiskBcdPath (exit code $LASTEXITCODE)"
                continue
            }

            $defaultLine = $bcdout | Select-String 'displayorder' | Select-Object -First 1
            
            if ($defaultLine -and ($defaultLine -match '\{([^}]+)\}')) {
                $defaultId = $matches[0]
                
                $beforeRaw = bcdedit /store $currentDiskBcdPath /enum $defaultId 2>&1
                Add-CommandOutput -Header "--- BCD BEFORE CHANGE (Disk $($diskGroup.Name)) ---" -Output $beforeRaw
                if ($LASTEXITCODE -ne 0) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to read BCD entry $defaultId before change (exit code $LASTEXITCODE)"
                    continue
                }
                
                $setDefaultOutput = bcdedit /store $currentDiskBcdPath /default $defaultId 2>&1
                Add-CommandOutput -Header "--- BCD SET DEFAULT OUTPUT (Disk $($diskGroup.Name)) ---" -Output $setDefaultOutput
                if ($LASTEXITCODE -ne 0) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to set default entry to $defaultId (exit code $LASTEXITCODE)"
                    continue
                }

                $setPolicyOutput = bcdedit /store $currentDiskBcdPath /set $defaultId bootstatuspolicy IgnoreAllFailures 2>&1
                Add-CommandOutput -Header "--- BCD SET BOOTSTATUSPOLICY OUTPUT (Disk $($diskGroup.Name)) ---" -Output $setPolicyOutput
                if ($LASTEXITCODE -ne 0) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to set bootstatuspolicy IgnoreAllFailures on $defaultId (exit code $LASTEXITCODE)"
                    continue
                }
                
                $afterRaw = bcdedit /store $currentDiskBcdPath /enum $defaultId 2>&1
                Add-CommandOutput -Header "--- BCD AFTER CHANGE (Disk $($diskGroup.Name)) ---" -Output $afterRaw
                if ($LASTEXITCODE -ne 0) {
                    $failedDisks++
                    Write-ScriptLog -Level Error -Message "Disk $($diskGroup.Name): failed to read BCD entry $defaultId after change (exit code $LASTEXITCODE)"
                    continue
                }
                
                $changedDisks++
                $script_final_status = $STATUS_SUCCESS
                Write-ScriptLog -Message "Disk $($diskGroup.Name): successfully set bootstatuspolicy IgnoreAllFailures for default entry $defaultId"
            }
            else {
                $failedDisks++
                Write-ScriptLog -Level Warning -Message "Disk $($diskGroup.Name): unable to identify default boot entry from displayorder"
            }
        }
        else {
            $skippedDisks++
            Write-ScriptLog -Message "Disk $($diskGroup.Name): skipped because BCD store or OS loader was not found"
        }
    }
}
catch {
    Write-ScriptLog -Level Error -Message "An error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    # Cleanup: Remove temporarily assigned EFI drive letters to avoid leaving orphaned mounts on rescue host
    if ($assignedEfiLetters.Count -gt 0) {
        Write-ScriptLog -Message "Cleaning up temporarily assigned EFI partition drive letters..."
        foreach ($efiMount in $assignedEfiLetters) {
            try {
                Write-ScriptLog -Message "Removing drive letter $($efiMount.Letter): from EFI partition (Disk $($efiMount.DiskNumber))"
                $efiMount.Partition | Set-Partition -NewDriveLetter $null -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            catch {
                Write-ScriptLog -Level Warning -Message "Failed to remove drive letter $($efiMount.Letter): from EFI partition, but continuing cleanup: $($_.Exception.Message)"
            }
        }
    }
    
    # Final logging of report via Log-Info (NOT Write-Output)
    if ($successReport.Count -gt 0) {
        foreach ($reportLine in $successReport) {
            Write-ScriptLog -Message $reportLine
        }
    }

    if ($changedDisks -eq 0) {
        $script_final_status = $STATUS_ERROR
    }

    Write-ScriptLog -Message "Summary: processed=$processedDisks, skipped=$skippedDisks, failed=$failedDisks, changed=$changedDisks"
    Write-ScriptLog -Message "Script completed with status: $script_final_status"
    Write-ScriptLog -Message "Desktop log file: $logFile"
}

# Proper return for Azure Telemetry
return $script_final_status
