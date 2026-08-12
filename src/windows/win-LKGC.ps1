<#
.SYNOPSIS
    Restores Last Known Good Configuration (LKGC) on attached Windows OS disks by updating
    Select values in each offline SYSTEM registry hive.

.DESCRIPTION
    This script runs from a rescue VM to activate LKGC on an attached faulty OS disk.
    Utilizes direct .NET Registry APIs to prevent handle locking and eliminate 0xc0000225 corruptions.
    It performs the following steps:
    1. Enumerates attached partitions via Get-Disk-Partitions, grouping by DiskNumber to isolate targets.
    2. Creates a safety backup of the target SYSTEM hive before modification.
    3. Opens the Select key using explicit .NET API frameworks to avoid provider caching.
    4. Validates that referenced control sets contain core Control and Services trees.
    5. Selects the existing LastKnownGood control set without inventing control-set numbers.
    6. Unloads the hive safely using a defensive 3x retry loop with explicit garbage collection.

.NOTES
    Name:          win-LKGC.ps1
    Author:        Tony.Mocanu@Microsoft.com
    Last Modified: 2026-08-12
    Version:       1.4
    Requirement:   Azure repair VM with an attached Windows OS disk and the VMRepair common helpers
    DeployMode:    az vm repair run (with --run-on-repair)
    Telemetry:     Emits structured start, success, output, and error events through the VMRepair logger

    Verification:
    1. Check the log file for success:
Get-ChildItem "C:\Users\Public\Desktop\win-LKGC-run-*\win-LKGC-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
    2. Confirm the presence of the terminal confirmation string:
       "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE"
     3. Confirm the log lists the referenced control sets before any write:
         "AVAILABLE CONTROL SETS: ControlSet001, ControlSet002"

     Safety behavior:
    If LastKnownGood references a missing ControlSet00N key, the script returns an error without
    changing the hive. If LastKnownGood equals Current, no alternate LKGC exists and the script
    returns success with no changes. A second valid control set cannot be created safely.

     Recovery after 0xc0000225 referencing \Windows\System32\config\system:
     Attach the OS disk to a repair VM and restore the pre-change SYSTEM.LKGC.bak.<timestamp>
     backup, or load the hive offline and point Current, Default, and LastKnownGood only to an
     existing ControlSet00N key. Always snapshot the OS disk before recovery.

    Version history:
    v1.4: [Aug 2026] - Selects the existing LastKnownGood control set instead of incrementing
                       Select values and treats the absence of an alternate LKGC as a safe no-op.
                       Validates referenced control sets and their core Control and Services trees.
                       Prevents 0xc0000225 from missing or incomplete ControlSet references.
                       Adds logger-compatible JSON telemetry, SYSTEM hive backup, post-write
                       verification, unload retries, and backup rollback after failed writes.
                       Rejects invalid zero or negative boot control-set references before writes
                       and retries stale offline-hive cleanup before loading each SYSTEM hive.
                       Adds SAC-aligned repair-context detection, repair-disk exclusion, unlettered
                       Windows partition discovery, temporary drive assignment, and cleanup.
    v1.3: [Aug 2026] - Added structured VMRepair telemetry for LKGC restoration.
    Update [Jul 2026] - Partition Architecture Alignment: Refactored the core disk processing
                         loop to group by DiskNumber and map drive properties exactly like the
                         validated sac-enabler.ps1 framework.
    v1.2: [May - Jul 2026] - Production Hardening & Handle Updates

.EXAMPLE
    az vm repair run -g <rg> -n <vm> --run-id win-LKGC --run-on-repair
.LINK
    How to start Azure Windows VM with Last Known Good Configuration - Virtual Machines | Microsoft Learn
#>

# Initialization (path-validated - matching local file layout)
$initPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\setup\init.ps1'
$diskPartitionsPath = Join-Path -Path $PSScriptRoot -ChildPath 'common\helpers\Get-Disk-Partitions-v2.ps1'

if (-not (Test-Path -Path $initPath -PathType Leaf)) {
    Write-Error "Missing required dependency: $initPath"
    return 1
}

. $initPath

if (-not (Test-Path -Path $diskPartitionsPath -PathType Leaf)) {
    Log-Error "Missing required dependency: $diskPartitionsPath"
    return $STATUS_ERROR
}

. $diskPartitionsPath

if (-not (Get-Command -Name Get-Disk-Partitions -CommandType Function -ErrorAction SilentlyContinue)) {
    Log-Error "Dependency did not define the required Get-Disk-Partitions function: $diskPartitionsPath"
    return $STATUS_ERROR
}

function Get-LkgcExecutionContext {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$TargetDiskGroups
    )

    if ($TargetDiskGroups.Count -gt 0) {
        return 'REPAIR_VM'
    }

    return 'STANDARD_VM'
}

function Get-LkgcAvailableTempDriveLetter {
    $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter)
    foreach ($letter in @('Z','Y','X','W','V','U','T','S','R','Q')) {
        if ($letter -notin $usedLetters -and -not (Test-Path -Path "${letter}:\")) {
            return $letter
        }
    }

    return $null
}

function Test-LkgcGptType {
    param(
        [AllowNull()]
        [object]$ActualType,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedType
    )

    $actual = ([string]$ActualType).Trim().Trim('{', '}')
    $expected = $ExpectedType.Trim().Trim('{', '}')
    return $actual -eq $expected
}

# Script-level logging: create a plain text desktop log that mirrors Log-* output.
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runOutputDir = Join-Path -Path $env:PUBLIC -ChildPath ("Desktop\\{0}-run-{1}" -f $scriptName, $runTimestamp)
$logFilePath = Join-Path -Path $runOutputDir -ChildPath ("{0}-{1}.log" -f $scriptName, $runTimestamp)

if (-not (Test-Path -Path $runOutputDir -PathType Container)) {
    New-Item -Path $runOutputDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -Path $logFilePath -PathType Leaf)) {
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}

$script:OriginalLogOutput = (Get-Command Log-Output -CommandType Function).ScriptBlock
$script:OriginalLogInfo = (Get-Command Log-Info -CommandType Function).ScriptBlock
$script:OriginalLogWarning = (Get-Command Log-Warning -CommandType Function).ScriptBlock
$script:OriginalLogError = (Get-Command Log-Error -CommandType Function).ScriptBlock
$script:OriginalLogDebug = (Get-Command Log-Debug -CommandType Function).ScriptBlock

function Write-DesktopLogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [PSObject[]]$Message
    )
    try {
        $renderedMessage = ($Message | ForEach-Object { "$_" }) -join ' '
        $line = "[{0} {1}]{2}" -f $Level, (Get-Date), $renderedMessage
        Add-Content -Path $logFilePath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        if ($script:OriginalLogWarning) {
            & $script:OriginalLogWarning -message "Failed to append to desktop log '$logFilePath': $($_.Exception.Message)"
        }
    }
}

function Log-Output {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogOutput -message $message
    Write-DesktopLogLine -Level 'Output' -Message $message
}
function Log-Info { Param([PSObject[]]$message) & $script:OriginalLogInfo -message $message; Write-DesktopLogLine -Level 'Info' -Message $message }
function Log-Warning { Param([PSObject[]]$message) & $script:OriginalLogWarning -message $message; Write-DesktopLogLine -Level 'Warning' -Message $message }
function Log-Error {
    Param([Parameter(Mandatory = $true)][PSObject[]]$message)
    & $script:OriginalLogError -message $message
    Write-DesktopLogLine -Level 'Error' -Message $message
}
function Log-Debug { Param([PSObject[]]$message) & $script:OriginalLogDebug -message $message; Write-DesktopLogLine -Level 'Debug' -Message $message }

$script:RepairScriptVersion = '1.4'
$script:ExecutionStarted = Get-Date

function Write-LkgcTelemetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Operation', 'Success', 'Error')]
        [string]$Event,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [hashtable]$Properties = @{}
    )

    $payload = [ordered]@{
        Event = $Event
        Message = $Message
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RepairScriptVersion = $script:RepairScriptVersion
        Properties = $Properties
    }

    $json = $payload | ConvertTo-Json -Compress -Depth 8
    if ($Event -eq 'Error') {
        Log-Error "[Telemetry] $json" | Out-Null
    }
    else {
        Log-Info "[Telemetry] $json" | Out-Null
    }
}

Log-Info "Starting AUTO LKGC Script. Desktop log: $logFilePath"
Log-Info "[script_start] Script=win-LKGC Version=$($script:RepairScriptVersion)"
Write-LkgcTelemetry -Event Start -Message 'Starting LKGC restoration' -Properties @{
    ScriptName = 'win-LKGC.ps1'
    ScriptVersion = $script:RepairScriptVersion
    ExecutionMode = 'REPAIR_VM_ONLY'
    DesktopLog = $logFilePath
}

# Status Tracking
$script_final_status = $STATUS_ERROR
$lkgcAppliedAny = $false
$processedCount = 0
$skippedCount = 0
$failedCount = 0
$changedCount = 0
$detectedExecutionContext = 'UNDETERMINED'

try {
    # Check if the Hyper-V module is available before performing nested VM checks
    if (Get-Module -ListAvailable -Name Hyper-V) {
        $guestHyperVVirtualMachine = Get-VM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($guestHyperVVirtualMachine -and $guestHyperVVirtualMachine.State -eq 'Running') {
            Log-Info "Stopping nested guest VM $($guestHyperVVirtualMachine.VMName)"
            try { Stop-VM $guestHyperVVirtualMachine -ErrorAction Stop -Force } catch { Log-Warning "Failed to stop nested guest VM" }
        }
    } else {
        Log-Info "Hyper-V PowerShell module is not available on this host. Skipping nested VM validation."
    }

    # Step 1 - Identify the repair VM OS disk and enumerate only secondary disks.
    $repairDrive = $env:SystemDrive -replace ':', ''
    $repairOsPartition = Get-Partition -DriveLetter $repairDrive -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $repairOsPartition -or $null -eq $repairOsPartition.DiskNumber) {
        throw "CRITICAL SAFETY CHECK FAILED: Could not identify the repair VM OS disk from $($env:SystemDrive)."
    }
    $repairDiskNumber = [int]$repairOsPartition.DiskNumber
    Log-Info "Repair VM OS disk identified as Disk $repairDiskNumber."

    $partitionlist = @(Get-Disk-Partitions)
    if ($partitionlist.Count -eq 0) {
        throw 'Get-Disk-Partitions returned no partitions from Azure virtual disks.'
    }

    $targetDiskGroups = @($partitionlist | Group-Object DiskNumber |
        Where-Object { [int]$_.Name -ne $repairDiskNumber })
    $detectedExecutionContext = Get-LkgcExecutionContext -TargetDiskGroups $targetDiskGroups
    Log-Info "Detected execution context: $detectedExecutionContext"
    if ($detectedExecutionContext -ne 'REPAIR_VM') {
        throw 'REPAIR-ONLY SCRIPT: No secondary disk was returned by the partition helper.'
    }

    $fixedDisks = @()

    Log-Info 'Enumerating disk partitions for LKGC analysis...'

    foreach ($partitionGroup in $targetDiskGroups) {
        $processedCount++
        $diskNumber = [int]$partitionGroup.Name
        $targetOSDrive = $null
        $tempOsLetter = $null
        $tempOsDiskNum = $null
        $tempOsPartNum = $null

        try {
            Log-Info "Processing Disk $diskNumber"
            $diskPartitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop)
            $efiGptType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'

            # Scan every currently mounted partition on this target disk.
            foreach ($partition in @($diskPartitions | Where-Object {
                $_.DriveLetter -and $_.DriveLetter -ne [char]0
            })) {
                $drive = [string]$partition.DriveLetter
                if ($drive -eq $repairDrive) { continue }

                $systemCandidate = "${drive}:\Windows\System32\config\SYSTEM"
                $candidateExists = Test-Path -LiteralPath $systemCandidate -PathType Leaf
                Log-Info "Disk ${diskNumber}: checking ${drive}: for SYSTEM hive; exists=$candidateExists"
                if ($candidateExists) {
                    $targetOSDrive = $drive
                    break
                }
            }

            # Match SAC's Gen2-safe fallback by probing unlettered non-EFI partitions.
            if (-not $targetOSDrive) {
                $unletteredOsCandidates = @($diskPartitions | Where-Object {
                    (-not $_.DriveLetter -or $_.DriveLetter -eq [char]0) -and
                    -not (Test-LkgcGptType -ActualType $_.GptType -ExpectedType $efiGptType)
                } | Sort-Object Size -Descending)

                Log-Info "Disk ${diskNumber}: probing $($unletteredOsCandidates.Count) unlettered non-EFI partition(s) for Windows."
                foreach ($osCandidate in $unletteredOsCandidates) {
                    $candidateLetter = Get-LkgcAvailableTempDriveLetter
                    if (-not $candidateLetter) {
                        Log-Warning "Disk ${diskNumber}: no temporary drive letter is available for OS probing."
                        break
                    }

                    $candidatePartNum = [int]$osCandidate.PartitionNumber
                    Log-Info "Disk ${diskNumber}: assigning ${candidateLetter}: to Partition $candidatePartNum for OS probing."
                    $assignOutput = @(
                        "select disk $diskNumber"
                        "select partition $candidatePartNum"
                        "assign letter=$candidateLetter"
                    ) | diskpart 2>&1
                    foreach ($line in @($assignOutput)) {
                        if ($line) { Log-Output "[diskpart][os-assign] $line" | Out-Null }
                    }
                    $tempOsLetter = $candidateLetter
                    $tempOsDiskNum = $diskNumber
                    $tempOsPartNum = $candidatePartNum
                    Start-Sleep -Seconds 2

                    $systemCandidate = "${candidateLetter}:\Windows\System32\config\SYSTEM"
                    $candidateExists = Test-Path -LiteralPath $systemCandidate -PathType Leaf
                    Log-Info "Disk ${diskNumber}: checked temporary ${candidateLetter}: for SYSTEM hive; exists=$candidateExists"
                    if ($candidateExists) {
                        $targetOSDrive = $candidateLetter
                        break
                    }

                    $removeOutput = @(
                        "select disk $diskNumber"
                        "select partition $candidatePartNum"
                        "remove letter=$candidateLetter noerr"
                    ) | diskpart 2>&1
                    foreach ($line in @($removeOutput)) {
                        if ($line) { Log-Output "[diskpart][os-remove] $line" | Out-Null }
                    }
                    $tempOsLetter = $null
                    $tempOsDiskNum = $null
                    $tempOsPartNum = $null
                }
            }

            if (-not $targetOSDrive) {
                Log-Info "Disk $diskNumber skipped: no valid attached OS partition containing \Windows found."
                $skippedCount++
                continue
            }

            Log-Info "Target OS partition successfully matched on letter: $($targetOSDrive):"

        $systemHivePath = "$(${targetOSDrive}):\Windows\System32\config\SYSTEM"
        $systemHiveBackup = "$systemHivePath.LKGC.bak.$runTimestamp"

        try {
            Copy-Item -LiteralPath $systemHivePath -Destination $systemHiveBackup -Force -ErrorAction Stop
            Log-Info "[$targetOSDrive] SYSTEM hive backup created: $systemHiveBackup"
        }
        catch {
            $failedCount++
            Log-Error "[$targetOSDrive] Failed to create SYSTEM hive backup. Skipping disk. Error: $($_.Exception.Message)"
            continue
        }

        # Step 2 - Load the SYSTEM hive from the target disk
        $sysHive = "HKLM\BROKENSYS_$targetOSDrive"
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        for ($preLoadUnloadAttempt = 1; $preLoadUnloadAttempt -le 3; $preLoadUnloadAttempt++) {
            $preLoadUnloadOutput = & reg.exe unload $sysHive 2>&1
            if ($LASTEXITCODE -eq 0) {
                Log-Info "[$targetOSDrive] Removed a stale pre-existing hive mount on attempt $preLoadUnloadAttempt."
                break
            }
            if ($preLoadUnloadAttempt -lt 3) { Start-Sleep -Seconds 2 }
        }
        $sysLoad = & reg.exe load $sysHive $systemHivePath 2>&1

        if ($LASTEXITCODE -ne 0) {
            $failedCount++
            Log-Warning "Failed to load SYSTEM hive from $($targetOSDrive): $($sysLoad -join ' | ') - skipping"
            continue
        }

        Start-Sleep -Seconds 2

        $writeAttempted = $false
        $restoreRequired = $false
        $registryProcessingFailed = $false
        $subKeyPath = "BROKENSYS_$targetOSDrive\Select"
        $regKey = $null
        $systemRootKey = $null

        try {
            # Step 4 - Open via direct .NET API to eliminate PowerShell registry caching engine bugs
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $true)
            if ($null -eq $regKey) { throw "Failed to open Select key via explicit .NET path: HKLM:\$subKeyPath" }

            $requiredSelectValues = @('current', 'default', 'failed', 'LastKnownGood')
            $missingSelectValues = @($requiredSelectValues | Where-Object { $_ -notin $regKey.GetValueNames() })
            if ($missingSelectValues.Count -gt 0) {
                throw "SYSTEM hive Select key is missing required value(s): $($missingSelectValues -join ', ')."
            }

            $currentVal    = [int]$regKey.GetValue('current')
            $defaultVal    = [int]$regKey.GetValue('default')
            $failedVal     = [int]$regKey.GetValue('failed')
            $lastKnownGood = [int]$regKey.GetValue('LastKnownGood')

            $invalidBootReferences = @(@(
                [pscustomobject]@{ Name = 'Current'; Value = $currentVal }
                [pscustomobject]@{ Name = 'Default'; Value = $defaultVal }
                [pscustomobject]@{ Name = 'LastKnownGood'; Value = $lastKnownGood }
            ) | Where-Object { $_.Value -lt 1 })
            if ($invalidBootReferences.Count -gt 0) {
                $invalidValues = @($invalidBootReferences | ForEach-Object { "$($_.Name)=$($_.Value)" })
                throw "SYSTEM hive Select contains invalid boot control-set reference(s): $($invalidValues -join ', '). No changes were attempted."
            }

            $systemRootKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("BROKENSYS_$targetOSDrive", $false)
            if ($null -eq $systemRootKey) {
                throw "Failed to inspect control sets in HKLM:\BROKENSYS_$targetOSDrive."
            }
            $availableControlSets = @($systemRootKey.GetSubKeyNames() | Where-Object { $_ -match '^ControlSet\d{3}$' })
            $availableControlSetNumbers = @($availableControlSets | ForEach-Object { [int]$_.Substring('ControlSet'.Length) })
            Log-Info "[$targetOSDrive] AVAILABLE CONTROL SETS: $($availableControlSets -join ', ')"

            $existingReferences = @(@($currentVal, $defaultVal, $failedVal, $lastKnownGood) |
                Where-Object { $_ -gt 0 } | Sort-Object -Unique)
            $invalidExistingReferences = @($existingReferences | Where-Object { $_ -notin $availableControlSetNumbers })
            if ($invalidExistingReferences.Count -gt 0) {
                $invalidNames = @($invalidExistingReferences | ForEach-Object { 'ControlSet{0:D3}' -f $_ })
                throw "SYSTEM hive Select already references missing control set(s): $($invalidNames -join ', '). No changes were attempted."
            }

            foreach ($controlSetNumber in $existingReferences) {
                $controlSetName = 'ControlSet{0:D3}' -f $controlSetNumber
                foreach ($requiredSubKey in @('Control', 'Services')) {
                    $validationKey = $systemRootKey.OpenSubKey("$controlSetName\$requiredSubKey", $false)
                    if ($null -eq $validationKey) {
                        throw "$controlSetName is incomplete: required $requiredSubKey tree is missing. No changes were attempted."
                    }
                    $validationKey.Dispose()
                }
            }

            $before = [PSCustomObject]@{
                Current       = $currentVal
                Default       = $defaultVal
                Failed        = $failedVal
                LastKnownGood = $lastKnownGood
            }

            Write-LkgcTelemetry -Event Operation -Message "Starting LKGC restoration on drive $targetOSDrive" -Properties @{
                DiskNumber   = "$diskNumber"
                TargetDrive  = "$targetOSDrive"
                SelectBefore = "$($before.Current),$($before.Default),$($before.Failed),$($before.LastKnownGood)"
            }

            Log-Info "[$targetOSDrive] REGISTRY STATE [BEFORE]: Current=$currentVal, Default=$defaultVal, Failed=$failedVal, LKG=$lastKnownGood"

            # Step 4 - Select the control set explicitly identified by LastKnownGood.
            if ($lastKnownGood -eq $currentVal) {
                Log-Warning "[$targetOSDrive] NO ALTERNATE LKGC EXISTS: LastKnownGood and Current both reference ControlSet$('{0:D3}' -f $currentVal)."
                Log-Info "[$targetOSDrive] LKGC_APPLIED=false"
                Write-LkgcTelemetry -Event Success -Message "No alternate LKGC is available on drive $targetOSDrive" -Properties @{
                    DiskNumber  = "$diskNumber"
                    TargetDrive = "$targetOSDrive"
                    Changed     = 'false'
                    Reason      = 'LastKnownGoodEqualsCurrent'
                }
            }
            else {
                # Step 5 - Point boot selection to the existing LastKnownGood control set.
                $plannedCurrent = $lastKnownGood
                $plannedDefault = $lastKnownGood
                $plannedFailed = $currentVal
                $plannedLastKnownGood = $lastKnownGood

                $writeAttempted = $true
                $regKey.SetValue('current', $plannedCurrent, [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('default', $plannedDefault, [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('failed', $plannedFailed, [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.SetValue('LastKnownGood', $plannedLastKnownGood, [Microsoft.Win32.RegistryValueKind]::DWord)

                # Step 6 - Validate downstream configurations
                $afterCurrent = $regKey.GetValue('current')
                $afterDefault = $regKey.GetValue('default')
                $afterFailed  = $regKey.GetValue('failed')
                $afterLKG     = $regKey.GetValue('LastKnownGood')

                if (($afterCurrent -ne $plannedCurrent) -or
                    ($afterDefault -ne $plannedDefault) -or
                    ($afterFailed -ne $plannedFailed) -or
                    ($afterLKG -ne $plannedLastKnownGood)) {
                    throw 'SYSTEM hive Select values did not match the requested LKGC updates.'
                }

                $after = [PSCustomObject]@{
                    Current       = $afterCurrent
                    Default       = $afterDefault
                    Failed        = $afterFailed
                    LastKnownGood = $afterLKG
                }

                Log-Info "[$targetOSDrive] REGISTRY STATE [AFTER]: Current=$afterCurrent, Default=$afterDefault, Failed=$afterFailed, LKG=$afterLKG"

                $telemetryProperties = @{
                    DiskNumber  = "$diskNumber"
                    TargetDrive = "$targetOSDrive"
                    SelectAfter = "$($after.Current),$($after.Default),$($after.Failed),$($after.LastKnownGood)"
                    Changed     = 'true'
                }

                Log-Output -Message "LKGC APPLIED"
                Write-LkgcTelemetry -Event Success -Message "LKGC registry values updated on drive $targetOSDrive" -Properties $telemetryProperties

                $lkgcAppliedAny = $true
                $changedCount++
                Log-Info "[$targetOSDrive] LKGC_APPLIED=true"
            }

            $fixedDisks += $targetOSDrive
        }
        catch {
            $failedCount++
            $registryProcessingFailed = $true
            if ($writeAttempted) { $restoreRequired = $true }
            Log-Error -Message "[$targetOSDrive] Failed to process registry modifications: $($_.Exception.Message)"
            Write-LkgcTelemetry -Event Error -Message 'Failed to process registry modifications' -Properties @{
                DiskNumber    = "$diskNumber"
                TargetDrive   = "$targetOSDrive"
                WriteAttempted = "$writeAttempted"
                Error = $_.Exception.Message
            }
            Log-Info "[$targetOSDrive] LKGC_APPLIED=false"
        }
        finally {
            if ($null -ne $systemRootKey) {
                try { $systemRootKey.Close() } catch {}
                try { $systemRootKey.Dispose() } catch {}
            }
            if ($null -ne $regKey) {
                try {
                    $regKey.Flush()
                }
                catch {
                    if (-not $registryProcessingFailed) {
                        $failedCount++
                        $registryProcessingFailed = $true
                    }
                    $restoreRequired = $true
                    Log-Error "[$targetOSDrive] Failed to flush the SYSTEM hive Select key: $($_.Exception.Message)"
                }
                finally {
                    try { $regKey.Close() } catch {}
                    try { $regKey.Dispose() } catch {}
                }
            }
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2

            # Step 7 - Unload the registry hive using the 3x safety retry array
            $unloaded = $false
            for ($i=1; $i -le 3; $i++) {
                $unloadOutput = & reg.exe unload $sysHive 2>&1
                if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
                Start-Sleep -Seconds 5
            }

            if (-not $unloaded) {
                if (-not $registryProcessingFailed) {
                    $failedCount++
                    $registryProcessingFailed = $true
                }
                $restoreRequired = $true
                Log-Error "Could not unload $sysHive cleanly. The disk will not be reported as successfully processed."
                $fixedDisks = @($fixedDisks | Where-Object { $_ -ne $targetOSDrive })
            }

            if ($restoreRequired) {
                if (-not $unloaded) {
                    Log-Error "[$targetOSDrive] SYSTEM hive backup cannot be restored while $sysHive remains loaded. Manual recovery may be required from $systemHiveBackup."
                }
                else {
                    try {
                        Copy-Item -LiteralPath $systemHiveBackup -Destination $systemHivePath -Force -ErrorAction Stop
                        Log-Warning "[$targetOSDrive] Restored SYSTEM hive backup after the failed write attempt."
                    }
                    catch {
                        Log-Error "[$targetOSDrive] CRITICAL: Failed to restore SYSTEM hive backup '$systemHiveBackup': $($_.Exception.Message)"
                    }
                }
            }
        }
        }
        catch {
            $failedCount++
            Log-Error "Disk $diskNumber failed during OS discovery or LKGC processing: $($_.Exception.Message)"
        }
        finally {
            if ($tempOsLetter) {
                Log-Info "Removing temp letter ${tempOsLetter}: from Disk $tempOsDiskNum Partition $tempOsPartNum"
                $cleanupOutput = @(
                    "select disk $tempOsDiskNum"
                    "select partition $tempOsPartNum"
                    "remove letter=$tempOsLetter noerr"
                ) | diskpart 2>&1
                foreach ($line in @($cleanupOutput)) {
                    if ($line) { Log-Output "[diskpart][os-cleanup] $line" | Out-Null }
                }
            }
        }
    }

    if ($failedCount -gt 0) {
        throw "LKGC processing failed on $failedCount disk(s). Review the preceding disk errors."
    }
    elseif ($fixedDisks.Count -gt 0 -or $changedCount -gt 0) {
        if ($lkgcAppliedAny) {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=TRUE, LKGC APPLIED on drives: $($fixedDisks -join ', ')"
        } else {
            Log-Output "SCRIPT FINISHED PROPERLY, CHANGES_APPLIED=FALSE (NO CHANGES REQUIRED), drives processed: $($fixedDisks -join ', ')"
        }
        $script_final_status = $STATUS_SUCCESS
    }
    else {
        throw "Could not find any rescue OS disk attached containing \Windows structure."
    }
}
catch {
    Log-Error "An unexpected error occurred: $($_.Exception.Message)"
    $script_final_status = $STATUS_ERROR
}
finally {
    $durationSeconds = [math]::Round(((Get-Date) - $script:ExecutionStarted).TotalSeconds, 3)
    $finalTelemetryProperties = @{
        FinalStatus    = "$script_final_status"
        DurationSeconds = $durationSeconds
        DisksProcessed = "$processedCount"
        DisksChanged   = "$changedCount"
        DisksSkipped   = "$skippedCount"
        DisksFailed    = "$failedCount"
    }

    if ($script_final_status -eq $STATUS_SUCCESS) {
        Write-LkgcTelemetry -Event Success -Message 'LKGC restoration script completed successfully' -Properties $finalTelemetryProperties
    }
    else {
        Write-LkgcTelemetry -Event Error -Message 'LKGC restoration script completed with errors' -Properties $finalTelemetryProperties
    }

    Log-Info "[final_status] Status=$script_final_status"
    Log-Info "Summary: processed=$processedCount changed=$changedCount skipped=$skippedCount failed=$failedCount"
    Log-Info "Script ended at $(Get-Date)"
}

return $script_final_status
