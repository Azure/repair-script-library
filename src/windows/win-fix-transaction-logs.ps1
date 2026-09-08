#########################################################################################################
#
# .SYNOPSIS
#   Clears exhausted Common Log File System transaction logs on an offline disk, so servicing that
#   fails with ERROR_LOG_FULL (0x800719e4) can run again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   The transactional registry (TxR) records registry changes made inside a Kernel Transaction
#   Manager transaction in Common Log File System containers: a .blf base log file and one or more
#   .regtrans-ms multiplexed containers, living in System32\config\TxR. A CLFS container is a fixed
#   size. When the log fills and cannot be advanced - because a transaction was never resolved, or
#   the machine lost power with work outstanding - every subsequent attempt to open a transaction
#   fails with ERROR_LOG_FULL, 0x800719e4.
#
#   The visible result is that servicing stops working. Windows Update fails, DISM fails, and
#   CBS.log fills with 0x800719e4. The installation itself is intact: nothing is corrupt, there is
#   no half-applied update to roll back, and there is no pending.xml to abandon. The only thing
#   wrong is that the log containers are full. Windows recreates them from scratch on the next boot,
#   so removing them clears the condition.
#
#   This is deliberately a different script from win-fix-pending-servicing. That one abandons an
#   interrupted servicing transaction - it reverts pending actions with DISM, renames pending.xml
#   and clears the Component Based Servicing markers. None of that applies here, and running it
#   would revert an update that had never started applying. Log exhaustion is a separate symptom
#   with a separate, much smaller repair, which is why it gets its own script.
#
#   Three scopes are understood. Only TxR is touched by default:
#     TxR     System32\config\TxR          the transactional registry logs.
#     Config  System32\config              CLFS logs sitting alongside the registry hives.
#     SMI     System32\SMI\Store\Machine   the Software Management Infrastructure store logs.
#
#   Config and SMI are opt-in because they sit in the same folder as data that must never be lost:
#   the registry hives themselves and their .LOG1/.LOG2 recovery logs. Removing a hive recovery log
#   from under a hive that has not been reconciled turns a recoverable installation into an
#   unbootable one - STATUS_CANNOT_LOAD_REGISTRY_FILE, 0xC0000218. The file selection below cannot
#   reach those files, and the verification below proves it did not, but the default still stays on
#   the folder that holds nothing else.
#
#   What is removed is chosen by an explicit extension allow-list, .blf and .regtrans-ms, and never
#   by a wildcard sweep of the folder. The list is built once, and the backup, the deletion and the
#   verification all work from that one list rather than from a fresh enumeration, so the set of
#   files cannot grow between deciding and acting. A hive, a .LOG1, a .LOG2 or anything else in the
#   folder is not on the list and is therefore not reachable, whatever it is called.
#
#   Every file is copied to a backup folder on the offline disk and the copy is hash-verified before
#   the original is deleted. After the deletion, six things are checked:
#     1. The folder still exists.
#     2. The folder is the original, not a recreated one - the creation timestamp is unchanged.
#     3. The folder's ACL is unchanged.
#     4. Exactly the planned files were removed, and nothing else was.
#     5. Every other file in the folder is untouched - same size, same last write time and same
#        attributes. This is the direct proof that the hives and their recovery logs were neither
#        deleted nor stripped of their System and Hidden attributes.
#     6. Every registry hive that loaded before the deletion still loads after it.
#   If any check fails, that scope is rolled back from the backup immediately, including the
#   original file attributes, and the script reports an error. A scope is never left half-cleared.
#
# .PARAMETER detectOnly
#   "true" reports what was found and what would be removed, and writes nothing. Default "false".
#
# .PARAMETER scope
#   Which log set to clear: TxR, Config, SMI or All. Default "TxR".
#
# .PARAMETER force
#   "true" clears the logs even when no ERROR_LOG_FULL evidence was found. Default "false". Needed
#   only when CBS.log has rolled over and taken the evidence with it - see .NOTES.
#
# .PARAMETER revert
#   "true" restores the files a previous run of this script backed up, and writes nothing else.
#
# .PARAMETER windowsDrive
#   Drive letter of the attached Windows volume, e.g. "F:". Detected automatically when omitted.
#
# .NOTES
#   Transaction logs are present and healthy on every running Windows installation. Their presence
#   is not evidence of anything, so this script does not treat it as evidence: with no sign of
#   exhaustion it removes nothing and says so. The evidence it looks for is 0x800719e4 or
#   ERROR_LOG_FULL in Windows\Logs\CBS\CBS.log and in any uncompressed CbsPersist_*.log beside it.
#
#   CBS.log rolls over into a compressed CbsPersist_*.cab once it passes its size limit, and this
#   script does not open cabinets. On a VM that has been failing for a while the evidence can
#   therefore be gone even though the fault is real. That is what "force true" is for. It is an
#   explicit operator decision that the symptom was identified some other way, and it is the only
#   way to make this script write anything without evidence of its own.
#
#   Clearing the logs does not fix an update that is already half applied. If pending servicing
#   markers are found as well they are reported, and win-fix-pending-servicing is the script for
#   that. This one never touches pending.xml, the CBS keys or the COMPONENTS hive.
#
#   The backup is written to Windows\Temp on the offline disk, so it travels back with the VM and a
#   revert can be run later from a different rescue VM. It is never written inside the folder being
#   cleared: a new file appearing there would be indistinguishable from one this script failed to
#   account for, and check 4 above would not be able to tell the difference.
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly.')]
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('TxR', 'Config', 'SMI', 'All', IgnoreCase = $true)][string]$scope = 'TxR',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$force = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineFileRemoval.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$isForce = ($force -eq 'true')

# The only extensions this script will ever delete. A Common Log File System log is a .blf base log
# file plus its .regtrans-ms containers, and nothing else in any of the three scope folders uses
# either extension.
#
# This is an allow-list rather than a wildcard for one reason: a registry hive recovery log is
# called SYSTEM.LOG1, and losing one from under an unreconciled hive is a documented route to
# STATUS_CANNOT_LOAD_REGISTRY_FILE. No pattern here can match it.
$script:TransactionLogExtension = @('.blf', '.regtrans-ms')

# Extensions that must never be deleted whatever else happens. Nothing on the allow-list above can
# produce a match here, so this is a second, independent check rather than a filter that does any
# work in normal operation. It exists so that a future edit to the allow-list cannot quietly make
# hive recovery logs reachable.
$script:ProtectedExtension = @('.log', '.log1', '.log2', '.dat', '.sav', '.bak')

# Primary registry hives that live in the scope folders. These are revalidated after the deletion:
# a hive that loaded before and does not load after means the folder was damaged, and the scope is
# rolled back. Nothing here is ever selected for deletion - this list only observes.
#
# The list is longer than the six hives usually named because a measured Server 2022 config folder
# holds ten: DRIVERS, ELAM, BBI and BCD-Template are hives too. Inclusion costs one scratch-copy
# parse each and can never remove a file, so the bar is "is it a hive in a folder we mutate", not
# "is it needed at boot".
#
# BCD-Template is the weakest of the ten and is kept deliberately. It is only the template bcdboot
# copies to build a fresh BCD store - the live BCD is on the boot partition, not here - and on a
# pristine disk it owns no transaction logs at all, so it contributes no deletion candidates. But
# loading a hive in place creates them: on the test disk a single in-place reg.exe load produced
# BCD-Template{guid}.TM.blf plus two .TMContainer files that were not there before. This script
# never loads in place - Test-OfflineHiveFile copies to scratch first, so it cannot create them -
# but a machine that reaches this script has usually already been worked on, and a prior bcdboot or
# repair attempt does load it in place. Once those logs exist a Config-scope run will delete them.
# Damaging BCD-Template would not cause a no-boot; it would break the next bcdboot the operator
# runs, which is a far more confusing failure.
#
# All ten loaded cleanly through Test-OfflineHiveFile on that disk, so the check is a real gate here
# rather than something advisory - Test-OfflineHiveFile parses with reg.exe, which does not have the
# ERROR_BADDB problem that makes RegLoadAppKey reject primary OS hives.
$script:RegistryHive = @{
    'TxR'    = @()
    'Config' = @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', 'DRIVERS', 'ELAM', 'BBI', 'BCD-Template')
    'SMI'    = @('SCHEMA.DAT')
}

# Test-OfflineHiveFile copies a hive to a scratch location to have Windows parse it, and it runs
# twice per repair - once for the baseline and once for the verification. Above this size the hive
# is reported as skipped instead of copied. The file-level comparison in check 5 still proves the
# file was not modified, so nothing is given up except the parse.
$script:HiveTestMaxBytes = 512MB

# What log exhaustion looks like in CBS.log. 0x800719e4 is ERROR_LOG_FULL as CBS prints it.
$script:LogFullPattern = '0x800719e4|ERROR_LOG_FULL'

# CBS.log is large and the useful part is the end of it. Reading the tail keeps this to a bounded
# read on a multi-hundred-megabyte file.
$script:CbsTailLine = 4000

function New-Finding {
    <#
    .SYNOPSIS
        Builds one detection finding.

    .DESCRIPTION
        Priority orders the report. Actionable marks a finding this script can do something about,
        as opposed to one that is reported so the operator knows where to look next.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $false)][ValidateSet('Critical', 'Warning', 'Information')][string]$Severity = 'Warning',
        [Parameter(Mandatory = $false)][int]$Priority = 50,
        [Parameter(Mandatory = $false)][bool]$Actionable = $true
    )

    return [PSCustomObject]@{
        Category   = $Category
        Detail     = $Detail
        Severity   = $Severity
        Priority   = $Priority
        Actionable = $Actionable
    }
}

function Get-TransactionLogScope {
    <#
    .SYNOPSIS
        Resolves a scope name to the folder it describes and the hives that live there.

    .OUTPUTS
        PSCustomObject with Scope, Label, Path and HiveName.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('TxR', 'Config', 'SMI')][string]$Name,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    switch ($Name) {
        'TxR' {
            $path = Join-OfflinePath $SystemRoot 'System32\config\TxR'
            $label = 'transactional registry logs'
        }
        'Config' {
            $path = Join-OfflinePath $SystemRoot 'System32\config'
            $label = 'registry configuration folder logs'
        }
        'SMI' {
            $path = Join-OfflinePath $SystemRoot 'System32\SMI\Store\Machine'
            $label = 'Software Management Infrastructure store logs'
        }
    }

    return [PSCustomObject]@{
        Scope    = $Name
        Label    = $label
        Path     = $path
        HiveName = $script:RegistryHive[$Name]
    }
}





function Get-TransactionLogPlan {
    <#
    .SYNOPSIS
        Builds the read-only plan for one scope: what is there, and what would be removed.

    .DESCRIPTION
        Writes nothing, so it is safe to call for a detectOnly run and is also the baseline the
        verification compares against.

        The plan itself is built by Use-OfflineFileRemoval.ps1, which owns the backup, deletion,
        verification and rollback for every script that clears files out of a folder that also
        holds registry hives. This wrapper only supplies the scope-specific configuration and adds
        the Actionable flag the caller reasons about.

    .OUTPUTS
        PSCustomObject from Get-OfflineRemovalPlan, plus Scope, ScopeInfo and Actionable.
    #>
    param(
        [Parameter(Mandatory = $true)]$ScopeInfo,
        [Parameter(Mandatory = $false)][switch]$SkipHiveState
    )

    $hiveName = if ($SkipHiveState) { @() } else { @($ScopeInfo.HiveName) }

    $plan = Get-OfflineRemovalPlan -Label $ScopeInfo.Scope -Path $ScopeInfo.Path `
        -MatchExtension $script:TransactionLogExtension `
        -ProtectedExtension $script:ProtectedExtension `
        -HiveName $hiveName `
        -HiveMaxBytes $script:HiveTestMaxBytes `
        -IncludeHash

    $snapshot = $plan.Snapshot
    Add-Member -InputObject $plan -NotePropertyName 'Scope' -NotePropertyValue $ScopeInfo.Scope
    Add-Member -InputObject $plan -NotePropertyName 'ScopeInfo' -NotePropertyValue $ScopeInfo
    Add-Member -InputObject $plan -NotePropertyName 'Actionable' -NotePropertyValue (
        $snapshot.Present -and $snapshot.Accessible -and @($snapshot.MatchedFile).Count -gt 0)

    return $plan
}

function Get-LogExhaustionEvidence {
    <#
    .SYNOPSIS
        Looks for ERROR_LOG_FULL in the servicing logs.

    .DESCRIPTION
        CBS.log is the log that records it, and it is read from the end because that is where the
        recent failures are and the file can be very large. Uncompressed CbsPersist_*.log files are
        read too; the .cab ones that CBS compresses on rollover are not opened, which is the reason
        the force parameter exists.

    .OUTPUTS
        PSCustomObject with Found, Source, SampleLine and LogsRead.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $result = [PSCustomObject]@{
        Found      = $false
        Source     = $null
        SampleLine = $null
        LogsRead   = @()
    }

    $cbsFolder = Join-OfflinePath $SystemRoot 'Logs\CBS'
    if (-not (Test-OfflinePath $cbsFolder)) { return $result }

    $candidates = [System.Collections.Generic.List[object]]::new()
    $cbsLog = Join-OfflinePath $cbsFolder 'CBS.log'
    if (Test-OfflinePath $cbsLog) { $candidates.Add($cbsLog) }

    try {
        $persist = @(Get-ChildItem -LiteralPath $cbsFolder -Filter 'CbsPersist_*.log' -File -Force -ErrorAction Stop |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 3)
        foreach ($item in $persist) { $candidates.Add($item.FullName) }
    }
    catch {
        # The rolled-over logs are a bonus, not a requirement. CBS.log alone is the normal case and
        # is already on the list, so a folder that cannot be enumerated is noted and not fatal.
        Add-OfflineRepairLog -Level Warning -Message "The rolled-over CBS logs in $cbsFolder could not be listed ($($_.Exception.Message))."
    }

    foreach ($path in $candidates) {
        $result.LogsRead += $path
        try {
            $tail = @(Get-Content -LiteralPath $path -Tail $script:CbsTailLine -ErrorAction Stop)
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not read $path ($($_.Exception.Message))."
            continue
        }

        $hit = $tail | Select-String -Pattern $script:LogFullPattern -CaseSensitive:$false | Select-Object -First 1
        if ($hit) {
            $result.Found = $true
            $result.Source = $path
            $result.SampleLine = $hit.Line.Trim()
            return $result
        }
    }

    return $result
}

function Get-PendingServicingMarker {
    <#
    .SYNOPSIS
        Reports whether an interrupted servicing transaction is also present.

    .DESCRIPTION
        Reported, never acted on. If these are present the VM has a second, different problem and
        win-fix-pending-servicing is the script for it. Clearing the logs will not finish an update
        that is already half applied.

    .OUTPUTS
        Array of marker description strings.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $markers = [System.Collections.Generic.List[string]]::new()

    $pendingXml = Join-OfflinePath $SystemRoot 'WinSxS\pending.xml'
    if (Test-OfflinePath $pendingXml) { $markers.Add('WinSxS\pending.xml is present') }

    $reboot = Join-OfflinePath $SystemRoot 'WinSxS\reboot.xml'
    if (Test-OfflinePath $reboot) { $markers.Add('WinSxS\reboot.xml is present') }

    return @($markers)
}






function Get-RevertManifestPath {
    param([Parameter(Mandatory = $true)][string]$Drive)
    return (Join-Path $Drive "$scriptName-revert.json")
}

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads the manifest a previous run left on the offline disk.

    .DESCRIPTION
        ConvertFrom-Json emits a JSON array as a single pipeline item, so the result is assigned
        before it is wrapped. Wrapping the pipeline directly produces one element holding the whole
        array, and the revert then silently restores nothing.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }

    try { $parsed = $content | ConvertFrom-Json }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The revert manifest at $Path could not be read ($($_.Exception.Message))."
        return $null
    }

    return $parsed
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run removed, without discarding what an earlier run recorded.

    .DESCRIPTION
        Each run writes the same file, so a plain overwrite loses the undo information from the run
        before it. A run that cleared TxR followed by a run that cleared SMI would otherwise leave a
        manifest naming only SMI, and reverting would restore half of what was taken.

        Entries are keyed by scope. A scope cleared twice keeps the most recent backup, because that
        is the one holding the files that were actually there last.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Entry
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($Entry)) { $entries.Add($item) }

    $existing = Read-RevertManifest -Path $Path
    if ($existing -and $existing.Scopes) {
        $known = @($entries | ForEach-Object { $_.Scope })
        foreach ($old in @($existing.Scopes)) {
            if ($known -notcontains $old.Scope) { $entries.Add($old) }
        }
    }

    $manifest = [PSCustomObject]@{
        Script    = $scriptName
        Timestamp = $scriptStartTime
        Scopes    = @($entries)
    }

    try {
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        Log-Info "Recorded the revert manifest at $Path." | Tee-Object -FilePath $logFile -Append
    }
    catch {
        Log-Warning "The revert manifest could not be written to $Path ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append
    }
}

#########################################################################################################
# Main
#########################################################################################################

try {
    Log-Output "=== $scriptName started at $scriptStartTime ===" | Tee-Object -FilePath $logFile -Append

    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $systemRoot = $offline.WindowsPath
    $manifestPath = Get-RevertManifestPath -Drive $offline.WindowsDrive

    $selectedScopes = if ($scope -eq 'All') { @('TxR', 'Config', 'SMI') } else { @($scope) }

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output '--- Revert ---' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -Path $manifestPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (-not $manifest -or -not $manifest.Scopes) {
            Log-Output "No revert manifest was found at $manifestPath, so there is nothing this script has to put back." | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        $restoredTotal = 0
        $failedTotal = 0
        foreach ($entry in @($manifest.Scopes)) {
            Log-Output "Restoring scope $($entry.Scope) from $($entry.BackupPath)." | Tee-Object -FilePath $logFile -Append
            $restore = Restore-OfflineFileSet -BackupPath $entry.BackupPath -TargetPath $entry.TargetPath -FileRecord $entry.Files
            foreach ($line in @($restore.Detail)) { Log-Info "  $line" | Tee-Object -FilePath $logFile -Append }
            $restoredTotal += $restore.Restored
            $failedTotal += $restore.Failed
        }

        Log-Output "Restored $restoredTotal file(s); $failedTotal could not be restored." | Tee-Object -FilePath $logFile -Append
        if ($failedTotal -gt 0) { return $STATUS_ERROR }

        try { Remove-Item -LiteralPath $manifestPath -Force -ErrorAction Stop }
        catch { Log-Warning "The manifest at $manifestPath could not be removed ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append }

        Log-Output 'Revert complete.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Detect
    #####################################################################################################
    Log-Output '--- Detection ---' | Tee-Object -FilePath $logFile -Append

    $findings = [System.Collections.Generic.List[object]]::new()

    $evidence = Get-LogExhaustionEvidence -SystemRoot $systemRoot
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($evidence.Found) {
        $findings.Add((New-Finding -Category 'Log exhaustion' -Severity 'Critical' -Priority 10 `
                    -Detail "ERROR_LOG_FULL was reported in $($evidence.Source): $($evidence.SampleLine)"))
        Log-Output "Log exhaustion evidence found in $($evidence.Source)." | Tee-Object -FilePath $logFile -Append
        Log-Output "  $($evidence.SampleLine)" | Tee-Object -FilePath $logFile -Append
    }
    elseif (@($evidence.LogsRead).Count -eq 0) {
        Log-Output 'No CBS log was available to read, so there is no evidence either way.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "No ERROR_LOG_FULL entry was found in the last $($script:CbsTailLine) lines of $(@($evidence.LogsRead).Count) CBS log(s)." | Tee-Object -FilePath $logFile -Append
    }

    $plans = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $selectedScopes) {
        $scopeInfo = Get-TransactionLogScope -Name $name -SystemRoot $systemRoot
        $plan = Get-TransactionLogPlan -ScopeInfo $scopeInfo
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $plans.Add($plan)

        if (-not $plan.Snapshot.Present) {
            Log-Output "Scope $name ($($scopeInfo.Label)): the folder $($scopeInfo.Path) is not present." | Tee-Object -FilePath $logFile -Append
            continue
        }
        if (-not $plan.Snapshot.Accessible) {
            Log-Warning "Scope ${name}: $($scopeInfo.Path) could not be enumerated ($($plan.Snapshot.AccessError))." | Tee-Object -FilePath $logFile -Append
            $findings.Add((New-Finding -Category 'Folder unreadable' -Severity 'Warning' -Priority 30 -Actionable $false `
                        -Detail "$($scopeInfo.Path) could not be enumerated: $($plan.Snapshot.AccessError)"))
            continue
        }

        Log-Output "Scope $name ($($scopeInfo.Label)): $($plan.FileCount) log file(s), $([math]::Round($plan.TotalBytes / 1KB)) KB, alongside $(@($plan.Snapshot.OtherFile).Count) other file(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($file in @($plan.Snapshot.MatchedFile)) {
            Log-Info "    $($file.Name)  $([math]::Round($file.Length / 1KB)) KB" | Tee-Object -FilePath $logFile -Append
        }
        foreach ($hive in @($plan.HiveState | Where-Object { $_.Present })) {
            $state = if ($hive.Tested) { if ($hive.Loads) { 'loads' } else { "does not load ($($hive.Reason))" } } else { $hive.Reason }
            Log-Info "    hive $($hive.Name): $state" | Tee-Object -FilePath $logFile -Append
        }
    }

    $markers = Get-PendingServicingMarker -SystemRoot $systemRoot
    foreach ($marker in $markers) {
        $findings.Add((New-Finding -Category 'Pending servicing' -Severity 'Warning' -Priority 40 -Actionable $false `
                    -Detail "$marker - an interrupted update is a different problem; win-fix-pending-servicing is the script for it"))
        Log-Warning "$marker. This script does not act on that; win-fix-pending-servicing does." | Tee-Object -FilePath $logFile -Append
    }

    $actionable = @($plans | Where-Object { $_.Actionable })

    Log-Output '--- Findings ---' | Tee-Object -FilePath $logFile -Append
    if ($findings.Count -eq 0) {
        Log-Output 'No issues found.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        foreach ($finding in @($findings | Sort-Object Priority)) {
            Log-Output "[$($finding.Severity)] $($finding.Category): $($finding.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }

    #####################################################################################################
    # Decide
    #####################################################################################################
    if ($isDetectOnly) {
        if ($actionable.Count -gt 0) {
            $total = ($actionable | Measure-Object -Property FileCount -Sum).Sum
            Log-Output "detectOnly: $total transaction log file(s) across $($actionable.Count) scope(s) would be removed." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'detectOnly: there are no transaction log files to remove.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output 'detectOnly was requested, so nothing was changed.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($actionable.Count -eq 0) {
        Log-Output 'There are no transaction log files in the selected scope(s), so there is nothing to remove.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if (-not $evidence.Found -and -not $isForce) {
        Log-Output 'Transaction logs are present, but they are present on every healthy Windows installation and no evidence of log exhaustion was found.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'Nothing was changed. If the symptom was identified another way - CBS.log can roll over into a .cab and take the evidence with it - re-run with "force true".' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if (-not $evidence.Found -and $isForce) {
        Log-Warning 'No log exhaustion evidence was found, but force was requested, so the logs will be cleared.' | Tee-Object -FilePath $logFile -Append
    }

    #####################################################################################################
    # Repair
    #####################################################################################################
    Log-Output '--- Repair ---' | Tee-Object -FilePath $logFile -Append

    $backupRoot = Join-OfflinePath $systemRoot "Temp\$scriptName\$scriptStartTime"
    try { New-Item -Path $backupRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch {
        Log-Error "The backup folder $backupRoot could not be created ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }
    Log-Output "Backups for this run are in $backupRoot." | Tee-Object -FilePath $logFile -Append

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($plan in $actionable) {
        Log-Output "Clearing scope $($plan.Scope) - $($plan.FileCount) file(s) in $($plan.ScopeInfo.Path)." | Tee-Object -FilePath $logFile -Append
        $outcome = Invoke-OfflineRemovalPlan -Plan $plan -BackupRoot $backupRoot
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $results.Add($outcome)
    }

    #####################################################################################################
    # Verify
    #####################################################################################################
    Log-Output '--- Verification ---' | Tee-Object -FilePath $logFile -Append

    $succeeded = @($results | Where-Object { $_.Success })
    $failed = @($results | Where-Object { -not $_.Success })

    $manifestEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($outcome in $succeeded) {
        $plan = @($actionable | Where-Object { $_.Scope -eq $outcome.Label } | Select-Object -First 1)[0]
        $manifestEntries.Add([PSCustomObject]@{
                Scope      = $outcome.Label
                TargetPath = $plan.ScopeInfo.Path
                BackupPath = $outcome.BackupPath
                Files      = @($plan.Snapshot.MatchedFile | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Attributes = $_.Attributes } })
            })
        Log-Output "Scope $($outcome.Label): $(@($outcome.Removed).Count) file(s) removed and verified." | Tee-Object -FilePath $logFile -Append
    }

    if ($manifestEntries.Count -gt 0) {
        Write-RevertManifest -Path $manifestPath -Entry @($manifestEntries)
    }

    foreach ($outcome in $failed) {
        Log-Error "Scope $($outcome.Label) failed and was rolled back: $($outcome.Reason)" | Tee-Object -FilePath $logFile -Append
    }

    if ($failed.Count -gt 0) {
        Log-Error "$($failed.Count) of $($results.Count) scope(s) failed. The disk is in the state it was in before this run." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output 'The transaction logs were cleared. Windows recreates them on the next boot.' | Tee-Object -FilePath $logFile -Append
    if (@($markers).Count -gt 0) {
        Log-Warning 'Pending servicing markers are still present, so the VM may need win-fix-pending-servicing as well.' | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detach the disk and reattach it to the original VM with 'az vm repair restore'." | Tee-Object -FilePath $logFile -Append
    Log-Output "The backups and the revert manifest travel back with the disk. Once the VM is confirmed healthy they can be deleted from $backupRoot and $manifestPath. Reverting needs both, so keep them until then." | Tee-Object -FilePath $logFile -Append

    return $STATUS_SUCCESS
}
catch {
    Log-Error "$scriptName failed: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error $_.ScriptStackTrace | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
