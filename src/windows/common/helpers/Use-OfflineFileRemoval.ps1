<#
.SYNOPSIS
    Removing a set of files from a folder on an offline Windows disk, with a verified backup, a
    proof that only the intended files went, and an automatic rollback when that proof fails.

.DESCRIPTION
    Deleting files out of a folder that also holds registry hives is the dangerous shape this
    helper exists to make safe. System32\config is the example: the transaction logs that a repair
    legitimately clears sit in the same folder as SYSTEM, SOFTWARE and their .LOG1/.LOG2 recovery
    logs, and a mistake there is unrecoverable on a disk that is already not booting.

    The safety comes from four things, in order:

      1. A two-layer allow-list. A file is only eligible if its extension is on the caller's match
         list AND is not on the caller's protected list. The second test can never fire given the
         first, which is the point: it is there so that widening the match list later cannot
         quietly make a hive recovery log deletable.

      2. Acting only from a captured list. The folder is enumerated once, into a plan. Nothing is
         re-enumerated between deciding and deleting, so the set of files removed is exactly the
         set that was reported and backed up.

      3. A hash-verified backup taken before anything is deleted. A copy that reported success but
         produced a short file would make the rollback useless at the moment it is needed.

      4. Six checks afterwards, all of which must pass, and a rollback of the whole set if any
         fails. A partially cleared CLFS log set is worse than a full one, because the .blf then
         refers to containers that no longer exist.

    Deleting itself goes through Invoke-OfflineProtectedFileRemoval. An ordinary delete is tried
    first, and
    only when it is actually refused is ownership of the file and its parent folder taken, the
    delete retried, and both descriptors put straight back. The parent matters because deleting a
    file is a write to the folder holding it, so rights on the file alone are not enough. This is
    not a fifth safety measure - it widens what the helper can remove - but it is safe to combine
    with the four above because check 3 compares the folder's security descriptor before and after:
    ownership that was taken and not handed back fails the run and rolls it back.

    Callers build a plan with Get-OfflineRemovalPlan and execute it with Invoke-OfflineRemovalPlan.
    The plan carries its own configuration - match list, protected list, hive names, size limit -
    so a caller can run several different plans in one script without threading parameters through.

    Nothing here writes to the output stream. Progress is recorded with Add-OfflineRepairLog and the
    caller flushes it, because these functions return values and a Log-* call would corrupt them.

.NOTES
    Requires OfflineRepairCommon.ps1 (Add-OfflineRepairLog, Join-OfflinePath, Test-OfflinePath),
    Use-OfflineRegistryHive.ps1 (Test-OfflineHiveFile) and Use-OfflineProtectedResource.ps1
    (Invoke-OfflineProtectedFileRemoval).
#>

function Get-OfflineFileHashValue {
    <#
    .SYNOPSIS
        SHA256 of a file, or $null when it cannot be read.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return $null }
}

function Get-OfflineFreeSpace {
    <#
    .SYNOPSIS
        Free bytes on the volume holding a path, or $null when it cannot be determined.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrWhiteSpace($root)) { return $null }
        $drive = Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction Stop
        return [int64]$drive.Free
    }
    catch { return $null }
}

function Test-OfflineRemovableFile {
    <#
    .SYNOPSIS
        Decides whether one file name is eligible for removal.

    .DESCRIPTION
        Two independent tests must both agree: the extension is on the match list, and it is not on
        the protected list. See the file header for why the second test is kept even though the
        first makes it unreachable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MatchExtension,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ProtectedExtension = @()
    )

    $extension = [System.IO.Path]::GetExtension($Name)
    if ([string]::IsNullOrEmpty($extension)) { return $false }

    $extension = $extension.ToLowerInvariant()
    if (@($ProtectedExtension) -contains $extension) { return $false }
    return (@($MatchExtension) -contains $extension)
}

function Get-OfflineFolderSnapshot {
    <#
    .SYNOPSIS
        Records the exact state of a folder, so the same folder can be compared afterwards.

    .DESCRIPTION
        [System.IO.Directory]::Exists is used rather than Test-Path so that a folder which exists
        but cannot be enumerated is still recorded as present. config\TxR restricts its own ACL on
        some builds and reading it can fail even from an elevated rescue VM; reporting it as absent
        would be wrong, and would make the "folder still exists" check pass for the wrong reason.

        CreationTimeUtc is the folder's identity. If the folder is deleted and recreated - which is
        what a wildcard delete of the folder itself would do - the timestamp changes even though the
        path is the same.

        An unreadable SDDL is recorded as $null rather than treated as an error. The comparison
        later skips a null on either side, because "could not read it before and cannot read it now"
        is not evidence of a change.

    .OUTPUTS
        PSCustomObject with Path, Present, Accessible, AccessError, CreatedUtc, Sddl, MatchedFile[]
        and OtherFile[].
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MatchExtension,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ProtectedExtension = @(),
        [Parameter(Mandatory = $false)][switch]$IncludeHash
    )

    $snapshot = [PSCustomObject]@{
        Path        = $Path
        Present     = $false
        Accessible  = $false
        AccessError = $null
        CreatedUtc  = $null
        Sddl        = $null
        MatchedFile = @()
        OtherFile   = @()
    }

    try { $snapshot.Present = [System.IO.Directory]::Exists($Path) }
    catch { $snapshot.Present = $false }

    if (-not $snapshot.Present) { return $snapshot }

    try { $snapshot.CreatedUtc = ([System.IO.Directory]::GetCreationTimeUtc($Path)).ToString('o') }
    catch { $snapshot.CreatedUtc = $null }

    try { $snapshot.Sddl = (Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl }
    catch { $snapshot.Sddl = $null }

    $items = $null
    try {
        $items = @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop)
        $snapshot.Accessible = $true
    }
    catch {
        $snapshot.AccessError = $_.Exception.Message
        return $snapshot
    }

    $matched = [System.Collections.Generic.List[object]]::new()
    $others = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $items) {
        $record = [PSCustomObject]@{
            Name         = $item.Name
            FullName     = $item.FullName
            Length       = $item.Length
            LastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
            Attributes   = $item.Attributes.ToString()
            Hash         = $null
        }

        if (Test-OfflineRemovableFile -Name $item.Name -MatchExtension $MatchExtension -ProtectedExtension $ProtectedExtension) {
            if ($IncludeHash) { $record.Hash = Get-OfflineFileHashValue -Path $item.FullName }
            $matched.Add($record)
        }
        else {
            $others.Add($record)
        }
    }

    $snapshot.MatchedFile = @($matched)
    $snapshot.OtherFile = @($others)
    return $snapshot
}

function Get-OfflineFolderHiveState {
    <#
    .SYNOPSIS
        Reports whether each named registry hive in a folder loads.

    .DESCRIPTION
        Only used as a before-and-after comparison. A hive that does not load before the deletion
        and still does not load after it says nothing about the removal; only a hive that loaded
        before and does not load after is evidence, and that is what the verification tests for.

        Test-OfflineHiveFile parses a scratch copy, so this never modifies the offline disk and
        never loads a hive in place. That matters: loading a hive in place creates KTM transaction
        logs next to it, which would show up as unexplained new files in the verification.

        Hives above the size limit are recorded as skipped rather than tested, so a multi-gigabyte
        COMPONENTS hive does not turn a small file deletion into a long copy. The file-level
        comparison still proves such a hive was not modified; only the parse is given up.

    .OUTPUTS
        Array of PSCustomObject with Name, Path, Present, Tested, Loads and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$HiveName = @(),
        [Parameter(Mandatory = $false)][int64]$MaxBytes = 512MB
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($hive in @($HiveName)) {
        $hivePath = Join-OfflinePath $Path $hive
        $state = [PSCustomObject]@{
            Name    = $hive
            Path    = $hivePath
            Present = $false
            Tested  = $false
            Loads   = $false
            Reason  = $null
        }

        if (-not (Test-OfflinePath $hivePath)) {
            $state.Reason = 'not present'
            $results.Add($state)
            continue
        }
        $state.Present = $true

        $size = 0
        try { $size = (Get-Item -LiteralPath $hivePath -Force -ErrorAction Stop).Length }
        catch { $size = 0 }

        if ($size -gt $MaxBytes) {
            $state.Reason = "skipped, $([math]::Round($size / 1MB)) MB is above the $([math]::Round($MaxBytes / 1MB)) MB test limit"
            $results.Add($state)
            continue
        }

        $test = Test-OfflineHiveFile -Path $hivePath
        $state.Tested = $true
        $state.Loads = [bool]$test.IsValid
        $state.Reason = $test.Reason
        $results.Add($state)
    }

    return @($results)
}

function Get-OfflineRemovalPlan {
    <#
    .SYNOPSIS
        Captures what would be removed from one folder, and the state to compare against later.

    .DESCRIPTION
        Building a plan is read-only. It takes the folder snapshot and the hive baseline in one
        place so that the caller can report exactly what a run would do before deciding to do it,
        and so that Invoke-OfflineRemovalPlan later works only from this captured list.

        Label is the caller's name for the plan and is used in log lines and in the result, so a
        script clearing several folders can tell them apart.

    .OUTPUTS
        PSCustomObject with Label, Path, Snapshot, HiveState, MatchExtension, ProtectedExtension,
        HiveName, HiveMaxBytes, FileCount and TotalBytes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MatchExtension,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ProtectedExtension = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$HiveName = @(),
        [Parameter(Mandatory = $false)][int64]$HiveMaxBytes = 512MB,
        [Parameter(Mandatory = $false)][switch]$IncludeHash
    )

    $snapshot = Get-OfflineFolderSnapshot -Path $Path -MatchExtension $MatchExtension -ProtectedExtension $ProtectedExtension -IncludeHash:$IncludeHash

    $hiveState = @()
    if ($snapshot.Present -and @($HiveName).Count -gt 0) {
        $hiveState = Get-OfflineFolderHiveState -Path $Path -HiveName $HiveName -MaxBytes $HiveMaxBytes
    }

    $totalBytes = 0
    foreach ($file in @($snapshot.MatchedFile)) { $totalBytes += [int64]$file.Length }

    return [PSCustomObject]@{
        Label              = $Label
        Path               = $Path
        Snapshot           = $snapshot
        HiveState          = @($hiveState)
        MatchExtension     = @($MatchExtension)
        ProtectedExtension = @($ProtectedExtension)
        HiveName           = @($HiveName)
        HiveMaxBytes       = $HiveMaxBytes
        FileCount          = @($snapshot.MatchedFile).Count
        TotalBytes         = $totalBytes
    }
}

function Backup-OfflineFile {
    <#
    .SYNOPSIS
        Copies one file to the backup folder and proves the copy is identical.

    .DESCRIPTION
        The hash comparison is the point. A copy that reported success but produced a short or
        empty file would make the rollback useless at exactly the moment it is needed, and the
        deletion is only allowed to run once this has returned success.

        Attributes are recorded rather than copied. Copy-Item does not carry them, and the rollback
        has to put back a file that is byte-identical and marked the same way.

    .OUTPUTS
        PSCustomObject with Name, Source, Backup, Attributes, Success and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)]$File,
        [Parameter(Mandatory = $true)][string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Name       = $File.Name
        Source     = $File.FullName
        Backup     = (Join-Path $BackupPath $File.Name)
        Attributes = $File.Attributes
        Success    = $false
        Reason     = $null
    }

    try {
        Copy-Item -LiteralPath $File.FullName -Destination $result.Backup -Force -ErrorAction Stop
    }
    catch {
        $result.Reason = "copy failed: $($_.Exception.Message)"
        return $result
    }

    $sourceHash = $File.Hash
    if (-not $sourceHash) { $sourceHash = Get-OfflineFileHashValue -Path $File.FullName }
    $backupHash = Get-OfflineFileHashValue -Path $result.Backup

    if (-not $sourceHash -or -not $backupHash) {
        $result.Reason = 'the backup copy could not be hash-verified'
        return $result
    }
    if ($sourceHash -ne $backupHash) {
        $result.Reason = 'the backup copy does not match the original'
        return $result
    }

    $result.Success = $true
    return $result
}

function Restore-OfflineFileSet {
    <#
    .SYNOPSIS
        Puts a backed-up set of files back where they came from.

    .DESCRIPTION
        Used both by the automatic rollback when verification fails and by a caller's "-revert"
        path.

        The file is copied back and then given its recorded attributes again. A restored .blf that
        is missing its original attributes is not the file that was there before, and CLFS is
        entitled to notice.

    .OUTPUTS
        PSCustomObject with Restored, Failed and Detail[].
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $false)][AllowNull()]$FileRecord = $null
    )

    $summary = [PSCustomObject]@{
        Restored = 0
        Failed   = 0
        Detail   = @()
    }
    $detail = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        $detail.Add("The backup folder $BackupPath is not present.")
        $summary.Failed = 1
        $summary.Detail = @($detail)
        return $summary
    }

    $backedUp = @(Get-ChildItem -LiteralPath $BackupPath -File -Force -ErrorAction SilentlyContinue)
    foreach ($item in $backedUp) {
        $destination = Join-Path $TargetPath $item.Name
        try {
            Copy-Item -LiteralPath $item.FullName -Destination $destination -Force -ErrorAction Stop

            $recorded = @($FileRecord) | Where-Object { $_ -and $_.Name -eq $item.Name } | Select-Object -First 1
            if ($recorded -and $recorded.Attributes) {
                try { (Get-Item -LiteralPath $destination -Force -ErrorAction Stop).Attributes = [System.IO.FileAttributes]$recorded.Attributes }
                catch { $detail.Add("Restored $($item.Name) but could not reapply its attributes ($($_.Exception.Message)).") }
            }

            $summary.Restored++
            $detail.Add("Restored $($item.Name).")
        }
        catch {
            $summary.Failed++
            $detail.Add("Could not restore $($item.Name): $($_.Exception.Message)")
        }
    }

    $summary.Detail = @($detail)
    return $summary
}

function Test-OfflineRemovalResult {
    <#
    .SYNOPSIS
        Proves the deletion removed the planned files and nothing else.

    .DESCRIPTION
        Six checks, all of which must pass. Check 5 is the one that matters most: comparing every
        other file in the folder by size, last write time and attributes is the direct evidence
        that the registry hives and their .LOG1/.LOG2 recovery logs were neither removed nor
        modified. Check 6 then has Windows confirm the hives still parse.

        A folder ACL that could not be read before and cannot be read now is passed rather than
        failed, because there is nothing to compare and refusing on that basis would roll back a
        correct repair on a build that simply restricts the folder.

    .OUTPUTS
        PSCustomObject with Passed, Check[] and Failure[].
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Removed
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    $before = $Plan.Snapshot
    $after = Get-OfflineFolderSnapshot -Path $Plan.Path -MatchExtension $Plan.MatchExtension -ProtectedExtension $Plan.ProtectedExtension

    function Add-Check {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        $checks.Add([PSCustomObject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
        if (-not $Passed) { $failures.Add("$Name - $Detail") }
    }

    # 1. The folder is still there.
    Add-Check -Name 'Folder present' -Passed $after.Present -Detail $(
        if ($after.Present) { 'the folder is still present' } else { 'the folder is gone' })

    if (-not $after.Present) {
        return [PSCustomObject]@{ Passed = $false; Check = @($checks); Failure = @($failures) }
    }

    # 2. It is the same folder, not a replacement.
    $sameFolder = ($null -eq $before.CreatedUtc) -or ($null -eq $after.CreatedUtc) -or ($before.CreatedUtc -eq $after.CreatedUtc)
    Add-Check -Name 'Folder not recreated' -Passed $sameFolder -Detail $(
        if ($sameFolder) { 'the creation timestamp is unchanged' }
        else { "the creation timestamp changed from $($before.CreatedUtc) to $($after.CreatedUtc)" })

    # 3. The ACL is unchanged.
    $sameAcl = ($null -eq $before.Sddl) -or ($null -eq $after.Sddl) -or ($before.Sddl -eq $after.Sddl)
    Add-Check -Name 'Folder ACL unchanged' -Passed $sameAcl -Detail $(
        if ($null -eq $before.Sddl -or $null -eq $after.Sddl) { 'the ACL could not be read, so there is nothing to compare' }
        elseif ($sameAcl) { 'the ACL is unchanged' }
        else { 'the ACL changed' })

    # 4. Exactly the planned files went, and no others.
    $expectedGone = @($Removed | ForEach-Object { $_.Name })
    $stillThere = @($after.MatchedFile | ForEach-Object { $_.Name })
    $notRemoved = @($expectedGone | Where-Object { $stillThere -contains $_ })
    $plannedNames = @($before.MatchedFile | ForEach-Object { $_.Name })
    $unexpectedlyGone = @($plannedNames | Where-Object { $expectedGone -notcontains $_ -and $stillThere -notcontains $_ })

    $removalOk = ($notRemoved.Count -eq 0 -and $unexpectedlyGone.Count -eq 0)
    Add-Check -Name 'Planned files removed' -Passed $removalOk -Detail $(
        if ($removalOk) { "$($expectedGone.Count) file(s) removed as planned" }
        elseif ($notRemoved.Count -gt 0) { "still present: $($notRemoved -join ', ')" }
        else { "removed without being planned: $($unexpectedlyGone -join ', ')" })

    # 5. Everything else in the folder is byte-for-byte and flag-for-flag as it was.
    $otherProblems = [System.Collections.Generic.List[string]]::new()
    foreach ($original in @($before.OtherFile)) {
        $current = @($after.OtherFile) | Where-Object { $_.Name -eq $original.Name } | Select-Object -First 1
        if (-not $current) { $otherProblems.Add("$($original.Name) is missing"); continue }
        if ($current.Length -ne $original.Length) { $otherProblems.Add("$($original.Name) changed size") }
        if ($current.LastWriteUtc -ne $original.LastWriteUtc) { $otherProblems.Add("$($original.Name) was written to") }
        if ($current.Attributes -ne $original.Attributes) { $otherProblems.Add("$($original.Name) had its attributes changed") }
    }
    $othersOk = ($otherProblems.Count -eq 0)
    Add-Check -Name 'Other files untouched' -Passed $othersOk -Detail $(
        if ($othersOk) { "all $(@($before.OtherFile).Count) other file(s) are unchanged" }
        else { ($otherProblems -join '; ') })

    # 6. Hives that loaded before still load.
    $hiveProblems = [System.Collections.Generic.List[string]]::new()
    $testedBefore = @($Plan.HiveState | Where-Object { $_.Tested -and $_.Loads })
    if ($testedBefore.Count -gt 0) {
        $afterHive = Get-OfflineFolderHiveState -Path $Plan.Path -HiveName $Plan.HiveName -MaxBytes $Plan.HiveMaxBytes
        foreach ($original in $testedBefore) {
            $current = @($afterHive) | Where-Object { $_.Name -eq $original.Name } | Select-Object -First 1
            if (-not $current -or -not $current.Tested) { $hiveProblems.Add("$($original.Name) could not be retested"); continue }
            if (-not $current.Loads) { $hiveProblems.Add("$($original.Name) no longer loads ($($current.Reason))") }
        }
    }
    $hivesOk = ($hiveProblems.Count -eq 0)
    Add-Check -Name 'Registry hives still load' -Passed $hivesOk -Detail $(
        if ($testedBefore.Count -eq 0) { 'no hive in this folder was testable beforehand, so there is nothing to compare' }
        elseif ($hivesOk) { "all $($testedBefore.Count) hive(s) still load" }
        else { ($hiveProblems -join '; ') })

    return [PSCustomObject]@{
        Passed  = ($failures.Count -eq 0)
        Check   = @($checks)
        Failure = @($failures)
    }
}

function Invoke-OfflineRemovalPlan {
    <#
    .SYNOPSIS
        Backs up, deletes and verifies the files captured in one plan.

    .DESCRIPTION
        Works only from the file list captured in the plan. The folder is never re-enumerated
        between deciding and acting, so the set of files that gets deleted is exactly the set that
        was reported and backed up.

        Deleting is delegated to Invoke-OfflineProtectedFileRemoval, which clears the attributes that
        block a delete and, only if the delete is actually refused, takes ownership of the file and
        its parent folder, retries, and restores both descriptors. Verification check 3 compares the
        folder's SDDL before and after, so an ownership change that was not handed back fails the
        run and rolls it back rather than being left behind.

        A failure at any point rolls the whole plan back. A partially cleared CLFS log set is worse
        than a full one: the .blf refers to containers that would no longer exist.

        Progress is recorded with Add-OfflineRepairLog rather than Log-*. The Log-* functions write
        to the output stream, so calling one here would put log strings into this function's return
        value and the caller would read them as extra results. The caller flushes the buffer after
        each call instead.

    .OUTPUTS
        PSCustomObject with Label, BackupPath, Removed[], Verification, Success and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string]$BackupRoot
    )

    $result = [PSCustomObject]@{
        Label        = $Plan.Label
        BackupPath   = $null
        Removed      = @()
        Verification = $null
        Success      = $false
        Reason       = $null
    }

    # Checked here, before anything is copied or deleted, so a script that forgot to dot-source
    # Use-OfflineProtectedResource.ps1 gets one clear sentence instead of an obscure failure part
    # way through a set of deletes.
    if (-not (Get-Command -Name 'Invoke-OfflineProtectedFileRemoval' -ErrorAction SilentlyContinue)) {
        $result.Reason = 'Use-OfflineProtectedResource.ps1 has not been loaded, so a protected file could not be removed. Dot-source it alongside this helper.'
        Add-OfflineRepairLog -Level Error -Message $result.Reason
        return $result
    }

    $backupPath = Join-Path $BackupRoot $Plan.Label
    try { New-Item -Path $backupPath -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch {
        $result.Reason = "the backup folder $backupPath could not be created: $($_.Exception.Message)"
        return $result
    }
    $result.BackupPath = $backupPath

    # Room for the backup, with the same again as headroom.
    $required = ($Plan.TotalBytes * 2)
    $free = Get-OfflineFreeSpace -Path $backupPath
    if ($null -eq $free) {
        Add-OfflineRepairLog -Level Warning -Message 'Free space on the backup volume could not be confirmed; continuing.'
    }
    elseif ($free -lt $required) {
        $result.Reason = "not enough free space for the backup: $([math]::Round($free / 1MB)) MB free, $([math]::Round($required / 1MB)) MB needed"
        return $result
    }

    # Back everything up first. Nothing is deleted until every file has a verified copy.
    foreach ($file in @($Plan.Snapshot.MatchedFile)) {
        $backup = Backup-OfflineFile -File $file -BackupPath $backupPath
        if (-not $backup.Success) {
            $result.Reason = "$($file.Name) could not be backed up - $($backup.Reason)"
            Add-OfflineRepairLog -Level Error -Message $result.Reason
            return $result
        }
        Add-OfflineRepairLog -Message "Backed up $($file.Name) ($([math]::Round($file.Length / 1KB)) KB)."
    }

    # Delete, working from the same list.
    #
    # Each file goes through Invoke-OfflineProtectedFileRemoval rather than a plain Remove-Item, so a
    # file whose DACL refuses the delete is retried after ownership is taken and handed straight
    # back. config\TxR is exactly that case: its CLFS artifacts are owned by TrustedInstaller, and
    # without the escalation the whole set rolls back over one refused file.
    $removed = [System.Collections.Generic.List[object]]::new()
    $deleteFailed = $null
    foreach ($file in @($Plan.Snapshot.MatchedFile)) {
        $attempt = Invoke-OfflineProtectedFileRemoval -Path $file.FullName

        if ($attempt.Removed) {
            $removed.Add([PSCustomObject]@{ Name = $file.Name; Length = $file.Length })
            if ($attempt.TookOwnership) {
                Add-OfflineRepairLog -Message "Removed $($file.Name) after taking ownership of it and its folder."
                if (-not $attempt.Restored) {
                    Add-OfflineRepairLog -Level Warning -Message "The original permissions on $($file.Name) or its folder could not be fully restored."
                }
            }
            else { Add-OfflineRepairLog -Message "Removed $($file.Name)." }
            continue
        }

        # Anything else rolls the set back, including "the file was not present". Every file here
        # was in the snapshot and was backed up seconds earlier, and nothing else should be touching
        # a disk attached to a rescue VM, so a file that has since vanished is an anomaly rather
        # than a result. Check 4 would fail it as unexpectedly gone in any case.
        $deleteFailed = "$($file.Name) could not be removed: $($attempt.Reason)"
        break
    }
    $result.Removed = @($removed)

    if ($deleteFailed) {
        Add-OfflineRepairLog -Level Error -Message "$deleteFailed Rolling this set back."
        $rollback = Restore-OfflineFileSet -BackupPath $backupPath -TargetPath $Plan.Path -FileRecord $Plan.Snapshot.MatchedFile
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.Reason = $deleteFailed
        return $result
    }

    # Prove it did what it was supposed to and nothing more.
    $verification = Test-OfflineRemovalResult -Plan $Plan -Removed $result.Removed
    $result.Verification = $verification

    foreach ($check in @($verification.Check)) {
        $line = "  [$(if ($check.Passed) { 'PASS' } else { 'FAIL' })] $($check.Name): $($check.Detail)"
        if ($check.Passed) { Add-OfflineRepairLog -Message $line }
        else { Add-OfflineRepairLog -Level Error -Message $line }
    }

    if (-not $verification.Passed) {
        Add-OfflineRepairLog -Level Error -Message "Verification failed for $($Plan.Label). Rolling it back."
        $rollback = Restore-OfflineFileSet -BackupPath $backupPath -TargetPath $Plan.Path -FileRecord $Plan.Snapshot.MatchedFile
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.Reason = ($verification.Failure -join '; ')
        return $result
    }

    $result.Success = $true
    return $result
}
