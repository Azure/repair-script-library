<#
.SYNOPSIS
    Removing a set of files from a folder on an offline Windows disk, with a verified backup, a
    proof that only the intended files went, and an automatic rollback when that proof fails.

.DESCRIPTION
    Deleting files out of a folder that also holds registry hives is the dangerous shape this
    helper exists to make safe. System32\config is the example: the transaction logs that a repair
    legitimately clears sit in the same folder as SYSTEM, SOFTWARE and their .LOG1/.LOG2 recovery
    logs, and a mistake there is unrecoverable on a disk that is already not booting.

    The safety comes from these things, in order:

      1. A genuine two-layer guard, where either layer on its own is enough to refuse a file:

           a. The hive base-name veto. A file whose name without its extension is one of the
              folder's registry hives - SYSTEM, SOFTWARE, SECURITY, SAM, DEFAULT and so on - is
              rejected outright, whether it is the bare hive or one of that hive's transaction and
              recovery logs (SYSTEM.LOG1, SOFTWARE.LOG2, SECURITY.blf, SYSTEM.regtrans-ms). Clearing
              a hive's dirty logs while the hive itself stays is a known way to make the hive
              unmountable, so the hive's own name is never removable in any form.

           b. The extension allow-list. Of what the veto leaves, a file is eligible only if its
              extension is on the caller's match list and is not on the caller's protected list.

         The two layers are independent on purpose: the veto bounds the file by identity and the
         allow-list bounds it by kind, so widening one can never quietly defeat the other.

      2. Acting only from a captured list. The folder is enumerated once, into a plan. Nothing is
         re-enumerated between deciding and deleting, so the set of files removed is exactly the
         set that was reported and backed up. Reparse points are dropped during that enumeration
         and never removed, so a link planted in the folder cannot redirect a delete off the disk.

      3. A hash-verified backup taken before anything is deleted, into a folder unique to the run,
         so one run can never overwrite an earlier run's only copy of the originals. Each file's
         owner and DACL are recorded in binary form alongside its bytes, so a rollback restores the
         security it had and not merely its contents.

      4. Independent checks afterwards, and a rollback of the whole set if any fails. The registry
         check reports INCONCLUSIVE, not PASS, when no hive was loadable beforehand, so a run that
         proved nothing about the hives cannot look like one that proved them intact. A partially
         cleared CLFS log set is worse than a full one, because the .blf then refers to containers
         that no longer exist. A rollback that itself fails - contents now gone with nothing put
         back - is reported as a distinct, fatal outcome rather than as an ordinary failure.

      5. A hard binding to the offline disk. Every path this helper deletes is checked with
         Assert-OfflineTarget first, so a caller that passes a degraded or unrooted path is refused
         rather than allowed to delete from the rescue VM's own volume.

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
    Requires OfflineRepairCommon.ps1 (Add-OfflineRepairLog, Assert-OfflineTarget, Join-OfflinePath,
    Test-OfflinePath), Use-OfflineRegistryHive.ps1 (Test-OfflineHiveFile) and
    Use-OfflineProtectedResource.ps1 (Invoke-OfflineProtectedFileRemoval, Copy-OfflineProtectedFile,
    Enable-OfflineOwnershipPrivilege, Save-OfflinePathSecurity).

.VERSION
    v1.1: Added the hive base-name veto so a hive's own transaction and recovery logs
          (SYSTEM.LOG1, SOFTWARE.LOG2, SECURITY.blf, SYSTEM.regtrans-ms) can no longer be removed;
          the guard is now genuinely two independent layers. Bound every delete to the offline root
          with Assert-OfflineTarget and stopped following reparse points. Made the rollback loud
          (it fails when it recovers fewer files than expected), routed restores through
          Copy-OfflineProtectedFile, and record and replay each file's owner and DACL in binary
          form. Surfaced rollback status on the result and made a failed rollback a distinct fatal
          outcome. Gave each run its own backup folder. Made post-check 4 re-test the filesystem
          instead of trusting the removed list, and post-check 6 report INCONCLUSIVE when no hive
          was testable.
    v1.0: Initial version.
#>

# Resolve every sibling against this file's own folder, so a scenario loads the same helpers
# wherever it dot-sources this from, and fail loudly here rather than part-way through a
# destructive removal. This file deletes files on the offline image and rolls them back, so a
# missing Copy-OfflineProtectedFile or Assert-OfflineTarget discovered mid-run is the worst case.
$script:OfflineFileRemovalDependencies = @(
    @{ File = 'OfflineRepairCommon.ps1';          Sentinel = 'Assert-OfflineTarget' },
    @{ File = 'Use-OfflineProtectedResource.ps1'; Sentinel = 'Copy-OfflineProtectedFile' },
    @{ File = 'Use-OfflineRegistryHive.ps1';      Sentinel = 'Test-OfflineHiveFile' }
)
foreach ($dependency in $script:OfflineFileRemovalDependencies) {
    if (Get-Command -Name $dependency.Sentinel -ErrorAction SilentlyContinue) { continue }
    $dependencyPath = Join-Path -Path $PSScriptRoot -ChildPath $dependency.File
    try {
        . $dependencyPath
    }
    catch {
        throw "Use-OfflineFileRemoval.ps1 could not load its dependency '$($dependency.File)' from '$dependencyPath': $($_.Exception.Message)"
    }
}
foreach ($required in @('Assert-OfflineTarget', 'Add-OfflineRepairLog', 'Copy-OfflineProtectedFile',
        'Invoke-OfflineProtectedFileRemoval', 'Save-OfflinePathSecurity', 'Test-OfflineHiveFile')) {
    if (-not (Get-Command -Name $required -ErrorAction SilentlyContinue)) {
        throw "Use-OfflineFileRemoval.ps1 requires '$required', which its dependencies did not define."
    }
}

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
        Two independent layers, either of which is enough on its own to refuse the file:

          1. The base-name veto. A file whose name without its extension matches one of the folder's
             registry hives is refused outright, whether it is the bare hive (SYSTEM) or one of that
             hive's transaction and recovery logs (SYSTEM.LOG1, SOFTWARE.LOG2, SECURITY.blf,
             SYSTEM.regtrans-ms). Deleting a hive's dirty logs while the hive itself stays is a known
             way to make the hive unmountable - the exact damage this helper exists to prevent - so
             the hive's own name is never removable in any form.

          2. The extension allow-list. Of what the veto leaves, a file is eligible only if its
             extension is on the match list and is not on the protected list.

    .PARAMETER Name
        File name (leaf, not a full path) to test.

    .PARAMETER MatchExtension
        Extensions eligible for removal, lower-case and with the leading dot, e.g. '.log1'.

    .PARAMETER ProtectedExtension
        Extensions never eligible even when they appear on the match list.

    .PARAMETER HiveName
        Registry hive base names (SYSTEM, SOFTWARE, ...) whose files must never be removed. Matched
        against the name without its extension, ordinal and case-insensitively.

    .OUTPUTS
        [bool] - $true only when the file may be removed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MatchExtension,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ProtectedExtension = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$HiveName = @()
    )

    # Layer 1: the base-name veto. GetFileNameWithoutExtension collapses both SYSTEM and SYSTEM.LOG1
    # onto "SYSTEM", so a hive and every one of its logs are refused together, in any casing.
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    foreach ($hive in @($HiveName)) {
        if ([string]::IsNullOrEmpty($hive)) { continue }
        if ([string]::Equals($baseName, $hive, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }

    # Layer 2: the extension allow-list.
    #
    # The extensionless refusal here is load-bearing and must stay. A bare hive such as SYSTEM has no
    # extension, and before the veto above existed this was the ONLY reason it was safe; it still
    # guards every other extensionless file - a hive this folder was never told to name, a caller
    # that passes no HiveName - that the veto cannot know to reject by name.
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

        Reparse points (symlinks, junctions) are recorded as other files and never as matched ones,
        so a link planted in the folder can never be selected for removal - deleting or taking
        ownership of a link can reach a target off the offline disk entirely.

    .OUTPUTS
        PSCustomObject with Path, Present, Accessible, AccessError, CreatedUtc, Sddl, MatchedFile[]
        and OtherFile[]. Reparse points and registry-hive files are always classified as OtherFile.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MatchExtension,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ProtectedExtension = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$HiveName = @(),
        [Parameter(Mandatory = $false)][switch]$IncludeHash,
        [Parameter(Mandatory = $false)][switch]$LogReparseSkips
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

        # A reparse point (symlink, junction) is a redirection, not a file to be cleared: removing
        # or taking ownership of one can reach a target outside this folder, and off the offline
        # disk. It is never eligible, whatever its name; it is kept as an other file so the
        # verification still proves it was left untouched.
        if ($item.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            if ($LogReparseSkips) { Add-OfflineRepairLog -Level Warning -Message "Skipping $($item.Name): it is a reparse point (link), so it will not be removed." }
            $others.Add($record)
            continue
        }

        if (Test-OfflineRemovableFile -Name $item.Name -MatchExtension $MatchExtension -ProtectedExtension $ProtectedExtension -HiveName $HiveName) {
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

        Test-OfflineHiveFile parses with offreg in memory, so this never modifies the offline
        disk or mounts a hive. That avoids the KTM transaction logs an in-place registry mount
        can create next to a hive, which would look like unexplained new files in verification.
        Loads records offreg's result for comparison, not a guarantee that Windows will boot.

        Hives above the size limit are recorded as skipped rather than tested, so a multi-gigabyte
        COMPONENTS hive does not turn a small file deletion into a large in-memory parse. The file-level
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

    $snapshot = Get-OfflineFolderSnapshot -Path $Path -MatchExtension $MatchExtension -ProtectedExtension $ProtectedExtension -HiveName $HiveName -IncludeHash:$IncludeHash -LogReparseSkips

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

        The owner and DACL are recorded too, in binary form, so the rollback can put back the exact
        security the file had. Binary rather than SDDL on purpose: a machine-relative SDDL alias
        (BA, SY and the like) would re-resolve against the rescue VM on the way back in, so a hive
        log could return owned by the wrong authority.

    .OUTPUTS
        PSCustomObject with Name, Source, Backup, Attributes, Security, Success and Reason.
        Security is a byte[] security descriptor, or $null when it could not be read.
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
        Security   = $null
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

    # Record the live source's owner and DACL, so a rollback restores the security the file had and
    # not merely its bytes. Best-effort: a file whose descriptor cannot be read is still backed up
    # and still deletable, but the rollback is warned that it could only put the contents back.
    try {
        if (Get-Command -Name 'Enable-OfflineOwnershipPrivilege' -ErrorAction SilentlyContinue) { Enable-OfflineOwnershipPrivilege }
        $result.Security = (Get-Acl -LiteralPath $File.FullName -ErrorAction Stop).GetSecurityDescriptorBinaryForm()
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The security descriptor of $($File.Name) could not be recorded ($($_.Exception.Message)); a rollback would restore its contents but not its original permissions."
        $result.Security = $null
    }

    $result.Success = $true
    return $result
}

function Restore-OfflineFileSecurity {
    <#
    .SYNOPSIS
        Replays an owner and DACL captured in binary form onto a restored file.

    .DESCRIPTION
        Only the Owner, Group and Access sections are written - never the SACL - so the write needs
        no SeSecurityPrivilege and touches nothing to do with auditing. Setting the owner back to an
        authority the rescue VM is not (TrustedInstaller, for a system hive) needs SeRestore, which
        Enable-OfflineOwnershipPrivilege turns on.

        The descriptor is replayed from bytes, not SDDL, because a machine-relative alias in an SDDL
        string would resolve against the rescue VM rather than the offline image.

    .OUTPUTS
        [bool] - $true when the security was written, $false when it could not be.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][AllowNull()][byte[]]$BinaryDescriptor = $null
    )

    if (-not $BinaryDescriptor -or $BinaryDescriptor.Length -eq 0) { return $false }
    if (-not (Test-OfflinePath $Path)) { return $false }

    try {
        if (Get-Command -Name 'Enable-OfflineOwnershipPrivilege' -ErrorAction SilentlyContinue) { Enable-OfflineOwnershipPrivilege }

        $security = [System.Security.AccessControl.FileSecurity]::new()
        $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor `
            [System.Security.AccessControl.AccessControlSections]::Group -bor `
            [System.Security.AccessControl.AccessControlSections]::Access
        $security.SetSecurityDescriptorBinaryForm($BinaryDescriptor, $sections)

        if (Get-Command -Name 'Save-OfflinePathSecurity' -ErrorAction SilentlyContinue) {
            Save-OfflinePathSecurity -Path $Path -Security $security
        }
        else {
            [System.IO.File]::SetAccessControl($Path, $security)
        }
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not replay the recorded security on $Path ($($_.Exception.Message)); it may carry inherited permissions instead of its original owner and DACL."
        return $false
    }
}

function Restore-OfflineFileSet {
    <#
    .SYNOPSIS
        Puts a backed-up set of files back where they came from, contents and security both.

    .DESCRIPTION
        Used both by the automatic rollback when verification fails and by a caller's "-revert"
        path.

        Each file is copied back through Copy-OfflineProtectedFile, not a plain Copy-Item, so a file
        that had to be de-protected to be backed up - a system hive log owned by TrustedInstaller -
        can actually be written back into its hardened folder. A plain copy fails silently on
        exactly the protected files that matter most. Its recorded attributes and its recorded owner
        and DACL are then reapplied, so a restored file is the one that was there before and not a
        look-alike carrying the rescue VM's idea of permissions.

        The rollback is deliberately loud. The backup folder is enumerated with -ErrorAction Stop,
        and the run is reported as failed unless the number of files recovered equals the number
        expected. A backup folder that has gone missing or unreadable, or a restore that quietly put
        back fewer files than it took, is the one moment this must not be mistaken for "there was
        nothing to restore".

    .OUTPUTS
        PSCustomObject with Restored, Failed, Expected, Succeeded and Detail[]. Succeeded is $true
        only when nothing failed and every expected file came back.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $false)][AllowNull()]$FileRecord = $null
    )

    $recordCount = @($FileRecord | Where-Object { $_ }).Count
    $summary = [PSCustomObject]@{
        Restored  = 0
        Failed    = 0
        Expected  = $recordCount
        Succeeded = $false
        Detail    = @()
    }
    $detail = [System.Collections.Generic.List[string]]::new()

    # Restoring goes through the protected-copy path, so the helper that provides it has to be
    # loaded. Saying so once beats failing per file with an obscure "command not found".
    if (-not (Get-Command -Name 'Copy-OfflineProtectedFile' -ErrorAction SilentlyContinue)) {
        $detail.Add('Use-OfflineProtectedResource.ps1 is not loaded, so files cannot be restored through the protected-copy path.')
        $summary.Failed = 1
        $summary.Detail = @($detail)
        return $summary
    }

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        $detail.Add("The backup folder $BackupPath is not present, so nothing could be restored.")
        $summary.Failed = 1
        $summary.Detail = @($detail)
        return $summary
    }

    # -ErrorAction Stop, not SilentlyContinue: a folder that cannot be enumerated has to surface as
    # a failure, not as an empty loop that returns "restored 0, failed 0" and reads as success.
    try {
        $backedUp = @(Get-ChildItem -LiteralPath $BackupPath -File -Force -ErrorAction Stop)
    }
    catch {
        $detail.Add("The backup folder $BackupPath could not be read ($($_.Exception.Message)), so the rollback cannot proceed.")
        $summary.Failed = 1
        $summary.Detail = @($detail)
        return $summary
    }

    # With no file record to go by, the backup folder itself is the expectation.
    if ($recordCount -le 0) { $summary.Expected = $backedUp.Count }

    foreach ($item in $backedUp) {
        $destination = Join-Path $TargetPath $item.Name
        $recorded = @($FileRecord) | Where-Object { $_ -and $_.Name -eq $item.Name } | Select-Object -First 1

        $copy = Copy-OfflineProtectedFile -Source $item.FullName -Destination $destination
        if (-not $copy.Copied) {
            $summary.Failed++
            $detail.Add("Could not restore $($item.Name): $($copy.Reason)")
            continue
        }

        if ($recorded -and $recorded.Attributes) {
            try { (Get-Item -LiteralPath $destination -Force -ErrorAction Stop).Attributes = [System.IO.FileAttributes]$recorded.Attributes }
            catch { $detail.Add("Restored $($item.Name) but could not reapply its attributes ($($_.Exception.Message)).") }
        }

        if ($recorded -and $recorded.Security) {
            if (-not (Restore-OfflineFileSecurity -Path $destination -BinaryDescriptor $recorded.Security)) {
                $detail.Add("Restored $($item.Name) but could not reapply its original owner and DACL.")
            }
        }

        $summary.Restored++
        $detail.Add("Restored $($item.Name).")
    }

    $summary.Succeeded = ($summary.Failed -eq 0 -and $summary.Restored -eq $summary.Expected)
    if (-not $summary.Succeeded -and $summary.Failed -eq 0) {
        $detail.Add("Rollback recovered $($summary.Restored) of $($summary.Expected) expected file(s).")
    }

    $summary.Detail = @($detail)
    return $summary
}

function Test-OfflineRemovalResult {
    <#
    .SYNOPSIS
        Proves the deletion removed the planned files and nothing else.

    .DESCRIPTION
        Six checks. Check 5 is the one that matters most: comparing every other file in the folder
        by size, last write time and attributes is the direct evidence that the registry hives and
        their .LOG1/.LOG2 recovery logs were neither removed nor modified. Check 6 then has Windows
        confirm the hives still parse.

        Check 4 re-reads the filesystem directly rather than trusting the list of files the delete
        loop reported it removed, so it can actually catch a delete that did not take. Check 6
        reports INCONCLUSIVE rather than PASS when no hive was loadable beforehand, so a run that
        proved nothing about the hives is never mistaken for one that proved them intact; an
        inconclusive check is not a failure and does not roll the run back.

        A folder ACL that could not be read before and cannot be read now is passed rather than
        failed, because there is nothing to compare and refusing on that basis would roll back a
        correct repair on a build that simply restricts the folder.

    .OUTPUTS
        PSCustomObject with Passed, Inconclusive, Check[] and Failure[]. Each Check carries Name,
        Passed, Status ('PASS', 'FAIL' or 'INCONCLUSIVE') and Detail.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Removed
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    $before = $Plan.Snapshot
    $after = Get-OfflineFolderSnapshot -Path $Plan.Path -MatchExtension $Plan.MatchExtension -ProtectedExtension $Plan.ProtectedExtension -HiveName $Plan.HiveName

    function Add-Check {
        param([string]$Name, [bool]$Passed, [string]$Detail, [string]$Status = $null)
        if ([string]::IsNullOrEmpty($Status)) { $Status = if ($Passed) { 'PASS' } else { 'FAIL' } }
        $checks.Add([PSCustomObject]@{ Name = $Name; Passed = $Passed; Status = $Status; Detail = $Detail })
        if (-not $Passed) { $failures.Add("$Name - $Detail") }
    }

    # 1. The folder is still there.
    Add-Check -Name 'Folder present' -Passed $after.Present -Detail $(
        if ($after.Present) { 'the folder is still present' } else { 'the folder is gone' })

    if (-not $after.Present) {
        return [PSCustomObject]@{ Passed = $false; Inconclusive = $false; Check = @($checks); Failure = @($failures) }
    }

    # 2. It is the same folder, not a replacement. A timestamp that could not be read on either
    #    side is INCONCLUSIVE, not PASS. "I could not read it" is the absence of evidence, and
    #    recording absence of evidence as a passed check is what makes a verification step mean
    #    nothing. Post-check 6 already draws this distinction; checks 2 and 3 now match it.
    $folderComparable = ($null -ne $before.CreatedUtc) -and ($null -ne $after.CreatedUtc)
    $sameFolder = (-not $folderComparable) -or ($before.CreatedUtc -eq $after.CreatedUtc)
    $folderStatus = if ($folderComparable) { $null } else { 'INCONCLUSIVE' }
    Add-Check -Name 'Folder not recreated' -Passed $sameFolder -Status $folderStatus -Detail $(
        if (-not $folderComparable) { 'the creation timestamp could not be read, so whether the folder was replaced could not be proven' }
        elseif ($sameFolder) { 'the creation timestamp is unchanged' }
        else { "the creation timestamp changed from $($before.CreatedUtc) to $($after.CreatedUtc)" })

    # 3. The ACL is unchanged. Same rule as check 2: unreadable is unproven, not passed.
    $aclComparable = ($null -ne $before.Sddl) -and ($null -ne $after.Sddl)
    $sameAcl = (-not $aclComparable) -or ($before.Sddl -eq $after.Sddl)
    $aclStatus = if ($aclComparable) { $null } else { 'INCONCLUSIVE' }
    Add-Check -Name 'Folder ACL unchanged' -Passed $sameAcl -Status $aclStatus -Detail $(
        if (-not $aclComparable) { 'the ACL could not be read, so whether it changed could not be proven' }
        elseif ($sameAcl) { 'the ACL is unchanged' }
        else { 'the ACL changed' })

    # 4. Exactly the planned files went, and no others. This re-reads the offline filesystem
    #    directly with Test-OfflinePath rather than trusting $Removed - the very list it exists to
    #    validate - so a delete the loop reported but that did not actually take is still caught.
    $expectedGone = @($Removed | ForEach-Object { $_.Name })
    $stillOnDisk = @($expectedGone | Where-Object { Test-OfflinePath (Join-OfflinePath $Plan.Path $_) })
    $plannedNames = @($before.MatchedFile | ForEach-Object { $_.Name })
    $unexpectedlyGone = @($plannedNames | Where-Object { $expectedGone -notcontains $_ -and -not (Test-OfflinePath (Join-OfflinePath $Plan.Path $_)) })

    $removalOk = ($stillOnDisk.Count -eq 0 -and $unexpectedlyGone.Count -eq 0)
    Add-Check -Name 'Planned files removed' -Passed $removalOk -Detail $(
        if ($removalOk) { "$($expectedGone.Count) file(s) removed as planned" }
        elseif ($stillOnDisk.Count -gt 0) { "still on disk: $($stillOnDisk -join ', ')" }
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
    if ($testedBefore.Count -eq 0) {
        # Nothing was provable here - no hive in this folder loaded beforehand, or none was named -
        # so the removal cannot be said to have preserved them. INCONCLUSIVE, never PASS, so a run
        # that proved nothing about the hives is not read as one that proved them intact. It is not
        # counted as a failure and so does not roll the run back.
        Add-Check -Name 'Registry hives still load' -Passed $true -Status 'INCONCLUSIVE' -Detail 'no hive in this folder was loadable beforehand, so whether the removal preserved them could not be proven'
    }
    else {
        $afterHive = Get-OfflineFolderHiveState -Path $Plan.Path -HiveName $Plan.HiveName -MaxBytes $Plan.HiveMaxBytes
        foreach ($original in $testedBefore) {
            $current = @($afterHive) | Where-Object { $_.Name -eq $original.Name } | Select-Object -First 1
            if (-not $current -or -not $current.Tested) { $hiveProblems.Add("$($original.Name) could not be retested"); continue }
            if (-not $current.Loads) { $hiveProblems.Add("$($original.Name) no longer loads ($($current.Reason))") }
        }
        $hivesOk = ($hiveProblems.Count -eq 0)
        Add-Check -Name 'Registry hives still load' -Passed $hivesOk -Detail $(
            if ($hivesOk) { "all $($testedBefore.Count) hive(s) still load" }
            else { ($hiveProblems -join '; ') })
    }

    return [PSCustomObject]@{
        Passed       = ($failures.Count -eq 0)
        Inconclusive = [bool](@($checks | Where-Object { $_.Status -eq 'INCONCLUSIVE' }).Count -gt 0)
        Check        = @($checks)
        Failure      = @($failures)
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

        Every path is checked against the bound offline root with Assert-OfflineTarget before it is
        touched - the folder once, and each file again as it is deleted - so a degraded or unrooted
        path is refused rather than allowed to delete from the rescue VM's own volume. The backup
        goes into a folder unique to this run, so one run cannot overwrite an earlier run's backups.

        A failure at any point rolls the whole plan back. A partially cleared CLFS log set is worse
        than a full one: the .blf refers to containers that would no longer exist. A rollback that
        itself fails - files now gone with nothing put back - is reported as a distinct, fatal
        outcome (RollbackAttempted true with RollbackSucceeded false), not as an ordinary failure.

        Progress is recorded with Add-OfflineRepairLog rather than Log-*. The Log-* functions write
        to the output stream, so calling one here would put log strings into this function's return
        value and the caller would read them as extra results. The caller flushes the buffer after
        each call instead.

    .OUTPUTS
        PSCustomObject with Label, BackupPath, Removed[], Verification, Success, Reason,
        RollbackAttempted, RollbackSucceeded and RollbackDetail[]. A run where Success is false,
        RollbackAttempted is true and RollbackSucceeded is false is the fatal case: the offline
        image is missing files the rollback could not put back.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $false)][string]$OfflineRoot
    )

    $result = [PSCustomObject]@{
        Label             = $Plan.Label
        BackupPath        = $null
        Removed           = @()
        Verification      = $null
        Success           = $false
        Reason            = $null
        RollbackAttempted = $false
        RollbackSucceeded = $false
        RollbackDetail    = @()
    }

    # Checked here, before anything is copied or deleted, so a script that forgot to dot-source
    # Use-OfflineProtectedResource.ps1 gets one clear sentence instead of an obscure failure part
    # way through a set of deletes.
    if (-not (Get-Command -Name 'Invoke-OfflineProtectedFileRemoval' -ErrorAction SilentlyContinue)) {
        $result.Reason = 'Use-OfflineProtectedResource.ps1 has not been loaded, so a protected file could not be removed. Dot-source it alongside this helper.'
        Add-OfflineRepairLog -Level Error -Message $result.Reason
        return $result
    }

    # The whole set has to sit under the bound offline root. Asserted once here, loudly, before a
    # single byte is copied or deleted: a caller that passes a degraded C:\ path, or forgot to bind
    # a disk at all, is refused outright rather than allowed to clear files off the rescue VM's own
    # volume.
    try {
        if ($PSBoundParameters.ContainsKey('OfflineRoot') -and $OfflineRoot) {
            [void](Assert-OfflineTarget -Path $Plan.Path -OfflineRoot $OfflineRoot -Action 'delete')
        }
        else {
            [void](Assert-OfflineTarget -Path $Plan.Path -Action 'delete')
        }
    }
    catch {
        $result.Reason = "the target folder is not on the offline disk: $($_.Exception.Message)"
        Add-OfflineRepairLog -Level Error -Message $result.Reason
        return $result
    }

    # A folder unique to this run - label, PID and a millisecond timestamp - so a second run can
    # never write over the first run's backups and destroy the only copy of the originals.
    $runStamp = '{0}_{1}_{2}' -f $Plan.Label, $PID, (Get-Date -Format 'yyyyMMddHHmmssfff')
    $backupPath = Join-Path $BackupRoot $runStamp
    try { New-Item -Path $backupPath -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch {
        $result.Reason = "the backup folder $backupPath could not be created: $($_.Exception.Message)"
        Add-OfflineRepairLog -Level Error -Message $result.Reason
        return $result
    }
    # Belt and braces: even with the unique name, refuse to reuse a folder that already holds files
    # rather than risk overwriting a backup that is somehow already there.
    if (@(Get-ChildItem -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue).Count -gt 0) {
        $result.Reason = "the backup folder $backupPath already contains files; refusing to reuse it and risk overwriting a previous backup"
        Add-OfflineRepairLog -Level Error -Message $result.Reason
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

    # Back everything up first. Nothing is deleted until every file has a verified copy. The backup
    # records - each carrying the file's recorded attributes and its owner and DACL - are what a
    # rollback restores from, so they are kept for the rollback calls below.
    $backups = [System.Collections.Generic.List[object]]::new()
    foreach ($file in @($Plan.Snapshot.MatchedFile)) {
        $backup = Backup-OfflineFile -File $file -BackupPath $backupPath
        if (-not $backup.Success) {
            $result.Reason = "$($file.Name) could not be backed up - $($backup.Reason)"
            Add-OfflineRepairLog -Level Error -Message $result.Reason
            return $result
        }
        $backups.Add($backup)
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
        # Assert each resolved path again, immediately before it is deleted. The set-level check
        # above proves the folder is on the offline disk; this proves the individual file still is,
        # closing the gap a caller-supplied or link-redirected path could otherwise slip through.
        try {
            if ($PSBoundParameters.ContainsKey('OfflineRoot') -and $OfflineRoot) {
                [void](Assert-OfflineTarget -Path $file.FullName -OfflineRoot $OfflineRoot -Action 'delete')
            }
            else {
                [void](Assert-OfflineTarget -Path $file.FullName -Action 'delete')
            }
        }
        catch {
            $deleteFailed = "$($file.Name) is not on the offline disk: $($_.Exception.Message)"
            break
        }

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
        $rollback = Restore-OfflineFileSet -BackupPath $backupPath -TargetPath $Plan.Path -FileRecord @($backups)
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.RollbackAttempted = $true
        $result.RollbackSucceeded = [bool]$rollback.Succeeded
        $result.RollbackDetail = @($rollback.Detail)
        # Verdict last, so it survives the 4096-character tail az vm run-command keeps.
        if ($rollback.Succeeded) {
            $result.Reason = "$deleteFailed The set was rolled back and the offline image is unchanged."
            Add-OfflineRepairLog -Level Warning -Message "Removal of '$($Plan.Label)' failed and was rolled back cleanly; the offline image is unchanged."
        }
        else {
            $result.Reason = "FATAL: $deleteFailed The rollback then failed ($($rollback.Restored) of $($rollback.Expected) restored); the offline image is missing files with no restored backup. Recover by hand from $backupPath."
            Add-OfflineRepairLog -Level Error -Message $result.Reason
        }
        return $result
    }

    # Prove it did what it was supposed to and nothing more.
    $verification = Test-OfflineRemovalResult -Plan $Plan -Removed $result.Removed
    $result.Verification = $verification

    foreach ($check in @($verification.Check)) {
        $line = "  [$($check.Status)] $($check.Name): $($check.Detail)"
        switch ($check.Status) {
            'FAIL' { Add-OfflineRepairLog -Level Error -Message $line }
            'INCONCLUSIVE' { Add-OfflineRepairLog -Level Warning -Message $line }
            default { Add-OfflineRepairLog -Message $line }
        }
    }

    if (-not $verification.Passed) {
        Add-OfflineRepairLog -Level Error -Message "Verification failed for $($Plan.Label). Rolling it back."
        $rollback = Restore-OfflineFileSet -BackupPath $backupPath -TargetPath $Plan.Path -FileRecord @($backups)
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.RollbackAttempted = $true
        $result.RollbackSucceeded = [bool]$rollback.Succeeded
        $result.RollbackDetail = @($rollback.Detail)
        # Verdict last, so it survives the 4096-character tail az vm run-command keeps.
        if ($rollback.Succeeded) {
            $result.Reason = ($verification.Failure -join '; ')
            Add-OfflineRepairLog -Level Warning -Message "Verification of '$($Plan.Label)' failed and was rolled back cleanly; the offline image is unchanged."
        }
        else {
            $result.Reason = "FATAL: verification failed and the rollback then failed ($($rollback.Restored) of $($rollback.Expected) restored): $($verification.Failure -join '; '). The offline image is missing files with no restored backup. Recover by hand from $backupPath."
            Add-OfflineRepairLog -Level Error -Message $result.Reason
        }
        return $result
    }

    $result.Success = $true
    # Verdict last. An inconclusive check is a success with a caveat and must not read as a clean,
    # fully proven one. The caveat names the checks that were actually unproven rather than
    # assuming it was the hive check: checks 2 and 3 can also land here, and a hardcoded
    # explanation would confidently report the wrong reason.
    if ($verification.Inconclusive) {
        $unproven = @($verification.Check | Where-Object { $_.Status -eq 'INCONCLUSIVE' })
        $unprovenDetail = ($unproven | ForEach-Object { "$($_.Name) - $($_.Detail)" }) -join '; '
        Add-OfflineRepairLog -Level Warning -Message "Removal of '$($Plan.Label)' succeeded, but $($unproven.Count) check(s) could not be proven: $unprovenDetail"
    }
    else {
        Add-OfflineRepairLog -Message "Removal of '$($Plan.Label)' succeeded and every check passed."
    }
    return $result
}
