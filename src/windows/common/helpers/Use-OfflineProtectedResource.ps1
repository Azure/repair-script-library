<#
.SYNOPSIS
    Taking ownership of a TrustedInstaller-owned file, folder or offline registry key just long
    enough to repair it, and putting the original security descriptor back afterwards.

.DESCRIPTION
    The servicing state a repair has to reach is deliberately protected. WinSxS is owned by
    NT SERVICE\TrustedInstaller and denies write even to Administrators, and the CBS pending keys
    carry their own ACL that denies delete. Running as SYSTEM is not enough: SYSTEM is not the
    owner, and only the owner can rewrite a DACL.

    Measured on a real Server 2022 disk with servicing markers planted, an offline repair running
    as SYSTEM could not rename WinSxS\pending.xml and could not delete CBS\PackagesPending or
    CBS\RebootPending. Every attempt failed, and the run still reported success.

    This helper closes that gap without leaving the disk less protected than it found it:

      1. The original descriptor is captured first, in SDDL form, including owner and group.

      2. Ownership is taken, and only then is an access rule added - a DACL cannot be written by
         an account that does not own the object.

      3. The captured descriptor is replayed WHOLE afterwards. It is never rebuilt rule by rule,
         and the granted ACE is never removed individually. Both of those approaches also drop
         the ACEs Windows shipped, which silently damages WinSxS and the component store. Replay
         restores the owner as well, so TrustedInstaller gets its object back.

      4. Ownership is only taken when it is actually needed. Every operation is attempted plainly
         first and the result is verified; the elevated path runs only if the plain one was
         refused. On a disk where the ACLs are already permissive, nothing is touched at all.

    Restoring an owner that is not the current account requires SeRestorePrivilege, and taking an
    owner requires SeTakeOwnershipPrivilege, so both are enabled up front. Without SeRestore the
    object could be taken but never handed back, which is the worst of the three outcomes.

.NOTES
    Registry handles are closed explicitly and the finalizer queue is drained before returning.
    A single leaked RegistryKey handle makes the later 'reg unload' fail, which strands the
    offline hive mounted under HKLM on the rescue VM.
#>

$script:OfflinePrivilegeReady = $false
$script:OfflineBackupPrivilegeReady = $false

# Owner, Group and Access. SACL is deliberately not captured or replayed: reading it needs
# SeSecurityPrivilege and writing it back can fail on its own, and nothing here changes auditing.
$script:OfflineSecuritySection = 'Owner,Group,Access'

function Initialize-OfflinePrivilegeType {
    <#
    .SYNOPSIS
        Compiling the token-privilege helper both privilege paths use.

    .DESCRIPTION
        Separate from the functions that enable privileges so that the ownership path and the
        backup path share one type rather than each carrying a copy of the same P/Invoke.
    #>
    [CmdletBinding()]
    param()

    if (-not ('OfflineRepairPrivilege' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class OfflineRepairPrivilege
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint length, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    public static bool Enable(string privilegeName)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020u | 0x0008u, out token)) { return false; }
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) { return false; }
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privilege.Luid = luid;
            tp.Privilege.Attributes = 0x00000002u;
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) { return false; }
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }
}
'@
    }
}

function Enable-OfflineOwnershipPrivilege {
    <#
    .SYNOPSIS
        Enabling the token privileges that taking and returning ownership need.

    .DESCRIPTION
        SeTakeOwnershipPrivilege allows taking an object whose DACL denies WRITE_OWNER.
        SeRestorePrivilege allows setting the owner to somebody other than the caller, which is
        what putting TrustedInstaller back requires.
        SeBackupPrivilege and SeSecurityPrivilege allow reading a descriptor the DACL would
        otherwise hide, so the capture is complete before anything is changed.
    #>
    [CmdletBinding()]
    param()

    if ($script:OfflinePrivilegeReady) { return }

    Initialize-OfflinePrivilegeType

    foreach ($privilege in @('SeTakeOwnershipPrivilege', 'SeRestorePrivilege', 'SeBackupPrivilege', 'SeSecurityPrivilege')) {
        if (-not [OfflineRepairPrivilege]::Enable($privilege)) {
            Add-OfflineRepairLog -Level Info -Message "$privilege could not be enabled. It is not held by this token, so a protected object may stay protected."
        }
    }

    $script:OfflinePrivilegeReady = $true
}

function Enable-OfflineBackupPrivilege {
    <#
    .SYNOPSIS
        Enabling only the two privileges that reading and writing a key through the backup path needs.

    .DESCRIPTION
        Deliberately narrower than Enable-OfflineOwnershipPrivilege: it does not enable
        SeTakeOwnershipPrivilege, so a detection pass that only ever reads cannot accidentally
        acquire the right to take an object it was only meant to look at.
    #>
    [CmdletBinding()]
    param()

    if ($script:OfflineBackupPrivilegeReady) { return $true }

    Initialize-OfflinePrivilegeType

    $ok = $true
    foreach ($privilege in @('SeBackupPrivilege', 'SeRestorePrivilege')) {
        if (-not [OfflineRepairPrivilege]::Enable($privilege)) {
            $ok = $false
            Add-OfflineRepairLog -Level Info -Message "$privilege could not be enabled. A key whose DACL denies this account will stay unreadable."
        }
    }

    $script:OfflineBackupPrivilegeReady = $ok
    return $ok
}

function Get-OfflineCurrentUserSid {
    <#
    .SYNOPSIS
        The SID this process runs as, which is the account ownership is taken by.
    #>
    [CmdletBinding()]
    param()

    return ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User
}

function ConvertTo-OfflineNativeSubKey {
    <#
    .SYNOPSIS
        Turning a PowerShell registry path into the subkey string the Win32 registry APIs want.

    .DESCRIPTION
        The provider hands back three shapes depending on how a key was reached, and the .NET
        RegistryKey APIs accept none of them: they want the path below the hive with no root.
        Returns $null for anything that is not under HKLM, because every offline hive this
        library mounts is mounted there.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match 'HKEY_LOCAL_MACHINE\\(.+)$') { return $Matches[1] }
    if ($Path -match '^HKLM:\\(.+)$') { return $Matches[1] }
    if ($Path -match '^HKLM\\(.+)$') { return $Matches[1] }
    return $null
}

function Get-OfflineRegistryKeySecurity {
    <#
    .SYNOPSIS
        Capturing a registry key's owner, group and DACL as SDDL, before anything is changed.

    .DESCRIPTION
        Returns $null when the descriptor cannot be read. A caller that gets $null must not take
        ownership: without a capture there is nothing to put back, and an object left owned by
        SYSTEM with an extra FullControl ACE is a permanent change to a system it was only meant
        to borrow.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) { return $null }

    $key = $null
    try {
        $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, $rights)
        if (-not $key) { return $null }

        $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
                    [System.Security.AccessControl.AccessControlSections]::Group -bor
                    [System.Security.AccessControl.AccessControlSections]::Access
        return $key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($script:OfflineSecuritySection)
    }
    catch { return $null }
    finally { if ($key) { $key.Close() } }
}

function Grant-OfflineRegistryKeyAccess {
    <#
    .SYNOPSIS
        Taking ownership of an offline hive key and everything below it, capturing what was there.

    .DESCRIPTION
        Deleting a key requires delete rights on that key AND on every subkey beneath it, so the
        whole subtree is covered rather than just the top. The parent is taken first, because its
        children cannot be enumerated reliably until it is readable.

        -NoRecurse covers the key alone. Use it when the target is a value rather than the key,
        because removing a value needs rights on its own key only - and because recursing a key
        like COMPONENTS would walk the entire component store to no purpose.

        Returns the list of captured descriptors, oldest first, for Restore-OfflineRegistrySecurity
        to replay. A key whose descriptor could not be captured is skipped rather than taken.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$NoRecurse
    )

    Enable-OfflineOwnershipPrivilege
    $me = Get-OfflineCurrentUserSid
    $captured = [System.Collections.Generic.List[object]]::new()

    # Enumerate before changing anything: the recursion below opens provider handles, and doing
    # that after ownership changes has been written makes a partial failure harder to unwind.
    $targets = [System.Collections.Generic.List[string]]::new()
    [void]$targets.Add($Path)
    if (-not $NoRecurse) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Recurse -ErrorAction SilentlyContinue)) {
            [void]$targets.Add($child.PSPath)
        }
    }

    foreach ($target in $targets) {
        $subKey = ConvertTo-OfflineNativeSubKey -Path $target
        if (-not $subKey) { continue }

        $sddl = Get-OfflineRegistryKeySecurity -Path $target
        if (-not $sddl) {
            Add-OfflineRepairLog -Level Info -Message "Could not read the security descriptor of $subKey, so its ownership was left alone."
            continue
        }

        $ownerKey = $null
        try {
            $ownerKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($ownerKey) {
                # Only the owner is set on this descriptor, so only the owner section is written
                # and the existing DACL survives until it is deliberately changed below.
                $ownerOnly = [System.Security.AccessControl.RegistrySecurity]::new()
                $ownerOnly.SetOwner($me)
                $ownerKey.SetAccessControl($ownerOnly)
            }
        }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not take ownership of $subKey : $($_.Exception.Message)"
        }
        finally { if ($ownerKey) { $ownerKey.Close() } }

        $accessKey = $null
        try {
            $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
                      [System.Security.AccessControl.RegistryRights]::ChangePermissions
            $accessKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
            if ($accessKey) {
                $access = $accessKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
                $access.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new(
                        $me, 'FullControl', 'None', 'None', 'Allow'))
                $accessKey.SetAccessControl($access)
            }
        }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not grant access on $subKey : $($_.Exception.Message)"
        }
        finally { if ($accessKey) { $accessKey.Close() } }

        [void]$captured.Add([PSCustomObject]@{ Path = $target; SubKey = $subKey; Sddl = $sddl })
    }

    # The provider opens keys of its own while enumerating. Releasing them here is what keeps the
    # later 'reg unload' from failing and stranding the hive mounted on the rescue VM.
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    return $captured
}

function Restore-OfflineRegistrySecurity {
    <#
    .SYNOPSIS
        Replaying captured registry descriptors, so every key that survives is as it was found.

    .DESCRIPTION
        Keys that no longer exist are skipped, because a key that was successfully deleted has
        nothing to restore - that is the normal outcome, not an error. The descriptor is replayed
        whole rather than by removing the ACE that was added, which also puts the owner back.

        Returns the number of keys whose descriptor was successfully replayed.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Captured)

    Enable-OfflineOwnershipPrivilege
    $restored = 0

    # Deepest first: a parent's DACL may deny what a child still needs to be written.
    $ordered = @($Captured | Sort-Object -Property { ($_.SubKey -split '\\').Count } -Descending)

    foreach ($entry in $ordered) {
        if (-not $entry.SubKey -or -not $entry.Sddl) { continue }

        $key = $null
        try {
            $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
                      [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                      [System.Security.AccessControl.RegistryRights]::TakeOwnership
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $entry.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
            if (-not $key) { continue }

            $sd = [System.Security.AccessControl.RegistrySecurity]::new()
            $sd.SetSecurityDescriptorSddlForm($entry.Sddl, $script:OfflineSecuritySection)
            $key.SetAccessControl($sd)
            $restored++
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not restore the original ACL on $($entry.SubKey): $($_.Exception.Message). Restore it by hand with: subinacl /keyreg `"$($entry.SubKey)`" /setowner=`"NT SERVICE\TrustedInstaller`""
        }
        finally { if ($key) { $key.Close() } }
    }

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    return $restored
}

function Invoke-OfflineKeyDeleteAttempt {
    <#
    .SYNOPSIS
        Deleting a key and reporting why if it is refused.

    .DESCRIPTION
        Remove-Item with -ErrorAction SilentlyContinue throws the reason away and leaves the caller
        unable to tell an access-denied delete from a key that was never there. The attempt is made
        with -ErrorAction Stop instead and the result is still confirmed by re-reading the path,
        because a provider that reports no error is not proof that the key has gone.

        Returns an object with Removed and Reason.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    catch {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [PSCustomObject]@{ Removed = $true; Reason = '' }
        }
        return [PSCustomObject]@{ Removed = $false; Reason = $_.Exception.Message }
    }

    if (Test-Path -LiteralPath $Path) {
        return [PSCustomObject]@{ Removed = $false; Reason = 'the delete reported no error but the key is still present' }
    }
    return [PSCustomObject]@{ Removed = $true; Reason = '' }
}

function Invoke-OfflineProtectedKeyRemoval {
    <#
    .SYNOPSIS
        Deleting an offline hive key, taking ownership only if the plain delete is refused.

    .DESCRIPTION
        The plain attempt runs first and its result is verified by re-reading the path, because a
        delete that is refused must not be mistaken for one that succeeded. Ownership is taken only
        when that verification says the key is still there.

        Both the key and its parent are taken. Deleting a key is a write against the key that
        contains it, so rights on the key alone are not enough - measured on Server 2022, a
        PackagesPending key owned by SYSTEM with FullControl on itself is still refused while its
        parent grants SYSTEM only KEY_READ. The parent is taken without recursing, so no sibling
        of the target is touched.

        A key that is successfully deleted has nothing to put back, but the parent always survives
        and so is always restored. Restore-OfflineRegistrySecurity works deepest first, which puts
        the parent back last - while its rights are still in place for the children beneath it.

        Returns an object with Removed, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = ''
    )

    if (-not $Label) { $Label = $Path }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'The key was not present.' }
    }

    $plain = Invoke-OfflineKeyDeleteAttempt -Path $Path
    if ($plain.Removed) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'Removed without changing any permission.' }
    }

    Add-OfflineRepairLog -Level Info -Message "$Label could not be removed as it stands ($($plain.Reason)). Taking ownership of it and of the key that contains it, deleting, and putting both back."

    $captured = [System.Collections.Generic.List[object]]::new()
    try {
        # The parent first: until it is writable the delete is refused no matter what the target
        # itself grants. -NoRecurse keeps the grant off every sibling of the target.
        $parent = Split-Path -Path $Path -Parent
        if ($parent -and (ConvertTo-OfflineNativeSubKey -Path $parent)) {
            foreach ($entry in @(Grant-OfflineRegistryKeyAccess -Path $parent -NoRecurse)) { [void]$captured.Add($entry) }
        }
        foreach ($entry in @(Grant-OfflineRegistryKeyAccess -Path $Path)) { [void]$captured.Add($entry) }
    }
    catch {
        $undone = Restore-OfflineRegistrySecurity -Captured $captured.ToArray()
        return [PSCustomObject]@{ Removed = $false; TookOwnership = $true; Restored = $undone; Reason = "Ownership could not be taken: $($_.Exception.Message)" }
    }

    $owned = Invoke-OfflineKeyDeleteAttempt -Path $Path

    # Always restore. On success only the parent is left to put back, because the keys below it no
    # longer exist and Restore-OfflineRegistrySecurity skips what has gone.
    $restored = Restore-OfflineRegistrySecurity -Captured $captured.ToArray()

    if ($owned.Removed) {
        return [PSCustomObject]@{
            Removed       = $true
            TookOwnership = $true
            Restored      = $restored
            Reason        = "Removed after taking ownership. $restored surviving descriptor(s) were put back."
        }
    }

    return [PSCustomObject]@{
        Removed       = $false
        TookOwnership = $true
        Restored      = $restored
        Reason        = "The key survived even after ownership was taken ($($owned.Reason)). $restored descriptor(s) were put back."
    }
}

function Invoke-OfflineProtectedValueRemoval {
    <#
    .SYNOPSIS
        Removing a value from an offline hive key, taking the key only if the plain remove fails.

    .DESCRIPTION
        The difference from a key removal is that the key survives, so the descriptor MUST be put
        back - there is no "it is gone, so there is nothing to restore" shortcut here. The restore
        runs in a finally, on every path.

        Only the key itself is taken, never its subkeys: removing a value needs rights on its own
        key. COMPONENTS is the caller this matters for, and recursing it would walk the whole
        component store for no benefit.

        The caller supplies a test rather than a comparison value, because "still set" for these
        markers means non-zero rather than merely present.

        Returns an object with Removed, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$StillSet
    )

    $read = { (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name }

    if (-not (& $StillSet (& $read))) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'The value was not set.' }
    }

    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    if (-not (& $StillSet (& $read))) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'Removed without changing any permission.' }
    }

    Add-OfflineRepairLog -Level Info -Message "$Name is protected by its key's ACL. Taking the key, removing the value, and putting the ACL back."

    $captured = @()
    try { $captured = @(Grant-OfflineRegistryKeyAccess -Path $Path -NoRecurse) }
    catch {
        return [PSCustomObject]@{ Removed = $false; TookOwnership = $false; Restored = 0; Reason = "Ownership could not be taken: $($_.Exception.Message)" }
    }

    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        $removed = -not (& $StillSet (& $read))
    }
    finally {
        # Always. The key is still here, so an unrestored descriptor is a permanent change.
        $restored = Restore-OfflineRegistrySecurity -Captured $captured
    }

    return [PSCustomObject]@{
        Removed       = $removed
        TookOwnership = $true
        Restored      = $restored
        Reason        = $(if ($removed) { "Removed after taking the key. $restored descriptor(s) were put back." }
                          else { "The value survived even after the key was taken. $restored descriptor(s) were put back." })
    }
}

function Test-OfflineRegistryAccessDenied {
    <#
    .SYNOPSIS
        Deciding whether a failed registry operation failed because of an ACL.

    .DESCRIPTION
        An offline hive refuses an operation in two different ways depending on which layer rejects
        it: the provider surfaces UnauthorizedAccessException, while the RegistryKey APIs raise
        SecurityException. Either one means "the ACL said no", and only those two are worth retrying
        behind an ownership change.

        Everything else - a missing key, a wrong value type - must keep failing loudly. Retrying
        those behind an ownership change would rewrite a security descriptor to work around a bug in
        the caller, and then still fail.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException]) { return $true }
        $ex = $ex.InnerException
    }
    return $false
}

function Get-OfflineNearestExistingKey {
    <#
    .SYNOPSIS
        Finding the key whose ACL actually governs an operation on a path that may not exist yet.

    .DESCRIPTION
        Setting a value needs rights on its own key, but creating a key needs rights on the nearest
        ancestor that already exists, because that is the descriptor consulted when the first
        missing level is created. Taking the leaf would be taking something that is not there.

        Returns $null when nothing on the path exists, which for a mounted hive means the caller was
        given a path outside it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) { return $current }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    return $null
}

function Invoke-OfflineProtectedRegistryWrite {
    <#
    .SYNOPSIS
        Writing to an offline hive key, taking the key only if the plain write is refused.

    .DESCRIPTION
        The write counterpart of Invoke-OfflineProtectedValueRemoval, and it exists for the same
        reason: a key in an offline hive can be owned by TrustedInstaller and deny write to
        Administrators, so a repair reports success having changed nothing.

        The plain write is attempted first and the descriptor is only touched when the write is
        actually refused. That matters more here than it does for a removal, because this sits
        behind every value a repair sets: unconditionally rewriting a descriptor per value would be
        slow and would be a change the guest never asked for. The overwhelming majority of writes
        take the fast path and cost nothing.

        Only the guarded key itself is taken, never its subtree. Setting a value needs KEY_SET_VALUE
        on one key, and recursing a key like Services would rewrite the descriptor of every key
        beneath it for no benefit.

        The restore runs in a finally, so a write that fails after ownership was taken still leaves
        the descriptor as it was found. Returns an object with Written, TookOwnership, Restored and
        Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $false)][string]$Description = 'the value'
    )

    try {
        & $Action
        return [PSCustomObject]@{ Written = $true; TookOwnership = $false; Restored = 0; Reason = 'Written without changing any permission.' }
    }
    catch {
        $firstError = $_
        if (-not (Test-OfflineRegistryAccessDenied -ErrorRecord $firstError)) { throw }
    }

    # Captured before anything changes so the descriptor can be replayed verbatim. A path that
    # cannot be addressed by these APIs leaves the original access-denied error as the honest answer.
    $guardPath = Get-OfflineNearestExistingKey -Path $Path
    if (-not $guardPath) { throw $firstError }

    Add-OfflineRepairLog -Level Info -Message "$guardPath is protected by its own ACL. Taking the key to write $Description, then putting the ACL back."

    $captured = @()
    try { $captured = @(Grant-OfflineRegistryKeyAccess -Path $guardPath -NoRecurse) }
    catch {
        [void](Restore-OfflineRegistrySecurity -Captured $captured)
        return [PSCustomObject]@{ Written = $false; TookOwnership = $false; Restored = 0; Reason = "Ownership could not be taken: $($_.Exception.Message)" }
    }

    $written = $false
    $failure = $null
    try {
        & $Action
        $written = $true
    }
    catch { $failure = $_ }
    finally {
        # Always. The key is still here, so an unrestored descriptor is a permanent change to a
        # system this script was only meant to borrow.
        $restored = Restore-OfflineRegistrySecurity -Captured $captured
    }

    return [PSCustomObject]@{
        Written       = $written
        TookOwnership = $true
        Restored      = $restored
        Reason        = $(if ($written) { "Written after taking the key. $restored descriptor(s) were put back." }
                          else { "The write still failed after the key was taken ($($failure.Exception.Message)). $restored descriptor(s) were put back." })
    }
}

function Get-OfflineProtectedRegistryValue {
    <#
    .SYNOPSIS
        Reading a value from an offline hive key that may deny read to Administrators.

    .DESCRIPTION
        The read counterpart of Invoke-OfflineProtectedRegistryWrite. A key locked to SYSTEM:Read
        denies Administrators even READ_CONTROL, so reporting the current value of a guarded key
        needs the same ownership dance the write does.

        -Found distinguishes "the value is genuinely not set" from "the value could not be read",
        which are different outcomes and must not be confused: mislabelling a locked value as absent
        is how a repair ends up logging 'was: (not set)' about a value it never managed to see, and
        then writing a default over something it never looked at.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)]$DefaultValue = $null,
        [Parameter(Mandatory = $false)][ref]$Found,
        [Parameter(Mandatory = $false)][ref]$Denied
    )

    if ($Found) { $Found.Value = $false }
    if ($Denied) { $Denied.Value = $false }

    $read = {
        $props = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($props -and ($props.PSObject.Properties.Name -contains $Name)) {
            if ($Found) { $Found.Value = $true }
            return $props.$Name
        }
        return $DefaultValue
    }

    try { return & $read }
    catch {
        if (-not (Test-OfflineRegistryAccessDenied -ErrorRecord $_)) { return $DefaultValue }
    }

    if ($Denied) { $Denied.Value = $true }

    $guardPath = Get-OfflineNearestExistingKey -Path $Path
    if (-not $guardPath) { return $DefaultValue }

    $captured = @()
    try { $captured = @(Grant-OfflineRegistryKeyAccess -Path $guardPath -NoRecurse) }
    catch {
        [void](Restore-OfflineRegistrySecurity -Captured $captured)
        return $DefaultValue
    }

    try { return & $read }
    catch { return $DefaultValue }
    finally { [void](Restore-OfflineRegistrySecurity -Captured $captured) }
}

function Get-OfflinePathSecurity {
    <#
    .SYNOPSIS
        Capturing a file or folder's owner, group and DACL as SDDL.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetSecurityDescriptorSddlForm($script:OfflineSecuritySection)
    }
    catch { return $null }
}

function Get-OfflineSddlOwner {
    <#
    .SYNOPSIS
        Reading just the owner SID out of a captured SDDL string.

    .DESCRIPTION
        Used to decide whether the owner needs writing at all. Rewriting an owner to the value it
        already holds still demands WRITE_OWNER, so skipping it is both less privileged and less
        of a change to an object this script is only borrowing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Sddl)

    if (-not $Sddl) { return '' }
    try {
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if ($raw.Owner) { return $raw.Owner.Value }
        return ''
    }
    catch { return '' }
}

function Save-OfflinePathSecurity {
    <#
    .SYNOPSIS
        Writing a partial security descriptor back to a file or folder.

    .DESCRIPTION
        Set-Acl is deliberately not used. It refuses a protected DACL - the D:P shape that WinSxS
        and every other hardened folder carries - unless the caller holds SeSecurityPrivilege, even
        though nothing about the write touches auditing. The .NET call writes only the sections the
        descriptor object records as modified and has no such requirement.

        These statics exist in the Windows PowerShell that az vm run-command starts on the rescue
        VM, which is the only place this library runs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$Security,
        [switch]$IsDirectory
    )

    if ($IsDirectory) { [System.IO.Directory]::SetAccessControl($Path, $Security) }
    else { [System.IO.File]::SetAccessControl($Path, $Security) }
}

function Grant-OfflinePathAccess {
    <#
    .SYNOPSIS
        Taking ownership of a file or folder and granting this account FullControl.

    .DESCRIPTION
        Returns the captured SDDL, or $null when it could not be captured - in which case nothing
        is changed, because an object that cannot be handed back should not be taken.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    Enable-OfflineOwnershipPrivilege

    $original = Get-OfflinePathSecurity -Path $Path
    if (-not $original) {
        Add-OfflineRepairLog -Level Info -Message "Could not read the security descriptor of $Path, so its ownership was left alone."
        return $null
    }

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $isDirectory = $item.PSIsContainer
    $me = Get-OfflineCurrentUserSid

    # Owner first and on its own, but only when it is not already ours. A DACL cannot be written by
    # an account that does not own the object, so ownership has to come first where it is needed -
    # yet writing the owner back to the value it already holds is a privileged write that buys
    # nothing, and an existing owner already carries the WRITE_DAC the grant below needs.
    if ((Get-OfflineSddlOwner -Sddl $original) -ne $me.Value) {
        $ownerOnly = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
        $ownerOnly.SetOwner($me)
        Save-OfflinePathSecurity -Path $Path -Security $ownerOnly -IsDirectory:$isDirectory
    }

    # Built from the captured SDDL rather than from Get-Acl, so that only the DACL is ever written.
    # A descriptor that carries the SACL along demands SeSecurityPrivilege for a change that has
    # nothing to do with auditing, and fails for that reason alone.
    # The granted ACE deliberately does not inherit: pushing it onto children would alter
    # descriptors that were never captured and so could never be put back. Callers that need a
    # child as well take that child in its own right.
    $acl = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
    $acl.SetSecurityDescriptorSddlForm($original, 'Access')
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $me, 'FullControl', 'None', 'None', 'Allow'))
    Save-OfflinePathSecurity -Path $Path -Security $acl -IsDirectory:$isDirectory

    return $original
}

function Restore-OfflinePathSecurity {
    <#
    .SYNOPSIS
        Replaying a descriptor captured by Grant-OfflinePathAccess.

    .DESCRIPTION
        Replayed whole, never rebuilt. Removing the granted ACE individually - the icacls
        /remove:g shape - also drops the inherited and shipped ACEs alongside it, which is how
        WinSxS ends up quietly damaged by a repair that looked like it cleaned up after itself.

        A missing path is not an error: the caller may legitimately offer both the original and
        the renamed path without knowing which one survived.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Sddl = ''
    )

    if (-not $Sddl) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    Enable-OfflineOwnershipPrivilege

    # Only the sections that actually differ are written. If ownership was never taken - because it
    # was already ours - then replaying the owner would be a privileged write with no effect, and
    # on a restricted account it would fail and take the DACL restore down with it.
    $sections = $script:OfflineSecuritySection
    $capturedOwner = Get-OfflineSddlOwner -Sddl $Sddl
    if ($capturedOwner -and $capturedOwner -eq (Get-OfflineSddlOwner -Sddl (Get-OfflinePathSecurity -Path $Path))) {
        $sections = 'Access'
    }

    try {
        $isDirectory = (Get-Item -LiteralPath $Path -Force).PSIsContainer
        $sd = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
        $sd.SetSecurityDescriptorSddlForm($Sddl, $sections)
        Save-OfflinePathSecurity -Path $Path -Security $sd -IsDirectory:$isDirectory
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not restore the original ACL on $Path : $($_.Exception.Message). Restore it by hand with: icacls `"$Path`" /setowner `"NT SERVICE\TrustedInstaller`""
        return $false
    }
}

function Rename-OfflineProtectedFile {
    <#
    .SYNOPSIS
        Renaming a file in a protected folder, taking the folder only if the plain rename fails.

    .DESCRIPTION
        Both the parent folder and the file are taken, because a rename needs rights on both and
        neither alone is enough. The parent supplies FILE_ADD_FILE for the new name; the file
        supplies the DELETE that Rename-Item asks for when it opens the source. Granting on the
        parent with inheritance would cover the file too, but it would also rewrite every other
        child's descriptor - descriptors that were never captured and so could never be handed
        back. Taking the one file explicitly changes exactly what has to change.

        Both descriptors are put back in a finally, so they are restored whether the rename
        succeeded, failed, or threw, and the file is restored first while the parent rights that
        make it reachable are still in place. Leaving WinSxS owned by SYSTEM would be a lasting
        weakening of a folder this script only needed to borrow for one rename.

        Returns an object with Renamed, NewPath, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$NewName
    )

    # The existence check itself can be refused on a protected folder, which is a symptom of the
    # very problem this function exists to solve rather than a reason to give up. Only a clean
    # "not there" answer counts as absent; a denied check falls through to the escalation below.
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            return [PSCustomObject]@{ Renamed = $false; NewPath = ''; TookOwnership = $false; Restored = $false; Reason = 'The file was not present.' }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Whether $Path exists could not even be checked ($($_.Exception.Message)). Treating that as protection rather than absence."
    }

    $parent = Split-Path -Path $Path -Parent
    $target = Join-Path $parent $NewName

    try {
        Rename-Item -LiteralPath $Path -NewName $NewName -Force -ErrorAction Stop
        return [PSCustomObject]@{ Renamed = $true; NewPath = $target; TookOwnership = $false; Restored = $false; Reason = 'Renamed without changing any permission.' }
    }
    catch {
        $firstError = $_.Exception.Message
    }

    Add-OfflineRepairLog -Level Info -Message "$Path could not be renamed ($firstError). Taking ownership of $parent, retrying, and putting its ACL back either way."

    $originalSddl = $null
    $fileSddl = $null
    $absent = $false
    $renamed = $false
    try {
        $originalSddl = Grant-OfflinePathAccess -Path $parent
        if (-not $originalSddl) {
            return [PSCustomObject]@{ Renamed = $false; NewPath = ''; TookOwnership = $false; Restored = $false; Reason = "The folder's security descriptor could not be read, so its ownership was left alone. Original error: $firstError" }
        }

        # Now that the folder can be read, the earlier check can be trusted. Saying "the rename was
        # refused" about a file that was never there would send an operator hunting for a
        # permissions problem that does not exist.
        if (-not (Test-Path -LiteralPath $Path)) {
            $absent = $true
            $reason = 'The file was not present once the folder could be read.'
        }
        else {
            $fileSddl = Grant-OfflinePathAccess -Path $Path
            Rename-Item -LiteralPath $Path -NewName $NewName -Force -ErrorAction Stop
            $renamed = $true
            $reason = 'Renamed after taking ownership of the file and its parent folder.'
        }
    }
    catch {
        $reason = "The rename was still refused after taking ownership of the file and its parent folder: $($_.Exception.Message)"
    }
    finally {
        # Always, on every path. Both objects were borrowed, not acquired. The file goes back
        # first, under whichever name it ended up with, while the parent still grants access to it.
        $restoredFile = $true
        if ($fileSddl) {
            $restoredFile = Restore-OfflinePathSecurity -Path $(if ($renamed) { $target } else { $Path }) -Sddl $fileSddl
        }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $originalSddl) -and $restoredFile
    }

    return [PSCustomObject]@{
        Renamed       = $renamed
        NewPath       = $(if ($renamed) { $target } else { '' })
        TookOwnership = -not $absent
        Restored      = [bool]$restored
        Reason        = $reason
    }
}

function Clear-OfflineBlockingAttribute {
    <#
    .SYNOPSIS
        Clearing the attributes that stop a file being deleted or renamed.

    .DESCRIPTION
        ReadOnly, Hidden and System all refuse a delete, and the write that clears them is itself
        refused on a protected file - which is why this is called again after ownership is taken
        rather than only before. Failure is deliberately swallowed: the attribute clear is a step
        towards the delete, not the point of it, and the delete reports its own error.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $blocking = ([System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
        if ($item.Attributes -band $blocking) {
            $item.Attributes = ($item.Attributes -band (-bnot $blocking))
        }
    }
    catch {
        # Deliberately swallowed. Clearing the attributes is a step towards the delete, not the
        # point of it, and on a protected file this write is refused for the same reason the delete
        # was - which the caller is about to handle by taking ownership and calling this again.
        Write-Verbose "Attributes on $Path could not be cleared: $($_.Exception.Message)"
    }
}

function Invoke-OfflineProtectedFileRemoval {
    <#
    .SYNOPSIS
        Deleting a file in a protected folder, taking the folder only if the plain delete fails.

    .DESCRIPTION
        The same shape as Rename-OfflineProtectedFile, and for the same reason: deleting a file is a
        write to the folder that contains it, so rights on the file alone are not enough. The parent
        supplies FILE_DELETE_CHILD and the file supplies the DELETE that Remove-Item asks for when it
        opens the source. Both are taken, and both are handed straight back in a finally.

        Ownership is only taken after an ordinary delete has actually been refused. A folder whose
        permissions were never in the way is never touched, so the common case leaves no trace.

        The blocking attributes are cleared twice on purpose. The first attempt is part of the plain
        delete; the second happens after ownership is taken, because on a genuinely protected file
        the attribute write is refused for exactly the same reason the delete was.

        Only the parent's descriptor is restored when the file goes, because a deleted file has no
        descriptor to hand back. That is not a failure, and it is not counted as one.

        Returns an object with Removed, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    # A denied existence check is a symptom of the problem this function exists to solve, not an
    # answer. Only a clean "not there" counts as absent.
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            return [PSCustomObject]@{ Removed = $false; TookOwnership = $false; Restored = $false; Absent = $true; Reason = 'The file was not present.' }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Whether $Path exists could not even be checked ($($_.Exception.Message)). Treating that as protection rather than absence."
    }

    try {
        Clear-OfflineBlockingAttribute -Path $Path
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = $false; Absent = $false; Reason = 'Removed without changing any permission.' }
    }
    catch {
        $firstError = $_.Exception.Message
    }

    $parent = Split-Path -Path $Path -Parent
    Add-OfflineRepairLog -Level Info -Message "$Path could not be removed ($firstError). Taking ownership of $parent, retrying, and putting its ACL back either way."

    $parentSddl = $null
    $fileSddl = $null
    $removed = $false
    $absent = $false
    try {
        $parentSddl = Grant-OfflinePathAccess -Path $parent
        if (-not $parentSddl) {
            return [PSCustomObject]@{ Removed = $false; TookOwnership = $false; Restored = $false; Absent = $false; Reason = "The folder's security descriptor could not be read, so its ownership was left alone. Original error: $firstError" }
        }

        # Now that the folder can be read, the earlier check can be trusted.
        if (-not (Test-Path -LiteralPath $Path)) {
            $absent = $true
            $reason = 'The file was not present once the folder could be read.'
        }
        else {
            $fileSddl = Grant-OfflinePathAccess -Path $Path
            Clear-OfflineBlockingAttribute -Path $Path
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            $removed = $true
            $reason = 'Removed after taking ownership of the file and its parent folder.'
        }
    }
    catch {
        $reason = "The delete was still refused after taking ownership of the file and its parent folder: $($_.Exception.Message)"
    }
    finally {
        # The file's descriptor is only restorable when the file survived. Restoring a path that was
        # successfully deleted would report false, which must not be read as a failure to hand back.
        $restoredFile = $true
        if ($fileSddl -and -not $removed) {
            $restoredFile = Restore-OfflinePathSecurity -Path $Path -Sddl $fileSddl
        }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $parentSddl) -and $restoredFile
    }

    return [PSCustomObject]@{
        Removed       = $removed
        TookOwnership = -not $absent
        Restored      = [bool]$restored
        Absent        = $absent
        Reason        = $reason
    }
}

function Copy-OfflineProtectedFile {
    <#
    .SYNOPSIS
        Writing a file into a protected folder, taking ownership only if the plain copy fails.

    .DESCRIPTION
        The same shape as Invoke-OfflineProtectedFileRemoval, and it exists for the same measured
        reason. On a Server 2022 disk attached to a rescue VM, opening
        F:\Windows\System32\winload.efi for write as SYSTEM is refused outright: the file is owned
        by NT SERVICE\TrustedInstaller, and SYSTEM is not the owner. A Copy-Item over the top fails
        just as silently, which is how a repair reports success while having changed nothing.

        Overwriting a file is a write to the file and, when it does not yet exist, a write to the
        folder that will hold it. Both are taken when needed and both are handed straight back in a
        finally, replaying the whole captured descriptor rather than removing the granted ACE.

        The destination keeps its own original descriptor. A replacement file must not inherit the
        rescue VM's idea of what the ACL should be, and it must not be left owned by whoever ran
        the repair - the guest has to boot with TrustedInstaller owning its system files again.

        Returns an object with Copied, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        return [PSCustomObject]@{ Copied = $false; TookOwnership = $false; Restored = $false; Reason = "The source file $Source was not present." }
    }

    $existed = $false
    try { $existed = Test-Path -LiteralPath $Destination -ErrorAction Stop } catch {
        Add-OfflineRepairLog -Level Info -Message "Whether $Destination exists could not even be checked ($($_.Exception.Message)). Treating that as protection rather than absence."
    }

    try {
        if ($existed) { Clear-OfflineBlockingAttribute -Path $Destination }
        Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        return [PSCustomObject]@{ Copied = $true; TookOwnership = $false; Restored = $false; Reason = 'Copied without changing any permission.' }
    }
    catch {
        $firstError = $_.Exception.Message
    }

    $parent = Split-Path -Path $Destination -Parent
    Add-OfflineRepairLog -Level Info -Message "$Destination could not be written ($firstError). Taking ownership of $parent, retrying, and putting its ACL back either way."

    $parentSddl = $null
    $fileSddl = $null
    $copied = $false
    $reason = ''
    try {
        $parentSddl = Grant-OfflinePathAccess -Path $parent
        if (-not $parentSddl) {
            return [PSCustomObject]@{ Copied = $false; TookOwnership = $false; Restored = $false; Reason = "The folder's security descriptor could not be read, so its ownership was left alone. Original error: $firstError" }
        }

        # Re-checked now that the folder can actually be read: the first check ran against a folder
        # that may have been denying us, so its answer could not be trusted.
        if (Test-Path -LiteralPath $Destination) {
            $fileSddl = Grant-OfflinePathAccess -Path $Destination
            Clear-OfflineBlockingAttribute -Path $Destination
        }

        Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        $copied = $true
        $reason = 'Copied after taking ownership of the destination and its parent folder.'
    }
    catch {
        $reason = "The copy was still refused after taking ownership of the destination and its parent folder: $($_.Exception.Message)"
    }
    finally {
        # The destination's own descriptor is replayed onto whatever now sits at that path, so a
        # freshly written file ends up owned by TrustedInstaller exactly as the one it replaced was.
        $restoredFile = $true
        if ($fileSddl) { $restoredFile = Restore-OfflinePathSecurity -Path $Destination -Sddl $fileSddl }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $parentSddl) -and $restoredFile
    }

    return [PSCustomObject]@{
        Copied        = $copied
        TookOwnership = $true
        Restored      = [bool]$restored
        Reason        = $reason
    }
}

#region Privileged registry access
# The functions above take ownership when a DACL refuses. The functions below never do: they open
# the key with REG_OPTION_BACKUP_RESTORE while SeBackupPrivilege and SeRestorePrivilege are held,
# which makes the kernel grant access on the strength of the privilege and skip the DACL check
# entirely. Nothing about the key changes, so a detection pass cannot dirty a healthy machine.
#
# "Privileged" here means "opened by privilege rather than by permission". It has nothing to do
# with Backup-OfflineHiveFile, which copies a hive file.
#
# Use these when a key denies read to everyone including SYSTEM - mpssvc's AppCs key is the known
# example. Use the *-OfflineProtected* functions when the key is merely owned by TrustedInstaller.

function Initialize-OfflinePrivilegedRegistryType {
    <#
    .SYNOPSIS
        Compiling the registry P/Invoke used by the backup-restore path.

    .DESCRIPTION
        The .NET registry classes give no way to pass REG_OPTION_BACKUP_RESTORE, and the PowerShell
        provider gives no way either, so the Win32 API is called directly.

        RegCreateKeyEx is used rather than RegOpenKeyEx because the backup-restore option is only
        honoured by RegCreateKeyEx. That function creates the key when it is absent, which would be
        a write to a machine that may be healthy, so every open checks the disposition it returns
        and removes anything it created before handing the handle back.
    #>
    [CmdletBinding()]
    param()

    if ('OfflinePrivilegedRegistry' -as [type]) { return }

    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class OfflinePrivilegedRegistry
{
    const int REG_OPTION_BACKUP_RESTORE = 0x00000004;
    const int REG_CREATED_NEW_KEY = 1;
    const int KEY_READ = 0x20019;
    const int KEY_WRITE = 0x20006;
    const int ERROR_SUCCESS = 0;
    const int ERROR_NO_MORE_ITEMS = 259;
    const int ERROR_MORE_DATA = 234;
    const int ERROR_ALREADY_EXISTS = 183;
    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegCreateKeyExW(IntPtr hKey, string lpSubKey, int Reserved, string lpClass,
        int dwOptions, int samDesired, IntPtr lpSecurityAttributes, out IntPtr phkResult,
        out int lpdwDisposition);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegDeleteKeyW(IntPtr hKey, string lpSubKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegEnumValueW(IntPtr hKey, int dwIndex, StringBuilder lpValueName,
        ref int lpcchValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, IntPtr lpcbData);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegEnumKeyExW(IntPtr hKey, int dwIndex, StringBuilder lpName, ref int lpcchName,
        IntPtr lpReserved, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved,
        out int lpType, byte[] lpData, ref int lpcbData);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegDeleteValueW(IntPtr hKey, string lpValueName);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegSetValueExW(IntPtr hKey, string lpValueName, int Reserved, int dwType,
        byte[] lpData, int cbData);

    // Opens an existing key through the backup path. Never leaves a key behind that it created:
    // if the disposition says the key was new, it is deleted again and the call reports failure,
    // so a caller can treat a non-zero result as "not there" without having changed anything.
    static int Open(string subKey, bool forWrite, out IntPtr handle)
    {
        handle = IntPtr.Zero;
        int disposition;
        int access = forWrite ? (KEY_READ | KEY_WRITE) : KEY_READ;
        int rc = RegCreateKeyExW(HKLM, subKey, 0, null, REG_OPTION_BACKUP_RESTORE, access,
                                 IntPtr.Zero, out handle, out disposition);
        if (rc != ERROR_SUCCESS) { handle = IntPtr.Zero; return rc; }
        if (disposition == REG_CREATED_NEW_KEY)
        {
            RegCloseKey(handle);
            RegDeleteKeyW(HKLM, subKey);
            handle = IntPtr.Zero;
            return ERROR_ALREADY_EXISTS;
        }
        return ERROR_SUCCESS;
    }

    public static int KeyExists(string subKey, out bool exists)
    {
        exists = false;
        IntPtr h;
        int rc = Open(subKey, false, out h);
        if (rc == ERROR_ALREADY_EXISTS) { return ERROR_SUCCESS; }
        if (rc != ERROR_SUCCESS) { return rc; }
        RegCloseKey(h);
        exists = true;
        return ERROR_SUCCESS;
    }

    // Deliberately creates the key when it is absent, and says which happened. Kept separate from
    // Open on purpose: Open guarantees that reading or correcting a value never adds anything to a
    // machine that may be healthy, so the one operation allowed to add has to be asked for by name.
    public static int CreateKey(string subKey, out bool created)
    {
        created = false;
        IntPtr h;
        int disposition;
        int rc = RegCreateKeyExW(HKLM, subKey, 0, null, REG_OPTION_BACKUP_RESTORE,
                                 KEY_READ | KEY_WRITE, IntPtr.Zero, out h, out disposition);
        if (rc != ERROR_SUCCESS) { return rc; }
        created = (disposition == REG_CREATED_NEW_KEY);
        RegCloseKey(h);
        return ERROR_SUCCESS;
    }

    public static int SubKeyNames(string subKey, out string[] names)
    {
        names = new string[0];
        IntPtr h;
        int rc = Open(subKey, false, out h);
        if (rc != ERROR_SUCCESS) { return rc; }
        try
        {
            List<string> found = new List<string>();
            for (int i = 0; ; i++)
            {
                StringBuilder sb = new StringBuilder(256);
                int len = sb.Capacity;
                int r = RegEnumKeyExW(h, i, sb, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (r == ERROR_NO_MORE_ITEMS) { break; }
                if (r != ERROR_SUCCESS) { return r; }
                found.Add(sb.ToString());
            }
            names = found.ToArray();
            return ERROR_SUCCESS;
        }
        finally { RegCloseKey(h); }
    }

    public static int ValueNames(string subKey, out string[] names)
    {
        names = new string[0];
        IntPtr h;
        int rc = Open(subKey, false, out h);
        if (rc != ERROR_SUCCESS) { return rc; }
        try
        {
            List<string> found = new List<string>();
            for (int i = 0; ; i++)
            {
                // 16383 characters is the documented maximum length of a value name.
                StringBuilder sb = new StringBuilder(16384);
                int len = sb.Capacity;
                int r = RegEnumValueW(h, i, sb, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (r == ERROR_NO_MORE_ITEMS) { break; }
                if (r != ERROR_SUCCESS) { return r; }
                found.Add(sb.ToString());
            }
            names = found.ToArray();
            return ERROR_SUCCESS;
        }
        finally { RegCloseKey(h); }
    }

    public static int GetValue(string subKey, string name, out int type, out byte[] data)
    {
        type = 0;
        data = null;
        IntPtr h;
        int rc = Open(subKey, false, out h);
        if (rc != ERROR_SUCCESS) { return rc; }
        try
        {
            int size = 0;
            int r = RegQueryValueExW(h, name, IntPtr.Zero, out type, null, ref size);
            if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) { return r; }
            byte[] buffer = new byte[size];
            r = RegQueryValueExW(h, name, IntPtr.Zero, out type, buffer, ref size);
            if (r != ERROR_SUCCESS) { return r; }
            data = buffer;
            return ERROR_SUCCESS;
        }
        finally { RegCloseKey(h); }
    }

    public static int DeleteValue(string subKey, string name)
    {
        IntPtr h;
        int rc = Open(subKey, true, out h);
        if (rc != ERROR_SUCCESS) { return rc; }
        try { return RegDeleteValueW(h, name); }
        finally { RegCloseKey(h); }
    }

    // The caller supplies the type as well as the bytes. The LSA policy database stores the
    // logon-right mask as REG_NONE, and rewriting it as REG_BINARY or REG_DWORD changes the shape
    // of the value even when the four bytes are identical, so the type is never inferred here.
    public static int SetValue(string subKey, string name, int type, byte[] data)
    {
        IntPtr h;
        int rc = Open(subKey, true, out h);
        if (rc != ERROR_SUCCESS) { return rc; }
        try { return RegSetValueExW(h, name, 0, type, data, data.Length); }
        finally { RegCloseKey(h); }
    }
}
"@
}

function Get-OfflinePrivilegedRegistryValueName {
    <#
    .SYNOPSIS
        Listing the value names under a key that may deny read to every account, SYSTEM included.

    .DESCRIPTION
        Returns an object rather than a bare list, because "the key holds no values" and "the key
        could not be opened" are different answers and must not be confused. Ok is $false only when
        something went wrong; a key that is genuinely absent comes back Ok with Exists $false.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Exists = $false; Names = @(); Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    [void](Enable-OfflineBackupPrivilege)
    Initialize-OfflinePrivilegedRegistryType

    $exists = $false
    $rc = [OfflinePrivilegedRegistry]::KeyExists($subKey, [ref]$exists)
    if ($rc -ne 0) {
        $result.Error = "The key could not be opened (error $rc)."
        return $result
    }
    if (-not $exists) {
        $result.Ok = $true
        return $result
    }

    $names = $null
    $rc = [OfflinePrivilegedRegistry]::ValueNames($subKey, [ref]$names)
    if ($rc -ne 0) {
        $result.Exists = $true
        $result.Error = "The key opened but its values could not be listed (error $rc)."
        return $result
    }

    $result.Ok = $true
    $result.Exists = $true
    $result.Names = @($names)
    return $result
}

function Get-OfflinePrivilegedRegistrySubKeyName {
    <#
    .SYNOPSIS
        Listing the subkeys of a key that may deny read to every account, SYSTEM included.

    .DESCRIPTION
        The counterpart of Get-OfflinePrivilegedRegistryValueName, for callers that have to walk a
        protected tree rather than read one key. The offline SECURITY hive is the case that needs
        it: Policy\Accounts holds one subkey per account that has been granted a logon right or a
        privilege, and neither the provider nor the .NET registry classes can enumerate it.

        As with the value-name listing, "the key has no subkeys" and "the key could not be opened"
        are different answers. Ok is $false only when something went wrong; a key that is genuinely
        absent comes back Ok with Exists $false.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Exists = $false; Names = @(); Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    [void](Enable-OfflineBackupPrivilege)
    Initialize-OfflinePrivilegedRegistryType

    $exists = $false
    $rc = [OfflinePrivilegedRegistry]::KeyExists($subKey, [ref]$exists)
    if ($rc -ne 0) {
        $result.Error = "The key could not be opened (error $rc)."
        return $result
    }
    if (-not $exists) {
        $result.Ok = $true
        return $result
    }

    $names = $null
    $rc = [OfflinePrivilegedRegistry]::SubKeyNames($subKey, [ref]$names)
    if ($rc -ne 0) {
        $result.Exists = $true
        $result.Error = "The key opened but its subkeys could not be listed (error $rc)."
        return $result
    }

    $result.Ok = $true
    $result.Exists = $true
    $result.Names = @($names)
    return $result
}

function Get-OfflinePrivilegedRegistryValue {
    <#
    .SYNOPSIS
        Reading one value from a key that may deny read to every account, SYSTEM included.

    .DESCRIPTION
        Returns the raw bytes and the registry type alongside a decoded value. The type matters as
        much as the content for a caller deciding whether the value is well formed, and a decoded
        string array cannot report either the type or the true byte length.

        Strings decodes REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ. Anything else is left to Bytes.

        Name accepts an empty string, which is how the Win32 registry API names a key's default
        (unnamed) value. Without AllowEmptyString the binder rejects the call before the function
        runs, which is not a theoretical concern: the offline SECURITY hive keeps the logon-right
        mask in the default value of Policy\Accounts\<SID>\ActSysAc, so that is the only way to
        read it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )

    $result = [PSCustomObject]@{
        Ok = $false; Found = $false; Type = 0; ByteLength = 0
        Bytes = $null; Strings = @(); Error = ''
    }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    [void](Enable-OfflineBackupPrivilege)
    Initialize-OfflinePrivilegedRegistryType

    $type = 0
    $bytes = $null
    $rc = [OfflinePrivilegedRegistry]::GetValue($subKey, $Name, [ref]$type, [ref]$bytes)

    # 2 is ERROR_FILE_NOT_FOUND, which the API returns both for a missing key and a missing value.
    if ($rc -eq 2) {
        $result.Ok = $true
        return $result
    }
    if ($rc -ne 0) {
        $result.Error = "$Name could not be read (error $rc)."
        return $result
    }

    $result.Ok = $true
    $result.Found = $true
    $result.Type = $type
    $result.Bytes = $bytes
    $result.ByteLength = @($bytes).Count

    # 1 REG_SZ, 2 REG_EXPAND_SZ, 7 REG_MULTI_SZ.
    if ($type -in 1, 2, 7 -and $result.ByteLength -gt 1) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
        $result.Strings = @($text.Split([char]0) | Where-Object { $_.Length -gt 0 })
    }

    return $result
}

function Remove-OfflinePrivilegedRegistryValue {
    <#
    .SYNOPSIS
        Removing one value from a key that may deny write to every account, SYSTEM included.

    .DESCRIPTION
        The key's owner and DACL are left exactly as they were found. Only the named value is
        removed; the key itself and every other value under it survive.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = [PSCustomObject]@{ Removed = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", 'Remove registry value')) { return $result }

    if (-not (Enable-OfflineBackupPrivilege)) {
        $result.Error = 'SeBackupPrivilege or SeRestorePrivilege could not be enabled, so the guarded key cannot be opened for write.'
        return $result
    }
    Initialize-OfflinePrivilegedRegistryType

    $rc = [OfflinePrivilegedRegistry]::DeleteValue($subKey, $Name)
    if ($rc -ne 0) {
        $result.Error = "$Name could not be removed (error $rc)."
        return $result
    }

    $result.Removed = $true
    return $result
}

function New-OfflinePrivilegedRegistryKey {
    <#
    .SYNOPSIS
        Creating a key under a hive that may deny write to every account, SYSTEM included.

    .DESCRIPTION
        Separate from Set-OfflinePrivilegedRegistryValue because creating a key is a different
        promise from correcting a value. Everything else in this helper is built so that reading or
        repairing cannot add anything to a machine that may be healthy; this is the one entry point
        that adds, so a caller has to ask for it by name.

        Reports whether the key was created or was already there, so a caller can tell a repair from
        a no-op, and confirms the key is readable afterwards rather than trusting the return code.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Created = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Create registry key')) { return $result }

    if (-not (Enable-OfflineBackupPrivilege)) {
        $result.Error = 'SeBackupPrivilege or SeRestorePrivilege could not be enabled, so the guarded key cannot be created.'
        return $result
    }
    Initialize-OfflinePrivilegedRegistryType

    $created = $false
    $rc = [OfflinePrivilegedRegistry]::CreateKey($subKey, [ref]$created)
    if ($rc -ne 0) {
        $result.Error = "$Path could not be created (error $rc)."
        return $result
    }

    $exists = $false
    $check = [OfflinePrivilegedRegistry]::KeyExists($subKey, [ref]$exists)
    if ($check -ne 0 -or -not $exists) {
        $result.Error = "$Path does not read back as an existing key after being created."
        return $result
    }

    $result.Created = $created
    $result.Ok = $true
    return $result
}

function Set-OfflinePrivilegedRegistryValue {
    <#
    .SYNOPSIS
        Writing one value to a key that may deny write to every account, SYSTEM included.

    .DESCRIPTION
        The key's owner and DACL are left exactly as they were found: the write goes through the
        backup-restore path rather than by granting anyone access, so nothing has to be put back
        afterwards and a failure part way cannot leave the hive more permissive than it was.

        Type is passed in rather than inferred. The offline SECURITY hive stores the logon-right
        mask as REG_NONE (type 0), and writing the same four bytes back as REG_BINARY changes the
        shape of the value even though the content matches.

        Name accepts an empty string, which is how the Win32 registry API names a key's default
        (unnamed) value - the only place the ActSysAc mask exists.

        Bytes accepts an empty array for the same reason: a zero-length value is a real thing in
        this hive. LSA leaves exactly one on each Policy\Accounts\<SID> key, so recreating an
        account entry that matches what LSA itself writes has to be able to write nothing. A
        mandatory [byte[]] rejects an empty array outright, which is why it is allowed explicitly.

        The value is read back and compared byte for byte before success is reported. A silent
        write failure on a protected hive would otherwise be indistinguishable from a repair.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][int]$Type,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    $result = [PSCustomObject]@{ Written = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", 'Set registry value')) { return $result }

    if (-not (Enable-OfflineBackupPrivilege)) {
        $result.Error = 'SeBackupPrivilege or SeRestorePrivilege could not be enabled, so the guarded key cannot be opened for write.'
        return $result
    }
    Initialize-OfflinePrivilegedRegistryType

    $rc = [OfflinePrivilegedRegistry]::SetValue($subKey, $Name, $Type, $Bytes)
    if ($rc -ne 0) {
        $result.Error = "$(if ([string]::IsNullOrEmpty($Name)) { 'the default value' } else { $Name }) could not be written (error $rc)."
        return $result
    }

    $readBack = Get-OfflinePrivilegedRegistryValue -Path $Path -Name $Name
    if (-not $readBack.Ok -or -not $readBack.Found) {
        $result.Error = "$Name was written but could not be read back."
        return $result
    }
    if ($readBack.Type -ne $Type) {
        $result.Error = "$Name reads back as type $($readBack.Type) instead of $Type."
        return $result
    }
    if (@($readBack.Bytes).Count -ne $Bytes.Count) {
        $result.Error = "$Name reads back as $($readBack.ByteLength) byte(s) instead of $($Bytes.Count)."
        return $result
    }
    for ($i = 0; $i -lt $Bytes.Count; $i++) {
        if ($readBack.Bytes[$i] -ne $Bytes[$i]) {
            $result.Error = "$Name reads back with different content at byte $i."
            return $result
        }
    }

    $result.Written = $true
    return $result
}
#endregion
