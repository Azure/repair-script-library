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

      1. The original descriptor is captured first, including owner and group. Registry keys, and
         this file's own copy, rename and delete paths, capture it in BINARY form, which round-trips
         losslessly where an SDDL string re-resolves machine-relative aliases (LA, DA, DU, DC)
         against the rescue VM's own SIDs. Measured: LA came back as the rescue VM's own local
         administrator rather than the offline image's, and DA, DU and DC could not be parsed at all
         on a workgroup machine - the alias needs a domain to resolve against, which a rescue VM
         does not have. An SDDL capture is still offered for the scenarios that consume it as a
         string.

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

.VERSION
    1.0  Capture the descriptor, take ownership, repair, and replay the descriptor whole.

    1.1  Hardened after the PR #143 review:
         - Every function that writes, deletes, takes ownership or changes a security descriptor
           now calls Assert-OfflineTarget BEFORE any privilege is enabled, so a privileged operation
           cannot land on the rescue VM's own disk or hive if an upstream precondition degrades. The
           public entry points take an optional -OfflineRoot to state the binding explicitly.
         - Registry descriptors are captured and replayed in BINARY rather than SDDL, so the P/AI
           control flags and machine-relative SIDs survive the round-trip; the file paths do the
           same through an optional binary capture while still returning SDDL for external callers.
         - Every restore is verified by reading the descriptor back and comparing owner, DACL and
           protection; a key that cannot be reopened to restore is reported, not silently skipped.
         - A value removal reports success only once the value is verified gone, and the key's
           descriptor is put back even when taking ownership throws part way through.
#>

$script:OfflinePrivilegeReady = $false
$script:OfflineBackupPrivilegeReady = $false

# Owner, Group and Access. SACL is deliberately not captured or replayed: reading it needs
# SeSecurityPrivilege and writing it back can fail on its own, and nothing here changes auditing.
$script:OfflineSecuritySection = 'Owner,Group,Access'

# The same three sections as the enum the binary security APIs take. Binary capture and replay is
# used wherever this file restores its own descriptors, because it is lossless where the SDDL string
# above is not: SDDL re-resolves machine-relative aliases against whatever machine parses it.
$script:OfflineSecuritySections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
    [System.Security.AccessControl.AccessControlSections]::Group -bor
    [System.Security.AccessControl.AccessControlSections]::Access

# Resolve the offline-repair core against this file's own folder, so a scenario loads the same
# helper wherever it dot-sources this from, and fail loudly here rather than at the first
# privileged call. Assert-OfflineTarget is the gate every ownership path in this file depends on:
# discovering it is missing halfway through taking ownership of a key is far worse than refusing
# to load.
if (-not (Get-Command -Name Assert-OfflineTarget -ErrorAction SilentlyContinue)) {
    $dependencyPath = Join-Path -Path $PSScriptRoot -ChildPath 'OfflineRepairCommon.ps1'
    try {
        . $dependencyPath
    }
    catch {
        throw "Use-OfflineProtectedResource.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$dependencyPath': $($_.Exception.Message)"
    }
}
foreach ($required in @('Assert-OfflineTarget', 'Add-OfflineRepairLog')) {
    if (-not (Get-Command -Name $required -ErrorAction SilentlyContinue)) {
        throw "Use-OfflineProtectedResource.ps1 requires '$required', which OfflineRepairCommon.ps1 did not define."
    }
}

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
    [OutputType([bool])]
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

function Get-OfflineRawOwner {
    <#
    .SYNOPSIS
        Reading just the owner SID out of a binary security descriptor.

    .DESCRIPTION
        Used to decide whether the owner still needs replaying. Comparing the captured owner with
        the current one avoids a privileged owner-write when the owner never changed. Returns an
        empty string when there is no owner or the descriptor cannot be parsed.

    .OUTPUTS
        [string] the owner SID in S-1-... form, or an empty string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([byte[]]$BinaryDescriptor)

    if (-not $BinaryDescriptor -or $BinaryDescriptor.Length -eq 0) { return '' }
    try {
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($BinaryDescriptor, 0)
        if ($raw.Owner) { return $raw.Owner.Value }
        return ''
    }
    catch { return '' }
}

function Test-OfflineDescriptorMatch {
    <#
    .SYNOPSIS
        Confirming a descriptor read back after a restore matches the one that was captured.

    .DESCRIPTION
        A restore is not trusted until it is verified, the same way a privileged value write is read
        back and byte-compared before it is called done. Raw self-relative bytes are not compared
        whole, because two equivalent descriptors can be laid out differently; instead the owner, the
        protected (P) and auto-inherited (AI) control flags, and every DACL ACE (compared by its own
        binary form, in canonical order) are checked. Those are exactly the parts an SDDL round-trip
        used to corrupt, so a mismatch here is a real restore failure, not a layout artefact.

        Returns $true only when both descriptors parse and every compared part is identical.

    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [byte[]]$Captured,
        [byte[]]$ReadBack
    )

    if (-not $Captured -or -not $ReadBack) { return $false }
    try {
        $a = [System.Security.AccessControl.RawSecurityDescriptor]::new($Captured, 0)
        $b = [System.Security.AccessControl.RawSecurityDescriptor]::new($ReadBack, 0)

        if ("$($a.Owner)" -ne "$($b.Owner)") { return $false }

        $mask = [System.Security.AccessControl.ControlFlags]'DiscretionaryAclProtected, DiscretionaryAclAutoInherited'
        if (($a.ControlFlags -band $mask) -ne ($b.ControlFlags -band $mask)) { return $false }

        $da = $a.DiscretionaryAcl
        $db = $b.DiscretionaryAcl
        if (($null -eq $da) -ne ($null -eq $db)) { return $false }
        if ($da) {
            if ($da.Count -ne $db.Count) { return $false }
            for ($i = 0; $i -lt $da.Count; $i++) {
                if ($da[$i].BinaryLength -ne $db[$i].BinaryLength) { return $false }
                $xb = [byte[]]::new($da[$i].BinaryLength)
                $yb = [byte[]]::new($db[$i].BinaryLength)
                $da[$i].GetBinaryForm($xb, 0)
                $db[$i].GetBinaryForm($yb, 0)
                for ($j = 0; $j -lt $xb.Length; $j++) {
                    if ($xb[$j] -ne $yb[$j]) { return $false }
                }
            }
        }
        return $true
    }
    catch { return $false }
}

function Get-OfflineRegistryKeySecurity {
    <#
    .SYNOPSIS
        Capturing a registry key's owner, group and DACL in binary form, before anything is changed.

    .DESCRIPTION
        Returns the descriptor as a byte array, or $null when it cannot be read. Binary is used
        rather than SDDL because a descriptor captured on the rescue VM and replayed against an
        offline hive has to survive the round-trip exactly: an SDDL string re-resolves the
        machine-relative aliases (LA, DA, DU, DC) against the machine that parses it. Measured on a
        workgroup host, LA silently became that host's own administrator SID, and DA, DU and DC
        threw outright because there is no domain to resolve them against. The binary form carries
        the raw SIDs and the exact control bits, so none of that happens.

        A caller that gets $null must not take ownership: without a capture there is nothing to put
        back, and an object left owned by SYSTEM with an extra FullControl ACE is a permanent change
        to a system it was only meant to borrow.

    .OUTPUTS
        [byte[]] the descriptor's Owner, Group and DACL in self-relative binary form, or $null.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) { return $null }

    $key = $null
    try {
        $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, $rights)
        if (-not $key) { return $null }

        return $key.GetAccessControl($script:OfflineSecuritySections).GetSecurityDescriptorBinaryForm()
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

        Assert-OfflineTarget runs before any privilege is enabled, so a key outside the mounted
        offline hive is refused before ownership is ever taken. That gate is the whole point of the
        helper: a privileged take-and-modify can only ever reach the offline image, never the rescue
        VM's own registry, even if an upstream precondition silently degrades.

        Each captured descriptor is appended to -CapturedInto, if the caller supplies a list, as it
        is taken. That way a throw part way through a subtree still leaves the caller holding
        everything captured so far to restore, instead of the whole capture being lost with a return
        value that never arrived. The same list is returned for callers that do not pass one.

        Descriptors are captured in binary (see Get-OfflineRegistryKeySecurity) so the replay is
        lossless. A key whose descriptor could not be captured is skipped rather than taken.

    .PARAMETER Path
        The offline hive key to take. Must resolve under a registered mounted hive.

    .PARAMETER NoRecurse
        Take only this key, not the subtree below it.

    .PARAMETER OfflineRoot
        Optional explicit mounted-hive key to validate $Path against instead of the registered
        mount(s). Forwarded to Assert-OfflineTarget.

    .PARAMETER CapturedInto
        Optional caller-owned list that each captured descriptor is appended to as it is taken, so a
        partial capture survives a mid-subtree throw.

    .OUTPUTS
        [System.Collections.Generic.List[object]] the captured descriptors, oldest first.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$NoRecurse,
        [string]$OfflineRoot = '',
        [System.Collections.Generic.List[object]]$CapturedInto
    )

    # The gate first, before a single privilege is enabled: if the path is not under a mounted
    # offline hive this throws, and nothing is taken.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'take ownership of')

    Enable-OfflineOwnershipPrivilege
    $me = Get-OfflineCurrentUserSid
    $captured = if ($CapturedInto) { $CapturedInto } else { [System.Collections.Generic.List[object]]::new() }

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

        $descriptor = Get-OfflineRegistryKeySecurity -Path $target
        if (-not $descriptor) {
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

        [void]$captured.Add([PSCustomObject]@{ Path = $target; SubKey = $subKey; Descriptor = $descriptor })
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
        whole from its binary capture rather than by removing the ACE that was added, which also
        puts the owner back and cannot be corrupted by SDDL alias re-resolution.

        Each restore is verified by reading the descriptor back and comparing owner, DACL and
        protection (see Test-OfflineDescriptorMatch). A key that cannot be reopened, rewritten or
        verified is reported with a Warning and a subinacl hint, because leaving it owned by this
        account with an added ACE is a lasting change to the offline image, not a clean outcome.

        Returns the number of keys whose descriptor was replayed AND verified.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Captured)

    Enable-OfflineOwnershipPrivilege
    $restored = 0

    # Deepest first: a parent's DACL may deny what a child still needs to be written.
    $ordered = @($Captured | Sort-Object -Property { ($_.SubKey -split '\\').Count } -Descending)

    foreach ($entry in $ordered) {
        if (-not $entry.SubKey -or -not $entry.Descriptor) { continue }

        $key = $null
        try {
            $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
                      [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                      [System.Security.AccessControl.RegistryRights]::TakeOwnership
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $entry.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
            if (-not $key) {
                # OpenSubKey returns null only for a key that does not exist; an existing key we may
                # not open throws instead and is handled by the catch below. A key captured and then
                # deleted on purpose - the whole subtree beneath a removed key - is the normal
                # outcome and has nothing to restore, so it is skipped silently. But a key that is
                # still present yet came back null is one we failed to reopen: leaving it owned by
                # this account with the added ACE is a lasting change to the offline image, so it is
                # reported rather than passed over.
                if (Test-Path -LiteralPath $entry.Path) {
                    Add-OfflineRepairLog -Level Warning -Message "Could not reopen $($entry.SubKey) to restore its original ACL, so it is left owned by this account. Restore it by hand with: subinacl /keyreg `"$($entry.SubKey)`" /setowner=`"NT SERVICE\TrustedInstaller`""
                }
                continue
            }

            $sd = [System.Security.AccessControl.RegistrySecurity]::new()
            $sd.SetSecurityDescriptorBinaryForm($entry.Descriptor, $script:OfflineSecuritySections)
            $key.SetAccessControl($sd)

            # Trust nothing: read the descriptor back and compare it to the capture, the same way a
            # privileged value write is read back and byte-compared before it is called done.
            $readBack = Get-OfflineRegistryKeySecurity -Path $entry.Path
            if ($readBack -and (Test-OfflineDescriptorMatch -Captured $entry.Descriptor -ReadBack $readBack)) {
                $restored++
            }
            else {
                Add-OfflineRepairLog -Level Warning -Message "The original ACL was written back to $($entry.SubKey) but did not read back identically, so it cannot be counted as restored. Check it by hand with: subinacl /keyreg `"$($entry.SubKey)`" /display"
            }
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
        [string]$Label = '',
        [string]$OfflineRoot = ''
    )

    if (-not $Label) { $Label = $Path }

    # The gate before the plain delete below, which is itself a mutation: refuse a key that is not
    # under the mounted offline hive before anything is attempted against it.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'delete the offline registry key')

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
            [void](Grant-OfflineRegistryKeyAccess -Path $parent -NoRecurse -OfflineRoot $OfflineRoot -CapturedInto $captured)
        }
        [void](Grant-OfflineRegistryKeyAccess -Path $Path -OfflineRoot $OfflineRoot -CapturedInto $captured)
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

        Both the plain remove and the owned remove run with -ErrorAction Stop. A refused remove is
        caught and escalated rather than swallowed, so a value that only reads back as gone because
        its key denies read is never mistaken for one that was removed, and success is reported only
        once the value is verified gone. If taking ownership throws part way, the key's descriptor is
        still put back, mirroring the write counterpart.

        Assert-OfflineTarget runs before any remove, so a value whose key is not under the mounted
        offline hive is refused before anything is attempted.

    .PARAMETER OfflineRoot
        Optional explicit mounted-hive key to validate $Path against, forwarded to the gate and the
        ownership grant.

    .OUTPUTS
        [PSCustomObject] with Removed, TookOwnership, Restored and Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$StillSet,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    # The gate before the plain remove below, which mutates: refuse a value whose key is not under
    # the mounted offline hive before anything is attempted.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'remove the offline registry value from')

    $read = { (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name }

    if (-not (& $StillSet (& $read))) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'The value was not set.' }
    }

    # -ErrorAction Stop, not SilentlyContinue: a refused remove has to be told apart from a real
    # one. An access-denied failure falls through to the ownership path; any other failure is the
    # honest answer and is rethrown, exactly as the write counterpart does.
    $deniedPlain = $false
    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    }
    catch {
        if (Test-OfflineRegistryAccessDenied -ErrorRecord $_) { $deniedPlain = $true }
        else { throw }
    }
    if (-not $deniedPlain -and -not (& $StillSet (& $read))) {
        return [PSCustomObject]@{ Removed = $true; TookOwnership = $false; Restored = 0; Reason = 'Removed without changing any permission.' }
    }

    Add-OfflineRepairLog -Level Info -Message "$Name is protected by its key's ACL. Taking the key, removing the value, and putting the ACL back."

    $captured = [System.Collections.Generic.List[object]]::new()
    try { [void](Grant-OfflineRegistryKeyAccess -Path $Path -NoRecurse -OfflineRoot $OfflineRoot -CapturedInto $captured) }
    catch {
        # Ownership may have been taken on the key before the failure, so its descriptor is put back
        # rather than left changed - the asymmetry the write counterpart already avoids.
        $undone = Restore-OfflineRegistrySecurity -Captured $captured.ToArray()
        return [PSCustomObject]@{ Removed = $false; TookOwnership = $true; Restored = $undone; Reason = "Ownership could not be taken: $($_.Exception.Message)" }
    }

    $removed = $false
    $failure = $null
    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
        $removed = -not (& $StillSet (& $read))
    }
    catch { $failure = $_ }
    finally {
        # Always. The key is still here, so an unrestored descriptor is a permanent change.
        $restored = Restore-OfflineRegistrySecurity -Captured $captured.ToArray()
    }

    return [PSCustomObject]@{
        Removed       = $removed
        TookOwnership = $true
        Restored      = $restored
        Reason        = $(if ($removed) { "Removed after taking the key. $restored descriptor(s) were put back." }
                          else { "The value survived even after the key was taken$(if ($failure) { " ($($failure.Exception.Message))" }). $restored descriptor(s) were put back." })
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
    [OutputType([bool])]
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
        [Parameter(Mandatory = $false)][string]$Description = 'the value',
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    # The gate before the fast-path write below: even the plain attempt mutates the hive, so a key
    # outside the mounted offline image must be refused before $Action runs at all.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'write to the offline registry key')

    try {
        # [void] so the caller scriptblock's own pipeline output cannot merge with and contaminate
        # this function's returned result object.
        [void](& $Action)
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

    $captured = [System.Collections.Generic.List[object]]::new()
    try { [void](Grant-OfflineRegistryKeyAccess -Path $guardPath -NoRecurse -OfflineRoot $OfflineRoot -CapturedInto $captured) }
    catch {
        [void](Restore-OfflineRegistrySecurity -Captured $captured.ToArray())
        return [PSCustomObject]@{ Written = $false; TookOwnership = $false; Restored = 0; Reason = "Ownership could not be taken: $($_.Exception.Message)" }
    }

    $written = $false
    $failure = $null
    try {
        # [void] so the caller scriptblock's own pipeline output cannot contaminate the result.
        [void](& $Action)
        $written = $true
    }
    catch { $failure = $_ }
    finally {
        # Always. The key is still here, so an unrestored descriptor is a permanent change to a
        # system this script was only meant to borrow.
        $restored = Restore-OfflineRegistrySecurity -Captured $captured.ToArray()
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Name',
        Justification = 'Name is used, inside the $read scriptblock below. PSScriptAnalyzer does not look into a scriptblock assigned to a variable, so it cannot see the three uses there. Removing the parameter would break every caller.')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)]$DefaultValue = $null,
        [Parameter(Mandatory = $false)][ref]$Found,
        [Parameter(Mandatory = $false)][ref]$Denied,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
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

    $captured = [System.Collections.Generic.List[object]]::new()
    try { [void](Grant-OfflineRegistryKeyAccess -Path $guardPath -NoRecurse -OfflineRoot $OfflineRoot -CapturedInto $captured) }
    catch {
        [void](Restore-OfflineRegistrySecurity -Captured $captured.ToArray())
        return $DefaultValue
    }

    try { return & $read }
    catch { return $DefaultValue }
    finally { [void](Restore-OfflineRegistrySecurity -Captured $captured.ToArray()) }
}

function Get-OfflinePathSecurity {
    <#
    .SYNOPSIS
        Capturing a file or folder's owner, group and DACL as SDDL, and optionally in binary form.

    .DESCRIPTION
        Returns the descriptor as an SDDL string, which is the form the scenarios that consume this
        capture expect. When -BinaryForm is supplied it is also set to the same descriptor's binary
        form, which round-trips losslessly where an SDDL string re-resolves machine-relative aliases
        against the machine parsing it; the copy, rename and delete paths in this file restore from
        that binary rather than from the SDDL.

    .PARAMETER BinaryForm
        Optional [ref] set to the descriptor's Owner+Group+DACL binary form ([byte[]]), or $null on
        failure.

    .OUTPUTS
        [string] the descriptor in SDDL form, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][ref]$BinaryForm
    )

    if ($BinaryForm) { $BinaryForm.Value = $null }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($BinaryForm) { $BinaryForm.Value = $acl.GetSecurityDescriptorBinaryForm() }
        return $acl.GetSecurityDescriptorSddlForm($script:OfflineSecuritySection)
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

    if ($IsDirectory) {
        if ([System.IO.Directory].GetMethod('SetAccessControl', [type[]]@([string], [System.Security.AccessControl.DirectorySecurity]))) {
            [System.IO.Directory]::SetAccessControl($Path, $Security)
            return
        }
        [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($Path), $Security)
        return
    }

    if ([System.IO.File].GetMethod('SetAccessControl', [type[]]@([string], [System.Security.AccessControl.FileSecurity]))) {
        [System.IO.File]::SetAccessControl($Path, $Security)
        return
    }
    [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($Path), $Security)
}

function Grant-OfflinePathAccess {
    <#
    .SYNOPSIS
        Taking ownership of a file or folder and granting this account FullControl.

    .DESCRIPTION
        Returns the captured SDDL, or $null when it could not be captured - in which case nothing
        is changed, because an object that cannot be handed back should not be taken.

        Assert-OfflineTarget runs before any privilege is enabled, so a path outside the bound
        offline root is refused before ownership is ever taken - a privileged take-and-modify can
        only ever reach the offline image, never the rescue VM's own disk.

        -CapturedBinary optionally receives the original descriptor in binary form, which the
        internal copy, rename and delete paths replay in preference to the SDDL because it
        round-trips losslessly where SDDL does not.

    .PARAMETER OfflineRoot
        Optional explicit offline root to validate $Path against instead of the bound root(s).

    .PARAMETER CapturedBinary
        Optional [ref] set to the original descriptor's binary form, for a lossless restore.

    .OUTPUTS
        [string] the captured descriptor in SDDL form, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = '',
        [Parameter(Mandatory = $false)][ref]$CapturedBinary
    )

    # The gate before any privilege is enabled.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'take ownership of')

    Enable-OfflineOwnershipPrivilege

    $binary = $null
    $original = Get-OfflinePathSecurity -Path $Path -BinaryForm ([ref]$binary)
    if (-not $original) {
        Add-OfflineRepairLog -Level Info -Message "Could not read the security descriptor of $Path, so its ownership was left alone."
        return $null
    }
    if ($CapturedBinary) { $CapturedBinary.Value = $binary }

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

        When -BinaryDescriptor is supplied it is replayed in preference to the SDDL, because a binary
        descriptor round-trips losslessly where an SDDL string re-resolves machine-relative aliases
        (LA, DA, DU, DC) against the machine that parses it - measured on a workgroup host, LA
        resolved to that host's own administrator and DA, DU and DC failed to parse at all. The
        internal copy, rename and delete paths capture and pass it; external callers that hold only
        the SDDL still get the SDDL replay.

        A binary restore is verified: the descriptor is read back and compared (owner, DACL and
        protection), and a restore that does not read back identically is reported and returns
        $false rather than being counted as done.

        A missing path is not an error: the caller may legitimately offer both the original and
        the renamed path without knowing which one survived.

    .PARAMETER BinaryDescriptor
        Optional [byte[]] captured by Grant-OfflinePathAccess -CapturedBinary. Replayed and verified
        in preference to -Sddl when present.

    .PARAMETER OfflineRoot
        Optional explicit offline root. Defaults to the root bound during disk discovery.
        Forwarded to Assert-OfflineTarget.

    .OUTPUTS
        [bool] $true when the descriptor was written (and, for a binary restore, verified).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Sddl = '',
        [byte[]]$BinaryDescriptor,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    $haveBinary = ($BinaryDescriptor -and $BinaryDescriptor.Length -gt 0)
    if (-not $Sddl -and -not $haveBinary) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    # Gated like every other privileged path, and for the same reason. Restoring is not inherently
    # safe just because it puts something back: this enables SeTakeOwnershipPrivilege and then writes
    # a descriptor that was captured from a DIFFERENT object, so a $Path that resolved to the rescue
    # VM's own C: would have its owner and DACL replaced with the offline image's. The gate runs after
    # the missing-path check, because a path that is not there is explicitly not an error here.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'restore the security descriptor of')

    Enable-OfflineOwnershipPrivilege

    try {
        $isDirectory = (Get-Item -LiteralPath $Path -Force).PSIsContainer
        $sd = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }

        if ($haveBinary) {
            # Only the sections that actually differ are written. If ownership was never taken -
            # because it was already ours - replaying the owner would be a privileged write with no
            # effect that fails on a restricted account and takes the DACL restore down with it.
            $capturedOwner = Get-OfflineRawOwner -BinaryDescriptor $BinaryDescriptor
            $currentBinary = $null
            [void](Get-OfflinePathSecurity -Path $Path -BinaryForm ([ref]$currentBinary))
            $sections = $script:OfflineSecuritySections
            if ($capturedOwner -and $currentBinary -and ($capturedOwner -eq (Get-OfflineRawOwner -BinaryDescriptor $currentBinary))) {
                $sections = [System.Security.AccessControl.AccessControlSections]::Access
            }
            $sd.SetSecurityDescriptorBinaryForm($BinaryDescriptor, $sections)
            Save-OfflinePathSecurity -Path $Path -Security $sd -IsDirectory:$isDirectory

            # Trust nothing: read the descriptor back and confirm it matches before calling it done.
            $readBack = $null
            [void](Get-OfflinePathSecurity -Path $Path -BinaryForm ([ref]$readBack))
            if ($readBack -and (Test-OfflineDescriptorMatch -Captured $BinaryDescriptor -ReadBack $readBack)) {
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The original ACL was written back to $Path but did not read back identically, so it cannot be counted as restored. Check it by hand with: icacls `"$Path`""
            return $false
        }

        # SDDL fall-back for external callers that captured only the string form.
        $sections = $script:OfflineSecuritySection
        $capturedOwner = Get-OfflineSddlOwner -Sddl $Sddl
        if ($capturedOwner -and $capturedOwner -eq (Get-OfflineSddlOwner -Sddl (Get-OfflinePathSecurity -Path $Path))) {
            $sections = 'Access'
        }
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
        [Parameter(Mandatory = $true)][string]$NewName,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    # The gate before the plain rename below, which mutates: refuse a file that is not under the
    # bound offline root before anything is attempted, even the plain first attempt.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'rename the offline file')

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
    $parentBin = $null
    $fileBin = $null
    $absent = $false
    $renamed = $false
    try {
        $originalSddl = Grant-OfflinePathAccess -Path $parent -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$parentBin)
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
            $fileSddl = Grant-OfflinePathAccess -Path $Path -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$fileBin)
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
        # The binary capture is replayed and verified in preference to the SDDL.
        $restoredFile = $true
        if ($fileSddl) {
            $restoredFile = Restore-OfflinePathSecurity -Path $(if ($renamed) { $target } else { $Path }) -Sddl $fileSddl -BinaryDescriptor $fileBin
        }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $originalSddl -BinaryDescriptor $parentBin) -and $restoredFile
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
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    # The gate before the plain delete below, which mutates: refuse a file that is not under the
    # bound offline root before anything is attempted, even the plain first attempt.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'delete the offline file')

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
    $parentBin = $null
    $fileBin = $null
    $removed = $false
    $absent = $false
    try {
        $parentSddl = Grant-OfflinePathAccess -Path $parent -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$parentBin)
        if (-not $parentSddl) {
            return [PSCustomObject]@{ Removed = $false; TookOwnership = $false; Restored = $false; Absent = $false; Reason = "The folder's security descriptor could not be read, so its ownership was left alone. Original error: $firstError" }
        }

        # Now that the folder can be read, the earlier check can be trusted.
        if (-not (Test-Path -LiteralPath $Path)) {
            $absent = $true
            $reason = 'The file was not present once the folder could be read.'
        }
        else {
            $fileSddl = Grant-OfflinePathAccess -Path $Path -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$fileBin)
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
        # The binary capture is replayed and verified in preference to the SDDL.
        $restoredFile = $true
        if ($fileSddl -and -not $removed) {
            $restoredFile = Restore-OfflinePathSecurity -Path $Path -Sddl $fileSddl -BinaryDescriptor $fileBin
        }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $parentSddl -BinaryDescriptor $parentBin) -and $restoredFile
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
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    # The gate is on the destination, which is what gets written: refuse a write whose target is
    # not under the bound offline root before the plain copy below runs. The source is only read,
    # so it may legitimately sit on the rescue VM (a staged replacement file).
    [void](Assert-OfflineTarget -Path $Destination -OfflineRoot $OfflineRoot -Action 'write the offline file')

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
    $parentBin = $null
    $fileBin = $null
    $copied = $false
    $reason = ''
    try {
        $parentSddl = Grant-OfflinePathAccess -Path $parent -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$parentBin)
        if (-not $parentSddl) {
            return [PSCustomObject]@{ Copied = $false; TookOwnership = $false; Restored = $false; Reason = "The folder's security descriptor could not be read, so its ownership was left alone. Original error: $firstError" }
        }

        # Re-checked now that the folder can actually be read: the first check ran against a folder
        # that may have been denying us, so its answer could not be trusted.
        if (Test-Path -LiteralPath $Destination) {
            $fileSddl = Grant-OfflinePathAccess -Path $Destination -OfflineRoot $OfflineRoot -CapturedBinary ([ref]$fileBin)
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
        # The binary capture is replayed and verified in preference to the SDDL.
        $restoredFile = $true
        if ($fileSddl) { $restoredFile = Restore-OfflinePathSecurity -Path $Destination -Sddl $fileSddl -BinaryDescriptor $fileBin }
        $restored = (Restore-OfflinePathSecurity -Path $parent -Sddl $parentSddl -BinaryDescriptor $parentBin) -and $restoredFile
    }

    return [PSCustomObject]@{
        Copied        = $copied
        TookOwnership = $true
        Restored      = [bool]$restored
        Reason        = $reason
    }
}
