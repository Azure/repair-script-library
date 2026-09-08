<#
.SYNOPSIS
    Reading and repairing a single offline registry key or value that denies access to every
    account, SYSTEM included, by opening it with SeBackupPrivilege / SeRestorePrivilege rather
    than by its DACL.

.DESCRIPTION
    Split out of Use-OfflineProtectedResource.ps1 during the PR #143 review because it solves a
    different problem by a different mechanism, and keeping the two apart keeps each one readable.

    Use-OfflineProtectedResource.ps1 handles objects that are merely OWNED by TrustedInstaller: it
    takes ownership, rewrites the DACL, does the repair, and puts the original security descriptor
    back afterwards. The functions here never change a key's owner or DACL at all. They open it
    with REG_OPTION_BACKUP_RESTORE while SeBackupPrivilege and SeRestorePrivilege are held, which
    makes the kernel grant access on the strength of the privilege and skip the DACL check
    entirely. Nothing about the key changes, so a read leaves even a healthy machine untouched and
    a write goes through the same privileged handle instead of loosening the key first.

    "Privileged" here means "opened by privilege rather than by permission". It has nothing to do
    with Backup-OfflineHiveFile, which copies a hive file.

    Use these when a key denies read to everyone including SYSTEM - mpssvc's AppCs key is the known
    example. Use the *-OfflineProtected* functions in Use-OfflineProtectedResource.ps1 when the key
    is merely owned by TrustedInstaller.

    The three functions that change the hive - New-OfflinePrivilegedRegistryKey,
    Set-OfflinePrivilegedRegistryValue and Remove-OfflinePrivilegedRegistryValue - each call
    Assert-OfflineTarget BEFORE enabling any privilege, so a privileged create, write or delete
    cannot land on the rescue VM's own registry if an upstream precondition degrades. They take an
    optional -OfflineRoot to state the binding explicitly. The read functions inspect only and are
    not gated.

    Exposed functions:
      Initialize-OfflinePrivilegedRegistryType    Compile the backup-restore P/Invoke (idempotent).
      Get-OfflinePrivilegedRegistryValueName      List value names under a guarded key.
      Get-OfflinePrivilegedRegistrySubKeyName     List subkey names under a guarded key.
      Get-OfflinePrivilegedRegistryValue          Read one value from a guarded key.
      New-OfflinePrivilegedRegistryKey            Create a guarded key.                 [gated]
      Set-OfflinePrivilegedRegistryValue          Write one value to a guarded key.     [gated]
      Remove-OfflinePrivilegedRegistryValue       Remove one value from a guarded key.  [gated]

.NOTES
    Name:   Use-OfflinePrivilegedRegistry.ps1
    Requires: OfflineRepairCommon.ps1 (Assert-OfflineTarget, Add-OfflineRepairLog) and
              Use-OfflineProtectedResource.ps1 (ConvertTo-OfflineNativeSubKey,
              Enable-OfflineBackupPrivilege). Both are dot-sourced below from this file's own
              folder via $PSScriptRoot, not the caller's working directory.
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.

.VERSION
    v1.0: Split unchanged out of Use-OfflineProtectedResource.ps1 so the backup-restore path lives
          on its own.
    v1.1: The three writing functions now call Assert-OfflineTarget before enabling
          SeBackupPrivilege / SeRestorePrivilege and accept an optional -OfflineRoot, so a
          privileged create, write or remove is proven to land on the mounted offline hive and
          never on the rescue VM's own registry (PR #143 review).
#>

# These functions call the offline-target gate (Assert-OfflineTarget, from OfflineRepairCommon) and
# the subkey and privilege helpers that stay in Use-OfflineProtectedResource.ps1
# (ConvertTo-OfflineNativeSubKey, Enable-OfflineBackupPrivilege). Resolve both siblings against this
# file's own folder so a scenario loads the same helpers wherever it dot-sources this from, and fail
# loudly if either cannot be loaded rather than at the first privileged call.
$script:OfflinePrivilegedRegistryDependencies = @(
    @{ File = 'OfflineRepairCommon.ps1';          Sentinel = 'Assert-OfflineTarget' },
    @{ File = 'Use-OfflineProtectedResource.ps1'; Sentinel = 'ConvertTo-OfflineNativeSubKey' }
)
foreach ($dependency in $script:OfflinePrivilegedRegistryDependencies) {
    if (Get-Command -Name $dependency.Sentinel -ErrorAction SilentlyContinue) { continue }
    $dependencyPath = Join-Path -Path $PSScriptRoot -ChildPath $dependency.File
    try {
        . $dependencyPath
    }
    catch {
        throw "Use-OfflinePrivilegedRegistry.ps1 could not load its dependency '$($dependency.File)' from '$dependencyPath': $($_.Exception.Message)"
    }
}

# A sentinel still missing after the load means the dependency did not define what these functions
# need, so running on would only defer the failure to a privileged registry call.
foreach ($required in @('Assert-OfflineTarget', 'ConvertTo-OfflineNativeSubKey', 'Enable-OfflineBackupPrivilege')) {
    if (-not (Get-Command -Name $required -ErrorAction SilentlyContinue)) {
        throw "Use-OfflinePrivilegedRegistry.ps1 loaded its dependencies but '$required' is still unavailable, so it cannot run safely."
    }
}

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

    .PARAMETER OfflineRoot
        Optional explicit mounted-hive key to validate $Path against, forwarded to
        Assert-OfflineTarget.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    $result = [PSCustomObject]@{ Removed = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    # The gate before the backup-restore privilege is enabled: a well-formed HKLM path that is not
    # under a mounted offline hive - the rescue VM's own live registry, say - is refused here rather
    # than opened for write by privilege. Throws by design, because a privileged write that lands on
    # the wrong hive is exactly the outcome this guards against.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'remove the offline registry value from')

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

    .PARAMETER OfflineRoot
        Optional explicit mounted-hive key to validate $Path against, forwarded to
        Assert-OfflineTarget.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    $result = [PSCustomObject]@{ Ok = $false; Created = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    # The gate before the backup-restore privilege is enabled: this is the one entry point that
    # ADDS a key, so it must be certain the key lands in the mounted offline hive and never in the
    # rescue VM's own registry. Throws by design when the target is not bound.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'create the offline registry key')

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

    .PARAMETER OfflineRoot
        Optional explicit mounted-hive key to validate $Path against, forwarded to
        Assert-OfflineTarget.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][int]$Type,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $false)][string]$OfflineRoot = ''
    )

    $result = [PSCustomObject]@{ Written = $false; Error = '' }

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) {
        $result.Error = "$Path is not a path under HKLM."
        return $result
    }

    # The gate before the backup-restore privilege is enabled: a well-formed HKLM path that is not
    # under a mounted offline hive is refused here rather than opened for write. Throws by design.
    [void](Assert-OfflineTarget -Path $Path -OfflineRoot $OfflineRoot -Action 'write to the offline registry value at')

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
