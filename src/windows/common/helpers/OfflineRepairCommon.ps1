<#
.SYNOPSIS
    Shared primitives for the offline repair helpers: buffered logging, drive-safe paths
    and offline binary trust checks.

.DESCRIPTION
    Buffered logging
    ----------------
    The library's Logger.ps1 functions write with Write-Output, which is the same stream
    a PowerShell function returns its value on. A helper that both logs and returns a
    value therefore returns the log lines as well, silently corrupting the result.

    This helper solves that: helper functions call Add-OfflineRepairLog, which buffers the
    message without writing anything, and the calling script calls Write-OfflineRepairLog
    at statement level to flush the buffer through the standard Log-* functions.

    Rules:
      - Inside a function that returns a value, use Add-OfflineRepairLog.
      - Call Write-OfflineRepairLog only at script level, never from a function whose
        return value is used, and always flush in the script's finally block.

    Drive-safe paths
    ----------------
    Join-Path and Test-Path throw DriveNotFoundException when a path refers to a drive
    letter that is not a live PowerShell drive. Offline repairs work with letters that
    come and go (EFI and Recovery partitions are mounted temporarily, and a partition can
    still advertise a stale access path), so Join-OfflinePath builds the string without
    resolving the drive and Test-OfflinePath answers false instead of throwing.

    Offline target binding
    ----------------------
    These helpers run as SYSTEM on a rescue VM that has its own healthy Windows
    installation attached at C:. Every destructive operation therefore has to prove it is
    acting on the broken disk and not on the rescue VM, because a precondition that fails
    quietly - a drive letter that was never assigned, a disk enumeration that returned
    nothing - otherwise leaves a path that still resolves, just on the wrong volume.

    Get-OfflineWindowsDisk calls Set-OfflineRepairRoot once it has chosen a volume, and
    Use-OfflineRegistryHive registers each mount key it creates. Assert-OfflineTarget is
    the single gate every writing function calls before it enables a privilege. It throws
    when nothing is bound and when the path falls outside what is bound: it never warns
    and never returns $false, because a caller that ignores a warning is exactly the
    failure being prevented.

    Shared state lives in $global: rather than $script:. A dot-sourced $script: variable
    binds to the scope of whoever sourced the file, so a helper sourced from inside a
    function would keep its own private buffer and its own private root list, and the gate
    would be asserting against a set the caller never populated.

.NOTES
    Name:   OfflineRepairCommon.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).

.VERSION
    v1.0: Initial version.
    v1.1: Added the offline target binding gate. Moved shared state to $global:. Trust
          reporting no longer infers a Microsoft signature from an unsigned version
          resource.
    v1.2: Added a read-only offreg reader for discovery and hive validation, without
          mounting hives in the rescue VM's registry or replaying logs onto the source.
    v1.3: Shared writable-hive lifecycle and default-drive state across dot-source scopes.
          Added numeric, read-only native queries for mounted keys and DWORD metadata.
#>

function Get-OfflineRepairState {
    <#
    .SYNOPSIS
        Returns the shared helper state, creating it on first use.

    .DESCRIPTION
        One hashtable in $global: holds the log buffer, target bindings, default Windows
        drive and hive lifecycle. See the file header for why this is not $script:.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
        Justification = 'Deliberate, and confined to this one function. These helpers are dot-sourced, and a $script: variable binds to the scope that did the dot-sourcing: a helper sourced from inside a function would get its own private copy of the root list, so Assert-OfflineTarget would check a set the caller never populated and the gate would fail open. Each az vm repair run is a fresh process, so there is nothing to leak into; Clear-OfflineRepairRoot resets it for tests.')]
    [CmdletBinding()]
    param()

    if (-not $global:OfflineRepairState) {
        $global:OfflineRepairState = @{
            LogBuffer     = [System.Collections.Generic.List[object]]::new()
            Roots         = [System.Collections.Generic.List[string]]::new()
            HiveKeys      = [System.Collections.Generic.List[string]]::new()
            WindowsDrive  = $null
            HiveLoadDepth = @{}
            HiveFilePaths = @{}
        }
    }
    # Upgrade an existing state without resetting another dot-source scope's acquisitions.
    foreach ($name in @('HiveLoadDepth', 'HiveFilePaths')) {
        if (-not $global:OfflineRepairState.ContainsKey($name)) {
            $global:OfflineRepairState[$name] = @{}
        }
    }
    if (-not $global:OfflineRepairState.ContainsKey('WindowsDrive')) {
        $global:OfflineRepairState.WindowsDrive = $null
    }
    return $global:OfflineRepairState
}

function Set-OfflineWindowsDrive {
    <#
    .SYNOPSIS
        Binds the default offline Windows drive for every dot-source scope.

    .DESCRIPTION
        Call after discovery selects the Windows volume. Returns the bound root, like
        Set-OfflineRepairRoot. An active hive caller must not have its default retargeted.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Only updates the in-process offline target binding; skipping it for WhatIf would leave subsequent helpers bound to the wrong default.')]
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $state = Get-OfflineRepairState
    $normalised = ConvertTo-OfflineComparablePath $WindowsDrive
    if ($state.WindowsDrive -and $normalised -ne $state.WindowsDrive -and $state.HiveLoadDepth.Count -gt 0) {
        throw "Cannot change the offline Windows drive from '$($state.WindowsDrive)' to '$WindowsDrive' while hives are in use."
    }
    $state.WindowsDrive = Set-OfflineRepairRoot -Path $WindowsDrive
    return $state.WindowsDrive
}

function Get-OfflineWindowsDrive {
    <#
    .SYNOPSIS
        Returns the shared default offline Windows drive.

    .DESCRIPTION
        Imports a legacy $script:OfflineWindowsDrive only when no shared default is set.
        Once imported, shared state is authoritative; callers changing disks must use
        Set-OfflineWindowsDrive rather than updating a scope-private variable.
    #>
    $state = Get-OfflineRepairState
    if ([string]::IsNullOrWhiteSpace($state.WindowsDrive)) {
        $legacy = Get-Variable -Name OfflineWindowsDrive -Scope Script -ErrorAction SilentlyContinue
        if ($legacy -and -not [string]::IsNullOrWhiteSpace($legacy.Value)) {
            $null = Set-OfflineWindowsDrive -WindowsDrive $legacy.Value
            Add-OfflineRepairLog -Level Warning -Message 'Imported the legacy OfflineWindowsDrive default. Use Set-OfflineWindowsDrive when selecting another disk.'
        }
    }
    return $state.WindowsDrive
}

function Add-OfflineRepairLog {
    <#
    .SYNOPSIS
        Buffers a log message without writing to the output stream.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('Info', 'Warning', 'Error', 'Output')][string]$Level = 'Info'
    )

    [void](Get-OfflineRepairState).LogBuffer.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
}

function Write-OfflineRepairLog {
    <#
    .SYNOPSIS
        Flushes the buffered helper messages through the library Log-* functions.

    .DESCRIPTION
        Call this only at script level. It writes to the output stream, so calling it
        inside a function whose return value is used would corrupt that value.

        Entries are written before the buffer is cleared, and the clear happens in a
        finally block. Clearing first would discard everything still unwritten if a Log-*
        call threw, which is exactly what happens when init.ps1 was not sourced - the run
        would lose the diagnostics that explain why it failed. For that case the Log-*
        functions are resolved once and fall back to Write-Output.
    #>
    $state = Get-OfflineRepairState
    if ($state.LogBuffer.Count -eq 0) { return }

    $haveLogger = [bool](Get-Command -Name Log-Info -ErrorAction SilentlyContinue)

    try {
        foreach ($entry in $state.LogBuffer) {
            if ([string]::IsNullOrEmpty($entry.Message)) { continue }
            if (-not $haveLogger) {
                Write-Output "[$($entry.Level)] $($entry.Message)"
                continue
            }
            switch ($entry.Level) {
                'Warning' { Log-Warning $entry.Message }
                'Error' { Log-Error $entry.Message }
                'Output' { Log-Output $entry.Message }
                default { Log-Info $entry.Message }
            }
        }
    }
    finally {
        $state.LogBuffer.Clear()
    }
}

function Get-OfflineRepairLog {
    <#
    .SYNOPSIS
        Returns the buffered messages without flushing them.
    #>
    return @((Get-OfflineRepairState).LogBuffer)
}

function Clear-OfflineRepairLog {
    <#
    .SYNOPSIS
        Discards the buffered messages.
    #>
    (Get-OfflineRepairState).LogBuffer.Clear()
}

function Initialize-OfflineRegistryReader {
    <#
    .SYNOPSIS
        Initialises read-only access to hive files through the Windows Offline Registry Library.

    .DESCRIPTION
        Uses the offreg.dll in System32. Reads and log recovery happen in memory; there
        is no HKLM mount, registry provider handle, save operation or reg.exe fallback.
        An unavailable library is an environment failure, not evidence of hive damage.
    #>
    [CmdletBinding()]
    param()

    if (-not ('RslOffline.RegistryHiveReader' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace RslOffline
{
    public sealed class RegistryHiveReader : IDisposable
    {
        private IntPtr handle;
        private const uint MaxValueBytes = 1024 * 1024;

        [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int OROpenHive(string path, out IntPtr result);

        [DllImport("offreg.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int ORCreateHive(out IntPtr result);

        [DllImport("offreg.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int ORCloseHive(IntPtr hive);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int ORGetValue(IntPtr hive, string key, string name,
            out uint type, byte[] data, ref uint size);

        private RegistryHiveReader(IntPtr value) { handle = value; }

        public bool IsOpen { get { return handle != IntPtr.Zero; } }

        private static void Check(int result, string operation)
        {
            if (result != 0)
                throw new Win32Exception(result, operation + " failed (Win32 error " +
                    result + "): " + new Win32Exception(result).Message);
        }

        public static void EnsureSupported()
        {
            IntPtr value;
            Check(ORCreateHive(out value), "Initialising offreg.dll");
            using (RegistryHiveReader reader = new RegistryHiveReader(value)) { }
        }

        public static RegistryHiveReader Open(string path)
        {
            IntPtr value;
            Check(OROpenHive(path, out value), "Opening offline hive '" + path + "'");
            return new RegistryHiveReader(value);
        }

        private byte[] ReadValue(string key, string name, out uint type)
        {
            if (!IsOpen) throw new ObjectDisposedException("RegistryHiveReader");
            uint size = 0;
            int result = ORGetValue(handle, key, name, out type, null, ref size);
            if (result == 2 || result == 3) return null;
            if (result != 234) Check(result, "Reading '" + key + "\\" + name + "'");
            if (size > MaxValueBytes)
                throw new InvalidDataException("Registry metadata value exceeds the 1 MiB read limit.");

            byte[] data = new byte[size];
            Check(ORGetValue(handle, key, name, out type, data, ref size),
                "Reading '" + key + "\\" + name + "'");
            if (size > data.Length)
                throw new InvalidDataException("Registry value grew beyond its reported size.");
            if (size != data.Length) Array.Resize(ref data, (int)size);
            return data;
        }

        public string ReadString(string key, string name)
        {
            uint type;
            byte[] data = ReadValue(key, name, out type);
            if (data == null) return null;
            if ((type != 1 && type != 2) || data.Length % 2 != 0)
                throw new InvalidDataException("'" + key + "\\" + name + "' is not a registry string.");
            return Encoding.Unicode.GetString(data).TrimEnd('\0');
        }

        public uint? ReadDword(string key, string name)
        {
            uint type;
            byte[] data = ReadValue(key, name, out type);
            if (data == null) return null;
            if (type != 4 || data.Length != 4)
                throw new InvalidDataException("'" + key + "\\" + name + "' is not a registry DWORD.");
            return BitConverter.ToUInt32(data, 0);
        }

        public void Dispose()
        {
            if (IsOpen)
            {
                Check(ORCloseHive(handle), "Closing offline hive");
                handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~RegistryHiveReader()
        {
            if (IsOpen) ORCloseHive(handle);
        }
    }
}
'@ -ErrorAction Stop
    }

    [RslOffline.RegistryHiveReader]::EnsureSupported()
}

function Open-OfflineRegistryReader {
    <#
    .SYNOPSIS
        Opens an offline hive for scalar metadata reads without mounting or modifying it.

    .DESCRIPTION
        ReadString and ReadDword take hive-relative key paths and return $null only for
        an absent key/value. Other read failures throw. Dirty hives may require their
        matching recovery logs alongside them. Always Dispose the reader in a finally;
        a failed close throws rather than reporting a successful cleanup.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    Initialize-OfflineRegistryReader
    return [RslOffline.RegistryHiveReader]::Open($Path)
}

function Initialize-OfflineMountedRegistry {
    <#
    .SYNOPSIS
        Initialises read-only native queries of already mounted HKLM keys.

    .DESCRIPTION
        RegOpenKeyEx returns numeric errors for the key itself, independently of its
        default value or the OS language. Every handle is disposed before returning.
        No privileges, registry provider handles, mounts or writes are involved.
        Offline file discovery and validation continue to use the separate offreg reader.
    #>
    [CmdletBinding()]
    param()

    if ('RslOffline.MountedRegistry' -as [type]) { return }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RslOffline
{
    public static class MountedRegistry
    {
        private static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));
        private const int KeyQueryValue = 1;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int RegOpenKeyExW(IntPtr key, string subKey, int options,
            int access, out SafeRegistryHandle result);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int RegQueryValueExW(SafeRegistryHandle key, string name,
            IntPtr reserved, out uint type, byte[] data, ref uint size);

        private static void Check(int result, string operation)
        {
            if (result != 0)
                throw new Win32Exception(result, operation + " failed (Win32 error " +
                    result + "): " + new Win32Exception(result).Message);
        }

        public static int OpenKeyResult(string subKey)
        {
            SafeRegistryHandle key;
            int result = RegOpenKeyExW(HKLM, subKey, 0, KeyQueryValue, out key);
            using (key) { return result; }
        }

        public static uint? ReadDword(string subKey, string name)
        {
            SafeRegistryHandle key;
            int result = RegOpenKeyExW(HKLM, subKey, 0, KeyQueryValue, out key);
            using (key)
            {
                if (result == 2 || result == 3) return null;
                Check(result, "Opening HKLM\\" + subKey);
                uint type;
                uint size = 4;
                byte[] data = new byte[size];
                result = RegQueryValueExW(key, name, IntPtr.Zero, out type, data, ref size);
                if (result == 2) return null;
                if (result != 234) Check(result, "Reading HKLM\\" + subKey + "\\" + name);
                if (result == 234 || type != 4 || size != 4)
                    throw new InvalidDataException("HKLM\\" + subKey + "\\" + name +
                        " is not a four-byte registry DWORD.");
                return BitConverter.ToUInt32(data, 0);
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-OfflineRegistryKeyOpenResult {
    <#
    .SYNOPSIS
        Returns the native result of opening an existing HKLM key for query access.
    #>
    param([Parameter(Mandatory = $true)][string]$Key)

    $normalised = ConvertTo-OfflineComparableRegistryPath $Key
    if (-not $normalised -or $normalised -eq 'HKLM') {
        throw "'$Key' is not an HKLM subkey."
    }
    Initialize-OfflineMountedRegistry
    return [RslOffline.MountedRegistry]::OpenKeyResult($normalised.Substring(5))
}

function Get-OfflineRegistryDword {
    <#
    .SYNOPSIS
        Reads a mounted HKLM DWORD without retaining a registry handle.

    .DESCRIPTION
        Returns null only for an absent key/value. A wrong type, access denial or any
        other native read failure throws instead of converting it into a missing value.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )

    $normalised = ConvertTo-OfflineComparableRegistryPath $Key
    if (-not $normalised -or $normalised -eq 'HKLM') {
        throw "'$Key' is not an HKLM subkey."
    }
    Initialize-OfflineMountedRegistry
    return [RslOffline.MountedRegistry]::ReadDword($normalised.Substring(5), $Name)
}

#region Offline target binding

$script:OfflineRootPattern = '^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)$'

# A repair ROOT must be a volume root, but a path built by Join-OfflinePath may be rooted
# anywhere under one - 'E:\Windows' and 'E:\Windows\System32\config' are both ordinary
# roots for a join. Reusing OfflineRootPattern for the join rejected every nested root and
# returned $null, which Test-OfflinePath then read as "file not present": a repair would
# find nothing to fix and report success. What actually has to be excluded is a root that
# is not volume-qualified at all, because that resolves against the rescue VM's current
# directory. ConvertTo-OfflineComparablePath already strips leading separators, so '\'
# collapses to empty and is rejected before this pattern is reached; this catches the
# residue, such as '\Windows' arriving as 'Windows'.
$script:OfflineQualifiedPathPattern = '^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)(\\[^\\]+)*$'

function ConvertTo-OfflineComparablePath {
    <#
    .SYNOPSIS
        Normalises a file system path for prefix comparison, or returns $null if it is unusable.

    .DESCRIPTION
        Comparison has to work on drives that are not mounted, so Resolve-Path and
        GetFullPath are both unavailable. The normalisation is therefore textual:
        forward slashes become backslashes, repeated separators collapse, and the
        trailing separator is dropped.

        A path containing a '..' segment returns $null rather than being canonicalised.
        There is no reliable way to resolve it without the drive, and no offline repair
        has a legitimate reason to use one, so it is treated as unusable input.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $normalised = $Path.Trim().Replace('/', '\')
    if ($normalised.IndexOfAny([char[]]@("`0", "`r", "`n")) -ge 0) { return $null }

    $isUnc = $normalised.StartsWith('\\')
    $normalised = $normalised.TrimStart('\')
    while ($normalised.Contains('\\')) { $normalised = $normalised.Replace('\\', '\') }
    if ($isUnc) { $normalised = '\\' + $normalised }

    foreach ($segment in $normalised.Split('\')) {
        if ($segment -eq '..') { return $null }
    }

    $normalised = $normalised.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($normalised)) { return $null }
    return $normalised
}

function ConvertTo-OfflineComparableRegistryPath {
    <#
    .SYNOPSIS
        Normalises the several spellings of an HKLM path to 'HKLM\Subkey', or $null.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $normalised = $Path.Trim().Replace('/', '\')
    $normalised = $normalised -replace '^(Microsoft\.PowerShell\.Core\\)?Registry::', ''
    $normalised = $normalised -replace '^HKEY_LOCAL_MACHINE(?=\\|$)', 'HKLM'
    $normalised = $normalised -replace '^HKLM:(?=\\|$)', 'HKLM'

    while ($normalised.Contains('\\')) { $normalised = $normalised.Replace('\\', '\') }
    foreach ($segment in $normalised.Split('\')) {
        if ($segment -eq '..') { return $null }
    }

    $normalised = $normalised.TrimEnd('\')
    if ($normalised -notmatch '^HKLM(\\|$)') { return $null }
    return $normalised
}

function Test-OfflineRegistryPath {
    <#
    .SYNOPSIS
        Reports whether a string is spelled as a registry path rather than a file path.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path.Trim() -match '^((Microsoft\.PowerShell\.Core\\)?Registry::)?(HKLM:|HKLM\\|HKEY_LOCAL_MACHINE)')
}

function Test-OfflinePathUnderRoot {
    <#
    .SYNOPSIS
        Reports whether a path is the given root or sits beneath it.

    .DESCRIPTION
        Prefix comparison appends the separator before testing, so 'D:' does not match
        'DD:\x' and 'D:\Win' does not match 'D:\Windows'.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Root,
        [Parameter(Mandatory = $false)][switch]$Registry
    )

    if ($Registry) {
        $candidate = ConvertTo-OfflineComparableRegistryPath $Path
        $prefix = ConvertTo-OfflineComparableRegistryPath $Root
    }
    else {
        $candidate = ConvertTo-OfflineComparablePath $Path
        $prefix = ConvertTo-OfflineComparablePath $Root
    }

    if (-not $candidate -or -not $prefix) { return $false }
    if ($candidate.Equals($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $candidate.StartsWith($prefix + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Set-OfflineRepairRoot {
    <#
    .SYNOPSIS
        Binds an offline volume, so the writing helpers can prove what they are acting on.

    .DESCRIPTION
        Called by Get-OfflineWindowsDisk once it has chosen a volume. Refuses the rescue
        VM's own system drive, because binding that would defeat the entire gate.

    .PARAMETER Path
        Volume root, for example 'D:' or 'D:\'. UNC roots are accepted as '\\server\share'.

    .EXAMPLE
        Set-OfflineRepairRoot -Path 'D:'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This changes in-process state only - it records which volume the helpers are allowed to touch - and never changes the system. Supporting -WhatIf would be actively harmful: skipping the bind would leave no root registered, so every subsequent Assert-OfflineTarget would throw and the run would fail for a reason unrelated to what the operator asked about.')]
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path)

    $normalised = ConvertTo-OfflineComparablePath $Path
    if (-not $normalised -or $normalised -notmatch $script:OfflineRootPattern) {
        throw "'$Path' is not a usable offline root. Expected a drive root such as 'D:' or a UNC share root."
    }

    $systemDrive = ConvertTo-OfflineComparablePath $env:SystemDrive
    if ($systemDrive -and $normalised.Equals($systemDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to bind '$Path' as an offline root: it is the rescue VM's own system drive."
    }

    $state = Get-OfflineRepairState
    if (-not ($state.Roots | Where-Object { $_.Equals($normalised, [System.StringComparison]::OrdinalIgnoreCase) })) {
        [void]$state.Roots.Add($normalised)
        Add-OfflineRepairLog -Level Info -Message "Bound offline repair root $normalised."
    }
    return $normalised
}

function Get-OfflineRepairRoot {
    <#
    .SYNOPSIS
        Returns the bound offline roots, most recently bound first.
    #>
    $roots = @((Get-OfflineRepairState).Roots)
    if ($roots.Count -eq 0) { return @() }
    [array]::Reverse($roots)
    return $roots
}

function Clear-OfflineRepairRoot {
    <#
    .SYNOPSIS
        Releases every bound root and registered hive key.

    .DESCRIPTION
        For a caller's finally block and for tests. After this, Assert-OfflineTarget
        throws for every path until something is bound again.
    #>
    $state = Get-OfflineRepairState
    $state.Roots.Clear()
    $state.HiveKeys.Clear()
    $state.WindowsDrive = $null
}

function Register-OfflineHiveKey {
    <#
    .SYNOPSIS
        Records a mount key as belonging to the offline image.

    .PARAMETER Key
        Mount key, for example 'HKLM\BROKEN_SYSTEM'.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Key)

    $normalised = ConvertTo-OfflineComparableRegistryPath $Key
    if (-not $normalised -or $normalised -eq 'HKLM') {
        throw "'$Key' is not a usable offline hive mount key."
    }

    $state = Get-OfflineRepairState
    if (-not ($state.HiveKeys | Where-Object { $_.Equals($normalised, [System.StringComparison]::OrdinalIgnoreCase) })) {
        [void]$state.HiveKeys.Add($normalised)
    }
    return $normalised
}

function Unregister-OfflineHiveKey {
    <#
    .SYNOPSIS
        Forgets a mount key once its hive has been unloaded.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Key)

    $normalised = ConvertTo-OfflineComparableRegistryPath $Key
    if (-not $normalised) { return }

    $state = Get-OfflineRepairState
    $existing = @($state.HiveKeys | Where-Object { $_.Equals($normalised, [System.StringComparison]::OrdinalIgnoreCase) })
    foreach ($item in $existing) { [void]$state.HiveKeys.Remove($item) }
}

function Get-OfflineHiveKey {
    <#
    .SYNOPSIS
        Returns the registered offline hive mount keys.
    #>
    return @((Get-OfflineRepairState).HiveKeys)
}

function Assert-OfflineTarget {
    <#
    .SYNOPSIS
        Throws unless a path belongs to the offline image. The gate every writer calls.

    .DESCRIPTION
        Call this before enabling a privilege, taking ownership, writing, or deleting.

        It throws rather than returning $false, and it throws when nothing has been bound
        at all. A helper that silently declines to act on an unbound target would let a
        repair report success having changed nothing, and a helper that returned $false
        would depend on every caller checking - which is the failure mode this exists to
        remove.

    .PARAMETER Path
        File system path or HKLM registry path to check.

    .PARAMETER OfflineRoot
        Optional explicit root to check against instead of the bound roots. Use when a
        caller wants to be explicit rather than rely on what Get-OfflineWindowsDisk bound.

    .PARAMETER Action
        Short description of the operation, used in the exception message.

    .EXAMPLE
        Assert-OfflineTarget -Path $file -Action 'take ownership'
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $false)][string]$OfflineRoot,
        [Parameter(Mandatory = $false)][string]$Action = 'modify'
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Refusing to $Action an empty path."
    }

    if (Test-OfflineRegistryPath $Path) {
        $normalised = ConvertTo-OfflineComparableRegistryPath $Path
        if (-not $normalised) {
            throw "Refusing to $Action '$Path': it is not a usable HKLM path."
        }

        $keys = if ($PSBoundParameters.ContainsKey('OfflineRoot') -and $OfflineRoot) { @($OfflineRoot) } else { @(Get-OfflineHiveKey) }
        if ($keys.Count -eq 0) {
            throw "Refusing to $Action '$Path': no offline hive is mounted, so this would act on the rescue VM's own registry."
        }
        foreach ($key in $keys) {
            if (Test-OfflinePathUnderRoot -Path $normalised -Root $key -Registry) { return $normalised }
        }
        throw "Refusing to $Action '$Path': it is outside the mounted offline hive(s) $($keys -join ', ')."
    }

    $normalised = ConvertTo-OfflineComparablePath $Path
    if (-not $normalised) {
        throw "Refusing to $Action '$Path': it is not a usable path."
    }
    if ($normalised -notmatch '^([A-Za-z]:|\\\\)') {
        throw "Refusing to $Action '$Path': it is not rooted on a drive, so it would resolve against the rescue VM's current directory."
    }

    # Belt and braces. Even a caller that somehow bound the wrong root cannot reach the
    # rescue VM's own Windows directory through this gate.
    $systemRoot = ConvertTo-OfflineComparablePath $env:SystemRoot
    if ($systemRoot -and (Test-OfflinePathUnderRoot -Path $normalised -Root $systemRoot)) {
        throw "Refusing to $Action '$Path': it is inside the rescue VM's own Windows directory."
    }

    $roots = if ($PSBoundParameters.ContainsKey('OfflineRoot') -and $OfflineRoot) { @($OfflineRoot) } else { @(Get-OfflineRepairRoot) }
    if ($roots.Count -eq 0) {
        throw "Refusing to $Action '$Path': no offline root is bound. Run Get-OfflineWindowsDisk first, or pass -OfflineRoot."
    }
    foreach ($root in $roots) {
        if (Test-OfflinePathUnderRoot -Path $normalised -Root $root) { return $normalised }
    }
    throw "Refusing to $Action '$Path': it is outside the bound offline root(s) $($roots -join ', ')."
}

#endregion

function Join-OfflinePath {
    <#
    .SYNOPSIS
        Joins a root and a child path without requiring the drive to exist.

    .DESCRIPTION
        Join-Path resolves the drive qualifier and throws DriveNotFoundException for a
        letter that is not currently mounted. Offline repairs routinely build paths on
        letters that are being mounted, are already unmounted, or are stale entries left
        on a partition, so the join is done as plain string composition instead.

        The root has to be volume-qualified. A root of '\' or a bare relative path would
        otherwise produce a root-relative result, which resolves against whatever drive the
        rescue VM's current directory happens to be on. It does NOT have to be a volume
        root: 'E:\Windows\System32\config' is a perfectly ordinary root for a join.

    .PARAMETER Root
        Root of the path, with or without a trailing backslash. Must be drive- or
        UNC-qualified, but may be at any depth. For example 'D:', 'D:\' or 'D:\Windows'.

    .PARAMETER ChildPath
        Relative path under the root, with or without a leading backslash.

    .EXAMPLE
        Join-OfflinePath -Root 'X:' -ChildPath 'Windows\System32\ntdll.dll'
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Root,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ChildPath
    )

    $trimmedRoot = ConvertTo-OfflineComparablePath $Root
    if (-not $trimmedRoot -or $trimmedRoot -notmatch $script:OfflineQualifiedPathPattern) { return $null }

    if ([string]::IsNullOrWhiteSpace($ChildPath)) { return "$trimmedRoot\" }
    return "$trimmedRoot\$($ChildPath.TrimStart('\'))"
}

function Test-OfflinePath {
    <#
    .SYNOPSIS
        Tests a path, returning false instead of throwing when the drive does not exist.

    .PARAMETER Path
        Path to test. Treated literally, so square brackets and braces are safe.

    .EXAMPLE
        if (Test-OfflinePath 'X:\Windows\System32\ntdll.dll') { 'found' }
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch { return $false }
}

function Test-OfflineFileSignature {
    <#
    .SYNOPSIS
        Reports what can actually be proven about a binary on the offline disk.

    .DESCRIPTION
        Authenticode alone is not enough offline. Most Windows inbox binaries are catalog
        signed, and the catalog store of the broken installation is not available to the
        rescue VM, so Get-AuthenticodeSignature reports NotSigned for perfectly good files.
        Boot manager payloads are compressed stubs that are not parseable at all.

        The version resource is used as a fallback, but it is unsigned data that any file
        can carry, so it never sets IsMicrosoft. Two separate signals are returned instead:

          IsMicrosoft        cryptographically proven - a valid Authenticode signature
                             whose subject carries the Microsoft organisation RDN. Use
                             this before trusting a binary enough to act on it.

          IsLikelyMicrosoft  proven, or claimed by the version resource. Use this when a
                             false negative is the more dangerous answer, for example when
                             deciding which drivers to leave alone.

          Confidence         High when Authenticode gave a definitive answer, Low when
                             only the version resource was available, None when nothing
                             could be established. A caller must not treat None as either
                             trusted or untrusted - it means the file could not be checked.

    .PARAMETER FilePath
        Full path to the file on the offline disk.

    .OUTPUTS
        PSCustomObject with Path, IsSigned, IsMicrosoft, IsLikelyMicrosoft, Confidence,
        Status, Subject and VersionCompany.

    .EXAMPLE
        (Test-OfflineFileSignature -FilePath 'D:\Windows\System32\drivers\storvsc.sys').IsLikelyMicrosoft

        IsLikelyMicrosoft, not IsMicrosoft. storvsc.sys is an inbox driver, so it is
        catalog-signed rather than Authenticode-signed, and its catalog lives on the
        offline image the rescue VM cannot consult. IsMicrosoft is therefore $false for a
        perfectly healthy copy. Asking for IsMicrosoft here would classify every inbox
        driver as untrusted, which is the more dangerous answer in this direction.

    .EXAMPLE
        $sig = Test-OfflineFileSignature -FilePath 'D:\Windows\System32\winload.efi'
        if ($sig.Confidence -eq 'High' -and -not $sig.IsMicrosoft) { 'replace it' }

        The safe shape for the opposite direction. Act on a file being bad only when
        Authenticode gave a definitive answer, so an unreadable catalog cannot be mistaken
        for evidence of tampering.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath
    )

    $result = [PSCustomObject]@{
        Path              = $FilePath
        IsSigned          = $false
        IsMicrosoft       = $false
        IsLikelyMicrosoft = $false
        Confidence        = 'None'
        Status            = 'FileNotFound'
        Subject           = ''
        VersionCompany    = ''
    }

    if (-not (Test-OfflinePath $FilePath)) { return $result }

    $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -eq 0) {
        $result.Status = 'ZeroByte'
        return $result
    }

    try { $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop }
    catch {
        $result.Status = 'Error'
        return $result
    }

    $result.Status = [string]$signature.Status
    $result.Subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }

    $versionInfo = $item.VersionInfo
    if ($versionInfo -and $versionInfo.CompanyName) { $result.VersionCompany = [string]$versionInfo.CompanyName }

    if ($signature.Status -eq 'Valid') {
        $result.IsSigned = $true
        $result.Confidence = 'High'
        # Anchored on the RDN boundary. An unanchored match is satisfied by a subject that
        # merely contains the text, for example CN=O=Microsoft Corporation, O=Somebody Else.
        if ($result.Subject -match '(?:^|,)\s*O=Microsoft Corporation\s*(?:,|$)') {
            $result.IsMicrosoft = $true
            $result.IsLikelyMicrosoft = $true
        }
        return $result
    }

    if ($signature.Status -in @('HashMismatch', 'NotTrusted')) {
        # Authenticode answered, and the answer is that the file is bad.
        $result.Confidence = 'High'
        return $result
    }

    if ($result.VersionCompany -match 'Microsoft') {
        # Consistent with a catalog signed inbox binary whose catalog the rescue VM cannot
        # see. Claimed, not proven, so IsMicrosoft stays false.
        $result.Status = 'CatalogSigned'
        $result.IsLikelyMicrosoft = $true
        $result.Confidence = 'Low'
        return $result
    }

    if ($signature.Status -in @('UnknownError', 'NotSupportedFileFormat')) {
        # Not parseable by Authenticode and carrying no version resource, for example a
        # compressed boot stub. Inconclusive: neither trusted nor untrusted.
        $result.Status = 'NotVerifiable'
        return $result
    }

    return $result
}

function Get-OfflineSecureBootState {
    <#
    .SYNOPSIS
        Reads the Secure Boot state the guest last booted with, from the Measured Boot log.

    .DESCRIPTION
        The obvious source, Control\SecureBoot\State\UEFISecureBootEnabled, does not work offline.
        That key is volatile: Windows recreates it from the firmware at every boot and never writes
        it to the SYSTEM hive file. Saving and reloading the hive on a running Server 2022 VM shows
        AvailableUpdates, SBAT and Servicing surviving while State disappears, so an attached disk
        never carries it. On a Generation 1 VM the key does not exist even while running.

        The firmware measures the EFI_GLOBAL_VARIABLE "SecureBoot" - a single byte, 0 or 1 - into
        PCR[7], and Windows writes the whole TCG log to Windows\Logs\MeasuredBoot at every boot.
        That is an ordinary file on the Windows partition, so it can simply be read.

        The record is UEFI_VARIABLE_DATA from the TCG PC Client Platform Firmware Profile:

            EFI_GUID VariableName;       // +0,  16 bytes
            UINT64   UnicodeNameLength;  // +16, in CHAR16 units
            UINT64   VariableDataLength; // +24, in bytes
            CHAR16   UnicodeName[];      // +32
            INT8     VariableData[];     // the state byte

        An absent or empty log is reported as unknown rather than as "off". Azure allows Secure Boot
        to be enabled with the vTPM disabled, and such a VM writes no Measured Boot log at all while
        still having Secure Boot on, so absence proves nothing.

    .OUTPUTS
        PSCustomObject with Known, Enabled, Source and MeasuredUtc.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $result = [PSCustomObject]@{ Known = $false; Enabled = $false; Source = ''; MeasuredUtc = $null }

    $logDir = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Logs\MeasuredBoot'
    if (-not (Test-OfflinePath $logDir)) {
        $result.Source = 'no Measured Boot log folder'
        return $result
    }

    $logs = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($logs.Count -eq 0) {
        $result.Source = 'the Measured Boot log folder is empty'
        return $result
    }

    # EFI_GLOBAL_VARIABLE {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}, in the little-endian order the
    # first three fields of an EFI_GUID are actually stored in.
    $guid = [byte[]]@(0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C)

    foreach ($log in ($logs | Select-Object -First 3)) {
        try { $bytes = [System.IO.File]::ReadAllBytes($log.FullName) }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not read the Measured Boot log $($log.Name): $($_.Exception.Message)"
            continue
        }

        for ($i = 0; $i -le $bytes.Length - 64; $i++) {
            if ($bytes[$i] -ne $guid[0]) { continue }

            $matched = $true
            for ($j = 1; $j -lt 16; $j++) {
                if ($bytes[$i + $j] -ne $guid[$j]) { $matched = $false; break }
            }
            if (-not $matched) { continue }

            $nameLength = [BitConverter]::ToUInt64($bytes, $i + 16)
            $dataLength = [BitConverter]::ToUInt64($bytes, $i + 24)

            # Guards against a random 16-byte run that happens to match the GUID. A real record
            # names a variable of a few characters and carries a byte or two of data.
            if ($nameLength -eq 0 -or $nameLength -gt 64) { continue }
            if ($dataLength -lt 1 -or $dataLength -gt 65536) { continue }
            if (($i + 32 + ($nameLength * 2) + $dataLength) -gt $bytes.Length) { continue }

            $nameBytes = New-Object byte[] ($nameLength * 2)
            [Array]::Copy($bytes, $i + 32, $nameBytes, 0, $nameLength * 2)
            if ([System.Text.Encoding]::Unicode.GetString($nameBytes) -ne 'SecureBoot') { continue }

            $result.Known = $true
            $result.Enabled = ($bytes[$i + 32 + ($nameLength * 2)] -eq 1)
            $result.Source = "Measured Boot log $($log.Name)"
            $result.MeasuredUtc = $log.LastWriteTimeUtc
            return $result
        }
    }

    $result.Source = 'the SecureBoot variable was not present in the most recent Measured Boot logs'
    return $result
}

function Get-OfflineNestedVmOwnershipTag {
    <#
    .SYNOPSIS
        Returns the persistent Notes marker shared by discovery and nested-guest helpers.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return 'repair-script-library:nested-repair:v1'
}

function Test-OfflineNestedVmManaged {
    <#
    .SYNOPSIS
        Reports whether a guest has the exact ownership marker on a separate Notes line.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Vm)

    if ($null -eq $Vm) { return $false }
    $notes = $Vm.PSObject.Properties['Notes']
    if (-not $notes) { return $false }
    $tag = Get-OfflineNestedVmOwnershipTag
    foreach ($line in ([string]$notes.Value -split '\r\n|\n|\r')) {
        if ([string]::Equals($line, $tag, [StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

function Enter-OfflineNestedVmLifecycle {
    <#
    .SYNOPSIS
        Serializes nested-guest ownership and disk hand-offs across host processes.

    .DESCRIPTION
        The lease is reentrant on the current thread, so discovery can call the guarded
        stopper while holding its own disk-preparation lease. Another thread or process
        is refused immediately. Release each acquired lease in finally; this is not a
        lease for an entire repair session or the lifetime of a running guest.
    #>
    [CmdletBinding()]
    [OutputType([System.Threading.Mutex])]
    param()

    $lease = $null
    $acquired = $false
    try {
        $lease = [System.Threading.Mutex]::new($false, 'Global\RslOfflineNestedVmLifecycleV1')
        try { $acquired = $lease.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
            Add-OfflineRepairLog -Level Warning -Message 'The previous nested-VM lifecycle owner exited unexpectedly. Guest ownership and disk state will be checked again before proceeding.'
        }
        if (-not $acquired) {
            throw 'Another nested-VM lifecycle operation is in progress on this host; the disk hand-off was refused.'
        }
        return $lease
    }
    catch {
        if ($lease) {
            try { if ($acquired) { $lease.ReleaseMutex() } }
            finally { $lease.Dispose() }
        }
        Add-OfflineRepairLog -Level Error -Message "Could not acquire the nested-VM lifecycle lease: $($_.Exception.Message)"
        throw
    }
}

function Exit-OfflineNestedVmLifecycle {
    <#
    .SYNOPSIS
        Releases and disposes a lifecycle lease acquired by the current thread.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Threading.Mutex]$Lease)

    try { $Lease.ReleaseMutex() }
    finally { $Lease.Dispose() }
}
