#########################################################################################################
#
# .SYNOPSIS
#   Rebuilds a damaged Authenticode catalog store on an offline disk, so a VM that bugchecks
#   0x5A CRITICAL_SERVICE_FAILED - or stops with 0xC0000428 - can boot again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM that will not boot even though every file on it is byte-perfect. Boot code
#   integrity does not trust a driver because of what it is called; it trusts it because its
#   Authenticode hash is published in a signed catalog. A driver that carries no embedded
#   signature has nothing to fall back on. If the catalog that published its hash is gone, the
#   load fails with STATUS_INVALID_IMAGE_HASH (0xC0000428), and if that driver is also marked
#   ErrorControl=3 (Critical) the boot is aborted with bugcheck 0x5A CRITICAL_SERVICE_FAILED.
#
#   Boot code integrity parses the raw .cat files under
#     <windows>\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}
#   It does NOT consult CatRoot2. CatRoot2 is a CryptSvc database that only exists once the OS is
#   running, so the widely repeated advice to delete CatRoot2 cannot fix a machine that never gets
#   that far. This script does not touch CatRoot2.
#
#   WHAT MAKES THIS A STORE FAULT RATHER THAN A DRIVER FAULT
#
#   The fingerprint is several unrelated inbox drivers failing the same way at once. Replacing
#   individual .sys files does not help - the bugcheck simply moves to the next driver in load
#   order, because the thing that is missing is the published hash, not the binary.
#
#   Measured on a live Azure Server 2022 VM, build 20348, UBR 5499:
#
#     boot-critical drivers (Start 0 or 1, kernel/FS)            126
#     of those, carrying NO embedded signature                    12
#     of those 12, resolved by the catalog store                  12
#
#     the 12, with Start/ErrorControl:
#       afunix s1 e1     ahcache s1 e1    BasicDisplay s1 e0   BasicRender s1 e0
#       cdrom  s1 e1     Dfsc    s1 e1    FileCrypt    s1 e3   NdisCap      s1 e1
#       NetBT  s1 e1     npsvctrig s1 e2  nsiproxy     s1 e1   Null         s1 e1
#
#   FileCrypt is ErrorControl=3, Critical. It is the driver that turns a damaged catalog store
#   from a degraded boot into a bugcheck, and it depends entirely on the store. npsvctrig at
#   ErrorControl=2 (Severe) compounds it. That is the whole mechanism, measured rather than
#   assumed, and it is why this repair has to happen offline: the machine never boots, so nothing
#   can be fixed from inside it.
#
#   THE REPAIR NEEDS NO DONOR DISK
#
#   The monolithic script this replaces required the operator to find a donor machine at the same
#   build AND the same patch level, mount it, and point at its CatRoot. That is a hard thing to
#   produce in an incident, and getting the UBR wrong produces a store that indexes perfectly and
#   resolves nothing.
#
#   It is also unnecessary. Every catalog in CatRoot is a payload file of the servicing package
#   that delivered it, and the package copy is still on the broken disk, under
#   <windows>\servicing\Packages. Measured on the same VM:
#
#     CatRoot\{GUID}                    2,990 catalogs   56.7 MB
#     servicing\Packages                2,962 catalogs   56.0 MB
#     random sample compared by SHA256     50 of 50 byte-IDENTICAL, 0 different
#     reference binaries covered locally   18 of 18
#     catalog-dependent boot drivers       12 of 12 recoverable from servicing\Packages
#
#   The local copy is therefore the same build and the same UBR by construction - it cannot be
#   mismatched, because it is the very package payload this installation was built from. That
#   removes the donor, and with it the entire class of "the donor did not match" failures.
#
#   The 28 catalogs that exist only in CatRoot are ntprint.cat, ntprint4.cat, oem0.cat to
#   oem12.cat and an Azure VM extension catalog: print drivers and third-party/OEM drivers
#   published into the store at install time. None of them covers an inbox boot driver. They are
#   reported honestly rather than silently ignored, and -donorPath remains available for the rare
#   case where a third-party boot driver's own catalog is the thing that was lost.
#
#   WHY MERGING IS SAFE
#
#   Catalogs are additive. Each one carries its own Microsoft signature, so adding one can only
#   widen the set of hashes boot code integrity is able to resolve. Nothing already present is
#   invalidated. This script never overwrites a catalog that opens correctly: a name that already
#   exists with identical content is skipped, and a name that exists with different content is
#   placed alongside it under a suffixed name instead of replacing it, because discarding a
#   catalog can only ever reduce coverage. The only files it replaces are ones that cannot be
#   opened at all - a zero-length or truncated .cat publishes nothing and can only be an
#   improvement to replace.
#
#   DETECTION, AND WHY A HEALTHY DISK IS LEFT ALONE
#
#   Detection is not a file count. It asks the same question boot code integrity asks: can this
#   store resolve the hashes of this machine's own binaries?
#
#     - The direct trigger is a boot-critical driver that carries no embedded signature and whose
#       hash resolves in no catalog in the store. That is the fault that stops the boot.
#     - The corroborating signal is a coverage ratio over eighteen inbox binaries that every
#       healthy Windows publishes in a servicing catalog - ntoskrnl.exe, hal.dll, ntfs.sys,
#       acpi.sys and the rest. A healthy Server 2022 scores 18 of 18, ratio 1.00, measured.
#
#   The monolithic script called a store "Usable" at ratio 0.6. That number was never measured
#   against anything. It is not used here: the threshold below is 0.9, which is one permitted miss
#   out of eighteen, chosen so a single legitimately out-of-band binary on some other build cannot
#   make this script write to a machine that has nothing wrong with it.
#
#   On a healthy disk every check passes, no finding is produced, and this script writes nothing.
#
# .PARAMETER detectOnly
#   'true' reports what is wrong and changes nothing at all. No catalog is copied and no backup is
#   taken.
#
# .PARAMETER windowsDrive
#   Skips discovery and uses this drive letter as the offline Windows volume.
#
# .PARAMETER donorPath
#   Merges from this path instead of the disk's own <windows>\servicing\Packages. Leave it empty
#   for the normal repair, which needs no donor because the servicing payload on the broken disk
#   is the same build and UBR by construction. Supply it only when the lost catalog belongs to a
#   third-party boot driver, which servicing\Packages cannot republish.
#
# .PARAMETER forceDonor
#   'true' uses the chosen source even when it fails the coverage check - that is, even when it
#   resolves too few of this machine's own reference binaries to be a build match. The check
#   exists because a mismatched store indexes perfectly and resolves nothing, so overriding it
#   can add files without making the machine bootable. It has no effect on a source that passes.
#
#   Reference: "Driver Signing" and "Kernel-Mode Code Signing requirements"
#   https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding and New-CatalogIndex build objects and change nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Findings are consumed inside script blocks passed to the offline hive helpers, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = '',
    [Parameter(Mandatory = $false)][string]$donorPath = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$forceDonor = 'false'
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isForceDonor = ($forceDonor -eq 'true')

$script:DocUrl = 'https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing'

# The only catalog store boot code integrity reads.
$script:CatalogGuid = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'

# Where the package payload copy of every inbox catalog lives on the guest's own disk.
$script:LocalSourceRelative = 'servicing\Packages'

# Measured healthy on build 20348 UBR 5499: 18 of 18, ratio 1.00. 0.9 permits a single miss so a
# legitimately out-of-band binary on another build cannot trigger a write.
$script:MinCoverageRatio = 0.9

# Below this many resolvable reference files the ratio is not evidence of anything.
$script:MinSampleSize = 6

# A catalog smaller than this cannot hold a signed member list; it is treated as truncated only if
# it also fails to open.
$script:MinPlausibleCatalogBytes = 512

# Inbox binaries every healthy Windows publishes in a servicing catalog. Used for two judgements:
# is the guest's own store complete enough for a miss to mean corruption, and does a donor match
# this guest closely enough to be merged into it. Only files that exist and are non-empty count,
# so a build that ships fewer of them does not dilute the ratio.
$script:ReferenceBinaries = @(
    'System32\ntoskrnl.exe', 'System32\ntdll.dll', 'System32\kernel32.dll'
    'System32\hal.dll', 'System32\smss.exe', 'System32\services.exe'
    'System32\winlogon.exe', 'System32\advapi32.dll', 'System32\user32.dll'
    'System32\drivers\ntfs.sys', 'System32\drivers\disk.sys', 'System32\drivers\partmgr.sys'
    'System32\drivers\volsnap.sys', 'System32\drivers\acpi.sys', 'System32\drivers\pci.sys'
    'System32\drivers\fltmgr.sys', 'System32\drivers\ndis.sys', 'System32\drivers\tcpip.sys'
)

$script:CatalogNativeReady = $null

function Initialize-CatalogNativeType {
    <#
    .SYNOPSIS
        Loading the wintrust catalog interop used to index a store and hash a file the way
        Authenticode does.

    .DESCRIPTION
        The hashes involved are PE-aware: they deliberately exclude the file checksum and the
        certificate table, which is exactly what makes them comparable with a catalog member
        entry. A plain SHA256 of the file is not the same number and would match nothing.
    #>
    if ($null -ne $script:CatalogNativeReady) { return $script:CatalogNativeReady }
    if ('OfflineRepair.CatalogNative' -as [type]) {
        $script:CatalogNativeReady = $true
        return $true
    }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace OfflineRepair
{
    public static class CatalogNative
    {
        // CRYPTCAT_OPEN_EXISTING (0x4) | CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG (0x20000000)
        private const uint OpenFlags = 0x20000004;

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CryptCATOpen(string pwszFileName, uint fdwOpenFlags,
            IntPtr hProv, uint dwPublicVersion, uint dwEncodingType);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATClose(IntPtr hCatalog);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr pPrevMember);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(ref IntPtr phCatAdmin,
            IntPtr pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm,
            IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin,
            IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile,
            ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ATTR_BLOB { public uint cbData; public IntPtr pbData; }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPTCATMEMBER
        {
            public uint cbStruct;
            public IntPtr pwszReferenceTag;
            public IntPtr pwszFileName;
            public Guid gSubjectType;
            public uint fdwMemberFlags;
            public IntPtr pIndirectData;
            public uint dwCertVersion;
            public uint dwReserved;
            public IntPtr hReserved;
            public CRYPT_ATTR_BLOB sEncodedIndirectData;
            public CRYPT_ATTR_BLOB sEncodedMemberInfo;
        }

        private static string ToHex(byte[] bytes, int length)
        {
            char[] c = new char[length * 2];
            for (int i = 0; i < length; i++)
            {
                int b = bytes[i] >> 4;
                c[i * 2] = (char)(b > 9 ? b + 0x37 : b + 0x30);
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(b > 9 ? b + 0x37 : b + 0x30);
            }
            return new string(c);
        }

        // The Authenticode reference tags (SHA-256 first, then SHA-1) that identify this file as a
        // catalog member. Both are returned because a store may publish either.
        public static string[] GetFileHashTags(string path)
        {
            List<string> tags = new List<string>();
            using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open,
                       System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

                IntPtr ctx = IntPtr.Zero;
                if (CryptCATAdminAcquireContext2(ref ctx, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                {
                    try
                    {
                        uint cb = 0;
                        CryptCATAdminCalcHashFromFileHandle2(ctx, hFile, ref cb, null, 0);
                        if (cb > 0 && cb <= 1024)
                        {
                            byte[] buf = new byte[cb];
                            fs.Position = 0;
                            if (CryptCATAdminCalcHashFromFileHandle2(ctx, hFile, ref cb, buf, 0))
                                tags.Add(ToHex(buf, (int)cb));
                        }
                    }
                    finally { CryptCATAdminReleaseContext(ctx, 0); }
                }

                uint cb1 = 0;
                fs.Position = 0;
                CryptCATAdminCalcHashFromFileHandle(hFile, ref cb1, null, 0);
                if (cb1 > 0 && cb1 <= 1024)
                {
                    byte[] buf1 = new byte[cb1];
                    fs.Position = 0;
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, ref cb1, buf1, 0))
                        tags.Add(ToHex(buf1, (int)cb1));
                }
            }
            return tags.ToArray();
        }

        // Maps every member reference tag to the catalog that publishes it. Catalogs are opened in
        // parallel: each thread owns the handle it opens, so no wintrust state is shared, and a
        // serial walk of several thousand catalogs is otherwise the slowest step in a repair run.
        // stats[0] = catalogs opened, stats[1] = member entries seen.
        public static Dictionary<string, int> BuildIndex(string[] catalogPaths, int[] stats)
        {
            ConcurrentDictionary<string, int> index =
                new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int opened = 0, members = 0;

            ParallelOptions options = new ParallelOptions();
            options.MaxDegreeOfParallelism = Math.Min(16, Math.Max(2, Environment.ProcessorCount * 2));

            Parallel.For(0, catalogPaths.Length, options, delegate(int i)
            {
                IntPtr hCat = CryptCATOpen(catalogPaths[i], OpenFlags, IntPtr.Zero, 0, 0);
                if (hCat == IntPtr.Zero || hCat == new IntPtr(-1)) return;
                Interlocked.Increment(ref opened);
                int localMembers = 0;
                try
                {
                    IntPtr m = IntPtr.Zero;
                    while ((m = CryptCATEnumerateMember(hCat, m)) != IntPtr.Zero)
                    {
                        CRYPTCATMEMBER cm = (CRYPTCATMEMBER)Marshal.PtrToStructure(m, typeof(CRYPTCATMEMBER));
                        if (cm.pwszReferenceTag == IntPtr.Zero) continue;
                        string tag = Marshal.PtrToStringUni(cm.pwszReferenceTag);
                        if (string.IsNullOrEmpty(tag)) continue;
                        localMembers++;
                        // First writer wins. Which catalog a shared tag maps to is arbitrary in a
                        // serial walk too, and any catalog holding it is equally valid.
                        index.TryAdd(tag, i);
                    }
                }
                catch { }
                finally { CryptCATClose(hCat); }
                Interlocked.Add(ref members, localMembers);
            });

            if (stats != null && stats.Length >= 2) { stats[0] = opened; stats[1] = members; }
            return new Dictionary<string, int>(index, StringComparer.OrdinalIgnoreCase);
        }

        // Catalogs present on disk that wintrust cannot open at all. A file in this list publishes
        // nothing, so it is contributing no coverage however plausible its name looks.
        public static string[] GetUnopenable(string[] catalogPaths)
        {
            List<string> bad = new List<string>();
            for (int i = 0; i < catalogPaths.Length; i++)
            {
                IntPtr hCat = CryptCATOpen(catalogPaths[i], OpenFlags, IntPtr.Zero, 0, 0);
                if (hCat == IntPtr.Zero || hCat == new IntPtr(-1)) { bad.Add(catalogPaths[i]); continue; }
                CryptCATClose(hCat);
            }
            return bad.ToArray();
        }
    }
}
'@
        $script:CatalogNativeReady = $true
    }
    catch {
        $script:CatalogNativeReady = $false
        Add-OfflineRepairLog -Level Warning -Message "The wintrust catalog APIs could not be loaded on this rescue VM: $($_.Exception.Message)"
    }
    return $script:CatalogNativeReady
}

function Get-CatalogStorePath {
    <#
    .SYNOPSIS
        The one store boot code integrity reads.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)
    return (Join-Path $WindowsPath "System32\CatRoot\$($script:CatalogGuid)")
}

function Get-LocalCatalogSourcePath {
    <#
    .SYNOPSIS
        The guest's own package payload copy of its catalogs.

    .DESCRIPTION
        Same build and same UBR by construction: these are the files the installation was built
        from. Measured byte-identical to the store copies on build 20348.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)
    return (Join-Path $WindowsPath $script:LocalSourceRelative)
}

function Get-AuthenticodeTag {
    <#
    .SYNOPSIS
        The catalog member identifiers for one file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or $item.Length -eq 0) { return @() }
    if (-not (Initialize-CatalogNativeType)) { return @() }

    try { return @([OfflineRepair.CatalogNative]::GetFileHashTags($item.FullName)) }
    catch { return @() }
}

function Get-ReferenceSampleFile {
    <#
    .SYNOPSIS
        The inbox binaries used to measure whether a store can resolve this machine.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    foreach ($relative in $script:ReferenceBinaries) {
        $path = Join-Path $WindowsPath $relative
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($item -and -not $item.PSIsContainer -and $item.Length -gt 0) { $item.FullName }
    }
}

function New-CatalogIndex {
    <#
    .SYNOPSIS
        Indexing a folder of catalogs, and reporting which of them could not be opened.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{
        Path = $Path; Exists = $false; Files = @(); FileCount = 0; TotalBytes = 0
        Index = $null; Opened = 0; Members = 0; Unopenable = @(); Error = ''
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $result }
    $result.Exists = $true

    $files = @(Get-ChildItem -LiteralPath $Path -Filter '*.cat' -File -ErrorAction SilentlyContinue)
    $result.Files = $files
    $result.FileCount = $files.Count
    if ($files.Count -eq 0) { return $result }
    $result.TotalBytes = ($files | Measure-Object -Property Length -Sum).Sum

    if (-not (Initialize-CatalogNativeType)) {
        $result.Error = 'the wintrust catalog APIs are unavailable on this rescue VM'
        return $result
    }

    $stats = [int[]]@(0, 0)
    try {
        $result.Index = [OfflineRepair.CatalogNative]::BuildIndex([string[]]($files.FullName), $stats)
        $result.Opened = $stats[0]
        $result.Members = $stats[1]
    }
    catch {
        $result.Error = $_.Exception.Message
        return $result
    }

    if ($result.Opened -lt $files.Count) {
        try { $result.Unopenable = @([OfflineRepair.CatalogNative]::GetUnopenable([string[]]($files.FullName))) }
        catch {
            Add-OfflineRepairLog -Level Info -Message "$($files.Count - $result.Opened) catalog(s) in $Path did not open, but the individual files could not be identified ($($_.Exception.Message))."
        }
    }

    return $result
}

function Get-StoreCoverage {
    <#
    .SYNOPSIS
        The question boot code integrity asks: does this store publish this machine's own hashes?
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$CatalogIndex,
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $result = [PSCustomObject]@{ Present = 0; Resolved = 0; Ratio = 0.0; Missing = @() }
    if (-not $CatalogIndex.Index) { return $result }

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($sample in @(Get-ReferenceSampleFile -WindowsPath $WindowsPath)) {
        $result.Present++
        $found = $false
        foreach ($tag in (Get-AuthenticodeTag -FilePath $sample)) {
            if ($CatalogIndex.Index.ContainsKey($tag)) { $found = $true; break }
        }
        if ($found) { $result.Resolved++ } else { [void]$missing.Add((Split-Path $sample -Leaf)) }
    }

    $result.Missing = @($missing)
    if ($result.Present -gt 0) { $result.Ratio = [math]::Round($result.Resolved / $result.Present, 3) }
    return $result
}

function Get-PeCertificateTableSize {
    <#
    .SYNOPSIS
        The size of a PE image's embedded certificate table.

    .DESCRIPTION
        Zero means the binary carries no embedded signature and therefore depends entirely on the
        catalog store. Minus one means the header could not be read and no claim is made.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.BinaryReader($stream)

        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or $peOffset -gt ($stream.Length - 24)) { return -1 }

        $stream.Position = $peOffset + 4 + 20        # PE signature + COFF header
        $magic = $reader.ReadUInt16()                # 0x20B = PE32+, 0x10B = PE32
        $directoryOffset = if ($magic -eq 0x20B) { $peOffset + 24 + 112 } elseif ($magic -eq 0x10B) { $peOffset + 24 + 96 } else { return -1 }

        $stream.Position = $directoryOffset + 32     # security directory is entry 4, each 8 bytes
        $null = $reader.ReadUInt32()                 # RVA, unused
        return [int]$reader.ReadUInt32()             # size
    }
    catch { return -1 }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Get-BootDriverRecord {
    <#
    .SYNOPSIS
        Every boot-critical driver on the offline guest, read from the mounted SYSTEM hive.

    .DESCRIPTION
        Start 0 (Boot) and 1 (System) only, and only kernel or file system drivers. Those are the
        loads that happen before anything can log in and fix them.

        Must be called inside Invoke-WithHive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $records = [System.Collections.Generic.List[object]]::new()
    $servicesKey = Join-Path $SystemRoot 'Services'
    if (-not (Test-Path -LiteralPath $servicesKey)) { return @($records) }

    foreach ($key in (Get-ChildItem -LiteralPath $servicesKey -ErrorAction SilentlyContinue)) {
        $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
        if (-not $properties) { continue }
        if ($null -eq $properties.Start -or [int]$properties.Start -gt 1) { continue }
        if ($null -eq $properties.Type -or ([int]$properties.Type -ne 1 -and [int]$properties.Type -ne 2)) { continue }

        $imagePath = $properties.ImagePath
        $resolved = if ([string]::IsNullOrWhiteSpace($imagePath)) {
            Join-Path $WindowsDrive "Windows\System32\drivers\$($key.PSChildName).sys"
        }
        else {
            Resolve-OfflineImagePath -ImagePath $imagePath -WindowsDrive $WindowsDrive
        }

        [void]$records.Add([PSCustomObject]@{
                Name         = $key.PSChildName
                Path         = $resolved
                Start        = [int]$properties.Start
                ErrorControl = if ($null -eq $properties.ErrorControl) { 0 } else { [int]$properties.ErrorControl }
            })
    }

    return @($records)
}

function Get-UnresolvedBootDriver {
    <#
    .SYNOPSIS
        The drivers that actually stop the boot.

    .DESCRIPTION
        A driver qualifies only when all three are true: it is boot-critical, its file carries no
        embedded signature, and no catalog in the store publishes its hash. Anything with an
        embedded signature is verified without the store and is not this fault.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Drivers,
        [Parameter(Mandatory = $true)]$CatalogIndex
    )

    $unresolved = [System.Collections.Generic.List[object]]::new()
    if (-not $CatalogIndex.Index) { return @($unresolved) }

    foreach ($driver in @($Drivers)) {
        if (-not (Test-Path -LiteralPath $driver.Path -PathType Leaf)) { continue }
        if ((Get-PeCertificateTableSize -Path $driver.Path) -ne 0) { continue }

        $found = $false
        foreach ($tag in (Get-AuthenticodeTag -FilePath $driver.Path)) {
            if ($CatalogIndex.Index.ContainsKey($tag)) { $found = $true; break }
        }
        if (-not $found) { [void]$unresolved.Add($driver) }
    }

    return @($unresolved)
}

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Repaired   = $false
        Data       = $Data
    }
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Everything wrong with this store, in one list.

    .DESCRIPTION
        A healthy disk produces an empty list. Each finding names the evidence that produced it, so
        nothing is reported on inference alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Store,
        [Parameter(Mandatory = $true)]$Coverage,
        [Parameter(Mandatory = $true)]$Unresolved,
        [Parameter(Mandatory = $true)][bool]$SourceUsable
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not $Store.Exists) {
        [void]$findings.Add((New-Finding -Cause 'StoreMissing' -Item $Store.Path `
                    -Message "The catalog store $($Store.Path) does not exist. Boot code integrity has nothing to verify catalog-signed drivers against." `
                    -Repairable $SourceUsable))
        return @($findings)
    }

    if ($Store.FileCount -eq 0) {
        [void]$findings.Add((New-Finding -Cause 'StoreEmpty' -Item $Store.Path `
                    -Message "The catalog store holds no .cat files at all. Every catalog-signed driver on this machine is unverifiable." `
                    -Repairable $SourceUsable))
        return @($findings)
    }

    if ($Store.Error) {
        [void]$findings.Add((New-Finding -Cause 'StoreUnreadable' -Item $Store.Path `
                    -Message "The catalog store could not be indexed ($($Store.Error)), so it cannot be assessed." `
                    -Repairable $false))
        return @($findings)
    }

    # The direct cause of the bugcheck. Reported as ONE finding, not one per driver: this is a
    # single store-level fault with several symptoms, and the returned log is capped at 4 KB, so a
    # finding per driver would push the summary out of the window the operator actually sees.
    if (@($Unresolved).Count -gt 0) {
        $ordered = @($Unresolved | Sort-Object -Property @{ Expression = 'ErrorControl'; Descending = $true }, 'Name')
        $names = @($ordered | ForEach-Object { '{0}(e{1})' -f $_.Name, $_.ErrorControl })
        $critical = @($ordered | Where-Object { $_.ErrorControl -eq 3 })
        $severe = @($ordered | Where-Object { $_.ErrorControl -eq 2 })

        $consequence = if ($critical.Count -gt 0) {
            "$(@($critical | ForEach-Object { $_.Name }) -join ', ') is ErrorControl=3 (Critical), so the boot is aborted with bugcheck 0x5A CRITICAL_SERVICE_FAILED."
        }
        elseif ($severe.Count -gt 0) {
            "$(@($severe | ForEach-Object { $_.Name }) -join ', ') is ErrorControl=2 (Severe), so the boot falls back to Last Known Good."
        }
        else {
            'None is Critical, so these loads fail and the boot continues degraded.'
        }

        [void]$findings.Add((New-Finding -Cause 'DriverUnresolved' -Item 'boot-critical drivers' `
                    -Message "$(@($ordered).Count) boot-critical driver(s) carry no embedded signature and resolve in no catalog in this store, so each fails with STATUS_INVALID_IMAGE_HASH (0xC0000428): $($names -join ', '). $consequence" `
                    -Repairable $SourceUsable -Data $ordered))
    }

    # The corroborating store-level signal.
    if ($Coverage.Present -ge $script:MinSampleSize -and $Coverage.Ratio -lt $script:MinCoverageRatio) {
        [void]$findings.Add((New-Finding -Cause 'CoverageLow' -Item $Store.Path `
                    -Message "This store resolves only $($Coverage.Resolved) of $($Coverage.Present) inbox reference binaries (ratio $($Coverage.Ratio), healthy is 1.00). That is store-level damage rather than one bad driver. Unresolved: $((@($Coverage.Missing) -join ', '))" `
                    -Repairable $SourceUsable -Data $Coverage))
    }

    # Files that are present but publish nothing.
    if (@($Store.Unopenable).Count -gt 0) {
        $sample = @($Store.Unopenable | Select-Object -First 5 | ForEach-Object { Split-Path $_ -Leaf })
        [void]$findings.Add((New-Finding -Cause 'CatalogUnopenable' -Item $Store.Path `
                    -Message "$(@($Store.Unopenable).Count) catalog file(s) in the store cannot be opened by wintrust and publish no hashes at all - truncated or zero-length. Example(s): $($sample -join ', ')" `
                    -Repairable $SourceUsable -Data @($Store.Unopenable)))
    }

    return @($findings)
}

function Resolve-DonorStorePath {
    <#
    .SYNOPSIS
        Accepts any sensible way of naming a donor: the GUID folder, a CatRoot folder, a System32
        folder, a Windows folder, or a mounted volume.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $candidates = @(
        $Path
        (Join-Path $Path $script:CatalogGuid)
        (Join-Path $Path "CatRoot\$($script:CatalogGuid)")
        (Join-Path $Path "System32\CatRoot\$($script:CatalogGuid)")
        (Join-Path $Path "Windows\System32\CatRoot\$($script:CatalogGuid)")
        (Join-Path $Path 'servicing\Packages')
        (Join-Path $Path 'Windows\servicing\Packages')
    )

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $found = @(Get-ChildItem -LiteralPath $candidate -Filter '*.cat' -File -ErrorAction SilentlyContinue)
        if ($found.Count -gt 0) { return $candidate }
    }
    return $null
}

function Invoke-CatalogMerge {
    <#
    .SYNOPSIS
        Merging catalogs from a source into the guest's store.

    .DESCRIPTION
        Never overwrites a catalog that opens. Identical content is skipped, different content with
        the same name is placed alongside under a suffixed name, and only a file that wintrust
        cannot open at all is replaced.

        The store folder's descriptor is taken once rather than per file: at several thousand
        catalogs, per-file ownership changes dominate the runtime by a wide margin.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)]$SourceFiles,
        [Parameter(Mandatory = $true)]$Unopenable
    )

    $outcome = [PSCustomObject]@{ Added = 0; Replaced = 0; SideBySide = 0; Skipped = 0; Failed = 0; Errors = @() }

    $existing = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $StorePath -Filter '*.cat' -File -ErrorAction SilentlyContinue)) {
        $existing[$file.Name] = $file
    }
    $badNames = @{}
    foreach ($bad in @($Unopenable)) { $badNames[(Split-Path $bad -Leaf)] = $true }

    $plan = [System.Collections.Generic.List[object]]::new()
    foreach ($source in @($SourceFiles)) {
        if (-not $existing.ContainsKey($source.Name)) {
            [void]$plan.Add([PSCustomObject]@{ Source = $source.FullName; Target = (Join-Path $StorePath $source.Name); Kind = 'Added' })
            continue
        }

        # Present but broken: replacing it can only be an improvement.
        if ($badNames.ContainsKey($source.Name)) {
            [void]$plan.Add([PSCustomObject]@{ Source = $source.FullName; Target = (Join-Path $StorePath $source.Name); Kind = 'Replaced' })
            continue
        }

        $current = $existing[$source.Name]
        if ($current.Length -eq $source.Length -and
            (Get-FileHash -LiteralPath $current.FullName -Algorithm SHA256).Hash -eq
            (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash) {
            $outcome.Skipped++
            continue
        }

        $sideBySide = Join-Path $StorePath ('{0}.local{1}' -f [IO.Path]::GetFileNameWithoutExtension($source.Name), [IO.Path]::GetExtension($source.Name))
        if (Test-Path -LiteralPath $sideBySide) { $outcome.Skipped++; continue }
        [void]$plan.Add([PSCustomObject]@{ Source = $source.FullName; Target = $sideBySide; Kind = 'SideBySide' })
    }

    if ($plan.Count -eq 0) {
        Add-OfflineRepairLog -Level Info -Message 'The store already holds every catalog this source can offer, so nothing was copied.'
        return $outcome
    }

    Add-OfflineRepairLog -Level Info -Message "Merging $($plan.Count) catalog(s) into $StorePath."

    $storeSddl = $null
    try {
        $storeSddl = Grant-OfflinePathAccess -Path $StorePath

        foreach ($item in $plan) {
            try {
                Copy-Item -LiteralPath $item.Source -Destination $item.Target -Force -ErrorAction Stop
                switch ($item.Kind) {
                    'Added' { $outcome.Added++ }
                    'Replaced' { $outcome.Replaced++ }
                    'SideBySide' { $outcome.SideBySide++ }
                }
            }
            catch {
                # Fall back to the per-file protected copy, which takes and hands back ownership of
                # the individual file when the folder grant was not enough.
                $fallback = Copy-OfflineProtectedFile -Source $item.Source -Destination $item.Target
                if ($fallback.Copied) {
                    switch ($item.Kind) {
                        'Added' { $outcome.Added++ }
                        'Replaced' { $outcome.Replaced++ }
                        'SideBySide' { $outcome.SideBySide++ }
                    }
                }
                else {
                    $outcome.Failed++
                    $outcome.Errors += "$(Split-Path $item.Target -Leaf): $($fallback.Reason)"
                }
            }
        }
    }
    finally {
        if ($storeSddl) { [void](Restore-OfflinePathSecurity -Path $StorePath -Sddl $storeSddl) }
    }

    return $outcome
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $windowsPath = $offline.WindowsPath
    $volumeRoot = Split-Path -Path $windowsPath -Parent

    Log-Info "Offline Windows installation: $windowsPath on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "$($script:DocUrl) describes why a kernel-mode driver must be signed; this script checks that the store which publishes those signatures can still resolve this machine's own binaries." | Tee-Object -FilePath $logFile -Append

    if (-not (Initialize-CatalogNativeType)) {
        Log-Error 'The wintrust catalog APIs are unavailable on this rescue VM, so the catalog store cannot be assessed. No changes were made.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $storePath = Get-CatalogStorePath -WindowsPath $windowsPath
    Log-Info "Catalog store: $storePath" | Tee-Object -FilePath $logFile -Append
    Log-Info 'CatRoot2 is a CryptSvc database that only exists once the OS runs. It is not consulted during boot and is not touched by this script.' | Tee-Object -FilePath $logFile -Append

    $store = New-CatalogIndex -Path $storePath
    if ($store.Exists) {
        Log-Info ("Store contents: {0:N0} catalog file(s), {1:N1} MB, {2:N0} opened, {3:N0} published hashes." -f `
                $store.FileCount, ($store.TotalBytes / 1MB), $store.Opened, $(if ($store.Index) { $store.Index.Count } else { 0 })) | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning "The catalog store folder is not present at $storePath." | Tee-Object -FilePath $logFile -Append
    }

    $coverage = Get-StoreCoverage -CatalogIndex $store -WindowsPath $windowsPath
    Log-Info "Reference coverage: $($coverage.Resolved) of $($coverage.Present) inbox binaries resolve in this store (ratio $($coverage.Ratio); healthy measured 1.00, threshold $($script:MinCoverageRatio))." | Tee-Object -FilePath $logFile -Append

    # Which source will be used if anything needs repairing.
    $sourcePath = $null
    $sourceKind = ''
    if ($donorPath) {
        $sourcePath = Resolve-DonorStorePath -Path $donorPath
        $sourceKind = 'donor'
        if (-not $sourcePath) {
            Log-Warning "No catalogs were found at or under the donor path '$donorPath'." | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        $localSource = Get-LocalCatalogSourcePath -WindowsPath $windowsPath
        if (Test-Path -LiteralPath $localSource -PathType Container) {
            $sourcePath = $localSource
            $sourceKind = 'the guest''s own servicing store'
        }
        else {
            Log-Warning "This installation has no $($script:LocalSourceRelative) folder, so no local catalog source is available." | Tee-Object -FilePath $logFile -Append
        }
    }

    $source = if ($sourcePath) { New-CatalogIndex -Path $sourcePath } else { $null }
    $sourceCoverage = $null
    $sourceUsable = $false

    if ($source -and $source.FileCount -gt 0 -and $source.Index) {
        $sourceCoverage = Get-StoreCoverage -CatalogIndex $source -WindowsPath $windowsPath
        Log-Info ("Repair source ({0}): {1} - {2:N0} catalog(s), resolves {3} of {4} of this machine's own reference binaries (ratio {5})." -f `
                $sourceKind, $sourcePath, $source.FileCount, $sourceCoverage.Resolved, $sourceCoverage.Present, $sourceCoverage.Ratio) | Tee-Object -FilePath $logFile -Append

        if ($sourceCoverage.Present -ge $script:MinSampleSize -and $sourceCoverage.Ratio -lt $script:MinCoverageRatio) {
            if ($isForceDonor) {
                Log-Warning "This source resolves only $($sourceCoverage.Ratio) of this machine's reference binaries, so it does not match this build. forceDonor=true was passed, so it will be used anyway." | Tee-Object -FilePath $logFile -Append
                $sourceUsable = $true
            }
            else {
                Log-Warning "This source does not match this installation: it resolves only $($sourceCoverage.Resolved) of $($sourceCoverage.Present) of the machine's own reference binaries. Merging it would add files without making the machine bootable, so it will not be used. Pass forceDonor=true to override, or point donorPath at a machine at the same build AND patch level." | Tee-Object -FilePath $logFile -Append
            }
        }
        else {
            $sourceUsable = $true
        }
    }
    elseif ($sourcePath) {
        Log-Warning "The repair source at $sourcePath holds no usable catalogs$(if ($source.Error) { " ($($source.Error))" })." | Tee-Object -FilePath $logFile -Append
    }

    # Boot drivers come from the hive; the catalog work above is all file work and needs no hive.
    $drivers = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $windowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        Add-OfflineRepairLog -Level Info -Message "Control set $(Split-Path -Path $systemRoot -Leaf)."
        return @(Get-BootDriverRecord -SystemRoot $systemRoot -WindowsDrive $volumeRoot)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $unresolved = @(Get-UnresolvedBootDriver -Drivers $drivers -CatalogIndex $store)
    Log-Info "Boot-critical drivers examined: $(@($drivers).Count). Depending on the catalog store and unresolved by it: $(@($unresolved).Count)." | Tee-Object -FilePath $logFile -Append

    $findings = @(Get-AllFinding -Store $store -Coverage $coverage -Unresolved $unresolved -SourceUsable $sourceUsable)

    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($findings.Count -eq 0) {
        Log-Output "No catalog store fault was found. The store resolves $($coverage.Resolved) of $($coverage.Present) inbox reference binaries and every catalog-dependent boot driver on this machine verifies against it. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0) {
        Log-Warning 'Every finding needs a decision that this script will not make on its own.' | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $unrepairable) {
            Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # One merge repairs the whole class: every finding above is the same store missing hashes.
    if (-not (Test-Path -LiteralPath $storePath -PathType Container)) {
        Add-OfflineRepairLog -Level Info -Message "Recreating the missing store folder $storePath."
        [void](New-Item -Path $storePath -ItemType Directory -Force -ErrorAction Stop)
    }

    $merge = Invoke-CatalogMerge -StorePath $storePath -SourceFiles $source.Files -Unopenable $store.Unopenable
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Merge result: $($merge.Added) added, $($merge.Replaced) replaced, $($merge.SideBySide) kept alongside an existing name, $($merge.Skipped) already identical, $($merge.Failed) failed." | Tee-Object -FilePath $logFile -Append
    foreach ($mergeError in @($merge.Errors | Select-Object -First 10)) {
        Log-Warning "  $mergeError" | Tee-Object -FilePath $logFile -Append
    }

    # Verify against freshly read state rather than trusting the writes above.
    $storeAfter = New-CatalogIndex -Path $storePath
    $coverageAfter = Get-StoreCoverage -CatalogIndex $storeAfter -WindowsPath $windowsPath
    $unresolvedAfter = @(Get-UnresolvedBootDriver -Drivers $drivers -CatalogIndex $storeAfter)

    Log-Info ("After repair: {0:N0} catalog(s), {1:N0} published hashes, reference coverage {2} of {3} (ratio {4}), unresolved boot drivers {5}." -f `
            $storeAfter.FileCount, $(if ($storeAfter.Index) { $storeAfter.Index.Count } else { 0 }), `
            $coverageAfter.Resolved, $coverageAfter.Present, $coverageAfter.Ratio, @($unresolvedAfter).Count) | Tee-Object -FilePath $logFile -Append

    $remaining = @(Get-AllFinding -Store $storeAfter -Coverage $coverageAfter -Unresolved $unresolvedAfter -SourceUsable $sourceUsable)
    $stillRepairable = @($remaining | Where-Object { $_.Repairable })

    $repairedCount = $repairable.Count - $stillRepairable.Count
    if ($repairedCount -lt 0) { $repairedCount = 0 }

    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported." }

    if ($merge.Failed -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($merge.Failed) copy(s) failed and $($stillRepairable.Count) issue(s) are still present." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM. Boot code integrity can resolve this machine's catalog-signed drivers again, so the 0xC0000428 load failure and the 0x5A bugcheck it caused do not recur." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
