#########################################################################################################
#
# .SYNOPSIS
#   Repairs named Windows system files on an offline disk from verified sources, one file at a time.
#
# .DESCRIPTION
#   Runs on the rescue VM against the attached copy of a broken VM's OS disk. It checks each file
#   passed in -files and, for every one that is missing or damaged, writes back a copy that has been
#   proven to be the exact file the guest expects. Nothing else on the disk is touched.
#
#   A file is judged by its embedded Authenticode signature where it has one, and otherwise by the
#   guest's own catalog store, read directly from the offline disk. Inbox binaries are mostly
#   catalog-signed, and the rescue VM's catalogs describe a different build, so only the guest's
#   catalogs can say whether a guest file is intact.
#
#   Replacement sources are tried in this order, and the first one that verifies is used:
#     1. An intact copy already on the disk: the component store folder, the WinSxS\Backup store
#        (plain or DCS-compressed), the driver store, or the rescue VM itself when it holds the
#        identical file.
#     2. A rebuild from the component store's differentials: an intact neighbour plus its reverse
#        differential gives the RTM file, and the guest's forward differential turns that into the
#        exact file.
#     3. The guest's installed cumulative update, downloaded from the Microsoft Update Catalog. It is
#        identified from the guest's own servicing store, and both the package and the file taken from
#        it are verified before use.
#     4. A targeted offline sfc /SCANFILE, which sources from the guest's component store.
#
#   Every replacement is checked again after it is written. A file that still fails is put back the
#   way it was found.
#
# .RESOLVES
#   A VM that fails to boot, or a role or service that fails to start, because a specific system file
#   is missing or corrupt. Typical signs are a bug check or boot error naming a driver or DLL, an
#   "image is either not designed to run on Windows or it contains an error" message, or
#   STATUS_INVALID_IMAGE_HASH (0xC0000428) for a named file.
#
#   This script does NOT cover:
#   - Boot configuration (BCD) problems. Use win-bcdedit-fix or win-rebuild-bcd.
#   - The Gen2 Secure Boot chain as a whole. Use win-fix-secure-boot.
#   - Code Integrity policy problems. Use win-fix-code-integrity.
#   - Broad or unknown corruption. Use win-sfc-sf-corruption, which runs a full DISM and sfc pass.
#   - Third-party drivers. There is no trusted source to restore them from.
#
# .PARAMETER files
#   Comma-separated list of files to check and repair. A bare name such as 'disk.sys' is looked for
#   in System32\drivers, System32, the Windows folder and System32\wbem, and must be found in exactly
#   one of them. Anything else is a path relative to the Windows folder, such as
#   'System32\drivers\disk.sys' or 'SysWOW64\ntdll.dll'. The forms 'C:\Windows\...',
#   '%SystemRoot%\...' and '\SystemRoot\...' are accepted too, whatever the drive letter. A missing
#   file has to be given by path, because there is nothing to find by name.
#
# .PARAMETER allowDownload
#   'true' (default) allows the cumulative update tier to contact the Microsoft Update Catalog. 'false'
#   keeps the run entirely offline. When the catalog cannot be reached, the tier is skipped and the
#   run carries on.
#
# .PARAMETER detectOnly
#   'true' reports what is wrong and changes nothing at all. No file is written, nothing is
#   downloaded and sfc is never invoked, because offline sfc repairs even when asked only to
#   verify - see .NOTES.
#
# .PARAMETER revert
#   'true' puts back the files that the most recent repair run replaced, and removes any file it
#   created. Use it if the VM behaves worse after the repair.
#
# .PARAMETER windowsDrive
#   The drive letter of the offline Windows volume, for example 'F:'. Leave it empty to find it
#   automatically.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-system-file --parameters "files=disk.sys,System32\drivers\ntfs.sys" --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-system-file --parameters files=disk.sys detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-system-file --parameters files=disk.sys allowDownload=false --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-system-file --parameters files=disk.sys windowsDrive=F --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-system-file --parameters revert=true --run-on-repair --verbose
#
# .NOTES
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Most inbox files are stored once and hard-linked into both their live location and their
#   component store folder, so the "component store copy" of a file damaged in place is the same
#   damaged data. Copies are compared by file ID, and a copy that shares the target's ID is never
#   used as a source. For the same reason, overwriting the live file in place also repairs its
#   component store link.
#
#   A file's version resource is not a reliable identity. Measured on Server 2019 build 17763.9245,
#   win32kbase.sys reports file version 17763.6659 while its component folder is 17763.9245, because
#   the file was unchanged by later updates. Candidates are matched on component identity and proven
#   by signature or catalog, never by version string alone.
#
#   Component store differentials come in two formats, and the engine is picked from each file's
#   header rather than from the guest's version. PA30 is applied with msdelta.dll. PA31, measured on
#   build 26100 behind a 4-byte CRC, is rejected by msdelta.dll and applied by UpdateCompression.dll,
#   taken from the rescue VM or, once it has verified as intact, from the guest itself. Server 2016
#   keeps no differentials, so that tier never applies to it.
#
#   Update packages that keep their payload in a WIM or PSF container are not unpacked. The tier
#   reports why and the run moves on to sfc.
#
#   Offline "sfc /VERIFYFILE" repairs despite its help text, so sfc is never run under detectOnly.
#   sfc's exit code is always 0 and it writes UTF-16 to the console, so only the "[SR]" lines of its
#   /OFFLOGFILE are read, and the outcome is decided by checking the file again afterwards.
#
#   Files under System32 are owned by TrustedInstaller, so every write goes through
#   Copy-OfflineProtectedFile, which takes ownership only when a plain copy is refused and always
#   puts the original ACL back.
#
#   Downloads and expanded packages are staged on the rescue VM and deleted when the run ends. They
#   are never written to the disk being repaired.
#
#   Each replaced file is first copied beside itself as
#   '<name>.win-fix-system-file-backup-<timestamp>', and a file that was missing gets an empty
#   '.absent' marker, so a later revert=true run can undo the change. These stay on the disk until
#   they are removed by hand once the VM is healthy. A backup is dropped straight away when the file
#   is left exactly as it was found. revert=true only undoes the file copies this script made: when
#   sfc was the tier that worked, any other file sfc changed in the same pass is not reverted.
#
#   A signature that Get-AuthenticodeSignature reports as valid through a catalog was found in the
#   rescue VM's catalogs, which belong to a different build. Such a file is judged again against the
#   guest's catalogs, so only an embedded signature is ever accepted on its own.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][string]$files = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$allowDownload = 'true',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$isDownloadAllowed = ($allowDownload -eq 'true')

$script:BackupSuffix = ".$scriptName-backup-$scriptStartTime"
# A file this script creates has no content to back up, so its record has to be a marker on the
# disk. An in-memory note would not survive the run, and -revert is a separate run.
$script:AbsentMarkerSuffix = '.absent'
$script:BackupManifest = [System.Collections.Generic.List[PSCustomObject]]::new()

$script:MaxFiles = 32
$script:ImageExtensions = @('.sys', '.dll', '.exe', '.efi', '.drv', '.ocx', '.cpl', '.mui', '.com', '.scr', '.ax', '.acm', '.tsp')
# Where a bare file name is looked for, in order. SysWOW64 is deliberately absent: a 32-bit copy is
# only ever chosen when the caller names it.
$script:BareNameFolder = @('System32\drivers', 'System32', '', 'System32\wbem')
$script:RevertFolder = @('', 'System32', 'System32\drivers', 'System32\wbem', 'SysWOW64')
$script:CatalogStoreGuid = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$script:ComponentPattern = [regex]'^(?<arch>[^_]+)_(?<name>.+)_(?<token>[0-9a-f]{16})_(?<ver>\d+\.\d+\.\d+\.\d+)_(?<culture>[^_]+)_(?<hash>[0-9a-f]{16})$'
$script:BackupEntryPattern = [regex]'^(?<comp>.+?_[0-9a-f]{16}_[\d.]+_[^_]+_[0-9a-f]{16})_(?<leaf>.+)_[0-9a-f]{8}$'

$script:WindowsPath = ''
$script:StagingRoot = Join-Path $env:TEMP "$scriptName-$scriptStartTime"
$script:StagingCounter = 0
$script:CatalogState = 'NotBuilt'
$script:CatalogSummary = ''
$script:CatalogIndex = $null
$script:CatalogFiles = @()
$script:CatalogTrust = @{}
$script:UpdatePackage = $null
$script:UpdateStagingRoot = ''
# WinSxS folder and WinSxS\Backup listings, cached per name prefix and shared by all files in a run.
$script:ComponentFolders = $null
$script:BackupEntries = $null
$script:OfflineDisk = $null
$script:GuestMachine = 0
$script:DeltaEngines = @{}

function Initialize-SystemFileNative {
    <#
    .SYNOPSIS
        Compiles the native helpers once: file IDs, DCS expansion, differential apply and catalog reads.

    .DESCRIPTION
        C# 5 only, so it compiles under Windows PowerShell 5.1. The DLLs are bound lazily, so a
        missing API fails the tier that needs it rather than the whole run.
    #>
    if ('RslSystemFile.Catalog' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace RslSystemFile
{
    public static class FileId
    {
        // FILETIME is two DWORDs and only 4-byte aligned. Declaring the times as long would make
        // the CLR pad after FileAttributes and shift every later field.
        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public uint CreationTimeLow; public uint CreationTimeHigh;
            public uint LastAccessTimeLow; public uint LastAccessTimeHigh;
            public uint LastWriteTimeLow; public uint LastWriteTimeHigh;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh; public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh; public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstFileNameW(string path, uint flags, ref uint length, System.Text.StringBuilder name);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextFileNameW(IntPtr handle, ref uint length, System.Text.StringBuilder name);
        [DllImport("kernel32.dll")]
        private static extern bool FindClose(IntPtr handle);

        // Every name of the file relative to its volume root, e.g. the live path and its WinSxS twin.
        public static string[] Links(string path)
        {
            var names = new List<string>();
            uint length = 32768;
            var name = new System.Text.StringBuilder(32768);
            IntPtr h = FindFirstFileNameW(path, 0, ref length, name);
            if (h == new IntPtr(-1)) return names.ToArray();
            try
            {
                do { names.Add(name.ToString()); length = 32768; }
                while (FindNextFileNameW(h, ref length, name));
            }
            finally { FindClose(h); }
            return names.ToArray();
        }

        // Zero access asks for metadata only, which works on a TrustedInstaller-owned file.
        public static string Get(string path)
        {
            IntPtr h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) return null;
            try
            {
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(h, out info)) return null;
                ulong index = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
                return string.Format("{0:X8}:{1:X16}", info.VolumeSerialNumber, index);
            }
            finally { CloseHandle(h); }
        }
    }

    public static class Dcs
    {
        [DllImport("cabinet.dll", SetLastError = true)]
        private static extern bool CreateDecompressor(uint algorithm, IntPtr routines, out IntPtr handle);
        [DllImport("cabinet.dll", SetLastError = true)]
        private static extern bool Decompress(IntPtr handle, byte[] src, UIntPtr srcLen, byte[] dst, UIntPtr dstLen, out UIntPtr outLen);
        [DllImport("cabinet.dll")]
        private static extern bool CloseDecompressor(IntPtr handle);

        // "DCS\x01", block count, total size, then per block: compressed size (which counts the
        // following 4-byte uncompressed size), uncompressed size, LZMS data.
        public static byte[] Expand(byte[] b)
        {
            if (b.Length < 12 || b[0] != 0x44 || b[1] != 0x43 || b[2] != 0x53 || b[3] != 1) throw new InvalidOperationException("not a DCS container");
            int blocks = BitConverter.ToInt32(b, 4);
            int total = BitConverter.ToInt32(b, 8);
            if (blocks <= 0 || total <= 0) throw new InvalidOperationException("empty DCS container");
            byte[] output = new byte[total];
            int pos = 12, o = 0;
            IntPtr h;
            // COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW
            if (!CreateDecompressor(5 | 0x20000000, IntPtr.Zero, out h)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                for (int i = 0; i < blocks; i++)
                {
                    if (pos + 8 > b.Length) throw new InvalidOperationException("DCS block header past the end");
                    int csize = BitConverter.ToInt32(b, pos);
                    int dsize = BitConverter.ToInt32(b, pos + 4);
                    if (csize <= 4 || dsize <= 0 || pos + 4 + csize > b.Length || o + dsize > total) throw new InvalidOperationException("DCS block " + i + " is malformed");
                    byte[] src = new byte[csize - 4];
                    Buffer.BlockCopy(b, pos + 8, src, 0, csize - 4);
                    byte[] dst = new byte[dsize];
                    UIntPtr got;
                    if (!Decompress(h, src, (UIntPtr)src.Length, dst, (UIntPtr)dsize, out got)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    Buffer.BlockCopy(dst, 0, output, o, (int)got);
                    o += (int)got;
                    pos += 4 + csize;
                }
            }
            finally { CloseDecompressor(h); }
            if (o != total || pos != b.Length) throw new InvalidOperationException("DCS size mismatch");
            return output;
        }
    }

    public static class Delta
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DELTA_INPUT { public IntPtr lpStart; public UIntPtr uSize; [MarshalAs(UnmanagedType.Bool)] public bool Editable; }
        [StructLayout(LayoutKind.Sequential)]
        private struct DELTA_OUTPUT { public IntPtr lpStart; public UIntPtr uSize; }
        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool ApplyDeltaB(long applyFlags, DELTA_INPUT source, DELTA_INPUT delta, out DELTA_OUTPUT target);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool DeltaFree(IntPtr memory);
        private sealed class Engine { public ApplyDeltaB Apply; public DeltaFree Free; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryExW(string fileName, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);
        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
        private static readonly Dictionary<string, Engine> Engines = new Dictionary<string, Engine>(StringComparer.OrdinalIgnoreCase);

        // msdelta.dll and UpdateCompression.dll export the same ApplyDeltaB/DeltaFree pair. The
        // library is loaded by path, and its own imports resolve only from the rescue VM's System32.
        private static Engine Load(string library)
        {
            Engine engine;
            lock (Engines)
            {
                if (Engines.TryGetValue(library, out engine)) return engine;
                IntPtr module = LoadLibraryExW(library, IntPtr.Zero, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (module == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "cannot load " + library);
                IntPtr apply = GetProcAddress(module, "ApplyDeltaB");
                IntPtr free = GetProcAddress(module, "DeltaFree");
                if (apply == IntPtr.Zero || free == IntPtr.Zero) throw new InvalidOperationException(library + " does not export ApplyDeltaB and DeltaFree");
                engine = new Engine();
                engine.Apply = (ApplyDeltaB)Marshal.GetDelegateForFunctionPointer(apply, typeof(ApplyDeltaB));
                engine.Free = (DeltaFree)Marshal.GetDelegateForFunctionPointer(free, typeof(DeltaFree));
                Engines[library] = engine;
                return engine;
            }
        }

        // An empty source applies a null differential. Servicing differentials carry a hash of the
        // file they expect, so a wrong or damaged source fails instead of producing a bad file.
        public static byte[] Apply(string library, byte[] source, byte[] delta, int offset)
        {
            Engine engine = Load(library);
            GCHandle pin = GCHandle.Alloc(delta, GCHandleType.Pinned);
            bool hasSource = source != null && source.Length > 0;
            GCHandle srcPin = hasSource ? GCHandle.Alloc(source, GCHandleType.Pinned) : new GCHandle();
            try
            {
                DELTA_INPUT src = new DELTA_INPUT();
                if (hasSource)
                {
                    src.lpStart = srcPin.AddrOfPinnedObject();
                    src.uSize = new UIntPtr((ulong)source.Length);
                }
                DELTA_INPUT input = new DELTA_INPUT();
                input.lpStart = new IntPtr(pin.AddrOfPinnedObject().ToInt64() + offset);
                input.uSize = new UIntPtr((ulong)(delta.Length - offset));
                DELTA_OUTPUT output;
                if (!engine.Apply(0, src, input, out output)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                try
                {
                    byte[] result = new byte[(long)output.uSize.ToUInt64()];
                    Marshal.Copy(output.lpStart, result, 0, result.Length);
                    return result;
                }
                finally { engine.Free(output.lpStart); }
            }
            finally
            {
                pin.Free();
                if (hasSource) srcPin.Free();
            }
        }
    }

    public static class Catalog
    {
        // CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG
        private const uint OpenFlags = 0x20000004;

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CryptCATOpen(string pwszFileName, uint fdwOpenFlags, IntPtr hProv, uint dwPublicVersion, uint dwEncodingType);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATClose(IntPtr hCatalog);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr pPrevMember);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(ref IntPtr phCatAdmin, IntPtr pgSubsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

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

        // The Authenticode reference tags catalogs use as member IDs, SHA-256 first, then SHA-1.
        // They exclude the checksum and certificate table, so they are comparable with catalogs.
        public static string[] GetFileHashTags(string path)
        {
            List<string> tags = new List<string>();
            using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
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
                            if (CryptCATAdminCalcHashFromFileHandle2(ctx, hFile, ref cb, buf, 0)) tags.Add(ToHex(buf, (int)cb));
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
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, ref cb1, buf1, 0)) tags.Add(ToHex(buf1, (int)cb1));
                }
            }
            return tags.ToArray();
        }

        // Maps every member tag to the index of a catalog holding it. stats[0] = catalogs opened.
        public static Dictionary<string, int> BuildIndex(string[] catalogPaths, int[] stats)
        {
            ConcurrentDictionary<string, int> index = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int opened = 0;
            ParallelOptions options = new ParallelOptions();
            options.MaxDegreeOfParallelism = Math.Min(16, Math.Max(2, Environment.ProcessorCount * 2));
            Parallel.For(0, catalogPaths.Length, options, delegate(int i)
            {
                IntPtr hCat = CryptCATOpen(catalogPaths[i], OpenFlags, IntPtr.Zero, 0, 0);
                if (hCat == IntPtr.Zero || hCat == new IntPtr(-1)) return;
                Interlocked.Increment(ref opened);
                try
                {
                    IntPtr m = IntPtr.Zero;
                    while ((m = CryptCATEnumerateMember(hCat, m)) != IntPtr.Zero)
                    {
                        CRYPTCATMEMBER cm = (CRYPTCATMEMBER)Marshal.PtrToStructure(m, typeof(CRYPTCATMEMBER));
                        if (cm.pwszReferenceTag == IntPtr.Zero) continue;
                        string tag = Marshal.PtrToStringUni(cm.pwszReferenceTag);
                        if (!string.IsNullOrEmpty(tag)) index.TryAdd(tag, i);
                    }
                }
                catch { }
                finally { CryptCATClose(hCat); }
            });
            if (stats != null && stats.Length >= 1) stats[0] = opened;
            return new Dictionary<string, int>(index, StringComparer.OrdinalIgnoreCase);
        }
    }
}
'@ -ErrorAction Stop
}

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
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

function New-StagingFolder {
    <#
    .SYNOPSIS
        Returns a fresh folder on the rescue VM for one staged file. The whole root is deleted at the end.
    #>
    $script:StagingCounter++
    $path = Join-Path $script:StagingRoot ('{0:D3}' -f $script:StagingCounter)
    [void](New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop)
    return $path
}

function Get-FileIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return [RslSystemFile.FileId]::Get($Path) } catch { return $null }
}

function Get-FileHeader {
    param([Parameter(Mandatory = $true)][string]$Path, [int]$Count = 4)
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $buffer = New-Object byte[] $Count
            $read = $stream.Read($buffer, 0, $Count)
            if ($read -lt $Count) { return $null }
            return , $buffer
        }
        finally { $stream.Dispose() }
    }
    catch { return $null }
}

function Get-PeImageInfo {
    <#
    .SYNOPSIS
        Reads just enough of a file to say whether it is a PE image, for which machine, and whether
        it carries an embedded signature block (data directory 4).
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $info = [PSCustomObject]@{ Exists = $false; Readable = $false; IsPe = $false; Machine = 0; Length = 0; CertSize = 0; Error = '' }
    if (-not (Test-OfflinePath $Path)) { return $info }
    $info.Exists = $true

    $header = New-Object byte[] 4096
    $read = 0
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $info.Length = $stream.Length
            $read = $stream.Read($header, 0, $header.Length)
        }
        finally { $stream.Dispose() }
        $info.Readable = $true
    }
    catch {
        $info.Error = $_.Exception.Message
        return $info
    }

    if ($read -lt 512 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) { return $info }
    $peOffset = [BitConverter]::ToInt32($header, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 26) -gt $read) { return $info }
    if ($header[$peOffset] -ne 0x50 -or $header[$peOffset + 1] -ne 0x45 -or $header[$peOffset + 2] -ne 0 -or $header[$peOffset + 3] -ne 0) { return $info }

    $info.IsPe = $true
    $info.Machine = [BitConverter]::ToUInt16($header, $peOffset + 4)
    $magic = [BitConverter]::ToUInt16($header, $peOffset + 24)
    $certEntry = $peOffset + 24 + $(if ($magic -eq 0x20B) { 144 } else { 128 })
    if (($certEntry + 8) -le $read) { $info.CertSize = [BitConverter]::ToUInt32($header, $certEntry + 4) }
    return $info
}

function Get-NumericFileVersion {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if (($v.FileMajorPart + $v.FileMinorPart + $v.FileBuildPart + $v.FilePrivatePart) -eq 0) { return '' }
        return ('{0}.{1}.{2}.{3}' -f $v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart)
    }
    catch { return '' }
}

#region Guest catalog store

function Get-CatalogReferenceSample {
    # Inbox binaries that a healthy installation always covers in a servicing catalog. Only files
    # that exist are returned, so the ratio is never diluted by a build that ships fewer of them.
    $relative = @(
        'System32\ntoskrnl.exe', 'System32\ntdll.dll', 'System32\kernel32.dll', 'System32\hal.dll'
        'System32\smss.exe', 'System32\services.exe', 'System32\winlogon.exe', 'System32\advapi32.dll'
        'System32\user32.dll', 'System32\drivers\ntfs.sys', 'System32\drivers\disk.sys'
        'System32\drivers\partmgr.sys', 'System32\drivers\volsnap.sys', 'System32\drivers\acpi.sys'
        'System32\drivers\pci.sys', 'System32\drivers\fltmgr.sys', 'System32\drivers\ndis.sys'
        'System32\drivers\tcpip.sys'
    )
    foreach ($rel in $relative) {
        $path = Join-OfflinePath -Root $script:WindowsPath -ChildPath $rel
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($item -and -not $item.PSIsContainer -and $item.Length -gt 0) { $item.FullName }
    }
}

function Initialize-GuestCatalog {
    <#
    .SYNOPSIS
        Indexes the offline guest's catalog store once, and decides whether a miss means corruption.

    .DESCRIPTION
        Usable means at least 6 reference binaries are present and at least 60% of them resolve. Below
        that the store itself is incomplete, so a miss proves nothing and is reported, not repaired.
    #>
    if ($script:CatalogState -ne 'NotBuilt') { return $script:CatalogState }
    $script:CatalogState = 'Unavailable'

    $store = Join-OfflinePath -Root $script:WindowsPath -ChildPath "System32\CatRoot\$($script:CatalogStoreGuid)"
    $catFiles = @(Get-ChildItem -LiteralPath $store -Filter '*.cat' -File -ErrorAction SilentlyContinue)
    if ($catFiles.Count -eq 0) {
        $script:CatalogSummary = 'the guest catalog store is missing or empty'
        return $script:CatalogState
    }

    $stats = [int[]]@(0)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try { $script:CatalogIndex = [RslSystemFile.Catalog]::BuildIndex([string[]]($catFiles.FullName), $stats) }
    catch {
        $script:CatalogSummary = "the guest catalog store could not be read ($($_.Exception.Message))"
        return $script:CatalogState
    }
    $script:CatalogFiles = $catFiles

    $sample = @(Get-CatalogReferenceSample)
    $found = 0
    foreach ($path in $sample) {
        foreach ($tag in (Get-CatalogTag -Path $path)) {
            if ($script:CatalogIndex.ContainsKey($tag)) { $found++; break }
        }
    }
    $ratio = if ($sample.Count -gt 0) { $found / $sample.Count } else { 0 }
    $script:CatalogState = if ($sample.Count -ge 6 -and $ratio -ge 0.6) { 'Usable' } else { 'Unusable' }
    $script:CatalogSummary = ('{0} catalogs, reference sample {1}/{2} resolved, {3:N1}s' -f $stats[0], $found, $sample.Count, $watch.Elapsed.TotalSeconds)
    Add-OfflineRepairLog -Level Info -Message "Guest catalog store is $($script:CatalogState): $($script:CatalogSummary)."
    return $script:CatalogState
}

function Get-CatalogTag {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return @([RslSystemFile.Catalog]::GetFileHashTags($Path)) } catch { return @() }
}

function Test-GuestCatalogMembership {
    <#
    .SYNOPSIS
        Is this exact content published in a catalog of the guest, and is that catalog validly
        signed by Microsoft? A catalog carries its own signature, so it can be checked offline.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Found = $false; IsMicrosoft = $false }
    if ((Initialize-GuestCatalog) -notin @('Usable', 'Unusable')) { return $result }

    $catalogIndex = -1
    foreach ($tag in (Get-CatalogTag -Path $Path)) {
        if ($script:CatalogIndex.ContainsKey($tag)) { $catalogIndex = $script:CatalogIndex[$tag]; break }
    }
    if ($catalogIndex -lt 0) { return $result }
    $result.Found = $true

    if (-not $script:CatalogTrust.ContainsKey($catalogIndex)) {
        $isMicrosoft = $false
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $script:CatalogFiles[$catalogIndex].FullName -ErrorAction Stop
            $isMicrosoft = ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
        }
        catch { $isMicrosoft = $false }
        $script:CatalogTrust[$catalogIndex] = $isMicrosoft
    }
    $result.IsMicrosoft = $script:CatalogTrust[$catalogIndex]
    return $result
}

#endregion

function Test-FileIntegrity {
    <#
    .SYNOPSIS
        Judges one file. Verdict is Intact, Missing, Broken, Untrusted, Unreadable or Unverified.

    .DESCRIPTION
        Used both for the target and for every candidate source, so a replacement is held to exactly
        the standard the damaged file failed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Verdict = 'Missing'; Detail = 'the file is missing'; Pe = $null }
    $pe = Get-PeImageInfo -Path $Path
    $result.Pe = $pe
    if (-not $pe.Exists) { return $result }
    if (-not $pe.Readable) { $result.Verdict = 'Unreadable'; $result.Detail = "the file could not be read ($($pe.Error))"; return $result }
    if ($pe.Length -eq 0) { $result.Verdict = 'Broken'; $result.Detail = 'the file is empty'; return $result }
    if (-not $pe.IsPe) { $result.Verdict = 'Broken'; $result.Detail = 'the file is no longer an executable image'; return $result }

    try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop }
    catch { $result.Verdict = 'Unreadable'; $result.Detail = "the signature could not be checked ($($_.Exception.Message))"; return $result }

    switch ([string]$sig.Status) {
        'Valid' {
            if (-not ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')) {
                $result.Verdict = 'Untrusted'; $result.Detail = "it is signed by '$($sig.SignerCertificate.Subject)', not Microsoft"
            }
            elseif ($pe.CertSize -gt 0 -and [string]$sig.SignatureType -ne 'Catalog') {
                $result.Verdict = 'Intact'; $result.Detail = 'its signature is valid'
            }
            else {
                # Valid through a catalog of the rescue VM, which describes the rescue VM's build.
                # Only the guest's own catalogs can say the file belongs to the guest.
                Set-GuestCatalogVerdict -Result $result -Path $Path
            }
        }
        'HashMismatch' { $result.Verdict = 'Broken'; $result.Detail = 'its content no longer matches its embedded signature' }
        'NotTrusted' { $result.Verdict = 'Untrusted'; $result.Detail = 'its signature chains to an untrusted root' }
        'NotSigned' {
            if ($pe.CertSize -gt 0) {
                $result.Verdict = 'Broken'; $result.Detail = 'it carries a signature block that no longer parses'
            }
            else {
                Set-GuestCatalogVerdict -Result $result -Path $Path
            }
        }
        default { $result.Verdict = 'Broken'; $result.Detail = "its signature check returned $($sig.Status)" }
    }
    return $result
}

function Set-GuestCatalogVerdict {
    <#
    .SYNOPSIS
        Judges a file with no usable embedded signature by the guest's own catalog store.
    #>
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Path)

    $membership = Test-GuestCatalogMembership -Path $Path
    if ($membership.Found -and $membership.IsMicrosoft) {
        $Result.Verdict = 'Intact'; $Result.Detail = 'it is listed in a Microsoft-signed catalog of the guest'
    }
    elseif ($membership.Found) {
        $Result.Verdict = 'Untrusted'; $Result.Detail = 'it is listed only in a catalog that is not validly signed by Microsoft'
    }
    elseif ($script:CatalogState -eq 'Usable') {
        $Result.Verdict = 'Broken'; $Result.Detail = 'its content is not listed in any catalog of the guest'
    }
    else {
        $Result.Verdict = 'Unverified'; $Result.Detail = "the guest catalog store cannot confirm it ($($script:CatalogSummary))"
    }
}

#region Target resolution

function Resolve-SystemFileTarget {
    <#
    .SYNOPSIS
        Turns one caller-supplied name into a path inside the offline Windows folder.

    .DESCRIPTION
        Accepts a bare name (win32kbase.sys), a Windows-relative path (System32\drivers\disk.sys), or
        the %SystemRoot%, %windir%, \SystemRoot and <drive>:\Windows forms. A bare name is looked up in
        BareNameFolder order and must be unique. Anything that leaves the Windows folder, names a WinSxS
        store file, or is not an executable image type is refused, so no caller input can steer a write
        elsewhere on the disk.
    #>
    param([Parameter(Mandatory = $true)][string]$Spec)

    $result = [PSCustomObject]@{ Spec = $Spec; Relative = ''; Path = ''; Name = ''; Error = '' }
    $text = $Spec.Trim().Trim('"', "'").Trim().Replace('/', '\')
    if (-not $text) { $result.Error = 'the name is empty'; return $result }

    $text = $text -replace '^(?i)(%SystemRoot%|%windir%|\\SystemRoot)\\?', ''
    if ($text -match '^(?i)[a-z]:\\Windows(\\|$)') { $text = $text.Substring($Matches[0].Length) }
    elseif ($text -match '^[a-zA-Z]:' -or $text.StartsWith('\\')) {
        $result.Error = 'it is outside the Windows folder'
        return $result
    }
    $text = $text.Trim('\')
    $segments = @($text.Split('\') | Where-Object { $_ -ne '' })
    if ($segments.Count -eq 0) { $result.Error = 'it does not name a file'; return $result }
    if ($segments | Where-Object { $_ -eq '.' -or $_ -eq '..' }) { $result.Error = 'relative segments (. or ..) are not allowed'; return $result }
    if ($segments | Where-Object { $_.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 }) { $result.Error = 'it contains characters that are not valid in a file name'; return $result }
    if ($segments[0] -eq 'WinSxS') { $result.Error = 'files inside the WinSxS store are sources, not targets'; return $result }

    $leaf = $segments[-1]
    if ([System.IO.Path]::GetExtension($leaf).ToLowerInvariant() -notin $script:ImageExtensions) {
        $result.Error = "only executable images can be repaired ($($script:ImageExtensions -join ', '))"
        return $result
    }
    $result.Name = $leaf

    if ($segments.Count -eq 1) {
        $hits = @(foreach ($folder in $script:BareNameFolder) {
                $rel = if ($folder) { "$folder\$leaf" } else { $leaf }
                if (Test-OfflinePath (Join-OfflinePath -Root $script:WindowsPath -ChildPath $rel)) { $rel }
            })
        if ($hits.Count -gt 1) {
            $result.Error = "the name is ambiguous ($($hits -join ', ')); pass the Windows-relative path instead"
            return $result
        }
        # A missing file is still a valid target: look for it where it would normally live.
        $result.Relative = if ($hits.Count -eq 1) { $hits[0] } else { "System32\$leaf" }
        if ($hits.Count -eq 0 -and [System.IO.Path]::GetExtension($leaf) -eq '.sys') { $result.Relative = "System32\drivers\$leaf" }
    }
    else {
        $result.Relative = $segments -join '\'
    }

    $result.Path = Join-OfflinePath -Root $script:WindowsPath -ChildPath $result.Relative
    $parent = Split-Path -Path $result.Path -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $result.Error = "its folder $parent does not exist on the offline disk"
    }
    return $result
}

function Get-RequestedTarget {
    <#
    .SYNOPSIS
        Splits the files parameter, resolves every entry and removes duplicates.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$List)

    $seen = @{}
    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($spec in @($List -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $target = Resolve-SystemFileTarget -Spec $spec
        $key = if ($target.Path) { $target.Path.ToLowerInvariant() } else { "?$($spec.ToLowerInvariant())" }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $targets.Add($target)
    }
    return , $targets
}

#endregion

#region Detection

function Get-SystemFileFinding {
    <#
    .SYNOPSIS
        Checks every requested file and returns one finding for each file that is not intact.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Target)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($t in $Target) {
        if ($t.Error) {
            $findings.Add((New-Finding -Cause 'TargetUnresolved' -Item $t.Spec -Repairable $false -Data $t -Message "'$($t.Spec)' was not checked: $($t.Error)."))
            continue
        }

        $check = Test-FileIntegrity -Path $t.Path
        switch ($check.Verdict) {
            'Intact' { Add-OfflineRepairLog -Level Info -Message "$($t.Relative) is intact: $($check.Detail)." }
            'Missing' { $findings.Add((New-Finding -Cause 'FileMissing' -Item $t.Relative -Data $t -Message "$($t.Relative) is missing.")) }
            'Broken' { $findings.Add((New-Finding -Cause 'FileDamaged' -Item $t.Relative -Data $t -Message "$($t.Relative) is damaged: $($check.Detail).")) }
            'Untrusted' { $findings.Add((New-Finding -Cause 'FileUntrusted' -Item $t.Relative -Repairable $false -Data $t -Message "$($t.Relative) is not a trusted Microsoft file: $($check.Detail). It may be a deliberate third-party replacement, so it was left alone.")) }
            'Unreadable' { $findings.Add((New-Finding -Cause 'FileUnreadable' -Item $t.Relative -Repairable $false -Data $t -Message "$($t.Relative) could not be checked: $($check.Detail).")) }
            default { $findings.Add((New-Finding -Cause 'FileUnverified' -Item $t.Relative -Repairable $false -Data $t -Message "$($t.Relative) could not be verified: $($check.Detail). Replacing it on that basis alone could overwrite a good file.")) }
        }
    }
    return , $findings
}

#endregion

#region Repair sources

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Get-ComponentFolder {
    <#
    .SYNOPSIS
        Lists offline WinSxS component folders, already split into their identity fields.

    .DESCRIPTION
        With -Prefix only the folders starting with it are listed. NTFS seeks its name index for a
        prefix, so this stays fast on a cold disk, where listing the whole store can take minutes.
        Each listing is read once per run.
    #>
    param([string]$Prefix = '')

    if ($null -eq $script:ComponentFolders) { $script:ComponentFolders = @{} }
    if ($script:ComponentFolders.ContainsKey($Prefix)) { return , $script:ComponentFolders[$Prefix] }
    $list = [System.Collections.Generic.List[PSCustomObject]]::new()
    $winsxs = Join-OfflinePath -Root $script:WindowsPath -ChildPath 'WinSxS'
    try {
        foreach ($dir in [System.IO.Directory]::EnumerateDirectories($winsxs, "$Prefix*")) {
            $m = $script:ComponentPattern.Match([System.IO.Path]::GetFileName($dir))
            if (-not $m.Success) { continue }
            $list.Add([PSCustomObject]@{
                    Folder  = $m.Value
                    Path    = $dir
                    Arch    = $m.Groups['arch'].Value
                    Name    = $m.Groups['name'].Value
                    Token   = $m.Groups['token'].Value
                    Version = [version]$m.Groups['ver'].Value
                    Culture = $m.Groups['culture'].Value
                })
        }
    }
    catch { Add-OfflineRepairLog -Level Warning -Message "The WinSxS store could not be listed: $($_.Exception.Message)" }
    $script:ComponentFolders[$Prefix] = $list
    return , $list
}

function Get-BackupEntry {
    <#
    .SYNOPSIS
        Lists WinSxS\Backup entries starting with -Prefix. Each name encodes the component and file it belongs to.
    #>
    param([string]$Prefix = '')

    if ($null -eq $script:BackupEntries) { $script:BackupEntries = @{} }
    if ($script:BackupEntries.ContainsKey($Prefix)) { return , $script:BackupEntries[$Prefix] }
    $list = [System.Collections.Generic.List[PSCustomObject]]::new()
    $folder = Join-OfflinePath -Root $script:WindowsPath -ChildPath 'WinSxS\Backup'
    try {
        foreach ($path in [System.IO.Directory]::EnumerateFiles($folder, "$Prefix*")) {
            $m = $script:BackupEntryPattern.Match([System.IO.Path]::GetFileName($path))
            if ($m.Success) { $list.Add([PSCustomObject]@{ Component = $m.Groups['comp'].Value; Leaf = $m.Groups['leaf'].Value; Path = $path }) }
        }
    }
    catch { $null = $_ }
    $script:BackupEntries[$Prefix] = $list
    return , $list
}

function Get-LinkedComponent {
    <#
    .SYNOPSIS
        The WinSxS component folder that holds a hard link to this file, from the file's own link names.

    .DESCRIPTION
        Reading the link names takes milliseconds, while finding the component by listing the whole
        store can take minutes on a cold disk. Returns '' when the file has no WinSxS twin.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [string]$FileId)

    if (-not $FileId) { return '' }
    $leaf = [System.IO.Path]::GetFileName($Path)
    $names = @()
    try { $names = @([RslSystemFile.FileId]::Links($Path)) } catch { return '' }
    foreach ($name in $names) {
        $m = [regex]::Match($name, '(?i)\\WinSxS\\(?<comp>[^\\]+)\\(?<leaf>[^\\]+)$')
        if (-not $m.Success -or $m.Groups['leaf'].Value -ne $leaf -or -not $script:ComponentPattern.IsMatch($m.Groups['comp'].Value)) { continue }
        $twin = Join-OfflinePath -Root $script:WindowsPath -ChildPath "WinSxS\$($m.Groups['comp'].Value)\$leaf"
        if ((Get-FileIdentity -Path $twin) -eq $FileId) { return $m.Groups['comp'].Value }
    }
    return ''
}

function Get-ExpectedMachine {
    <#
    .SYNOPSIS
        The component architecture(s) and PE machine a replacement for this target must have.
    #>
    param([Parameter(Mandatory = $true)]$Target)

    if ($Target.Relative -match '^(?i)SysWOW64\\') { return [PSCustomObject]@{ Arch = @('wow64', 'x86'); Machine = 0x14C } }
    $kernel = Get-PeImageInfo -Path (Join-OfflinePath -Root $script:WindowsPath -ChildPath 'System32\ntoskrnl.exe')
    switch ($kernel.Machine) {
        0xAA64 { return [PSCustomObject]@{ Arch = @('arm64'); Machine = 0xAA64 } }
        0x14C { return [PSCustomObject]@{ Arch = @('x86'); Machine = 0x14C } }
        default { return [PSCustomObject]@{ Arch = @('amd64'); Machine = 0x8664 } }
    }
}

function Get-SourcePlan {
    <#
    .SYNOPSIS
        Works out which WinSxS component the target belongs to, and which related components exist.

    .DESCRIPTION
        The component whose copy shares the target's file ID is the installed one: WinSxS and the live
        file are hard links, so this holds even when the content is damaged. For a missing file the
        newest component with a full copy is taken, and only when every copy belongs to one component
        name; otherwise the store cannot say which one is expected and the store-based tiers are skipped.
    #>
    param([Parameter(Mandatory = $true)]$Target)

    $leaf = $Target.Name
    $machine = Get-ExpectedMachine -Target $Target
    $targetPe = Get-PeImageInfo -Path $Target.Path
    $plan = [PSCustomObject]@{
        Target = $Target; TargetId = (Get-FileIdentity -Path $Target.Path); TargetHash = ''
        TargetPe = $targetPe; Machine = $machine.Machine
        Entries = @(); Expected = $null; Family = @(); Reason = ''
    }
    if ($targetPe.Exists -and $targetPe.Readable) { $plan.TargetHash = Get-FileSha256 -Path $Target.Path }

    # The installed component names the family, so only its folders need listing. Without a WinSxS
    # twin (a missing or unlinked file) the whole store is scanned for the file name instead.
    $prefix = ''
    $linkedFolder = Get-LinkedComponent -Path $Target.Path -FileId $plan.TargetId
    if ($linkedFolder) {
        $lm = $script:ComponentPattern.Match($linkedFolder)
        $prefix = "$($lm.Groups['arch'].Value)_$($lm.Groups['name'].Value)_$($lm.Groups['token'].Value)_"
    }
    else {
        Add-OfflineRepairLog -Level Info -Message "$($Target.Relative) has no WinSxS twin, so the whole component store is searched; on a cold disk this can take several minutes."
    }

    $entries = foreach ($component in (Get-ComponentFolder -Prefix $prefix)) {
        if ($component.Arch -notin $machine.Arch) { continue }
        $full = Join-Path $component.Path $leaf
        $forward = Join-Path $component.Path "f\$leaf"
        $reverse = Join-Path $component.Path "r\$leaf"
        $null_ = Join-Path $component.Path "n\$leaf"
        $hasFull = [System.IO.File]::Exists($full)
        $hasForward = [System.IO.File]::Exists($forward)
        $hasReverse = [System.IO.File]::Exists($reverse)
        $hasNull = [System.IO.File]::Exists($null_)
        if (-not ($hasFull -or $hasForward -or $hasReverse -or $hasNull)) { continue }
        [PSCustomObject]@{
            Component = $component
            Full      = $(if ($hasFull) { $full } else { '' })
            Forward   = $(if ($hasForward) { $forward } else { '' })
            Reverse   = $(if ($hasReverse) { $reverse } else { '' })
            Null      = $(if ($hasNull) { $null_ } else { '' })
            Linked    = ($hasFull -and $plan.TargetId -and (Get-FileIdentity -Path $full) -eq $plan.TargetId)
        }
    }
    $plan.Entries = @($entries)
    if ($plan.Entries.Count -eq 0) { $plan.Reason = 'no WinSxS component carries this file'; return $plan }

    $linked = @($plan.Entries | Where-Object { $_.Linked })
    if ($linked.Count -gt 0) {
        $plan.Expected = $linked[0]
    }
    else {
        $names = @($plan.Entries | Where-Object { $_.Full -or $_.Forward } | ForEach-Object { "$($_.Component.Name)|$($_.Component.Culture)" } | Sort-Object -Unique)
        if ($names.Count -ne 1) {
            $plan.Reason = "the file belongs to $($names.Count) different components, so the store cannot say which copy is expected"
            return $plan
        }
        # Without a hard link the store cannot say which version is installed: a newer one may only
        # be staged, or left behind by a rolled-back update. The damaged file's own version resource
        # decides when it survives; otherwise only a store holding a single version is trusted.
        $usable = @($plan.Entries | Where-Object { $_.Full -or $_.Forward })
        $versions = @($usable | ForEach-Object { [string]$_.Component.Version } | Sort-Object -Unique)
        if ($versions.Count -eq 1) {
            $plan.Expected = @($usable | Where-Object { $_.Full } | Select-Object -First 1)[0]
            if (-not $plan.Expected) { $plan.Expected = $usable[0] }
        }
        else {
            $targetVersion = ''
            if ($targetPe.IsPe) { $targetVersion = Get-NumericFileVersion -Path $Target.Path }
            $matching = @()
            if ($targetVersion) {
                $matching = @($usable | Where-Object { $_.Full -and (Get-NumericFileVersion -Path $_.Full) -eq $targetVersion })
            }
            if ($matching.Count -eq 0) {
                $plan.Reason = "the store holds $($versions.Count) versions of the file and nothing shows which one is installed"
                return $plan
            }
            $plan.Expected = @($matching | Sort-Object { $_.Component.Version } -Descending)[0]
        }
    }

    $e = $plan.Expected.Component
    $plan.Family = @($plan.Entries | Where-Object {
            $_.Component.Name -eq $e.Name -and $_.Component.Token -eq $e.Token -and $_.Component.Culture -eq $e.Culture -and $_.Component.Arch -eq $e.Arch
        })
    return $plan
}

function Test-RepairCandidate {
    <#
    .SYNOPSIS
        Decides whether a file may replace the target. Returns Accepted, Reason and Hash.

    .DESCRIPTION
        A hard link to the target, or a byte-identical copy, holds the same damage and is refused. The
        candidate must be an intact image for the expected machine. -Strict, used for sources outside
        the target's own component (DriverStore, the rescue VM), also requires the exact content to be
        published by the guest: a guest catalog hit, or an embedded Microsoft signature plus a version
        match, so a newer or older build is never written.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Plan,
        [switch]$Strict,
        [string]$Version = '',
        [long]$Length = 0
    )

    $result = [PSCustomObject]@{ Accepted = $false; Reason = ''; Hash = '' }
    if ($Plan.TargetId -and (Get-FileIdentity -Path $Path) -eq $Plan.TargetId) { $result.Reason = 'it is a hard link to the damaged file'; return $result }
    $result.Hash = Get-FileSha256 -Path $Path
    if (-not $result.Hash) { $result.Reason = 'it could not be read'; return $result }
    if ($Plan.TargetHash -and $result.Hash -eq $Plan.TargetHash) { $result.Reason = 'it holds the same bytes as the damaged file'; return $result }

    $check = Test-FileIntegrity -Path $Path
    if ($check.Verdict -ne 'Intact') { $result.Reason = $check.Detail; return $result }
    if ($check.Pe.Machine -ne $Plan.Machine) { $result.Reason = ('it is built for machine 0x{0:X4}, not 0x{1:X4}' -f $check.Pe.Machine, $Plan.Machine); return $result }
    if ($Length -gt 0 -and $check.Pe.Length -ne $Length) { $result.Reason = "its size is $($check.Pe.Length) bytes, not $Length"; return $result }
    if ($Version -and (Get-NumericFileVersion -Path $Path) -ne $Version) { $result.Reason = "its version is not $Version"; return $result }

    if ($Strict) {
        $membership = Test-GuestCatalogMembership -Path $Path
        $exact = ($membership.Found -and $membership.IsMicrosoft) -or ($check.Pe.CertSize -gt 0 -and $Version)
        if (-not $exact) { $result.Reason = 'the guest does not publish this exact content'; return $result }
    }
    $result.Accepted = $true
    return $result
}

function Get-ReferenceVersion {
    <#
    .SYNOPSIS
        The file version and size a copy from outside the component must have, or empty when unknown.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    $reference = [PSCustomObject]@{ Version = ''; Length = [long]0 }
    if ($Plan.Expected -and $Plan.Expected.Full -and -not $Plan.Expected.Linked) {
        $reference.Version = Get-NumericFileVersion -Path $Plan.Expected.Full
        $reference.Length = (Get-Item -LiteralPath $Plan.Expected.Full -Force).Length
    }
    elseif ($Plan.TargetPe.IsPe) {
        # A damaged image usually keeps its version resource; its size is only trusted when the
        # damage did not truncate it, so it is not used as a constraint here.
        $reference.Version = Get-NumericFileVersion -Path $Plan.Target.Path
    }
    return $reference
}

function Expand-BackupEntry {
    <#
    .SYNOPSIS
        Returns a usable full file for a WinSxS\Backup entry: the entry itself when it is a complete
        image, an expanded copy on the rescue VM when it is DCS-compressed, or nothing.
    #>
    param([Parameter(Mandatory = $true)]$Entry, [Parameter(Mandatory = $true)][string]$Leaf)

    $header = Get-FileHeader -Path $Entry.Path -Count 4
    if (-not $header) { return $null }
    if ($header[0] -eq 0x4D -and $header[1] -eq 0x5A) { return $Entry.Path }
    if ($header[0] -ne 0x44 -or $header[1] -ne 0x43 -or $header[2] -ne 0x53 -or $header[3] -ne 0x01) { return $null }
    try {
        $bytes = [RslSystemFile.Dcs]::Expand([System.IO.File]::ReadAllBytes($Entry.Path))
        $staged = Join-Path (New-StagingFolder) $Leaf
        [System.IO.File]::WriteAllBytes($staged, $bytes)
        return $staged
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Backup entry $(Split-Path $Entry.Path -Leaf) could not be expanded: $($_.Exception.Message)"
        return $null
    }
}

function Get-DirectCandidate {
    <#
    .SYNOPSIS
        Tier 1: existing complete copies of the exact file, in the order they are tried.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    $leaf = $Plan.Target.Name
    if ($Plan.Expected) {
        if ($Plan.Expected.Full -and -not $Plan.Expected.Linked) {
            [PSCustomObject]@{ Origin = "WinSxS\$($Plan.Expected.Component.Folder)"; Path = $Plan.Expected.Full; Strict = $false }
        }
        foreach ($entry in (Get-BackupEntry -Prefix "$($Plan.Expected.Component.Folder)_$($leaf)_")) {
            if ($entry.Component -ne $Plan.Expected.Component.Folder -or $entry.Leaf -ne $leaf) { continue }
            $path = Expand-BackupEntry -Entry $entry -Leaf $leaf
            if ($path) { [PSCustomObject]@{ Origin = "WinSxS\Backup\$(Split-Path $entry.Path -Leaf)"; Path = $path; Strict = $false } }
        }
    }

    $repository = Join-OfflinePath -Root $script:WindowsPath -ChildPath 'System32\DriverStore\FileRepository'
    foreach ($package in @(Get-ChildItem -LiteralPath $repository -Directory -Force -ErrorAction SilentlyContinue)) {
        $path = Join-Path $package.FullName $leaf
        if ([System.IO.File]::Exists($path)) { [PSCustomObject]@{ Origin = "DriverStore\$($package.Name)"; Path = $path; Strict = $true } }
    }

    $hostCopy = Join-Path $env:SystemRoot $Plan.Target.Relative
    if ([System.IO.File]::Exists($hostCopy)) { [PSCustomObject]@{ Origin = 'the rescue VM'; Path = $hostCopy; Strict = $true } }
}

#endregion

#region Delta rebuild

function Get-DeltaFormat {
    <#
    .SYNOPSIS
        Reads a WinSxS delta header: PA30 or PA31, either at offset 0 or behind a 4-byte CRC.

    .DESCRIPTION
        PA30 is the msdelta format of Windows 10 and Server 2016 to 2022. PA31 is written by 24H2 and
        Server 2025 servicing and only UpdateCompression.dll applies it. The engine is chosen from the
        header, never from the guest's version.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    foreach ($offset in @(4, 0)) {
        if ($Bytes.Length -ge $offset + 4 -and $Bytes[$offset] -eq 0x50 -and $Bytes[$offset + 1] -eq 0x41 -and $Bytes[$offset + 2] -eq 0x33 -and $Bytes[$offset + 3] -in @(0x30, 0x31)) {
            return [PSCustomObject]@{ Format = 'PA3' + [char]$Bytes[$offset + 3]; Offset = $offset }
        }
    }
    return [PSCustomObject]@{ Format = 'Unknown'; Offset = 0 }
}

function Get-DeltaEngine {
    <#
    .SYNOPSIS
        Returns the libraries that can apply a delta format, in the order to try them.

    .DESCRIPTION
        PA30 uses the rescue VM's msdelta.dll. PA31 uses the rescue VM's UpdateCompression.dll when it
        has one, then the guest's own copy: a guest that wrote PA31 deltas ships the library that
        applies them. The guest copy is staged on the rescue VM and must verify as intact before it
        is loaded, so the bytes checked are the bytes run.
    #>
    param([Parameter(Mandatory = $true)][string]$Format)
    if ($script:DeltaEngines.ContainsKey($Format)) { return $script:DeltaEngines[$Format] }
    $engines = [System.Collections.Generic.List[string]]::new()
    switch ($Format) {
        'PA30' { $engines.Add((Join-Path $env:SystemRoot 'System32\msdelta.dll')) }
        'PA31' {
            $local = Join-Path $env:SystemRoot 'System32\UpdateCompression.dll'
            if ([System.IO.File]::Exists($local)) { $engines.Add($local) }
            $guest = Join-Path $script:WindowsPath 'System32\UpdateCompression.dll'
            if ($script:WindowsPath -and [System.IO.File]::Exists($guest)) {
                $staged = Join-Path (New-StagingFolder) 'UpdateCompression.dll'
                Copy-Item -LiteralPath $guest -Destination $staged -Force
                $integrity = Test-FileIntegrity -Path $staged
                if ($integrity.Verdict -eq 'Intact') { $engines.Add($staged) }
                else { Add-OfflineRepairLog -Level Info -Message "The guest's UpdateCompression.dll was not used: $($integrity.Detail)." }
            }
            if ($engines.Count -eq 0) { Add-OfflineRepairLog -Level Info -Message 'PA31 deltas need UpdateCompression.dll, and neither the rescue VM nor the guest has a usable copy.' }
            else { Add-OfflineRepairLog -Level Info -Message "PA31 deltas are applied with $($engines -join ', then ')." }
        }
    }
    $script:DeltaEngines[$Format] = $engines
    return $engines
}

function Invoke-DeltaApply {
    param([byte[]]$Source, [Parameter(Mandatory = $true)][string]$DeltaPath)
    $delta = [System.IO.File]::ReadAllBytes($DeltaPath)
    $header = Get-DeltaFormat -Bytes $delta
    if ($header.Format -eq 'Unknown') { throw "$([System.IO.Path]::GetFileName($DeltaPath)) is not a PA30 or PA31 delta" }
    $engines = @(Get-DeltaEngine -Format $header.Format)
    if ($engines.Count -eq 0) { throw "no library that applies $($header.Format) deltas is available" }
    $failure = $null
    foreach ($engine in $engines) {
        try { return , ([RslSystemFile.Delta]::Apply($engine, $Source, $delta, $header.Offset)) }
        catch { $failure = $_.Exception }
    }
    throw $failure
}

function Get-RtmBase {
    <#
    .SYNOPSIS
        Rebuilds the RTM image of the component family: an intact family member with its r\ delta, or
        an RTM member directly. Returns the bytes and where they came from, or $null.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    $members = @($Plan.Family | Where-Object { $_.Full -and -not $_.Linked } | Sort-Object { $_.Component.Version } -Descending)
    foreach ($member in $members) {
        if ($member.Component.Version.Revision -le 1) {
            if ((Test-FileIntegrity -Path $member.Full).Verdict -eq 'Intact') {
                return [PSCustomObject]@{ Bytes = [System.IO.File]::ReadAllBytes($member.Full); Origin = $member.Component.Folder }
            }
            continue
        }
        if (-not $member.Reverse) { continue }
        try {
            $bytes = Invoke-DeltaApply -Source ([System.IO.File]::ReadAllBytes($member.Full)) -DeltaPath $member.Reverse
            return [PSCustomObject]@{ Bytes = $bytes; Origin = "$($member.Component.Folder) + r\" }
        }
        catch { Add-OfflineRepairLog -Level Info -Message "The reverse delta of $($member.Component.Folder) did not apply: $($_.Exception.Message)" }
    }
    return $null
}

function Get-DeltaCandidate {
    <#
    .SYNOPSIS
        Tier 2: rebuilds the expected file from deltas in the guest's own component store.

    .DESCRIPTION
        A null delta (n\) rebuilds the file from nothing. A forward delta (f\) needs the RTM image,
        which is rebuilt from any intact family member and its reverse delta (r\). The output is staged
        on the rescue VM and then verified like any other candidate.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    if (-not $Plan.Expected) { return }
    $expected = $Plan.Expected
    $leaf = $Plan.Target.Name

    if ($expected.Null) {
        try {
            $bytes = Invoke-DeltaApply -Source $null -DeltaPath $expected.Null
            $staged = Join-Path (New-StagingFolder) $leaf
            [System.IO.File]::WriteAllBytes($staged, $bytes)
            [PSCustomObject]@{ Origin = "$($expected.Component.Folder)\n\ (null delta)"; Path = $staged; Strict = $false }
        }
        catch { Add-OfflineRepairLog -Level Info -Message "The null delta for $leaf did not apply: $($_.Exception.Message)" }
    }

    if (-not $expected.Forward) { return }
    $base = Get-RtmBase -Plan $Plan
    if (-not $base) {
        Add-OfflineRepairLog -Level Info -Message "No intact $leaf of another build is in the store, so its forward delta cannot be applied."
        return
    }
    try {
        $bytes = Invoke-DeltaApply -Source $base.Bytes -DeltaPath $expected.Forward
        $staged = Join-Path (New-StagingFolder) $leaf
        [System.IO.File]::WriteAllBytes($staged, $bytes)
        [PSCustomObject]@{ Origin = "RTM from $($base.Origin) + $($expected.Component.Folder)\f\"; Path = $staged; Strict = $false }
    }
    catch { Add-OfflineRepairLog -Level Info -Message "The forward delta for $leaf did not apply: $($_.Exception.Message)" }
}

#endregion

#region Update package

function Get-PackageIdentifier {
    <#
    .SYNOPSIS
        Reads the KB identifier from a servicing package manifest without resolving external entities.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create($Path, $settings)
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        foreach ($node in $document.GetElementsByTagName('package')) {
            $id = $node.GetAttribute('identifier')
            if ($id -match '^KB\d+$') { return $id }
        }
    }
    catch { Add-OfflineRepairLog -Level Info -Message "Package manifest $(Split-Path $Path -Leaf) could not be read: $($_.Exception.Message)" }
    finally { if ($reader) { $reader.Dispose() } }
    return ''
}

function Get-GuestUpdate {
    <#
    .SYNOPSIS
        Identifies the cumulative update installed on the guest: the RollupFix package whose servicing
        state is Installed, preferring the one that matches the guest's UBR.
    #>
    $packages = Join-OfflinePath -Root $script:WindowsPath -ChildPath 'servicing\Packages'
    $manifests = @(Get-ChildItem -LiteralPath $packages -Filter 'Package_for_RollupFix~*.mum' -File -Force -ErrorAction SilentlyContinue)
    if ($manifests.Count -eq 0) { return $null }

    $hive = Join-OfflinePath -Root $script:WindowsPath -ChildPath 'System32\config\SOFTWARE'
    $installed = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ubr = $null
    $reader = $null
    try {
        $reader = Open-OfflineRegistryReader -Path $hive
        $ubr = $reader.ReadDword('Microsoft\Windows NT\CurrentVersion', 'UBR')
        foreach ($manifest in $manifests) {
            $m = [regex]::Match($manifest.BaseName, '~~(\d+\.\d+\.\d+\.\d+)$')
            if (-not $m.Success) { continue }
            $state = $reader.ReadDword("Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\$($manifest.BaseName)", 'CurrentState')
            if ($state -ne 0x70) { continue }
            $kb = Get-PackageIdentifier -Path $manifest.FullName
            if ($kb) { $installed.Add([PSCustomObject]@{ Kb = $kb; Version = [version]$m.Groups[1].Value; Name = $manifest.BaseName }) }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The guest's installed updates could not be read: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($reader) { try { $reader.Dispose() } catch { Add-OfflineRepairLog -Level Warning -Message "Closing the SOFTWARE hive failed: $($_.Exception.Message)" } }
    }

    if ($installed.Count -eq 0) { return $null }
    $match = @($installed | Where-Object { $null -ne $ubr -and $_.Version.Minor -eq $ubr })
    if ($match.Count -gt 0) { return $match[0] }
    return @($installed | Sort-Object Version -Descending)[0]
}

function Get-UpdateTitlePattern {
    <#
    .SYNOPSIS
        The Update Catalog title pattern for the guest's product and architecture, or '' when unknown.
    #>
    param([Parameter(Mandatory = $true)][int]$Build, [string]$ProductName = '', [int]$Machine = 0x8664)

    $isServer = $ProductName -match 'Server'
    $product = switch ($Build) {
        14393 { if ($isServer) { 'Windows Server 2016' } else { 'Windows 10 Version 1607' } }
        17763 { if ($isServer) { 'Windows Server 2019' } else { 'Windows 10 Version 1809' } }
        19044 { if (-not $isServer) { 'Windows 10 Version 21H2' } }
        19045 { if (-not $isServer) { 'Windows 10 Version 22H2' } }
        20348 { if ($isServer) { 'Microsoft server operating system,? version 21H2' } }
        22621 { if (-not $isServer) { 'Windows 11 Version 22H2' } }
        22631 { if (-not $isServer) { 'Windows 11 Version 23H2' } }
        26100 { if ($isServer) { 'Microsoft server operating system,? version 24H2' } else { 'Windows 11 Version 24H2' } }
    }
    if (-not $product) { return '' }
    $arch = switch ($Machine) { 0xAA64 { 'arm64-based' } 0x14C { 'x86-based' } default { 'x64-based' } }
    return "(?i)$product.*$arch"
}

function Test-TcpReachable {
    param([Parameter(Mandatory = $true)][string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 8000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($pending)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Find-UpdateDownload {
    <#
    .SYNOPSIS
        Looks the KB up in the Microsoft Update Catalog and returns the URL of its .msu, or throws.
    #>
    param([Parameter(Mandatory = $true)][string]$Kb, [Parameter(Mandatory = $true)][string]$TitlePattern)

    $client = New-Object System.Net.WebClient
    try {
        $html = $client.DownloadString("https://www.catalog.update.microsoft.com/Search.aspx?q=$Kb")
        $rows = [regex]::Matches($html, "<a id=['""]?(?<id>[0-9a-fA-F\-]{36})_link['""]?[^>]*>\s*(?<t>[^<]+?)\s*</a>")
        $row = $rows | Where-Object {
            $title = $_.Groups['t'].Value
            $title -match $TitlePattern -and $title -notmatch '(?i)Dynamic|\.NET'
        } | Select-Object -First 1
        if (-not $row) { throw "the catalog lists no $Kb entry for this product" }

        $id = $row.Groups['id'].Value
        $payload = '[{"size":0,"languages":"","uidInfo":"' + $id + '","updateID":"' + $id + '"}]'
        $client.Headers['Content-Type'] = 'application/x-www-form-urlencoded'
        $dialog = $client.UploadString('https://www.catalog.update.microsoft.com/DownloadDialog.aspx', 'updateIDs=' + [uri]::EscapeDataString($payload))
        $urls = @([regex]::Matches($dialog, "files\[\d+\]\.url\s*=\s*'(?<u>[^']+)'") | ForEach-Object { $_.Groups['u'].Value } | Where-Object { $_ -match '(?i)\.msu$' })
        # A checkpoint-based update lists more than one package; the one named after the KB is the update itself.
        $url = @($urls | Where-Object { $_ -match "(?i)$($Kb.ToLowerInvariant())" }) + $urls | Select-Object -First 1
        if (-not $url) { throw "the catalog offered no .msu for $Kb" }

        $uri = [uri]$url
        if ($uri.Scheme -notin @('http', 'https') -or $uri.Host -notmatch '(?i)(\.|^)(windowsupdate\.com|microsoft\.com)$') {
            throw "the catalog returned an unexpected download host '$($uri.Host)'"
        }
        return [PSCustomObject]@{ Title = $row.Groups['t'].Value.Trim(); Url = $url }
    }
    finally { $client.Dispose() }
}

function Get-DownloadSize {
    param([Parameter(Mandatory = $true)][string]$Url)
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = 'HEAD'
        $request.Timeout = 30000
        $response = $request.GetResponse()
        try { return [long]$response.ContentLength } finally { $response.Close() }
    }
    catch { return [long]-1 }
}

function Select-StagingVolume {
    <#
    .SYNOPSIS
        Picks the rescue VM's fixed volume with the most free space, never the guest's disk or another
        attached Windows installation. Returns the root, or '' when none has the space required.
    #>
    param([Parameter(Mandatory = $true)][long]$RequiredBytes)

    $guestRoot = [System.IO.Path]::GetPathRoot($script:WindowsPath)
    $hostRoot = [System.IO.Path]::GetPathRoot($env:SystemRoot)
    $best = $null
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or -not $drive.IsReady) { continue }
            $root = $drive.RootDirectory.FullName
            if ($root -eq $guestRoot) { continue }
            if ($root -ne $hostRoot -and [System.IO.File]::Exists((Join-Path $root 'Windows\System32\config\SYSTEM'))) { continue }
            if ($drive.AvailableFreeSpace -lt $RequiredBytes) { continue }
            if (-not $best -or $drive.AvailableFreeSpace -gt $best.AvailableFreeSpace) { $best = $drive }
        }
        catch { continue }
    }
    if ($best) { return $best.RootDirectory.FullName }
    return ''
}

function Test-MicrosoftSignedFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
    }
    catch { return $false }
}

function Get-CabinetEntry {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expandExe = Join-Path $env:SystemRoot 'System32\expand.exe'
    $prefix = '^' + [regex]::Escape($Path) + ':\s+(.+?)\s*$'
    return @(& $expandExe -D $Path 2>&1 | ForEach-Object {
            $m = [regex]::Match([string]$_, $prefix, 'IgnoreCase')
            if ($m.Success) { $m.Groups[1].Value }
        })
}

function Initialize-UpdatePackage {
    <#
    .SYNOPSIS
        Downloads the guest's installed cumulative update once per run and indexes its cabinets.

    .DESCRIPTION
        The package is staged on the rescue VM's roomiest volume, never on the guest. The .msu and every
        top-level cabinet must carry a valid Microsoft signature; nested cabinets are covered by the
        signature of the cabinet that contains them. Any failure leaves Ready false with a Reason.
    #>
    if ($null -ne $script:UpdatePackage) { return $script:UpdatePackage }
    $package = [PSCustomObject]@{ Ready = $false; Reason = ''; Kb = ''; Cabs = [System.Collections.Generic.List[PSCustomObject]]::new() }
    $script:UpdatePackage = $package

    if (-not $isDownloadAllowed) { $package.Reason = 'downloads are disabled (allowDownload=false)'; return $package }
    $update = Get-GuestUpdate
    if (-not $update) { $package.Reason = 'the guest has no installed cumulative update on record'; return $package }
    $package.Kb = $update.Kb
    $pattern = Get-UpdateTitlePattern -Build ([int]$script:OfflineDisk.BuildNumber) -ProductName ([string]$script:OfflineDisk.ProductName) -Machine $script:GuestMachine
    if (-not $pattern) { $package.Reason = "build $($script:OfflineDisk.BuildNumber) is not a product this script can look up"; return $package }
    foreach ($name in @('www.catalog.update.microsoft.com', 'catalog.s.download.windowsupdate.com')) {
        if (-not (Test-TcpReachable -HostName $name)) { $package.Reason = "the rescue VM cannot reach $name on port 443"; return $package }
    }

    $expandExe = Join-Path $env:SystemRoot 'System32\expand.exe'
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $download = Find-UpdateDownload -Kb $update.Kb -TitlePattern $pattern
        $size = Get-DownloadSize -Url $download.Url
        $required = $(if ($size -gt 0) { [long]($size * 3.5) } else { [long]6GB })
        $volume = Select-StagingVolume -RequiredBytes $required
        if (-not $volume) { throw ('no rescue VM volume has {0:N1} GB free to unpack it' -f ($required / 1GB)) }

        $root = Join-Path $volume "$(Split-Path $script:StagingRoot -Leaf)-update"
        $null = New-Item -ItemType Directory -Path $root -Force
        $script:UpdateStagingRoot = $root
        Log-Info ('Downloading {0} ({1}) to {2}' -f $update.Kb, $(if ($size -gt 0) { '{0:N0} MB' -f ($size / 1MB) } else { 'size unknown' }), $volume) | Tee-Object -FilePath $logFile -Append
        $msu = Join-Path $root ([System.IO.Path]::GetFileName(([uri]$download.Url).AbsolutePath))
        $client = New-Object System.Net.WebClient
        try { $client.DownloadFile($download.Url, $msu) } finally { $client.Dispose() }
        if (-not (Test-MicrosoftSignedFile -Path $msu)) { throw "the downloaded $($update.Kb) package is not signed by Microsoft" }

        $expanded = Join-Path $root 'msu'
        $null = New-Item -ItemType Directory -Path $expanded -Force
        $null = & $expandExe -F:* $msu $expanded 2>&1
        if ($LASTEXITCODE -ne 0) { throw "expand.exe could not unpack the .msu (exit $LASTEXITCODE)" }
        Remove-Item -LiteralPath $msu -Force -ErrorAction SilentlyContinue

        # A package can carry its payload in a WIM or PSF container next to small
        # metadata and servicing-stack cabinets, so searching only the cabinets would miss it.
        $container = @(Get-ChildItem -LiteralPath $expanded -File | Where-Object { $_.Extension -in @('.psf', '.wim') } | ForEach-Object { $_.Extension.TrimStart('.').ToUpperInvariant() } | Select-Object -Unique)
        if ($container.Count -gt 0) { throw "the $($update.Kb) package stores its payload in $($container -join ' and '), which this script cannot unpack" }
        $queue = New-Object System.Collections.Queue
        foreach ($cab in @(Get-ChildItem -LiteralPath $expanded -Filter '*.cab' -File | Where-Object { $_.Name -notmatch '(?i)^WSUSSCAN' })) {
            if (-not (Test-MicrosoftSignedFile -Path $cab.FullName)) { throw "$($cab.Name) in the update is not signed by Microsoft" }
            $queue.Enqueue(@($cab.FullName, 0))
        }
        $counter = 0
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()
            $entries = Get-CabinetEntry -Path $item[0]
            $package.Cabs.Add([PSCustomObject]@{ Path = $item[0]; Entries = $entries })
            $nested = @($entries | Where-Object { $_ -match '(?i)\.cab$' })
            if ($nested.Count -gt 0 -and $item[1] -lt 4) {
                $out = Join-Path $root ('c{0:D3}' -f (++$counter))
                $null = New-Item -ItemType Directory -Path $out -Force
                $null = & $expandExe -R '-F:*.cab' $item[0] $out 2>&1
                foreach ($inner in @(Get-ChildItem -LiteralPath $out -Filter '*.cab' -File -Recurse)) { $queue.Enqueue(@($inner.FullName, $item[1] + 1)) }
            }
        }
        if ($package.Cabs.Count -eq 0) { throw "the $($update.Kb) package contains no cabinets" }
        $package.Ready = $true
        Add-OfflineRepairLog -Level Info -Message "Indexed $($package.Cabs.Count) cabinet(s) of $($update.Kb): $($download.Title)"
    }
    catch { $package.Reason = "$($update.Kb) could not be used: $($_.Exception.Message)" }
    return $package
}

function Select-UpdatePayload {
    <#
    .SYNOPSIS
        Picks, from a folder expand -R extracted one file name into, the copies that belong to the
        expected component: the full file (<folder>\<leaf>), a null delta (n\) or a forward delta (f\).
        Reverse deltas and copies from any other component are ignored.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$Leaf
    )

    $rank = @('full', 'n', 'f')
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -Filter $Leaf -File -Recurse -ErrorAction SilentlyContinue)) {
        if ($file.Name -ine $Leaf) { continue }
        $parent = $file.Directory
        $kind = $(if ($parent.Name -in @('n', 'f')) { $parent.Name.ToLowerInvariant() } elseif ($parent.Name -ieq 'r') { '' } else { 'full' })
        if (-not $kind) { continue }
        $component = $(if ($kind -eq 'full') { $parent.Name } else { $parent.Parent.Name })
        if ($component -ine $Folder) { continue }
        $entry = $(if ($kind -eq 'full') { "$component\$Leaf" } else { "$component\$kind\$Leaf" })
        [PSCustomObject]@{ Path = $file.FullName; Entry = $entry; Kind = $kind; Rank = [array]::IndexOf($rank, $kind) }
    }
}

function Get-UpdateCandidate {
    <#
    .SYNOPSIS
        Tier 3: the expected component's copy of the file from the guest's own cumulative update, as a
        full file, a null delta, or a forward delta applied to the rebuilt RTM image.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    if (-not $Plan.Expected) { return }
    $package = Initialize-UpdatePackage
    if (-not $package.Ready) { Add-OfflineRepairLog -Level Info -Message "The update package tier was skipped: $($package.Reason)"; return }

    $folder = $Plan.Expected.Component.Folder
    $leaf = $Plan.Target.Name
    # expand -D lists only leaf names, so the component folder is known only once the file is
    # extracted with -R, which recreates the folders it sits in.
    $expandExe = Join-Path $env:SystemRoot 'System32\expand.exe'
    $hits = foreach ($cab in $package.Cabs) {
        if (-not @($cab.Entries | Where-Object { [System.IO.Path]::GetFileName($_) -ieq $leaf }).Count) { continue }
        $out = New-StagingFolder
        $null = & $expandExe -R "-F:$leaf" $cab.Path $out 2>&1
        Select-UpdatePayload -Root $out -Folder $folder -Leaf $leaf
    }
    $hits = @($hits | Sort-Object Rank)
    if ($hits.Count -eq 0) { Add-OfflineRepairLog -Level Info -Message "$($package.Kb) does not carry $leaf for $folder."; return }

    foreach ($hit in $hits) {
        $file = $hit.Path
        $origin = "$($package.Kb) $($hit.Entry)"
        try {
            switch ($hit.Kind) {
                'full' { [PSCustomObject]@{ Origin = $origin; Path = $file; Strict = $false } }
                'n' {
                    $staged = Join-Path (New-StagingFolder) $leaf
                    [System.IO.File]::WriteAllBytes($staged, (Invoke-DeltaApply -Source $null -DeltaPath $file))
                    [PSCustomObject]@{ Origin = "$origin (null delta)"; Path = $staged; Strict = $false }
                }
                'f' {
                    $base = Get-RtmBase -Plan $Plan
                    if (-not $base) { Add-OfflineRepairLog -Level Info -Message "$origin is a forward delta, and no RTM base could be rebuilt from the store."; continue }
                    $staged = Join-Path (New-StagingFolder) $leaf
                    [System.IO.File]::WriteAllBytes($staged, (Invoke-DeltaApply -Source $base.Bytes -DeltaPath $file))
                    [PSCustomObject]@{ Origin = "$origin on RTM from $($base.Origin)"; Path = $staged; Strict = $false }
                }
            }
        }
        catch { Add-OfflineRepairLog -Level Info -Message "$origin did not apply: $($_.Exception.Message)" }
    }
}

#endregion

#region Backup and sfc

function Get-BackupPath {
    <#
    .SYNOPSIS
        A backup path beside the file, unique to this run.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $candidate = "$Path$script:BackupSuffix"
    $counter = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = "$Path$script:BackupSuffix-$counter"
        $counter++
    }
    return $candidate
}

function Backup-Artifact {
    <#
    .SYNOPSIS
        Copies a file aside before it is replaced, and records it so -revert can find it.

    .DESCRIPTION
        A file that does not exist yet is recorded as an empty marker file beside where it will go, so
        reverting deletes what this script created. The marker has to be on the disk because -revert is
        a later, separate run of this script. Failing to write the marker is reported but does not stop
        the repair: a missing system file is the more serious problem.

    .OUTPUTS
        PSCustomObject with Succeeded, BackupPath and Existed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-OfflineTarget -Path $Path -Action 'back up'
    if (-not (Test-Path -LiteralPath $Path)) {
        $markerPath = "$(Get-BackupPath -Path $Path)$script:AbsentMarkerSuffix"
        try {
            New-Item -Path $markerPath -ItemType File -Force -ErrorAction Stop | Out-Null
            [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = $markerPath; Existed = $false })
            return [PSCustomObject]@{ Succeeded = $true; BackupPath = $markerPath; Existed = $false }
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not record that $Path was absent ($($_.Exception.Message)). A revert will leave the created file in place."
            return [PSCustomObject]@{ Succeeded = $true; BackupPath = ''; Existed = $false }
        }
    }

    $backupPath = Get-BackupPath -Path $Path
    try {
        Copy-Item -LiteralPath $Path -Destination $backupPath -Force -ErrorAction Stop
        [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = $backupPath; Existed = $true })
        return [PSCustomObject]@{ Succeeded = $true; BackupPath = $backupPath; Existed = $true }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not back up $Path : $($_.Exception.Message)"
        return [PSCustomObject]@{ Succeeded = $false; BackupPath = ''; Existed = $true }
    }
}

function Undo-Artifact {
    <#
    .SYNOPSIS
        Puts a file back the way Backup-Artifact found it, after a candidate failed verification.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Backup)

    if (-not $Backup.Existed) {
        $removal = Invoke-OfflineProtectedFileRemoval -Path $Path
        return ($removal.Removed -or $removal.Absent)
    }
    if (-not $Backup.BackupPath) { return $false }
    $restore = Copy-OfflineProtectedFile -Source $Backup.BackupPath -Destination $Path
    return [bool]$restore.Copied
}

function Clear-Artifact {
    <#
    .SYNOPSIS
        Drops the backup or marker of a file this run left exactly as it found it.

    .DESCRIPTION
        A record left behind by a failed repair would make a later revert=true act on it as the newest
        run: copying stale bytes over a file fixed some other way, or deleting a file this script did
        not create. It is only dropped when the file provably matches its original state; anything
        else keeps it, because then there is a change to undo.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Backup)

    if (-not $Backup.BackupPath -or -not (Test-Path -LiteralPath $Backup.BackupPath)) { return }
    if ($Backup.Existed) {
        $current = Get-FileSha256 -Path $Path
        if (-not $current -or $current -ne (Get-FileSha256 -Path $Backup.BackupPath)) { return }
    }
    elseif (Test-Path -LiteralPath $Path) { return }

    Assert-OfflineTarget -Path $Backup.BackupPath -Action 'remove an unused backup'
    try {
        Remove-Item -LiteralPath $Backup.BackupPath -Force -ErrorAction Stop
        $entry = @($script:BackupManifest | Where-Object { $_.BackupPath -eq $Backup.BackupPath })
        foreach ($e in $entry) { [void]$script:BackupManifest.Remove($e) }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not remove the unused backup $($Backup.BackupPath): $($_.Exception.Message). Delete it before any revert=true run."
    }
}

function Invoke-OfflineSfcScanFile {
    <#
    .SYNOPSIS
        Repairs one file from the guest's own component store with a targeted sfc.

    .DESCRIPTION
        Only ever /SCANFILE, and only ever against a file detection has already found to be wrong.
        The store it sources from belongs to the guest, so the replacement is the right build by
        construction.

        sfc exits 0 whether or not it repaired anything and writes UTF-16 to the console, so neither
        is usable. /OFFLOGFILE is parsed instead. The log is written to the rescue VM rather than the
        guest, so a failed repair leaves nothing behind on the disk being repaired.

        What this reports is only ever used as detail for the caller's message. Whether the repair
        actually worked is decided by the caller re-checking the file, because one sfc transaction
        can repair files beyond the one it was given and will then report no repair for a file that
        is already correct.

    .OUTPUTS
        PSCustomObject with Succeeded, Detail and LogLines.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $drive = $WindowsDrive.TrimEnd('\')
    $sfcLog = Join-Path $env:TEMP ("sfc-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $sfcArgs = @(
        "/SCANFILE=$Path"
        "/OFFBOOTDIR=$drive\"
        "/OFFWINDIR=$drive\Windows"
        "/OFFLOGFILE=$sfcLog"
    )

    Add-OfflineRepairLog -Level Info -Message "Running offline sfc /SCANFILE against $Path."
    try { $null = & sfc.exe @sfcArgs 2>&1 }
    catch {
        return [PSCustomObject]@{ Succeeded = $false; Detail = "sfc could not be started: $($_.Exception.Message)"; LogLines = @() }
    }

    $lines = @()
    if (Test-Path -LiteralPath $sfcLog) {
        $lines = @(Get-Content -LiteralPath $sfcLog -ErrorAction SilentlyContinue | Where-Object { $_ -match '\[SR\]' })
        Remove-Item -LiteralPath $sfcLog -Force -ErrorAction SilentlyContinue
    }

    if ($lines.Count -eq 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc produced no offline log, so nothing can be said about what it did.'; LogLines = @() }
    }

    $repaired = @($lines | Where-Object { $_ -match 'Repair complete|successfully repaired|Repairing file' })
    $unrepairable = @($lines | Where-Object { $_ -match 'Cannot repair member file' -and $_ -notmatch 'Repaired file' })

    # az vm repair keeps only the last 4 KB of the log, so sfc's long [SR] lines are written only when
    # it did not do what it was asked.
    if ($repaired.Count -eq 0) {
        foreach ($line in ($lines | Select-Object -Last 6)) {
            Add-OfflineRepairLog -Level Info -Message "  sfc: $($line.Trim())"
        }
    }

    if ($repaired.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $true; Detail = 'sfc reported a repair from the component store.'; LogLines = $lines }
    }
    if ($unrepairable.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc found the file damaged but could not repair it, which means the component store copy is damaged too.'; LogLines = $lines }
    }

    return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc reported no repair.'; LogLines = $lines }
}

#endregion

#region Repair and revert

function Repair-Finding {
    <#
    .SYNOPSIS
        Replaces one missing or damaged file from the first source that verifies.

    .DESCRIPTION
        The file is backed up once. The tiers are then tried in order: an intact copy already on the
        disk, a delta rebuild from the guest's own store, the guest's own cumulative update, and last a
        targeted sfc. Every candidate is verified before it is written and the file is verified again
        after, by re-reading it. A candidate that does not verify in place is rolled back before the
        next one is tried, so a failed repair leaves the file exactly as it was found.

        The live file and its WinSxS copy are hard links. Copying over the live file writes through the
        link, so the component store is repaired along with it.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    if ($Finding.Cause -notin @('FileMissing', 'FileDamaged')) {
        return [PSCustomObject]@{ Repaired = $false; Detail = "No repair is defined for $($Finding.Cause)." }
    }

    $t = $Finding.Data
    # One sfc transaction can repair more than the file it was given, so an earlier repair may
    # already have fixed this one.
    if ((Test-FileIntegrity -Path $t.Path).Verdict -eq 'Intact') {
        return [PSCustomObject]@{ Repaired = $true; Detail = "$($t.Relative) was already repaired by an earlier step." }
    }

    $plan = Get-SourcePlan -Target $t
    if ($plan.Reason) { Add-OfflineRepairLog -Level Info -Message "$($t.Relative): $($plan.Reason)." }
    $ref = Get-ReferenceVersion -Plan $plan

    $backup = Backup-Artifact -Path $t.Path
    if (-not $backup.Succeeded) {
        return [PSCustomObject]@{ Repaired = $false; Detail = "$($t.Relative) could not be backed up, so it was left alone." }
    }

    $tried = @{}
    $rejected = 0
    foreach ($tier in @('Direct', 'Delta', 'Update')) {
        $candidates = @(switch ($tier) {
                'Direct' { Get-DirectCandidate -Plan $plan }
                'Delta' { Get-DeltaCandidate -Plan $plan }
                'Update' { Get-UpdateCandidate -Plan $plan }
            })

        foreach ($candidate in $candidates) {
            if ($candidate.Strict) {
                $verdict = Test-RepairCandidate -Path $candidate.Path -Plan $plan -Strict -Version $ref.Version -Length $ref.Length
            }
            else {
                $verdict = Test-RepairCandidate -Path $candidate.Path -Plan $plan
            }
            if (-not $verdict.Accepted) {
                $rejected++
                Add-OfflineRepairLog -Level Info -Message "Not using $($candidate.Origin): $($verdict.Reason)."
                continue
            }
            if ($tried.ContainsKey($verdict.Hash)) { continue }
            $tried[$verdict.Hash] = $true

            $copy = Copy-OfflineProtectedFile -Source $candidate.Path -Destination $t.Path
            if ($copy.Copied) {
                $after = Test-FileIntegrity -Path $t.Path
                if ((Get-FileSha256 -Path $t.Path) -eq $verdict.Hash -and $after.Verdict -eq 'Intact') {
                    return [PSCustomObject]@{ Repaired = $true; Detail = "$($t.Relative) was replaced from $($candidate.Origin) and verifies ($($after.Detail))." }
                }
                Add-OfflineRepairLog -Level Warning -Message "$($t.Relative) did not verify after copying $($candidate.Origin) ($($after.Detail)). Rolling back."
            }
            else {
                Add-OfflineRepairLog -Level Warning -Message "$($t.Relative) could not be written from $($candidate.Origin): $($copy.Reason)"
            }
            if (-not (Undo-Artifact -Path $t.Path -Backup $backup)) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "A replacement for $($t.Relative) failed verification and the original could not be put back. The backup is $($backup.BackupPath)." }
            }
        }
    }

    Add-OfflineRepairLog -Level Info -Message "No verified replacement for $($t.Relative) was found ($($tried.Count) tried, $rejected rejected). Falling back to a targeted sfc."
    $sfc = Invoke-OfflineSfcScanFile -Path $t.Path -WindowsDrive $WindowsDrive

    # The outcome decides whether this worked, not what sfc said it did.
    $after = Test-FileIntegrity -Path $t.Path
    if ($after.Verdict -eq 'Intact') {
        return [PSCustomObject]@{ Repaired = $true; Detail = "$($t.Relative) was repaired by sfc and verifies ($($after.Detail))." }
    }
    Clear-Artifact -Path $t.Path -Backup $backup
    return [PSCustomObject]@{ Repaired = $false; Detail = "$($sfc.Detail.TrimEnd('.')), but $($t.Relative) still does not verify ($($after.Detail))." }
}

function Get-RevertCandidate {
    <#
    .SYNOPSIS
        Finds the backups a previous run of this script left behind.

    .DESCRIPTION
        The run timestamp is part of the suffix, so the newest set is chosen and the rest are left
        alone. Reverting the newest run is what an operator means by "put it back".

        A name ending in the absent marker is a file that was not there before the repair created it.
        It carries no content, and putting it back means deleting the file rather than copying over it.

        The folders searched are those of any files passed in, plus every folder a bare name can
        resolve to, so -revert true works without repeating the file list.
    #>
    param([AllowEmptyCollection()]$Target = @())

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($folder in $script:RevertFolder) {
        $roots.Add($(if ($folder) { Join-OfflinePath -Root $script:WindowsPath -ChildPath $folder } else { $script:WindowsPath }))
    }
    foreach ($t in @($Target)) {
        if ($t.Path -and -not $t.Error) { $roots.Add((Split-Path -Path $t.Path -Parent)) }
    }

    $seen = @{}
    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pattern = "^(?<original>.+)\.$([regex]::Escape($scriptName))-backup-(?<stamp>\d{14})(-\d+)?(?<absent>$([regex]::Escape($script:AbsentMarkerSuffix)))?$"
    foreach ($root in $roots) {
        $key = $root.TrimEnd('\').ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if (-not (Test-OfflinePath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter "*.$scriptName-backup-*" -File -Force -ErrorAction SilentlyContinue)) {
            $m = [regex]::Match($file.Name, $pattern)
            if (-not $m.Success) { continue }
            [void]$found.Add([PSCustomObject]@{
                    BackupPath   = $file.FullName
                    OriginalPath = Join-Path $root $m.Groups['original'].Value
                    Stamp        = $m.Groups['stamp'].Value
                    Existed      = -not $m.Groups['absent'].Success
                })
        }
    }

    if ($found.Count -eq 0) { return @() }

    $newestStamp = @($found | Sort-Object Stamp -Descending | Select-Object -First 1).Stamp
    return @($found | Where-Object { $_.Stamp -eq $newestStamp })
}

function Invoke-Revert {
    <#
    .SYNOPSIS
        Puts back the files the most recent run replaced, and removes the ones it created.
    #>
    param([AllowEmptyCollection()]$Target = @())

    $candidates = @(Get-RevertCandidate -Target $Target)
    if ($candidates.Count -eq 0) {
        Log-Output 'No backups from a previous run of this script were found, so there is nothing to put back.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    Log-Output "Restoring $($candidates.Count) file(s) backed up by the run of $($candidates[0].Stamp)." | Tee-Object -FilePath $logFile -Append

    $restored = 0
    $removed = 0
    $failed = 0
    foreach ($candidate in $candidates) {
        if (-not $candidate.Existed) {
            $deletion = Invoke-OfflineProtectedFileRemoval -Path $candidate.OriginalPath
            if ($deletion.Removed -or $deletion.Absent) {
                $removed++
                Log-Output "  Removed $($candidate.OriginalPath), which this script had created." | Tee-Object -FilePath $logFile -Append
                Remove-Item -LiteralPath $candidate.BackupPath -Force -ErrorAction SilentlyContinue
            }
            else {
                $failed++
                Log-Warning "  Could not remove $($candidate.OriginalPath): $($deletion.Reason)" | Tee-Object -FilePath $logFile -Append
            }
            continue
        }

        $copy = Copy-OfflineProtectedFile -Source $candidate.BackupPath -Destination $candidate.OriginalPath
        if ($copy.Copied) {
            $restored++
            Log-Output "  Restored $($candidate.OriginalPath)." | Tee-Object -FilePath $logFile -Append
            Remove-Item -LiteralPath $candidate.BackupPath -Force -ErrorAction SilentlyContinue
        }
        else {
            $failed++
            Log-Warning "  Could not restore $($candidate.OriginalPath): $($copy.Reason)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $summary = "Restored $restored file(s) and removed $removed file(s) that the repair had created"
    if ($failed -gt 0) {
        Log-Error "$summary, but $failed could not be put back." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "$summary. The disk is back in the state it was in before this script ran." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}

#endregion

try {
    "$scriptStartTime" | Out-File -FilePath $logFile -Append
    Log-Output "START: Running script $scriptName (files='$files', detectOnly=$isDetectOnly, revert=$isRevert, allowDownload=$isDownloadAllowed)" | Tee-Object -FilePath $logFile -Append

    $offline = if ($windowsDrive) { Get-OfflineWindowsDisk -WindowsDrive $windowsDrive } else { Get-OfflineWindowsDisk }
    $script:OfflineDisk = $offline
    $script:WindowsPath = $offline.WindowsPath
    Log-Output "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName), build $($offline.BuildNumber))." | Tee-Object -FilePath $logFile -Append

    Initialize-SystemFileNative

    $targets = @()
    if ($files.Trim()) { $targets = Get-RequestedTarget -List $files }

    if ($isRevert) {
        return Invoke-Revert -Target $targets
    }

    if ($targets.Count -eq 0) {
        Log-Error "No files were named. Pass the damaged file(s) with -parameters files=<name>[,<name>...], for example files=win32kbase.sys or files=System32\drivers\disk.sys. The file names usually come from the boot screen, the serial console or a bugcheck." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }
    if ($targets.Count -gt $script:MaxFiles) {
        Log-Error "$($targets.Count) files were named; at most $($script:MaxFiles) are checked per run. For wider damage use win-sfc-sf-corruption, which scans the whole installation." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $script:GuestMachine = (Get-ExpectedMachine -Target ([PSCustomObject]@{ Relative = '' })).Machine

    $findings = Get-SystemFileFinding -Target $targets
    if ($script:CatalogSummary) { Log-Info "Guest catalog: $($script:CatalogSummary)" | Tee-Object -FilePath $logFile -Append }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($findings.Count -eq 0) {
        Log-Output "All $($targets.Count) named file(s) are intact: each carries a signature that verifies, either embedded or through the guest's own catalogs. No changes were made. If the VM still fails, the fault is elsewhere; the boot screen, serial console or a memory dump names the file that actually failed." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    foreach ($finding in $findings) {
        Log-Output "[$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "detectOnly was requested, so nothing was changed. $($repairable.Count) file(s) can be repaired, $($unrepairable.Count) need a decision." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = @()
    foreach ($finding in $repairable) {
        $result = Repair-Finding -Finding $finding -WindowsDrive $offline.WindowsDrive
        if ($result.Repaired) {
            $finding.Repaired = $true
            $repairedCount++
            Log-Output "  Repaired [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
        else {
            $failed += $finding
            Log-Warning "  Repair failed [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Verified against freshly read state rather than by trusting the repairs above.
    $remaining = Get-SystemFileFinding -Target $targets
    Write-OfflineRepairLog | Out-Null
    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) file(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) file(s) need a decision and were only reported." }

    if ($failed.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($failed.Count) repair(s) failed and $($stillRepairable.Count) file(s) are still damaged or missing." | Tee-Object -FilePath $logFile -Append
        if (-not $isDownloadAllowed) {
            Log-Output 'Downloads were disabled. Running again with -parameters allowDownload=true lets the script fetch the guest''s own cumulative update as a source.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    if ($repairedCount -gt 0) {
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
        Log-Output "If the VM still fails to start, run this script again with -parameters revert=true files=<same files> to put the original files back." | Tee-Object -FilePath $logFile -Append
        Log-Output "The originals were kept beside each file as '<name>$($script:BackupSuffix)'. Delete them once the VM is healthy; revert=true needs them." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
finally {
    # A dependency may have failed to load before these functions became available.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        Clear-OfflineDriveLetter
    }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        Write-OfflineRepairLog
    }
    # Staged copies and the unpacked update live on the rescue VM only and are never needed again.
    foreach ($staging in @($script:StagingRoot, $script:UpdateStagingRoot)) {
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
