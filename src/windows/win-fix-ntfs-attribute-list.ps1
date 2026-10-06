#########################################################################################################
#
# .SYNOPSIS
#   Repairs the NTFS metafile attribute list entries that make a volume fail to mount with stop
#   error 0x24 NTFS_FILE_SYSTEM.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   An ATTRIBUTE_LIST_ENTRY stores the offset of its name in a single byte at entry offset 7. The
#   canonical value is 0x1a. Some servicing and imaging paths have been seen to write 0x1c instead.
#   Older NTFS revisions tolerated it, newer ones do not: resolving the referenced stream fails and
#   the volume refuses to mount, which the guest shows as a boot loop bugchecking 0x24.
#
#   This is deliberately not a chkdsk wrapper, and chkdsk is not a substitute for it. Faced with
#   this layout chkdsk discards the entire attribute list rather than correcting the one byte, which
#   orphans every child record the list referenced. When that list belongs to $Secure, the volume
#   loses its security descriptor stream and comes back with default permissions on everything.
#   This script corrects the byte in place and leaves every other structure untouched.
#
#   How it works:
#     1. Scans the reserved file records (FRN 0 to 31, the NTFS metafiles) of every NTFS partition on
#        the attached broken disk, applying the update sequence array fixup so the records read
#        exactly as NTFS sees them. Records that cannot be read or parsed are counted, and a scan
#        with any of them is reported as inconclusive rather than healthy.
#     2. Reports every attribute list entry whose name offset is not 0x1a, split into entries that
#        can be corrected (exactly 0x1c, with a name that still fits at 0x1a) and entries it will
#        not touch.
#     3. Repairs only the correctable entries. A mounted volume is locked and dismounted and then
#        written through that handle. A volume Windows will not mount is written through the
#        physical disk at the partition offset, while its volume device is held locked and
#        dismounted; if that lock is refused nothing is written. Either way the entries are
#        re-scanned through the write handle first, so the repair acts on the bytes it validated.
#     4. Writes a restore manifest containing the original bytes of every region it is about to
#        change, reads it back, and refuses to write at all if that manifest cannot be saved.
#     5. Verifies through the write handle before releasing the lock, then again with a fresh one.
#
#   Nothing is written when no correctable entry is found, so a healthy disk is left untouched.
#
#   Limitations: BitLocker-encrypted partitions are not scanned (their boot sector is not NTFS);
#   unlock and decrypt them first. Only $MFT is changed; the $MFTMirr copy of FRN 0-3 is left as is.
#
# .RESOLVES
#   Stop error 0x24 NTFS_FILE_SYSTEM boot loops caused by a non-canonical attribute list name
#   offset in an NTFS metafile, typically appearing after a servicing operation.
#
# .PARAMETER detectOnly
#   "true" to scan and report without writing anything. Defaults to "false".
#
# .PARAMETER volume
#   Restrict the scan to a single mounted volume, for example "F". Defaults to every NTFS
#   partition on the attached disk.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when automatic
#   detection picks the wrong volume.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --parameters volume=F --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --parameters windowsDrive=F --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   This script writes directly to the disk. It only changes attribute list entries whose name
#   offset is exactly 0x1c and whose name still fits at 0x1a: the name is moved back two bytes and
#   the offset set to 0x1a. The original bytes of every region are captured first. The restore
#   manifest is written next to the detail log on the rescue VM's public desktop; copy it off the
#   rescue VM before deleting it.
#
#   The partition's volume is locked and dismounted for the repair, also when it has to be written
#   through the physical disk. Make sure no offline registry hive is still mounted from the disk, or
#   the lock will be refused and nothing will be written.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$volume = '',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')

# The canonical name offset, the single malformed value this script knows how to correct, and the
# highest reserved file record number to scan. FRN 0 to 31 are the NTFS metafiles; user files start
# at 32 and are out of scope.
$script:NtfsAttrListGoodNameOffset = 0x1A
$script:NtfsAttrListBadNameOffset = 0x1C
$script:NtfsAttrListMaxFrn = 31
$script:OfflineNtfsBackupDir = "$env:PUBLIC\Desktop"

# Byte offset added to every raw read and write. Zero when a mounted volume is
# addressed directly; the partition's offset when the volume will not mount and
# the partition has to be reached through the physical disk instead.
$script:NtfsIoBaseOffset = [long]0

function Initialize-NtfsRawVolumeIo {
    # Raw volume read/write primitives. Loaded on demand so the script has no
    # cost when no attribute-list operation is requested.
    if (([System.Management.Automation.PSTypeName]'OfflineNtfsRawVolumeIo').Type) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class OfflineNtfsRawVolumeIo
{
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
private static extern SafeFileHandle CreateFileW(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer,
    uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer,
    uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool SetFilePointerEx(SafeFileHandle hFile,
    long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool FlushFileBuffers(SafeFileHandle hFile);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
    IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
    out uint lpBytesReturned, IntPtr lpOverlapped);

private const uint GENERIC_READ          = 0x80000000;
private const uint GENERIC_WRITE         = 0x40000000;
private const uint FILE_SHARE_RW         = 0x00000003;
private const uint OPEN_EXISTING         = 3;
private const uint FSCTL_LOCK_VOLUME     = 0x00090018;
private const uint FSCTL_UNLOCK_VOLUME   = 0x0009001C;
private const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;

public static SafeFileHandle OpenVolume(string path, bool forWrite)
{
    uint access = GENERIC_READ | (forWrite ? GENERIC_WRITE : 0);
    SafeFileHandle handle = CreateFileW(path, access, FILE_SHARE_RW, IntPtr.Zero,
                                        OPEN_EXISTING, 0, IntPtr.Zero);
    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    return handle;
}

public static byte[] Read(SafeFileHandle handle, long offset, int size)
{
    long position;
    if (!SetFilePointerEx(handle, offset, out position, 0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    byte[] buffer = new byte[size];
    uint read;
    if (!ReadFile(handle, buffer, (uint)size, out read, IntPtr.Zero))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    if (read != (uint)size)
        throw new IOException("Short read at offset " + offset + ": expected " + size + " bytes, got " + read + ".");
    return buffer;
}

public static void Write(SafeFileHandle handle, long offset, byte[] data)
{
    long position;
    if (!SetFilePointerEx(handle, offset, out position, 0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    uint written;
    if (!WriteFile(handle, data, (uint)data.Length, out written, IntPtr.Zero))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    if (written != (uint)data.Length)
        throw new IOException("Short write at offset " + offset + ": expected " + data.Length + " bytes, wrote " + written + ".");
}

public static void Flush(SafeFileHandle handle)
{
    if (!FlushFileBuffers(handle))
        throw new Win32Exception(Marshal.GetLastWin32Error());
}

public static void LockVolume(SafeFileHandle handle)
{
    uint returned;
    if (!DeviceIoControl(handle, FSCTL_LOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero))
        throw new Win32Exception(Marshal.GetLastWin32Error());
}

public static void DismountVolume(SafeFileHandle handle)
{
    uint returned;
    if (!DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero))
        throw new Win32Exception(Marshal.GetLastWin32Error());
}

public static void UnlockVolume(SafeFileHandle handle)
{
    uint returned;
    DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero);
}
}
'@
}

function Get-NtfsLeUInt16 { param([byte[]]$Buffer, [int]$Offset) return [BitConverter]::ToUInt16($Buffer, $Offset) }

function Get-NtfsLeUInt32 { param([byte[]]$Buffer, [int]$Offset) return [BitConverter]::ToUInt32($Buffer, $Offset) }

function Get-NtfsLeUInt64 { param([byte[]]$Buffer, [int]$Offset) return [BitConverter]::ToUInt64($Buffer, $Offset) }

function ConvertTo-NtfsVolumePath {
    # Accepts 'F', 'F:', 'F:\' or '\\.\F:' and returns the raw device form '\\.\F:'.
    param([Parameter(Mandatory)][string]$Volume)
    $value = $Volume.Trim()
    if ($value -match '^\\\\[.?]\\') { return ($value.TrimEnd('\')) }
    $letter = $value.TrimEnd('\').TrimEnd(':')
    if ($letter -notmatch '^[A-Za-z]$') { throw "Unsupported volume specification: $Volume" }
    return "\\.\$($letter.ToUpperInvariant()):"
}

function Read-NtfsVolumeAligned {
    # Raw handles only accept sector-aligned offsets and sector-multiple sizes.
    # Reads the enclosing aligned window and returns just the requested slice.
    #
    # Offsets passed in are always volume relative. When the handle is a physical
    # disk rather than a mounted volume, $script:NtfsIoBaseOffset holds the byte
    # offset of the partition, which is what makes the same NTFS code work on a
    # volume Windows refuses to mount.
    param(
        [Parameter(Mandatory)]$Handle,
        [Parameter(Mandatory)][long]$Offset,
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][int]$BytesPerSector
    )
    $absolute = [long]($Offset + $script:NtfsIoBaseOffset)
    $start = [long]([math]::Floor($absolute / $BytesPerSector) * $BytesPerSector)
    $delta = [int]($absolute - $start)
    $span = [int]([math]::Ceiling(($delta + $Size) / [double]$BytesPerSector) * $BytesPerSector)
    $window = [OfflineNtfsRawVolumeIo]::Read($Handle, $start, $span)
    $result = New-Object byte[] $Size
    [Array]::Copy($window, $delta, $result, 0, $Size)
    # Comma operator: a bare 'return $result' unrolls the byte[] into the
    # pipeline, so the caller receives an Object[]. Binding that to a
    # [byte[]] parameter silently converts it to a *new* array, which would
    # discard in-place multi-sector fixups applied by the callee.
    return , $result
}

function Write-NtfsVolumeAligned {
    # Sector-aligned read-modify-write so callers can patch arbitrary offsets.
    param(
        [Parameter(Mandatory)]$Handle,
        [Parameter(Mandatory)][long]$Offset,
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$BytesPerSector
    )
    $absolute = [long]($Offset + $script:NtfsIoBaseOffset)
    $start = [long]([math]::Floor($absolute / $BytesPerSector) * $BytesPerSector)
    $delta = [int]($absolute - $start)
    $span = [int]([math]::Ceiling(($delta + $Data.Length) / [double]$BytesPerSector) * $BytesPerSector)
    $window = [OfflineNtfsRawVolumeIo]::Read($Handle, $start, $span)
    [Array]::Copy($Data, 0, $window, $delta, $Data.Length)
    [OfflineNtfsRawVolumeIo]::Write($Handle, $start, $window)
}

function Convert-NtfsMappingPairs {
    # Decodes an NTFS mapping-pairs run list into absolute LCN/cluster-count pairs.
    # Decoding stops at $EndOffset, the end of the attribute that owns the list, so
    # a damaged list cannot run into the next attribute. Throws on a run list that
    # is truncated or describes a sparse run: an $ATTRIBUTE_LIST is never sparse,
    # so either case means the record is not safe to interpret.
    param([byte[]]$Record, [int]$StartOffset, [int]$EndOffset = -1)
    if ($EndOffset -lt 0 -or $EndOffset -gt $Record.Length) { $EndOffset = $Record.Length }
    $runs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lcn = [long]0
    $pos = $StartOffset
    $terminated = $false
    while ($pos -lt $EndOffset) {
        $header = $Record[$pos]
        if ($header -eq 0) { $terminated = $true; break }
        $pos++
        $lengthSize = $header -band 0x0F
        $offsetSize = ($header -shr 4) -band 0x0F
        if ($lengthSize -eq 0 -or $lengthSize -gt 8 -or $offsetSize -gt 8 -or ($pos + $lengthSize + $offsetSize) -gt $EndOffset) {
            throw 'Mapping pairs run list is truncated or malformed.'
        }
        if ($offsetSize -eq 0) { throw 'Mapping pairs run list contains a sparse run.' }

        [long]$runLength = 0
        for ($i = 0; $i -lt $lengthSize; $i++) { $runLength = $runLength -bor ([long]$Record[$pos + $i] -shl ($i * 8)) }
        $pos += $lengthSize

        [long]$runOffset = 0
        for ($i = 0; $i -lt $offsetSize; $i++) { $runOffset = $runOffset -bor ([long]$Record[$pos + $i] -shl ($i * 8)) }
        # Sign-extend the delta: run offsets are signed and may move backwards.
        if ($Record[$pos + $offsetSize - 1] -band 0x80) {
            for ($i = $offsetSize; $i -lt 8; $i++) { $runOffset = $runOffset -bor ([long]0xFF -shl ($i * 8)) }
        }
        $pos += $offsetSize
        $lcn += $runOffset
        if ($runLength -le 0 -or $lcn -lt 0) { throw 'Mapping pairs run list has an invalid run.' }
        $runs.Add([PSCustomObject]@{ Lcn = $lcn; Clusters = $runLength })
    }
    if (-not $terminated) { throw 'Mapping pairs run list is not terminated inside its attribute.' }
    return $runs
}
function Get-NtfsAttributeTypeName {
    param([uint32]$TypeCode)
    switch ($TypeCode) {
        0x10 { '$STANDARD_INFORMATION' }
        0x20 { '$ATTRIBUTE_LIST' }
        0x30 { '$FILE_NAME' }
        0x40 { '$OBJECT_ID' }
        0x50 { '$SECURITY_DESCRIPTOR' }
        0x60 { '$VOLUME_NAME' }
        0x70 { '$VOLUME_INFORMATION' }
        0x80 { '$DATA' }
        0x90 { '$INDEX_ROOT' }
        0xA0 { '$INDEX_ALLOCATION' }
        0xB0 { '$BITMAP' }
        0xC0 { '$REPARSE_POINT' }
        0x100 { '$LOGGED_UTILITY_STREAM' }
        default { "0x$($TypeCode.ToString('x'))" }
    }
}

# The update sequence array protects every 512-byte stride of a multi-sector
# record, whatever the disk's sector size, so the fixup never uses BytesPerSector:
# a 4Kn volume still has one fixup entry per 512 bytes.
$script:NtfsUsaStride = 512

function Resolve-NtfsUsaFixup {
    # Applies the update-sequence-array fixup in place (on-disk -> in-memory).
    # Returns $false when the record's stride tails do not carry the expected
    # update sequence number, which means the record is not safe to interpret.
    param([byte[]]$Record)
    if ($Record.Length -lt 0x30) { return $false }
    $usaOffset = Get-NtfsLeUInt16 $Record 4
    $usaCount = Get-NtfsLeUInt16 $Record 6
    if ($usaCount -lt 2 -or ($usaOffset + $usaCount * 2) -gt $Record.Length) { return $false }
    if ((($usaCount - 1) * $script:NtfsUsaStride) -gt $Record.Length) { return $false }
    $usn = Get-NtfsLeUInt16 $Record $usaOffset
    for ($i = 1; $i -lt $usaCount; $i++) {
        $strideEnd = $i * $script:NtfsUsaStride - 2
        if ((Get-NtfsLeUInt16 $Record $strideEnd) -ne $usn) { return $false }
    }
    for ($i = 1; $i -lt $usaCount; $i++) {
        $strideEnd = $i * $script:NtfsUsaStride - 2
        $stored = Get-NtfsLeUInt16 $Record ($usaOffset + $i * 2)
        $Record[$strideEnd] = [byte]($stored -band 0xFF)
        $Record[$strideEnd + 1] = [byte](($stored -shr 8) -band 0xFF)
    }
    return $true
}

function Set-NtfsUsaFixup {
    # Re-applies the update-sequence-array fixup in place (in-memory -> on-disk).
    # Exact inverse of Resolve-NtfsUsaFixup, so a record can be patched in its
    # readable form and written back without corrupting the stride tails.
    param([byte[]]$Record)
    $usaOffset = Get-NtfsLeUInt16 $Record 4
    $usaCount = Get-NtfsLeUInt16 $Record 6
    if ($usaCount -lt 2 -or ($usaOffset + $usaCount * 2) -gt $Record.Length -or (($usaCount - 1) * $script:NtfsUsaStride) -gt $Record.Length) {
        throw 'File record update sequence array does not fit the record.'
    }
    $usn = Get-NtfsLeUInt16 $Record $usaOffset
    for ($i = 1; $i -lt $usaCount; $i++) {
        $strideEnd = $i * $script:NtfsUsaStride - 2
        $real = Get-NtfsLeUInt16 $Record $strideEnd
        $Record[$usaOffset + $i * 2] = [byte]($real -band 0xFF)
        $Record[$usaOffset + $i * 2 + 1] = [byte](($real -shr 8) -band 0xFF)
        $Record[$strideEnd] = [byte]($usn -band 0xFF)
        $Record[$strideEnd + 1] = [byte](($usn -shr 8) -band 0xFF)
    }
}

function Get-NtfsAttributeListLocation {
    # Locates the $ATTRIBUTE_LIST attribute inside a fixed-up file record and
    # describes where its value lives (inside the record, or in disk runs).
    # Returns $null when the record has no attribute list, and an object with
    # Malformed = $true when the attribute walk or the list itself cannot be
    # trusted, so the caller can tell "nothing to check" from "could not check".
    param([byte[]]$FileRecord)
    $malformed = { param($Reason) [PSCustomObject]@{ Malformed = $true; Reason = $Reason } }
    $pos = [int](Get-NtfsLeUInt16 $FileRecord 0x14)
    if ($pos -lt 0x18) { return (& $malformed 'first attribute offset is invalid') }
    while (($pos + 8) -le $FileRecord.Length) {
        $typeCode = Get-NtfsLeUInt32 $FileRecord $pos
        # Compare against [uint32]::MaxValue: the literal 0xFFFFFFFF parses as
        # Int32 -1, which never equals an unsigned type code.
        if ($typeCode -eq [uint32]::MaxValue) { return $null }
        $recordLength = [int](Get-NtfsLeUInt32 $FileRecord ($pos + 4))
        if ($recordLength -lt 16 -or ($pos + $recordLength) -gt $FileRecord.Length) {
            return (& $malformed ("attribute at +0x{0:x} has an invalid length" -f $pos))
        }

        if ($typeCode -eq 0x20) {
            $isResident = ($FileRecord[$pos + 8] -eq 0)
            if ($isResident) {
                $valueLength = [long](Get-NtfsLeUInt32 $FileRecord ($pos + 0x10))
                $valueOffset = [int](Get-NtfsLeUInt16 $FileRecord ($pos + 0x14))
                if (($valueOffset + $valueLength) -gt $recordLength) { return (& $malformed 'resident attribute list value overruns its attribute') }
                return [PSCustomObject]@{
                    Malformed        = $false
                    IsResident       = $true
                    DataSize         = [int]$valueLength
                    RecordValueStart = [int]($pos + $valueOffset)
                    Runs             = @()
                }
            }
            if ($recordLength -lt 0x40) { return (& $malformed 'non-resident attribute list header is truncated') }
            $mappingOffset = [int](Get-NtfsLeUInt16 $FileRecord ($pos + 0x20))
            $dataSize = Get-NtfsLeUInt64 $FileRecord ($pos + 0x30)
            if ($mappingOffset -lt 0x40 -or $mappingOffset -ge $recordLength) { return (& $malformed 'mapping pairs offset is outside the attribute') }
            if ($dataSize -gt [int]::MaxValue) { return (& $malformed 'attribute list data size is implausible') }
            try {
                $runs = @(Convert-NtfsMappingPairs -Record $FileRecord -StartOffset ($pos + $mappingOffset) -EndOffset ($pos + $recordLength))
            }
            catch {
                return (& $malformed $_.Exception.Message)
            }
            if ($runs.Count -eq 0) { return (& $malformed 'attribute list has no data runs') }
            return [PSCustomObject]@{
                Malformed        = $false
                IsResident       = $false
                DataSize         = [int]$dataSize
                RecordValueStart = -1
                Runs             = $runs
            }
        }
        $pos += $recordLength
    }
    return (& $malformed 'attribute walk has no end marker')
}
function Get-NtfsVolumeGeometry {
    # Reads NTFS boot-sector geometry through an open raw handle. The boot sector
    # is at offset 0 of the volume, which is the partition offset when the handle
    # is a physical disk, so the base offset applies here too.
    param([Parameter(Mandatory)]$Handle)
    # 4096 covers both 512-byte and 4Kn sector sizes in a single aligned read.
    $boot = [OfflineNtfsRawVolumeIo]::Read($Handle, $script:NtfsIoBaseOffset, 4096)
    if ([System.Text.Encoding]::ASCII.GetString($boot, 3, 4) -ne 'NTFS') {
        throw 'Volume does not carry an NTFS boot sector.'
    }
    $bytesPerSector = Get-NtfsLeUInt16 $boot 0x0B
    # Sectors-per-cluster and clusters-per-record both switch to a signed
    # representation once the value no longer fits a byte: N > 0x80 means
    # 2^(256-N) rather than N literally.
    $rawSectorsPerCluster = $boot[0x0D]
    $sectorsPerCluster = if ($rawSectorsPerCluster -le 0x80) { [int]$rawSectorsPerCluster } else { 1 -shl (256 - $rawSectorsPerCluster) }
    if ($bytesPerSector -le 0 -or $sectorsPerCluster -le 0) { throw 'Invalid NTFS boot sector geometry.' }
    $clusterSize = $bytesPerSector * $sectorsPerCluster
    $rawRecordSize = $boot[0x40]
    $recordSize = if ($rawRecordSize -lt 0x80) { $rawRecordSize * $clusterSize } else { 1 -shl (256 - $rawRecordSize) }
    return [PSCustomObject]@{
        BytesPerSector = [int]$bytesPerSector
        ClusterSize    = [int]$clusterSize
        MftLcn         = [long](Get-NtfsLeUInt64 $boot 0x30)
        RecordSize     = [int]$recordSize
    }
}

function Get-NtfsMetafileAttrListState {
    # Read-only scan of the reserved file records on one volume. Reports every
    # ATTRIBUTE_LIST_ENTRY whose NameOffset is not the canonical 0x1a, split into
    # entries this script can repair (0x1c) and entries it will not touch.
    # Never writes; safe to call from diagnostic paths. Pass an already-open
    # handle to scan under a lock the caller is holding.
    #
    # A record that should be readable but is not - a damaged header, a failed
    # update sequence check, a record that does not carry its own number, an
    # attribute list that cannot be walked - is added to Inconclusive. A scan with
    # any inconclusive record has not shown that the volume is healthy.
    param(
        [Parameter(Mandatory)][string]$Volume,
        $Handle = $null
    )

    Initialize-NtfsRawVolumeIo
    $volumePath = ConvertTo-NtfsVolumePath -Volume $Volume
    $result = [PSCustomObject]@{
        Volume       = $volumePath
        Label        = ($volumePath -replace '^\\\\[.?]\\', '')
        Scanned      = $false
        Geometry     = $null
        Records      = @()
        Inconclusive = @()
        Fixable      = 0
        Unfixable    = 0
        Error        = ''
    }

    $ownsHandle = ($null -eq $Handle)
    $handle = $Handle
    try {
        if ($ownsHandle) { $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($volumePath, $false) }
        $geometry = Get-NtfsVolumeGeometry -Handle $handle
        $result.Geometry = $geometry
        $records = [System.Collections.Generic.List[PSCustomObject]]::new()
        $inconclusive = [System.Collections.Generic.List[PSCustomObject]]::new()

        for ($frn = 0; $frn -le $script:NtfsAttrListMaxFrn; $frn++) {
            $recordOffset = [long]$geometry.MftLcn * $geometry.ClusterSize + $frn * $geometry.RecordSize
            $record = Read-NtfsVolumeAligned -Handle $handle -Offset $recordOffset -Size $geometry.RecordSize -BytesPerSector $geometry.BytesPerSector
            $skip = { param($Reason) $inconclusive.Add([PSCustomObject]@{ Frn = $frn; Name = (Get-NtfsMetafileName -Frn $frn); Reason = $Reason }) }

            $signature = [System.Text.Encoding]::ASCII.GetString($record, 0, 4)
            if ($signature -ne 'FILE') {
                # FRN 0-15 always hold a formatted record. Above that, a record that was
                # never used is all zero; anything else is damage NTFS would trip over.
                if ($frn -lt 16 -or $signature -ne "`0`0`0`0") { & $skip "record signature is '$($signature -replace '[^\x20-\x7E]', '.')', not FILE" }
                continue
            }
            $flags = Get-NtfsLeUInt16 $record 0x16
            if (($flags -band 0x01) -eq 0) { continue }
            if (-not (Resolve-NtfsUsaFixup -Record $record)) { & $skip 'update sequence check failed'; continue }

            # NTFS 3.1 records carry their own number at 0x2c. A record that names a
            # different FRN is not the record this offset should hold.
            $usaOffset = Get-NtfsLeUInt16 $record 4
            if ($usaOffset -ge 0x30) {
                $selfNumber = Get-NtfsLeUInt32 $record 0x2C
                if ($selfNumber -ne $frn) { & $skip "record reports itself as FRN $selfNumber"; continue }
            }

            $location = Get-NtfsAttributeListLocation -FileRecord $record
            if ($null -eq $location) { continue }
            if ($location.Malformed) { & $skip "attribute walk failed: $($location.Reason)"; continue }

            # Materialise the attribute-list bytes. Resident lists come from the
            # fixed-up record; non-resident lists are read from their runs, whole
            # runs at a time so the write-back path stays cluster-aligned.
            $listBytes = $null
            if ($location.IsResident) {
                $listBytes = New-Object byte[] $location.DataSize
                [Array]::Copy($record, $location.RecordValueStart, $listBytes, 0, $location.DataSize)
            }
            else {
                $allocated = [long]0
                foreach ($run in $location.Runs) { $allocated += [long]$run.Clusters * $geometry.ClusterSize }
                if ($allocated -lt $location.DataSize -or $allocated -gt 64MB) { & $skip "attribute list allocation ($allocated bytes) does not fit its data size ($($location.DataSize) bytes)"; continue }
                $listBytes = New-Object byte[] $allocated
                $cursor = 0
                foreach ($run in $location.Runs) {
                    $runBytes = [int]($run.Clusters * $geometry.ClusterSize)
                    $chunk = Read-NtfsVolumeAligned -Handle $handle -Offset ([long]$run.Lcn * $geometry.ClusterSize) -Size $runBytes -BytesPerSector $geometry.BytesPerSector
                    [Array]::Copy($chunk, 0, $listBytes, $cursor, $runBytes)
                    $cursor += $runBytes
                }
            }

            $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
            $malformed = $false
            $position = 0
            while (($position + 8) -le $location.DataSize) {
                $typeCode = Get-NtfsLeUInt32 $listBytes $position
                if ($typeCode -eq 0 -or $typeCode -eq [uint32]::MaxValue) { break }
                $entryLength = Get-NtfsLeUInt16 $listBytes ($position + 4)
                if ($entryLength -lt 0x1A -or ($position + $entryLength) -gt $location.DataSize) { $malformed = $true; break }

                $nameLength = $listBytes[$position + 6]
                $nameOffset = $listBytes[$position + 7]
                $name = ''
                if ($nameLength -gt 0 -and ($nameOffset + $nameLength * 2) -le $entryLength) {
                    $name = [System.Text.Encoding]::Unicode.GetString($listBytes, $position + $nameOffset, $nameLength * 2)
                }

                if ($nameOffset -ne $script:NtfsAttrListGoodNameOffset) {
                    $canRepair = ($nameOffset -eq $script:NtfsAttrListBadNameOffset) -and
                                 ($nameLength -gt 0) -and
                                 (($script:NtfsAttrListGoodNameOffset + $nameLength * 2) -le $entryLength) -and
                                 (($nameOffset + $nameLength * 2) -le $entryLength)
                    $entries.Add([PSCustomObject]@{
                        EntryOffset = $position
                        TypeCode    = $typeCode
                        TypeName    = Get-NtfsAttributeTypeName $typeCode
                        NameLength  = $nameLength
                        NameOffset  = $nameOffset
                        Name        = $name
                        CanRepair   = $canRepair
                    })
                }
                $position += $entryLength
            }
            if ($malformed) {
                & $skip ("attribute list entry at +0x{0:x} has an invalid length; the list was not parsed to the end" -f $position)
                # A list that cannot be walked to its end is not rewritten.
                foreach ($entry in $entries) { $entry.CanRepair = $false }
            }

            if ($entries.Count -gt 0 -or $malformed) {
                $records.Add([PSCustomObject]@{
                    Frn              = $frn
                    Name             = Get-NtfsMetafileName -Frn $frn
                    IsResident       = $location.IsResident
                    Malformed        = $malformed
                    RecordOffset     = $recordOffset
                    RecordValueStart = $location.RecordValueStart
                    DataSize         = $location.DataSize
                    Runs             = @($location.Runs)
                    Entries          = @($entries)
                })
            }
        }

        $result.Records = @($records)
        $result.Inconclusive = @($inconclusive)
        $result.Fixable = @($records | ForEach-Object { $_.Entries } | Where-Object { $_.CanRepair }).Count
        $result.Unfixable = @($records | ForEach-Object { $_.Entries } | Where-Object { -not $_.CanRepair }).Count
        $result.Scanned = $true
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($ownsHandle -and $handle -and -not $handle.IsClosed) { $handle.Close() }
    }

    return $result
}
function Get-NtfsMetafileName {
    # Friendly name for the well-known reserved file records.
    param([int]$Frn)
    switch ($Frn) {
        0 { '$MFT' }
        1 { '$MFTMirr' }
        2 { '$LogFile' }
        3 { '$Volume' }
        4 { '$AttrDef' }
        5 { '. (root)' }
        6 { '$Bitmap' }
        7 { '$Boot' }
        8 { '$BadClus' }
        9 { '$Secure' }
        10 { '$UpCase' }
        11 { '$Extend' }
        default { "file record $Frn" }
    }
}

function Set-NtfsAttrListEntryNameOffset {
    # Rewrites one ATTRIBUTE_LIST_ENTRY to the canonical layout: shifts the
    # attribute name back two bytes and sets NameOffset to 0x1a.
    #
    # RecordLength is deliberately left untouched. The entry keeps its original
    # size and the two freed trailing bytes become zero padding, so neither the
    # attribute list's length nor its on-disk allocation changes - which is what
    # keeps this a single-record edit rather than a structural rewrite.
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$EntryStart,
        [Parameter(Mandatory)][int]$NameLength
    )
    $good = $script:NtfsAttrListGoodNameOffset
    $bad = $script:NtfsAttrListBadNameOffset
    $byteCount = $NameLength * 2
    $nameBytes = New-Object byte[] $byteCount
    [Array]::Copy($Buffer, $EntryStart + $bad, $nameBytes, 0, $byteCount)
    for ($i = 0; $i -lt $byteCount; $i++) { $Buffer[$EntryStart + $bad + $i] = 0 }
    [Array]::Copy($nameBytes, 0, $Buffer, $EntryStart + $good, $byteCount)
    $Buffer[$EntryStart + 7] = [byte]$good
}

function Write-NtfsDetail {
    # Per-entry detail goes to the detail log only, so the Run Command output stays
    # bounded to one line per affected record.
    param([Parameter(Mandatory)][string]$Message)
    if ($script:NtfsDetailLog) { "    $Message" | Out-File -FilePath $script:NtfsDetailLog -Append -Encoding UTF8 }
}

function Get-NtfsSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '') }
    finally { $sha.Dispose() }
}

function New-NtfsRestoreManifest {
    # Everything needed to put every changed region back byte for byte, and to
    # prove the manifest belongs to this disk and partition before doing so.
    # Region offsets are volume relative; AbsoluteOffset adds BaseOffset, which is
    # the partition offset in disk mode and zero in volume mode.
    param(
        [Parameter(Mandatory)][string]$DevicePath,
        [Parameter(Mandatory)]$Geometry,
        [Parameter(Mandatory)][object[]]$Operations,
        $Target = $null,
        [long]$BaseOffset = 0
    )
    $mode = if ($DevicePath -match '(?i)PhysicalDrive\d+$') { 'disk' } else { 'volume' }
    return [ordered]@{
        Script          = 'win-fix-ntfs-attribute-list'
        CapturedUtc     = (Get-Date).ToUniversalTime().ToString('o')
        Mode            = $mode
        DevicePath      = $DevicePath
        BaseOffset      = $BaseOffset
        DiskNumber      = $(if ($Target) { $Target.DiskNumber } else { $null })
        PartitionNumber = $(if ($Target) { $Target.PartitionNumber } else { $null })
        VolumeGuidPath  = $(if ($Target) { "$($Target.VolumeGuidPath)" } else { '' })
        Disk            = $(if ($Target -and $Target.DiskIdentity) { $Target.DiskIdentity } else { $null })
        BytesPerSector  = $Geometry.BytesPerSector
        ClusterSize     = $Geometry.ClusterSize
        RecordSize      = $Geometry.RecordSize
        MftLcn          = $Geometry.MftLcn
        Regions         = @($Operations | ForEach-Object {
                [ordered]@{
                    Offset         = [long]$_.Offset
                    AbsoluteOffset = [long]($_.Offset + $BaseOffset)
                    Length         = $_.Original.Length
                    Sha256Original = Get-NtfsSha256Hex -Bytes $_.Original
                    Sha256Updated  = Get-NtfsSha256Hex -Bytes $_.Updated
                    OriginalBase64 = [Convert]::ToBase64String($_.Original)
                }
            })
    }
}

function Get-NtfsRestoreManifestPath {
    # Unique per disk, partition and run, so a second run never overwrites the
    # pre-image of the first.
    param([Parameter(Mandatory)][string]$Directory, $Target = $null, [string]$Label = '')
    $ticks = (Get-Date).ToUniversalTime().Ticks
    if ($Target) { $name = "win-fix-ntfs-attribute-list_d$($Target.DiskNumber)_p$($Target.PartitionNumber)_$ticks.json" }
    else { $name = "win-fix-ntfs-attribute-list_$($Label -replace '[^A-Za-z0-9]', '')_$ticks.json" }
    return (Join-Path $Directory $name)
}

function Save-NtfsRestoreManifest {
    # Writes the manifest and reads it back. Throws unless every region decodes to
    # exactly the pre-image it was captured from, so no write happens on the
    # strength of a manifest that could not restore it.
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Operations
    )
    $directory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop }
    $Manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop

    $saved = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $regions = @($saved.Regions)
    if ($regions.Count -ne $Operations.Count) { throw "Restore manifest read-back has $($regions.Count) region(s), expected $($Operations.Count)." }
    for ($i = 0; $i -lt $regions.Count; $i++) {
        $bytes = [Convert]::FromBase64String($regions[$i].OriginalBase64)
        $expected = Get-NtfsSha256Hex -Bytes $Operations[$i].Original
        if ([long]$regions[$i].Offset -ne [long]$Operations[$i].Offset -or (Get-NtfsSha256Hex -Bytes $bytes) -ne $expected -or $regions[$i].Sha256Original -ne $expected) {
            throw "Restore manifest read-back does not match region $i."
        }
    }
}

function Lock-NtfsPartitionVolume {
    # Disk mode writes through \\.\PhysicalDriveN, but Windows still keeps a volume
    # device for the partition (mounted as RAW when NTFS refuses it). Holding that
    # volume locked and dismounted keeps any file system off the partition while it
    # is written and makes Windows accept the disk writes. Throws when the lock is
    # refused; the caller must then not write.
    param([Parameter(Mandatory)][string]$VolumeGuidPath)
    $path = $VolumeGuidPath.TrimEnd('\')
    $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($path, $true)
    try {
        [OfflineNtfsRawVolumeIo]::LockVolume($handle)
        [OfflineNtfsRawVolumeIo]::DismountVolume($handle)
    }
    catch {
        $handle.Close()
        throw
    }
    return $handle
}

function Repair-NtfsAttrListVolume {
    # Applies the canonical name offset to one volume, re-scanning through the
    # write handle first so the repair acts on exactly the bytes it validated.
    # Every region is captured to a restore manifest, saved and read back, before
    # the first write.
    #
    # Volume mode: the mounted volume is locked and dismounted, and written
    # through that handle.
    # Disk mode: the volume will not mount, which is the usual state for this
    # corruption, so the caller passes \\.\PhysicalDriveN and sets
    # $script:NtfsIoBaseOffset to the partition offset. The partition's volume
    # device is locked and dismounted for the whole write; when it has one and the
    # lock is refused, nothing is written.
    param(
        [Parameter(Mandatory)][string]$Volume,
        $Target = $null
    )

    $volumePath = ConvertTo-NtfsVolumePath -Volume $Volume
    $label = if ($Target -and $Target.Label) { $Target.Label } else { $volumePath -replace '^\\\\[.?]\\', '' }
    $isDiskMode = ($volumePath -match '(?i)PhysicalDrive\d+$')
    $handle = $null
    $volumeLockHandle = $null
    $locked = $false
    $repaired = 0
    $backupPath = ''
    $failure = { param($Message) [PSCustomObject]@{ Volume = $volumePath; Repaired = 0; RegionsWritten = 0; BackupPath = $backupPath; VerifiedClean = $false; Locked = $locked; Error = $Message } }

    try {
        try {
            if ($isDiskMode) {
                if ($Target -and $Target.VolumeGuidPath) {
                    $volumeLockHandle = Lock-NtfsPartitionVolume -VolumeGuidPath $Target.VolumeGuidPath
                    $locked = $true
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "${label}: the partition has no volume device to lock, so no file system can be mounted on it; writing through the physical disk."
                }
                $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($volumePath, $true)
            }
            else {
                $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($volumePath, $true)
                [OfflineNtfsRawVolumeIo]::LockVolume($handle)
                $locked = $true
                [OfflineNtfsRawVolumeIo]::DismountVolume($handle)
            }
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "$label could not be locked for exclusive access: $($_.Exception.Message)"
            Add-OfflineRepairLog -Level Warning -Message "Close any open handle to $label, and make sure no offline registry hive is still mounted from it, before retrying."
            return (& $failure "could not lock $label; nothing was written")
        }

        $state = Get-NtfsMetafileAttrListState -Volume $volumePath -Handle $handle
        if (-not $state.Scanned) { throw "Re-scan under volume lock failed: $($state.Error)" }
        $geometry = $state.Geometry

        # Pass 1: compute every byte range that will change. Nothing is written yet.
        $operations = [System.Collections.Generic.List[PSCustomObject]]::new()
        $planned = [System.Collections.Generic.List[string]]::new()

        foreach ($record in $state.Records) {
            $fixable = @($record.Entries | Where-Object { $_.CanRepair })
            if ($fixable.Count -eq 0) { continue }

            if ($record.IsResident) {
                $frs = Read-NtfsVolumeAligned -Handle $handle -Offset $record.RecordOffset -Size $geometry.RecordSize -BytesPerSector $geometry.BytesPerSector
                $original = $frs.Clone()
                if (-not (Resolve-NtfsUsaFixup -Record $frs)) {
                    Add-OfflineRepairLog -Level Warning -Message "  $label $($record.Name): update sequence check failed on re-read; skipped."
                    continue
                }
                foreach ($entry in $fixable) {
                    Set-NtfsAttrListEntryNameOffset -Buffer $frs -EntryStart ($record.RecordValueStart + $entry.EntryOffset) -NameLength $entry.NameLength
                }
                # Restore the stride tails so the record is written back in on-disk form.
                Set-NtfsUsaFixup -Record $frs
                $operations.Add([PSCustomObject]@{ Offset = [long]$record.RecordOffset; Original = $original; Updated = $frs }) | Out-Null
            }
            else {
                $allocated = 0
                foreach ($run in $record.Runs) { $allocated += [int]($run.Clusters * $geometry.ClusterSize) }
                $buffer = New-Object byte[] $allocated
                $cursor = 0
                foreach ($run in $record.Runs) {
                    $runBytes = [int]($run.Clusters * $geometry.ClusterSize)
                    $chunk = Read-NtfsVolumeAligned -Handle $handle -Offset ([long]$run.Lcn * $geometry.ClusterSize) -Size $runBytes -BytesPerSector $geometry.BytesPerSector
                    [Array]::Copy($chunk, 0, $buffer, $cursor, $runBytes)
                    $cursor += $runBytes
                }
                $original = $buffer.Clone()
                foreach ($entry in $fixable) {
                    Set-NtfsAttrListEntryNameOffset -Buffer $buffer -EntryStart $entry.EntryOffset -NameLength $entry.NameLength
                }
                # Attribute list runs are not update-sequence protected; write them back verbatim.
                $cursor = 0
                foreach ($run in $record.Runs) {
                    $runBytes = [int]($run.Clusters * $geometry.ClusterSize)
                    $originalSlice = New-Object byte[] $runBytes
                    $updatedSlice = New-Object byte[] $runBytes
                    [Array]::Copy($original, $cursor, $originalSlice, 0, $runBytes)
                    [Array]::Copy($buffer, $cursor, $updatedSlice, 0, $runBytes)
                    $operations.Add([PSCustomObject]@{
                        Offset   = [long]($run.Lcn * $geometry.ClusterSize)
                        Original = $originalSlice
                        Updated  = $updatedSlice
                    }) | Out-Null
                    $cursor += $runBytes
                }
            }

            foreach ($entry in $fixable) {
                $planned.Add("$($record.Name) ($($entry.TypeName)$(if ($entry.Name) { ":$($entry.Name)" }))") | Out-Null
                $repaired++
            }
        }

        if ($operations.Count -eq 0) {
            Add-OfflineRepairLog -Message "${label}: nothing to repair."
            return [PSCustomObject]@{ Volume = $volumePath; Repaired = 0; RegionsWritten = 0; BackupPath = ''; VerifiedClean = $true; Locked = $locked; Error = '' }
        }

        # Capture the pre-image of every region before the first write, so the
        # volume can be put back byte for byte if the result is not what we want.
        try {
            $backupPath = Get-NtfsRestoreManifestPath -Directory $script:OfflineNtfsBackupDir -Target $Target -Label $label
            $manifest = New-NtfsRestoreManifest -DevicePath $volumePath -Geometry $geometry -Operations @($operations) -Target $Target -BaseOffset $script:NtfsIoBaseOffset
            Save-NtfsRestoreManifest -Manifest $manifest -Path $backupPath -Operations @($operations)
            Add-OfflineRepairLog -Message "  Saved and read back the pre-repair image of $($operations.Count) region(s): $backupPath"
        }
        catch {
            $message = "Refusing to write: the pre-repair backup could not be saved and verified ($($_.Exception.Message))."
            $backupPath = ''
            throw $message
        }

        # Pass 2: apply.
        foreach ($operation in $operations) {
            Write-NtfsVolumeAligned -Handle $handle -Offset $operation.Offset -Data $operation.Updated -BytesPerSector $geometry.BytesPerSector
        }
        [OfflineNtfsRawVolumeIo]::Flush($handle)

        # Verify through the write handle before releasing the lock.
        $verify = Get-NtfsMetafileAttrListState -Volume $volumePath -Handle $handle
        if (-not $verify.Scanned) {
            Add-OfflineRepairLog -Level Warning -Message "  ${label}: repair written but the verification pass could not run - $($verify.Error)"
        }
        elseif ($verify.Fixable -gt 0) {
            Add-OfflineRepairLog -Level Warning -Message "  ${label}: $($verify.Fixable) entry/entries still report a non-canonical name offset after the repair."
        }
        else {
            foreach ($item in $planned) { Write-NtfsDetail -Message "[OK] $label $item  NameOffset 0x1c -> 0x1a" }
            Add-OfflineRepairLog -Message "  [OK] $label verified: all attribute list entries now use the canonical name offset."
        }

        return [PSCustomObject]@{
            Volume         = $volumePath
            Repaired       = $repaired
            RegionsWritten = $operations.Count
            BackupPath     = $backupPath
            VerifiedClean  = ($verify.Scanned -and $verify.Fixable -eq 0)
            Locked         = $locked
            Error          = ''
        }
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message "Attribute list repair failed on ${label}: $($_.Exception.Message)"
        if ($backupPath) { Add-OfflineRepairLog -Level Warning -Message "The pre-repair image is available at $backupPath" }
        return (& $failure "$($_.Exception.Message)")
    }
    finally {
        if ($handle -and -not $handle.IsClosed) {
            if ($locked -and -not $isDiskMode) { try { [OfflineNtfsRawVolumeIo]::UnlockVolume($handle) } catch { } }
            $handle.Close()
        }
        if ($volumeLockHandle -and -not $volumeLockHandle.IsClosed) {
            try { [OfflineNtfsRawVolumeIo]::UnlockVolume($volumeLockHandle) } catch { }
            $volumeLockHandle.Close()
        }
    }
}

function Test-NtfsPartitionSignature {
    # Reads a partition's boot sector straight off the physical disk and checks the
    # NTFS OEM id. This is deliberately not Get-Volume: the corruption this script
    # repairs stops the volume mounting, and an unmounted volume reports its file
    # system as Unknown or RAW, which would hide exactly the disks that need help.
    param(
        [Parameter(Mandatory)][int]$DiskNumber,
        [Parameter(Mandatory)][long]$PartitionOffset
    )
    $handle = $null
    try {
        $handle = [OfflineNtfsRawVolumeIo]::OpenVolume("\\.\PhysicalDrive$DiskNumber", $false)
        $sector = [OfflineNtfsRawVolumeIo]::Read($handle, $PartitionOffset, 4096)
        return ([System.Text.Encoding]::ASCII.GetString($sector, 3, 8) -eq 'NTFS    ')
    }
    catch { return $false }
    finally { if ($handle -and -not $handle.IsClosed) { $handle.Close() } }
}

function Get-NtfsRescueDiskNumber {
    # The rescue VM's own OS disk. Fails closed: without it the rescue disk cannot be
    # told apart from the disks this script is allowed to write.
    try { return [int](Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop).DiskNumber }
    catch { throw "Could not determine the rescue VM's own system disk number, so it cannot be excluded from the scan: $($_.Exception.Message)" }
}

function Get-NtfsCandidateDiskNumber {
    # Disks the raw scan may look at when no offline Windows installation was found.
    # The same filter Get-OfflineWindowsDisk applies: a data disk on a virtual bus,
    # online and writable, never the rescue VM's boot/system disk and never the
    # temporary storage disk. Nothing here brings a disk online.
    param([Parameter(Mandatory)][int]$RescueDiskNumber)
    return @(Get-Disk -ErrorAction Stop | Where-Object {
            $_.BusType -in @('SCSI', 'SAS', 'RAID', 'NVMe', 'File Backed Virtual') -and
            $_.Number -ne $RescueDiskNumber -and
            -not ($_.IsOffline -or $_.IsReadOnly) -and
            -not ($_.IsBoot -or $_.IsSystem) -and
            -not (Test-TemporaryStorageDisk -Disk $_)
        } | ForEach-Object { [int]$_.Number })
}

function ConvertTo-NtfsRequestedVolume {
    # 'F', 'F:', 'F:\' and ' f:\ ' all mean drive F.
    param([string]$Volume)
    if ([string]::IsNullOrWhiteSpace($Volume)) { return '' }
    return $Volume.Trim().TrimEnd('\', ':').ToUpperInvariant()
}

function Get-NtfsScanTarget {
    # Every NTFS partition on the attached disk(s), whether or not Windows will
    # mount it, or just the one the caller asked for.
    #
    # Two access modes are produced:
    #   volume mode - the partition is mounted and has a usable root, so it is
    #                 addressed as \\.\X: and is locked and dismounted before any
    #                 write, which is what evicts the file system cache.
    #   disk mode   - the partition will not mount, so it is addressed through
    #                 \\.\PhysicalDriveN with the partition offset as a base. The
    #                 partition's volume device (VolumeGuidPath) is locked and
    #                 dismounted while it is written.
    #
    # Drive letters are read from Get-OfflineWindowsDisk's PartitionRoots map when
    # it is available, because EFI System and Recovery partitions are mounted with
    # Add-PartitionAccessPath and Get-Partition never reports a letter for those.
    param(
        $Offline = $null,
        [string]$RequestedVolume = ''
    )

    Initialize-NtfsRawVolumeIo

    $rescueDisk = Get-NtfsRescueDiskNumber
    if ($Offline) { $diskNumbers = @([int]$Offline.DiskNumber) }
    else { $diskNumbers = @(Get-NtfsCandidateDiskNumber -RescueDiskNumber $rescueDisk) }

    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($diskNumber in ($diskNumbers | Sort-Object -Unique)) {
        if ($diskNumber -eq $rescueDisk) { continue }

        $disk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
        $identity = if ($disk) {
            [ordered]@{
                Number         = $diskNumber
                UniqueId       = "$($disk.UniqueId)"
                SerialNumber   = "$($disk.SerialNumber)".Trim()
                Guid           = "$($disk.Guid)"
                Signature      = $disk.Signature
                PartitionStyle = "$($disk.PartitionStyle)"
                Size           = $disk.Size
            }
        }
        else { [ordered]@{ Number = $diskNumber } }

        $partitions = @()
        try { $partitions = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop) } catch { continue }

        foreach ($partition in ($partitions | Sort-Object PartitionNumber)) {
            if ("$($partition.Type)" -eq 'Reserved') { continue }
            if ($partition.Size -lt 1MB) { continue }

            if (-not (Test-NtfsPartitionSignature -DiskNumber $diskNumber -PartitionOffset ([long]$partition.Offset))) {
                Add-OfflineRepairLog -Message "Disk $diskNumber partition $($partition.PartitionNumber): skipped, no NTFS signature in its boot sector."
                continue
            }

            # Prefer a mounted root, so the write path can take a volume lock.
            $letter = ''
            if ($Offline -and $Offline.PartitionRoots) {
                $root = @($Offline.PartitionRoots["$diskNumber-$($partition.PartitionNumber)"]) |
                    Where-Object { $_ -match '^[A-Za-z]:' } | Select-Object -First 1
                if ($root) { $letter = ConvertTo-NtfsRequestedVolume -Volume "$root" }
            }
            if (-not $letter) {
                $access = @($partition.AccessPaths) | Where-Object { $_ -match '^[A-Za-z]:' } | Select-Object -First 1
                if ($access) { $letter = ConvertTo-NtfsRequestedVolume -Volume "$access" }
            }
            $volumeGuidPath = @($partition.AccessPaths) | Where-Object { $_ -match '^\\\\\?\\Volume\{' } | Select-Object -First 1
            $volumeGuidPath = if ($volumeGuidPath) { "$volumeGuidPath".TrimEnd('\') } else { '' }

            $mounted = ($letter -and (Test-OfflinePath "${letter}:\"))

            $targets.Add([PSCustomObject]@{
                DiskNumber      = $diskNumber
                PartitionNumber = $partition.PartitionNumber
                Letter          = $letter
                Mounted         = [bool]$mounted
                DevicePath      = $(if ($mounted) { "\\.\${letter}:" } else { "\\.\PhysicalDrive$diskNumber" })
                BaseOffset      = $(if ($mounted) { [long]0 } else { [long]$partition.Offset })
                VolumeGuidPath  = $volumeGuidPath
                DiskIdentity    = $identity
                Label           = $(if ($mounted) { "${letter}:" } else { "disk $diskNumber partition $($partition.PartitionNumber)" })
            })
        }
    }

    if ($RequestedVolume) {
        $requested = ConvertTo-NtfsRequestedVolume -Volume $RequestedVolume
        $match = @($targets | Where-Object { $_.Letter -eq $requested })
        if ($match.Count -eq 0) {
            throw "Volume ${requested}: is not an NTFS partition on the attached disk(s). Found: $(@($targets.Label) -join ', ')"
        }
        return $match
    }

    return @($targets)
}
function Invoke-WithNtfsTarget {
    # Runs a scriptblock with the raw I/O base offset set for this target, and
    # always clears it afterwards. Every offset inside the NTFS functions is
    # volume relative; the base offset is what redirects them at a partition when
    # the volume itself cannot be opened.
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][scriptblock]$Body
    )
    $script:NtfsIoBaseOffset = [long]$Target.BaseOffset
    try { & $Body }
    finally { $script:NtfsIoBaseOffset = [long]0 }
}

function Write-NtfsFinding {
    # Bounded stdout summary: one line per affected record, detail goes to the log file.
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$LogFile
    )

    foreach ($record in $State.Records) {
        $fixable = @($record.Entries | Where-Object { $_.CanRepair })
        $blocked = @($record.Entries | Where-Object { -not $_.CanRepair })
        $residency = if ($record.IsResident) { 'resident' } else { 'non-resident' }

        if ($fixable.Count -gt 0) {
            Log-Warning "$Label FRN $($record.Frn) $($record.Name) ($residency): $($fixable.Count) attribute list entry/entries use name offset 0x1c instead of 0x1a." | Tee-Object -FilePath $LogFile -Append
            foreach ($entry in $fixable) {
                Write-NtfsDetail -Message "$Label FRN $($record.Frn) +0x$('{0:x}' -f $entry.EntryOffset) $($entry.TypeName) name '$($entry.Name)' NameOffset 0x$('{0:x2}' -f $entry.NameOffset) -> 0x1a"
            }
        }
        if ($blocked.Count -gt 0) {
            Log-Warning "$Label FRN $($record.Frn) $($record.Name): $($blocked.Count) entry/entries have a name offset this script will not correct. They are reported only." | Tee-Object -FilePath $LogFile -Append
            foreach ($entry in $blocked) {
                Write-NtfsDetail -Message "$Label FRN $($record.Frn) +0x$('{0:x}' -f $entry.EntryOffset) $($entry.TypeName) name '$($entry.Name)' NameOffset 0x$('{0:x2}' -f $entry.NameOffset), length $($entry.NameLength) - left alone"
            }
        }
    }

    $inconclusive = @($State.Inconclusive)
    if ($inconclusive.Count -gt 0) {
        $shown = @($inconclusive | Select-Object -First 3 | ForEach-Object { "FRN $($_.Frn) $($_.Name) ($($_.Reason))" }) -join '; '
        $more = if ($inconclusive.Count -gt 3) { "; and $($inconclusive.Count - 3) more in the detail log" } else { '' }
        Log-Warning "$Label`: $($inconclusive.Count) reserved file record(s) could not be checked: $shown$more." | Tee-Object -FilePath $LogFile -Append
        foreach ($item in $inconclusive) { Write-NtfsDetail -Message "$Label FRN $($item.Frn) $($item.Name): not checked - $($item.Reason)" }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $LogFile -Append
}

function Test-NtfsNoWindowsInstallError {
    # True only for Get-OfflineWindowsDisk's "no installation found" outcome. That is
    # thrown after the helper has brought its filtered disks online and assigned
    # drive letters, and it is the expected symptom of this corruption, because the
    # Windows volume will not mount. Every other failure - the rescue disk could not
    # be identified, a nested guest is still active, no data disk is attached - is a
    # refusal that must stop the run.
    param([string]$Message)
    return ("$Message" -like 'No offline Windows installation was found*')
}

function Get-NtfsScanOutcome {
    # What the scan has shown. Only a complete scan of at least one partition, with
    # every reserved record read and parsed, can report a disk as healthy.
    param(
        [int]$TargetCount,
        [int]$UnscannedCount,
        [int]$InconclusiveCount,
        [int]$Fixable,
        [int]$Unfixable
    )
    if ($TargetCount -le 0) { return 'NoTargets' }
    if ($Fixable -gt 0) { return 'Fixable' }
    if ($UnscannedCount -gt 0 -or $InconclusiveCount -gt 0) { return 'Inconclusive' }
    if ($Unfixable -gt 0) { return 'UnfixableOnly' }
    return 'Healthy'
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

$status = $STATUS_ERROR
try {
    :Main do {
        . .\src\windows\common\helpers\OfflineRepairCommon.ps1
        . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1

        $script:NtfsDetailLog = $logFile
        $volume = ConvertTo-NtfsRequestedVolume -Volume $volume

        # The offline Windows installation is useful context, but it is not required.
        # A volume carrying this corruption does not mount, so insisting on finding
        # \Windows would refuse to run on precisely the disks this script is for.
        # Only that outcome falls back to a raw scan; any refusal stops the run.
        $offline = $null
        try {
            $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
        }
        catch {
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            if (-not (Test-NtfsNoWindowsInstallError -Message $_.Exception.Message)) {
                Log-Error "Offline disk discovery refused to continue: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
                Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
                break Main
            }
            Log-Warning "No offline Windows installation could be identified: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
            Log-Info 'That is the expected symptom of this corruption, because the volume will not mount. Continuing with a raw scan of every NTFS partition on the attached data disk(s).' | Tee-Object -FilePath $logFile -Append
        }

        $targets = @(Get-NtfsScanTarget -Offline $offline -RequestedVolume $volume)
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($targets.Count -gt 0) {
            Log-Info "Scanning the reserved file records (FRN 0-$script:NtfsAttrListMaxFrn) of: $(@($targets | ForEach-Object { "$($_.Label)$(if (-not $_.Mounted) { ' [unmounted, raw]' })" }) -join ', ')" | Tee-Object -FilePath $logFile -Append
        }

        # Phase 1: detect.
        $scans = [System.Collections.Generic.List[PSCustomObject]]::new()
        $unscanned = 0
        foreach ($target in $targets) {
            $state = Invoke-WithNtfsTarget -Target $target -Body { Get-NtfsMetafileAttrListState -Volume $target.DevicePath }
            if (-not $state.Scanned) {
                Log-Warning "$($target.Label) could not be scanned: $($state.Error)" | Tee-Object -FilePath $logFile -Append
                $unscanned++
                continue
            }
            Log-Info "$($target.Label): scanned. $($state.Fixable) correctable entry/entries, $($state.Unfixable) reported only, $(@($state.Inconclusive).Count) record(s) not checked." | Tee-Object -FilePath $logFile -Append
            Write-NtfsFinding -State $state -Label $target.Label -LogFile $logFile
            $scans.Add([PSCustomObject]@{ Target = $target; State = $state }) | Out-Null
        }

        $totalFixable = [int](($scans | ForEach-Object { $_.State.Fixable } | Measure-Object -Sum).Sum)
        $totalUnfixable = [int](($scans | ForEach-Object { $_.State.Unfixable } | Measure-Object -Sum).Sum)
        $totalInconclusive = [int](($scans | ForEach-Object { @($_.State.Inconclusive).Count } | Measure-Object -Sum).Sum)
        $incomplete = ($unscanned -gt 0 -or $totalInconclusive -gt 0)
        $incompleteText = "$unscanned partition(s) could not be scanned and $totalInconclusive reserved file record(s) could not be checked"

        # Phase 2: decide.
        $outcome = Get-NtfsScanOutcome -TargetCount $targets.Count -UnscannedCount $unscanned -InconclusiveCount $totalInconclusive -Fixable $totalFixable -Unfixable $totalUnfixable
        switch ($outcome) {
            'NoTargets' {
                Log-Error 'No NTFS partition was found on the attached data disk(s), so the scan could not run. Confirm the broken OS disk is attached to the rescue VM and online.' | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
            }
            'Inconclusive' {
                Log-Error "The scan is inconclusive: $incompleteText. No correctable entry was found in what could be read, but this does not show the disk is free of the 0x24 attribute list problem. No changes were made; see the detail log." | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
            }
            'UnfixableOnly' {
                Log-Warning "$totalUnfixable attribute list entry/entries have a name offset that is neither the canonical 0x1a nor the 0x1c value this script corrects. They were left untouched, because changing them without knowing what wrote them risks losing the streams they point at. See the detail log." | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_SUCCESS
            }
            'Healthy' {
                Log-Output "Every NTFS metafile attribute list entry on $($scans.Count) partition(s) already uses the canonical name offset 0x1a. This disk does not have the 0x24 attribute list problem, and no changes were made." | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_SUCCESS
            }
        }
        if ($outcome -ne 'Fixable') {
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            break Main
        }

        if ($isDetectOnly) {
            foreach ($scan in ($scans | Where-Object { $_.State.Fixable -gt 0 })) {
                Log-Output "  $($scan.Target.Label): $($scan.State.Fixable) entry/entries in $(@($scan.State.Records | Where-Object { @($_.Entries | Where-Object { $_.CanRepair }).Count -gt 0 } | ForEach-Object { "FRN $($_.Frn) $($_.Name)" }) -join ', ')" | Tee-Object -FilePath $logFile -Append
            }
            if ($incomplete) {
                Log-Error "The scan is incomplete: $incompleteText." | Tee-Object -FilePath $logFile -Append
            }
            # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
            # so a summary printed first is the first thing a long run loses.
            Log-Output "Detect only: $totalFixable correctable entry/entries on $(@($scans | Where-Object { $_.State.Fixable -gt 0 }).Count) partition(s). No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $(if ($incomplete) { $STATUS_ERROR } else { $STATUS_SUCCESS })
            break Main
        }

        # Phase 3: repair. Only partitions with a correctable entry are touched.
        Log-Info 'Repairing. Each target is locked, re-scanned through the handle it writes with, and the original bytes of every region are saved and read back before the first write.' | Tee-Object -FilePath $logFile -Append

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($scan in ($scans | Where-Object { $_.State.Fixable -gt 0 })) {
            $target = $scan.Target
            $result = Invoke-WithNtfsTarget -Target $target -Body { Repair-NtfsAttrListVolume -Volume $target.DevicePath -Target $target }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            $results.Add([PSCustomObject]@{ Target = $target; Result = $result }) | Out-Null

            if ($result.Error) {
                Log-Error "$($target.Label) repair failed: $($result.Error)" | Tee-Object -FilePath $logFile -Append
            }
            else {
                Log-Info "$($target.Label): repaired $($result.Repaired) entry/entries across $($result.RegionsWritten) region(s)." | Tee-Object -FilePath $logFile -Append
            }
        }

        # Phase 4: verify with a fresh handle, and report whether the volume mounts again.
        $stillBroken = 0
        foreach ($item in $results) {
            $target = $item.Target
            if ($item.Result.Error -and -not $item.Result.BackupPath) { continue }
            $recheck = Invoke-WithNtfsTarget -Target $target -Body { Get-NtfsMetafileAttrListState -Volume $target.DevicePath }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

            if (-not $recheck.Scanned) {
                Log-Warning "$($target.Label): the verification scan could not run: $($recheck.Error)" | Tee-Object -FilePath $logFile -Append
                $stillBroken++
                continue
            }
            if ($recheck.Fixable -gt 0) {
                Log-Warning "$($target.Label): $($recheck.Fixable) correctable entry/entries are still present after the repair." | Tee-Object -FilePath $logFile -Append
                $stillBroken++
                continue
            }

            Log-Info "$($target.Label): verified with a fresh handle, every correctable attribute list entry now uses the canonical name offset 0x1a." | Tee-Object -FilePath $logFile -Append

            # A partition that was unmountable before the repair may mount now.
            if (-not $target.Mounted) {
                try {
                    $null = Update-HostStorageCache -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    $partition = Get-Partition -DiskNumber $target.DiskNumber -PartitionNumber $target.PartitionNumber -ErrorAction Stop
                    $fs = (Get-Volume -Partition $partition -ErrorAction Stop).FileSystemType
                    if ("$fs" -eq 'NTFS') { Log-Info "$($target.Label): the volume is recognised as NTFS again." | Tee-Object -FilePath $logFile -Append }
                    else { Log-Info "$($target.Label): Windows still reports '$fs'. The volume may only remount after the disk is re-attached or the VM restarts; if it still does not mount then, another fault remains." | Tee-Object -FilePath $logFile -Append }
                }
                catch {
                    Log-Warning "$($target.Label): could not re-check the file system after the repair: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
                }
            }
        }

        $repairedTotal = [int](($results | ForEach-Object { $_.Result.Repaired } | Measure-Object -Sum).Sum)
        $failed = @($results | Where-Object { $_.Result.Error })
        $manifests = @($results | Where-Object { $_.Result.BackupPath } | ForEach-Object { $_.Result.BackupPath })

        if ($totalUnfixable -gt 0) {
            Log-Warning "$totalUnfixable entry/entries with a different non-canonical name offset were deliberately left untouched. See the detail log." | Tee-Object -FilePath $logFile -Append
        }
        if ($failed.Count -gt 0 -or $stillBroken -gt 0) {
            Log-Error "Repaired $repairedTotal entry/entries, but $($failed.Count) target(s) failed and $stillBroken still report a non-canonical name offset. Do not start the VM yet: review the detail log." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
        }
        elseif ($incomplete) {
            Log-Error "Corrected and verified $repairedTotal entry/entries, but the scan was incomplete: $incompleteText. The disk may still carry the problem there; see the detail log." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
        }
        else {
            Log-Output "Corrected $repairedTotal NTFS attribute list entry/entries on $($results.Count) partition(s) and verified the result." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
        }
        foreach ($manifest in $manifests) {
            Log-Output "Restore manifest (pre-repair bytes; copy it off the rescue VM): $manifest" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    } while ($false)
}
catch {
    $status = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
}
finally {
    # A dependency may have failed to load before these functions became available.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        try {
            Clear-OfflineDriveLetter
            if (@(Get-OfflineAssignedDriveLetter).Count -gt 0) {
                $status = $STATUS_ERROR
                Add-OfflineRepairLog -Level Error -Message 'Temporary drive letters remain assigned. The scan or repair may have completed, but cleanup is incomplete; inspect the cleanup diagnostics before proceeding.'
            }
        }
        catch {
            $status = $STATUS_ERROR
            Add-OfflineRepairLog -Level Error -Message "Drive-letter cleanup failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        try {
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append -ErrorAction Stop
        }
        catch {
            $status = $STATUS_ERROR
            Log-Error "Final helper diagnostics could not be written to the detail log: $($_.Exception.Message)"
        }
    }
}
return $status