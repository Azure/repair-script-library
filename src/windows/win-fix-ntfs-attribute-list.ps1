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
#     1. Scans the reserved file records (FRN 0 to 31, the NTFS metafiles) of every NTFS volume on
#        the attached disk, applying the update sequence array fixup so the records read exactly as
#        NTFS sees them.
#     2. Reports every attribute list entry whose name offset is not 0x1a, split into entries that
#        can be corrected (exactly 0x1c, with a name that still fits at 0x1a) and entries it will
#        not touch.
#     3. Repairs only the correctable entries. The volume is locked and dismounted first, then
#        re-scanned through the same handle, so the repair acts on the bytes it validated rather
#        than on a stale read.
#     4. Writes a restore manifest containing the original bytes of every region it is about to
#        change, and refuses to write at all if that manifest cannot be saved.
#     5. Verifies through the same locked handle before releasing the volume.
#
#   Nothing is written when no correctable entry is found, so a healthy disk is left untouched.
#
# .RESOLVES
#   Stop error 0x24 NTFS_FILE_SYSTEM boot loops caused by a non-canonical attribute list name
#   offset in an NTFS metafile, typically appearing after a servicing operation.
#
# .PARAMETER detectOnly
#   "true" to scan and report without writing anything. Defaults to "false".
#
# .PARAMETER volume
#   Restrict the scan to a single volume, for example "F". Defaults to every NTFS volume on the
#   attached disk.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when automatic
#   detection picks the wrong volume.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-ntfs-attribute-list --parameters detectOnly=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   This script writes directly to the volume. It only ever changes the single name offset byte of
#   an attribute list entry that is exactly 0x1c and whose name still fits at 0x1a, and it captures
#   the original bytes of every region first. The restore manifest is written next to the detail log
#   on the rescue VM's public desktop; copy it off the rescue VM before deleting it.
#
#   The volume is locked and dismounted for the repair. Make sure no offline registry hive is still
#   mounted from the disk, or the lock will be refused and nothing will be written.
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
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1

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
    param([byte[]]$Record, [int]$StartOffset)
    $runs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lcn = [long]0
    $pos = $StartOffset
    while ($pos -lt $Record.Length) {
        $header = $Record[$pos]
        if ($header -eq 0) { break }
        $pos++
        $lengthSize = $header -band 0x0F
        $offsetSize = ($header -shr 4) -band 0x0F
        if ($lengthSize -eq 0 -or ($pos + $lengthSize + $offsetSize) -gt $Record.Length) { break }

        [long]$runLength = 0
        for ($i = 0; $i -lt $lengthSize; $i++) { $runLength = $runLength -bor ([long]$Record[$pos + $i] -shl ($i * 8)) }
        $pos += $lengthSize

        if ($offsetSize -gt 0) {
            [long]$runOffset = 0
            for ($i = 0; $i -lt $offsetSize; $i++) { $runOffset = $runOffset -bor ([long]$Record[$pos + $i] -shl ($i * 8)) }
            # Sign-extend the delta: run offsets are signed and may move backwards.
            if ($Record[$pos + $offsetSize - 1] -band 0x80) {
                for ($i = $offsetSize; $i -lt 8; $i++) { $runOffset = $runOffset -bor ([long]0xFF -shl ($i * 8)) }
            }
            $pos += $offsetSize
            $lcn += $runOffset
        }
        if ($runLength -le 0) { break }
        $runs.Add([PSCustomObject]@{ Lcn = $lcn; Clusters = $runLength })
    }
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

function Resolve-NtfsUsaFixup {
    # Applies the update-sequence-array fixup in place (on-disk -> in-memory).
    # Returns $false when the record's sector tails do not carry the expected
    # update sequence number, which means the record is not safe to interpret.
    param([byte[]]$Record, [int]$BytesPerSector)
    $usaOffset = Get-NtfsLeUInt16 $Record 4
    $usaCount = Get-NtfsLeUInt16 $Record 6
    if ($usaCount -lt 1 -or ($usaOffset + $usaCount * 2) -gt $Record.Length) { return $false }
    $usn = Get-NtfsLeUInt16 $Record $usaOffset
    for ($i = 1; $i -lt $usaCount; $i++) {
        $sectorEnd = $i * $BytesPerSector - 2
        if (($sectorEnd + 2) -gt $Record.Length) { return $false }
        if ((Get-NtfsLeUInt16 $Record $sectorEnd) -ne $usn) { return $false }
        $stored = Get-NtfsLeUInt16 $Record ($usaOffset + $i * 2)
        $Record[$sectorEnd] = [byte]($stored -band 0xFF)
        $Record[$sectorEnd + 1] = [byte](($stored -shr 8) -band 0xFF)
    }
    return $true
}

function Set-NtfsUsaFixup {
    # Re-applies the update-sequence-array fixup in place (in-memory -> on-disk).
    # Exact inverse of Resolve-NtfsUsaFixup, so a record can be patched in its
    # readable form and written back without corrupting the sector tails.
    param([byte[]]$Record, [int]$BytesPerSector)
    $usaOffset = Get-NtfsLeUInt16 $Record 4
    $usaCount = Get-NtfsLeUInt16 $Record 6
    $usn = Get-NtfsLeUInt16 $Record $usaOffset
    for ($i = 1; $i -lt $usaCount; $i++) {
        $sectorEnd = $i * $BytesPerSector - 2
        $real = Get-NtfsLeUInt16 $Record $sectorEnd
        $Record[$usaOffset + $i * 2] = [byte]($real -band 0xFF)
        $Record[$usaOffset + $i * 2 + 1] = [byte](($real -shr 8) -band 0xFF)
        $Record[$sectorEnd] = [byte]($usn -band 0xFF)
        $Record[$sectorEnd + 1] = [byte](($usn -shr 8) -band 0xFF)
    }
}

function Get-NtfsAttributeListLocation {
    # Locates the $ATTRIBUTE_LIST attribute inside a fixed-up file record and
    # describes where its value lives (inside the record, or in disk runs).
    param(
        [byte[]]$FileRecord,
        [long]$FileRecordOffset,
        [int]$ClusterSize
    )
    $pos = Get-NtfsLeUInt16 $FileRecord 0x14
    while (($pos + 8) -le $FileRecord.Length) {
        $typeCode = Get-NtfsLeUInt32 $FileRecord $pos
        # Compare against [uint32]::MaxValue: the literal 0xFFFFFFFF parses as
        # Int32 -1, which never equals an unsigned type code.
        if ($typeCode -eq [uint32]::MaxValue) { break }
        $recordLength = Get-NtfsLeUInt32 $FileRecord ($pos + 4)
        if ($recordLength -lt 16 -or ($pos + $recordLength) -gt $FileRecord.Length) { break }

        if ($typeCode -eq 0x20) {
            $isResident = ($FileRecord[$pos + 8] -eq 0)
            if ($isResident) {
                $valueLength = Get-NtfsLeUInt32 $FileRecord ($pos + 0x10)
                $valueOffset = Get-NtfsLeUInt16 $FileRecord ($pos + 0x14)
                if (($pos + $valueOffset + $valueLength) -gt $FileRecord.Length) { return $null }
                return [PSCustomObject]@{
                    IsResident       = $true
                    DataSize         = [int]$valueLength
                    RecordValueStart = [int]($pos + $valueOffset)
                    Runs             = @()
                }
            }
            $mappingOffset = Get-NtfsLeUInt16 $FileRecord ($pos + 0x20)
            $dataSize = Get-NtfsLeUInt64 $FileRecord ($pos + 0x30)
            $runs = @(Convert-NtfsMappingPairs -Record $FileRecord -StartOffset ($pos + $mappingOffset))
            if ($runs.Count -eq 0) { return $null }
            return [PSCustomObject]@{
                IsResident       = $false
                DataSize         = [int]$dataSize
                RecordValueStart = -1
                Runs             = $runs
            }
        }
        $pos += $recordLength
    }
    return $null
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
    param(
        [Parameter(Mandatory)][string]$Volume,
        $Handle = $null
    )

    Initialize-NtfsRawVolumeIo
    $volumePath = ConvertTo-NtfsVolumePath -Volume $Volume
    $result = [PSCustomObject]@{
        Volume     = $volumePath
        Label      = ($volumePath -replace '^\\\\[.?]\\', '')
        Scanned    = $false
        Geometry   = $null
        Records    = @()
        Fixable    = 0
        Unfixable  = 0
        Error      = ''
    }

    $ownsHandle = ($null -eq $Handle)
    $handle = $Handle
    try {
        if ($ownsHandle) { $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($volumePath, $false) }
        $geometry = Get-NtfsVolumeGeometry -Handle $handle
        $result.Geometry = $geometry
        $records = [System.Collections.Generic.List[PSCustomObject]]::new()

        for ($frn = 0; $frn -le $script:NtfsAttrListMaxFrn; $frn++) {
            $recordOffset = [long]$geometry.MftLcn * $geometry.ClusterSize + $frn * $geometry.RecordSize
            $record = Read-NtfsVolumeAligned -Handle $handle -Offset $recordOffset -Size $geometry.RecordSize -BytesPerSector $geometry.BytesPerSector

            if ([System.Text.Encoding]::ASCII.GetString($record, 0, 4) -ne 'FILE') { continue }
            $flags = Get-NtfsLeUInt16 $record 0x16
            if (($flags -band 0x01) -eq 0) { continue }
            if (-not (Resolve-NtfsUsaFixup -Record $record -BytesPerSector $geometry.BytesPerSector)) { continue }

            $location = Get-NtfsAttributeListLocation -FileRecord $record -FileRecordOffset $recordOffset -ClusterSize $geometry.ClusterSize
            if ($null -eq $location) { continue }

            # Materialise the attribute-list bytes. Resident lists come from the
            # fixed-up record; non-resident lists are read from their runs, whole
            # runs at a time so the write-back path stays cluster-aligned.
            $listBytes = $null
            if ($location.IsResident) {
                $listBytes = New-Object byte[] $location.DataSize
                [Array]::Copy($record, $location.RecordValueStart, $listBytes, 0, $location.DataSize)
            }
            else {
                $allocated = 0
                foreach ($run in $location.Runs) { $allocated += [int]($run.Clusters * $geometry.ClusterSize) }
                if ($allocated -lt $location.DataSize) { continue }
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

function Repair-NtfsAttrListVolume {
    # Applies the canonical name offset to one volume. A mounted volume is locked
    # and dismounted first, then re-scanned through the same handle so the repair
    # acts on exactly the bytes it validated. Every region is captured to a
    # restore manifest before the first write.
    #
    # When the volume will not mount, which is the usual state for the corruption
    # this script repairs, the caller passes a physical disk device path and sets
    # $script:NtfsIoBaseOffset to the partition offset. There is no volume to lock
    # in that case, and nothing is holding the region either, so the lock is
    # skipped rather than treated as a failure.
    param([Parameter(Mandatory)][string]$Volume)

    $volumePath = ConvertTo-NtfsVolumePath -Volume $Volume
    $label = $volumePath -replace '^\\\\[.?]\\', ''
    $isDiskMode = ($volumePath -match '(?i)PhysicalDrive\d+$')
    $handle = $null
    $locked = $false
    $repaired = 0
    $backupPath = ''

    try {
        try {
            $handle = [OfflineNtfsRawVolumeIo]::OpenVolume($volumePath, $true)
            if (-not $isDiskMode) {
                [OfflineNtfsRawVolumeIo]::LockVolume($handle)
                $locked = $true
                [OfflineNtfsRawVolumeIo]::DismountVolume($handle)
            }
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "$label could not be locked for exclusive access: $($_.Exception.Message)"
            Add-OfflineRepairLog -Level Warning -Message "Close any open handle to $label, and make sure no offline registry hive is still mounted from it, before retrying."
            return [PSCustomObject]@{ Volume = $volumePath; Repaired = 0; RegionsWritten = 0; BackupPath = ''; VerifiedClean = $false; Locked = $false; Error = "could not lock $label" }
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
                if (-not (Resolve-NtfsUsaFixup -Record $frs -BytesPerSector $geometry.BytesPerSector)) {
                    Add-OfflineRepairLog -Level Warning -Message "  $label $($record.Name): update sequence check failed on re-read; skipped."
                    continue
                }
                foreach ($entry in $fixable) {
                    Set-NtfsAttrListEntryNameOffset -Buffer $frs -EntryStart ($record.RecordValueStart + $entry.EntryOffset) -NameLength $entry.NameLength
                }
                # Restore the sector tails so the record is written back in on-disk form.
                Set-NtfsUsaFixup -Record $frs -BytesPerSector $geometry.BytesPerSector
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
                $name = if ($entry.Name) { "$($entry.TypeName):$($entry.Name)" } else { $entry.TypeName }
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
            $backupDir = $script:OfflineNtfsBackupDir
            if (-not (Test-Path $backupDir)) { $null = New-Item -Path $backupDir -ItemType Directory -Force }
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $safeLabel = $label -replace '[^A-Za-z0-9]', ''
            $backupPath = Join-Path $backupDir "win-fix-ntfs-attribute-list_${safeLabel}_${stamp}.json"
            $manifest = [ordered]@{
                Volume         = $volumePath
                CapturedUtc    = (Get-Date).ToUniversalTime().ToString('o')
                BytesPerSector = $geometry.BytesPerSector
                Regions        = @($operations | ForEach-Object {
                        [ordered]@{ Offset = $_.Offset; Length = $_.Original.Length; OriginalBase64 = [Convert]::ToBase64String($_.Original) }
                    })
            }
            $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $backupPath -Encoding UTF8
            Add-OfflineRepairLog -Message "  Saved pre-repair image of $($operations.Count) region(s) to $backupPath"
        }
        catch {
            throw "Refusing to write: the pre-repair backup could not be saved ($($_.Exception.Message))."
        }

        # Pass 2: apply.
        foreach ($operation in $operations) {
            Write-NtfsVolumeAligned -Handle $handle -Offset $operation.Offset -Data $operation.Updated -BytesPerSector $geometry.BytesPerSector
        }
        [OfflineNtfsRawVolumeIo]::Flush($handle)

        # Verify through the same locked handle before releasing the volume.
        $verify = Get-NtfsMetafileAttrListState -Volume $volumePath -Handle $handle
        if (-not $verify.Scanned) {
            Add-OfflineRepairLog -Level Warning -Message "  ${label}: repair written but the verification pass could not run - $($verify.Error)"
        }
        elseif ($verify.Fixable -gt 0) {
            Add-OfflineRepairLog -Level Warning -Message "  ${label}: $($verify.Fixable) entry/entries still report a non-canonical name offset after the repair."
        }
        else {
            foreach ($item in $planned) {
                Add-OfflineRepairLog -Message "  [OK] $label $item  NameOffset 0x1c -> 0x1a"
            }
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
        Add-OfflineRepairLog -Level Error -Message "Attribute list repair failed on ${label}: $_"
        if ($backupPath) { Add-OfflineRepairLog -Level Warning -Message "The pre-repair image is available at $backupPath" }
        return [PSCustomObject]@{ Volume = $volumePath; Repaired = 0; RegionsWritten = 0; BackupPath = $backupPath; VerifiedClean = $false; Locked = $locked; Error = "$($_.Exception.Message)" }
    }
    finally {
        if ($handle -and -not $handle.IsClosed) {
            if ($locked) { try { [OfflineNtfsRawVolumeIo]::UnlockVolume($handle) } catch { } }
            $handle.Close()
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

function Get-NtfsScanTarget {
    # Every NTFS partition on the attached disk(s), whether or not Windows will
    # mount it, or just the one the caller asked for.
    #
    # Two access modes are produced:
    #   volume mode - the partition is mounted and has a usable root, so it is
    #                 addressed as \\.\X: and can be locked and dismounted before
    #                 any write, which is what evicts the file system cache.
    #   disk mode   - the partition will not mount, so it is addressed through
    #                 \\.\PhysicalDriveN with the partition offset as a base. There
    #                 is no mounted volume to lock, and Windows only blocks direct
    #                 disk writes to regions owned by a mounted volume, so this is
    #                 both necessary and safe.
    #
    # Drive letters are read from Get-OfflineWindowsDisk's PartitionRoots map when
    # it is available, because EFI System and Recovery partitions are mounted with
    # Add-PartitionAccessPath and Get-Partition never reports a letter for those.
    param(
        $Offline = $null,
        [string]$RequestedVolume = ''
    )

    Initialize-NtfsRawVolumeIo

    $rescueDisk = -1
    try { $rescueDisk = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':') -ErrorAction Stop).DiskNumber } catch { }

    $diskNumbers = @()
    if ($Offline) { $diskNumbers = @($Offline.DiskNumber) }
    else { $diskNumbers = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.Number -ne $rescueDisk } | ForEach-Object { $_.Number }) }

    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($diskNumber in ($diskNumbers | Sort-Object -Unique)) {
        if ($diskNumber -eq $rescueDisk) { continue }

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
                    Where-Object { $_ -match '^[A-Za-z]:$' } | Select-Object -First 1
                if ($root) { $letter = ("$root").TrimEnd(':').ToUpperInvariant() }
            }
            if (-not $letter) {
                $access = @($partition.AccessPaths) | Where-Object { $_ -match '^[A-Za-z]:' } | Select-Object -First 1
                if ($access) { $letter = ("$access").TrimEnd('\').TrimEnd(':').ToUpperInvariant() }
            }

            $mounted = ($letter -and (Test-OfflinePath "${letter}:\"))

            $targets.Add([PSCustomObject]@{
                DiskNumber      = $diskNumber
                PartitionNumber = $partition.PartitionNumber
                Letter          = $letter
                Mounted         = [bool]$mounted
                DevicePath      = $(if ($mounted) { "\\.\${letter}:" } else { "\\.\PhysicalDrive$diskNumber" })
                BaseOffset      = $(if ($mounted) { [long]0 } else { [long]$partition.Offset })
                Label           = $(if ($mounted) { "${letter}:" } else { "disk $diskNumber partition $($partition.PartitionNumber)" })
                IsWindows       = ($Offline -and $letter -and $letter -eq ("$($Offline.WindowsDrive)").TrimEnd(':').ToUpperInvariant())
            })
        }
    }

    if ($RequestedVolume) {
        $requested = $RequestedVolume.TrimEnd(':').ToUpperInvariant()
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

        if ($record.Malformed) {
            Log-Warning "$Label FRN $($record.Frn) $($record.Name): the attribute list is malformed and was not parsed to the end." | Tee-Object -FilePath $LogFile -Append
        }
        if ($fixable.Count -gt 0) {
            Log-Warning "$Label FRN $($record.Frn) $($record.Name) ($residency): $($fixable.Count) attribute list entry/entries use name offset 0x1c instead of 0x1a." | Tee-Object -FilePath $LogFile -Append
            foreach ($entry in $fixable) {
                Add-OfflineRepairLog -Message "    +0x$('{0:x}' -f $entry.EntryOffset) $($entry.TypeName) name '$($entry.Name)' NameOffset 0x$('{0:x2}' -f $entry.NameOffset) -> 0x1a"
            }
        }
        if ($blocked.Count -gt 0) {
            Log-Warning "$Label FRN $($record.Frn) $($record.Name): $($blocked.Count) entry/entries have a name offset this script will not correct. They are reported only." | Tee-Object -FilePath $LogFile -Append
            foreach ($entry in $blocked) {
                Add-OfflineRepairLog -Message "    +0x$('{0:x}' -f $entry.EntryOffset) $($entry.TypeName) name '$($entry.Name)' NameOffset 0x$('{0:x2}' -f $entry.NameOffset), length $($entry.NameLength) - left alone"
            }
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $LogFile -Append
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    # The offline Windows installation is useful context, but it is not required.
    # A volume carrying this corruption does not mount, so insisting on finding
    # \Windows would refuse to run on precisely the disks this script is for.
    $offline = $null
    try {
        $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    }
    catch {
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Warning "No offline Windows installation could be identified: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
        Log-Info 'That is the expected symptom of this corruption, because the volume will not mount. Continuing with a raw scan of every NTFS partition on the attached disk(s).' | Tee-Object -FilePath $logFile -Append

        foreach ($disk in @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsOffline })) {
            try {
                Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop
                Log-Info "Brought disk $($disk.Number) online for the raw scan." | Tee-Object -FilePath $logFile -Append
            }
            catch {
                # Not fatal - another disk may still carry the volume, so the loop continues. But it
                # must not be silent: a disk that stayed offline is the most likely reason the scan
                # below finds no NTFS partition, and without this the run reports "nothing to scan"
                # as a success while never having looked at the disk that mattered.
                Log-Warning "Could not bring disk $($disk.Number) online for the raw scan: $($_.Exception.Message). Any NTFS partition on that disk will not be scanned." | Tee-Object -FilePath $logFile -Append
            }
        }
    }

    $targets = @(Get-NtfsScanTarget -Offline $offline -RequestedVolume $volume)
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($targets.Count -eq 0) {
        Log-Warning 'No NTFS partition was found on the attached disk(s). Nothing to scan.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    Log-Info "Scanning the reserved file records (FRN 0-$script:NtfsAttrListMaxFrn) of: $(@($targets | ForEach-Object { "$($_.Label)$(if (-not $_.Mounted) { ' [unmounted, raw]' })" }) -join ', ')" | Tee-Object -FilePath $logFile -Append

    # Phase 1: detect.
    $scans = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($target in $targets) {
        $state = Invoke-WithNtfsTarget -Target $target -Body { Get-NtfsMetafileAttrListState -Volume $target.DevicePath }
        if (-not $state.Scanned) {
            Log-Warning "$($target.Label) could not be scanned: $($state.Error)" | Tee-Object -FilePath $logFile -Append
            continue
        }
        Log-Info "$($target.Label): scanned. $($state.Fixable) correctable entry/entries, $($state.Unfixable) reported only." | Tee-Object -FilePath $logFile -Append
        Write-NtfsFinding -State $state -Label $target.Label -LogFile $logFile
        $scans.Add([PSCustomObject]@{ Target = $target; State = $state }) | Out-Null
    }

    if ($scans.Count -eq 0) {
        Log-Error "None of the $($targets.Count) NTFS partition(s) could be scanned. See the detail log." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $totalFixable = ($scans | ForEach-Object { $_.State.Fixable } | Measure-Object -Sum).Sum
    $totalUnfixable = ($scans | ForEach-Object { $_.State.Unfixable } | Measure-Object -Sum).Sum

    # Phase 2: decide.
    if ($totalFixable -eq 0) {
        if ($totalUnfixable -gt 0) {
            Log-Warning "$totalUnfixable attribute list entry/entries have a name offset that is neither the canonical 0x1a nor the 0x1c value this script corrects. They were left untouched, because changing them without knowing what wrote them risks losing the streams they point at. See the detail log." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "Every NTFS metafile attribute list entry on $($scans.Count) partition(s) already uses the canonical name offset 0x1a. This disk does not have the 0x24 attribute list problem, and no changes were made." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        foreach ($scan in ($scans | Where-Object { $_.State.Fixable -gt 0 })) {
            Log-Output "  $($scan.Target.Label): $($scan.State.Fixable) entry/entries in $(@($scan.State.Records | Where-Object { @($_.Entries | Where-Object { $_.CanRepair }).Count -gt 0 } | ForEach-Object { "FRN $($_.Frn) $($_.Name)" }) -join ', ')" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: $totalFixable correctable entry/entries on $(@($scans | Where-Object { $_.State.Fixable -gt 0 }).Count) partition(s). No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Phase 3: repair. Only partitions with a correctable entry are touched.
    Log-Info 'Repairing. Each target is re-scanned through the same handle it writes with, and the original bytes of every region are saved before the first write.' | Tee-Object -FilePath $logFile -Append

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($scan in ($scans | Where-Object { $_.State.Fixable -gt 0 })) {
        $target = $scan.Target
        $result = Invoke-WithNtfsTarget -Target $target -Body { Repair-NtfsAttrListVolume -Volume $target.DevicePath }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $results.Add([PSCustomObject]@{ Target = $target; Result = $result }) | Out-Null

        if ($result.Error) {
            Log-Error "$($target.Label) repair failed: $($result.Error)" | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info "$($target.Label): repaired $($result.Repaired) entry/entries across $($result.RegionsWritten) region(s). Restore manifest: $($result.BackupPath)" | Tee-Object -FilePath $logFile -Append
        }
    }

    # Phase 4: verify with a fresh handle, and report whether the volume mounts again.
    $stillBroken = 0
    foreach ($item in $results) {
        $target = $item.Target
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

        Log-Info "$($target.Label): verified, every attribute list entry now uses the canonical name offset 0x1a." | Tee-Object -FilePath $logFile -Append

        # A partition that was unmountable before the repair should mount now.
        # That is the strongest available evidence that the volume is usable again.
        if (-not $target.Mounted) {
            try {
                $null = Update-HostStorageCache -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $partition = Get-Partition -DiskNumber $target.DiskNumber -PartitionNumber $target.PartitionNumber -ErrorAction Stop
                $fs = (Get-Volume -Partition $partition -ErrorAction Stop).FileSystemType
                if ("$fs" -eq 'NTFS') { Log-Info "$($target.Label): the volume is recognised as NTFS again." | Tee-Object -FilePath $logFile -Append }
                else { Log-Warning "$($target.Label): still reported as '$fs' rather than NTFS. The attribute list is correct, so any remaining fault is elsewhere." | Tee-Object -FilePath $logFile -Append }
            }
            catch {
                Log-Warning "$($target.Label): could not re-check the file system after the repair: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
            }
        }
    }

    $repairedTotal = ($results | ForEach-Object { $_.Result.Repaired } | Measure-Object -Sum).Sum
    $failed = @($results | Where-Object { $_.Result.Error })

    if ($failed.Count -gt 0 -or $stillBroken -gt 0) {
        Log-Error "Repaired $repairedTotal entry/entries, but $($failed.Count) target(s) failed and $stillBroken still report a non-canonical name offset. Do not start the VM yet: review the detail log." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "Corrected $repairedTotal NTFS attribute list entry/entries on $($results.Count) partition(s) and verified the result. Restore manifest(s): $(@($results | ForEach-Object { $_.Result.BackupPath }) -join ', ')" | Tee-Object -FilePath $logFile -Append
    if ($totalUnfixable -gt 0) {
        Log-Warning "$totalUnfixable entry/entries with a different non-canonical name offset were deliberately left untouched. See the detail log." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Error "$_" | Tee-Object -FilePath $logFile -Append
    throw $_
    return $STATUS_ERROR
}
