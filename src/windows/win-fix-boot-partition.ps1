#########################################################################################################
#
# .SYNOPSIS
#   Repairs the system partition of an offline Windows disk: the partition the firmware reads before
#   Windows exists, and the boot sectors inside it. Targets a damaged or missing system partition,
#   not the contents of the BCD store.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". It answers the
#   question "can the firmware reach a boot partition on this disk at all", which is the layer below
#   win-fix-bcd. If there is no system partition, or its boot sectors are damaged, no amount of BCD
#   repair helps, because the firmware never gets far enough to read the store.
#
#   The script repairs in two tiers, and which tier runs is decided by the evidence:
#
#     Tier 1, sectors. The system partition exists but the boot sectors are wrong: a missing 0x55AA
#     signature, zeroed bootstrap code, a stale BPB HiddenSectors field, or an Active flag that is
#     missing or set on more than one partition. Each is corrected on its own. This is Gen1/BIOS
#     only, because UEFI reads a file from a FAT32 partition and never executes a boot sector.
#
#     Tier 2, partition. There is no system partition on the disk at all, or the one that is there
#     holds no filesystem. A new one is created and populated with bcdboot. This is the second
#     choice: it writes to the partition table, which the sector tier never does.
#
#   Causes detected:
#     1. The disk carries no system partition at all, and the Windows partition is not itself
#        bootable. The firmware has nothing to start.
#     2. Gen2 only: the EFI System Partition exists but holds no recognisable filesystem, so the
#        firmware cannot read \EFI\Microsoft\Boot\bootmgfw.efi from it.
#     3. Gen1 only: MBR sector 0 has no 0x55AA boot signature, so the BIOS does not consider the
#        disk bootable.
#     4. Gen1 only: the MBR bootstrap code is zeroed, or is not a Windows bootstrap, so nothing
#        useful runs after the BIOS hands over.
#     5. Gen1 only: no partition is flagged Active, so the Windows MBR bootstrap has no volume boot
#        record to load.
#     6. Gen1 only: more than one partition is flagged Active. The bootstrap requires exactly one.
#     7. Gen1 only: the volume boot record has no 0x55AA signature.
#     8. Gen1 only: the volume boot record carries no bootstrap code, or carries the NT52 (NTLDR)
#        bootstrap on an installation that boots through BOOTMGR.
#     9. Gen1 only: the BPB HiddenSectors field does not equal the partition's start LBA. The
#        bootstrap adds this value to every relative read, so the BIOS reads the wrong absolute
#        sectors. Windows itself ignores the field, which is why chkdsk and sfc come back clean
#        and the volume mounts perfectly on a rescue VM.
#
#   Reported but never repaired here:
#     - BPB TotalSectors is larger than the partition that contains it. The filesystem believes it
#       is bigger than its container, which follows a bad resize. Correcting the boot sector would
#       hide a filesystem fault rather than fix it. Use win-fix-file-system.
#     - The boot partition holds no NTFS filesystem on Gen1. That is a filesystem fault, not a boot
#       sector fault.
#     - There is not enough unallocated space to create a system partition. Nothing is moved or
#       shrunk to make room, because that risks the data partition.
#     - The MBR bootstrap needs rebuilding but no healthy MBR disk is attached to this rescue VM to
#       copy a known good bootstrap from. Attach the disk to a Gen1 rescue VM and run this again.
#
#   Once the firmware can reach the partition again, the boot configuration inside it is a separate
#   question. Run win-fix-bcd after this script if the VM still does not boot.
#
# .RESOLVES
#   "A disk read error occurred. Press Ctrl+Alt+Del to restart" - the classic stale HiddenSectors
#               signature after a partition move, a restore from backup, or a bad resize
#   "Operating system not found" / "No bootable device" / "No boot device found"
#   "Missing operating system"
#   "Invalid partition table"
#   "Error loading operating system"
#   Gen2 VMs that boot straight into the UEFI shell or the firmware boot menu because the EFI
#   System Partition was deleted or left unformatted.
#
# .PARAMETER detectOnly
#   "true" to report the findings and make no writes at all. Defaults to "false".
#
# .PARAMETER revert
#   "true" to write back the boot sectors this script backed up on its last run, using the manifest
#   it wrote. Defaults to "false". See the notes for what revert does and does not cover.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-boot-partition --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-boot-partition --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-boot-partition --parameters revert=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   This is the only script in the library that writes raw sectors, so it is deliberately cautious:
#
#     - Sector 0 and the volume boot record are copied to <windowsDrive>\win-fix-boot-partition-backup-*
#       before anything is written, and the paths are recorded in
#       <windowsDrive>\win-fix-boot-partition-revert.json.
#     - Writes only ever touch the 512 byte sectors named by a finding. The MBR partition table at
#       offset 446 is preserved byte for byte when the bootstrap is rewritten.
#     - Windows blocks writes to sectors that belong to a mounted volume, so the disk is taken
#       offline for the write and brought back online immediately afterwards.
#     - The repair is verified by reading the sectors back and running the whole detect phase again.
#
#   revert=true writes the backed up sectors back. On a Gen1 disk that also puts back the partition
#   table as it was, which will remove a system partition this script created. It does not undo a
#   Gen2 EFI System Partition, because a GPT partition table is not carried in the sectors that are
#   backed up; the created partition is reported so it can be removed by hand if that is wanted.
#
#   The Active flag is also corrected by win-fix-bcd, which sets it on the partition holding the BCD
#   store. The two agree: this script additionally clears the flag from any other partition, which
#   matters only in the "more than one Active" case that win-fix-bcd does not look for.
#
#   bootsect.exe is not used. It is not in-box on Windows Server, so it is never present on a rescue
#   VM, and it does not correct BPB HiddenSectors, which is the highest value repair here. The
#   bootstrap is instead restored from the NTFS backup boot sector kept at the end of the volume, or
#   copied from a healthy Windows volume attached to the rescue VM.
#
#   Related scenarios, deliberately not folded in because they are different problems:
#     win-fix-bcd                       the boot configuration inside the system partition
#     win-fix-file-system               chkdsk and filesystem level damage
#     win-sfc-sf-corruption             damaged Windows binaries
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')

$script:EspGptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
$script:BasicDataGptType = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'

# NTFS bootstrap code in sector 0 occupies 0x54 to 0x1FD. Everything below it is the BPB, which
# describes this specific volume and must never be copied from anywhere else.
$script:VbrBootCodeStart = 0x54
$script:VbrBootCodeEnd = 0x1FD

# Smallest system partition worth creating. These are deliberately below the sizes Windows Setup
# picks, because the job here is to make an unbootable disk bootable again in the space that is
# actually free, not to reproduce a fresh install layout. An Azure Gen2 image ships a 99 MiB EFI
# System Partition, so a 100 MB floor would refuse to rebuild an ESP in the very gap one just left.
# FAT32 needs 65525 clusters, which is 33 MB at the smallest cluster size, so 50 MB is a safe floor;
# a BIOS System Reserved partition holds bootmgr and \Boot, which is what Windows 7 fitted in 100 MB.
$script:MinEspSize = 50MB
$script:MinSystemReservedSize = 100MB

# A Gen2 VM does not boot by scanning for an EFI System Partition. It boots from a UEFI boot entry
# that names the partition by its GPT unique GUID, and that entry lives in firmware, not on the disk.
# Recreating the partition gives it a fresh random GUID, so the entry resolves to nothing and the
# firmware reports "Unknown Device" without ever reading a file - even though the partition, its
# filesystem, its boot loader and its BCD are all perfect. The original GUID therefore has to be put
# back, and partmgr's cache of the partition table is where an offline Windows still records it.
#
# partmgr writes that cache under each disk's device key as PartitionTableCache: a 48 byte header
# (version, record count, disk GUID, disk size) followed by one PARTITION_INFORMATION_EX record per
# partition. Each record carries the partition type GUID, so the EFI System Partition is identified
# by what it is rather than guessed at, along with the offset and length to check the answer against.
$script:PartitionTableCacheValue = 'PartitionTableCache'
$script:PartitionTableCacheHeaderSize = 48
$script:PartitionTableCacheRecordSize = 144
$script:PartitionTableCacheVersion = 1

# Buses an Azure disk can appear on. Enumerating these by name keeps the search to a few dozen keys;
# walking the whole Enum subtree takes minutes on a full SYSTEM hive.
$script:PartitionTableCacheBuses = @('SCSI', 'NVME', 'IDE', 'STORAGE', 'VMBUS', 'SCM')

# PowerShell reads 0xFFFFFFFF and 0xEDB88320 as negative Int32 values, which makes every UInt64
# conversion in a CRC32 loop throw. Both constants are written in decimal for that reason.
$script:Crc32Mask = [UInt64]4294967295
$script:Crc32Polynomial = [UInt64]3988292384
$script:Crc32Table = $null

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.

    .PARAMETER Tier
        'Sector' when a raw sector write or an Active flag change corrects it, 'Partition' when a
        new system partition has to be created, 'None' when nothing here can.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)][ValidateSet('Sector', 'Partition', 'None')][string]$Tier = 'Sector',
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Tier       = $Tier
        Repaired   = $false
        Data       = $Data
    }
}

function Read-RawDiskSector {
    <#
    .SYNOPSIS
        Reads sectors straight from the physical disk, bypassing the filesystem.

    .DESCRIPTION
        Opened with FileShare.ReadWrite so the read succeeds while the disk is online and its
        volumes are mounted. Reading never needs the disk offline; only writing does.

        The stream reads ahead a whole physical sector, so a short read that starts inside the
        last physical sector of the disk runs off the end of the media and fails. Callers that
        need the tail of a disk should read the region as one block that ends at the media end.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][UInt64]$ByteOffset,
        [Parameter(Mandatory = $false)][int]$Length = 512
    )

    $stream = $null
    try {
        $stream = New-Object System.IO.FileStream("\\.\PhysicalDrive$DiskNumber",
            [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $null = $stream.Seek([long]$ByteOffset, [System.IO.SeekOrigin]::Begin)

        $buffer = New-Object byte[] $Length
        $read = 0
        while ($read -lt $Length) {
            $count = $stream.Read($buffer, $read, $Length - $read)
            if ($count -le 0) { break }
            $read += $count
        }
        if ($read -lt $Length) { throw "Short read at offset $ByteOffset : got $read of $Length bytes." }
        return $buffer
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Write-RawDiskSector {
    <#
    .SYNOPSIS
        Writes whole sectors straight to the physical disk.

    .DESCRIPTION
        The disk must be offline. Windows refuses writes to sectors that belong to a mounted volume,
        and silently succeeding against the cache instead of the platter would be worse than failing.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][UInt64]$ByteOffset,
        [Parameter(Mandatory = $true)][byte[]]$Data
    )

    if ($Data.Length % 512 -ne 0) { throw "Sector writes must be a multiple of 512 bytes (got $($Data.Length))." }

    $stream = $null
    try {
        $stream = New-Object System.IO.FileStream("\\.\PhysicalDrive$DiskNumber",
            [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        $null = $stream.Seek([long]$ByteOffset, [System.IO.SeekOrigin]::Begin)
        $stream.Write($Data, 0, $Data.Length)
        $stream.Flush($true)
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Get-SectorAsciiView {
    <#
    .SYNOPSIS
        Renders a sector as ASCII so the strings a bootstrap carries can be matched.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $chars = foreach ($byte in $Bytes) { if ($byte -ge 32 -and $byte -le 126) { [char]$byte } else { '.' } }
    return (-join $chars)
}

function ConvertFrom-MbrSector {
    <#
    .SYNOPSIS
        Decodes sector 0 of an MBR disk: signature, bootstrap, disk signature and partition table.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Sector)

    if ($Sector.Length -lt 512) { throw "MBR sector must be at least 512 bytes (got $($Sector.Length))." }

    $result = [ordered]@{
        HasSignature      = ($Sector[510] -eq 0x55 -and $Sector[511] -eq 0xAA)
        BootCodeNonZero   = 0
        IsWindowsBootCode = $false
        IsProtectiveMbr   = $false
        DiskSignature     = ''
        Markers           = @()
        Partitions        = @()
        ActiveCount       = 0
    }

    $bootCode = $Sector[0..439]
    $result.BootCodeNonZero = @($bootCode | Where-Object { $_ -ne 0 }).Count

    # Strings carried by the standard Windows MBR bootstrap, unchanged since NT.
    $text = Get-SectorAsciiView -Bytes $bootCode
    foreach ($marker in @('Invalid partition table', 'Error loading operating system', 'Missing operating system')) {
        if ($text.Contains($marker)) { $result.Markers += $marker }
    }
    $result.IsWindowsBootCode = ($result.Markers.Count -ge 2)

    $result.DiskSignature = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $Sector[443], $Sector[442], $Sector[441], $Sector[440]

    for ($i = 0; $i -lt 4; $i++) {
        $offset = 446 + ($i * 16)
        $type = $Sector[$offset + 4]
        if ($type -eq 0 -and $Sector[$offset] -eq 0) { continue }

        $isActive = ($Sector[$offset] -eq 0x80)
        if ($isActive) { $result.ActiveCount++ }
        if ($type -eq 0xEE) { $result.IsProtectiveMbr = $true }

        $result.Partitions += [PSCustomObject]@{
            Index       = $i + 1
            IsActive    = $isActive
            TypeByte    = ('0x{0:X2}' -f $type)
            StartLBA    = [BitConverter]::ToUInt32($Sector, $offset + 8)
            SectorCount = [BitConverter]::ToUInt32($Sector, $offset + 12)
        }
    }

    return [PSCustomObject]$result
}

function ConvertFrom-NtfsVbr {
    <#
    .SYNOPSIS
        Decodes a volume boot record: signature, OEM id, BPB geometry and which loader it looks for.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -lt 512) { throw "A volume boot record needs at least 512 bytes (got $($Bytes.Length))." }

    $oemId = [Text.Encoding]::ASCII.GetString($Bytes, 3, 8)
    $result = [ordered]@{
        HasSignature      = ($Bytes[510] -eq 0x55 -and $Bytes[511] -eq 0xAA)
        OemId             = $oemId
        IsNtfs            = ($oemId -eq 'NTFS    ')
        BytesPerSector    = [BitConverter]::ToUInt16($Bytes, 11)
        SectorsPerCluster = $Bytes[13]
        HiddenSectors     = [BitConverter]::ToUInt32($Bytes, 28)
        TotalSectors      = [UInt64]0
        BootCodeNonZero   = 0
        Loader            = 'None'
        Markers           = @()
    }
    if ($result.IsNtfs) { $result.TotalSectors = [BitConverter]::ToUInt64($Bytes, 40) }

    $result.BootCodeNonZero = @($Bytes[$script:VbrBootCodeStart..$script:VbrBootCodeEnd] | Where-Object { $_ -ne 0 }).Count

    $text = Get-SectorAsciiView -Bytes $Bytes
    foreach ($marker in @('BOOTMGR is missing', 'BOOTMGR is compressed', 'A disk read error occurred',
            'Press Ctrl+Alt+Del to restart', 'NTLDR is missing', 'NTLDR is compressed', 'BOOTMGR', 'NTLDR')) {
        if ($text.Contains($marker)) { $result.Markers += $marker }
    }
    if ($result.Markers -contains 'BOOTMGR') { $result.Loader = 'BOOTMGR' }
    elseif ($result.Markers -contains 'NTLDR') { $result.Loader = 'NTLDR' }

    return [PSCustomObject]$result
}

function Get-VbrFileSystem {
    <#
    .SYNOPSIS
        Names the filesystem from the boot sector alone.

    .DESCRIPTION
        Get-Volume needs the partition to be mounted, and an EFI System Partition usually is not.
        The boot sector carries the answer without mounting anything, which also means a partition
        with a damaged filesystem still gets an honest answer instead of an exception.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -lt 512) { return 'Unknown' }

    if ([Text.Encoding]::ASCII.GetString($Bytes, 3, 8) -eq 'NTFS    ') { return 'NTFS' }
    if ([Text.Encoding]::ASCII.GetString($Bytes, 82, 8).TrimEnd() -eq 'FAT32') { return 'FAT32' }

    $fatLabel = [Text.Encoding]::ASCII.GetString($Bytes, 54, 8).TrimEnd()
    if ($fatLabel -in @('FAT16', 'FAT12', 'FAT')) { return $fatLabel }

    return 'Unknown'
}

function Get-WindowsMbrBootstrap {
    <#
    .SYNOPSIS
        Finds a known good Windows MBR bootstrap on another disk attached to this rescue VM.

    .DESCRIPTION
        The Windows MBR bootstrap is not shipped as a standalone file anywhere in Windows, so the
        only honest source is a disk that already carries one. Only the 440 bytes of code are taken;
        the partition table and disk signature that follow are never copied.
    #>
    param([Parameter(Mandatory = $false)][int]$ExcludeDiskNumber = -1)

    $disks = @(Get-Disk -ErrorAction SilentlyContinue |
        Where-Object { $_.PartitionStyle -eq 'MBR' -and $_.Number -ne $ExcludeDiskNumber } |
        Sort-Object Number)

    foreach ($disk in $disks) {
        try {
            $sector = Read-RawDiskSector -DiskNumber $disk.Number -ByteOffset 0 -Length 512
            $info = ConvertFrom-MbrSector -Sector $sector
            if ($info.HasSignature -and $info.IsWindowsBootCode -and -not $info.IsProtectiveMbr) {
                return [PSCustomObject]@{
                    SourceDisk = $disk.Number
                    Bootstrap  = $sector[0..439]
                }
            }
        }
        catch { continue }
    }

    return $null
}

function Get-WindowsVbrBootstrap {
    <#
    .SYNOPSIS
        Finds a known good NT60 volume bootstrap on a healthy NTFS volume of this rescue VM.

    .DESCRIPTION
        This is what "bootsect /nt60" writes. Only the bootstrap code region is taken, never the
        BPB, because the BPB describes the source volume's own geometry.
    #>
    param([Parameter(Mandatory = $false)][int]$ExcludeDiskNumber = -1)

    $excludedLetters = @()
    if ($ExcludeDiskNumber -ge 0) {
        $excludedLetters = @(Get-Partition -DiskNumber $ExcludeDiskNumber -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter)" })
    }

    $volumes = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter -and $_.FileSystem -eq 'NTFS' -and "$($_.DriveLetter)" -notin $excludedLetters })

    foreach ($volume in $volumes) {
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream("\\.\$($volume.DriveLetter):",
                [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $buffer = New-Object byte[] 512
            if ($stream.Read($buffer, 0, 512) -ne 512) { continue }

            $info = ConvertFrom-NtfsVbr -Bytes $buffer
            if ($info.HasSignature -and $info.IsNtfs -and $info.Loader -eq 'BOOTMGR') {
                return [PSCustomObject]@{
                    SourceVolume = "$($volume.DriveLetter):"
                    Bootstrap    = $buffer[$script:VbrBootCodeStart..$script:VbrBootCodeEnd]
                }
            }
        }
        catch { continue }
        finally { if ($stream) { $stream.Dispose() } }
    }

    return $null
}

function Resolve-BootPartition {
    <#
    .SYNOPSIS
        Decides whether this disk has a system partition, and which one it is.

    .DESCRIPTION
        Deliberately more thorough than the boot partition that Get-OfflineWindowsDisk reports.
        That one falls back to the Active flag on Gen1, so a System Reserved partition whose Active
        flag was cleared and whose BCD store is missing reads as "no boot partition". Creating a
        second system partition in that situation would be wrong, so every other piece of evidence
        is checked first: the GPT partition type, the boot files actually present on the partition,
        and finally the Active flag.
    #>
    param([Parameter(Mandatory = $true)]$Offline)

    $result = [PSCustomObject]@{
        Partition          = $null
        Root               = $null
        Evidence           = ''
        IsWindowsPartition = $false
    }

    $windowsRoot = $Offline.WindowsDrive.TrimEnd('\')
    $partitions = @(Get-Partition -DiskNumber $Offline.DiskNumber -ErrorAction SilentlyContinue)

    $rootOf = {
        param($PartitionNumber)
        @($Offline.PartitionRoots["$($Offline.DiskNumber)-$PartitionNumber"]) | Select-Object -First 1
    }

    if ($Offline.Generation -eq 2) {
        foreach ($partition in $partitions) {
            $isEsp = ("$($partition.Type)" -eq 'System') -or
                     ("$($partition.GptType)".ToLowerInvariant() -eq $script:EspGptType)
            if (-not $isEsp) { continue }

            $result.Partition = $partition
            $result.Root = (& $rootOf $partition.PartitionNumber)
            $result.Evidence = 'GPT partition type is EFI System Partition'
            return $result
        }

        # An ESP whose type GUID was overwritten still holds the EFI boot tree.
        foreach ($partition in $partitions) {
            $root = & $rootOf $partition.PartitionNumber
            if (-not $root) { continue }
            if (Test-OfflinePath (Join-OfflinePath -Root $root -ChildPath 'EFI\Microsoft\Boot')) {
                $result.Partition = $partition
                $result.Root = $root
                $result.Evidence = 'holds \EFI\Microsoft\Boot'
                return $result
            }
        }

        return $result
    }

    # Gen1: a separate System Reserved partition is identified by the boot files it holds.
    foreach ($partition in $partitions) {
        $root = & $rootOf $partition.PartitionNumber
        if (-not $root) { continue }
        if ($root.TrimEnd('\') -eq $windowsRoot) { continue }

        foreach ($evidencePath in @('Boot\BCD', 'bootmgr', 'Boot')) {
            if (Test-OfflinePath (Join-OfflinePath -Root $root -ChildPath $evidencePath)) {
                $result.Partition = $partition
                $result.Root = $root
                $result.Evidence = "holds \$evidencePath"
                return $result
            }
        }
    }

    foreach ($partition in $partitions) {
        if (-not $partition.IsActive) { continue }
        $root = & $rootOf $partition.PartitionNumber
        if ($root -and $root.TrimEnd('\') -eq $windowsRoot) { continue }

        $result.Partition = $partition
        $result.Root = $root
        $result.Evidence = 'flagged Active'
        return $result
    }

    # A single partition layout is valid: Windows boots from its own partition.
    foreach ($partition in $partitions) {
        $root = & $rootOf $partition.PartitionNumber
        if (-not $root -or $root.TrimEnd('\') -ne $windowsRoot) { continue }

        # The BCD is what makes a partition a system partition. bootmgr on its own is not proof:
        # Windows leaves a copy of it on the Windows volume of an ordinary two partition install, so
        # accepting that would name a partition the firmware cannot actually boot from.
        if (Test-OfflinePath (Join-OfflinePath -Root $root -ChildPath 'Boot\BCD')) {
            $result.Partition = $partition
            $result.Root = $root
            $result.Evidence = 'Windows partition holds \Boot\BCD (single partition layout)'
            $result.IsWindowsPartition = $true
            return $result
        }

        # Flagged Active but holding no BCD is what a disk looks like after its System Reserved
        # partition was deleted: the flag falls to the Windows partition and nothing can boot from
        # it. Accept it only when there is nowhere to put a proper system partition, so a disk that
        # still has the gap gets one rebuilt in it instead of being called healthy.
        if ($partition.IsActive) {
            $disk = Get-Disk -Number $Offline.DiskNumber -ErrorAction SilentlyContinue
            $freeSpace = if ($disk) { [UInt64]$disk.LargestFreeExtent } else { [UInt64]0 }
            if ($freeSpace -ge $script:MinSystemReservedSize) { continue }

            $result.Partition = $partition
            $result.Root = $root
            $result.Evidence = 'Windows partition is flagged Active and the disk has no room for a separate system partition (single partition layout)'
            $result.IsWindowsPartition = $true
            return $result
        }
    }

    return $result
}

function Get-BootSectorState {
    <#
    .SYNOPSIS
        Reads every sector this script reasons about, once, and returns the decoded picture.

    .DESCRIPTION
        NTFS keeps a byte identical copy of sector 0 in the final sector of the volume. TotalSectors
        excludes that sector, so the backup sits exactly at partitionOffset + TotalSectors * bytesPerSector.
        That copy is the best source for a damaged bootstrap because it was written by the format of
        this very volume and carries this volume's own BPB.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $false)]$BootPartition = $null
    )

    $state = [PSCustomObject]@{
        DiskNumber       = $Offline.DiskNumber
        Mbr              = $null
        MbrRaw           = $null
        Vbr              = $null
        VbrRaw           = $null
        VbrOffset        = [UInt64]0
        BackupVbr        = $null
        BackupVbrRaw     = $null
        BackupVbrOffset  = [UInt64]0
        FileSystem       = 'Unknown'
        ExpectedHidden   = [UInt64]0
        Errors           = @()
    }

    try {
        $state.MbrRaw = Read-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset 0 -Length 512
        $state.Mbr = ConvertFrom-MbrSector -Sector $state.MbrRaw
    }
    catch { $state.Errors += "Could not read sector 0 of disk $($Offline.DiskNumber): $($_.Exception.Message)" }

    if (-not $BootPartition) { return $state }

    try {
        $state.VbrOffset = [UInt64]$BootPartition.Offset
        $state.VbrRaw = Read-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset $state.VbrOffset -Length 512
        $state.Vbr = ConvertFrom-NtfsVbr -Bytes $state.VbrRaw
        $state.FileSystem = Get-VbrFileSystem -Bytes $state.VbrRaw

        $bytesPerSector = if ($state.Vbr.BytesPerSector -ge 512) { [UInt64]$state.Vbr.BytesPerSector } else { [UInt64]512 }
        $state.ExpectedHidden = $state.VbrOffset / $bytesPerSector

        if ($state.Vbr.IsNtfs -and $state.Vbr.TotalSectors -gt 0) {
            $backupOffset = $state.VbrOffset + ([UInt64]$state.Vbr.TotalSectors * $bytesPerSector)
            if (($backupOffset + 512) -le [UInt64]($BootPartition.Offset + $BootPartition.Size)) {
                $state.BackupVbrOffset = $backupOffset
                $state.BackupVbrRaw = Read-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset $backupOffset -Length 512
                $state.BackupVbr = ConvertFrom-NtfsVbr -Bytes $state.BackupVbrRaw
            }
        }
    }
    catch { $state.Errors += "Could not read the volume boot record of partition $($BootPartition.PartitionNumber): $($_.Exception.Message)" }

    return $state
}

function Get-MissingPartitionFinding {
    <#
    .SYNOPSIS
        Reports a disk that has no system partition, and whether one can be created.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Resolved
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Resolved.Partition) { return @($findings) }

    $disk = Get-Disk -Number $Offline.DiskNumber -ErrorAction SilentlyContinue
    $minimumSize = if ($Offline.Generation -eq 2) { $script:MinEspSize } else { $script:MinSystemReservedSize }
    $freeSpace = if ($disk) { [UInt64]$disk.LargestFreeExtent } else { [UInt64]0 }
    $kind = if ($Offline.Generation -eq 2) { 'EFI System Partition' } else { 'System Reserved partition' }

    if ($freeSpace -lt $minimumSize) {
        [void]$findings.Add((New-Finding -Cause 'NoBootPartition' -Item "disk $($Offline.DiskNumber)" -Repairable $false -Tier 'None' -Message (
            "Disk $($Offline.DiskNumber) has no $kind and the firmware has nothing to start, but only " +
            "$([math]::Round($freeSpace / 1MB, 1)) MB of unallocated space is available and at least " +
            "$([math]::Round($minimumSize / 1MB, 0)) MB is needed. Shrink the Windows volume by hand to make room, " +
            'then run this script again. Nothing is shrunk automatically because that would move data.')))
        return @($findings)
    }

    [void]$findings.Add((New-Finding -Cause 'NoBootPartition' -Item "disk $($Offline.DiskNumber)" -Tier 'Partition' -Data $freeSpace -Message (
        "Disk $($Offline.DiskNumber) has no $kind, so the firmware has nothing to start. " +
        "A new one will be created in the $([math]::Round($freeSpace / 1MB, 1)) MB of unallocated space and populated with bcdboot.")))

    return @($findings)
}

function Get-PartitionFilesystemFinding {
    <#
    .SYNOPSIS
        Gen2 only: reports an EFI System Partition that holds no filesystem the firmware can read.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Resolved,
        [Parameter(Mandatory = $true)]$State
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Offline.Generation -ne 2 -or -not $Resolved.Partition) { return @($findings) }

    if ($State.FileSystem -in @('FAT32', 'FAT16', 'FAT12', 'FAT')) { return @($findings) }

    [void]$findings.Add((New-Finding -Cause 'EspNotFormatted' -Item "partition $($Resolved.Partition.PartitionNumber)" -Tier 'Partition' -Data $Resolved.Partition.PartitionNumber -Message (
        "The EFI System Partition (partition $($Resolved.Partition.PartitionNumber)) holds no FAT filesystem " +
        "(boot sector reads as '$($State.FileSystem)'), so UEFI cannot read a boot loader from it. " +
        'It will be formatted FAT32 and repopulated with bcdboot. An EFI System Partition holds only boot files, ' +
        'all of which bcdboot writes again.')))

    return @($findings)
}

function Get-MbrFinding {
    <#
    .SYNOPSIS
        Gen1 only: reports faults in sector 0, the code the BIOS executes first.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Resolved,
        [Parameter(Mandatory = $true)]$State
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Offline.Generation -eq 2 -or -not $State.Mbr) { return @($findings) }

    if (-not $State.Mbr.HasSignature) {
        [void]$findings.Add((New-Finding -Cause 'MbrSignature' -Item 'sector 0' -Message (
            'Sector 0 has no 0x55AA boot signature, so the BIOS does not treat this disk as bootable at all ' +
            '("Operating system not found" / "No bootable device").')))
    }

    if ($State.Mbr.BootCodeNonZero -eq 0) {
        $source = Get-WindowsMbrBootstrap -ExcludeDiskNumber $Offline.DiskNumber
        [void]$findings.Add((New-Finding -Cause 'MbrBootstrap' -Item 'sector 0' -Repairable ([bool]$source) -Tier $(if ($source) { 'Sector' } else { 'None' }) -Data $source -Message (
            'The MBR bootstrap code is entirely zero, so nothing runs after the BIOS hands over ' +
            '("Operating system not found").' +
            $(if ($source) { " A known good Windows bootstrap is available on disk $($source.SourceDisk) and will be copied." }
              else { ' No healthy MBR disk is attached to this rescue VM to copy a known good bootstrap from, so this cannot be repaired here. Attach the disk to a Gen1 rescue VM and run this script again.' }))))
    }
    elseif (-not $State.Mbr.IsWindowsBootCode) {
        $source = Get-WindowsMbrBootstrap -ExcludeDiskNumber $Offline.DiskNumber
        [void]$findings.Add((New-Finding -Cause 'MbrBootstrap' -Item 'sector 0' -Repairable ([bool]$source) -Tier $(if ($source) { 'Sector' } else { 'None' }) -Data $source -Message (
            'The MBR bootstrap code is present but is not the standard Windows bootstrap ' +
            "(markers found: $(if ($State.Mbr.Markers.Count) { $State.Mbr.Markers -join ', ' } else { 'none' })). " +
            'It is either a third party boot loader or damaged code.' +
            $(if ($source) { " A known good Windows bootstrap is available on disk $($source.SourceDisk) and will be copied. The partition table is preserved." }
              else { ' No healthy MBR disk is attached to this rescue VM to copy a known good bootstrap from, so this cannot be repaired here.' }))))
    }

    if (-not $Resolved.Partition) { return @($findings) }

    if ($State.Mbr.ActiveCount -eq 0) {
        [void]$findings.Add((New-Finding -Cause 'ActiveFlagMissing' -Item "partition $($Resolved.Partition.PartitionNumber)" -Data $Resolved.Partition.PartitionNumber -Message (
            'No partition on this disk is flagged Active, so the Windows MBR bootstrap has no volume boot record to ' +
            'load and stops with "Missing operating system". ' +
            "The Active flag will be set on partition $($Resolved.Partition.PartitionNumber) ($($Resolved.Evidence)).")))
    }
    elseif ($State.Mbr.ActiveCount -gt 1) {
        [void]$findings.Add((New-Finding -Cause 'ActiveFlagAmbiguous' -Item "disk $($Offline.DiskNumber)" -Data $Resolved.Partition.PartitionNumber -Message (
            "$($State.Mbr.ActiveCount) partitions are flagged Active. The MBR bootstrap requires exactly one and " +
            'loads the first it finds, which may not be the system partition. ' +
            "The flag will be left only on partition $($Resolved.Partition.PartitionNumber) ($($Resolved.Evidence)).")))
    }
    elseif (-not $Resolved.Partition.IsActive) {
        [void]$findings.Add((New-Finding -Cause 'ActiveFlagMissing' -Item "partition $($Resolved.Partition.PartitionNumber)" -Data $Resolved.Partition.PartitionNumber -Message (
            "The system partition (partition $($Resolved.Partition.PartitionNumber), $($Resolved.Evidence)) is not the " +
            'partition flagged Active, so the BIOS loads the boot sector of a partition that carries no boot files.')))
    }

    return @($findings)
}

function Get-VbrFinding {
    <#
    .SYNOPSIS
        Gen1 only: reports faults in the volume boot record of the system partition.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Resolved,
        [Parameter(Mandatory = $true)]$State
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Offline.Generation -eq 2 -or -not $Resolved.Partition -or -not $State.Vbr) { return @($findings) }

    $label = "partition $($Resolved.Partition.PartitionNumber)"

    if (-not $State.Vbr.IsNtfs) {
        [void]$findings.Add((New-Finding -Cause 'BootVolumeNotNtfs' -Item $label -Repairable $false -Tier 'None' -Message (
            "The system partition ($label) does not hold an NTFS filesystem: its boot sector reads as " +
            "'$($State.FileSystem)' (OEM id '$($State.Vbr.OemId)'). That is filesystem damage rather than a boot " +
            'sector fault, and rewriting the boot sector would hide it. Use win-fix-file-system.')))
        return @($findings)
    }

    if (-not $State.Vbr.HasSignature) {
        [void]$findings.Add((New-Finding -Cause 'VbrSignature' -Item $label -Message (
            "The volume boot record of $label has no 0x55AA signature, so the MBR bootstrap refuses it and stops " +
            'with "Missing operating system".')))
    }

    $needsBootstrap = ($State.Vbr.BootCodeNonZero -eq 0) -or ($State.Vbr.Loader -eq 'NTLDR')
    if ($needsBootstrap) {
        $source = Get-VbrBootstrapSource -Offline $Offline -State $State
        $reason = if ($State.Vbr.BootCodeNonZero -eq 0) {
            'carries no bootstrap code at all, so the MBR loads it and nothing happens'
        }
        else {
            'carries the NT52 bootstrap, which looks for NTLDR, but this installation boots through BOOTMGR'
        }

        [void]$findings.Add((New-Finding -Cause 'VbrBootstrap' -Item $label -Repairable ([bool]$source) -Tier $(if ($source) { 'Sector' } else { 'None' }) -Data $source -Message (
            "The volume boot record of $label $reason." +
            $(if ($source) { " It will be restored from $($source.Description)." }
              else { ' The NTFS backup boot sector is unreadable and no healthy NTFS volume is attached to this rescue VM to copy a bootstrap from, so this cannot be repaired here.' }))))
    }

    # The highest value check in this script. Windows never reads HiddenSectors, so the volume mounts
    # perfectly on a rescue VM and chkdsk and sfc report nothing, while the BIOS bootstrap adds the
    # stale value to every relative read and lands on the wrong absolute sectors.
    if ([UInt64]$State.Vbr.HiddenSectors -ne $State.ExpectedHidden) {
        if ($State.ExpectedHidden -gt [UInt32]::MaxValue) {
            [void]$findings.Add((New-Finding -Cause 'HiddenSectors' -Item $label -Repairable $false -Tier 'None' -Message (
                "The system partition starts at LBA $($State.ExpectedHidden), which does not fit in the 32 bit BPB " +
                'HiddenSectors field. A BIOS boot partition cannot live that far into the disk.')))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'HiddenSectors' -Item $label -Data $State.ExpectedHidden -Message (
                "The BPB HiddenSectors field of $label reads $($State.Vbr.HiddenSectors) but the partition actually " +
                "starts at LBA $($State.ExpectedHidden). The BIOS bootstrap adds this value to every relative read, " +
                'so it reads the wrong absolute sectors and stops with "A disk read error occurred. Press Ctrl+Alt+Del ' +
                'to restart". Windows ignores the field, which is why the volume mounts here and chkdsk and sfc come ' +
                'back clean.')))
        }
    }

    if ($State.Vbr.TotalSectors -gt 0) {
        $bytesPerSector = if ($State.Vbr.BytesPerSector -ge 512) { [UInt64]$State.Vbr.BytesPerSector } else { [UInt64]512 }
        $partitionSectors = [UInt64]$Resolved.Partition.Size / $bytesPerSector
        if ([UInt64]$State.Vbr.TotalSectors -ge $partitionSectors) {
            [void]$findings.Add((New-Finding -Cause 'TotalSectorsOverflow' -Item $label -Repairable $false -Tier 'None' -Message (
                "The BPB says the volume holds $($State.Vbr.TotalSectors) sectors but $label only has room for " +
                "$partitionSectors. The filesystem believes it is larger than its container, which follows a bad " +
                'resize and also makes the NTFS backup boot sector unreachable. Repair the filesystem first with ' +
                'win-fix-file-system, then run this script again.')))
        }
    }

    return @($findings)
}

function Get-VbrBootstrapSource {
    <#
    .SYNOPSIS
        Picks where a replacement volume bootstrap comes from, preferring this volume's own backup.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$State
    )

    if ($State.BackupVbr -and $State.BackupVbr.HasSignature -and $State.BackupVbr.IsNtfs -and $State.BackupVbr.Loader -eq 'BOOTMGR') {
        return [PSCustomObject]@{
            Description = "this volume's own NTFS backup boot sector at offset $($State.BackupVbrOffset)"
            Bootstrap   = $State.BackupVbrRaw[$script:VbrBootCodeStart..$script:VbrBootCodeEnd]
        }
    }

    $external = Get-WindowsVbrBootstrap -ExcludeDiskNumber $Offline.DiskNumber
    if ($external) {
        return [PSCustomObject]@{
            Description = "the NT60 bootstrap on $($external.SourceVolume) of this rescue VM"
            Bootstrap   = $external.Bootstrap
        }
    }

    return $null
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Runs the whole detect phase and returns every finding in one list.
    #>
    param([Parameter(Mandatory = $true)]$Offline)

    $resolved = Resolve-BootPartition -Offline $Offline
    $state = Get-BootSectorState -Offline $Offline -BootPartition $resolved.Partition

    foreach ($readError in $state.Errors) { Add-OfflineRepairLog -Level Warning -Message $readError }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($finding in (Get-MissingPartitionFinding -Offline $Offline -Resolved $resolved)) { [void]$findings.Add($finding) }
    foreach ($finding in (Get-PartitionFilesystemFinding -Offline $Offline -Resolved $resolved -State $state)) { [void]$findings.Add($finding) }
    foreach ($finding in (Get-MbrFinding -Offline $Offline -Resolved $resolved -State $state)) { [void]$findings.Add($finding) }
    foreach ($finding in (Get-VbrFinding -Offline $Offline -Resolved $resolved -State $state)) { [void]$findings.Add($finding) }

    return [PSCustomObject]@{
        Resolved = $resolved
        State    = $state
        Findings = @($findings)
    }
}

function Save-BootSectorBackup {
    <#
    .SYNOPSIS
        Copies the sectors this script may write to files on the offline Windows partition.

    .DESCRIPTION
        Written before the disk is taken offline, because the Windows volume has to be mounted to
        write to it. Both files are plain 512 byte images, so they can also be inspected or restored
        by hand with any hex editor.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$State
    )

    $backup = [PSCustomObject]@{
        MbrPath   = ''
        VbrPath   = ''
        VbrOffset = [UInt64]0
    }

    $prefix = Join-OfflinePath -Root $Offline.WindowsDrive -ChildPath "$scriptName-backup-$scriptStartTime"

    if ($State.MbrRaw) {
        $backup.MbrPath = "$prefix-sector0.bin"
        [System.IO.File]::WriteAllBytes($backup.MbrPath, $State.MbrRaw)
        Add-OfflineRepairLog -Level Info -Message "Backed up sector 0 to $($backup.MbrPath)."
    }

    if ($State.VbrRaw) {
        $backup.VbrPath = "$prefix-vbr.bin"
        $backup.VbrOffset = $State.VbrOffset
        [System.IO.File]::WriteAllBytes($backup.VbrPath, $State.VbrRaw)
        Add-OfflineRepairLog -Level Info -Message "Backed up the volume boot record at offset $($State.VbrOffset) to $($backup.VbrPath)."
    }

    return $backup
}

function Set-DiskOnlineState {
    <#
    .SYNOPSIS
        Takes the disk offline or brings it back, and waits for the volumes to settle.

    .DESCRIPTION
        Raw sector writes into a mounted volume are refused by Windows, so the disk has to be offline
        for the write. Azure data disks can also come back online read only, which is why the read
        only flag is cleared on the way back in.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][bool]$Online
    )

    try {
        if ($Online) {
            Set-Disk -Number $DiskNumber -IsOffline $false -ErrorAction Stop
            Set-Disk -Number $DiskNumber -IsReadOnly $false -ErrorAction SilentlyContinue

            for ($attempt = 0; $attempt -lt 15; $attempt++) {
                Start-Sleep -Seconds 1
                $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
                if ($disk -and -not $disk.IsOffline) { break }
            }

            $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
            if ($disk -and $disk.IsOffline) {
                Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber did not come back online."
                return $false
            }
            Add-OfflineRepairLog -Level Info -Message "Disk $DiskNumber is online again."
            return $true
        }

        Set-Disk -Number $DiskNumber -IsOffline $true -ErrorAction Stop
        Start-Sleep -Seconds 2
        Add-OfflineRepairLog -Level Info -Message "Disk $DiskNumber taken offline so its boot sectors can be written."
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not set disk $DiskNumber online state to $Online : $($_.Exception.Message)"
        return $false
    }
}

function Invoke-SectorRepair {
    <#
    .SYNOPSIS
        Applies every sector tier finding in one offline window.

    .DESCRIPTION
        The sectors are assembled in memory first and written in a single offline window, so the disk
        is unmounted once rather than once per finding. Each write is checked by reading the sector
        back before the disk is brought online.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Findings
    )

    $sectorFindings = @($Findings | Where-Object { $_.Repairable -and $_.Tier -eq 'Sector' })
    if ($sectorFindings.Count -eq 0) { return $true }

    # The Active flag lives in the partition table, which the Storage module owns. Letting
    # Set-Partition do it keeps the table consistent instead of hand editing sector 0.
    $activeFindings = @($sectorFindings | Where-Object { $_.Cause -in @('ActiveFlagMissing', 'ActiveFlagAmbiguous') })
    $rawFindings = @($sectorFindings | Where-Object { $_.Cause -notin @('ActiveFlagMissing', 'ActiveFlagAmbiguous') })

    foreach ($finding in $activeFindings) {
        $target = [int]$finding.Data
        $succeeded = $true

        if ($finding.Cause -eq 'ActiveFlagAmbiguous') {
            foreach ($partition in @(Get-Partition -DiskNumber $Offline.DiskNumber -ErrorAction SilentlyContinue)) {
                if ($partition.PartitionNumber -eq $target -or -not $partition.IsActive) { continue }
                try {
                    Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -IsActive $false -ErrorAction Stop
                    Add-OfflineRepairLog -Level Info -Message "Cleared the Active flag from partition $($partition.PartitionNumber)."
                }
                catch {
                    Add-OfflineRepairLog -Level Warning -Message "Could not clear the Active flag from partition $($partition.PartitionNumber): $($_.Exception.Message)"
                    $succeeded = $false
                }
            }
        }

        try {
            Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $target -IsActive $true -ErrorAction Stop
            Add-OfflineRepairLog -Level Info -Message "Set the Active flag on partition $target."
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not set the Active flag on partition $target : $($_.Exception.Message)"
            $succeeded = $false
        }

        $finding.Repaired = $succeeded
    }

    if ($rawFindings.Count -eq 0) { return $true }

    # Build the two candidate sectors in memory. Nothing is written until every finding has been
    # applied to the buffer, so a failure part way through leaves the disk untouched.
    $newMbr = if ($State.MbrRaw) { $State.MbrRaw.Clone() } else { $null }
    $newVbr = if ($State.VbrRaw) { $State.VbrRaw.Clone() } else { $null }
    $mbrDirty = $false
    $vbrDirty = $false

    foreach ($finding in $rawFindings) {
        switch ($finding.Cause) {
            'MbrSignature' {
                if ($null -eq $newMbr) { break }
                $newMbr[510] = 0x55
                $newMbr[511] = 0xAA
                $mbrDirty = $true
            }
            'MbrBootstrap' {
                if ($null -eq $newMbr -or -not $finding.Data) { break }
                [Array]::Copy([byte[]]$finding.Data.Bootstrap, 0, $newMbr, 0, 440)
                Add-OfflineRepairLog -Level Info -Message "Prepared the Windows MBR bootstrap copied from disk $($finding.Data.SourceDisk). The partition table at offset 446 is unchanged."
                $mbrDirty = $true
            }
            'VbrSignature' {
                if ($null -eq $newVbr) { break }
                $newVbr[510] = 0x55
                $newVbr[511] = 0xAA
                $vbrDirty = $true
            }
            'VbrBootstrap' {
                if ($null -eq $newVbr -or -not $finding.Data) { break }
                [Array]::Copy([byte[]]$finding.Data.Bootstrap, 0, $newVbr, $script:VbrBootCodeStart, ($script:VbrBootCodeEnd - $script:VbrBootCodeStart + 1))
                Add-OfflineRepairLog -Level Info -Message "Prepared the volume bootstrap from $($finding.Data.Description). The BPB describing this volume is unchanged."
                $vbrDirty = $true
            }
            'HiddenSectors' {
                if ($null -eq $newVbr) { break }
                [Array]::Copy([BitConverter]::GetBytes([UInt32]$finding.Data), 0, $newVbr, 28, 4)
                Add-OfflineRepairLog -Level Info -Message "Prepared BPB HiddenSectors = $($finding.Data)."
                $vbrDirty = $true
            }
        }
    }

    if (-not $mbrDirty -and -not $vbrDirty) { return $true }

    if (-not (Set-DiskOnlineState -DiskNumber $Offline.DiskNumber -Online $false)) {
        Add-OfflineRepairLog -Level Error -Message "Disk $($Offline.DiskNumber) could not be taken offline, so no sector was written."
        return $false
    }

    $succeeded = $true
    try {
        if ($mbrDirty) {
            Write-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset 0 -Data $newMbr
            $readBack = Read-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset 0 -Length 512
            if (Compare-Object $newMbr $readBack -SyncWindow 0) {
                Add-OfflineRepairLog -Level Error -Message 'Sector 0 did not read back as written.'
                $succeeded = $false
            }
            else {
                Add-OfflineRepairLog -Level Info -Message 'Sector 0 written and read back identical.'
            }
        }

        if ($vbrDirty) {
            Write-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset $State.VbrOffset -Data $newVbr
            $readBack = Read-RawDiskSector -DiskNumber $Offline.DiskNumber -ByteOffset $State.VbrOffset -Length 512
            if (Compare-Object $newVbr $readBack -SyncWindow 0) {
                Add-OfflineRepairLog -Level Error -Message "The volume boot record at offset $($State.VbrOffset) did not read back as written."
                $succeeded = $false
            }
            else {
                Add-OfflineRepairLog -Level Info -Message "The volume boot record at offset $($State.VbrOffset) was written and read back identical."
            }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message "Writing boot sectors failed: $($_.Exception.Message)"
        $succeeded = $false
    }
    finally {
        [void](Set-DiskOnlineState -DiskNumber $Offline.DiskNumber -Online $true)
    }

    if ($succeeded) {
        foreach ($finding in $rawFindings) { $finding.Repaired = $true }
    }

    return $succeeded
}

function Get-Crc32 {
    <#
    .SYNOPSIS
        CRC32 as GPT uses it: reflected, polynomial 0xEDB88320, initial and final value all ones.

    .DESCRIPTION
        A GPT header carries a checksum of itself and of its partition entry array. Editing an entry
        without recomputing both leaves a table Windows and the firmware will reject, so this is not
        optional bookkeeping.
    #>
    param(
        [Parameter(Mandatory = $true)][byte[]]$Data,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length
    )

    if ($null -eq $script:Crc32Table) {
        $script:Crc32Table = New-Object 'UInt32[]' 256
        for ($index = 0; $index -lt 256; $index++) {
            $value = [UInt64]$index
            for ($bit = 0; $bit -lt 8; $bit++) {
                if ($value -band 1) { $value = ($script:Crc32Polynomial -bxor ($value -shr 1)) -band $script:Crc32Mask }
                else { $value = ($value -shr 1) -band $script:Crc32Mask }
            }
            $script:Crc32Table[$index] = [UInt32]$value
        }
    }

    $crc = $script:Crc32Mask
    for ($i = $Offset; $i -lt $Offset + $Length; $i++) {
        $index = [int](($crc -bxor [UInt64]$Data[$i]) -band 255)
        $crc = (([UInt64]$script:Crc32Table[$index]) -bxor ($crc -shr 8)) -band $script:Crc32Mask
    }

    return [UInt32](($crc -bxor $script:Crc32Mask) -band $script:Crc32Mask)
}

function ConvertTo-Guid {
    <#
    .SYNOPSIS
        Reads a 16 byte GUID out of a buffer.

    .DESCRIPTION
        Slicing a PowerShell array yields Object[], which [Guid]::new refuses, so the slice is cast
        back to byte[] first.
    #>
    param(
        [Parameter(Mandatory = $true)][byte[]]$Data,
        [Parameter(Mandatory = $true)][int]$Offset
    )

    return [Guid]::new([byte[]]($Data[$Offset..($Offset + 15)]))
}

function Get-RecordedEspIdentity {
    <#
    .SYNOPSIS
        Gen2 only: recovers the EFI System Partition's original GPT unique GUID from the offline
        Windows registry.

    .DESCRIPTION
        Reads partmgr's PartitionTableCache for every disk the offline Windows has seen and returns
        the records whose partition type is the EFI System Partition type. The offset and length come
        back with the GUID so the caller can confirm the record describes the gap it is about to fill
        rather than some other disk's partition.

    .OUTPUTS
        Zero or more objects with Id, StartingOffset, Length and Source.
    #>
    param([Parameter(Mandatory = $true)]$Offline)

    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Offline.Generation -ne 2) { return @($found) }

    $espType = [Guid]::Parse($script:EspGptType)

    try {
        Invoke-WithHive 'SYSTEM' {
            foreach ($controlSet in @(Get-OfflineReferencedControlSetName)) {
                foreach ($bus in $script:PartitionTableCacheBuses) {
                    $busPath = "HKLM:\BROKENSYSTEM\$controlSet\Enum\$bus"
                    if (-not (Test-Path $busPath)) { continue }

                    foreach ($key in @(Get-ChildItem -Path $busPath -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.PSChildName -eq 'Partmgr' })) {

                        $cache = (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).$($script:PartitionTableCacheValue)
                        if ($cache -isnot [byte[]] -or $cache.Length -lt $script:PartitionTableCacheHeaderSize) { continue }

                        if ([BitConverter]::ToUInt32($cache, 0) -ne $script:PartitionTableCacheVersion) { continue }
                        $count = [int][BitConverter]::ToUInt32($cache, 4)
                        $expected = $script:PartitionTableCacheHeaderSize + ($count * $script:PartitionTableCacheRecordSize)
                        if ($count -le 0 -or $cache.Length -ne $expected) { continue }

                        for ($record = 0; $record -lt $count; $record++) {
                            $base = $script:PartitionTableCacheHeaderSize + ($record * $script:PartitionTableCacheRecordSize)
                            if ((ConvertTo-Guid -Data $cache -Offset ($base + 32)) -ne $espType) { continue }

                            [void]$found.Add([PSCustomObject]@{
                                    Id             = ConvertTo-Guid -Data $cache -Offset ($base + 48)
                                    StartingOffset = [BitConverter]::ToUInt64($cache, $base + 8)
                                    Length         = [BitConverter]::ToUInt64($cache, $base + 16)
                                    Source         = "$controlSet\Enum\$bus...\Partmgr"
                                })
                        }
                    }
                }
            }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not read partmgr's cached partition table from the offline registry: $($_.Exception.Message)"
        return @()
    }

    return @($found)
}

function Set-GptPartitionUniqueId {
    <#
    .SYNOPSIS
        Rewrites one GPT entry's unique partition GUID in both copies of the partition table.

    .DESCRIPTION
        Neither diskpart nor the Storage module can set a partition's unique GUID - 'set id=' and
        Set-Partition -GptType both change the partition *type*, and 'uniqueid disk' changes the
        *disk* GUID - so the entry is edited in place. The primary table, the backup table and all
        three CRCs are updated together; a table whose CRCs disagree is worse than the problem being
        fixed. The disk must already be offline.

    .OUTPUTS
        $true when both copies were written and read back identical.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][UInt64]$PartitionOffset,
        [Parameter(Mandatory = $true)][Guid]$UniqueId
    )

    # Sectors 0 to 33: protective MBR, primary header, and the whole primary entry array.
    $primary = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Length (34 * 512)
    if ([Text.Encoding]::ASCII.GetString($primary, 512, 8) -ne 'EFI PART') {
        Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber has no GPT header where one is expected, so the partition GUID was left alone."
        return $false
    }

    $headerSize = [int][BitConverter]::ToUInt32($primary, 512 + 12)
    $alternateLba = [BitConverter]::ToUInt64($primary, 512 + 32)
    $primaryArrayLba = [BitConverter]::ToUInt64($primary, 512 + 72)
    $entryCount = [int][BitConverter]::ToUInt32($primary, 512 + 80)
    $entrySize = [int][BitConverter]::ToUInt32($primary, 512 + 84)
    $primaryArrayOffset = [int]($primaryArrayLba * 512)

    if ($headerSize -lt 92 -or $headerSize -gt 512 -or $entrySize -lt 128 -or
        ($primaryArrayOffset + ($entryCount * $entrySize)) -gt $primary.Length) {
        Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber has a GPT header this script cannot edit safely (header $headerSize bytes, $entryCount entries of $entrySize bytes), so the partition GUID was left alone."
        return $false
    }

    $slot = -1
    for ($index = 0; $index -lt $entryCount; $index++) {
        $entry = $primaryArrayOffset + ($index * $entrySize)
        if ((ConvertTo-Guid -Data $primary -Offset $entry) -eq [Guid]::Empty) { continue }
        if (([BitConverter]::ToUInt64($primary, $entry + 32) * 512) -eq $PartitionOffset) { $slot = $index; break }
    }
    if ($slot -lt 0) {
        Add-OfflineRepairLog -Level Warning -Message "No GPT entry on disk $DiskNumber starts at offset $PartitionOffset, so the partition GUID was left alone."
        return $false
    }

    $newId = $UniqueId.ToByteArray()
    $arrayLength = $entryCount * $entrySize

    [Array]::Copy($newId, 0, $primary, $primaryArrayOffset + ($slot * $entrySize) + 16, 16)
    [Array]::Copy([BitConverter]::GetBytes((Get-Crc32 -Data $primary -Offset $primaryArrayOffset -Length $arrayLength)), 0, $primary, 512 + 88, 4)
    [Array]::Copy(([byte[]](0, 0, 0, 0)), 0, $primary, 512 + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes((Get-Crc32 -Data $primary -Offset 512 -Length $headerSize)), 0, $primary, 512 + 16, 4)

    # The backup table lives at the very end of the disk: the entry array followed immediately by
    # the backup header in the final sector. Both are read as one block, because a lone 512-byte
    # read of a sector in the last 4 KB fails - the file stream reads ahead a whole 4 KB physical
    # sector and runs off the end of the media. The block is located from AlternateLBA rather than
    # from the disk size, and the backup header is then asked to confirm where its own array sits.
    $backupOffset = ($alternateLba * 512) - $arrayLength
    $backup = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset $backupOffset -Length ($arrayLength + 512)
    $backupHeaderAt = $arrayLength

    if ([Text.Encoding]::ASCII.GetString($backup, $backupHeaderAt, 8) -ne 'EFI PART') {
        Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber has no backup GPT header at LBA $alternateLba, so the partition GUID was left alone rather than written to only one copy of the table."
        return $false
    }
    if ((([BitConverter]::ToUInt64($backup, $backupHeaderAt + 72)) * 512) -ne $backupOffset) {
        Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber keeps its backup GPT entry array somewhere this script does not expect, so the partition GUID was left alone rather than written to only one copy of the table."
        return $false
    }

    [Array]::Copy($newId, 0, $backup, ($slot * $entrySize) + 16, 16)

    $backupHeaderSize = [int][BitConverter]::ToUInt32($backup, $backupHeaderAt + 12)
    [Array]::Copy([BitConverter]::GetBytes((Get-Crc32 -Data $backup -Offset 0 -Length $arrayLength)), 0, $backup, $backupHeaderAt + 88, 4)
    [Array]::Copy(([byte[]](0, 0, 0, 0)), 0, $backup, $backupHeaderAt + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes((Get-Crc32 -Data $backup -Offset $backupHeaderAt -Length $backupHeaderSize)), 0, $backup, $backupHeaderAt + 16, 4)

    try {
        Write-RawDiskSector -DiskNumber $DiskNumber -ByteOffset $backupOffset -Data $backup
        Write-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Data $primary
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message "Writing the GPT partition GUID failed: $($_.Exception.Message)"
        return $false
    }

    $readBack = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Length (34 * 512)
    $written = ConvertTo-Guid -Data $readBack -Offset ($primaryArrayOffset + ($slot * $entrySize) + 16)
    if ($written -ne $UniqueId) {
        Add-OfflineRepairLog -Level Error -Message "The GPT entry did not read back with the expected GUID (got $written)."
        return $false
    }

    $readBackTail = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset $backupOffset -Length ($arrayLength + 512)
    $writtenBackup = ConvertTo-Guid -Data $readBackTail -Offset (($slot * $entrySize) + 16)
    if ($writtenBackup -ne $UniqueId) {
        Add-OfflineRepairLog -Level Error -Message "The backup GPT entry did not read back with the expected GUID (got $writtenBackup), so the two copies of the partition table disagree."
        return $false
    }

    Add-OfflineRepairLog -Level Info -Message "GPT entry $slot on disk $DiskNumber now carries unique GUID $UniqueId in both copies of the partition table."
    return $true
}

function Restore-EspUniqueId {
    <#
    .SYNOPSIS
        Gen2 only: puts the original GPT unique GUID back on a freshly created EFI System Partition.

    .DESCRIPTION
        Only acts on a recovered record that describes this exact partition, because writing some
        other partition's GUID would be a guess dressed up as a repair. When no record matches, the
        partition is left with its new GUID and the caller is told plainly that the VM may still not
        boot, rather than being handed a silent failure.

    .OUTPUTS
        $true when the GUID was restored.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)][UInt64]$PartitionOffset,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Recorded
    )

    $match = @($Recorded | Where-Object { $_.StartingOffset -eq $PartitionOffset }) | Select-Object -First 1
    if (-not $match) {
        Add-OfflineRepairLog -Level Warning -Message (
            "The offline registry holds no record of an EFI System Partition at offset $PartitionOffset, so the new " +
            'partition keeps the random GUID Windows gave it. A Gen2 VM boots from a UEFI boot entry that names the ' +
            'partition by GUID, so if the firmware still holds the old entry it will report "Unknown Device" and the ' +
            'VM will not start until the boot entry is recreated from the UEFI setup menu.')
        return $false
    }

    $existing = @(Get-Partition -DiskNumber $Offline.DiskNumber -ErrorAction SilentlyContinue |
            Where-Object { $_.Offset -ne $PartitionOffset -and "$($_.Guid)".Trim('{', '}') -eq $match.Id.ToString() })
    if ($existing.Count -gt 0) {
        Add-OfflineRepairLog -Level Warning -Message "Partition $($existing[0].PartitionNumber) already carries GUID $($match.Id), so it was not written a second time."
        return $false
    }

    Add-OfflineRepairLog -Level Info -Message "The offline registry records the EFI System Partition as GUID $($match.Id) at offset $($match.StartingOffset), length $($match.Length) (from $($match.Source))."

    if (-not (Set-DiskOnlineState -DiskNumber $Offline.DiskNumber -Online $false)) {
        Add-OfflineRepairLog -Level Warning -Message "Disk $($Offline.DiskNumber) could not be taken offline, so the partition GUID was left alone."
        return $false
    }

    try {
        return (Set-GptPartitionUniqueId -DiskNumber $Offline.DiskNumber -PartitionOffset $PartitionOffset -UniqueId $match.Id)
    }
    finally {
        [void](Set-DiskOnlineState -DiskNumber $Offline.DiskNumber -Online $true)
    }
}

function Get-LargestFreeExtent {
    <#
    .SYNOPSIS
        Returns the start and size of the largest run of unallocated space on a GPT disk.

    .DESCRIPTION
        Get-Disk reports the size of the largest free extent but not where it is, and the offset is
        what lets a recreated partition be put back exactly where the old one was. The usable range
        comes from the GPT header rather than from the disk size, so the reserved sectors at both
        ends are respected.
    #>
    param([Parameter(Mandatory = $true)][int]$DiskNumber)

    $result = [PSCustomObject]@{ Start = [UInt64]0; Size = [UInt64]0 }

    try {
        $header = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 512 -Length 512
        if ([Text.Encoding]::ASCII.GetString($header, 0, 8) -ne 'EFI PART') { return $result }
        $cursor = ([BitConverter]::ToUInt64($header, 40)) * 512
        $usableEnd = (([BitConverter]::ToUInt64($header, 48)) + 1) * 512
    }
    catch { return $result }

    foreach ($partition in @(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue | Sort-Object Offset)) {
        $start = [UInt64]$partition.Offset
        if ($start -gt $cursor -and ($start - $cursor) -gt $result.Size) {
            $result.Start = $cursor
            $result.Size = $start - $cursor
        }
        $end = $start + [UInt64]$partition.Size
        if ($end -gt $cursor) { $cursor = $end }
    }

    if ($usableEnd -gt $cursor -and ($usableEnd - $cursor) -gt $result.Size) {
        $result.Start = $cursor
        $result.Size = $usableEnd - $cursor
    }

    return $result
}

function New-BootPartition {
    <#
    .SYNOPSIS
        Creates a system partition and populates it with bcdboot.

    .DESCRIPTION
        The EFI System Partition is created as a basic data partition, formatted, populated, and only
        then given the EFI System Partition type GUID. Windows hides a partition that already carries
        that GUID, so it could not be formatted or written to while it wore it.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)][UInt64]$FreeSpace
    )

    $result = [PSCustomObject]@{
        Success         = $false
        PartitionNumber = 0
        DriveLetter     = ''
        GuidRestored    = $false
        Reason          = ''
    }

    $isUefi = ($Offline.Generation -eq 2)
    $idealSize = if ($isUefi) { 100MB } else { 500MB }

    # Recover the old EFI System Partition's identity before touching the disk. Reading the offline
    # registry needs the Windows volume mounted, and creating a partition is what unmounts it.
    $recorded = @()
    if ($isUefi) {
        $recorded = @(Get-RecordedEspIdentity -Offline $Offline)
        if ($recorded.Count -eq 0) {
            Add-OfflineRepairLog -Level Warning -Message 'The offline registry holds no cached partition table, so the original EFI System Partition GUID cannot be recovered.'
        }
    }

    # Use the whole extent when it is smaller than the ideal. An Azure Gen2 image ships a 99 MiB EFI
    # System Partition, so the gap left by a deleted one is just under 100 MB - falling back to a
    # fixed minimum here would leave part of that gap stranded for no reason.
    $newPartitionArgs = @{
        DiskNumber        = $Offline.DiskNumber
        AssignDriveLetter = $true
        ErrorAction       = 'Stop'
    }
    if ($FreeSpace -ge $idealSize) { $newPartitionArgs['Size'] = $idealSize }
    else { $newPartitionArgs['UseMaximumSize'] = $true }
    $size = if ($FreeSpace -ge $idealSize) { [UInt64]$idealSize } else { $FreeSpace }

    # Put the partition back exactly where the old one was when the registry says where that is and
    # the space is still free. A UEFI boot entry describes the partition by offset and length as well
    # as by GUID, so reproducing the original extent is the difference between a disk the firmware
    # recognises and one it does not.
    if ($isUefi -and $recorded.Count -gt 0) {
        $extent = Get-LargestFreeExtent -DiskNumber $Offline.DiskNumber
        $exact = @($recorded | Where-Object {
                $_.Length -gt 0 -and $_.StartingOffset -ge $extent.Start -and
                ($_.StartingOffset + $_.Length) -le ($extent.Start + $extent.Size)
            }) | Select-Object -First 1

        if ($exact) {
            $newPartitionArgs.Remove('UseMaximumSize')
            $newPartitionArgs['Offset'] = $exact.StartingOffset
            $newPartitionArgs['Size'] = $exact.Length
            $size = [UInt64]$exact.Length
            Add-OfflineRepairLog -Level Info -Message "Recreating the EFI System Partition at its recorded offset $($exact.StartingOffset), length $($exact.Length)."
        }
    }

    $partition = $null
    try {
        if ($isUefi) { $newPartitionArgs['GptType'] = $script:BasicDataGptType }

        $partition = @(New-Partition @newPartitionArgs) | Select-Object -First 1
        Add-OfflineRepairLog -Level Info -Message "Created partition $($partition.PartitionNumber) of $([math]::Round($size / 1MB, 0)) MB on disk $($Offline.DiskNumber)."
    }
    catch {
        $result.Reason = "Could not create the system partition: $($_.Exception.Message)"
        return $result
    }

    $result.PartitionNumber = $partition.PartitionNumber

    $partition = Get-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -ErrorAction SilentlyContinue
    $letter = "$($partition.DriveLetter)"
    if ([string]::IsNullOrWhiteSpace($letter) -or $letter -eq "`0") {
        try {
            Add-PartitionAccessPath -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -AssignDriveLetter -ErrorAction Stop
            $partition = Get-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber
            $letter = "$($partition.DriveLetter)"
        }
        catch {
            $result.Reason = "The new partition was created but could not be given a drive letter: $($_.Exception.Message)"
            return $result
        }
    }
    $result.DriveLetter = "${letter}:"

    $fileSystem = if ($isUefi) { 'FAT32' } else { 'NTFS' }
    $label = if ($isUefi) { 'SYSTEM' } else { 'System Reserved' }
    try {
        Format-Volume -DriveLetter $letter -FileSystem $fileSystem -NewFileSystemLabel $label -Force -Confirm:$false -ErrorAction Stop | Out-Null
        Add-OfflineRepairLog -Level Info -Message "Formatted ${letter}: as $fileSystem, label '$label'."
    }
    catch {
        $result.Reason = "Could not format the new system partition as $fileSystem : $($_.Exception.Message)"
        return $result
    }

    if (-not $isUefi) {
        try {
            foreach ($other in @(Get-Partition -DiskNumber $Offline.DiskNumber -ErrorAction SilentlyContinue)) {
                if ($other.PartitionNumber -eq $partition.PartitionNumber -or -not $other.IsActive) { continue }
                Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $other.PartitionNumber -IsActive $false -ErrorAction Stop
                Add-OfflineRepairLog -Level Info -Message "Cleared the Active flag from partition $($other.PartitionNumber)."
            }
            Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -IsActive $true -ErrorAction Stop
            Add-OfflineRepairLog -Level Info -Message "Set the Active flag on partition $($partition.PartitionNumber)."
        }
        catch {
            $result.Reason = "Could not set the Active flag on the new system partition: $($_.Exception.Message)"
            return $result
        }
    }

    $firmware = if ($isUefi) { 'UEFI' } else { 'BIOS' }
    $bcdbootArgs = @("$($Offline.WindowsPath)", '/s', $result.DriveLetter, '/f', $firmware)
    Add-OfflineRepairLog -Level Info -Message "Running: bcdboot $($bcdbootArgs -join ' ')"

    $output = & bcdboot.exe @bcdbootArgs 2>&1
    $exitCode = $LASTEXITCODE
    foreach ($line in @($output)) {
        if (-not [string]::IsNullOrWhiteSpace("$line")) { Add-OfflineRepairLog -Level Info -Message "  bcdboot: $line" }
    }

    if ($exitCode -ne 0) {
        $result.Reason = "bcdboot failed with exit code $exitCode, so the new partition holds no boot files."
        return $result
    }

    if ($isUefi) {
        try {
            Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -GptType $script:EspGptType -ErrorAction Stop
            Add-OfflineRepairLog -Level Info -Message "Set the EFI System Partition type on partition $($partition.PartitionNumber)."
        }
        catch {
            $result.Reason = "The partition was created and populated but its GPT type could not be set to EFI System Partition: $($_.Exception.Message). UEFI will not consider it bootable."
            return $result
        }

        # Last, because it edits the partition table by hand and every step above rewrites it.
        $placed = Get-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $partition.PartitionNumber -ErrorAction SilentlyContinue
        if ($placed) {
            $result.GuidRestored = Restore-EspUniqueId -Offline $Offline -PartitionOffset ([UInt64]$placed.Offset) -Recorded $recorded
        }
    }

    $result.Success = $true
    return $result
}

function Repair-EspFileSystem {
    <#
    .SYNOPSIS
        Formats an existing but unreadable EFI System Partition and repopulates it with bcdboot.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)][int]$PartitionNumber
    )

    $result = [PSCustomObject]@{ Success = $false; DriveLetter = ''; Reason = '' }

    # The EFI System Partition type hides the volume from Windows, so it has to wear the basic data
    # type while it is formatted and populated.
    try {
        Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $PartitionNumber -GptType $script:BasicDataGptType -ErrorAction Stop
        Add-PartitionAccessPath -DiskNumber $Offline.DiskNumber -PartitionNumber $PartitionNumber -AssignDriveLetter -ErrorAction SilentlyContinue
    }
    catch {
        $result.Reason = "Could not make the EFI System Partition writable: $($_.Exception.Message)"
        return $result
    }

    $partition = Get-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $PartitionNumber -ErrorAction SilentlyContinue
    $letter = "$($partition.DriveLetter)"
    if ([string]::IsNullOrWhiteSpace($letter) -or $letter -eq "`0") {
        $result.Reason = 'The EFI System Partition could not be given a drive letter, so it cannot be formatted here.'
        return $result
    }
    $result.DriveLetter = "${letter}:"

    try {
        Format-Volume -DriveLetter $letter -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Force -Confirm:$false -ErrorAction Stop | Out-Null
        Add-OfflineRepairLog -Level Info -Message "Formatted the EFI System Partition (${letter}:) as FAT32."
    }
    catch {
        $result.Reason = "Could not format the EFI System Partition as FAT32: $($_.Exception.Message)"
        return $result
    }

    $bcdbootArgs = @("$($Offline.WindowsPath)", '/s', $result.DriveLetter, '/f', 'UEFI')
    Add-OfflineRepairLog -Level Info -Message "Running: bcdboot $($bcdbootArgs -join ' ')"

    $output = & bcdboot.exe @bcdbootArgs 2>&1
    $exitCode = $LASTEXITCODE
    foreach ($line in @($output)) {
        if (-not [string]::IsNullOrWhiteSpace("$line")) { Add-OfflineRepairLog -Level Info -Message "  bcdboot: $line" }
    }
    if ($exitCode -ne 0) {
        $result.Reason = "bcdboot failed with exit code $exitCode, so the EFI System Partition holds no boot files."
        return $result
    }

    try {
        Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $PartitionNumber -GptType $script:EspGptType -ErrorAction Stop
        Add-OfflineRepairLog -Level Info -Message "Restored the EFI System Partition type on partition $PartitionNumber."
    }
    catch {
        $result.Reason = "The partition was formatted and populated but its GPT type could not be set back to EFI System Partition: $($_.Exception.Message)."
        return $result
    }

    $result.Success = $true
    return $result
}

function Get-UnreadablePartitionTable {
    <#
    .SYNOPSIS
        Finds an attached disk whose partition table Windows refuses to read because sector 0 has
        lost its 0x55AA signature.

    .DESCRIPTION
        Windows reports such a disk as RAW and enumerates no partitions at all, so the offline
        Windows installation cannot be found and every later check has nothing to look at. The
        signature is two bytes; the partition entries behind it are normally still intact. A disk
        is reported only when those entries are still plausible, so a genuinely blank disk that is
        RAW because nobody ever partitioned it is left alone.

        A disk that is RAW cannot be hosting the running rescue Windows, so there is nothing to
        exclude here.

    .OUTPUTS
        One object per candidate disk, or nothing.
    #>

    foreach ($disk in @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.PartitionStyle -eq 'RAW' } | Sort-Object Number)) {
        $sector = $null
        try { $sector = Read-RawDiskSector -DiskNumber $disk.Number -ByteOffset 0 -Length 512 } catch { continue }
        if (-not $sector) { continue }
        if ($sector[510] -eq 0x55 -and $sector[511] -eq 0xAA) { continue }

        $diskSectors = [UInt64]($disk.Size / 512)
        $entries = 0
        $plausible = $true

        for ($index = 0; $index -lt 4; $index++) {
            $at = 446 + ($index * 16)
            if ($sector[$at + 4] -eq 0) { continue }

            $entries++
            $startLba = [UInt64][BitConverter]::ToUInt32($sector, $at + 8)
            $count = [UInt64][BitConverter]::ToUInt32($sector, $at + 12)
            if ($startLba -lt 1 -or $count -lt 1 -or ($startLba + $count) -gt $diskSectors) { $plausible = $false }
        }

        if ($entries -gt 0 -and $plausible) {
            [PSCustomObject]@{ DiskNumber = $disk.Number; Entries = $entries; Sector = $sector }
        }
    }
}

function Restore-PartitionTableSignature {
    <#
    .SYNOPSIS
        Writes the 0x55AA signature back into sector 0 so Windows can read the partition table.

    .DESCRIPTION
        Self validating: the disk is rescanned afterwards and the original sector is put back if the
        partitions still do not appear, because a signature over a table Windows cannot use is not a
        repair. Only the two signature bytes are touched; the partition entries are left exactly as
        they are found.

    .OUTPUTS
        $true when the disk enumerates partitions afterwards.
    #>
    param([Parameter(Mandatory = $true)][int]$DiskNumber)

    $original = Read-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Length 512
    $patched = [byte[]]::new(512)
    [Array]::Copy($original, $patched, 512)
    $patched[510] = 0x55
    $patched[511] = 0xAA

    if (-not (Set-DiskOnlineState -DiskNumber $DiskNumber -Online $false)) {
        Add-OfflineRepairLog -Level Error -Message "Disk $DiskNumber could not be taken offline, so the partition table signature was left alone."
        return $false
    }

    try {
        Write-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Data $patched
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message "Writing the partition table signature failed: $($_.Exception.Message)"
        [void](Set-DiskOnlineState -DiskNumber $DiskNumber -Online $true)
        return $false
    }

    [void](Set-DiskOnlineState -DiskNumber $DiskNumber -Online $true)
    [void](Update-Disk -Number $DiskNumber -ErrorAction SilentlyContinue)

    $partitions = @(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue)
    if ($partitions.Count -gt 0) {
        Add-OfflineRepairLog -Level Info -Message "Restored the 0x55AA signature in sector 0 of disk $DiskNumber; Windows now reads $($partitions.Count) partition(s) from it."
        return $true
    }

    Add-OfflineRepairLog -Level Warning -Message "Disk $DiskNumber still shows no partitions with the signature in place, so the original sector 0 was put back. The partition table itself is damaged, not just its signature."
    if (Set-DiskOnlineState -DiskNumber $DiskNumber -Online $false) {
        try { Write-RawDiskSector -DiskNumber $DiskNumber -ByteOffset 0 -Data $original }
        catch { Add-OfflineRepairLog -Level Error -Message "Putting the original sector 0 back failed: $($_.Exception.Message)" }
        [void](Set-DiskOnlineState -DiskNumber $DiskNumber -Online $true)
    }
    return $false
}

function Get-RevertManifestPath {
    param([Parameter(Mandatory = $true)][string]$Drive)
    return (Join-OfflinePath -Root $Drive -ChildPath "$scriptName-revert.json")
}

function Save-RevertManifest {
    <#
    .SYNOPSIS
        Records which sectors were backed up and what was created, so revert does not have to guess.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Backup,
        [Parameter(Mandatory = $false)][int]$CreatedPartition = 0
    )

    $manifestPath = Get-RevertManifestPath -Drive $Offline.WindowsDrive
    $manifest = [PSCustomObject]@{
        Script           = $scriptName
        Timestamp        = $scriptStartTime
        DiskNumber       = $Offline.DiskNumber
        Generation       = $Offline.Generation
        MbrBackupPath    = $Backup.MbrPath
        VbrBackupPath    = $Backup.VbrPath
        VbrOffset        = [string]$Backup.VbrOffset
        CreatedPartition = $CreatedPartition
    }

    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Add-OfflineRepairLog -Level Info -Message "Wrote the revert manifest to $manifestPath."
}

function Invoke-Revert {
    <#
    .SYNOPSIS
        Writes the backed up sectors back to the disk.
    #>
    param([Parameter(Mandatory = $true)]$Offline)

    $manifestPath = Get-RevertManifestPath -Drive $Offline.WindowsDrive
    if (-not (Test-OfflinePath $manifestPath)) {
        Add-OfflineRepairLog -Level Warning -Message "No revert manifest was found at $manifestPath. There is nothing recorded to put back."
        return $false
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    $writes = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($manifest.MbrBackupPath -and (Test-OfflinePath $manifest.MbrBackupPath)) {
        [void]$writes.Add([PSCustomObject]@{ Offset = [UInt64]0; Path = $manifest.MbrBackupPath; Label = 'sector 0' })
    }
    if ($manifest.VbrBackupPath -and (Test-OfflinePath $manifest.VbrBackupPath)) {
        [void]$writes.Add([PSCustomObject]@{ Offset = [UInt64]$manifest.VbrOffset; Path = $manifest.VbrBackupPath; Label = "the volume boot record at offset $($manifest.VbrOffset)" })
    }

    if ($writes.Count -eq 0) {
        Add-OfflineRepairLog -Level Warning -Message 'The manifest records no sector backup that is still available, so there is nothing to put back.'
        return $false
    }

    # The backups live on the disk that is about to be taken offline, which unmounts the volume
    # holding them, so they are read into memory while the volume is still there to read from.
    $pending = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($write in $writes) {
        $bytes = [System.IO.File]::ReadAllBytes($write.Path)
        if ($bytes.Length -ne 512) {
            Add-OfflineRepairLog -Level Warning -Message "$($write.Path) is $($bytes.Length) bytes, not a 512 byte sector image. Skipped."
            continue
        }
        [void]$pending.Add([PSCustomObject]@{ Offset = $write.Offset; Path = $write.Path; Label = $write.Label; Data = $bytes })
    }

    if ($pending.Count -eq 0) {
        Add-OfflineRepairLog -Level Warning -Message 'None of the recorded backups is a usable sector image, so there is nothing to put back.'
        return $false
    }

    if ($manifest.CreatedPartition -gt 0) {
        if ($manifest.Generation -eq 2) {
            Add-OfflineRepairLog -Level Warning -Message "This script created EFI System Partition $($manifest.CreatedPartition). A GPT partition table is not carried in the sectors that were backed up, so revert leaves it in place. Remove it by hand if that is wanted."
        }
        else {
            Add-OfflineRepairLog -Level Warning -Message "This script created system partition $($manifest.CreatedPartition). Writing sector 0 back also restores the partition table as it was, which removes that partition and returns the disk to its earlier unbootable state."
        }
    }

    if (-not (Set-DiskOnlineState -DiskNumber $manifest.DiskNumber -Online $false)) {
        Add-OfflineRepairLog -Level Error -Message "Disk $($manifest.DiskNumber) could not be taken offline, so nothing was written back."
        return $false
    }

    $reverted = $false
    try {
        foreach ($write in $pending) {
            Write-RawDiskSector -DiskNumber $manifest.DiskNumber -ByteOffset $write.Offset -Data $write.Data
            Add-OfflineRepairLog -Level Info -Message "Restored $($write.Label) from $($write.Path)."
            $reverted = $true
        }
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message "Writing the backed up sectors back failed: $($_.Exception.Message)"
    }
    finally {
        [void](Set-DiskOnlineState -DiskNumber $manifest.DiskNumber -Online $true)
    }

    return $reverted
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

try {
    # Sector 0 is checked before anything else looks for Windows: a disk whose partition table
    # signature is gone is reported by Windows as RAW with no partitions at all, so the offline
    # installation cannot be found and the run would end with a misleading "no Windows here".
    foreach ($unreadable in @(Get-UnreadablePartitionTable)) {
        Log-Output "  [FIXABLE] Disk $($unreadable.DiskNumber) has a partition table Windows cannot read, because sector 0 has lost its 0x55AA signature. The firmware stops at `"Missing operating system`" and no tool can see the volumes, although the $($unreadable.Entries) partition entries behind the signature are still intact. The two signature bytes will be written back." | Tee-Object -FilePath $logFile -Append

        if ($isDetectOnly) {
            Log-Output 'Detect only: found 1 issue(s), 1 of which this script can repair. No changes were made.' | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }
        if ($isRevert) { continue }

        $signatureRestored = Restore-PartitionTableSignature -DiskNumber $unreadable.DiskNumber
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (-not $signatureRestored) {
            Log-Error "Disk $($unreadable.DiskNumber) still has no readable partition table. See the detail log." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }
    }

    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber)), Gen$($offline.Generation) / $($offline.PartitionStyle)." | Tee-Object -FilePath $logFile -Append

    if ($offline.PartitionStyle -notin @('MBR', 'GPT')) {
        Log-Error "Disk $($offline.DiskNumber) has partition style '$($offline.PartitionStyle)'. This script only understands MBR and GPT disks." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    if ($isRevert) {
        $reverted = Invoke-Revert -Offline $offline
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($reverted) {
            Log-Output 'Revert complete. The boot sectors this script backed up have been written back.' | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }
        Log-Error 'Revert found nothing it could put back. See the detail log.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $detected = Get-AllFinding -Offline $offline
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($detected.Resolved.Partition) {
        Log-Info "System partition: partition $($detected.Resolved.Partition.PartitionNumber) at offset $($detected.Resolved.Partition.Offset) ($($detected.Resolved.Evidence)), filesystem $($detected.State.FileSystem)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning "No system partition could be identified on disk $($offline.DiskNumber)." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($detected.Findings)
    $repairable = @($findings | Where-Object { $_.Repairable })

    if ($isDetectOnly) {
        if ($findings.Count -eq 0) {
            Log-Output 'Detect only: the system partition and its boot sectors are consistent with this disk. No changes were made.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            foreach ($finding in $findings) {
                Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
            }
            # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
            # so a summary printed first is the first thing a long run loses.
            Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0) {
        Log-Output 'No system partition fault was found. The firmware can reach a boot partition on this disk. If the VM still does not boot, the fault is in the boot configuration inside it: use run id win-fix-bcd.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    foreach ($finding in $findings) {
        Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($repairable.Count -eq 0) {
        Log-Error "Found $($findings.Count) issue(s), none of which this script can repair. See the messages above." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # Back up before the first write. The Windows volume has to be mounted for this, so it happens
    # while the disk is still online and before anything is changed.
    $backup = Save-BootSectorBackup -Offline $offline -State $detected.State
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $createdPartition = 0
    $partitionRepairRan = $false

    foreach ($finding in @($repairable | Where-Object { $_.Cause -eq 'NoBootPartition' })) {
        $created = New-BootPartition -Offline $offline -FreeSpace ([UInt64]$finding.Data)
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (-not $created.Success) {
            Log-Error $created.Reason | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }

        $finding.Repaired = $true
        $createdPartition = $created.PartitionNumber
        $partitionRepairRan = $true
        Log-Output "Created system partition $($created.PartitionNumber) ($($created.DriveLetter)) and populated it with bcdboot." | Tee-Object -FilePath $logFile -Append

        if ($offline.Generation -eq 2 -and -not $created.GuidRestored) {
            Log-Warning ('The new EFI System Partition could not be given the GUID the old one had. A Gen2 VM boots from a ' +
                'UEFI boot entry that names the partition by GUID, so the firmware may report "Unknown Device" and refuse to ' +
                'start even though the partition is correct. See the detail log for what was found.') | Tee-Object -FilePath $logFile -Append
        }
    }

    foreach ($finding in @($repairable | Where-Object { $_.Cause -eq 'EspNotFormatted' })) {
        $repaired = Repair-EspFileSystem -Offline $offline -PartitionNumber ([int]$finding.Data)
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (-not $repaired.Success) {
            Log-Error $repaired.Reason | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }

        $finding.Repaired = $true
        $partitionRepairRan = $true
        Log-Output 'Reformatted the EFI System Partition and repopulated it with bcdboot.' | Tee-Object -FilePath $logFile -Append
    }

    # Creating or formatting a partition rewrites the partition table and the boot sectors of the new
    # partition, so everything the first pass read is now stale. The sector tier assembles its writes
    # from a sector image held in memory, and writing the pre-repair image back would undo the
    # partition that was just created. Read the disk again and work from what is on it now.
    $sectorSource = $detected
    if ($partitionRepairRan) {
        Log-Info 'Re-reading the disk after the partition change, so the boot sector repair works from the partition table that is there now rather than the one read before it.' | Tee-Object -FilePath $logFile -Append
        $sectorSource = Get-AllFinding -Offline $offline
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    $sectorOk = Invoke-SectorRepair -Offline $offline -State $sectorSource.State -Findings $sectorSource.Findings
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if (-not $sectorOk) {
        Log-Error 'Writing the repaired boot sectors did not complete. The disk is back online and the original sectors are available in the backup files listed above.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Save-RevertManifest -Offline $offline -Backup $backup -CreatedPartition $createdPartition
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Verify by detecting again. The repair is only finished when the disk itself says so.
    $after = Get-AllFinding -Offline $offline
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillBroken = @($after.Findings | Where-Object { $_.Repairable })
    $manualOnly = @($after.Findings | Where-Object { -not $_.Repairable })

    if ($stillBroken.Count -gt 0) {
        Log-Error "Repair ran but $($stillBroken.Count) issue(s) are still present:" | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $stillBroken) { Log-Error "  $($finding.Message)" | Tee-Object -FilePath $logFile -Append }
        Log-Output "Run this script again with revert=true to write the original sectors back." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "System partition repaired: $($repairable.Count) issue(s) corrected and verified against the disk." | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $manualOnly) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    if ($backup.MbrPath) { Log-Output "The original sector 0 was kept at $($backup.MbrPath)." | Tee-Object -FilePath $logFile -Append }
    if ($backup.VbrPath) { Log-Output "The original volume boot record was kept at $($backup.VbrPath)." | Tee-Object -FilePath $logFile -Append }
    Log-Output "If the VM still does not boot, the boot configuration inside the partition is the next layer: use run id win-fix-bcd." | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
