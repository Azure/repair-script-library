# Standalone regression test for Azure resource-disk exclusion in Get-Disk-Partitions-v3.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-get-disk-partitions-v3.ps1

Param(
    [string]$HelperPath = "$PSScriptRoot/../src/windows/common/helpers/Get-Disk-Partitions-v3.ps1"
)

$ErrorActionPreference = 'Stop'

$resourceDisk = [PSCustomObject]@{
    Number = 1
    BusType = 'SAS'
    Model = 'Virtual Disk'
    IsBoot = $false
    IsSystem = $false
    IsOffline = $false
    IsReadOnly = $false
}
$osDisk = [PSCustomObject]@{
    Number = 2
    BusType = 'SAS'
    Model = 'Virtual Disk'
    IsBoot = $false
    IsSystem = $false
    IsOffline = $false
    IsReadOnly = $false
}
$resourcePartition = [PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 1; DriveLetter = 'D' }
$osPartition = [PSCustomObject]@{ DiskNumber = 2; PartitionNumber = 1; DriveLetter = 'F' }

function Get-Disk {
    [CmdletBinding()]
    Param([int]$Number)

    if ($PSBoundParameters.ContainsKey('Number')) {
        return @($resourceDisk, $osDisk) | Where-Object Number -eq $Number
    }

    return @($resourceDisk, $osDisk)
}

function Get-Partition {
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true)][int]$DiskNumber)

    if ($DiskNumber -eq 1) { return $resourcePartition }
    if ($DiskNumber -eq 2) { return $osPartition }
}

function Get-Volume {
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true)][PSObject]$Partition)

    if ($Partition.DiskNumber -eq 1) {
        return [PSCustomObject]@{ FileSystemLabel = 'Temporary Storage' }
    }

    return [PSCustomObject]@{ FileSystemLabel = 'Operating System' }
}

function Set-Disk {
    [CmdletBinding()]
    Param([bool]$IsOffline, [bool]$IsReadOnly, [Parameter(ValueFromPipeline = $true)]$InputObject)
    Process { return }
}

. $HelperPath

$result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0)
if ($result.Count -ne 1) {
    throw "Expected one repair target after excluding the SAS resource disk; found $($result.Count)."
}
if ($result[0].DiskNumber -ne 2 -or $result[0].DriveLetter -ne 'F') {
    throw "Expected only OS partition F: on disk 2; found $($result | ConvertTo-Json -Compress)."
}

Write-Host 'PASS: SAS resource disk with a scalar partition result is excluded; OS disk remains.'

# -ReadOnly: detection-only callers must never make the attached OS disk writable.
$script:setDiskCalls = @()
$script:readOnlyFlagSticks = $true

function Set-Disk {
    [CmdletBinding()]
    Param([Nullable[bool]]$IsOffline, [Nullable[bool]]$IsReadOnly, [Parameter(ValueFromPipeline = $true)]$InputObject)
    Process {
        if ($PSBoundParameters.ContainsKey('IsReadOnly')) {
            $script:setDiskCalls += "disk$($InputObject.Number):IsReadOnly=$IsReadOnly"
            if ($script:readOnlyFlagSticks) { $InputObject.IsReadOnly = $IsReadOnly }
        }
        if ($PSBoundParameters.ContainsKey('IsOffline')) {
            $script:setDiskCalls += "disk$($InputObject.Number):IsOffline=$IsOffline"
            if ($script:onlineSticks -or $IsOffline) { $InputObject.IsOffline = $IsOffline }
        }
    }
}
$script:onlineSticks = $true
$osDisk | Add-Member -NotePropertyName Guid -NotePropertyValue '{os-copy}'
$osDisk | Add-Member -NotePropertyName OfflineReason -NotePropertyValue ''
$resourceDisk | Add-Member -NotePropertyName Guid -NotePropertyValue '{resource}'

function Reset-OfflineOsDisk {
    $osDisk.IsOffline = $true
    $osDisk.IsReadOnly = $false
    $osDisk.Guid = '{os-copy}'
    $osDisk.OfflineReason = ''
    $script:setDiskCalls = @()
    $global:DiskPartitionsV3ReadOnlyChanges = @()
}

Reset-OfflineOsDisk
$result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0 -ReadOnly)
if ($result.Count -ne 1 -or $result[0].DriveLetter -ne 'F') {
    throw "ReadOnly: expected OS partition F: to be returned; found $($result | ConvertTo-Json -Compress)."
}
$expectedCalls = 'disk2:IsReadOnly=True,disk2:IsOffline=False'
if (($script:setDiskCalls -join ',') -ne $expectedCalls) {
    throw "ReadOnly: the disk must be marked read-only before it is onlined. Expected '$expectedCalls', got '$($script:setDiskCalls -join ',')'."
}
if (-not $osDisk.IsReadOnly) { throw 'ReadOnly: the OS disk must remain read-only.' }
Write-Host 'PASS: -ReadOnly marks an offline disk read-only before onlining it.'

$script:setDiskCalls = @()
$failed = @(Restore-Disk-Partitions-v3)
if (($script:setDiskCalls -join ',') -ne 'disk2:IsOffline=True,disk2:IsReadOnly=False') {
    throw "Restore: the disk must go offline before read-only is cleared; calls were '$($script:setDiskCalls -join ',')'."
}
if ($failed.Count -or -not $osDisk.IsOffline -or $osDisk.IsReadOnly) { throw 'Restore: the disk must end offline and writable, as it was attached.' }
if (@($global:DiskPartitionsV3ReadOnlyChanges).Count) { throw 'Restore: the change list must be cleared.' }
Write-Host 'PASS: Restore-Disk-Partitions-v3 returns the disk offline first, then clears read-only.'

foreach ($collision in @('reason', 'same-id')) {
    Reset-OfflineOsDisk
    if ($collision -eq 'reason') { $osDisk.OfflineReason = 'Collision' } else { $osDisk.Guid = '{resource}' }
    $result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0 -ReadOnly 3>$null)
    if ($result.Count -ne 0 -or $script:setDiskCalls.Count -ne 0) {
        throw "ReadOnly ($collision): a disk-ID collision must be skipped without any Set-Disk call; calls were '$($script:setDiskCalls -join ',')'."
    }
}
Write-Host 'PASS: -ReadOnly leaves a disk with a disk-ID collision untouched (OfflineReason and matching GUID).'

Reset-OfflineOsDisk
$script:onlineSticks = $false
$result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0 -ReadOnly 3>$null)
$script:onlineSticks = $true
if ($result.Count -ne 0 -or $osDisk.IsReadOnly -or @($global:DiskPartitionsV3ReadOnlyChanges).Count) {
    throw "ReadOnly: a disk that does not come online must get its read-only flag back; calls were '$($script:setDiskCalls -join ',')'."
}
Write-Host 'PASS: -ReadOnly reverts its read-only flag when the disk does not come online.'

Reset-OfflineOsDisk
$script:readOnlyFlagSticks = $false
$result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0 -ReadOnly)
$script:readOnlyFlagSticks = $true
if ($result.Count -ne 0) { throw 'ReadOnly: a disk whose read-only flag did not stick must be skipped.' }
if ($script:setDiskCalls -contains 'disk2:IsOffline=False') { throw 'ReadOnly: a disk that is not read-only must never be brought online.' }
if (-not $osDisk.IsOffline) { throw 'ReadOnly: the disk must stay offline.' }
Write-Host 'PASS: -ReadOnly leaves a disk offline when it cannot be made read-only.'

Reset-OfflineOsDisk
$osDisk.IsReadOnly = $true
$result = @(Get-Disk-Partitions-v3 -DriveLetterTimeoutSeconds 0)
if ($script:setDiskCalls -notcontains 'disk2:IsReadOnly=False' -or $result.Count -ne 1) {
    throw "Default mode must keep bringing disks online read-write; calls were '$($script:setDiskCalls -join ',')'."
}
Write-Host 'PASS: default mode still brings an offline, read-only disk online read-write.'
