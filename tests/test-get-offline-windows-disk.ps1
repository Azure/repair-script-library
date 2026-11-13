# Standalone fixture tests for the resource-disk classification in Get-OfflineWindowsDisk.ps1.
# Run from the repository root on Windows:
#   pwsh -NoProfile -File ./tests/test-get-offline-windows-disk.ps1
#
# Provisioning writes DATALOSS_WARNING_README.txt to whatever volume is D:. On a rescue VM size
# without a resource disk that is a partition of the attached broken OS disk, so the marker alone
# must not classify a disk as the resource disk. A disk that also holds Windows content is the OS
# disk; a disk with the marker and no Windows content is still the resource disk and stays excluded.
#
# The shipped helper is dot-sourced exactly as the repair scripts load it. Get-Disk, Get-Partition
# and Get-Volume are replaced with stubs that describe the attached disks, and every volume root is
# a real temporary folder, so the marker and Windows-evidence probes run against real files.

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$helperScript = Join-Path $repositoryRoot 'src/windows/common/helpers/Get-OfflineWindowsDisk.ps1'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rsl-offline-windows-disk-$([guid]::NewGuid())"
$script:Passed = 0

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:Passed++
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', found '$Actual'." }
    $script:Passed++
}

function Assert-Throws {
    Param([scriptblock]$ScriptBlock, [string]$Pattern, [string]$Message)
    try { & $ScriptBlock }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw "$Message Threw '$($_.Exception.Message)', which does not match '$Pattern'." }
        $script:Passed++
        return
    }
    throw "$Message It did not throw."
}

. $helperScript

# Attached disks and their partitions, keyed by disk number. Each partition carries the volumes
# Get-Volume returns for it.
$script:Disks = @()
$script:Partitions = @{}

function Get-Disk {
    [CmdletBinding()]
    Param([int]$Number = -1)
    if ($Number -ge 0) { return @($script:Disks | Where-Object { $_.Number -eq $Number }) }
    return $script:Disks
}

function Get-Partition {
    [CmdletBinding()]
    Param([int]$DiskNumber = -1, [string]$DriveLetter)
    # The rescue VM's own system drive lives on disk 0, which is never one of the fixture disks.
    if ($DriveLetter) { return [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 1 } }
    return @($script:Partitions[$DiskNumber])
}

function Get-Volume {
    [CmdletBinding()]
    Param([Parameter(ValueFromPipeline = $true)]$Partition)
    process { $Partition.FixtureVolume }
}

function Start-Sleep { Param([int]$Seconds) }
function Enter-OfflineNestedVmLifecycle { return [PSCustomObject]@{ Fixture = $true } }
function Exit-OfflineNestedVmLifecycle { Param($Lease) }
function Stop-NestedRepairVm { Param($VmId) return $null }
# Partition letter assignment comes after disk selection, so stopping here isolates the selection.
function Get-VolumeDriveLetterMap { throw 'FIXTURE: disk selection finished.' }

function New-FixtureDisk {
    Param([int]$Number)
    return [PSCustomObject]@{
        Number = $Number; BusType = 'SCSI'; IsBoot = $false; IsSystem = $false
        IsOffline = $false; IsReadOnly = $false; PartitionStyle = 'MBR'
    }
}

# Creates a partition whose volume root is a real folder holding the given relative files.
# -ByDriveLetter exposes the root through the volume's Path instead of the partition access path,
# which is how a partition with no access path but a mounted volume is seen.
function New-FixturePartition {
    Param([int]$DiskNumber, [int]$PartitionNumber, [string]$Label = '', [string[]]$File = @(), [switch]$ByVolumePath)
    $root = Join-Path $fixtureRoot "disk$DiskNumber-part$PartitionNumber"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    foreach ($relative in $File) {
        $path = Join-Path $root $relative
        New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
        Set-Content -LiteralPath $path -Value 'fixture'
    }
    $rootWithSlash = "$root\"
    $volume = [PSCustomObject]@{ FileSystemLabel = $Label; Path = $(if ($ByVolumePath) { $rootWithSlash } else { $null }); DriveLetter = $null }
    $partition = [PSCustomObject]@{
        DiskNumber = $DiskNumber; PartitionNumber = $PartitionNumber
        AccessPaths = @($(if (-not $ByVolumePath) { $rootWithSlash }))
        FixtureVolume = $volume
    }
    $script:Partitions[$DiskNumber] = @($script:Partitions[$DiskNumber]) + $partition | Where-Object { $_ }
    return $partition
}

function Reset-Fixture {
    $script:Disks = @()
    $script:Partitions = @{}
    Clear-OfflineRepairLog
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
}

function Get-LoggedText { return ((Get-OfflineRepairLog | ForEach-Object { "[$($_.Level)] $($_.Message)" }) -join "`n") }

$marker = 'DATALOSS_WARNING_README.txt'

try {
    # 1. Broken OS disk, Generation 1: System Reserved received D: during provisioning, so it has
    #    the warning file next to bootmgr and the BCD store, and Windows is on the next partition.
    Reset-Fixture
    $osDisk = New-FixtureDisk 1
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -Label 'System Reserved' -File @($marker, 'bootmgr', 'Boot\BCD')
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 2 -Label 'Windows' -File @('Windows\System32\config\SYSTEM')
    Assert-Equal $false (Test-TemporaryStorageDisk -Disk $osDisk) 'An OS disk with the warning file and boot files is not the resource disk.'
    $logged = Get-LoggedText
    Assert-True ($logged -match '\[Warning\] Disk 1 carries a resource-disk marker') 'The override is logged as a warning.'
    Assert-True ($logged -match [regex]::Escape($marker)) 'The warning names the marker that was found.'
    Assert-True ($logged -match 'bootmgr') 'The warning names the Windows evidence that overrode it.'

    # 2. The marker and the Windows evidence on different partitions still mean the OS disk.
    Reset-Fixture
    $osDisk = New-FixtureDisk 1
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -File @($marker)
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 2 -File @('Windows\System32\config\SYSTEM')
    Assert-Equal $false (Test-TemporaryStorageDisk -Disk $osDisk) 'Windows content on any partition of the disk overrides the marker.'

    # 3. Generation 2 OS disk whose EFI partition holds the marker and the UEFI BCD store.
    Reset-Fixture
    $osDisk = New-FixtureDisk 1
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -File @($marker, 'EFI\Microsoft\Boot\BCD') -ByVolumePath
    Assert-Equal $false (Test-TemporaryStorageDisk -Disk $osDisk) 'A UEFI boot partition with the marker is not the resource disk.'

    # 4. The 'Temporary Storage' label is a marker too, and Windows content overrides it the same way.
    Reset-Fixture
    $osDisk = New-FixtureDisk 1
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -Label 'Temporary Storage' -File @('Windows\System32\config\SYSTEM')
    Assert-Equal $false (Test-TemporaryStorageDisk -Disk $osDisk) 'A Temporary Storage label on a Windows volume does not make it the resource disk.'

    # 5. A real resource disk: the warning file and the label, no Windows content.
    Reset-Fixture
    $resourceDisk = New-FixtureDisk 2
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Temporary Storage' -File @($marker)
    Assert-Equal $true (Test-TemporaryStorageDisk -Disk $resourceDisk) 'A real resource disk is still recognised.'
    Assert-True (-not ((Get-LoggedText) -match 'carries a resource-disk marker')) 'A real resource disk logs no override.'

    # 6. A resource disk on a non-English image has a localized label, so only the file identifies it.
    Reset-Fixture
    $resourceDisk = New-FixtureDisk 2
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Stockage temporaire' -File @($marker) -ByVolumePath
    Assert-Equal $true (Test-TemporaryStorageDisk -Disk $resourceDisk) 'The language-independent warning file alone identifies the resource disk.'

    # 7. The English label alone identifies it as well.
    Reset-Fixture
    $resourceDisk = New-FixtureDisk 2
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Temporary Storage'
    Assert-Equal $true (Test-TemporaryStorageDisk -Disk $resourceDisk) 'The Temporary Storage label alone identifies the resource disk.'

    # 8. A data disk with neither marker is not the resource disk, and nothing is logged about it.
    Reset-Fixture
    $dataDisk = New-FixtureDisk 3
    $null = New-FixturePartition -DiskNumber 3 -PartitionNumber 1 -Label 'Data' -File @('readme.txt')
    Assert-Equal $false (Test-TemporaryStorageDisk -Disk $dataDisk) 'A plain data disk is not the resource disk.'
    Assert-Equal '' (Get-LoggedText) 'A plain data disk produces no resource-disk log.'

    # 9. Set-OfflineDisksOnline keeps the OS disk and excludes only the real resource disk.
    Reset-Fixture
    $script:Disks = @((New-FixtureDisk 1), (New-FixtureDisk 2), (New-FixtureDisk 3))
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -Label 'System Reserved' -File @($marker, 'bootmgr', 'Boot\BCD')
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 2 -File @('Windows\System32\config\SYSTEM')
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Temporary Storage' -File @($marker)
    $null = New-FixturePartition -DiskNumber 3 -PartitionNumber 1 -Label 'Data'
    $online = @(Set-OfflineDisksOnline)
    Assert-Equal '1,3' ($online -join ',') 'The OS disk and the data disk are online; the resource disk is left alone.'
    $logged = Get-LoggedText
    Assert-True ($logged -match 'Disk 2 is the Azure resource disk and is left untouched') 'The resource disk exclusion is logged.'
    Assert-True (-not ($logged -match 'Disk 1 is the Azure resource disk')) 'The OS disk is not reported as the resource disk.'

    # 10. Get-OfflineWindowsDisk selects the OS disk that carries the marker as a candidate.
    Reset-Fixture
    $script:Disks = @((New-FixtureDisk 1), (New-FixtureDisk 2))
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 1 -Label 'System Reserved' -File @($marker, 'bootmgr', 'Boot\BCD')
    $null = New-FixturePartition -DiskNumber 1 -PartitionNumber 2 -File @('Windows\System32\config\SYSTEM')
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Temporary Storage' -File @($marker)
    Assert-Throws { Get-OfflineWindowsDisk } '^FIXTURE: disk selection finished\.$' 'Discovery gets past disk selection with the OS disk.'
    $logged = Get-LoggedText
    Assert-True ($logged -match 'disk 2: it is the Azure resource disk') 'Discovery excludes the real resource disk.'
    Assert-True (-not ($logged -match 'disk 1:')) 'Discovery does not exclude the OS disk for any reason.'

    # 11. With only the resource disk attached, discovery fails and names the right reason. The
    #     resource disk is judged before the online check, because Set-OfflineDisksOnline never
    #     brings it online; testing online first would misreport it as "not confirmed online".
    Reset-Fixture
    $script:Disks = @((New-FixtureDisk 2))
    $null = New-FixturePartition -DiskNumber 2 -PartitionNumber 1 -Label 'Temporary Storage' -File @($marker)
    Assert-Throws { Get-OfflineWindowsDisk } 'No attached broken OS disk was found\..*disk 2: it is the Azure resource disk' 'Discovery reports the resource disk as the reason.'
    Assert-True (-not ((Get-LoggedText) -match 'disk 2: it was not confirmed online')) 'The resource disk is not misreported as an online failure.'

    Write-Output "PASS: $script:Passed assertions in test-get-offline-windows-disk.ps1"
}
finally {
    Clear-OfflineRepairLog
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
