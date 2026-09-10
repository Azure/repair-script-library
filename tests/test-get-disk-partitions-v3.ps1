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
