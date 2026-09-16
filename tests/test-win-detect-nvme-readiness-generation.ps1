# Fixture tests for the generation detection added to win-detect-nvme-readiness.ps1.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-detect-nvme-readiness-generation.ps1

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-detect-nvme-readiness.ps1'

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    if ("$Expected" -ne "$Actual") { throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')" }
}

# Get-OfflineWindowsGeneration is the unit under test. Extracting it keeps the fixture to the disk
# cmdlets it actually calls, instead of standing up the whole hive-mounting script.
$ESP_GUID = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
$sourceText = Get-Content -LiteralPath $sourceScript -Raw
$match = [regex]::Match($sourceText, '(?s)function Get-OfflineWindowsGeneration \{.*?\n\}')
Assert-True $match.Success 'Get-OfflineWindowsGeneration must exist in the detector.'

function Invoke-GenerationFixture {
    Param([string]$PartitionStyle, [bool]$WithEsp, [switch]$NoPartition, [switch]$NoDisk)

    $scriptText = @"
function Log-Output { Param([string]`$Message) }
function Log-Warning { Param([string]`$Message) }
function Get-Partition {
    Param([string]`$DriveLetter, [int]`$DiskNumber)
    if ($([bool]$NoPartition ? '$true' : '$false')) { return `$null }
    if (`$PSBoundParameters.ContainsKey('DriveLetter')) { return [pscustomobject]@{ DiskNumber = 1 } }
    `$partitions = @([pscustomobject]@{ GptType = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' })
    if ($([bool]$WithEsp ? '$true' : '$false')) {
        `$partitions += [pscustomobject]@{ GptType = '$ESP_GUID' }
    }
    return `$partitions
}
function Get-Disk {
    Param([int]`$Number)
    if ($([bool]$NoDisk ? '$true' : '$false')) { return `$null }
    return [pscustomobject]@{ PartitionStyle = '$PartitionStyle' }
}

$($match.Value)

Get-OfflineWindowsGeneration -DriveLetter 'F' | ConvertTo-Json -Compress
"@

    $output = pwsh -NoProfile -Command $scriptText
    return ($output | ConvertFrom-Json)
}

# A Generation 2 guest: GPT with an EFI system partition. This is the only shape an NVMe-capable
# size can boot, so it is the only shape the NVMe repair applies to.
$gen2 = Invoke-GenerationFixture -PartitionStyle 'GPT' -WithEsp $true
Assert-Equal 'GPT' $gen2.partitionStyle 'A GPT disk should report GPT.'
Assert-Equal $true $gen2.efiSystemPartitionPresent 'The EFI system partition should be detected by its UEFI GUID.'
Assert-Equal 'UEFI' $gen2.firmwareType 'GPT plus an ESP means UEFI firmware.'
Assert-Equal 'V2' $gen2.hyperVGeneration 'GPT plus an ESP is a Generation 2 installation.'

# A Generation 1 guest: MBR. No stornvme value can make this boot on an NVMe controller.
$gen1 = Invoke-GenerationFixture -PartitionStyle 'MBR' -WithEsp $false
Assert-Equal 'MBR' $gen1.partitionStyle 'An MBR disk should report MBR.'
Assert-Equal 'BIOS' $gen1.firmwareType 'MBR means BIOS firmware.'
Assert-Equal 'V1' $gen1.hyperVGeneration 'An MBR installation is Generation 1.'

# GPT without an ESP is not a bootable Generation 2 layout, and guessing either way would be wrong:
# claiming V2 invites a repair that cannot work, claiming V1 invites an unnecessary conversion.
$gptNoEsp = Invoke-GenerationFixture -PartitionStyle 'GPT' -WithEsp $false
Assert-Equal 'GPT' $gptNoEsp.partitionStyle 'Partition style should still be reported.'
Assert-Equal $false $gptNoEsp.efiSystemPartitionPresent 'No ESP should be reported as absent, not assumed.'
Assert-Equal 'Unknown' $gptNoEsp.hyperVGeneration 'GPT without an ESP must not be claimed as Generation 2.'

# The detector runs against whatever disk is attached. Neither missing partitions nor a missing disk
# may throw: the rest of the stornvme evidence is still worth collecting.
$noPartition = Invoke-GenerationFixture -PartitionStyle 'GPT' -WithEsp $true -NoPartition
Assert-Equal 'Unknown' $noPartition.hyperVGeneration 'An unreadable partition must report Unknown, not fail.'
Assert-Equal 'Unknown' $noPartition.partitionStyle 'An unreadable partition must not invent a partition style.'

$noDisk = Invoke-GenerationFixture -PartitionStyle 'GPT' -WithEsp $true -NoDisk
Assert-Equal 'Unknown' $noDisk.hyperVGeneration 'An unreadable disk must report Unknown, not fail.'

# Contract assertions against the script text itself.
Assert-True ($sourceText -match 'GEN1_TO_GEN2_CONVERSION_REQUIRED') `
    'The detector must emit the GEN1_TO_GEN2_CONVERSION_REQUIRED signature.'
Assert-True ($sourceText -match "schemaVersion\s*=\s*'1\.1'") `
    'Adding fields to the evidence record requires a schema version bump.'
Assert-True ($sourceText -match 'conversionRequired\s*=\s*\(\$generation\.hyperVGeneration -eq ''V1''\)') `
    'conversionRequired must be derived from the detected generation.'
Assert-True ($sourceText -match '-and \(-not \$finding\.conversionRequired\)') `
    'A Generation 1 guest must never report bootReadyForNvme = true.'
Assert-True ($match.Value -match [regex]::Escape($ESP_GUID)) `
    'The ESP must be matched by the UEFI-specification GUID, not by a partition label or size heuristic.'

Write-Host 'PASS: win-detect-nvme-readiness generation detection — Gen 2, Gen 1, ambiguous GPT, unreadable disk/partition, and the signature/schema contract.'
