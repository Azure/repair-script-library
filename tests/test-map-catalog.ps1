# Catalogue tests for map.json — the public run-id contract.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-map-catalog.ps1

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$mapPath = Join-Path $repositoryRoot 'map.json'

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

# A run id that resolves to nothing, or to the wrong file, fails only at the moment an operator is
# running a repair against a broken VM. That is the worst possible time to discover it.
$catalog = @(Get-Content -LiteralPath $mapPath -Raw | ConvertFrom-Json)
Assert-True ($catalog.Count -gt 0) 'map.json must contain at least one entry.'

foreach ($entry in $catalog) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($entry.id)) 'Every entry needs an id.'
    Assert-True (-not [string]::IsNullOrWhiteSpace($entry.path)) "Entry '$($entry.id)' needs a path."
    Assert-True (-not [string]::IsNullOrWhiteSpace($entry.description)) "Entry '$($entry.id)' needs a description."
    Assert-True ($entry.path -notmatch '\\') "Entry '$($entry.id)' must use forward slashes; the path is used in a URL."
    Assert-True (Test-Path -LiteralPath (Join-Path $repositoryRoot $entry.path) -PathType Leaf) `
        "Entry '$($entry.id)' points at '$($entry.path)', which does not exist."
}

$duplicates = @($catalog | Group-Object id | Where-Object Count -gt 1)
Assert-True ($duplicates.Count -eq 0) "Duplicate run ids: $(($duplicates | ForEach-Object Name) -join ', ')."

# The extension resolves a run id to a path and then downloads the whole bundle. An entry whose OS
# does not match its directory sends a PowerShell script to a Linux guest, or the reverse.
foreach ($entry in $catalog) {
    if ($entry.path -like 'src/windows/*') {
        Assert-True ($entry.path -like '*.ps1') "Windows entry '$($entry.id)' must point at a .ps1 file."
    }
    elseif ($entry.path -like 'src/linux/*') {
        Assert-True ($entry.path -like '*.sh') "Linux entry '$($entry.id)' must point at a .sh file."
    }
    else {
        throw "Entry '$($entry.id)' is outside src/windows and src/linux: '$($entry.path)'."
    }
}

$nvmeRecovery = @($catalog | Where-Object id -eq 'win-enable-nvme-boot-driver')
Assert-True ($nvmeRecovery.Count -eq 1) 'win-enable-nvme-boot-driver must be registered exactly once.'
Assert-True ($nvmeRecovery[0].path -eq 'src/windows/win-enable-nvme-boot-driver.ps1') `
    'win-enable-nvme-boot-driver must point at the Windows recovery script.'
Assert-True ($nvmeRecovery[0].description -match '--run-on-repair') `
    'The recovery run id operates on an attached offline disk, so its description must say --run-on-repair.'

foreach ($detector in 'win-detect-nvme-readiness', 'linux-detect-nvme-readiness') {
    Assert-True (@($catalog | Where-Object id -eq $detector).Count -eq 1) "$detector must stay registered."
}

Write-Host "PASS: map.json catalogue — $($catalog.Count) entries, unique ids, existing paths, OS/extension agreement, NVMe run ids registered."
