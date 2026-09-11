# Standalone fixture tests for win-enable-nvme-boot-driver.ps1.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-enable-nvme-boot-driver.ps1

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-enable-nvme-boot-driver.ps1'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rsl-nvme-recovery-$([guid]::NewGuid())"
$fixtureScript = Join-Path $fixtureRoot 'src/windows/win-enable-nvme-boot-driver.ps1'
$originalPublic = $env:PUBLIC

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', found '$Actual'." }
}

function Copy-FixtureState {
    Param([hashtable]$State)
    $copy = [ordered]@{}
    foreach ($key in $State.Keys) { $copy[$key] = $State[$key] }
    return $copy
}

function Set-NvmeFixture {
    Param(
        [hashtable]$State,
        [bool]$DriverPresent = $true,
        [int]$CandidateCount = 1,
        [bool]$HiveReadable = $true
    )

    $global:NvmeFixture = @{
        State = Copy-FixtureState $State
        DriverPresent = $DriverPresent
        CandidateCount = $CandidateCount
        HiveReadable = $HiveReadable
        HiveActive = $false
        StrictCalls = 0
        ImportFails = $false
        Operations = [System.Collections.Generic.List[string]]::new()
        Backups = @{}
        LastBackup = $null
    }
    $global:LASTEXITCODE = 0
}

function Invoke-NvmeFixture {
    Param([hashtable]$Parameters = @{})
    Push-Location $fixtureRoot
    try {
        $output = @(& $fixtureScript @Parameters)
        return [PSCustomObject]@{ Status = $output[-1]; Output = ($output -join "`n") }
    }
    finally {
        Pop-Location
    }
}

function Get-HealthyState {
    return [ordered]@{
        Start = 0
        Type = 1
        ErrorControl = 3
        Group = 'SCSI miniport'
        ImagePath = 'system32\drivers\stornvme.sys'
        Sentinel = 'unchanged'
    }
}

function Assert-FixtureServicePath {
    Param([string]$Path)
    $expected = 'HKLM:\BROKENSYSTEM\ControlSet001\Services\stornvme'
    if (-not $Path.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Fixture observed registry access outside the strict stornvme target: '$Path'."
    }
}

try {
    $helperRoot = Join-Path $fixtureRoot 'src/windows/common/helpers'
    $setupRoot = Join-Path $fixtureRoot 'src/windows/common/setup'
    New-Item -Path (Split-Path $fixtureScript -Parent), $helperRoot, $setupRoot -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $sourceScript -Destination $fixtureScript
    $env:PUBLIC = $fixtureRoot

    @'
$STATUS_SUCCESS = 0
$STATUS_ERROR = 1
function Log-Output { Param([string]$Message) Write-Output $Message }
function Log-Info { Param([string]$Message) Write-Output $Message }
function Log-Warning { Param([string]$Message) Write-Output "WARNING: $Message" }
function Log-Error { Param([string]$Message) Write-Output "ERROR: $Message" }
'@ | Set-Content -LiteralPath (Join-Path $setupRoot 'init.ps1') -Encoding Utf8

    @'
function Join-OfflinePath { Param([string]$Root, [string]$ChildPath) return "$($Root.TrimEnd('\'))\$($ChildPath.TrimStart('\'))" }
function Test-OfflinePath { Param([string]$Path) return [bool]$global:NvmeFixture.DriverPresent }
function Assert-OfflineTarget {
    Param([string]$Path, [string]$Action)
    Assert-FixtureServicePath $Path
    [void]$global:NvmeFixture.Operations.Add("Assert:$Action")
    return $Path
}
function Write-OfflineRepairLog { }
function Get-OfflineHiveKeyState { Param([string]$HiveKey) return 'Present' }
'@ | Set-Content -LiteralPath (Join-Path $helperRoot 'OfflineRepairCommon.ps1') -Encoding Utf8

    @'
function Get-OfflineWindowsDisk {
    Param([string]$WindowsDrive)
    $count = $global:NvmeFixture.CandidateCount
    $candidates = @(for ($index = 0; $index -lt $count; $index++) { [PSCustomObject]@{ Drive = "$(if ($index -eq 0) { 'F' } else { 'G' }):" } })
    return [PSCustomObject]@{
        WindowsDrive = if ($WindowsDrive) { $WindowsDrive.TrimEnd(':') + ':' } else { 'F:' }
        WindowsPath = if ($WindowsDrive) { $WindowsDrive.TrimEnd(':') + ':\Windows' } else { 'F:\Windows' }
        Candidates = $candidates
    }
}
function Clear-OfflineDriveLetter { }
'@ | Set-Content -LiteralPath (Join-Path $helperRoot 'Get-OfflineWindowsDisk.ps1') -Encoding Utf8

    @'
function Invoke-WithHive {
    Param([string[]]$Hive, [scriptblock]$ScriptBlock)
    $global:NvmeFixture.HiveActive = $true
    try {
        if (-not $global:NvmeFixture.HiveReadable) { throw 'Fixture SYSTEM hive is unreadable.' }
        return & $ScriptBlock
    }
    finally {
        $global:NvmeFixture.HiveActive = $false
    }
}
function Get-OfflineSystemRootPath {
    Param([switch]$Strict)
    if (-not $Strict) { throw 'Fixture refused a non-strict control-set lookup.' }
    $global:NvmeFixture.StrictCalls++
    return 'HKLM:\BROKENSYSTEM\ControlSet001'
}
function Get-ItemProperty {
    Param([string]$LiteralPath, $ErrorAction)
    Assert-FixtureServicePath $LiteralPath
    return [PSCustomObject](Copy-FixtureState $global:NvmeFixture.State)
}
function New-ItemProperty {
    Param([string]$LiteralPath, [string]$Name, $Value, [string]$PropertyType, [switch]$Force, $ErrorAction)
    Assert-FixtureServicePath $LiteralPath
    $operations = $global:NvmeFixture.Operations
    if ($operations.Count -eq 0 -or -not $operations[$operations.Count - 1].StartsWith('Assert:')) {
        throw "Fixture observed an unguarded registry write to $Name."
    }
    [void]$operations.Add("Write:$Name")
    $global:NvmeFixture.State[$Name] = $Value
}
function Remove-ItemProperty {
    Param([string]$LiteralPath, [string]$Name, [switch]$Force, $ErrorAction)
    Assert-FixtureServicePath $LiteralPath
    $operations = $global:NvmeFixture.Operations
    if ($operations.Count -eq 0 -or -not $operations[$operations.Count - 1].StartsWith('Assert:')) {
        throw "Fixture observed an unguarded registry-value removal from $Name."
    }
    [void]$operations.Add("Remove:$Name")
    [void]$global:NvmeFixture.State.Remove($Name)
}
function global:reg.exe {
    $verb = "$($args[0])".ToLowerInvariant()
    if ($verb -eq 'export') {
        $path = "$($args[2])"
        $expected = 'HKLM\BROKENSYSTEM\ControlSet001\Services\stornvme'
        if (-not "$($args[1])".Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Fixture observed registry export outside the strict stornvme target: '$($args[1])'."
        }
        $global:NvmeFixture.Backups[$path] = Copy-FixtureState $global:NvmeFixture.State
        $global:NvmeFixture.LastBackup = $path
        $key = "$($args[1])" -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
        $valueLines = @($global:NvmeFixture.State.Keys | Sort-Object | ForEach-Object {
                $name = $_
                $value = $global:NvmeFixture.State[$name]
                if ($value -is [int]) { '"{0}"=dword:{1:x8}' -f $name, $value }
                else { '"{0}"="{1}"' -f $name, "$value".Replace('\', '\\').Replace('"', '\"') }
            })
        "Windows Registry Editor Version 5.00`r`n`r`n[$key]`r`n$($valueLines -join "`r`n")`r`n" | Set-Content -LiteralPath $path -Encoding Unicode
        $global:LASTEXITCODE = 0
        return
    }
    if ($verb -eq 'import') {
        $path = "$($args[1])"
        $operations = $global:NvmeFixture.Operations
        if ($operations.Count -eq 0 -or -not $operations[$operations.Count - 1].StartsWith('Assert:')) {
            throw 'Fixture observed an unguarded registry import.'
        }
        [void]$operations.Add('Import:stornvme')
        if ($global:NvmeFixture.ImportFails) {
            $global:LASTEXITCODE = 5
            return 'fixture import failure'
        }
        $global:NvmeFixture.State = Copy-FixtureState $global:NvmeFixture.Backups[$path]
        $global:LASTEXITCODE = 0
        return
    }
    $global:LASTEXITCODE = 1
}
'@ | Set-Content -LiteralPath (Join-Path $helperRoot 'Use-OfflineRegistryHive.ps1') -Encoding Utf8

    $healthy = Get-HealthyState
    Set-NvmeFixture -State $healthy
    $reportHealthy = Invoke-NvmeFixture
    Assert-Equal 0 $reportHealthy.Status 'Healthy Report mode should succeed.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'Healthy Report mode must not write.'
    Assert-True ($reportHealthy.Output -match 'NoChangeNeeded') 'Healthy Report mode should report NoChangeNeeded.'

    $broken = Get-HealthyState
    $broken.Start = 4
    $broken.Type = 2
    $broken.ErrorControl = 1
    $broken.Group = 'wrong group'
    $broken.ImagePath = 'wrong.sys'
    Set-NvmeFixture -State $broken
    $reportBroken = Invoke-NvmeFixture
    Assert-Equal 0 $reportBroken.Status 'Broken Report mode should succeed.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'Broken Report mode must not write.'
    Assert-True ($reportBroken.Output -match '5 value\(s\) would change') 'Broken Report mode should list five planned changes.'

    Set-NvmeFixture -State $broken
    $repair = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 0 $repair.Status 'Repair mode should succeed.'
    Assert-True ($repair.Output -match 'VERIFIED') 'Repair mode should report verification.'
    foreach ($name in @('Start', 'Type', 'ErrorControl', 'Group', 'ImagePath')) {
        Assert-True ($global:NvmeFixture.Operations -contains "Write:$name") "Repair mode should write $name."
    }
    Assert-Equal 'unchanged' $global:NvmeFixture.State.Sentinel 'Repair must not change unrelated values.'
    Assert-True (-not $global:NvmeFixture.State.Contains('CriticalDeviceDatabase')) 'Repair must not write CriticalDeviceDatabase.'
    $backupPath = $global:NvmeFixture.LastBackup
    Assert-True (Test-Path -LiteralPath $backupPath -PathType Leaf) 'Repair should create a verified rollback backup.'

    $global:NvmeFixture.Operations.Clear()
    $secondRepair = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 0 $secondRepair.Status 'A second Repair run should succeed.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'A second Repair run must make no writes.'
    Assert-True ($secondRepair.Output -match 'NoChangeNeeded') 'A second Repair run should report NoChangeNeeded.'

    $global:NvmeFixture.Operations.Clear()
    $rollback = Invoke-NvmeFixture -Parameters @{ Mode = 'Rollback'; BackupFile = $backupPath }
    Assert-Equal 0 $rollback.Status "Rollback mode should succeed. Output: $($rollback.Output)"
    Assert-True ($rollback.Output -match 'rollback backup was imported') 'Rollback should report a verified import.'
    Assert-Equal 4 $global:NvmeFixture.State.Start 'Rollback should restore the original Start value.'
    Assert-Equal 'wrong.sys' $global:NvmeFixture.State.ImagePath 'Rollback should restore the original ImagePath.'
    Assert-Equal 'unchanged' $global:NvmeFixture.State.Sentinel 'Rollback should restore unrelated values exactly.'

    $missingValue = Get-HealthyState
    [void]$missingValue.Remove('ImagePath')
    $missingValue.Start = 4
    Set-NvmeFixture -State $missingValue
    $repairMissingValue = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 0 $repairMissingValue.Status 'Repair should create a missing managed value.'
    $missingValueBackup = $global:NvmeFixture.LastBackup
    $global:NvmeFixture.Operations.Clear()
    $rollbackMissingValue = Invoke-NvmeFixture -Parameters @{ Mode = 'Rollback'; BackupFile = $missingValueBackup }
    Assert-Equal 0 $rollbackMissingValue.Status 'Rollback should restore a fixture with an originally absent value.'
    Assert-True (-not $global:NvmeFixture.State.Contains('ImagePath')) 'Rollback should remove a managed value that was absent originally.'
    Assert-True ($global:NvmeFixture.Operations -contains 'Remove:ImagePath') 'Rollback should explicitly remove the value that Repair introduced.'
    Assert-Equal 'unchanged' $global:NvmeFixture.State.Sentinel 'Absent-value rollback must preserve unrelated values.'

    $outOfScopeBackup = Join-Path $fixtureRoot 'out-of-scope.reg'
    "Windows Registry Editor Version 5.00`r`n`r`n[HKEY_LOCAL_MACHINE\BROKENSYSTEM\ControlSet001\Services\stornvme]`r`n`r`n[HKEY_CURRENT_USER\Software\Unexpected]`r`n" |
        Set-Content -LiteralPath $outOfScopeBackup -Encoding Unicode
    Set-NvmeFixture -State $healthy
    $outOfScope = Invoke-NvmeFixture -Parameters @{ Mode = 'Rollback'; BackupFile = $outOfScopeBackup }
    Assert-Equal 1 $outOfScope.Status 'Rollback should reject an out-of-scope registry backup.'
    Assert-True (-not $global:NvmeFixture.HiveActive) 'An out-of-scope backup failure must unload the hive.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'An out-of-scope backup must not write.'

    Set-NvmeFixture -State $healthy
    $global:NvmeFixture.Backups[$backupPath] = Copy-FixtureState $broken
    $global:NvmeFixture.ImportFails = $true
    $beforeFailedImport = Copy-FixtureState $global:NvmeFixture.State
    $failedImport = Invoke-NvmeFixture -Parameters @{ Mode = 'Rollback'; BackupFile = $backupPath }
    Assert-Equal 1 $failedImport.Status 'A failed registry import should fail Rollback.'
    Assert-True (-not $global:NvmeFixture.HiveActive) 'A failed registry import must unload the hive.'
    Assert-Equal $beforeFailedImport.Start $global:NvmeFixture.State.Start 'A failed import must leave current service values intact.'
    Assert-True (-not ($global:NvmeFixture.Operations -match '^Remove:')) 'A failed import must not remove any current service value.'

    Set-NvmeFixture -State $broken -DriverPresent $false
    $missingDriver = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 1 $missingDriver.Status 'A missing driver should fail.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'A missing driver must not write.'
    Assert-True ($missingDriver.Output -match 'could make the guest unbootable') 'The missing-driver refusal should be actionable.'

    Set-NvmeFixture -State $broken -CandidateCount 2
    $ambiguous = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 1 $ambiguous.Status 'Ambiguous Windows installations should fail.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'An ambiguous target must not write.'
    Assert-True ($ambiguous.Output -match 'Refusing to guess') 'The ambiguous-target refusal should be explicit.'

    Set-NvmeFixture -State $broken -CandidateCount 2
    $selected = Invoke-NvmeFixture -Parameters @{ Mode = 'Report'; OsDriveLetter = 'F' }
    Assert-Equal 0 $selected.Status 'An explicit OS drive should resolve an ambiguous fixture.'

    Set-NvmeFixture -State $broken -HiveReadable $false
    $corruptHive = Invoke-NvmeFixture -Parameters @{ Mode = 'Repair' }
    Assert-Equal 1 $corruptHive.Status 'An unreadable hive should fail.'
    Assert-True (-not $global:NvmeFixture.HiveActive) 'An unreadable hive must not remain mounted.'
    Assert-Equal 0 $global:NvmeFixture.Operations.Count 'An unreadable hive must not write.'

    Set-NvmeFixture -State $broken
    $strict = Invoke-NvmeFixture
    Assert-Equal 0 $strict.Status 'The strict-control-set fixture should succeed.'
    Assert-Equal 1 $global:NvmeFixture.StrictCalls 'The script should resolve the control set exactly once with -Strict.'

    $sourceText = Get-Content -LiteralPath $sourceScript -Raw
    Assert-True ($sourceText -notmatch 'ControlSet001') 'The script must not contain a ControlSet001 fallback.'
    Assert-True ($sourceText -notmatch 'CriticalDeviceDatabase\\') 'The script must not contain a CriticalDeviceDatabase write path.'

    Write-Host 'PASS: win-enable-nvme-boot-driver report, repair, idempotency, rollback, refusal, cleanup, strict-selection, and write-gate fixtures.'
}
finally {
    $env:PUBLIC = $originalPublic
    Remove-Item Function:\reg.exe -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}