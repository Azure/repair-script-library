# Fixture tests for win-fix-mana-driver.ps1.
# Run from the repository root (Windows PowerShell 5.1 and PowerShell 7; no elevation needed):
#   pwsh -NoProfile -File ./tests/test-win-fix-mana-driver.ps1
#
# Planning and manifest validation are exercised directly. The registry write path runs for real against a
# scratch key under HKCU standing in for the mounted offline SYSTEM hive, so the gate, backup and read-back are
# tested without loading a hive. DISM is mocked; Add-WindowsDriver itself is covered by live validation.

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-fix-mana-driver.ps1'
$sourceText = Get-Content -LiteralPath $sourceScript -Raw

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    if ("$Expected" -ne "$Actual") { throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')" }
}

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourceScript, [ref]$null, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) "The repair script must parse cleanly: $($parseErrors | Out-String)"
# Script-level constants first, then the functions that use them.
ForEach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $statement.Left.Extent.Text -match '^\$(manifestSchema|demandStart|serviceDisabled|minimumBuild|servicePattern|publishedDriverPattern)$') {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
ForEach ($fn in $ast.FindAll({ Param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

# --- Planning -------------------------------------------------------------------------------------
function New-Assessment {
    Param([string[]]$Problems = @(), [string[]]$Unknowns = @(), [string]$Architecture = 'AMD64', [string]$Build = '20348')
    [pscustomobject]@{ problems = $Problems; unknowns = $Unknowns; architecture = $Architecture; currentBuild = $Build }
}
$packages = @(
    [pscustomobject]@{ inf = 'manavf.inf'; package = 'manavf.inf_amd64_a'; driverVer = '1/1/2026,2.0.18.52'; infPath = 'C:\x\manavf.inf' },
    [pscustomobject]@{ inf = 'mana_bus_vf.inf'; package = 'mana_bus_vf.inf_amd64_b'; driverVer = '1/1/2026,2.0.18.52'; infPath = 'C:\x\mana_bus_vf.inf' }
)

$plan = Get-ManaRepairPlan -Assessment (New-Assessment) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-True (@($plan.actions).Count -eq 0 -and @($plan.blockers).Count -eq 0) 'A ready installation needs no action.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-disabled:mana_bus') -RepairVmArchitecture 'AMD64'
Assert-Equal 'EnableService:mana_bus:4:3' (@($plan.actions | ForEach-Object { "$($_.type):$($_.service):$($_.from):$($_.to)" }) -join ',') 'A disabled MANA service is set back to demand start.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-missing') -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 'manavf.inf,mana_bus_vf.inf' (@($plan.actions | ForEach-Object { $_.inf }) -join ',') 'A missing driver is repaired with every MANA package from the repair VM.'
Assert-Equal 'C:\x\manavf.inf' @($plan.actions)[0].source 'Each package is added from its staged INF on the repair VM.'

$refusals = @(
    @{ Name = 'no package on the repair VM'; A = (New-Assessment -Problems 'mana-driver-missing'); P = @(); Expect = 'repair-vm-has-no-mana-driver' },
    @{ Name = 'architecture mismatch'; A = (New-Assessment -Problems 'mana-driver-missing' -Architecture 'ARM64'); P = $packages; Expect = 'architecture-mismatch:ARM64-vs-AMD64' },
    @{ Name = 'architecture unknown'; A = (New-Assessment -Problems 'mana-driver-missing' -Architecture ''); P = $packages; Expect = 'architecture-mismatch:-vs-AMD64' },
    @{ Name = 'build older than WS2016'; A = (New-Assessment -Problems 'mana-driver-missing' -Build '9600'); P = $packages; Expect = 'unsupported-os-build:9600' },
    @{ Name = 'build unknown'; A = (New-Assessment -Problems 'mana-driver-missing' -Build ''); P = $packages; Expect = 'unsupported-os-build:' },
    @{ Name = 'incomplete assessment'; A = (New-Assessment -Problems 'mana-driver-disabled:mana_bus' -Unknowns 'netvsc-state-unknown'); P = @(); Expect = 'assessment-incomplete:netvsc-state-unknown' },
    @{ Name = 'missing driver binary'; A = (New-Assessment -Problems 'mana-driver-binary-missing:mana_bus'); P = @(); Expect = 'mana-driver-binary-missing:mana_bus' },
    @{ Name = 'hostile service name'; A = (New-Assessment -Problems 'mana-driver-disabled:..\..\Control'); P = @(); Expect = 'unexpected-service-name:..\..\Control' }
)
ForEach ($case in $refusals) {
    $plan = Get-ManaRepairPlan -Assessment $case.A -RepairVmPackages $case.P -RepairVmArchitecture 'AMD64'
    Assert-True (@($plan.blockers) -contains $case.Expect) "Refusal '$($case.Name)': expected blocker '$($case.Expect)', got '$(@($plan.blockers) -join ',')'."
    if ($case.Name -ne 'incomplete assessment') {
        Assert-True (@($plan.actions).Count -eq 0) "Refusal '$($case.Name)' must not plan an action for the refused problem."
    }
}

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'synthetic-nic-driver-disabled', 'mana-driver-disabled:Mana') -RepairVmArchitecture 'AMD64'
Assert-Equal 'synthetic-nic-driver-disabled' (@($plan.outOfScope) -join ',') 'netvsc problems are reported, never repaired, by this script.'
Assert-Equal 1 @($plan.actions).Count 'A MANA problem next to a netvsc problem is still planned.'
Write-Host "PASS: repair planning (ready, disabled, missing, $($refusals.Count) refusals, netvsc out of scope)."

# --- Rollback manifest validation -----------------------------------------------------------------
$offline = [pscustomobject]@{ BuildNumber = '20348'; GuestComputerName = 'guest01' }
function New-Manifest {
    Param($Services = @(@{ service = 'mana_bus'; before = 4; after = 3 }), $Drivers = @(@{ publishedName = 'oem9.inf'; inf = 'manavf.inf' }), $Build = '20348', $Schema = $manifestSchema)
    [pscustomobject]@{ schema = $Schema; guest = [pscustomobject]@{ buildNumber = $Build; computerName = 'guest01' }; serviceChanges = $Services; addedDrivers = $Drivers }
}
Assert-Equal 0 @(Test-ManaRollbackManifest -Manifest (New-Manifest) -Offline $offline).Count 'A valid manifest has no rejection reason.'
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest -Build '17763') -Offline $offline).Count -gt 0) 'A manifest from another installation is rejected.'
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest -Schema 'other/1') -Offline $offline).Count -gt 0) 'An unknown schema is rejected.'
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest -Services @(@{ service = 'a\..\b'; before = 4 })) -Offline $offline).Count -gt 0) 'A path-like service name is rejected.'
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest -Services @(@{ service = 'mana_bus'; before = 9 })) -Offline $offline).Count -gt 0) 'An out-of-range Start value is rejected.'
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest -Drivers @(@{ publishedName = 'netvsc.inf' })) -Offline $offline).Count -gt 0) 'Only oemN.inf published names can be removed.'
Write-Host 'PASS: rollback manifest validation (valid, other installation, schema, service name, Start range, driver name).'

# --- Offline MANA driver discovery ----------------------------------------------------------------
function Get-WindowsDriver {
    Param([string]$Path)
    @(
        [pscustomobject]@{ Driver = 'oem6.inf'; OriginalFileName = 'F:\Windows\System32\DriverStore\FileRepository\manavf.inf_amd64_a\manavf.inf'; Version = '2.0.18.52' },
        [pscustomobject]@{ Driver = 'OEM7.inf'; OriginalFileName = 'F:\Windows\System32\DriverStore\FileRepository\mana_bus_vf.inf_amd64_b\mana_bus_vf.inf'; Version = '2.0.18.52' },
        [pscustomobject]@{ Driver = 'oem8.inf'; OriginalFileName = 'F:\Windows\System32\DriverStore\FileRepository\mlx5.inf_amd64_c\mlx5.inf'; Version = '3.0' },
        [pscustomobject]@{ Driver = 'oem9.inf'; OriginalFileName = 'F:\Windows\INF\notmana.inf'; Version = '1.0' }
    )
}
$entries = Get-OfflineManaDriverEntry -ImageRoot 'F:\'
Assert-Equal 'oem6.inf,oem7.inf' ((@($entries.Keys) | Sort-Object) -join ',') 'Only MANA packages are reported, with published names lower-cased.'
Remove-Item Function:\Get-WindowsDriver
Write-Host 'PASS: offline MANA driver discovery.'

# --- Service write path against a scratch registry key ----------------------------------------------
$scratch = 'HKCU:\Software\RslManaFixTest-' + [guid]::NewGuid().ToString('N')
$backupDir = Join-Path ([System.IO.Path]::GetTempPath()) ('mana-fix-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backupDir | Out-Null
$script:gateCalls = @()
function Invoke-WithHive { Param($Hive, [scriptblock]$ScriptBlock) & $ScriptBlock }
function Get-OfflineSystemRootPath { Param([switch]$Strict) $scratch }
function Get-OfflineHiveKeyState { Param($HiveKey) if (Test-Path -LiteralPath $HiveKey) { 'Present' } else { 'Absent' } }
function Assert-OfflineTarget { Param($Path, $Action) $script:gateCalls += $Path; $true }
try {
    New-Item -Path "$scratch\Services\mana_bus" -Force | Out-Null
    New-ItemProperty -Path "$scratch\Services\mana_bus" -Name Start -Value 4 -PropertyType DWord | Out-Null
    New-Item -Path "$scratch\Services\Mana" -Force | Out-Null
    New-ItemProperty -Path "$scratch\Services\Mana" -Name Start -Value 3 -PropertyType DWord | Out-Null

    # The expected current value is a gate: a stale plan must not write anything, not even the other change.
    $threw = $false
    try { Set-OfflineServiceStart -Changes @([pscustomobject]@{ service = 'mana_bus'; from = 4; to = 3 }, [pscustomobject]@{ service = 'Mana'; from = 4; to = 3 }) -BackupDirectory $backupDir }
    catch { $threw = $_.Exception.Message -match 'expected 4' }
    Assert-True $threw 'A service whose Start no longer matches the plan must stop the repair.'
    Assert-Equal 4 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'Nothing may be written when any change is stale.'
    Assert-Equal 0 $script:gateCalls.Count 'No write gate may be reached when validation fails.'

    $threw = $false
    try { Set-OfflineServiceStart -Changes @([pscustomobject]@{ service = 'absent'; from = 4; to = 3 }) }
    catch { $threw = $_.Exception.Message -match 'not present' }
    Assert-True $threw 'A missing service key must stop the repair.'

    Set-OfflineServiceStart -Changes @([pscustomobject]@{ service = 'mana_bus'; from = 4; to = 3 }) -BackupDirectory $backupDir
    Assert-Equal 3 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'The disabled service is set to demand start.'
    Assert-Equal "$scratch\Services\mana_bus" ($script:gateCalls -join ',') 'Every write passes the offline-target gate first.'
    $backup = Join-Path $backupDir 'mana_bus-before.reg'
    Assert-True ((Test-Path $backup) -and ((Get-Content $backup -Raw) -match '"Start"=dword:00000004')) 'The pre-change service key is exported with its original Start value.'

    # Rollback direction: the recorded value is restored only from the value Repair wrote.
    Set-OfflineServiceStart -Changes @([pscustomobject]@{ service = 'mana_bus'; from = 3; to = 4 })
    Assert-Equal 4 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'Rollback restores the recorded Start value.'
    Write-Host 'PASS: service write path (stale-plan gate, missing key, offline-target gate, .reg backup, read-back, rollback).'
}
finally {
    Remove-Item -Path $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Static safety contract -----------------------------------------------------------------------
Assert-True ($sourceText -match "\[string\]\`$Mode = 'Report'") 'Report must be the default mode.'
Assert-True ($sourceText -notmatch '(?i)ForceUnsigned') 'Driver packages must keep their signature check.'
Assert-True ($sourceText -notmatch '(?i)pnputil') 'pnputil services the running repair VM; offline DISM servicing must be used.'
Assert-True ($sourceText -notmatch '(?i)reg(\.exe)?\s+(load|unload|import|delete|add)') 'Hives are mounted only through Invoke-WithHive, and never imported or deleted directly.'
$commands = $ast.FindAll({ Param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
ForEach ($write in 'Set-ItemProperty', 'Add-WindowsDriver', 'Remove-WindowsDriver') {
    $calls = @($commands | Where-Object { $_.GetCommandName() -eq $write })
    Assert-True ($calls.Count -gt 0) "The repair script is expected to call $write."
    ForEach ($call in $calls) {
        $start = $call.Extent.StartOffset
        $preceding = $sourceText.Substring([Math]::Max(0, $start - 400), [Math]::Min(400, $start))
        Assert-True ($preceding -match 'Assert-OfflineTarget') "The $write call on line $($call.Extent.StartLineNumber) must be preceded by an Assert-OfflineTarget gate."
    }
}
Assert-True ($sourceText -match '(?s)Mode -eq .Report.\).*No changes were made') 'Report mode must say that it made no changes.'
Assert-True ($sourceText -match '\[MANA-REPAIR-JSON\]') 'The repair must emit its machine-readable result.'
Write-Host 'PASS: static safety contract (Report default, signed drivers, offline DISM only, gated writes, JSON result).'
