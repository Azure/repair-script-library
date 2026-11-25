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
        $statement.Left.Extent.Text -match '^\$(manifestSchema|demandStart|serviceDisabled|reinstallFlag|minimumBuild|servicePattern|devicePattern|registryKeyPattern|publishedDriverPattern|controlSetPattern)$') {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
. (Join-Path $repositoryRoot 'src/windows/common/helpers/ManaReadiness.ps1')
ForEach ($fn in $ast.FindAll({ Param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

# --- Planning -------------------------------------------------------------------------------------
$vf = [pscustomobject]@{ path = 'PCI\VEN_1414&DEV_00BA&SUBSYS_00B91414&REV_00\5&a70fb64&0&0'; service = $null; configFlags = 0 }
$nic = [pscustomobject]@{ path = 'MANA_BUS\VEN_1414&ROLE_004C\6&13fe4004&0&7c1e'; service = 'Mana'; configFlags = 0 }
function New-Assessment {
    Param([string[]]$Problems = @(), [string[]]$Unknowns = @(), [string]$Architecture = 'AMD64', [string]$Build = '20348', [object[]]$Packages = @(), [object[]]$Devices = @())
    [pscustomobject]@{ problems = $Problems; unknowns = $Unknowns; architecture = $Architecture; currentBuild = $Build; manaPackages = $Packages; manaDevices = $Devices }
}
$packages = @(
    [pscustomobject]@{ inf = 'manavf.inf'; package = 'manavf.inf_amd64_a'; driverVer = '1/1/2026,2.0.18.52'; infPath = 'C:\x\manavf.inf'; services = @('Mana', 'ManaDirect'); hardwareIds = @('MANA_BUS\VEN_1414&ROLE_004C'); class = 'Net' },
    [pscustomobject]@{ inf = 'mana_bus_vf.inf'; package = 'mana_bus_vf.inf_amd64_b'; driverVer = '1/1/2026,2.0.18.52'; infPath = 'C:\x\mana_bus_vf.inf'; services = @('mana_bus'); hardwareIds = @('PCI\VEN_1414&DEV_00BA'); class = 'System' }
)
function Get-ActionText { Param($Plan) @($Plan.actions | ForEach-Object { if ($_.type -eq 'AddDriverPackage') { "Add:$($_.inf)" } elseif ($_.type -eq 'EnableService') { "Enable:$($_.service):$($_.from):$($_.to)" } else { "Reinstall:$($_.device):$($_.from):$($_.to)" } }) -join ',' }

$plan = Get-ManaRepairPlan -Assessment (New-Assessment) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-True (@($plan.actions).Count -eq 0 -and @($plan.blockers).Count -eq 0) 'A ready installation needs no action.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-disabled:mana_bus' -Packages $packages) -RepairVmArchitecture 'AMD64'
Assert-Equal 'Enable:mana_bus:4:3' (Get-ActionText $plan) 'A disabled MANA service is set back to demand start.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-missing') -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 'Add:manavf.inf,Add:mana_bus_vf.inf' (Get-ActionText $plan) 'A missing driver on a never-seen device is repaired by adding every MANA package from the repair VM.'
Assert-Equal 'C:\x\manavf.inf' @($plan.actions)[0].source 'Each package is added from its staged INF on the repair VM.'

# Live finding: a device Windows has already seen keeps ConfigFlags=0 and never gets a driver staged later.
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-missing', "mana-device-not-bound:$($vf.path)" -Devices @($vf)) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal "Add:manavf.inf,Add:mana_bus_vf.inf,Reinstall:$($vf.path):0:32" (Get-ActionText $plan) 'An already-seen device gets the reinstall flag after the packages are added.'
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-missing', "mana-device-no-driver:$($vf.path)" -Devices @($vf)) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 0 @($plan.blockers).Count 'A device without a driver is repairable when an added package supports its hardware ID.'
Assert-True (@($plan.actions | Where-Object { $_.type -eq 'ReinstallDevice' -and $_.device -eq $vf.path }).Count -eq 1) 'A seen device the added packages support is flagged for reinstall.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems "mana-device-not-bound:$($vf.path)" -Packages $packages -Devices @($vf)) -RepairVmArchitecture 'AMD64'
Assert-Equal "Reinstall:$($vf.path):0:32" (Get-ActionText $plan) 'A staged driver that was never installed for a seen device only needs the reinstall flag.'

# A binary removed with the driver comes back when a staged package is installed for the device bound to it.
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-missing', 'mana-driver-disabled:Mana', 'mana-driver-binary-missing:Mana' -Devices @($nic)) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal "Add:manavf.inf,Add:mana_bus_vf.inf,Enable:Mana:4:3,Reinstall:$($nic.path):0:32" (Get-ActionText $plan) 'A leftover disabled service without its binary is enabled and its device reinstalled from the added package.'

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems "mana-device-not-bound:$($vf.path)", "mana-device-not-bound:$($vf.path)" -Packages $packages -Devices @($vf)) -RepairVmArchitecture 'AMD64'
Assert-Equal 1 @($plan.actions).Count 'A device is flagged once.'

# A partially populated store gets only the package for the missing function.
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-ethernet-driver-missing' -Packages @($packages[1])) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 'Add:manavf.inf' (Get-ActionText $plan) 'A store with only the bus driver gets the Net-class Ethernet package.'
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-bus-driver-missing' -Packages @($packages[0])) -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 'Add:mana_bus_vf.inf' (Get-ActionText $plan) 'A store with only the Ethernet driver gets the VF bus package.'
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-bus-driver-missing', 'mana-ethernet-driver-missing') -RepairVmPackages $packages -RepairVmArchitecture 'AMD64'
Assert-Equal 'Add:mana_bus_vf.inf,Add:manavf.inf' (Get-ActionText $plan) 'A store with neither function (only RDMA, for example) gets both packages.'

# A seen device still bound to a deleted service is reinstalled from the staged package that provides it.
$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'mana-driver-service-missing:Mana' -Packages $packages -Devices @($nic)) -RepairVmArchitecture 'AMD64'
Assert-Equal "Reinstall:$($nic.path):0:32" (Get-ActionText $plan) 'A device bound to a deleted service is flagged for reinstall.'

$refusals = @(
    @{ Name = 'no package on the repair VM'; A = (New-Assessment -Problems 'mana-driver-missing'); P = @(); Expect = 'repair-vm-has-no-mana-driver' },
    @{ Name = 'architecture mismatch'; A = (New-Assessment -Problems 'mana-driver-missing' -Architecture 'ARM64'); P = $packages; Expect = 'architecture-mismatch:ARM64-vs-AMD64' },
    @{ Name = 'architecture unknown'; A = (New-Assessment -Problems 'mana-driver-missing' -Architecture ''); P = $packages; Expect = 'architecture-mismatch:-vs-AMD64' },
    @{ Name = 'build older than WS2016'; A = (New-Assessment -Problems 'mana-driver-missing' -Build '9600'); P = $packages; Expect = 'unsupported-os-build:9600' },
    @{ Name = 'build unknown'; A = (New-Assessment -Problems 'mana-driver-missing' -Build ''); P = $packages; Expect = 'unsupported-os-build:' },
    @{ Name = 'incomplete assessment'; A = (New-Assessment -Problems 'mana-driver-disabled:mana_bus' -Unknowns 'netvsc-state-unknown'); P = @(); Expect = 'assessment-incomplete:netvsc-state-unknown' },
    @{ Name = 'binary with no package to restore it'; A = (New-Assessment -Problems 'mana-driver-binary-missing:mana_bus'); P = @(); Expect = 'mana-driver-binary-missing:mana_bus' },
    @{ Name = 'hostile service name'; A = (New-Assessment -Problems 'mana-driver-disabled:..\..\Control'); P = @(); Expect = 'unexpected-service-name:..\..\Control' },
    @{ Name = 'unknown device'; A = (New-Assessment -Problems 'mana-device-not-bound:PCI\X\Y' -Packages $packages); P = @(); Expect = 'unexpected-device:PCI\X\Y' },
    @{ Name = 'device with no driver to install'; A = (New-Assessment -Problems 'mana-driver-missing', "mana-device-no-driver:$($vf.path)" -Devices @($vf) -Architecture 'ARM64'); P = $packages; Expect = "no-driver-to-install:$($vf.path)" },
    @{ Name = 'repair VM without the Ethernet package'; A = (New-Assessment -Problems 'mana-ethernet-driver-missing' -Packages @($packages[1])); P = @($packages[1]); Expect = 'repair-vm-has-no-mana-driver:mana-ethernet-driver-missing' },
    @{ Name = 'deleted service with no package to restore it'; A = (New-Assessment -Problems 'mana-driver-service-missing:Mana' -Devices @($nic)); P = @(); Expect = 'mana-driver-service-missing:Mana' },
    @{ Name = 'device the added packages do not support'; A = (New-Assessment -Problems 'mana-driver-missing', 'mana-device-no-driver:MANA_BUS\VEN_1414&ROLE_0003\6&1' -Devices @([pscustomobject]@{ path = 'MANA_BUS\VEN_1414&ROLE_0003\6&1'; service = $null; configFlags = 0 })); P = $packages; Expect = 'no-driver-to-install:MANA_BUS\VEN_1414&ROLE_0003\6&1' }
)
ForEach ($case in $refusals) {
    $plan = Get-ManaRepairPlan -Assessment $case.A -RepairVmPackages $case.P -RepairVmArchitecture 'AMD64'
    Assert-True (@($plan.blockers) -contains $case.Expect) "Refusal '$($case.Name)': expected blocker '$($case.Expect)', got '$(@($plan.blockers) -join ',')'."
}

$plan = Get-ManaRepairPlan -Assessment (New-Assessment -Problems 'synthetic-nic-driver-disabled', 'mana-driver-disabled:Mana' -Packages $packages) -RepairVmArchitecture 'AMD64'
Assert-Equal 'synthetic-nic-driver-disabled' (@($plan.outOfScope) -join ',') 'netvsc problems are reported, never repaired, by this script.'
Assert-Equal 1 @($plan.actions).Count 'A MANA problem next to a netvsc problem is still planned.'
Write-Host "PASS: repair planning (ready, disabled, missing, already-seen device, leftover service, $($refusals.Count) refusals, netvsc out of scope)."

# --- Rollback manifest validation -----------------------------------------------------------------
$offline = [pscustomobject]@{ BuildNumber = '20348'; GuestComputerName = 'guest01' }
function New-Manifest {
    Param($Changes = @(@{ key = 'Services\mana_bus'; name = 'Start'; before = 4; after = 3 }, @{ key = "Enum\$($vf.path)"; name = 'ConfigFlags'; before = 0; after = 32 }),
        $Drivers = @(@{ publishedName = 'oem9.inf'; inf = 'manavf.inf' }), $Build = '20348', $Schema = $manifestSchema, $ControlSet = 'ControlSet002')
    [pscustomobject]@{ schema = $Schema; controlSet = $ControlSet; guest = [pscustomobject]@{ buildNumber = $Build; computerName = 'guest01' }; registryChanges = $Changes; addedDrivers = $Drivers }
}
$targets = [pscustomobject]@{ controlSetFound = $true; services = @('mana_bus', 'Mana'); devices = @($vf.path, $nic.path) }
Assert-Equal 0 @(Test-ManaRollbackManifest -Manifest (New-Manifest) -Offline $offline -Targets $targets).Count 'A valid manifest has no rejection reason.'
$rejected = @(
    @{ Name = 'boot-critical service'; M = (New-Manifest -Changes @(@{ key = 'Services\storvsc'; name = 'Start'; before = 4; after = 0 })) },
    @{ Name = 'non-MANA service with the Repair transition'; M = (New-Manifest -Changes @(@{ key = 'Services\storvsc'; name = 'Start'; before = 4; after = 3 })) },
    @{ Name = 'MANA service with another transition'; M = (New-Manifest -Changes @(@{ key = 'Services\mana_bus'; name = 'Start'; before = 4; after = 0 })) },
    @{ Name = 'ConfigFlags change other than the reinstall bit'; M = (New-Manifest -Changes @(@{ key = "Enum\$($vf.path)"; name = 'ConfigFlags'; before = 0; after = 1 })) },
    @{ Name = 'reinstall bit already set before'; M = (New-Manifest -Changes @(@{ key = "Enum\$($vf.path)"; name = 'ConfigFlags'; before = 32; after = 32 })) },
    @{ Name = 'device not on the disk'; M = (New-Manifest -Changes @(@{ key = 'Enum\PCI\VEN_1414&DEV_00BA\9&other'; name = 'ConfigFlags'; before = 0; after = 32 })) },
    @{ Name = 'Start on a device key'; M = (New-Manifest -Changes @(@{ key = "Enum\$($vf.path)"; name = 'Start'; before = 4; after = 3 })) },
    @{ Name = 'ConfigFlags on a service key'; M = (New-Manifest -Changes @(@{ key = 'Services\mana_bus'; name = 'ConfigFlags'; before = 0; after = 32 })) },
    @{ Name = 'no control set'; M = (New-Manifest -ControlSet $null) },
    @{ Name = 'path-like control set'; M = (New-Manifest -ControlSet 'ControlSet001\..\Select') },
    @{ Name = 'other installation'; M = (New-Manifest -Build '17763') },
    @{ Name = 'unknown schema'; M = (New-Manifest -Schema 'other/1') },
    @{ Name = 'key outside Services/Enum MANA'; M = (New-Manifest -Changes @(@{ key = 'Control\Session Manager'; name = 'Start'; before = 4; after = 3 })) },
    @{ Name = 'path-like service'; M = (New-Manifest -Changes @(@{ key = 'Services\a\..\b'; name = 'Start'; before = 4; after = 3 })) },
    @{ Name = 'other value name'; M = (New-Manifest -Changes @(@{ key = 'Services\mana_bus'; name = 'ImagePath'; before = 4; after = 3 })) },
    @{ Name = 'Start out of range'; M = (New-Manifest -Changes @(@{ key = 'Services\mana_bus'; name = 'Start'; before = 9; after = 3 })) },
    @{ Name = 'non-oem driver'; M = (New-Manifest -Drivers @(@{ publishedName = 'netvsc.inf' })) }
)
ForEach ($case in $rejected) {
    Assert-True (@(Test-ManaRollbackManifest -Manifest $case.M -Offline $offline -Targets $targets).Count -gt 0) "Manifest '$($case.Name)' must be rejected."
}
$missingSet = [pscustomobject]@{ controlSetFound = $false; services = @(); devices = @() }
Assert-True (@(Test-ManaRollbackManifest -Manifest (New-Manifest) -Offline $offline -Targets $missingSet).Count -gt 0) 'A manifest whose control set is not on the disk must be rejected.'
Write-Host "PASS: rollback manifest validation (valid plus $($rejected.Count) rejections)."

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

# --- Registry write path against a scratch key ------------------------------------------------------
$scratchRoot = 'HKCU:\Software\RslManaFixTest-' + [guid]::NewGuid().ToString('N')
$scratch = "$scratchRoot\ControlSet001"
$scratch2 = "$scratchRoot\ControlSet002"
$backupDir = Join-Path ([System.IO.Path]::GetTempPath()) ('mana-fix-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backupDir | Out-Null
$script:gateCalls = @()
function Invoke-WithHive { Param($Hive, [scriptblock]$ScriptBlock) & $ScriptBlock }
function Get-OfflineSystemRootPath { Param([switch]$Strict) $scratch }   # Select\Current boots ControlSet001
function Get-OfflineHiveKeyState { Param($HiveKey) if (Test-Path -LiteralPath $HiveKey) { 'Present' } else { 'Absent' } }
function Assert-OfflineTarget { Param($Path, $Action) $script:gateCalls += $Path; $true }
function New-Change { Param($Key, $Name, $From, $To, [switch]$Optional) [pscustomobject]@{ key = $Key; name = $Name; from = $From; to = $To; optional = [bool]$Optional } }
try {
    New-Item -Path "$scratch\Services\mana_bus" -Force | Out-Null
    New-ItemProperty -Path "$scratch\Services\mana_bus" -Name Start -Value 4 -PropertyType DWord | Out-Null
    New-Item -Path "$scratch\Services\Mana" -Force | Out-Null
    New-ItemProperty -Path "$scratch\Services\Mana" -Name Start -Value 3 -PropertyType DWord | Out-Null
    $deviceKey = 'Enum\PCI\VEN_1414&DEV_00BA\5&a70fb64&0&0'
    New-Item -Path "$scratch\$deviceKey" -Force | Out-Null   # no ConfigFlags value: read as 0, as Windows does

    # The expected current value is a gate: a stale plan must not write anything, not even the other change.
    $threw = $false
    try { Set-OfflineRegistryDword -Changes @((New-Change 'Services\mana_bus' Start 4 3), (New-Change 'Services\Mana' Start 4 3)) -BackupDirectory $backupDir -ControlSet ControlSet001 -RequireCurrent | Out-Null }
    catch { $threw = $_.Exception.Message -match 'expected 4' }
    Assert-True $threw 'A value that no longer matches the plan must stop the repair.'
    Assert-Equal 4 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'Nothing may be written when any required change is stale.'
    Assert-Equal 0 $script:gateCalls.Count 'No write gate may be reached when validation fails.'

    $threw = $false
    try { Set-OfflineRegistryDword -Changes @(New-Change 'Services\absent' Start 4 3) -ControlSet ControlSet001 | Out-Null }
    catch { $threw = $_.Exception.Message -match 'not present' }
    Assert-True $threw 'A missing key must stop the repair.'

    # Repair writes only the assessed control set, and only while it is the one Select\Current boots.
    $threw = $false
    try { Set-OfflineRegistryDword -Changes @(New-Change 'Services\mana_bus' Start 4 3) -ControlSet ControlSet002 -RequireCurrent | Out-Null }
    catch { $threw = $_.Exception.Message -match 'not the assessed ControlSet002' }
    Assert-True $threw 'Repair must refuse a control set that is not the current one.'
    $threw = $false
    try { Set-OfflineRegistryDword -Changes @(New-Change 'Services\mana_bus' Start 4 3) -ControlSet ControlSet002 | Out-Null }
    catch { $threw = $_.Exception.Message -match "control set 'ControlSet002' is not present" }
    Assert-True $threw 'A control set that does not exist must be refused.'
    Assert-Equal 0 $script:gateCalls.Count 'No write gate may be reached for a refused control set.'

    $result = Set-OfflineRegistryDword -Changes @((New-Change 'Services\mana_bus' Start 4 3), (New-Change $deviceKey ConfigFlags 0 32)) -BackupDirectory $backupDir -ControlSet ControlSet001 -RequireCurrent
    Assert-Equal 3 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'The disabled service is set to demand start.'
    Assert-Equal 32 (Get-ItemProperty "$scratch\$deviceKey").ConfigFlags 'The device is flagged for reinstall.'
    Assert-Equal 2 @($result.Applied).Count 'Both changes are reported as applied.'
    Assert-Equal "$scratch\Services\mana_bus,$scratch\$deviceKey" ($script:gateCalls -join ',') 'Every write passes the offline-target gate first.'
    $backup = Join-Path $backupDir 'Services_mana_bus-before.reg'
    Assert-True ((Test-Path $backup) -and ((Get-Content $backup -Raw) -match '"Start"=dword:00000004')) 'The pre-change key is exported with its original value.'

    # Rollback direction. Plug and Play clears the reinstall flag once used; an optional change is then skipped.
    Set-ItemProperty -Path "$scratch\$deviceKey" -Name ConfigFlags -Value 0 -Type DWord
    $result = Set-OfflineRegistryDword -Changes @((New-Change 'Services\mana_bus' Start 3 4), (New-Change $deviceKey ConfigFlags 32 0 -Optional)) -ControlSet ControlSet001
    Assert-Equal 4 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'Rollback restores the recorded Start value.'
    Assert-Equal 1 @($result.Skipped).Count 'A reinstall flag already used by Plug and Play is skipped, not treated as a conflict.'

    # Rollback restores the control set in its manifest, even when Select\Current now boots another one.
    New-Item -Path "$scratch2\Services\mana_bus" -Force | Out-Null
    New-ItemProperty -Path "$scratch2\Services\mana_bus" -Name Start -Value 3 -PropertyType DWord | Out-Null
    $result = Set-OfflineRegistryDword -Changes @(New-Change 'Services\mana_bus' Start 3 4) -ControlSet ControlSet002
    Assert-Equal 4 (Get-ItemProperty "$scratch2\Services\mana_bus").Start 'Rollback writes the recorded control set.'
    Assert-Equal 4 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'The current control set is left alone.'

    # A write whose read-back fails is still returned in Applied, so Repair records it for Rollback.
    Set-ItemProperty -Path "$scratch\Services\mana_bus" -Name Start -Value 4 -Type DWord
    $script:failReadBack = $true
    function Get-ItemProperty {
        [CmdletBinding()]
        Param([string]$LiteralPath, [string]$Name, [string]$Path)
        if ($Name -and $script:failReadBack) { throw 'simulated read-back failure' }
        Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
    }
    $result = Set-OfflineRegistryDword -Changes @((New-Change 'Services\mana_bus' Start 4 3), (New-Change $deviceKey ConfigFlags 0 32)) -ControlSet ControlSet001 -RequireCurrent
    $script:failReadBack = $false
    Remove-Item Function:\Get-ItemProperty
    Assert-Equal 3 (Get-ItemProperty "$scratch\Services\mana_bus").Start 'The value was written before the read-back failed.'
    Assert-Equal 'Services\mana_bus' (@($result.Applied | ForEach-Object { $_.key }) -join ',') 'The written value is in Applied; nothing after the failure is written.'
    Assert-True ($result.Error -match 'simulated read-back failure') 'The read-back failure is returned to the caller.'
    Write-Host 'PASS: registry write path (stale-plan gate, missing key, exact control set, offline-target gate, .reg backup, read-back, rollback, used reinstall flag, failed read-back recorded).'
}
finally {
    Remove-Item -Path $scratchRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Static safety contract -----------------------------------------------------------------------
Assert-True ($sourceText -match "\[string\]\`$Mode = 'Report'") 'Report must be the default mode.'
Assert-True ($sourceText -notmatch '(?i)ForceUnsigned') 'Driver packages must keep their signature check.'
$invoked = @($ast.FindAll({ Param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { "$($_.GetCommandName())" })
Assert-True (@($invoked | Where-Object { $_ -match '(?i)^pnputil(\.exe)?$' }).Count -eq 0) 'pnputil services the running repair VM; offline DISM servicing must be used.'
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
Assert-True ($sourceText -match '(?s)Add-WindowsDriver -Path.*\$staged = Get-ManaOfflineAssessment.*Get-ManaRepairPlan -Assessment \$staged') 'Registry changes are re-planned from the disk after the packages are added.'
Assert-True ($sourceText.IndexOf('Add-WindowsDriver -Path') -lt $sourceText.IndexOf('Set-OfflineRegistryDword -Changes $registryChanges -BackupDirectory')) 'Packages are added before any registry value changes, so a DISM failure leaves the registry untouched.'
Assert-True ($sourceText -match '(?s)Mode -eq .Report.\).*No changes were made') 'Report mode must say that it made no changes.'
Assert-True ($sourceText -match '\[MANA-REPAIR-JSON\]') 'The repair must emit its machine-readable result.'
Write-Host 'PASS: static safety contract (Report default, signed drivers, offline DISM only, gated writes, packages before registry, JSON result).'
