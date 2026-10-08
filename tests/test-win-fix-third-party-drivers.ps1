# Standalone fixture tests for win-fix-third-party-drivers.ps1.
# Run from the repository root on Windows:
#   pwsh -NoProfile -File ./tests/test-win-fix-third-party-drivers.ps1
#
# Covers the revert manifest transaction: a manifest that cannot be written must roll back every
# Start value this run changed, a rollback that cannot complete must say so, a failed apply or
# revert must be reported, and a manifest that cannot be deleted after a revert must be kept and
# reported. The shipped functions run against a throwaway HKCU registry tree that stands in for the
# mounted offline SYSTEM control set; failures are injected with locked files and command stubs.

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-fix-third-party-drivers.ps1'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rsl-third-party-drivers-$([guid]::NewGuid())"
$registryRoot = "HKCU:\Software\rsl-third-party-drivers-test-$([guid]::NewGuid())"
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

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourceScript, [ref]$tokens, [ref]$parseErrors)
Assert-Equal 0 @($parseErrors).Count 'The script must parse.'

# The manifest and driver functions are loaded on their own, so they are tested exactly as shipped.
$shippedFunction = @(
    'Read-RevertManifest', 'Write-RevertManifest', 'Write-RevertManifestOrRollback', 'Clear-RevertManifest',
    'Repair-Finding', 'Invoke-DriverRevert'
)
$definitions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in $shippedFunction) {
    $definition = @($definitions | Where-Object { $_.Name -eq $name })
    Assert-Equal 1 $definition.Count "Exactly one definition of $name is expected."
    . ([scriptblock]::Create($definition[0].Extent.Text))
}

$script:LoggedMessage = [System.Collections.Generic.List[string]]::new()
$script:SystemRoot = "$registryRoot\ControlSet001"
$script:HiveMounts = 0
$script:FailHiveMount = $false
$script:FailStartWriteFor = $null

function Add-OfflineRepairLog { Param([string]$Level, [string]$Message) $script:LoggedMessage.Add($Message) }
function Test-OfflinePath { Param([string]$Path) return [bool](Test-Path -LiteralPath $Path) }
function Get-OfflineSystemRootPath { Param([switch]$Strict) return $script:SystemRoot }
function Invoke-WithHive {
    Param([string[]]$Hive, [scriptblock]$ScriptBlock, [string]$WindowsPath)
    $script:HiveMounts++
    if ($script:FailHiveMount) { throw [System.UnauthorizedAccessException]::new('reg load failed: the hive is in use.') }
    return (& $ScriptBlock)
}

# Shadows the cmdlet so one named service's Start write can be made to fail on demand.
function Set-ItemProperty {
    Param([string]$LiteralPath, [string]$Name, $Value, [string]$Type, [switch]$Force, $ErrorAction)
    if ($script:FailStartWriteFor -and $LiteralPath -like "*\Services\$($script:FailStartWriteFor)") {
        throw [System.UnauthorizedAccessException]::new("Requested registry access is not allowed for $($script:FailStartWriteFor).")
    }
    Microsoft.PowerShell.Management\Set-ItemProperty -LiteralPath $LiteralPath -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
}

$originalStart = @{ fltA = 0; fltB = 1; fltC = 2 }

function Reset-Fixture {
    if (Test-Path -LiteralPath $registryRoot) { Remove-Item -LiteralPath $registryRoot -Recurse -Force }
    foreach ($service in $originalStart.Keys) {
        $key = New-Item -Path "$script:SystemRoot\Services\$service" -Force
        New-ItemProperty -LiteralPath $key.PSPath -Name 'Start' -Value $originalStart[$service] -PropertyType DWord -Force | Out-Null
    }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $script:LoggedMessage.Clear()
    $script:HiveMounts = 0
    $script:FailHiveMount = $false
    $script:FailStartWriteFor = $null
}

function Get-Start { Param([string]$Service) return (Get-ItemProperty -LiteralPath "$script:SystemRoot\Services\$Service" -Name 'Start').Start }

function New-DriverFinding {
    Param([string]$Service)
    return [PSCustomObject]@{
        Cause    = 'NonMicrosoftBootDriver'
        Item     = $Service
        Repaired = $false
        Data     = [PSCustomObject]@{ Service = $Service; Type = 1; Group = 'FSFilter Activity Monitor'; ImagePath = "\SystemRoot\System32\drivers\$Service.sys"; Vendor = 'Contoso' }
    }
}

# Applies the repair to the named fixture drivers, as the script's repair loop does.
function Invoke-FixtureRepair {
    Param([string[]]$Service)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $Service) {
        $entry = Repair-Finding -Finding (New-DriverFinding $name) -SystemRoot $script:SystemRoot -ControlSet 'ControlSet001'
        if ($null -ne $entry) { [void]$entries.Add($entry) }
    }
    return @($entries)
}

function Lock-File {
    Param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Set-Content -LiteralPath $Path -Value '[]' -Encoding UTF8 }
    return [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
}

try {
    $manifestPath = Join-Path $fixtureRoot 'win-fix-third-party-drivers-revert.json'

    # Happy path: the manifest is written and nothing is rolled back.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA', 'fltB'
    Assert-Equal 4 (Get-Start 'fltA') 'The repair disables fltA.'
    $outcome = Write-RevertManifestOrRollback -ManifestPath $manifestPath -Entries $entries -WindowsPath 'X:\Windows'
    Assert-True $outcome.Written 'A writable manifest is reported as written.'
    Assert-Equal 0 $script:HiveMounts 'A written manifest does not trigger a rollback.'
    $recorded = @(Read-RevertManifest -ManifestPath $manifestPath)
    Assert-Equal 2 $recorded.Count 'The manifest records both disabled drivers.'
    Assert-Equal 1 (@($recorded | Where-Object { $_.Service -eq 'fltB' })[0].OriginalStart) 'The manifest records the original Start value.'
    Assert-True (Write-RevertManifestOrRollback -ManifestPath $manifestPath -Entries @() -WindowsPath 'X:\Windows').Written 'No change needs no manifest.'

    # Manifest write fails because the file is locked: every change is rolled back and proven.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA', 'fltB', 'fltC'
    $lock = Lock-File $manifestPath
    try { $outcome = Write-RevertManifestOrRollback -ManifestPath $manifestPath -Entries $entries -WindowsPath 'X:\Windows' }
    finally { $lock.Dispose() }
    Assert-True (-not $outcome.Written) 'A locked manifest is reported as not written.'
    Assert-True ($outcome.Error -match 'IOException') "The write failure is reported with its type. Got '$($outcome.Error)'."
    Assert-True $outcome.RolledBack 'The rollback is reported as complete.'
    Assert-Equal 3 $outcome.Restored 'All three changes are rolled back.'
    Assert-Equal 1 $script:HiveMounts 'The rollback runs under the mounted hive.'
    foreach ($service in $originalStart.Keys) { Assert-Equal $originalStart[$service] (Get-Start $service) "$service is back at its original Start." }
    Assert-Equal '[]' (Get-Content -LiteralPath $manifestPath -Raw).Trim() 'The locked manifest was not partly written.'

    # Manifest write fails because its folder is gone.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA'
    $outcome = Write-RevertManifestOrRollback -ManifestPath (Join-Path $fixtureRoot 'missing\revert.json') -Entries $entries -WindowsPath 'X:\Windows'
    Assert-True (-not $outcome.Written -and $outcome.RolledBack) 'A missing folder is rolled back too.'
    Assert-Equal 0 (Get-Start 'fltA') 'fltA is back at Start 0.'

    # Manifest write fails and one rollback write fails: the rollback must not claim success.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA', 'fltB'
    $lock = Lock-File $manifestPath
    $script:FailStartWriteFor = 'fltB'
    try { $outcome = Write-RevertManifestOrRollback -ManifestPath $manifestPath -Entries $entries -WindowsPath 'X:\Windows' }
    finally { $lock.Dispose(); $script:FailStartWriteFor = $null }
    Assert-True (-not $outcome.Written) 'The manifest is reported as not written.'
    Assert-True (-not $outcome.RolledBack) 'A partial rollback is not reported as complete.'
    Assert-Equal 1 $outcome.Restored 'Only fltA was restored.'
    Assert-True (@($outcome.RollbackErrors | Where-Object { $_ -match '^fltB: .*UnauthorizedAccessException' }).Count -eq 1) "The failed restore is named. Got: $($outcome.RollbackErrors -join ' | ')"
    Assert-True (@($outcome.RollbackErrors | Where-Object { $_ -match '^fltB: still at Start=4' }).Count -eq 1) 'The re-read proves fltB is still disabled.'
    Assert-Equal 0 (Get-Start 'fltA') 'fltA was restored.'
    Assert-Equal 4 (Get-Start 'fltB') 'fltB really is still disabled.'

    # Manifest write fails and the hive cannot be mounted for the rollback.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA'
    $script:FailHiveMount = $true
    $outcome = Write-RevertManifestOrRollback -ManifestPath (Join-Path $fixtureRoot 'missing\revert.json') -Entries $entries -WindowsPath 'X:\Windows'
    Assert-True (-not $outcome.RolledBack) 'A rollback that could not mount the hive is not reported as complete.'
    Assert-True ($outcome.RollbackErrors[0] -match '^Rollback: System.UnauthorizedAccessException') 'The mount failure is reported.'

    # Apply failure: a missing key or a refused write throws and changes nothing.
    Reset-Fixture
    Assert-Throws { Repair-Finding -Finding (New-DriverFinding 'fltMissing') -SystemRoot $script:SystemRoot -ControlSet 'ControlSet001' } 'no longer present' 'A missing service key fails the apply.'
    $script:FailStartWriteFor = 'fltC'
    Assert-Throws { Repair-Finding -Finding (New-DriverFinding 'fltC') -SystemRoot $script:SystemRoot -ControlSet 'ControlSet001' } 'not allowed' 'A refused write fails the apply.'
    $script:FailStartWriteFor = $null
    Assert-Equal 2 (Get-Start 'fltC') 'A failed apply leaves Start unchanged.'
    $entry = Repair-Finding -Finding (New-DriverFinding 'fltC') -SystemRoot $script:SystemRoot -ControlSet 'ControlSet001'
    Assert-Equal 2 $entry.OriginalStart 'The apply succeeds once the write is allowed, and records the original Start.'
    Assert-True ($null -eq (Repair-Finding -Finding (New-DriverFinding 'fltC') -SystemRoot $script:SystemRoot -ControlSet 'ControlSet001')) 'An already disabled driver yields no manifest entry, so a re-run never records 4 as the original.'

    # Revert failure: Invoke-DriverRevert reports every entry it could not restore.
    Reset-Fixture
    $entries = Invoke-FixtureRepair 'fltA', 'fltB'
    Remove-Item -LiteralPath "$script:SystemRoot\Services\fltA" -Recurse -Force
    $script:FailStartWriteFor = 'fltB'
    $revert = Invoke-DriverRevert -SystemRoot $script:SystemRoot -Entries $entries
    $script:FailStartWriteFor = $null
    Assert-Equal 0 $revert.Restored 'Nothing was restored.'
    Assert-Equal 2 @($revert.Errors).Count 'Both failures are reported.'
    Assert-True (@($revert.Errors | Where-Object { $_ -match '^fltA: the service key is no longer present' }).Count -eq 1) 'The missing key is reported.'
    Assert-True (@($revert.Errors | Where-Object { $_ -match '^fltB: System.UnauthorizedAccessException' }).Count -eq 1) 'The refused write is reported.'

    # Manifest removal after a revert: deleted and proven gone, or kept and reported.
    Reset-Fixture
    Set-Content -LiteralPath $manifestPath -Value '[]' -Encoding UTF8
    Clear-RevertManifest -ManifestPath $manifestPath
    Assert-True (-not (Test-Path -LiteralPath $manifestPath)) 'A deletable manifest is removed.'

    $lock = Lock-File $manifestPath
    try { Assert-Throws { Clear-RevertManifest -ManifestPath $manifestPath } 'being used by another process' 'A locked manifest fails the removal.' }
    finally { $lock.Dispose() }
    Assert-True (Test-Path -LiteralPath $manifestPath) 'A manifest that could not be removed is kept.'

    function Remove-Item { Param([string]$LiteralPath, [switch]$Force, $ErrorAction) }
    try { Assert-Throws { Clear-RevertManifest -ManifestPath $manifestPath } 'still present after it was deleted' 'A delete that silently leaves the file is caught.' }
    finally { Microsoft.PowerShell.Management\Remove-Item -LiteralPath Function:\Remove-Item }
    Assert-True (Test-Path -LiteralPath $manifestPath) 'The manifest is still there for the operator.'

    # The script body must route every manifest write and delete through the transactional helpers.
    $mainBody = $ast.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] }
    $mainText = ($mainBody | ForEach-Object { $_.Extent.Text }) -join "`n"
    Assert-True ($mainText -notmatch 'Write-RevertManifest\s+-') 'The script body never writes the manifest without the rollback.'
    Assert-True ($mainText -match 'Write-RevertManifestOrRollback') 'The script body writes the manifest through the rollback helper.'
    Assert-True ($mainText -notmatch 'Remove-Item[^\r\n]*manifestPath') 'The script body never deletes the manifest directly.'
    Assert-True ($mainText -match 'Clear-RevertManifest') 'The script body deletes the manifest through the verified helper.'
    Assert-True ($ast.Extent.Text -notmatch 'manifestPath[^\r\n]*SilentlyContinue') 'No manifest operation suppresses its error.'

    Write-Host "PASS: $script:Passed assertions in test-win-fix-third-party-drivers.ps1"
}
finally {
    if (Test-Path -LiteralPath $registryRoot) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $registryRoot -Recurse -Force }
    if (Test-Path -LiteralPath $fixtureRoot) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
