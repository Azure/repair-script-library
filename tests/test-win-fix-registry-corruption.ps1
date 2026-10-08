# Standalone fixture tests for the hive replacement and rollback paths in
# win-fix-registry-corruption.ps1. Every write is made to real files in a temp folder, and
# Copy-Item / Move-Item failures are injected by path so each rollback branch is exercised.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-fix-registry-corruption.ps1

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-fix-registry-corruption.ps1'
$commonHelper = Join-Path $repositoryRoot 'src/windows/common/helpers/OfflineRepairCommon.ps1'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rsl-regcorr-$([guid]::NewGuid())"
$script:AssertionCount = 0
$script:Failures = [System.Collections.Generic.List[string]]::new()

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    $script:AssertionCount++
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    $script:AssertionCount++
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', found '$Actual'." }
}

function Invoke-Case {
    Param([string]$Name, [scriptblock]$Body)
    Reset-Fixture
    try {
        & $Body
        Write-Host "ok   $Name"
    }
    catch {
        Write-Host "FAIL $Name : $($_.Exception.Message)"
        [void]$script:Failures.Add("$Name : $($_.Exception.Message)")
    }
}

. $commonHelper

# The script runs a repair when it is loaded, so only the functions under test are taken from it.
$wanted = @(
    'Get-HiveRollbackFailure', 'Test-HiveRollbackFailure', 'Move-HiveTransactionLog', 'Copy-HiveBackup',
    'Restore-HiveFileFromBackup', 'Undo-HiveReplacement', 'Repair-HiveInPlace', 'Restore-HiveFromRegBack'
)
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourceScript, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "The script under test does not parse: $($parseErrors[0].Message)" }
$definitions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted }, $false))
foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
$missing = @($wanted | Where-Object { $_ -notin @($definitions.Name) })
if ($missing.Count -gt 0) { Write-Host "Not defined by the script under test: $($missing -join ', ')" }
if ('Test-HiveRollbackFailure' -in $missing) {
    # Lets a run against an older revision report behaviour rather than a missing name.
    function Test-HiveRollbackFailure { Param($Exception) return $false }
}

# ---- stubs for the chkreg and hive loading layer ------------------------------------------

function Invoke-ChkReg {
    Param([string]$ChkRegPath, [string]$HivePath, [string]$ScratchDir, [bool]$Repair)
    if (-not $Repair) { return [PSCustomObject]@{ ExitCode = 0; FoundProblem = $false; Output = '' } }
    New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null
    $repaired = Join-Path $ScratchDir "$(Split-Path $HivePath -Leaf).repaired"
    Set-Content -LiteralPath $repaired -Value 'REPAIRED' -NoNewline
    return [PSCustomObject]@{ RepairedPath = $repaired; ExitCode = 0; FoundProblem = $false; Output = '' }
}

function Test-OfflineHiveFile {
    Param([string]$Path)
    $onDisk = -not $Path.StartsWith($global:RegFixture.Scratch, [System.StringComparison]::OrdinalIgnoreCase)
    if ($onDisk -and $global:RegFixture.InvalidOnDisk) {
        return [PSCustomObject]@{ IsValid = $false; Reason = 'FIXTURE: does not load' }
    }
    return [PSCustomObject]@{ IsValid = $true; Reason = '' }
}

function Get-HiveContentLossText {
    Param([string]$HiveName, [string]$Path)
    return $null
}

# ---- path keyed fault injection -----------------------------------------------------------
# A fault matches on the command, the source and the destination (wildcards allowed) and fires
# once. 'Fail' raises a non-terminating error without touching anything, as the real cmdlets
# do, so the caller's -ErrorAction decides whether it stops. 'Corrupt' reports success after
# writing the wrong bytes, which is how a silently failed copy looks to the caller.

function Add-Fault {
    Param([string]$Command, [string]$Source, [string]$Destination = '*', [ValidateSet('Fail', 'Corrupt')][string]$Mode = 'Fail')
    [void]$global:RegFixture.Faults.Add([PSCustomObject]@{ Command = $Command; Source = $Source; Destination = $Destination; Mode = $Mode; Fired = $false })
}

function Get-Fault {
    Param([string]$Command, [string]$Source, [string]$Destination)
    foreach ($fault in $global:RegFixture.Faults) {
        if (-not $fault.Fired -and $fault.Command -eq $Command -and $Source -like $fault.Source -and $Destination -like $fault.Destination) {
            $fault.Fired = $true
            return $fault
        }
    }
    return $null
}

function Copy-Item {
    [CmdletBinding()]
    Param([string]$LiteralPath, [string]$Destination, [switch]$Force)
    $fault = Get-Fault -Command 'Copy-Item' -Source $LiteralPath -Destination $Destination
    if ($fault -and $fault.Mode -eq 'Fail') { Write-Error "FIXTURE: copying $LiteralPath to $Destination failed."; return }
    if ($fault -and $fault.Mode -eq 'Corrupt') {
        Microsoft.PowerShell.Management\Set-Content -LiteralPath $Destination -Value 'TORN' -NoNewline
        return
    }
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force -ErrorAction Stop
}

function Move-Item {
    [CmdletBinding()]
    Param([string]$LiteralPath, [string]$Destination, [switch]$Force)
    $fault = Get-Fault -Command 'Move-Item' -Source $LiteralPath -Destination $Destination
    if ($fault) { Write-Error "FIXTURE: moving $LiteralPath to $Destination failed."; return }
    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force -ErrorAction Stop
}

# ---- fixture ------------------------------------------------------------------------------

function Reset-Fixture {
    if (Test-Path -LiteralPath $fixtureRoot) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    $config = Join-Path $fixtureRoot 'Config'
    $regBack = Join-Path $config 'RegBack'
    $scratch = Join-Path $fixtureRoot 'scratch'
    New-Item -ItemType Directory -Path $regBack, $scratch -Force | Out-Null
    $global:RegFixture = @{
        Config = $config
        RegBack = $regBack
        Scratch = $scratch
        InvalidOnDisk = $false
        Faults = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    Clear-OfflineRepairLog
}

function New-Hive {
    Param([string]$Name, [string]$Content = "ORIGINAL-$Name", [string[]]$Logs = @('.LOG', '.LOG1', '.LOG2'), [string]$RegBackContent = "REGBACK-$Name")
    $live = Join-Path $global:RegFixture.Config $Name
    Set-Content -LiteralPath $live -Value $Content -NoNewline
    foreach ($suffix in $Logs) { Set-Content -LiteralPath "$live$suffix" -Value "LOG$suffix-$Name" -NoNewline }
    $source = Join-Path $global:RegFixture.RegBack $Name
    Set-Content -LiteralPath $source -Value $RegBackContent -NoNewline
    return [PSCustomObject]@{ Name = $Name; LivePath = $live; SourcePath = $source }
}

function Get-Text {
    Param([string]$Path)
    return [System.IO.File]::ReadAllText($Path)
}

function Get-MovedLogCount {
    Param([string]$Live)
    return @(Get-ChildItem -LiteralPath (Split-Path $Live -Parent) -Filter "$(Split-Path $Live -Leaf).LOG*.bak-*" -Force).Count
}

function Assert-HiveOriginal {
    Param([string]$Live, [string]$Name, [string]$Context)
    Assert-Equal "ORIGINAL-$Name" (Get-Text $Live) "$Context The live $Name hive is the original."
    foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
        Assert-True (Test-Path -LiteralPath "$Live$suffix") "$Context $Name$suffix is back beside its hive."
        Assert-Equal "LOG$suffix-$Name" (Get-Text "$Live$suffix") "$Context $Name$suffix still holds its own content."
    }
    Assert-Equal 0 (Get-MovedLogCount $Live) "$Context No $Name log is left under a .bak name."
}

function Get-LogText {
    Param([string]$Level)
    return (@(Get-OfflineRepairLog | Where-Object { -not $Level -or $_.Level -eq $Level } | ForEach-Object { $_.Message }) -join "`n")
}

function Invoke-InPlace {
    Param([string]$Name, [switch]$TestOnly)
    $finding = [PSCustomObject]@{ Item = $Name; Data = [PSCustomObject]@{ Path = (Join-Path $global:RegFixture.Config $Name) } }
    return Repair-HiveInPlace -Finding $finding -ChkRegPath 'chkreg.exe' -ScratchDir $global:RegFixture.Scratch -TestOnly:$TestOnly
}

try {
    # ---- Repair-HiveInPlace -------------------------------------------------------------

    Invoke-Case 'in place: a clean install replaces the hive and moves every log aside' {
        $hive = New-Hive SYSTEM
        $result = Invoke-InPlace SYSTEM
        Assert-True ($result -eq $true) 'The repair reports success.'
        Assert-Equal 'REPAIRED' (Get-Text $hive.LivePath) 'The repaired hive is installed.'
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
            Assert-True (-not (Test-Path -LiteralPath "$($hive.LivePath)$suffix")) "SYSTEM$suffix no longer sits beside the repaired hive."
        }
        Assert-Equal 3 (Get-MovedLogCount $hive.LivePath) 'Every log was kept under a .bak name.'
        $backup = @(Get-ChildItem -LiteralPath $global:RegFixture.Config -Filter 'SYSTEM.bak-*' -Force)
        Assert-Equal 1 $backup.Count 'One hive backup was written.'
        Assert-Equal 'ORIGINAL-SYSTEM' (Get-Text $backup[0].FullName) 'The backup holds the original hive.'
    }

    Invoke-Case 'in place: TestOnly writes nothing to the disk' {
        $hive = New-Hive SYSTEM
        $result = Invoke-InPlace SYSTEM -TestOnly
        Assert-True ($result -eq $true) 'TestOnly reports the hive as repairable.'
        Assert-HiveOriginal $hive.LivePath SYSTEM 'TestOnly:'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $global:RegFixture.Config -Filter 'SYSTEM.bak-*' -Force).Count 'TestOnly writes no backup.'
    }

    Invoke-Case 'in place: a backup copy that fails leaves the hive untouched' {
        $hive = New-Hive SYSTEM
        Add-Fault -Command 'Copy-Item' -Source $hive.LivePath -Destination '*.bak-*'
        $threw = $false
        try { [void](Invoke-InPlace SYSTEM) } catch { $threw = $true }
        Assert-True $threw 'A failed backup stops the replacement.'
        Assert-HiveOriginal $hive.LivePath SYSTEM 'Failed backup:'
    }

    Invoke-Case 'in place: a torn backup is caught before the hive is overwritten' {
        $hive = New-Hive SYSTEM
        Add-Fault -Command 'Copy-Item' -Source $hive.LivePath -Destination '*.bak-*' -Mode Corrupt
        $threw = $false
        try { [void](Invoke-InPlace SYSTEM) } catch { $threw = $true; $message = $_.Exception.Message }
        Assert-True $threw 'A backup that does not match the hive stops the replacement.'
        Assert-True ($message -match 'does not match') "The failure names the mismatch. Message: $message"
        Assert-HiveOriginal $hive.LivePath SYSTEM 'Torn backup:'
    }

    Invoke-Case 'in place: a hive that does not validate on disk is rolled back and verified' {
        $hive = New-Hive SYSTEM
        $global:RegFixture.InvalidOnDisk = $true
        $result = Invoke-InPlace SYSTEM
        Assert-True ($result -eq $false) 'The repair reports failure.'
        Assert-HiveOriginal $hive.LivePath SYSTEM 'Invalid on disk:'
        Assert-True ((Get-LogText Warning) -match 'put back from .* and verified') 'The warning says the original was put back and verified.'
    }

    Invoke-Case 'in place: a rollback copy that fails stops the run with the backup location' {
        $hive = New-Hive SYSTEM
        $global:RegFixture.InvalidOnDisk = $true
        Add-Fault -Command 'Copy-Item' -Source '*SYSTEM.bak-*' -Destination $hive.LivePath
        $caught = $null
        try { $result = Invoke-InPlace SYSTEM } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught) "A failed rollback must not return quietly. It returned '$result'."
        Assert-True (Test-HiveRollbackFailure $caught) 'The exception is tagged as a rollback failure.'
        Assert-True ($caught.Message -match [regex]::Escape("$($hive.LivePath).bak-")) "The message names the backup to restore from. Message: $($caught.Message)"
        Assert-True ($caught.Message -match 'unverified state') 'The message says the disk is unverified.'
    }

    Invoke-Case 'in place: a rollback copy that completes with the wrong bytes is caught' {
        $hive = New-Hive SYSTEM
        $global:RegFixture.InvalidOnDisk = $true
        Add-Fault -Command 'Copy-Item' -Source '*SYSTEM.bak-*' -Destination $hive.LivePath -Mode Corrupt
        $caught = $null
        try { [void](Invoke-InPlace SYSTEM) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught -and (Test-HiveRollbackFailure $caught)) 'A rollback that is not verified by hash is a rollback failure.'
    }

    Invoke-Case 'in place: a log that cannot be moved rolls back the hive and the logs already moved' {
        $hive = New-Hive SYSTEM
        Add-Fault -Command 'Move-Item' -Source "$($hive.LivePath).LOG1"
        $result = $null
        try { $result = Invoke-InPlace SYSTEM } catch { throw "A recoverable log failure must not throw: $($_.Exception.Message)" }
        Assert-True ($result -eq $false) 'The repair reports failure instead of success over a stale log.'
        Assert-HiveOriginal $hive.LivePath SYSTEM 'Log move failure:'
        Assert-True ((Get-LogText Warning) -match 'logs were put back') 'The warning says the logs were put back.'
    }

    Invoke-Case 'in place: a log that cannot be moved back stops the run' {
        $hive = New-Hive SYSTEM
        Add-Fault -Command 'Move-Item' -Source "$($hive.LivePath).LOG1"
        Add-Fault -Command 'Move-Item' -Source "$($hive.LivePath).LOG.bak-*" -Destination "$($hive.LivePath).LOG"
        $caught = $null
        try { [void](Invoke-InPlace SYSTEM) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught -and (Test-HiveRollbackFailure $caught)) 'A log that cannot be put back is a rollback failure.'
        Assert-True ($caught.Message -match 'SYSTEM\.LOG') "The message names the stranded log. Message: $($caught.Message)"
        Assert-Equal 'ORIGINAL-SYSTEM' (Get-Text $hive.LivePath) 'The hive itself was still put back.'
    }

    # ---- Restore-HiveFromRegBack --------------------------------------------------------

    Invoke-Case 'RegBack: a clean restore replaces the identity pair and moves their logs' {
        $sam = New-Hive SAM
        $security = New-Hive SECURITY
        $plan = [PSCustomObject]@{ Hives = @($sam, $security) }
        $restored = @(Restore-HiveFromRegBack -Plan $plan -Wanted @('SAM'))
        Assert-Equal 'SAM,SECURITY' (($restored | Sort-Object) -join ',') 'SAM pulls in SECURITY.'
        Assert-Equal 'REGBACK-SAM' (Get-Text $sam.LivePath) 'SAM was restored.'
        Assert-Equal 'REGBACK-SECURITY' (Get-Text $security.LivePath) 'SECURITY was restored.'
        Assert-Equal 3 (Get-MovedLogCount $sam.LivePath) 'Every SAM log was moved aside.'
        Assert-Equal 3 (Get-MovedLogCount $security.LivePath) 'Every SECURITY log was moved aside.'
    }

    Invoke-Case 'RegBack: a log move failure on the second hive rolls back both hives and every log' {
        $sam = New-Hive SAM
        $security = New-Hive SECURITY
        $plan = [PSCustomObject]@{ Hives = @($sam, $security) }
        Add-Fault -Command 'Move-Item' -Source "$($security.LivePath).LOG1"
        $caught = $null
        try { [void](Restore-HiveFromRegBack -Plan $plan -Wanted @('SAM', 'SECURITY')) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught) 'A log that cannot be moved fails the restore instead of leaving it behind.'
        Assert-True (-not (Test-HiveRollbackFailure $caught)) 'A complete rollback is reported as an ordinary failure.'
        Assert-HiveOriginal $sam.LivePath SAM 'RegBack log failure:'
        Assert-HiveOriginal $security.LivePath SECURITY 'RegBack log failure:'
    }

    Invoke-Case 'RegBack: a rollback that cannot restore a hive is reported as a rollback failure' {
        $sam = New-Hive SAM
        $security = New-Hive SECURITY
        $plan = [PSCustomObject]@{ Hives = @($sam, $security) }
        Add-Fault -Command 'Move-Item' -Source "$($security.LivePath).LOG"
        Add-Fault -Command 'Copy-Item' -Source "$($sam.LivePath).bak-*" -Destination $sam.LivePath
        $caught = $null
        try { [void](Restore-HiveFromRegBack -Plan $plan -Wanted @('SAM', 'SECURITY')) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught -and (Test-HiveRollbackFailure $caught)) 'The failed rollback is tagged.'
        Assert-True ($caught.Message -match [regex]::Escape($sam.LivePath)) "The message names the hive left behind. Message: $($caught.Message)"
        Assert-True ((Get-LogText Error) -match 'Rollback failed') 'The failed step is logged as an error.'
        Assert-HiveOriginal $security.LivePath SECURITY 'Partial rollback:'
        Assert-Equal 0 (Get-MovedLogCount $sam.LivePath) 'SAM logs were still put back.'
    }

    Invoke-Case 'RegBack: a hive created by the restore is removed again on rollback' {
        $sam = New-Hive SAM
        $security = New-Hive SECURITY -Logs @()
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $security.LivePath -Force
        $plan = [PSCustomObject]@{ Hives = @($sam, $security) }
        Add-Fault -Command 'Copy-Item' -Source $security.SourcePath -Destination $security.LivePath -Mode Corrupt
        $caught = $null
        try { [void](Restore-HiveFromRegBack -Plan $plan -Wanted @('SAM', 'SECURITY')) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught -and -not (Test-HiveRollbackFailure $caught)) 'The hash mismatch fails the restore and the rollback completes.'
        Assert-True (-not (Test-Path -LiteralPath $security.LivePath)) 'The SECURITY file that did not exist before is removed.'
        Assert-HiveOriginal $sam.LivePath SAM 'Created hive:'
    }

    # ---- the main loop stops on a rollback failure --------------------------------------

    Invoke-Case 'main loop: a rollback failure from the in place repair is not swallowed' {
        $tries = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.TryStatementAst] -and $node.Body.Extent.Text -match 'Repair-HiveInPlace -Finding \$finding' -and $node.Body.Extent.Text -notmatch '-TestOnly' }, $true))
        Assert-Equal 1 $tries.Count 'The repair loop wraps the in place repair in one try.'
        $handler = $tries[0].CatchClauses[0].Body.Extent.Text
        Assert-True ($handler -match 'Test-HiveRollbackFailure[^\r\n]*\{\s*throw\s*\}') 'The handler rethrows a rollback failure before falling through to RegBack.'
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Variable -Name RegFixture -Scope Global -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    Write-Host "FAIL: $($script:Failures.Count) case(s) failed in $(Split-Path $PSCommandPath -Leaf)"
    exit 1
}
"PASS: $script:AssertionCount assertions in $(Split-Path $PSCommandPath -Leaf)"
