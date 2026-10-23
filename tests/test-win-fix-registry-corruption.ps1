# Standalone fixture tests for detection, final status, hive replacement and rollback in
# win-fix-registry-corruption.ps1. Every write is made to real files in a temp folder, and
# Copy/move/hash failures are injected by path; backup-copy failures use a real file lock.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-fix-registry-corruption.ps1

$ErrorActionPreference = 'Stop'
$null = Get-Command Microsoft.PowerShell.Utility\Get-FileHash -ErrorAction Stop
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
    'Restore-HiveFileFromBackup', 'Undo-HiveReplacement', 'Repair-HiveInPlace', 'Restore-HiveFromRegBack',
    'Invoke-ChkReg', 'Get-OfflineHiveSpec', 'New-Finding', 'Get-AllFinding', 'Write-OperatorLog',
    'Get-RegBackPlan', 'Test-RegBackMaintained', 'New-PrivateScratchDirectory'
)
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourceScript, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "The script under test does not parse: $($parseErrors[0].Message)" }
$mainTry = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] })
if ($mainTry.Count -ne 1) { throw 'Expected one top-level repair try/catch/finally.' }
$script:MainUnderTest = [scriptblock]::Create($mainTry[0].Extent.Text + "`nreturn `$status")
$definitions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted }, $false))
foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
$missing = @($wanted | Where-Object { $_ -notin @($definitions.Name) })
if ($missing.Count -gt 0) { Write-Host "Not defined by the script under test: $($missing -join ', ')" }

# A stub Invoke-ChkReg is defined further down to drive the hive-replacement tests, which would
# otherwise shadow the real function under test. The genuine implementation is kept under its
# own name so it can still be exercised directly.
if ('Invoke-ChkReg' -in @($definitions.Name)) {
    ${function:Invoke-ChkRegReal} = ${function:Invoke-ChkReg}
}
if ('New-PrivateScratchDirectory' -in @($definitions.Name)) {
    ${function:New-PrivateScratchDirectoryReal} = ${function:New-PrivateScratchDirectory}
    function New-PrivateScratchDirectory {
        Param([string]$Parent)
        if ($Parent -eq $env:TEMP) { $Parent = $global:RegFixture.Scratch }
        New-PrivateScratchDirectoryReal -Parent $Parent
    }
}
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [PSCustomObject]@{ Exists = $false; IsValid = $false; Size = 0; Reason = 'not present' }
    }
    $size = (Get-Item -LiteralPath $Path).Length
    $onDisk = -not $Path.StartsWith($global:RegFixture.Scratch, [System.StringComparison]::OrdinalIgnoreCase)
    if ($onDisk -and ($global:RegFixture.InvalidOnDisk -or (Split-Path $Path -Leaf) -eq $global:RegFixture.DamagedHive)) {
        return [PSCustomObject]@{ Exists = $true; IsValid = $false; Size = $size; Reason = 'FIXTURE: does not load' }
    }
    return [PSCustomObject]@{ Exists = $true; IsValid = $true; Size = $size; Reason = '' }
}

function Test-HiveContentIntact {
    Param([string]$HiveName, [string]$Path)
    if ($HiveName -eq $global:RegFixture.ProbeFailure) {
        throw [System.InvalidOperationException]::new("FIXTURE: $HiveName probe unavailable")
    }
    return [PSCustomObject]@{ IsIntact = $true; Missing = @() }
}

function Get-OfflineWindowsDisk {
    Param([string]$WindowsDrive)
    if ($global:RegFixture.DiscoveryFailure) { throw 'FIXTURE: discovery failed after assigning a drive letter' }
    return [PSCustomObject]@{ WindowsPath = $global:RegFixture.Windows; DiskNumber = -1; ProductName = 'fixture'; BuildNumber = 'fixture' }
}

function Get-ChkRegPath { return 'fixture-chkreg.exe' }

function Get-RegBackSuggestion {
    Param([string]$ConfigPath, [string[]]$Wanted, [string]$ChkRegPath, [string]$ScratchDir)
    return [PSCustomObject]@{ Available = $false; Hives = @(); WrittenUtc = $null }
}

function Resolve-RegBackSource {
    Param([string]$SourcePath, [string]$ChkRegPath, [string]$ScratchDir)
    return [PSCustomObject]@{ IsUsable = $true; Path = $SourcePath; Reconciled = $false; Reason = '' }
}

function Clear-OfflineDriveLetter {
    $global:RegFixture.DriveLettersCleared = $true
    if ($global:RegFixture.CleanupWarning) { Add-OfflineRepairLog -Level Warning -Message 'FIXTURE: a temporary drive letter could not be removed.' }
}

function Open-OfflineRegistryReader {
    Param([string]$Path)
    $global:RegFixture.ReaderPath = $Path
    $reader = [pscustomobject]@{}
    $reader | Add-Member -MemberType ScriptMethod -Name ReadDword -Value {
        Param([string]$Key, [string]$Name)
        if ($global:RegFixture.ReaderReadFailure) { throw 'FIXTURE: metadata read failed' }
        if ($Key -eq 'Select' -and $Name -eq 'Current') { return 2 }
        if ($Key -eq 'ControlSet002\Control\Session Manager\Configuration Manager' -and $Name -eq 'EnablePeriodicBackup') {
            return $global:RegFixture.PeriodicBackup
        }
        throw "Unexpected reader request: $Key\$Name"
    }
    $reader | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $global:RegFixture.ReaderDisposed = $true
        if ($global:RegFixture.ReaderCloseFailure) { throw 'FIXTURE: reader close failed' }
    }
    return $reader
}

function Get-Date {
    Param([string]$Format)
    if ($Format -eq 'yyyyMMddHHmmss' -and $global:RegFixture.FixedStamp) { return $global:RegFixture.FixedStamp }
    if ($Format) { return Microsoft.PowerShell.Utility\Get-Date -Format $Format }
    return Microsoft.PowerShell.Utility\Get-Date
}

function Log-Output {
    Param([string]$Message)
    [void]$global:RegFixture.OperatorLog.Add($Message)
    return $Message
}

function Log-Info { Param([string]$Message) Log-Output $Message }
function Log-Warning { Param([string]$Message) Log-Output $Message }
function Log-Error { Param([string]$Message) Log-Output $Message }

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

function Remove-Item {
    [CmdletBinding()]
    Param([string]$LiteralPath, [switch]$Recurse, [switch]$Force)
    $fault = Get-Fault -Command 'Remove-Item' -Source $LiteralPath -Destination ''
    if ($fault) { Write-Error "FIXTURE: deleting $LiteralPath failed."; return }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse:$Recurse -Force:$Force -ErrorAction Stop
}

function Get-FileHash {
    [CmdletBinding()]
    Param([string]$LiteralPath, [string]$Algorithm = 'SHA256')
    $fault = Get-Fault -Command 'Get-FileHash' -Source $LiteralPath -Destination ''
    if ($fault -and $fault.Mode -eq 'Corrupt') {
        Microsoft.PowerShell.Management\Set-Content -LiteralPath $LiteralPath -Value 'TORN' -NoNewline
    }
    Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm -ErrorAction Stop
}

# ---- fixture ------------------------------------------------------------------------------

function Reset-Fixture {
    if (Test-Path -LiteralPath $fixtureRoot) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    $windows = Join-Path $fixtureRoot 'Windows'
    $config = Join-Path $windows 'System32\Config'
    $regBack = Join-Path $config 'RegBack'
    $scratch = Join-Path $fixtureRoot 'scratch'
    New-Item -ItemType Directory -Path $regBack, $scratch -Force | Out-Null
    $global:RegFixture = @{
        Config = $config
        Windows = $windows
        RegBack = $regBack
        Scratch = $scratch
        InvalidOnDisk = $false
        DamagedHive = ''
        ProbeFailure = ''
        FixedStamp = ''
        DriveLettersCleared = $false
        DiscoveryFailure = $false
        CleanupWarning = $false
        PeriodicBackup = 1
        ReaderReadFailure = $false
        ReaderCloseFailure = $false
        ReaderDisposed = $false
        ReaderPath = ''
        OperatorLog = [System.Collections.Generic.List[string]]::new()
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

function Get-ConfigManifest {
    return (@(Get-ChildItem -LiteralPath $global:RegFixture.Config -File -Recurse |
                Sort-Object FullName | ForEach-Object {
                    "$($_.FullName):$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)"
                }) -join "`n")
}

function Invoke-FixtureMain {
    $STATUS_SUCCESS = 'fixture-success'
    $STATUS_ERROR = 'fixture-error'
    $windowsDrive = ''
    $isDetectOnly = $false
    $isRegBackAllowed = $false
    $hiveFilter = $null
    $scratchDir = $global:RegFixture.Scratch
    $logFile = Join-Path $fixtureRoot 'operator.log'
    $result = @(& $script:MainUnderTest)
    return $result[-1]
}

function Invoke-InPlace {
    Param([string]$Name, [switch]$TestOnly)
    $finding = [PSCustomObject]@{ Item = $Name; Data = [PSCustomObject]@{ Path = (Join-Path $global:RegFixture.Config $Name) } }
    return Repair-HiveInPlace -Finding $finding -ChkRegPath 'chkreg.exe' -ScratchDir $global:RegFixture.Scratch -TestOnly:$TestOnly
}

function New-FakeChkReg {
    # Stands in for chkreg.exe: it writes its own status text to stderr and exits 0, which is
    # exactly how the real tool reports success. Used to prove that text is not mistaken for a
    # terminating error.
    Param([string]$StderrText = 'ChkpValidateHiveAndRecoverFromLog succeeded.', [int]$ExitCode = 0)
    $path = Join-Path $global:RegFixture.Scratch "fake-chkreg-$([guid]::NewGuid()).cmd"
    Set-Content -LiteralPath $path -Value @(
        '@echo off'
        "echo $StderrText 1>&2"
        "exit /b $ExitCode"
    ) -Encoding Ascii
    return $path
}

try {
    foreach ($missingHive in @('SAM', 'SECURITY')) {
        Invoke-Case "detection: missing $missingHive is actionable and cannot report a successful repair" {
            foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) { [void](New-Hive $name) }
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $global:RegFixture.Config $missingHive) -Force
            $before = Get-ConfigManifest
            $findings = @(Get-AllFinding -ConfigPath $global:RegFixture.Config -ChkRegPath 'fixture' -ScratchDir $global:RegFixture.Scratch)
            Assert-Equal 1 $findings.Count 'Only the absent identity hive is reported.'
            Assert-Equal $missingHive $findings[0].Item 'The finding names the missing hive.'
            Assert-Equal 'HiveMissing' $findings[0].Cause 'The finding identifies an absent required file.'
            Assert-Equal 'fixture-error' (Invoke-FixtureMain) 'Default repair returns the error status with no recovery source.'
            Assert-True (($global:RegFixture.OperatorLog -join "`n") -match "STILL PRESENT \[HiveMissing\].*$missingHive") 'The operator sees the unresolved missing hive.'
            Assert-Equal $before (Get-ConfigManifest) 'All unrelated hives, transaction logs and backups remain unchanged.'
        }
    }

    foreach ($failedHive in @('SAM', 'SECURITY')) {
        Invoke-Case "detection: a $failedHive content-probe exception aborts before any replacement" {
            foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) { [void](New-Hive $name) }
            $global:RegFixture.ProbeFailure = $failedHive
            $global:RegFixture.DamagedHive = 'SYSTEM'
            $before = Get-ConfigManifest
            $caught = $null
            try { [void](Get-AllFinding -ConfigPath $global:RegFixture.Config -ChkRegPath 'fixture' -ScratchDir $global:RegFixture.Scratch) }
            catch { $caught = $_.Exception }
            Assert-True ($null -ne $caught) 'An indeterminate integrity check cannot return an empty finding list.'
            Assert-True ($caught.Message -match "$failedHive.*required-content") 'The error identifies the hive and required-content check.'
            Assert-True ($caught.Message -match 'InvalidOperationException.*probe unavailable') 'The original exception context is preserved.'
            Assert-Equal 'fixture-error' (Invoke-FixtureMain) 'The actual main handler returns the error status.'
            Assert-True (($global:RegFixture.OperatorLog -join "`n") -match "$failedHive.*required-content") 'The operator sees the failed integrity check.'
            Assert-Equal $before (Get-ConfigManifest) 'Detection failure performs no hive, log or backup mutation.'
        }
    }

    Invoke-Case 'detection: healthy required hives and absent optional hives remain a no-write success' {
        foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) { [void](New-Hive $name) }
        $before = Get-ConfigManifest
        Assert-Equal 0 @(Get-AllFinding -ConfigPath $global:RegFixture.Config -ChkRegPath 'fixture' -ScratchDir $global:RegFixture.Scratch).Count 'Absent DEFAULT and COMPONENTS are still optional.'
        Assert-Equal 'fixture-success' (Invoke-FixtureMain) 'Healthy hives retain the success status.'
        Assert-True $global:RegFixture.DriveLettersCleared 'The main finally releases discovery-assigned drive letters.'
        Assert-Equal $before (Get-ConfigManifest) 'A healthy installation produces zero hive writes.'
    }

    Invoke-Case 'RegBack plan: missing identity backups do not redefine the SYSTEM/SOFTWARE core set' {
        [void](New-Hive SYSTEM)
        [void](New-Hive SOFTWARE)
        $plan = Get-RegBackPlan -ConfigPath $global:RegFixture.Config -ScratchDir $global:RegFixture.Scratch
        Assert-True $plan.CanRestore 'Core backups remain usable when identity backups are absent.'
        Assert-Equal 'SOFTWARE,SYSTEM' (($plan.Hives.Name | Sort-Object) -join ',') 'Only the original core set is selected.'
    }

    Invoke-Case 'RegBack plan: core backups written more than a day apart are rejected' {
        $system = New-Hive SYSTEM
        [void](New-Hive SOFTWARE)
        (Get-Item -LiteralPath $system.SourcePath).LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-3)
        $plan = Get-RegBackPlan -ConfigPath $global:RegFixture.Config -ScratchDir $global:RegFixture.Scratch
        Assert-True (-not $plan.CanRestore) 'Individually valid but mismatched core backups are not a consistent restore set.'
        Assert-Equal 0 $plan.Hives.Count 'No replacement is authorized.'
        Assert-True ($plan.Reason -match 'SYSTEM.*SOFTWARE.*hours') 'The reason names the mismatched core hives and their time gap.'
    }

    Invoke-Case 'RegBack plan: stale identity backups remain excluded from the core set' {
        foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) {
            $hiveFile = New-Hive $name
            if ($name -in @('SAM', 'SECURITY')) { (Get-Item -LiteralPath $hiveFile.SourcePath).LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-3) }
        }
        $plan = Get-RegBackPlan -ConfigPath $global:RegFixture.Config -ScratchDir $global:RegFixture.Scratch
        Assert-True $plan.CanRestore 'The matched SYSTEM/SOFTWARE backups are still usable.'
        Assert-Equal 'SOFTWARE,SYSTEM' (($plan.Hives.Name | Sort-Object) -join ',') 'Stale identity backups cannot bypass the timestamp gate.'
    }

    Invoke-Case 'RegBack plan: an identity pair more than a day apart is excluded together' {
        $time = [datetime]::UtcNow
        foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) {
            $hiveFile = New-Hive $name
            $written = $time
            if ($name -eq 'SAM') { $written = $time.AddHours(-23) }
            if ($name -eq 'SECURITY') { $written = $time.AddHours(23) }
            (Get-Item -LiteralPath $hiveFile.SourcePath).LastWriteTimeUtc = $written
        }
        $plan = Get-RegBackPlan -ConfigPath $global:RegFixture.Config -ScratchDir $global:RegFixture.Scratch
        Assert-True $plan.CanRestore 'The consistent core remains available.'
        Assert-Equal 'SOFTWARE,SYSTEM' (($plan.Hives.Name | Sort-Object) -join ',') 'Individually near-core but mutually mismatched identity hives are excluded together.'
    }

    Invoke-Case 'scratch: private directories have unique names and a restricted inheritable DACL' {
        $first = New-PrivateScratchDirectory -Parent $global:RegFixture.Scratch
        $second = New-PrivateScratchDirectory -Parent $global:RegFixture.Scratch
        Assert-True ($first -ne $second) 'Two operations cannot reuse a scratch directory.'
        $acl = Get-Acl -LiteralPath $first
        Assert-True $acl.AreAccessRulesProtected 'The directory does not inherit broad TEMP access.'
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object)
        $ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $expectedSids = @('S-1-5-18', 'S-1-5-32-544', $ownerSid) | Sort-Object -Unique
        Assert-Equal ($expectedSids -join ',') ($sids -join ',') 'Only the repair identity, SYSTEM and Administrators receive access.'
        Assert-True (@($acl.Access | Where-Object { $_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl' }).Count -eq 0) 'The private directory remains usable by its repair identity.'
        Assert-True (@($acl.Access | Where-Object { $_.InheritanceFlags -ne 'ContainerInherit, ObjectInherit' }).Count -eq 0) 'Copies and subdirectories inherit the same restriction.'
    }

    Invoke-Case 'scratch: a reparse-point parent is rejected before copying any hive' {
        $target = Join-Path $fixtureRoot 'junction-target'
        $link = Join-Path $global:RegFixture.Scratch 'junction-parent'
        New-Item -ItemType Directory -Path $target | Out-Null
        New-Item -ItemType Junction -Path $link -Target $target | Out-Null
        try {
            $caught = $null
            try { [void](New-PrivateScratchDirectory -Parent $link) } catch { $caught = $_.Exception }
            Assert-True ($null -ne $caught -and $caught.Message -match 'reparse') 'An untrusted parent is not followed.'
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $target).Count 'No scratch files reach the linked target.'
        }
        finally { [System.IO.Directory]::Delete($link) }
    }

    Invoke-Case 'main: cleanup warnings precede the final status' {
        foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) { [void](New-Hive $name) }
        $global:RegFixture.CleanupWarning = $true
        Assert-Equal 'fixture-success' (Invoke-FixtureMain) 'A warning does not displace the final result.'
        Assert-True (($global:RegFixture.OperatorLog -join "`n") -match 'temporary drive letter') 'The helper cleanup warning is surfaced.'
    }

    Invoke-Case 'main: drive letters are released after partial discovery fails' {
        $global:RegFixture.DiscoveryFailure = $true
        Assert-Equal 'fixture-error' (Invoke-FixtureMain) 'Discovery failure retains the error status.'
        Assert-True $global:RegFixture.DriveLettersCleared 'Cleanup runs even before discovery returns an offline object.'
    }

    Invoke-Case 'main: failed scratch deletion is visible and cannot report success' {
        foreach ($name in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) { [void](New-Hive $name) }
        Add-Fault -Command 'Remove-Item' -Source "$($global:RegFixture.Scratch)\*" -Destination ''
        Assert-Equal 'fixture-error' (Invoke-FixtureMain) 'Credential-bearing scratch cleanup failure changes the final status.'
        Assert-True (($global:RegFixture.OperatorLog -join "`n") -match 'scratch.*FIXTURE') 'The retained scratch path and failure are operator-visible.'
        Assert-True $global:RegFixture.DriveLettersCleared 'Drive-letter cleanup still runs after scratch cleanup fails.'
    }

    Invoke-Case 'RegBack maintenance: the selected control set is read without registry mounts' {
        $hiveFile = New-Hive SYSTEM
        $before = Get-ConfigManifest
        Assert-True (Test-RegBackMaintained -ConfigPath $global:RegFixture.Config) 'The enabled setting is detected.'
        Assert-Equal $hiveFile.LivePath $global:RegFixture.ReaderPath 'SYSTEM is opened read-only in place.'
        Assert-True $global:RegFixture.ReaderDisposed 'The reader is closed.'
        Assert-Equal $before (Get-ConfigManifest) 'Metadata reads do not copy or mutate hives or logs.'
        $global:RegFixture.PeriodicBackup = $null
        Assert-True (-not (Test-RegBackMaintained -ConfigPath $global:RegFixture.Config)) 'An absent setting is conservatively treated as disabled.'
    }

    Invoke-Case 'RegBack maintenance: read failures are logged and the reader is closed' {
        [void](New-Hive SYSTEM)
        $global:RegFixture.ReaderReadFailure = $true
        Assert-True (-not (Test-RegBackMaintained -ConfigPath $global:RegFixture.Config)) 'An unverified backup is not offered.'
        Assert-True $global:RegFixture.ReaderDisposed 'A failed read still disposes the reader.'
        Assert-True ((Get-LogText) -match 'metadata read failed') 'The read failure is recorded explicitly.'
    }

    Invoke-Case 'RegBack maintenance: a reader close failure is not swallowed' {
        [void](New-Hive SYSTEM)
        $global:RegFixture.ReaderCloseFailure = $true
        $caught = $null
        try { [void](Test-RegBackMaintained -ConfigPath $global:RegFixture.Config) } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught -and $caught.Message -match 'reader close failed') 'Failed resource cleanup aborts instead of reporting a verified setting.'
    }

    Invoke-Case 'scratch: a failed recovery-log copy prevents chkreg from running' {
        $hiveFile = New-Hive SYSTEM
        Add-Fault -Command 'Copy-Item' -Source "$($hiveFile.LivePath).LOG1"
        $caught = $null
        try { [void](Invoke-ChkRegReal -ChkRegPath (New-FakeChkReg) -HivePath $hiveFile.LivePath -ScratchDir $global:RegFixture.Scratch) }
        catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught) 'A present log that could not be copied is not silently omitted.'
        Assert-True ($caught.Message -match 'SYSTEM.LOG1') 'The error identifies the unreadable recovery log.'
    }

    Invoke-Case 'scratch: validation after log retirement cannot reuse stale scratch logs' {
        $hiveFile = New-Hive SYSTEM
        $tool = New-FakeChkReg
        $first = Invoke-ChkRegReal -ChkRegPath $tool -HivePath $hiveFile.LivePath -ScratchDir $global:RegFixture.Scratch -Repair $true
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath "$($hiveFile.LivePath)$suffix" -Force }
        $second = Invoke-ChkRegReal -ChkRegPath $tool -HivePath $hiveFile.LivePath -ScratchDir $global:RegFixture.Scratch -Repair $true
        Assert-True ($first.RepairedPath -ne $second.RepairedPath) 'Every check uses its own snapshot.'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath (Split-Path $second.RepairedPath -Parent) -Filter 'SYSTEM.LOG*').Count 'No earlier transaction log is carried into the fresh snapshot.'
    }

    Invoke-Case 'backup: in-place and paired RegBack replacement in the same second preserve the first original' {
        $sam = New-Hive SAM
        $security = New-Hive SECURITY
        $global:RegFixture.FixedStamp = '20261014000000'
        Assert-True (Invoke-InPlace SAM) 'The first replacement succeeds.'
        [void](Restore-HiveFromRegBack -Plan ([PSCustomObject]@{ Hives = @($sam, $security) }) -Wanted @('SECURITY'))
        $backups = @(Get-ChildItem -LiteralPath $global:RegFixture.Config -Filter 'SAM.bak-*')
        Assert-Equal 2 $backups.Count 'The intermediate replacement receives a different backup identity.'
        Assert-True (@($backups | Where-Object { (Get-Text $_.FullName) -eq 'ORIGINAL-SAM' }).Count -eq 1) 'The first original remains available for manual recovery.'
    }

    Invoke-Case 'backup: an existing recovery copy is never overwritten' {
        $hiveFile = New-Hive SYSTEM
        $backup = "$($hiveFile.LivePath).bak-existing"
        Set-Content -LiteralPath $backup -Value 'FIRST-RECOVERY-COPY' -NoNewline
        $caught = $null
        try { Copy-HiveBackup -Path $hiveFile.LivePath -Backup $backup } catch { $caught = $_.Exception }
        Assert-True ($null -ne $caught) 'A colliding backup path stops the replacement.'
        Assert-Equal 'FIRST-RECOVERY-COPY' (Get-Text $backup) 'The pre-existing recovery copy remains intact.'
    }

    # ---- Invoke-ChkReg -------------------------------------------------------------------
    # These cases call the genuine Invoke-ChkReg (captured as Invoke-ChkRegReal above), not the
    # stub used by the rest of this file, and run with this file's own $ErrorActionPreference of
    # 'Stop' still in effect - the exact caller condition the bot's fault injection used.

    Invoke-Case 'Invoke-ChkReg: a status line on stderr during validation is not a terminating error' {
        $hive = New-Hive SYSTEM
        $chkReg = New-FakeChkReg
        $result = Invoke-ChkRegReal -ChkRegPath $chkReg -HivePath $hive.LivePath -ScratchDir $global:RegFixture.Scratch -Repair $false
        Assert-Equal 0 $result.ExitCode 'A success exit code is still reported.'
        Assert-True (-not $result.FoundProblem) 'Success status text on stderr is not read as a found problem.'
        Assert-True ($result.Output -match 'succeeded') 'The status text is captured as plain output.'
    }

    Invoke-Case 'Invoke-ChkReg: a status line on stderr during repair is not a terminating error' {
        $hive = New-Hive SYSTEM
        $chkReg = New-FakeChkReg
        $result = Invoke-ChkRegReal -ChkRegPath $chkReg -HivePath $hive.LivePath -ScratchDir $global:RegFixture.Scratch -Repair $true
        Assert-Equal 0 $result.ExitCode 'A success exit code is still reported.'
        Assert-True (-not $result.FoundProblem) 'Success status text on stderr is not read as a found problem.'
        Assert-True ([string]::IsNullOrEmpty($result.RepairedPath) -eq $false) 'The repaired scratch copy path is still returned.'
    }

    Invoke-Case 'Invoke-ChkReg: the caller error preference is restored after a stderr status line' {
        $hive = New-Hive SYSTEM
        $chkReg = New-FakeChkReg
        $before = $ErrorActionPreference
        [void](Invoke-ChkRegReal -ChkRegPath $chkReg -HivePath $hive.LivePath -ScratchDir $global:RegFixture.Scratch -Repair $false)
        Assert-Equal $before $ErrorActionPreference 'The function does not leak its internal error preference back to the caller.'
    }

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
        $lock = [System.IO.File]::Open($hive.LivePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $threw = $false
        try {
            try { [void](Invoke-InPlace SYSTEM) } catch { $threw = $true }
        }
        finally { $lock.Dispose() }
        Assert-True $threw 'A failed backup stops the replacement.'
        Assert-HiveOriginal $hive.LivePath SYSTEM 'Failed backup:'
    }

    Invoke-Case 'in place: a torn backup is caught before the hive is overwritten' {
        $hive = New-Hive SYSTEM
        Add-Fault -Command 'Get-FileHash' -Source '*.bak-*' -Mode Corrupt
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
