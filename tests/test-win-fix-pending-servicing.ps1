# Standalone fixture tests for win-fix-pending-servicing.ps1.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-fix-pending-servicing.ps1
#
# Covers the revert manifest, which lives on the customer's disk and is therefore untrusted input,
# and the two exit paths a repair must not report as success.

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-fix-pending-servicing.ps1'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rsl-pending-servicing-$([guid]::NewGuid())"
$originalPublic = $env:PUBLIC
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
$scriptText = $ast.Extent.Text

# The manifest functions are loaded on their own, so they are tested exactly as shipped.
$manifestFunction = @(
    'Get-RevertManifestPath', 'Read-RevertManifest', 'Test-RevertPathReparsePoint', 'Get-PathBelowRoot',
    'Get-TxRBackupBase', 'Resolve-PendingXmlBackupPath', 'Resolve-TxRBackupFolder',
    'ConvertTo-ValidatedRevertManifest', 'Get-EmptyRevertManifest', 'Test-RevertManifestHasUndo', 'Save-RevertManifest'
)
$definitions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in $manifestFunction) {
    $definition = @($definitions | Where-Object { $_.Name -eq $name })
    Assert-Equal 1 $definition.Count "Exactly one definition of $name is expected."
    . ([scriptblock]::Create($definition[0].Extent.Text))
}

$scriptName = 'win-fix-pending-servicing'
$scriptStartTime = '20260101120000'
$script:WindowsUpdateService = @('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'UpdateOrchestrator')
$script:LoggedMessage = [System.Collections.Generic.List[string]]::new()
function Assert-OfflineTarget { Param([string]$Path, [string]$Action) return $Path }
function Add-OfflineRepairLog { Param([string]$Level, [string]$Message) $script:LoggedMessage.Add($Message) }

function New-ValidManifest {
    return [PSCustomObject]@{
        Script              = $scriptName
        Timestamp           = $scriptStartTime
        Services            = @([PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = 3 })
        PendingXmlRenamedTo = 'pending.xml.bak-20260101120000'
        TxRBackupFolder     = '20260101120000\TxR-20260101120000'
        TxRBackupRecord     = @([PSCustomObject]@{ Name = '{guid}.TM.blf' })
        HiveBackups         = @([PSCustomObject]@{ Hive = 'SOFTWARE'; Path = 'SOFTWARE.bak-20260101120000' })
        RegistryNotReverted = $false
    }
}

function Copy-Manifest {
    Param($Manifest, [hashtable]$Override = @{})
    $copy = $Manifest | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    foreach ($key in $Override.Keys) { $copy.$key = $Override[$key] }
    return $copy
}

# A path on the current drive, rewritten as if the disk had been attached under another letter.
function ConvertTo-OtherDrive {
    Param([string]$Path)
    $other = if ([System.IO.Path]::GetPathRoot($Path) -like 'Z*') { 'Y:' } else { 'Z:' }
    return $other + (Get-PathBelowRoot $Path)
}

try {
    $windowsPath = Join-Path $fixtureRoot 'Windows'
    New-Item -Path (Join-Path $windowsPath 'WinSxS'), (Join-Path $windowsPath 'System32\config\TxR'), (Join-Path $windowsPath "Temp\$scriptName") -ItemType Directory -Force | Out-Null
    $manifestPath = Get-RevertManifestPath -Drive $fixtureRoot

    # --- Read-RevertManifest fails closed --------------------------------------------------------
    Assert-True ($null -eq (Read-RevertManifest -Path $manifestPath)) 'An absent manifest must read as $null.'

    foreach ($case in @(
            @{ Content = ''; Pattern = 'is empty' },
            @{ Content = '   '; Pattern = 'is empty' },
            @{ Content = '{ "Script": '; Pattern = 'not valid JSON' },
            @{ Content = '[1, 2]'; Pattern = 'does not hold a JSON object' },
            @{ Content = '"text"'; Pattern = 'does not hold a JSON object' })) {
        [System.IO.File]::WriteAllText($manifestPath, $case.Content)
        Assert-Throws { Read-RevertManifest -Path $manifestPath } $case.Pattern "A manifest of '$($case.Content)' must be refused."
        Assert-Equal $case.Content ([System.IO.File]::ReadAllText($manifestPath)) 'A refused manifest must be left untouched.'
    }
    Remove-Item -LiteralPath $manifestPath -Force

    $directoryManifest = Join-Path $fixtureRoot 'as-directory-revert.json'
    New-Item -Path $directoryManifest -ItemType Directory | Out-Null
    Assert-Throws { Read-RevertManifest -Path $directoryManifest } 'not a regular file' 'A directory in place of the manifest must be refused.'

    # --- ConvertTo-ValidatedRevertManifest accepts this script's own manifest ---------------------
    $valid = ConvertTo-ValidatedRevertManifest -Manifest (Copy-Manifest (New-ValidManifest)) -WindowsPath $windowsPath
    Assert-Equal 'pending.xml.bak-20260101120000' $valid.PendingXmlRenamedTo 'The pending.xml backup must be kept as a leaf.'
    Assert-Equal '20260101120000\TxR-20260101120000' $valid.TxRBackupFolder 'The TxR folder must be kept relative to its base.'
    Assert-Equal 3 $valid.Services[0].OriginalStart 'A valid start type must be kept.'
    Assert-Equal 'SOFTWARE.bak-20260101120000' $valid.HiveBackups[0].Path 'A hive backup must be kept as a leaf.'
    Assert-True (Test-RevertManifestHasUndo -Manifest $valid) 'A manifest with backups has something to undo.'
    Assert-True (-not (Test-RevertManifestHasUndo -Manifest (Get-EmptyRevertManifest))) 'An empty manifest has nothing to undo.'

    # Rooted paths written while the disk was attached under another letter still resolve here.
    $rooted = Copy-Manifest (New-ValidManifest) @{
        PendingXmlRenamedTo = ConvertTo-OtherDrive (Join-Path $windowsPath 'WinSxS\pending.xml.bak-20260101120000')
        TxRBackupFolder     = ConvertTo-OtherDrive (Join-Path $windowsPath "Temp\$scriptName\20260101120000\TxR-20260101120000")
        HiveBackups         = @([PSCustomObject]@{ Hive = 'SYSTEM'; Path = ConvertTo-OtherDrive (Join-Path $windowsPath 'System32\config\SYSTEM.bak-20260101120000') })
    }
    $portable = ConvertTo-ValidatedRevertManifest -Manifest $rooted -WindowsPath $windowsPath
    Assert-Equal 'pending.xml.bak-20260101120000' $portable.PendingXmlRenamedTo 'A rooted pending.xml backup on another drive letter must normalise to its leaf.'
    Assert-Equal '20260101120000\TxR-20260101120000' $portable.TxRBackupFolder 'A rooted TxR folder on another drive letter must normalise to a relative path.'
    Assert-Equal 'SYSTEM.bak-20260101120000' $portable.HiveBackups[0].Path 'A rooted hive backup on another drive letter must normalise to its leaf.'

    # --- ...and refuses anything that is not ------------------------------------------------------
    $windowsBelowRoot = Get-PathBelowRoot $windowsPath
    $rejected = @(
        @{ Name = 'another script'; Override = @{ Script = 'win-something-else' }; Pattern = 'not win-fix-pending-servicing' },
        @{ Name = 'a missing script'; Override = @{ Script = $null }; Pattern = 'not win-fix-pending-servicing' },
        @{ Name = 'pending.xml traversal'; Override = @{ PendingXmlRenamedTo = '..\..\System32\config\SAM' }; Pattern = 'not a pending.xml backup' },
        @{ Name = 'a pending.xml backup with the wrong name'; Override = @{ PendingXmlRenamedTo = 'pending.xml' }; Pattern = 'not a pending.xml backup' },
        @{ Name = 'a pending.xml backup outside WinSxS'; Override = @{ PendingXmlRenamedTo = 'C:\Users\pending.xml.bak-20260101120000' }; Pattern = 'is not in' },
        @{ Name = 'a non-string pending.xml backup'; Override = @{ PendingXmlRenamedTo = 5 }; Pattern = 'not a string' },
        @{ Name = 'TxR traversal'; Override = @{ TxRBackupFolder = '..\..\System32\config' }; Pattern = 'is not under' },
        @{ Name = 'the TxR base itself'; Override = @{ TxRBackupFolder = '.' }; Pattern = 'is not under' },
        @{ Name = 'a rooted TxR folder elsewhere'; Override = @{ TxRBackupFolder = "C:$windowsBelowRoot\System32\config" }; Pattern = 'is not under' },
        @{ Name = 'a TxR alternate data stream'; Override = @{ TxRBackupFolder = '20260101120000:stream' }; Pattern = 'not a usable path|alternate data stream' },
        @{ Name = 'a TxR record path'; Override = @{ TxRBackupRecord = @([PSCustomObject]@{ Name = '..\SAM' }) }; Pattern = 'not a plain file name' },
        @{ Name = 'an unnamed TxR record'; Override = @{ TxRBackupRecord = @([PSCustomObject]@{ Size = 1 }) }; Pattern = 'not a plain file name' },
        @{ Name = 'an unmanaged service'; Override = @{ Services = @([PSCustomObject]@{ Service = 'TermService'; OriginalStart = 4 }) }; Pattern = 'not a Windows Update service' },
        @{ Name = 'a start type of 5'; Override = @{ Services = @([PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = 5 }) }; Pattern = 'not a service start type' },
        @{ Name = 'a negative start type'; Override = @{ Services = @([PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = -1 }) }; Pattern = 'not a service start type' },
        @{ Name = 'a string start type'; Override = @{ Services = @([PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = '3' }) }; Pattern = 'not a service start type' },
        @{ Name = 'a duplicated service'; Override = @{ Services = @([PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = 3 }, [PSCustomObject]@{ Service = 'wuauserv'; OriginalStart = 2 }) }; Pattern = 'more than once' },
        @{ Name = 'an unmanaged hive'; Override = @{ HiveBackups = @([PSCustomObject]@{ Hive = 'SAM'; Path = 'SAM.bak-20260101120000' }) }; Pattern = 'does not back up' },
        @{ Name = 'a hive backup outside config'; Override = @{ HiveBackups = @([PSCustomObject]@{ Hive = 'SOFTWARE'; Path = 'C:\Temp\SOFTWARE.bak-20260101120000' }) }; Pattern = 'not a backup this script creates' },
        @{ Name = 'a relative hive backup path'; Override = @{ HiveBackups = @([PSCustomObject]@{ Hive = 'SOFTWARE'; Path = '..\SOFTWARE.bak-20260101120000' }) }; Pattern = 'not a backup this script creates' },
        @{ Name = 'a hive backup of another hive'; Override = @{ HiveBackups = @([PSCustomObject]@{ Hive = 'SOFTWARE'; Path = 'SYSTEM.bak-20260101120000' }) }; Pattern = 'not a backup this script creates' },
        @{ Name = 'a non-boolean RegistryNotReverted'; Override = @{ RegistryNotReverted = 'yes' }; Pattern = 'not a boolean' }
    )
    foreach ($case in $rejected) {
        $candidate = Copy-Manifest (New-ValidManifest) $case.Override
        Assert-Throws { ConvertTo-ValidatedRevertManifest -Manifest $candidate -WindowsPath $windowsPath } "$($case.Pattern)" "A manifest with $($case.Name) must be refused."
    }

    # A junction planted on the disk must not redirect the TxR restore.
    $junction = Join-Path $windowsPath "Temp\$scriptName\planted"
    $junctionTarget = Join-Path $fixtureRoot 'elsewhere'
    New-Item -Path $junctionTarget -ItemType Directory | Out-Null
    $null = cmd.exe /c mklink /J "$junction" "$junctionTarget"
    if (Test-Path -LiteralPath $junction) {
        $planted = Copy-Manifest (New-ValidManifest) @{ TxRBackupFolder = 'planted\TxR-20260101120000' }
        Assert-Throws { ConvertTo-ValidatedRevertManifest -Manifest $planted -WindowsPath $windowsPath } 'reparse point' 'A TxR folder reached through a junction must be refused.'
        [System.IO.Directory]::Delete($junction)
    }
    else {
        Write-Warning 'mklink /J is unavailable here, so the reparse-point case was skipped.'
    }

    # --- Save-RevertManifest round-trips and leaves no staging files ------------------------------
    Save-RevertManifest -Path $manifestPath -Manifest $valid
    $saved = Read-RevertManifest -Path $manifestPath
    $reloaded = ConvertTo-ValidatedRevertManifest -Manifest $saved -WindowsPath $windowsPath
    Assert-Equal $valid.TxRBackupFolder $reloaded.TxRBackupFolder 'A saved manifest must read back with the same TxR folder.'
    Assert-Equal 'wuauserv' $reloaded.Services[0].Service 'A saved manifest must read back with the same services.'
    $valid.RegistryNotReverted = $true
    Save-RevertManifest -Path $manifestPath -Manifest $valid
    Assert-True ((Read-RevertManifest -Path $manifestPath).RegistryNotReverted -eq $true) 'Saving over an existing manifest must replace it.'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $fixtureRoot -Filter '*.tmp' -Force).Count 'Saving must not leave a staging file behind.'

    $blocked = Join-Path $fixtureRoot 'missing-folder\win-fix-pending-servicing-revert.json'
    Assert-Throws { Save-RevertManifest -Path $blocked -Manifest $valid } 'could not be saved' 'A manifest that cannot be written must throw.'

    # --- Exit paths, checked in the shipped script ------------------------------------------------
    $ifStatements = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.IfStatementAst] }, $true)
    $remainingError = @($ifStatements | Where-Object {
            $_.Clauses[0].Item1.Extent.Text -eq '$remaining.Count -gt 0 -or $disableFailed.Count -gt 0' -and
            $_.Clauses[0].Item2.Extent.Text -match '\$status = \$STATUS_ERROR'
        })
    Assert-Equal 1 $remainingError.Count 'Remaining servicing markers or a service that could not be disabled must end in an error.'
    $lastSuccess = @($ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Extent.Text -eq '$status = $STATUS_SUCCESS'
            }, $true))[-1]
    Assert-True ($remainingError[0].Extent.StartOffset -lt $lastSuccess.Extent.StartOffset) 'The remaining-marker error must come before the final success.'

    # The status must be the last line the script writes, so it is returned after the finally block
    # has flushed its own log lines, never from inside the try.
    $tryStatement = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] })
    Assert-Equal 1 $tryStatement.Count 'Exactly one top-level try is expected.'
    Assert-Equal 'return $status' $ast.EndBlock.Statements[-1].Extent.Text 'The script must end by returning the status.'
    $returnsInTry = @($tryStatement[0].Body.FindAll({
                $args[0] -is [System.Management.Automation.Language.ReturnStatementAst] -and
                $args[0].Extent.Text -match '\$STATUS_'
            }, $true))
    Assert-Equal 0 $returnsInTry.Count 'No status may be returned from inside the try; set $status and break Main instead.'

    # Windows Update: only real services, and the disable goes through the protected writer.
    Assert-True ($scriptText -notmatch "'UpdateOrchestrator'") 'UpdateOrchestrator is a scheduled-task folder, not a service.'
    Assert-True ($scriptText -match "Invoke-OfflineProtectedRegistryWrite -Path \`$path -Description `"\`$\(\`$entry\.Service\) Start`"") 'Disabling a service must use the protected registry writer.'
    Assert-True ($scriptText -match '\[void\]\$disableFailed\.Add') 'A service that could not be disabled must be recorded as a failure.'

    $revertBlock = @($ifStatements | Where-Object { $_.Clauses[0].Item1.Extent.Text -eq '$isRevert' })
    Assert-Equal 1 $revertBlock.Count 'Exactly one revert block is expected.'
    $revertText = $revertBlock[0].Clauses[0].Item2.Extent.Text
    Assert-True ($revertText -match '\$manifest\.RegistryNotReverted = \$true') 'Revert must record that the registry was not reverted.'
    Assert-True ($revertText -notmatch 'Remove-Item') 'Revert must keep the manifest, which lists the hive backups.'

    # --- detectOnly=true with revert=true is refused before any disk is touched -------------------
    $helperRoot = Join-Path $fixtureRoot 'repo/src/windows/common/helpers'
    $setupRoot = Join-Path $fixtureRoot 'repo/src/windows/common/setup'
    New-Item -Path $helperRoot, $setupRoot, (Join-Path $fixtureRoot 'Desktop') -ItemType Directory -Force | Out-Null
    $fixtureScript = Join-Path $fixtureRoot 'repo/src/windows/win-fix-pending-servicing.ps1'
    Copy-Item -LiteralPath $sourceScript -Destination $fixtureScript
    @'
$STATUS_SUCCESS = 0
$STATUS_ERROR = 1
function Log-Output { Param([string]$Message) Write-Output $Message }
function Log-Info { Param([string]$Message) Write-Output $Message }
function Log-Warning { Param([string]$Message) Write-Output "WARNING: $Message" }
function Log-Error { Param([string]$Message) Write-Output "ERROR: $Message" }
'@ | Set-Content -LiteralPath (Join-Path $setupRoot 'init.ps1') -Encoding UTF8
    @'
function Get-OfflineWindowsDisk { $global:PendingServicingFixture.DiskDiscovered = $true; throw 'Fixture: disk discovery must not run.' }
function Clear-OfflineDriveLetter { }
'@ | Set-Content -LiteralPath (Join-Path $helperRoot 'Get-OfflineWindowsDisk.ps1') -Encoding UTF8
    foreach ($helper in 'OfflineRepairCommon.ps1', 'Use-OfflineRegistryHive.ps1', 'Use-OfflineFileRemoval.ps1', 'Use-OfflineProtectedResource.ps1') {
        '' | Set-Content -LiteralPath (Join-Path $helperRoot $helper) -Encoding UTF8
    }

    $env:PUBLIC = $fixtureRoot
    $global:PendingServicingFixture = @{ DiskDiscovered = $false }
    Push-Location (Join-Path $fixtureRoot 'repo')
    try { $output = @(& $fixtureScript -detectOnly true -revert true) }
    finally { Pop-Location }
    Assert-Equal 1 $output[-1] 'detectOnly=true with revert=true must return an error.'
    Assert-True (($output -join "`n") -match 'cannot be combined') 'detectOnly=true with revert=true must say why it was refused.'
    Assert-True (-not $global:PendingServicingFixture.DiskDiscovered) 'detectOnly=true with revert=true must stop before disk discovery.'

    Write-Output "PASS: $script:Passed assertions in test-win-fix-pending-servicing.ps1"
}
finally {
    $env:PUBLIC = $originalPublic
    Remove-Variable -Name PendingServicingFixture -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
