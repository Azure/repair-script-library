# Static safety-contract tests for win-convert-gen1-to-gen2.ps1.
# Run from the repository root:
#   pwsh -NoProfile -File ./tests/test-win-convert-gen1-to-gen2.ps1

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repositoryRoot 'src/windows/win-convert-gen1-to-gen2.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

function Assert-Match {
    Param([string]$Pattern, [string]$Message)
    if ($source -notmatch $Pattern) { throw "ASSERTION FAILED: $Message" }
}

function Assert-NotMatch {
    Param([string]$Pattern, [string]$Message)
    if ($source -match $Pattern) { throw "ASSERTION FAILED: $Message" }
}

$tokens = $null
$parseErrors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "ASSERTION FAILED: script has PowerShell parse errors: $($parseErrors.Message -join '; ')"
}

Assert-Match "ValidateSet\('Report', 'Convert'\)" 'Only Report and Convert modes should be exposed.'
Assert-Match "\[string\]\`$Mode = 'Report'" 'Report must remain the non-destructive default.'
Assert-Match "ValidateSet\('true', 'false'\)\]\[string\]\`$BackupConfirmed" 'Backup consent must accept vm-repair named string parameters.'
Assert-Match "ValidateSet\('true', 'false'\)\]\[string\]\`$TrustedLaunchPrerequisitesConfirmed" 'Prerequisite consent must accept vm-repair named string parameters.'
Assert-Match 'CONVERT_TO_GEN2_TRUSTED_LAUNCH' 'Convert must require an exact acknowledgement.'
Assert-Match 'Invoke-Mbr2Gpt -Operation validate' 'MBR2GPT validation must run before conversion.'
Assert-Match 'Invoke-Mbr2Gpt -Operation convert' 'Conversion must delegate partition surgery to MBR2GPT.'
Assert-Match "'/allowFullOS'" 'The supported source-VM MBR2GPT mode must be used.'
Assert-Match 'VOLUME_ENCRYPTED' 'Encrypted OS volumes must have a stable refusal signature.'
Assert-Match 'TOO_MANY_PRIMARY_PARTITIONS' 'Ineligible layouts must have a stable refusal signature.'
Assert-Match 'GEN2_CONVERSION_APPLICABLE' 'Report success must have a stable signature.'
Assert-Match 'GEN2_CONVERSION_COMPLETED' 'Conversion success must have a stable signature.'
Assert-Match 'CONVERSION_VERIFICATION_FAILED' 'Post-conversion failures must have a stable signature.'
Assert-Match 'Test-ConvertedBootLayout' 'Conversion must verify GPT, ESP, and EFI BCD.'
Assert-Match 'assign letter=\$DriveLetter' 'EFI verification must assign its temporary drive letter with diskpart.'
Assert-Match 'remove letter=\$DriveLetter' 'EFI cleanup must remove the same temporary drive letter with diskpart.'
Assert-Match 'Wait-DriveRootReady' 'EFI verification must wait for the temporary drive root to become available.'
Assert-Match "if \(\`$disk\.PartitionStyle -eq 'GPT'\)[\s\S]+Test-ConvertedBootLayout[\s\S]+NO_CHANGE_NEEDED" 'An already-GPT disk must pass ESP and BCD verification before success.'
Assert-Match 'Write-CurrentConversionResult' 'Stored refusal results must have an explicit emission path.'
Assert-Match 'return \$status\s*$' 'The repair-library status token must be the final output.'
Assert-NotMatch 'SupportsShouldProcess|ShouldProcess|\[switch\]\$BackupConfirmed|\[switch\]\$TrustedLaunchPrerequisitesConfirmed' 'Run Command must not depend on interactive or switch parameter binding.'
Assert-NotMatch 'Restart-Computer|Stop-Computer|shutdown\.exe|az vm update|Update-AzVM' 'The guest script must not reboot the VM or mutate Azure control-plane state.'
Assert-NotMatch 'Remove-PartitionAccessPath[^\r\n]+-PartitionNumber[^\r\n]+-DriveLetter' 'EFI cleanup must not combine incompatible parameter sets.'
Assert-NotMatch 'Set-Partition[^\r\n]+-NewDriveLetter' 'Set-Partition cannot assign drive letters to EFI system partitions.'
Assert-NotMatch 'Remove-PartitionAccessPath[^\r\n]+SilentlyContinue' 'EFI cleanup failures must not be suppressed.'

function Get-FunctionSource {
    Param([Parameter(Mandatory = $true)][string]$Name)

    $functionAst = $scriptAst.Find({
        Param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true)
    if (-not $functionAst) { throw "ASSERTION FAILED: function '$Name' was not found." }
    return $functionAst.Extent.Text
}

& {
    Invoke-Expression (Get-FunctionSource -Name 'Add-EfiDriveLetter')
    Invoke-Expression (Get-FunctionSource -Name 'Remove-EfiDriveLetter')

    $script:diskpartInput = ''
    function diskpart.exe {
        process { $script:diskpartInput += "$_`n" }
        end { $global:LASTEXITCODE = 0 }
    }
    function Wait-DriveRootReady { return $true }

    Add-EfiDriveLetter -DiskNumber 3 -PartitionNumber 2 -DriveLetter Z
    if ($script:diskpartInput -notmatch 'select disk 3[\s\S]+select partition 2[\s\S]+assign letter=Z') {
        throw 'ASSERTION FAILED: EFI assignment did not target the expected disk, partition, and letter.'
    }

    $script:diskpartInput = ''
    Remove-EfiDriveLetter -DiskNumber 3 -PartitionNumber 2 -DriveLetter Z
    if ($script:diskpartInput -notmatch 'select disk 3[\s\S]+select partition 2[\s\S]+remove letter=Z') {
        throw 'ASSERTION FAILED: EFI cleanup did not target the expected disk, partition, and letter.'
    }

    function Wait-DriveRootReady { return $false }
    try {
        Remove-EfiDriveLetter -DiskNumber 3 -PartitionNumber 2 -DriveLetter Z
        throw 'ASSERTION FAILED: EFI cleanup failure did not terminate verification.'
    }
    catch {
        if ($_.Exception.Message -notmatch 'Could not remove temporary EFI drive letter') { throw }
    }
}

& {
    Invoke-Expression (Get-FunctionSource -Name 'Wait-DriveRootReady')

    $script:mockDriveRootPresent = $true
    function Test-Path { return $script:mockDriveRootPresent }
    if (-not (Wait-DriveRootReady -DriveLetter Z -State Present -TimeoutSeconds 1)) {
        throw 'ASSERTION FAILED: readiness polling did not recognize a present drive root.'
    }
    $script:mockDriveRootPresent = $false
    if (-not (Wait-DriveRootReady -DriveLetter Z -State Absent -TimeoutSeconds 1)) {
        throw 'ASSERTION FAILED: readiness polling did not recognize a removed drive root.'
    }
}

& {
    Invoke-Expression (Get-FunctionSource -Name 'Write-CurrentConversionResult')
    Invoke-Expression (Get-FunctionSource -Name 'Invoke-Mbr2Gpt')

    $script:resultEmitted = $false
    $script:result = [ordered]@{ mode = 'Report'; signature = ''; diskNumber = 0; logPath = $null; message = '' }
    $script:emittedOutput = @()
    function Log-Output { Param([string]$Message) $script:emittedOutput += $Message }

    $originalSystemRoot = $env:SystemRoot
    try {
        $env:SystemRoot = Join-Path $env:TEMP 'missing-system-root'
        try {
            $null = Invoke-Mbr2Gpt -Operation validate -DiskNumber 0 -Logs $env:TEMP
            throw 'ASSERTION FAILED: missing MBR2GPT.exe did not terminate execution.'
        }
        catch {
            if (-not $script:resultEmitted) { Write-CurrentConversionResult }
        }
    }
    finally {
        $env:SystemRoot = $originalSystemRoot
    }
    if ($script:emittedOutput.Count -ne 1 -or $script:emittedOutput[0] -notmatch 'MBR2GPT_UNAVAILABLE') {
        throw "ASSERTION FAILED: the stored MBR2GPT_UNAVAILABLE result was not emitted exactly once. Signature='$($script:result.signature)'; count=$($script:emittedOutput.Count); output='$($script:emittedOutput -join ' | ')'."
    }
}

Write-Host 'PASS: Gen1-to-Gen2 script syntax and static safety contract.'