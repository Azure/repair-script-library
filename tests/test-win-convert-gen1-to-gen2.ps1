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
[void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
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
Assert-Match 'Remove-PartitionAccessPath[^\r\n]+-AccessPath \$mountRoot' 'EFI cleanup must remove the temporary access path.'
Assert-Match 'return \$status\s*$' 'The repair-library status token must be the final output.'
Assert-NotMatch 'SupportsShouldProcess|ShouldProcess|\[switch\]\$BackupConfirmed|\[switch\]\$TrustedLaunchPrerequisitesConfirmed' 'Run Command must not depend on interactive or switch parameter binding.'
Assert-NotMatch 'Restart-Computer|Stop-Computer|shutdown\.exe|az vm update|Update-AzVM' 'The guest script must not reboot the VM or mutate Azure control-plane state.'
Assert-NotMatch 'Remove-PartitionAccessPath[^\r\n]+-PartitionNumber[^\r\n]+-DriveLetter' 'EFI cleanup must not combine incompatible parameter sets.'

Write-Host 'PASS: Gen1-to-Gen2 script syntax and static safety contract.'