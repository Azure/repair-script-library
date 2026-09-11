#########################################################################################################
#
# .SYNOPSIS
#   Enable the Windows inbox NVMe storage driver on the boot path of an offline OS disk. v1.0.0
#
# .DESCRIPTION
#   Runs on a repair VM against the source VM's OS disk attached as a data disk. Report mode is the
#   default and makes no configuration changes. Repair mode backs up, corrects, and verifies the
#   stornvme service values. Rollback mode restores a backup created by Repair mode.
#
# .PARAMETER Mode
#   Report (default), Repair, or Rollback.
#
# .PARAMETER OsDriveLetter
#   Optional drive letter selecting one offline Windows installation, for example F or F:.
#
# .PARAMETER IncludeCriticalDeviceDatabase
#   Reserved opt-in parameter. CriticalDeviceDatabase entries are not changed by this version.
#
# .PARAMETER BackupFile
#   Full path to the .reg backup created by Repair mode. Required for Rollback mode.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('Report', 'Repair', 'Rollback')][string]$Mode = 'Report',
    [Parameter(Mandatory = $false)][ValidatePattern('^[A-Za-z]:?$')][string]$OsDriveLetter = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$IncludeCriticalDeviceDatabase = 'false',
    [Parameter(Mandatory = $false)][string]$BackupFile = ''
)

. .\src\windows\common\setup\init.ps1

$status = $STATUS_ERROR
try {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1

    $discoveryParameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($OsDriveLetter)) {
        $discoveryParameters.WindowsDrive = $OsDriveLetter
    }
    $offline = Get-OfflineWindowsDisk @discoveryParameters

    if ([string]::IsNullOrWhiteSpace($OsDriveLetter) -and @($offline.Candidates).Count -gt 1) {
        $candidateDrives = @($offline.Candidates | ForEach-Object { $_.Drive }) -join ', '
        throw "Found $(@($offline.Candidates).Count) Windows installations ($candidateDrives). Refusing to guess; re-run with OsDriveLetter=<drive>."
    }

    $driverPath = Join-OfflinePath -Root $offline.WindowsPath -ChildPath 'System32\drivers\stornvme.sys'
    if (-not (Test-OfflinePath $driverPath)) {
        throw "stornvme.sys was not found at '$driverPath'. Enabling a missing boot driver could make the guest unbootable; no changes were made."
    }

    if ($IncludeCriticalDeviceDatabase -eq 'true') {
        Log-Warning 'IncludeCriticalDeviceDatabase=true was requested, but this version never writes CriticalDeviceDatabase entries. Only stornvme service values are inspected or repaired.'
    }

    $desiredValues = [ordered]@{
        Start        = [PSCustomObject]@{ Value = 0; Kind = 'DWord' }
        Type         = [PSCustomObject]@{ Value = 1; Kind = 'DWord' }
        ErrorControl = [PSCustomObject]@{ Value = 3; Kind = 'DWord' }
        Group        = [PSCustomObject]@{ Value = 'SCSI miniport'; Kind = 'String' }
        ImagePath    = [PSCustomObject]@{ Value = 'system32\drivers\stornvme.sys'; Kind = 'ExpandString' }
    }

    $result = Invoke-WithHive 'SYSTEM' {
        $root = Get-OfflineSystemRootPath -Strict
        $servicePath = "$root\Services\stornvme"
        $nativeServicePath = $servicePath -replace '^HKLM:\\', 'HKLM\'
        $serviceKeyState = Get-OfflineHiveKeyState -HiveKey $servicePath
        if ($Mode -ne 'Rollback' -and $serviceKeyState -ne 'Present') {
            throw "The offline stornvme service key '$servicePath' is not present. No changes were made."
        }

        $changes = @()
        if ($Mode -ne 'Rollback') {
            $current = Get-ItemProperty -LiteralPath $servicePath -ErrorAction Stop
            $currentKey = Get-Item -LiteralPath $servicePath -ErrorAction Stop
            foreach ($name in $desiredValues.Keys) {
                $desired = $desiredValues[$name]
                $actual = $current.$name
                $actualKind = if ($current.PSObject.Properties.Name -contains $name) { $currentKey.GetValueKind($name).ToString() } else { $null }
                if ($actual -ne $desired.Value -or $actualKind -ne $desired.Kind) {
                    $changes += [PSCustomObject]@{ Name = $name; Before = $actual; BeforeKind = $actualKind; After = $desired.Value; AfterKind = $desired.Kind }
                }
            }
        }

        if ($Mode -eq 'Report') {
            return [PSCustomObject]@{ Outcome = 'Report'; ServicePath = $servicePath; Changes = $changes; BackupFile = $null }
        }

        if ($Mode -eq 'Rollback') {
            if ([string]::IsNullOrWhiteSpace($BackupFile) -or -not [System.IO.Path]::IsPathRooted($BackupFile) -or
                -not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
                throw "Mode=Rollback requires BackupFile=<full path> to a .reg backup created by Repair mode. Not found: '$BackupFile'."
            }

            $backupText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $BackupFile).Path)
            $expectedKey = ($servicePath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\')
            $sections = @([regex]::Matches($backupText, '(?m)^\s*\[(-?[^\]]+)\]\s*$'))
            if ($sections.Count -eq 0) {
                throw "BackupFile '$BackupFile' contains no registry section."
            }
            foreach ($section in $sections) {
                $sectionKey = $section.Groups[1].Value
                if ($sectionKey.StartsWith('-', [System.StringComparison]::Ordinal)) {
                    throw "BackupFile '$BackupFile' contains a deletion section '$sectionKey'."
                }
                if (-not $sectionKey.Equals($expectedKey, [System.StringComparison]::OrdinalIgnoreCase) -and
                    -not $sectionKey.StartsWith($expectedKey + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "BackupFile '$BackupFile' contains an out-of-scope registry section '$sectionKey'."
                }
            }

            [void](Assert-OfflineTarget -Path $servicePath -Action 'import the offline stornvme rollback backup')
            $importOutput = & reg.exe import $BackupFile 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Registry rollback import failed with exit code $LASTEXITCODE`: $(($importOutput | Out-String).Trim())"
            }

            $escapedExpectedKey = [regex]::Escape($expectedKey)
            $rootSection = [regex]::Match($backupText, "(?ms)^\s*\[$escapedExpectedKey\]\s*\r?\n(?<Body>.*?)(?=^\s*\[|\z)")
            if (-not $rootSection.Success) {
                throw "BackupFile '$BackupFile' contains no exact '$expectedKey' section."
            }
            $backedUpValueNames = @([regex]::Matches($rootSection.Groups['Body'].Value, '(?m)^\s*"([^"]+)"=') |
                ForEach-Object { $_.Groups[1].Value })
            $restored = Get-ItemProperty -LiteralPath $servicePath -ErrorAction Stop
            foreach ($name in $desiredValues.Keys) {
                if ($backedUpValueNames -contains $name -or -not ($restored.PSObject.Properties.Name -contains $name)) { continue }
                [void](Assert-OfflineTarget -Path $servicePath -Action "remove the offline stornvme $name value during rollback")
                Remove-ItemProperty -LiteralPath $servicePath -Name $name -Force -ErrorAction Stop
            }

            $verificationPath = Join-Path ([System.IO.Path]::GetTempPath()) "nvme-rollback-$([guid]::NewGuid()).reg"
            try {
                $verificationOutput = & reg.exe export $nativeServicePath $verificationPath /y 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $verificationPath -PathType Leaf)) {
                    throw "The restored stornvme key could not be exported for verification: $(($verificationOutput | Out-String).Trim())"
                }
                $restoredText = [System.IO.File]::ReadAllText($verificationPath).Trim()
                if (-not $restoredText.Equals($backupText.Trim(), [System.StringComparison]::Ordinal)) {
                    throw "Rollback import completed, but the restored stornvme subtree does not exactly match '$BackupFile'."
                }
            }
            finally {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $verificationPath -Force -ErrorAction SilentlyContinue
            }

            return [PSCustomObject]@{ Outcome = 'RolledBack'; ServicePath = $servicePath; Changes = @(); BackupFile = $BackupFile }
        }

        if ($changes.Count -eq 0) {
            return [PSCustomObject]@{ Outcome = 'NoChangeNeeded'; ServicePath = $servicePath; Changes = @(); BackupFile = $null }
        }

        $evidenceRoot = Join-Path $env:PUBLIC "Desktop\nvme-repair-$(Get-Date -Format yyyyMMddHHmmss)-$([guid]::NewGuid().ToString('N'))"
        New-Item -Path $evidenceRoot -ItemType Directory -ErrorAction Stop | Out-Null
        $backupPath = Join-Path $evidenceRoot "$($offline.WindowsDrive.TrimEnd(':'))-stornvme-before.reg"
        $exportOutput = & reg.exe export $nativeServicePath $backupPath /y 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or
            (Get-Item -LiteralPath $backupPath).Length -eq 0) {
            throw "Could not verify the pre-repair registry backup '$backupPath'; no service values were changed. reg export: $(($exportOutput | Out-String).Trim())"
        }

        foreach ($change in $changes) {
            [void](Assert-OfflineTarget -Path $servicePath -Action "set the offline stornvme $($change.Name) value")
            $desired = $desiredValues[$change.Name]
            New-ItemProperty -LiteralPath $servicePath -Name $change.Name -Value $desired.Value -PropertyType $desired.Kind -Force -ErrorAction Stop | Out-Null
        }

        $verified = Get-ItemProperty -LiteralPath $servicePath -ErrorAction Stop
        $verifiedKey = Get-Item -LiteralPath $servicePath -ErrorAction Stop
        foreach ($name in $desiredValues.Keys) {
            $verifiedKind = if ($verified.PSObject.Properties.Name -contains $name) { $verifiedKey.GetValueKind($name).ToString() } else { $null }
            if ($verified.$name -ne $desiredValues[$name].Value -or $verifiedKind -ne $desiredValues[$name].Kind) {
                throw "Verification failed for $servicePath\$name. Expected '$($desiredValues[$name].Value)' ($($desiredValues[$name].Kind)), read '$($verified.$name)' ($verifiedKind). Roll back with Mode=Rollback BackupFile='$backupPath'."
            }
        }

        return [PSCustomObject]@{ Outcome = 'Repaired'; ServicePath = $servicePath; Changes = $changes; BackupFile = $backupPath }
    }

    foreach ($change in @($result.Changes)) {
        Log-Output "PLAN: $($result.ServicePath)\$($change.Name) = '$($change.After)' (was '$($change.Before)')"
    }
    switch ($result.Outcome) {
        'Report' {
            if (@($result.Changes).Count -eq 0) { Log-Output 'NoChangeNeeded: all stornvme boot-driver values already match the required state.' }
            else { Log-Output "Report only: $(@($result.Changes).Count) value(s) would change. No configuration writes were made." }
        }
        'NoChangeNeeded' { Log-Output 'NoChangeNeeded: all stornvme boot-driver values already match the required state. No backup or registry write was needed.' }
        'Repaired' { Log-Output "VERIFIED: stornvme boot-driver values were repaired and read back successfully. Rollback file: $($result.BackupFile)" }
        'RolledBack' { Log-Output "VERIFIED: rollback backup was imported successfully from $($result.BackupFile)." }
    }

    $status = $STATUS_SUCCESS
}
catch {
    Log-Error $_.Exception.Message
}
finally {
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) { Clear-OfflineDriveLetter }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) { Write-OfflineRepairLog }
}
return $status