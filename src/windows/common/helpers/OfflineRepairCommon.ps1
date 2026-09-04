<#
.SYNOPSIS
    Shared primitives for the offline repair helpers: buffered logging, drive-safe paths
    and offline binary trust checks.

.DESCRIPTION
    Buffered logging
    ----------------
    The library's Logger.ps1 functions write with Write-Output, which is the same stream
    a PowerShell function returns its value on. A helper that both logs and returns a
    value therefore returns the log lines as well, silently corrupting the result.

    This helper solves that: helper functions call Add-OfflineRepairLog, which buffers the
    message without writing anything, and the calling script calls Write-OfflineRepairLog
    at statement level to flush the buffer through the standard Log-* functions.

    Rules:
      - Inside a function that returns a value, use Add-OfflineRepairLog.
      - Call Write-OfflineRepairLog only at script level, never from a function whose
        return value is used, and always flush in the script's finally block.

    Drive-safe paths
    ----------------
    Join-Path and Test-Path throw DriveNotFoundException when a path refers to a drive
    letter that is not a live PowerShell drive. Offline repairs work with letters that
    come and go (EFI and Recovery partitions are mounted temporarily, and a partition can
    still advertise a stale access path), so Join-OfflinePath builds the string without
    resolving the drive and Test-OfflinePath answers false instead of throwing.

.NOTES
    Name:   OfflineRepairCommon.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).

.VERSION
    v1.0: Initial version.
#>

if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) {
    $script:OfflineRepairLogBuffer = [System.Collections.Generic.List[object]]::new()
}

function Add-OfflineRepairLog {
    <#
    .SYNOPSIS
        Buffers a log message without writing to the output stream.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('Info', 'Warning', 'Error', 'Output')][string]$Level = 'Info'
    )

    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) {
        $script:OfflineRepairLogBuffer = [System.Collections.Generic.List[object]]::new()
    }
    [void]$script:OfflineRepairLogBuffer.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
}

function Write-OfflineRepairLog {
    <#
    .SYNOPSIS
        Flushes the buffered helper messages through the library Log-* functions.

    .DESCRIPTION
        Call this only at script level. It writes to the output stream, so calling it
        inside a function whose return value is used would corrupt that value.
    #>
    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) { return }
    if ($script:OfflineRepairLogBuffer.Count -eq 0) { return }

    $entries = @($script:OfflineRepairLogBuffer)
    $script:OfflineRepairLogBuffer.Clear()

    foreach ($entry in $entries) {
        if ([string]::IsNullOrEmpty($entry.Message)) { continue }
        switch ($entry.Level) {
            'Warning' { Log-Warning $entry.Message }
            'Error' { Log-Error $entry.Message }
            'Output' { Log-Output $entry.Message }
            default { Log-Info $entry.Message }
        }
    }
}

function Get-OfflineRepairLog {
    <#
    .SYNOPSIS
        Returns the buffered messages without flushing them.
    #>
    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) { return @() }
    return @($script:OfflineRepairLogBuffer)
}

function Clear-OfflineRepairLog {
    <#
    .SYNOPSIS
        Discards the buffered messages.
    #>
    if (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue) {
        $script:OfflineRepairLogBuffer.Clear()
    }
}

function Join-OfflinePath {
    <#
    .SYNOPSIS
        Joins a root and a child path without requiring the drive to exist.

    .DESCRIPTION
        Join-Path resolves the drive qualifier and throws DriveNotFoundException for a
        letter that is not currently mounted. Offline repairs routinely build paths on
        letters that are being mounted, are already unmounted, or are stale entries left
        on a partition, so the join is done as plain string composition instead.

    .PARAMETER Root
        Root of the path, with or without a trailing backslash. For example 'D:' or 'D:\'.

    .PARAMETER ChildPath
        Relative path under the root, with or without a leading backslash.

    .EXAMPLE
        Join-OfflinePath -Root 'X:' -ChildPath 'Windows\System32\ntdll.dll'
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Root,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ChildPath
    )

    if ([string]::IsNullOrWhiteSpace($Root)) { return $null }
    $trimmedRoot = $Root.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($ChildPath)) { return "$trimmedRoot\" }
    return "$trimmedRoot\$($ChildPath.TrimStart('\'))"
}

function Test-OfflinePath {
    <#
    .SYNOPSIS
        Tests a path, returning false instead of throwing when the drive does not exist.

    .PARAMETER Path
        Path to test. Treated literally, so square brackets and braces are safe.

    .EXAMPLE
        if (Test-OfflinePath 'X:\Windows\System32\ntdll.dll') { 'found' }
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch { return $false }
}

function Test-OfflineFileSignature {
    <#
    .SYNOPSIS
        Reports whether a binary on the offline disk is a trustworthy Microsoft file.

    .DESCRIPTION
        Authenticode alone is not enough offline. Most Windows inbox binaries are catalog
        signed, and the catalog store of the broken installation is not available to the
        rescue VM, so Get-AuthenticodeSignature reports NotSigned for perfectly good files.
        Boot manager payloads are compressed stubs that are not parseable at all. The
        version resource is therefore used as a fallback before a file is called untrusted.

    .PARAMETER FilePath
        Full path to the file on the offline disk.

    .OUTPUTS
        PSCustomObject with Path, IsSigned, IsMicrosoft, Status and Subject.

    .EXAMPLE
        (Test-OfflineFileSignature -FilePath 'D:\Windows\System32\drivers\storvsc.sys').IsMicrosoft
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath
    )

    $result = [PSCustomObject]@{
        Path        = $FilePath
        IsSigned    = $false
        IsMicrosoft = $false
        Status      = 'FileNotFound'
        Subject     = ''
    }

    if (-not (Test-OfflinePath $FilePath)) { return $result }

    $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -eq 0) {
        $result.Status = 'ZeroByte'
        return $result
    }

    try { $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop }
    catch {
        $result.Status = 'Error'
        return $result
    }

    $result.Status = [string]$signature.Status
    $result.Subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }

    if ($signature.Status -eq 'Valid') {
        $result.IsSigned = $true
        if ($result.Subject -match 'O=Microsoft Corporation') { $result.IsMicrosoft = $true }
        return $result
    }

    $versionInfo = $item.VersionInfo
    if ($versionInfo -and $versionInfo.CompanyName -match 'Microsoft') {
        $result.IsSigned = $true
        $result.IsMicrosoft = $true
        $result.Status = 'CatalogSigned'
        $result.Subject = $versionInfo.CompanyName
    }
    elseif ($signature.Status -in @('UnknownError', 'NotSupportedFileFormat')) {
        # Not parseable by Authenticode and carrying no version resource, for example a
        # compressed boot stub. Inconclusive rather than untrusted.
        $result.Status = 'NotVerifiable'
        $result.IsSigned = $true
        $result.IsMicrosoft = $true
    }

    return $result
}

function Get-OfflineSecureBootState {
    <#
    .SYNOPSIS
        Reads the Secure Boot state the guest last booted with, from the Measured Boot log.

    .DESCRIPTION
        The obvious source, Control\SecureBoot\State\UEFISecureBootEnabled, does not work offline.
        That key is volatile: Windows recreates it from the firmware at every boot and never writes
        it to the SYSTEM hive file. Saving and reloading the hive on a running Server 2022 VM shows
        AvailableUpdates, SBAT and Servicing surviving while State disappears, so an attached disk
        never carries it. On a Generation 1 VM the key does not exist even while running.

        The firmware measures the EFI_GLOBAL_VARIABLE "SecureBoot" - a single byte, 0 or 1 - into
        PCR[7], and Windows writes the whole TCG log to Windows\Logs\MeasuredBoot at every boot.
        That is an ordinary file on the Windows partition, so it can simply be read.

        The record is UEFI_VARIABLE_DATA from the TCG PC Client Platform Firmware Profile:

            EFI_GUID VariableName;       // +0,  16 bytes
            UINT64   UnicodeNameLength;  // +16, in CHAR16 units
            UINT64   VariableDataLength; // +24, in bytes
            CHAR16   UnicodeName[];      // +32
            INT8     VariableData[];     // the state byte

        An absent or empty log is reported as unknown rather than as "off". Azure allows Secure Boot
        to be enabled with the vTPM disabled, and such a VM writes no Measured Boot log at all while
        still having Secure Boot on, so absence proves nothing.

    .OUTPUTS
        PSCustomObject with Known, Enabled, Source and MeasuredUtc.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $result = [PSCustomObject]@{ Known = $false; Enabled = $false; Source = ''; MeasuredUtc = $null }

    $logDir = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Logs\MeasuredBoot'
    if (-not (Test-OfflinePath $logDir)) {
        $result.Source = 'no Measured Boot log folder'
        return $result
    }

    $logs = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($logs.Count -eq 0) {
        $result.Source = 'the Measured Boot log folder is empty'
        return $result
    }

    # EFI_GLOBAL_VARIABLE {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}, in the little-endian order the
    # first three fields of an EFI_GUID are actually stored in.
    $guid = [byte[]]@(0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C)

    foreach ($log in ($logs | Select-Object -First 3)) {
        try { $bytes = [System.IO.File]::ReadAllBytes($log.FullName) }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not read the Measured Boot log $($log.Name): $($_.Exception.Message)"
            continue
        }

        for ($i = 0; $i -le $bytes.Length - 64; $i++) {
            if ($bytes[$i] -ne $guid[0]) { continue }

            $matched = $true
            for ($j = 1; $j -lt 16; $j++) {
                if ($bytes[$i + $j] -ne $guid[$j]) { $matched = $false; break }
            }
            if (-not $matched) { continue }

            $nameLength = [BitConverter]::ToUInt64($bytes, $i + 16)
            $dataLength = [BitConverter]::ToUInt64($bytes, $i + 24)

            # Guards against a random 16-byte run that happens to match the GUID. A real record
            # names a variable of a few characters and carries a byte or two of data.
            if ($nameLength -eq 0 -or $nameLength -gt 64) { continue }
            if ($dataLength -lt 1 -or $dataLength -gt 65536) { continue }
            if (($i + 32 + ($nameLength * 2) + $dataLength) -gt $bytes.Length) { continue }

            $nameBytes = New-Object byte[] ($nameLength * 2)
            [Array]::Copy($bytes, $i + 32, $nameBytes, 0, $nameLength * 2)
            if ([System.Text.Encoding]::Unicode.GetString($nameBytes) -ne 'SecureBoot') { continue }

            $result.Known = $true
            $result.Enabled = ($bytes[$i + 32 + ($nameLength * 2)] -eq 1)
            $result.Source = "Measured Boot log $($log.Name)"
            $result.MeasuredUtc = $log.LastWriteTimeUtc
            return $result
        }
    }

    $result.Source = 'the SecureBoot variable was not present in the most recent Measured Boot logs'
    return $result
}
