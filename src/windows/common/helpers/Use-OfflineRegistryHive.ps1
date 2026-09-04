<#
.SYNOPSIS
    Helper functions for loading, using and unloading registry hives from an offline
    Windows installation attached to a rescue VM as a data disk.

.DESCRIPTION
    Provides a safe, reference-counted wrapper around 'reg load' / 'reg unload' so that
    repair scripts can read and modify an offline hive without leaking mounted keys.

    Offline hives are mounted under HKLM:\BROKEN<HIVE> (for example HKLM:\BROKENSYSTEM).

    Exposed functions:
      Invoke-WithHive                   Mount hive(s), run a script block, always unmount.
      Get-OfflineSystemRootPath         Active ControlSet path inside the mounted SYSTEM hive.
      Get-OfflineControlSetName         Active ControlSet name (e.g. ControlSet001).
      Get-OfflineControlSetNames        All referenced ControlSet names (Current/Default/LKG).
      Backup-OfflineHiveFile            Copy a hive file before it is modified.
      Resolve-OfflineImagePath          Translate a guest ImagePath into a rescue-VM path.

    Mount/unmount primitives (Mount-OfflineHive / Dismount-OfflineHive) are exported too,
    but Invoke-WithHive should be preferred because it guarantees cleanup.

.NOTES
    Name:   Use-OfflineRegistryHive.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.

.VERSION
    v1.0: Initial version.
#>

if (-not (Get-Command Add-OfflineRepairLog -ErrorAction SilentlyContinue)) {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
}

# Drive letter of the offline Windows installation, normally set by Get-OfflineWindowsDisk.ps1.
if (-not (Get-Variable -Name OfflineWindowsDrive -Scope Script -ErrorAction SilentlyContinue)) {
    $script:OfflineWindowsDrive = $null
}

function Get-OfflineHiveFilePath {
    <#
    .SYNOPSIS
        Returns the full path of an offline hive file for a given Windows directory.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    return (Join-OfflinePath -Root $WindowsPath -ChildPath "System32\Config\$Hive")
}

function Mount-OfflineHive {
    <#
    .SYNOPSIS
        Loads an offline hive as HKLM\BROKEN<HIVE>. Reuses an existing mount if present.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    $offHive = Get-OfflineHiveFilePath -WindowsPath $WindowsPath -Hive $Hive
    if (-not (Test-OfflinePath $offHive)) {
        throw "$Hive hive not found: $offHive"
    }

    # A previous failed unload can leave the key mounted. Reuse it rather than failing.
    if (Test-Path "HKLM:\BROKEN$Hive") {
        Add-OfflineRepairLog -Level Info -Message "HKLM\BROKEN$Hive is already loaded - reusing the existing mount."
        return
    }

    Add-OfflineRepairLog -Level Info -Message "Loading offline hive: reg load HKLM\BROKEN$Hive `"$offHive`""
    $out = reg.exe load "HKLM\BROKEN$Hive" "$offHive" 2>&1 | Out-String

    if ($LASTEXITCODE -ne 0) {
        if ($out -match 'being used by another process|locked') {
            # The hive file is loaded under a different key name. Help the caller find it.
            $stdKeys = @('BCD00000000', 'HARDWARE', 'SAM', 'SECURITY', 'SOFTWARE', 'SYSTEM',
                'BROKENSYSTEM', 'BROKENSOFTWARE', 'BROKENCOMPONENTS', 'BROKENSAM',
                'BROKENSECURITY', 'BROKENDEFAULT')
            $foreign = reg.exe query HKLM 2>&1 | ForEach-Object {
                if ($_ -match '^HKEY_LOCAL_MACHINE\\(.+)$') { $Matches[1] }
            } | Where-Object { $_ -notin $stdKeys }

            $hint = if ($foreign) {
                "Non-standard HKLM keys that may hold this hive: $($foreign -join ', '). Unload them first with: reg unload HKLM\<keyname>"
            }
            else {
                'Check for a hive loaded under a different key name (reg query HKLM) and unload it first.'
            }
            throw "Cannot load the $Hive hive - the file is already in use by another process. $hint"
        }
        throw "Failed to load the offline $Hive hive: $($out.Trim())"
    }
}

function Dismount-OfflineHive {
    <#
    .SYNOPSIS
        Unloads HKLM\BROKEN<HIVE>, retrying while the registry provider releases handles.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    $hiveKey = "HKLM\BROKEN$Hive"

    # Query with reg.exe (separate process) so we do not open new .NET handles here.
    $null = reg.exe query $hiveKey /ve 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-OfflineRepairLog -Level Info -Message "$hiveKey is not currently loaded - nothing to unload."
        return $true
    }

    # Release cached RegistryKey handles held by PowerShell's registry provider.
    # Do NOT call Test-Path/Get-Item on the hive path here - those open NEW handles.
    $Error.Clear()
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    [GC]::Collect()
    Start-Sleep -Milliseconds 500

    Add-OfflineRepairLog -Level Info -Message "Unloading offline hive: reg unload $hiveKey"
    $maxAttempts = 6
    for ($i = 1; $i -le $maxAttempts; $i++) {
        $out = reg.exe unload $hiveKey 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { return $true }
        if ($out -match 'unable to find|parameter is incorrect') { return $true }

        if ($i -lt $maxAttempts) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
            Start-Sleep -Milliseconds (500 + ($i * 500))
        }
    }

    Add-OfflineRepairLog -Level Warning -Message "Failed to unload $hiveKey after $maxAttempts attempts: $($out.Trim()). The hive may still be loaded."
    return $false
}

function Invoke-WithHive {
    <#
    .SYNOPSIS
        Mounts one or more offline hives, runs a script block, and always unmounts them.

    .DESCRIPTION
        Nested calls are reference counted, so an inner call can reuse an outer mount
        without unloading it from under the caller. Hives are unmounted in reverse order.

    .EXAMPLE
        Invoke-WithHive 'SYSTEM' { Get-ItemProperty "$(Get-OfflineSystemRootPath)\Services\storvsc" }

    .EXAMPLE
        Invoke-WithHive 'SYSTEM','SOFTWARE' { ... }
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Hive,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)][string]$WindowsPath
    )

    if (-not (Get-Variable -Name OfflineHiveLoadDepth -Scope Script -ErrorAction SilentlyContinue)) {
        $script:OfflineHiveLoadDepth = @{}
    }

    if ([string]::IsNullOrWhiteSpace($WindowsPath)) {
        if ([string]::IsNullOrWhiteSpace($script:OfflineWindowsDrive)) {
            throw 'The offline Windows drive is unknown. Run Get-OfflineWindowsDisk first, or pass -WindowsPath.'
        }
        $WindowsPath = Join-OfflinePath -Root $script:OfflineWindowsDrive -ChildPath 'Windows'
    }

    $mountedHere = [System.Collections.Generic.List[string]]::new()
    foreach ($h in $Hive) {
        $hiveName = $h.ToUpperInvariant()
        $depth = if ($script:OfflineHiveLoadDepth.ContainsKey($hiveName)) { [int]$script:OfflineHiveLoadDepth[$hiveName] } else { 0 }
        if ($depth -eq 0) {
            Mount-OfflineHive -WindowsPath $WindowsPath -Hive $hiveName
            [void]$mountedHere.Add($hiveName)
        }
        $script:OfflineHiveLoadDepth[$hiveName] = $depth + 1
    }

    try {
        & $ScriptBlock
    }
    finally {
        for ($i = $Hive.Count - 1; $i -ge 0; $i--) {
            $hiveName = $Hive[$i].ToUpperInvariant()
            $depth = if ($script:OfflineHiveLoadDepth.ContainsKey($hiveName)) { [int]$script:OfflineHiveLoadDepth[$hiveName] } else { 0 }
            if ($depth -le 1) {
                $script:OfflineHiveLoadDepth.Remove($hiveName)
                if ($mountedHere.Contains($hiveName)) { $null = Dismount-OfflineHive -Hive $hiveName }
            }
            else {
                $script:OfflineHiveLoadDepth[$hiveName] = $depth - 1
            }
        }
    }
}

function Get-OfflineSystemRootPath {
    <#
    .SYNOPSIS
        Returns the active ControlSet path inside the mounted BROKENSYSTEM hive.

    .DESCRIPTION
        Falls back to ControlSet001 when the Select key is absent (e.g. offline WinPE disks).
    #>
    $current = (Get-ItemProperty 'HKLM:\BROKENSYSTEM\Select' -ErrorAction SilentlyContinue).Current
    if ($current) { return 'HKLM:\BROKENSYSTEM\ControlSet{0:d3}' -f $current }
    return 'HKLM:\BROKENSYSTEM\ControlSet001'
}

function Get-OfflineControlSetName {
    <#
    .SYNOPSIS
        Returns the active ControlSet name, for example 'ControlSet001'.
    #>
    return (Split-Path -Path (Get-OfflineSystemRootPath) -Leaf)
}

function Get-OfflineControlSetNames {
    <#
    .SYNOPSIS
        Returns every ControlSet referenced by Select (Current, Default, LastKnownGood).
    #>
    $names = [System.Collections.Generic.List[string]]::new()
    $select = Get-ItemProperty 'HKLM:\BROKENSYSTEM\Select' -ErrorAction SilentlyContinue

    foreach ($value in @($select.Current, $select.Default, $select.LastKnownGood)) {
        if ($null -eq $value) { continue }
        $name = 'ControlSet{0:d3}' -f [int]$value
        if (-not $names.Contains($name) -and (Test-Path "HKLM:\BROKENSYSTEM\$name")) {
            [void]$names.Add($name)
        }
    }

    if ($names.Count -eq 0 -and (Test-Path 'HKLM:\BROKENSYSTEM\ControlSet001')) {
        [void]$names.Add('ControlSet001')
    }

    return @($names)
}

function Backup-OfflineHiveFile {
    <#
    .SYNOPSIS
        Copies an offline hive file before it is modified, so a failed repair can be reverted.

    .DESCRIPTION
        The backup is written next to the hive with a .bak-<timestamp> suffix and the
        full path is returned. The hive must NOT be mounted when this is called.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    $source = Get-OfflineHiveFilePath -WindowsPath $WindowsPath -Hive $Hive
    if (-not (Test-OfflinePath $source)) { throw "$Hive hive not found: $source" }

    $backup = "$source.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $source -Destination $backup -Force
    Add-OfflineRepairLog -Level Info -Message "Backed up the $Hive hive to $backup"
    return $backup
}

function Test-OfflineHiveFile {
    <#
    .SYNOPSIS
        Reports whether a registry hive file is structurally loadable by Windows.

    .DESCRIPTION
        A size and 'regf' signature check only proves the file looks like a hive. The
        authoritative test is to have Windows parse it, which is done by loading a scratch
        copy with reg.exe. The copy means the file on the offline disk is never modified by
        the check, while log replay still happens exactly as it would at boot, so a dirty
        hive whose logs are present and applicable is correctly reported as healthy.

        This is a test of whether Windows will load the file as it stands, not a verdict on
        whether the data is recoverable. A hive left unreconciled with no usable logs, which
        is the normal state of a RegBack copy, is reported invalid here even though chkreg
        can recover it. Callers that have a recovery path must try it before giving up.

        It is also not a corruption check. reg.exe loads a hive with wrecked bins without
        complaining, so structural damage needs chkreg on top of this.

        RegLoadAppKey is deliberately not used. It rejects primary OS hives with
        ERROR_BADDB (1009): measured on a healthy Windows Server 2022 disk, SAM and
        COMPONENTS load through it but SYSTEM and SOFTWARE always fail, while reg.exe
        loads the same SYSTEM file without error.

    .OUTPUTS
        PSCustomObject with Path, Exists, Size, IsValid and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $result = [PSCustomObject]@{
        Path    = $Path
        Exists  = $false
        Size    = 0
        IsValid = $false
        Reason  = $null
    }

    $scratch = $null
    $mountKey = "RSLVALIDATE$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $mounted = $false
    try {
        if (-not (Test-OfflinePath $Path)) { throw 'File does not exist.' }

        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) { throw 'Path is a directory, not a hive file.' }

        $result.Exists = $true
        $result.Size = $item.Length
        if ($item.Length -eq 0) { throw 'File is 0 bytes.' }
        if ($item.Length -lt 4096) { throw "File is $($item.Length) bytes, smaller than the 4096 byte minimum hive structure." }

        $header = [byte[]]::new(4)
        $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { [void]$stream.Read($header, 0, 4) } finally { $stream.Dispose() }
        if ([System.Text.Encoding]::ASCII.GetString($header) -ne 'regf') { throw "Hive header signature 'regf' is missing." }

        $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("rsl-hive-{0}" -f [guid]::NewGuid().ToString('N'))
        Copy-Item -LiteralPath $Path -Destination $scratch -Force -ErrorAction Stop

        # The transaction logs travel with the hive so that a dirty hive is recovered the
        # way Windows would recover it, instead of being reported as damaged.
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
            if (Test-OfflinePath "$Path$suffix") {
                Copy-Item -LiteralPath "$Path$suffix" -Destination "$scratch$suffix" -Force -ErrorAction SilentlyContinue
            }
        }

        $loadOutput = & reg.exe load "HKLM\$mountKey" $scratch 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "Windows could not load the hive: $((@($loadOutput) -join ' ').Trim())" }
        $mounted = $true

        $result.IsValid = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
    }
    finally {
        if ($mounted) {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            & reg.exe unload "HKLM\$mountKey" 2>&1 | Out-Null
        }
        if ($scratch) {
            foreach ($suffix in @('', '.LOG', '.LOG1', '.LOG2')) {
                if (Test-Path -LiteralPath "$scratch$suffix") {
                    Remove-Item -LiteralPath "$scratch$suffix" -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    return $result
}

function Resolve-OfflineImagePath {
    <#
    .SYNOPSIS
        Translates a guest driver/service ImagePath into a path valid on the rescue VM.

    .EXAMPLE
        Resolve-OfflineImagePath '\SystemRoot\System32\drivers\storvsc.sys'
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ImagePath,
        [Parameter(Mandatory = $false)][string]$WindowsDrive
    )

    if ([string]::IsNullOrWhiteSpace($WindowsDrive)) { $WindowsDrive = $script:OfflineWindowsDrive }
    if ([string]::IsNullOrWhiteSpace($WindowsDrive)) {
        throw 'The offline Windows drive is unknown. Run Get-OfflineWindowsDisk first, or pass -WindowsDrive.'
    }

    $drive = $WindowsDrive.TrimEnd('\')
    $resolved = $ImagePath `
        -replace '(?i)\\SystemRoot\\', "$drive\Windows\" `
        -replace '(?i)%SystemRoot%', "$drive\Windows" `
        -replace '(?i)\\\?\?\\', '' `
        -replace '(?i)^system32\\', "$drive\Windows\System32\" `
        -replace '(?i)^"?[A-Z]:\\', "$drive\"

    if ($resolved -match '^(.+?\.(?:sys|exe|dll))') { $resolved = $Matches[1] }
    return $resolved
}
