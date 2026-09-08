<#
.SYNOPSIS
    Helper functions for loading, using and unloading registry hives from an offline
    Windows installation attached to a rescue VM as a data disk.

.DESCRIPTION
    Provides a safe, reference-counted wrapper around 'reg load' / 'reg unload' so that
    repair scripts can read and modify an offline hive without leaking mounted keys.

    Offline hives are mounted under HKLM:\BROKEN<HIVE> (for example HKLM:\BROKENSYSTEM).

    Every mount is registered with the offline-target gate (Register-OfflineHiveKey) and
    every confirmed unload unregisters it (Unregister-OfflineHiveKey), so Assert-OfflineTarget
    in OfflineRepairCommon can prove that a write lands on the mounted offline image and not
    on the rescue VM's own registry.

    Invoke-WithHive materialises the script block's output into an inert snapshot before it
    unloads the hive, because a live registry object returned by the block keeps a handle
    open and makes 'reg unload' fail. See its help for the exact contract.

    Exposed functions:
      Invoke-WithHive                   Mount hive(s), run a script block, always unmount.
      Get-OfflineSystemRootPath         Active ControlSet path inside the mounted SYSTEM hive.
      Get-OfflineControlSetName         Active ControlSet name (e.g. ControlSet001).
      Get-OfflineReferencedControlSetName        All referenced ControlSet names (Current/Default/LKG).
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
    v1.1: Made the unload deterministic and honest. Invoke-WithHive now snapshots the
          block's output so no live registry handle blocks the unload, mounts inside the
          try so a partial mount cannot strand a hive, and only drops its bookkeeping and
          reports success once the unload is confirmed. Mount/Dismount register and
          unregister the mount key with the offline-target gate. An existing mount is
          reused only when its backing file is verified. Test-OfflineHiveFile copies hives
          into a per-run directory locked to SYSTEM and Administrators and checks its own
          unload and cleanup.
#>

if (-not (Get-Command Add-OfflineRepairLog -ErrorAction SilentlyContinue)) {
    try {
        . (Join-Path $PSScriptRoot 'OfflineRepairCommon.ps1')
    }
    catch {
        throw "Use-OfflineRegistryHive.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$PSScriptRoot': $($_.Exception.Message)"
    }
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

function Get-OfflineHiveKeyState {
    <#
    .SYNOPSIS
        Reports whether a mount key is loaded, using reg.exe so no in-process handle opens.

    .DESCRIPTION
        Returns 'Present' when the key is loaded, 'Absent' when reg.exe reports the key does
        not exist, and 'Unknown' when the state could not be read (for example access is
        denied). The distinction is the point: treating 'Unknown' as 'Absent' is exactly how
        an access-denied result was previously mistaken for a clean unload.

    .OUTPUTS
        [string] one of 'Present', 'Absent' or 'Unknown'.
    #>
    param([Parameter(Mandatory = $true)][string]$HiveKey)

    $out = reg.exe query $HiveKey /ve 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { return 'Present' }
    # reg.exe reports "The system was unable to find the specified registry key or value"
    # only when the key genuinely is not loaded. Any other failure is an undetermined state.
    if ($out -match 'unable to find|cannot find|specified registry key') { return 'Absent' }
    return 'Unknown'
}

function Test-OfflineFileInUse {
    <#
    .SYNOPSIS
        Reports whether a file is held open by another handle, without modifying it.

    .DESCRIPTION
        Opens the file for read with no sharing. A loaded hive keeps its primary file open,
        so an exclusive open fails with a sharing violation, while a file nothing has mounted
        opens cleanly. The handle is closed at once and nothing is written, so the hive on
        the offline disk is never changed by the check. Any other failure (for example access
        denied) is raised to the caller, which must treat it as 'cannot verify'.

    .OUTPUTS
        [bool] $true when the file is in use, $false when it can be opened exclusively.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        $stream.Dispose()
        return $false
    }
    catch [System.IO.IOException] {
        return $true
    }
}

function Invoke-OfflineRegUnload {
    <#
    .SYNOPSIS
        Unloads a mount key with reg.exe, retrying while handles release, then verifies.

    .DESCRIPTION
        Releases cached registry handles with a garbage collection pass, then retries
        'reg unload' while PowerShell's registry provider lets go. After the loop it
        re-queries the key with reg.exe and reports success only when the key is actually
        gone - a zero exit code is not trusted on its own, so a hive left mounted is never
        mistaken for unloaded. Callers decide how loudly to report a failure.

    .OUTPUTS
        [bool] $true when the key is confirmed unloaded, $false otherwise.
    #>
    param([Parameter(Mandatory = $true)][string]$HiveKey)

    # Release cached RegistryKey handles held by PowerShell's registry provider.
    # Do NOT call Test-Path/Get-Item on the hive path here - those open NEW handles.
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    [GC]::Collect()
    Start-Sleep -Milliseconds 500

    Add-OfflineRepairLog -Level Info -Message "Unloading offline hive: reg unload $HiveKey"
    $maxAttempts = 6
    $out = ''
    for ($i = 1; $i -le $maxAttempts; $i++) {
        $out = reg.exe unload $HiveKey 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -or $out -match 'unable to find|parameter is incorrect') { break }
        if ($i -lt $maxAttempts) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
            Start-Sleep -Milliseconds (500 + ($i * 500))
        }
    }

    # A zero exit code is necessary but not sufficient. Confirm the key is really gone before
    # reporting success, so a hive that is still mounted is never reported as unloaded.
    if ((Get-OfflineHiveKeyState -HiveKey $HiveKey) -eq 'Absent') { return $true }

    Add-OfflineRepairLog -Level Warning -Message "reg unload $HiveKey did not confirm removal (last message: $($out.Trim()))."
    return $false
}

function Mount-OfflineHive {
    <#
    .SYNOPSIS
        Loads an offline hive as HKLM\BROKEN<HIVE> and registers it with the offline gate.

    .DESCRIPTION
        A pre-existing HKLM\BROKEN<HIVE> key is reused only when it is proven to be backed by
        THIS disk's hive file: a loaded hive holds its primary file open, so the target file
        being in use is the signal that the mount is ours. If that file is free - which is
        what a stale key from a crashed run, or a concurrent run against a different disk,
        looks like - the mount is refused rather than silently retargeting every read and
        write to the wrong hive. On a successful load or a verified reuse the key is
        registered with Register-OfflineHiveKey so Assert-OfflineTarget will allow writes.
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

    $hiveKey = "HKLM\BROKEN$Hive"

    # A previous failed unload, or another run, can leave the key mounted. Reuse it only after
    # proving it is backed by our file; otherwise refuse, because reusing a foreign or stale
    # mount would point every read and write at the wrong hive.
    if ((Get-OfflineHiveKeyState -HiveKey $hiveKey) -eq 'Present') {
        try { $targetInUse = Test-OfflineFileInUse -Path $offHive }
        catch {
            throw "Refusing to reuse the existing $hiveKey mount: the state of '$offHive' could not be verified ($($_.Exception.Message)). Unload the key with 'reg unload $hiveKey' and retry."
        }

        if ($targetInUse) {
            Add-OfflineRepairLog -Level Info -Message "$hiveKey is already loaded from '$offHive' - reusing the existing mount."
            $null = Register-OfflineHiveKey -Key $hiveKey
            return
        }

        throw "Refusing to reuse the existing $hiveKey mount: it is not backed by '$offHive' (that file is not open), so it belongs to a different disk or a crashed run. Unload it first with 'reg unload $hiveKey'."
    }

    Add-OfflineRepairLog -Level Info -Message "Loading offline hive: reg load $hiveKey `"$offHive`""
    $out = reg.exe load $hiveKey "$offHive" 2>&1 | Out-String

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

    $null = Register-OfflineHiveKey -Key $hiveKey
}

function Dismount-OfflineHive {
    <#
    .SYNOPSIS
        Unloads HKLM\BROKEN<HIVE>, retrying while the registry provider releases handles.

    .DESCRIPTION
        Reports success only when the key is confirmed gone. A hive that is genuinely not
        loaded is a success; a state that cannot be read (for example access is denied) is
        NOT, so it is never mistaken for a clean unload. On a confirmed unload the mount key
        is unregistered from the offline-target gate; on failure it is left registered and
        $false is returned, because the file is still locked.

    .OUTPUTS
        [bool] $true when the hive is confirmed unloaded, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    $hiveKey = "HKLM\BROKEN$Hive"
    $Error.Clear()

    $state = Get-OfflineHiveKeyState -HiveKey $hiveKey
    if ($state -eq 'Absent') {
        Add-OfflineRepairLog -Level Info -Message "$hiveKey is not currently loaded - nothing to unload."
        $null = Unregister-OfflineHiveKey -Key $hiveKey
        return $true
    }
    if ($state -eq 'Unknown') {
        # The load state could not be read. Do not assume it is unloaded; attempt the unload
        # and let the post-unload verification inside Invoke-OfflineRegUnload decide.
        Add-OfflineRepairLog -Level Warning -Message "Could not read the load state of $hiveKey; attempting to unload it anyway."
    }

    if (Invoke-OfflineRegUnload -HiveKey $hiveKey) {
        $null = Unregister-OfflineHiveKey -Key $hiveKey
        return $true
    }

    Add-OfflineRepairLog -Level Error -Message "Failed to unload $hiveKey. The hive file may still be locked, which will block later runs against the same disk."
    return $false
}

function ConvertTo-OfflineInertRegistryKey {
    <#
    .SYNOPSIS
        Captures a live RegistryKey's data into a plain object and disposes the handle.

    .DESCRIPTION
        A returned Microsoft.Win32.RegistryKey holds an open handle that keeps the hive
        rooted. This reads its name, values and immediate subkey names into a PSCustomObject
        - so a caller can still read $key.Start or $key.Name - and then disposes the handle
        so it can no longer block the unload.
    #>
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$Key)

    $snapshot = [ordered]@{}
    try {
        $snapshot['Name'] = $Key.Name
        $snapshot['PSChildName'] = ($Key.Name -split '\\')[-1]
        foreach ($valueName in $Key.GetValueNames()) {
            $propertyName = if ([string]::IsNullOrEmpty($valueName)) { '(default)' } else { $valueName }
            if (-not $snapshot.Contains($propertyName)) {
                try { $snapshot[$propertyName] = $Key.GetValue($valueName) }
                catch { $snapshot[$propertyName] = $null }
            }
        }
        try { $snapshot['PSSubKeyNames'] = @($Key.GetSubKeyNames()) }
        catch { $snapshot['PSSubKeyNames'] = @() }
    }
    finally {
        $Key.Dispose()
    }
    return [pscustomobject]$snapshot
}

function ConvertTo-OfflineInertValue {
    <#
    .SYNOPSIS
        Returns a snapshot of a value with every live registry handle removed.

    .DESCRIPTION
        Invoke-WithHive has to unload the hive after the block runs, and a single live
        Microsoft.Win32.RegistryKey - or a PSObject still bound to the registry provider,
        which every Get-Item/Get-ItemProperty/Get-ChildItem result is through its PSDrive -
        keeps a handle open on the hive and makes 'reg unload' fail.

        This walks the block's output once and replaces ONLY those live objects with plain,
        disconnected snapshots, disposing any handle it finds. Everything else is returned by
        reference, unchanged: $null, strings, numbers and other value types, byte[] and other
        value-type arrays, hashtables and PSCustomObjects that carry no registry reference are
        never rebuilt. A subtree is rebuilt only on the path down to a registry object it
        actually contains. A registry-backed object becomes a PSCustomObject exposing the same
        value members (so a caller still reads $result.Start), but with no PSDrive/PSProvider
        link and no open handle.

        The ChangeCount reference is internal bookkeeping: it counts the live objects that
        were neutralised so each level can tell whether it must rebuild or can hand back the
        very same object it was given.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][ref]$ChangeCount,
        [int]$Depth = 0
    )

    if ($null -eq $InputObject) { return $null }
    # Real registry output is shallow; the guard only stops a pathological self-referential graph.
    if ($Depth -gt 64) { return $InputObject }

    $isPsObject = $InputObject -is [System.Management.Automation.PSObject]
    $base = if ($isPsObject) { $InputObject.BaseObject } else { $InputObject }

    if ($base -is [Microsoft.Win32.RegistryKey]) {
        $ChangeCount.Value++
        return ConvertTo-OfflineInertRegistryKey -Key $base
    }

    # Provider metadata that pins an output back to the mounted drive. Its name is inert.
    if ($base -is [System.Management.Automation.PSDriveInfo] -or $base -is [System.Management.Automation.ProviderInfo]) {
        $ChangeCount.Value++
        return [string]$base
    }

    if ($base -is [string] -or $base -is [System.ValueType]) { return $InputObject }

    if ($base -is [System.Array]) {
        $elementType = $base.GetType().GetElementType()
        if ($null -ne $elementType -and ($elementType.IsValueType -or $elementType -eq [string])) {
            # byte[], int[], string[] and the like hold no handle and keep their exact type.
            return $InputObject
        }
        $before = $ChangeCount.Value
        $items = [object[]]::new($base.Length)
        for ($index = 0; $index -lt $base.Length; $index++) {
            $items[$index] = ConvertTo-OfflineInertValue -InputObject $base[$index] -ChangeCount $ChangeCount -Depth ($Depth + 1)
        }
        if ($ChangeCount.Value -gt $before) { return $items }
        return $InputObject
    }

    if ($base -is [System.Collections.IDictionary]) {
        $before = $ChangeCount.Value
        $copy = [ordered]@{}
        foreach ($entry in @($base.GetEnumerator())) {
            $copy[$entry.Key] = ConvertTo-OfflineInertValue -InputObject $entry.Value -ChangeCount $ChangeCount -Depth ($Depth + 1)
        }
        if ($ChangeCount.Value -gt $before) { return $copy }
        return $InputObject
    }

    if ($isPsObject) {
        $before = $ChangeCount.Value
        $snapshot = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            # PSProvider and PSDrive are the live references that keep the hive rooted; drop them.
            if ($property.Name -eq 'PSProvider' -or $property.Name -eq 'PSDrive') {
                if ($null -ne $property.Value) { $ChangeCount.Value++ }
                continue
            }
            $snapshot[$property.Name] = ConvertTo-OfflineInertValue -InputObject $property.Value -ChangeCount $ChangeCount -Depth ($Depth + 1)
        }
        if ($ChangeCount.Value -gt $before) { return [pscustomobject]$snapshot }
        return $InputObject
    }

    # Any other reference type is passed through unchanged. The contract is to neutralise
    # registry handles, not to deep-clone arbitrary objects a block might return.
    return $InputObject
}

function Invoke-WithHive {
    <#
    .SYNOPSIS
        Mounts one or more offline hives, runs a script block, and always unmounts them.

    .DESCRIPTION
        Nested calls are reference counted, so an inner call can reuse an outer mount
        without unloading it from under the caller. Hives are unmounted in reverse order.

        The block's output is materialised before the hive is unloaded. PowerShell's registry
        provider keeps a key open behind every live object it returns - a
        Microsoft.Win32.RegistryKey from Get-Item/Get-ChildItem, or the PSDrive carried by a
        Get-ItemProperty result - and that open handle makes 'reg unload' fail with 'Access
        is denied', which is the exact failure this helper exists to prevent. So the output is
        passed through ConvertTo-OfflineInertValue, which replaces ONLY those live registry
        objects with disconnected snapshots (a RegistryKey becomes a PSCustomObject exposing
        the same values; a registry-backed PSObject loses its PSDrive/PSProvider link) and
        disposes the handles. Ordinary results - strings, numbers, byte[], hashtables and
        PSCustomObjects built from plain values - are returned unchanged.

        A block that returned a live key and then read from it AFTER this function returned was
        already unsafe, because the hive is unloaded by then; such a caller now receives the
        snapshot's captured values instead of a dead handle.

        The mount loop runs inside the try, so a hive that fails to load part-way through a
        multi-hive mount does not strand the ones already mounted. If a hive cannot be
        confirmed unloaded, its depth entry is kept (the mount is still real) and the call
        throws rather than reporting a success that left the file locked.

    .OUTPUTS
        The script block's output, with any live registry handle replaced by an inert
        snapshot. Shape and ordinary values are preserved.

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
    # Every hive whose depth counter this call incremented, in order, so the finally can undo
    # exactly those - and no others - even when a later mount in the loop throws.
    $acquired = [System.Collections.Generic.List[string]]::new()
    $failedUnloads = [System.Collections.Generic.List[string]]::new()
    $snapshot = $null
    $scriptError = $null

    try {
        # The mount loop lives inside the try so that a failure part-way through is cleaned up
        # by the finally: without this, a first hive stays mounted when a second fails to load.
        foreach ($h in $Hive) {
            $hiveName = $h.ToUpperInvariant()
            $depth = if ($script:OfflineHiveLoadDepth.ContainsKey($hiveName)) { [int]$script:OfflineHiveLoadDepth[$hiveName] } else { 0 }
            if ($depth -eq 0) {
                Mount-OfflineHive -WindowsPath $WindowsPath -Hive $hiveName
                [void]$mountedHere.Add($hiveName)
            }
            $script:OfflineHiveLoadDepth[$hiveName] = $depth + 1
            [void]$acquired.Add($hiveName)
        }

        $rawOutput = & $ScriptBlock
        # Sever every live registry handle before the finally tries to unload the hive.
        $changeCount = 0
        $snapshot = if ($null -eq $rawOutput) { $null } else { ConvertTo-OfflineInertValue -InputObject $rawOutput -ChangeCount ([ref]$changeCount) }
        $rawOutput = $null
    }
    catch {
        $scriptError = $_
    }
    finally {
        # Release the provider's cached handles once, now that the output holds none, then unload.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        [GC]::Collect()

        for ($i = $acquired.Count - 1; $i -ge 0; $i--) {
            $hiveName = $acquired[$i]
            $depth = if ($script:OfflineHiveLoadDepth.ContainsKey($hiveName)) { [int]$script:OfflineHiveLoadDepth[$hiveName] } else { 0 }
            if ($depth -le 1) {
                if ($mountedHere.Contains($hiveName)) {
                    $unloaded = $false
                    try { $unloaded = Dismount-OfflineHive -Hive $hiveName }
                    catch { $unloaded = $false; Add-OfflineRepairLog -Level Error -Message "Unloading BROKEN$hiveName threw: $($_.Exception.Message)" }
                    if ($unloaded) {
                        # Only now is the hive really gone, so only now does the counter drop.
                        [void]$script:OfflineHiveLoadDepth.Remove($hiveName)
                    }
                    else {
                        # Keep the counter: the hive is still mounted and its file still locked.
                        [void]$failedUnloads.Add($hiveName)
                    }
                }
                else {
                    # An outer scope owns this mount; just release our reference to it.
                    [void]$script:OfflineHiveLoadDepth.Remove($hiveName)
                }
            }
            else {
                $script:OfflineHiveLoadDepth[$hiveName] = $depth - 1
            }
        }
    }

    # Surface the block's own failure first; any unload failure below is already logged Error.
    if ($scriptError) { throw $scriptError }

    if ($failedUnloads.Count -gt 0) {
        throw "Failed to unload offline hive(s) $($failedUnloads -join ', '): the hive file(s) remain locked, so a later repair run against the same disk would fail. Unload them with 'reg unload HKLM\BROKEN<HIVE>' before retrying."
    }

    return $snapshot
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

function Get-OfflineReferencedControlSetName {
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

        The scratch copy is made inside a per-run directory that is locked to SYSTEM and
        Administrators with inheritance disabled BEFORE any hive bytes are written, because
        SAM and SECURITY carry credential material that must not be left readable under a
        default TEMP ACL. The validation unload is confirmed and the directory is deleted
        afterwards; a copy that survives cleanup is reported as an error, not ignored.

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

    $scratchDir = $null
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

        # Create the scratch directory and lock it down BEFORE copying any hive bytes into it,
        # so SAM/SECURITY credential material is never written out under an inheritable TEMP ACL.
        $scratchDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rsl-hive-{0}-{1}" -f $PID, [guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($scratchDir)
        $acl = Get-Acl -LiteralPath $scratchDir
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existingRule in @($acl.Access)) { [void]$acl.RemoveAccessRule($existingRule) }
        $inheritBoth = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $noPropagation = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
        foreach ($wellKnownSid in @([System.Security.Principal.WellKnownSidType]::LocalSystemSid, [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($wellKnownSid, $null)
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, $fullControl, $inheritBoth, $noPropagation, $allow))
        }
        Set-Acl -LiteralPath $scratchDir -AclObject $acl -ErrorAction Stop

        $scratchHive = Join-Path $scratchDir ([System.IO.Path]::GetFileName($Path))
        Copy-Item -LiteralPath $Path -Destination $scratchHive -Force -ErrorAction Stop

        # The transaction logs travel with the hive so that a dirty hive is recovered the
        # way Windows would recover it, instead of being reported as damaged.
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
            if (Test-OfflinePath "$Path$suffix") {
                Copy-Item -LiteralPath "$Path$suffix" -Destination "$scratchHive$suffix" -Force -ErrorAction SilentlyContinue
            }
        }

        $loadOutput = & reg.exe load "HKLM\$mountKey" $scratchHive 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "Windows could not load the hive: $((@($loadOutput) -join ' ').Trim())" }
        $mounted = $true

        $result.IsValid = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
    }
    finally {
        if ($mounted) {
            # Confirm the validation mount is gone; a copy left loaded keeps the scratch file locked.
            if (-not (Invoke-OfflineRegUnload -HiveKey "HKLM\$mountKey")) {
                Add-OfflineRepairLog -Level Error -Message "Could not unload the validation hive HKLM\$mountKey; a scratch copy of '$Path' may remain loaded."
            }
        }
        if ($scratchDir -and (Test-Path -LiteralPath $scratchDir)) {
            Remove-Item -LiteralPath $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $scratchDir) {
                # A surviving copy of SAM/SECURITY is a credential exposure, so it is surfaced, not swallowed.
                Add-OfflineRepairLog -Level Error -Message "Could not remove the validation scratch directory '$scratchDir'; it may hold a copy of hive '$Path' (which can include SAM/SECURITY credential material). Remove it manually."
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
