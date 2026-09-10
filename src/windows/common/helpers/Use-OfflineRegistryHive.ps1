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
    v1.2: Test-OfflineHiveFile uses the shared read-only offreg reader, avoiding registry
          mounts and scratch hive copies. An unavailable reader aborts validation rather
          than misclassifying the hive as corrupt. Writable HKLM-based helpers are unchanged.
    v1.3: Removed localised-output decisions, distinguished file sharing from other failures,
          added strict control-set selection for writers and shared lifecycle/default state.
#>

if (-not (Get-Command Get-OfflineRegistryKeyOpenResult -ErrorAction SilentlyContinue)) {
    try {
        . (Join-Path $PSScriptRoot 'OfflineRepairCommon.ps1')
    }
    catch {
        throw "Use-OfflineRegistryHive.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$PSScriptRoot': $($_.Exception.Message)"
    }
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
        Reports whether a key exists using a numeric native open result.

    .DESCRIPTION
        Returns 'Present' for ERROR_SUCCESS, 'Absent' only for ERROR_FILE_NOT_FOUND or
        ERROR_PATH_NOT_FOUND, and 'Unknown' for access denial or any indeterminate result.
        The query tests the key, not its default value or its backing file's lock state.
        The native handle is disposed before this function returns.

    .OUTPUTS
        [string] one of 'Present', 'Absent' or 'Unknown'.
    #>
    param([Parameter(Mandatory = $true)][string]$HiveKey)

    try {
        $result = Get-OfflineRegistryKeyOpenResult -Key $HiveKey
        if ($result -eq 0) { return 'Present' }
        if ($result -eq 2 -or $result -eq 3) { return 'Absent' }
        Add-OfflineRepairLog -Level Warning -Message "Could not determine whether $HiveKey exists (Win32 error $result)."
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not determine whether $HiveKey exists: $($_.Exception.Message)"
    }
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
        denied, missing file or unrelated I/O failure) is raised to the caller, which must
        treat it as 'cannot verify'. A sharing violation alone does not identify a mount.

    .OUTPUTS
        [bool] $true when the file is in use, $false when it can be opened exclusively.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        return $false
    }
    catch [System.UnauthorizedAccessException] {
        throw [System.UnauthorizedAccessException]::new("File access to '$Path' could not be verified: access was denied.", $_.Exception)
    }
    catch [System.IO.IOException] {
        # HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION).
        if ($_.Exception.HResult -in @(-2147024864, -2147024863)) { return $true }
        throw
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Invoke-OfflineRegUnload {
    <#
    .SYNOPSIS
        Unloads a mount key with reg.exe, retrying while handles release, then verifies.

    .DESCRIPTION
        Releases cached registry handles with a garbage collection pass, then retries
        'reg unload' while PowerShell's registry provider lets go. After the loop it
        checks the key with a numeric native query and reports success only when it is actually
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
    $keyState = 'Unknown'
    for ($i = 1; $i -le $maxAttempts; $i++) {
        $out = reg.exe unload $HiveKey 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $keyState = Get-OfflineHiveKeyState -HiveKey $HiveKey
        if ($keyState -eq 'Absent') { return $true }
        if ($exitCode -eq 0) { break }
        if ($i -lt $maxAttempts) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
            Start-Sleep -Milliseconds (500 + ($i * 500))
        }
    }

    Add-OfflineRepairLog -Level Warning -Message "reg unload $HiveKey did not confirm removal (exit code $exitCode; key state $keyState; last message: $($out.Trim()))."
    return $false
}

function Mount-OfflineHive {
    <#
    .SYNOPSIS
        Loads an offline hive as HKLM\BROKEN<HIVE> and registers it with the offline gate.

    .DESCRIPTION
        A pre-existing key is reused only when shared lifecycle state records a successful
        load of THIS file and the file remains in use. A file lock alone proves neither
        mount existence nor ownership. An untracked mount is not adopted, even if the
        target file is locked by some other process. Successful loads and verified reuse
        are registered with Register-OfflineHiveKey so Assert-OfflineTarget allows writes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive
    )

    $offHive = Get-OfflineHiveFilePath -WindowsPath $WindowsPath -Hive $Hive
    $hiveKey = "HKLM\BROKEN$Hive"
    $state = Get-OfflineRepairState
    $keyState = Get-OfflineHiveKeyState -HiveKey $hiveKey
    if ($keyState -eq 'Unknown') {
        throw "Cannot load $hiveKey because its existing key state could not be verified. Resolve the registry query failure before retrying."
    }
    if ($keyState -eq 'Absent') {
        $null = Unregister-OfflineHiveKey -Key $hiveKey
        [void]$state.HiveFilePaths.Remove($hiveKey)
    }

    try { $targetInUse = Test-OfflineFileInUse -Path $offHive }
    catch [System.IO.FileNotFoundException] { throw "$Hive hive not found: $offHive" }
    catch [System.IO.DirectoryNotFoundException] { throw "$Hive hive not found: $offHive" }
    catch [System.UnauthorizedAccessException] {
        throw "File access to '$offHive' could not be verified: access was denied. Check file permissions before retrying; no mount ownership was inferred."
    }
    catch {
        throw "File access to '$offHive' could not be verified: $($_.Exception.Message). No mount ownership was inferred."
    }

    if ($keyState -eq 'Present') {
        $knownFile = $state.HiveFilePaths[$hiveKey]
        if ($knownFile -and $knownFile -eq (ConvertTo-OfflineComparablePath $offHive) -and $targetInUse) {
            Add-OfflineRepairLog -Level Info -Message "$hiveKey is already loaded from '$offHive' - reusing the existing mount."
            $null = Register-OfflineHiveKey -Key $hiveKey
            return
        }

        throw "Refusing to reuse ${hiveKey}: its backing file could not be verified as '$offHive' from this process's mount records. A file lock alone does not identify a hive mount. Identify the existing key's owner before taking action."
    }

    Add-OfflineRepairLog -Level Info -Message "Loading offline hive: reg load $hiveKey `"$offHive`""
    $out = reg.exe load $hiveKey "$offHive" 2>&1 | Out-String

    if ($LASTEXITCODE -ne 0) {
        $exitCode = $LASTEXITCODE
        try { $targetInUse = Test-OfflineFileInUse -Path $offHive }
        catch {
            throw "Failed to load the offline $Hive hive (exit code $exitCode): $($out.Trim()). File access to '$offHive' could not be verified: $($_.Exception.Message). No mount ownership was inferred."
        }
        if ($targetInUse) {
            throw "Cannot load the $Hive hive: '$offHive' has a sharing or lock violation. Identify the process or mount holding the file before taking action; a lock does not prove a foreign mount. reg load exit code ${exitCode}: $($out.Trim())"
        }
        throw "Failed to load the offline $Hive hive (exit code $exitCode): $($out.Trim())"
    }

    $state.HiveFilePaths[$hiveKey] = ConvertTo-OfflineComparablePath $offHive
    try { $null = Register-OfflineHiveKey -Key $hiveKey }
    catch {
        $registrationError = $_
        try {
            if (-not (Dismount-OfflineHive -Hive $Hive)) {
                Add-OfflineRepairLog -Level Error -Message "Registration failed and cleanup of $hiveKey could not be confirmed."
            }
        }
        catch {
            Add-OfflineRepairLog -Level Error -Message "Registration failed and cleanup of $hiveKey threw: $($_.Exception.Message)"
        }
        throw $registrationError
    }
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
        $false is returned, because the mount may still exist.

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

    $sharedState = Get-OfflineRepairState
    if ([int]$sharedState.HiveLoadDepth[$Hive] -gt 0) {
        Add-OfflineRepairLog -Level Error -Message "Refusing to unload $hiveKey while an Invoke-WithHive caller still owns a reference."
        return $false
    }

    $state = Get-OfflineHiveKeyState -HiveKey $hiveKey
    if ($state -eq 'Absent') {
        Add-OfflineRepairLog -Level Info -Message "$hiveKey is not currently loaded - nothing to unload."
        $null = Unregister-OfflineHiveKey -Key $hiveKey
        [void]$sharedState.HiveFilePaths.Remove($hiveKey)
        return $true
    }
    if ($state -eq 'Unknown') {
        # The load state could not be read. Do not assume it is unloaded; attempt the unload
        # and let the post-unload verification inside Invoke-OfflineRegUnload decide.
        Add-OfflineRepairLog -Level Warning -Message "Could not read the load state of $hiveKey; attempting to unload it anyway."
    }

    if (Invoke-OfflineRegUnload -HiveKey $hiveKey) {
        $null = Unregister-OfflineHiveKey -Key $hiveKey
        [void]$sharedState.HiveFilePaths.Remove($hiveKey)
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
        Nested calls share reference counts across dot-source scopes, so an inner call
        can reuse an outer mount without unloading it from under the caller. Reusing a
        hive name for a different Windows path is refused. Hives unload in reverse order.

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
        confirmed unloaded, its mount record is kept and the call throws. Reference counts
        track active callers only and are always balanced, including on cleanup failure;
        a later call can retry cleanup of the recorded mount instead of inheriting a
        phantom active caller.

    .OUTPUTS
        The script block's output, with any live registry handle replaced by an inert
        snapshot. Shape and ordinary values are preserved.

    .EXAMPLE
        Invoke-WithHive 'SYSTEM' { Get-ItemProperty "$(Get-OfflineSystemRootPath)\Services\storvsc" }

    .EXAMPLE
        Invoke-WithHive 'SYSTEM','SOFTWARE' { ... }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SYSTEM', 'SOFTWARE', 'COMPONENTS', 'SAM', 'SECURITY', 'DEFAULT')]
        [string[]]$Hive,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)][string]$WindowsPath
    )

    $offlineHiveLifecycle = Get-OfflineRepairState
    $offlineHiveDepths = $offlineHiveLifecycle.HiveLoadDepth

    if ([string]::IsNullOrWhiteSpace($WindowsPath)) {
        $offlineDefaultWindowsDrive = Get-OfflineWindowsDrive
        if ([string]::IsNullOrWhiteSpace($offlineDefaultWindowsDrive)) {
            throw 'The offline Windows drive is unknown. Run Get-OfflineWindowsDisk first, or pass -WindowsPath.'
        }
        $WindowsPath = Join-OfflinePath -Root $offlineDefaultWindowsDrive -ChildPath 'Windows'
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
            $offlineHiveKey = "HKLM\BROKEN$hiveName"
            $offlineHiveFile = ConvertTo-OfflineComparablePath (Get-OfflineHiveFilePath -WindowsPath $WindowsPath -Hive $hiveName)
            $depth = if ($offlineHiveDepths.ContainsKey($hiveName)) { [int]$offlineHiveDepths[$hiveName] } else { 0 }
            if ($depth -eq 0) {
                Mount-OfflineHive -WindowsPath $WindowsPath -Hive $hiveName
                [void]$mountedHere.Add($hiveName)
                $offlineHiveLifecycle.HiveFilePaths[$offlineHiveKey] = $offlineHiveFile
            }
            elseif ($offlineHiveLifecycle.HiveFilePaths[$offlineHiveKey] -ne $offlineHiveFile) {
                throw "Cannot reuse $offlineHiveKey for '$offlineHiveFile': an outer caller owns '$($offlineHiveLifecycle.HiveFilePaths[$offlineHiveKey])'."
            }
            $offlineHiveDepths[$hiveName] = $depth + 1
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
            $depth = [int]$offlineHiveDepths[$hiveName]
            if ($depth -lt 1) {
                Add-OfflineRepairLog -Level Error -Message "The shared reference count for BROKEN$hiveName was lost; refusing an unowned unload."
                [void]$failedUnloads.Add($hiveName)
                continue
            }
            if ($depth -gt 1) {
                $offlineHiveDepths[$hiveName] = $depth - 1
                continue
            }

            [void]$offlineHiveDepths.Remove($hiveName)
            if ($mountedHere.Contains($hiveName)) {
                $unloaded = $false
                try { $unloaded = Dismount-OfflineHive -Hive $hiveName }
                catch { Add-OfflineRepairLog -Level Error -Message "Unloading BROKEN$hiveName threw: $($_.Exception.Message)" }
                if (-not $unloaded) { [void]$failedUnloads.Add($hiveName) }
            }
        }
    }

    # Surface the block's own failure first; any unload failure below is already logged Error.
    if ($scriptError) { throw $scriptError }

    if ($failedUnloads.Count -gt 0) {
        throw "Failed to confirm unload of offline hive(s) $($failedUnloads -join ', '). Mount records are retained for retry; inspect the logged errors before attempting manual cleanup."
    }

    return $snapshot
}

function Get-OfflineSelectedControlSetName {
    <#
    .SYNOPSIS
        Resolves one Select reference to an existing control set without provider handles.

    .DESCRIPTION
        Current is required. Default and LastKnownGood may be absent, zero or point at a
        missing optional set, which is skipped. A non-DWORD, out-of-range reference or
        indeterminate target key is not a missing optional set. Strict callers throw for
        those failures; tolerant readers log the reason and receive no selection.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Current', 'Default', 'LastKnownGood')][string]$Name,
        [switch]$Strict
    )

    try {
        $number = Get-OfflineRegistryDword -Key 'HKLM\BROKENSYSTEM\Select' -Name $Name
        if ($null -eq $number -or ($Name -ne 'Current' -and $number -eq 0)) {
            if ($Name -eq 'Current') { throw 'Select\Current is missing.' }
            return $null
        }
        if ($number -isnot [uint32] -or $number -lt 1 -or $number -gt 999) {
            throw "Select\$Name must be a DWORD in the range 1..999."
        }

        $controlSet = 'ControlSet{0:d3}' -f $number
        $keyState = Get-OfflineHiveKeyState -HiveKey "HKLM\BROKENSYSTEM\$controlSet"
        if ($keyState -eq 'Absent' -and $Name -ne 'Current') {
            Add-OfflineRepairLog -Level Warning -Message "Select\$Name references missing optional $controlSet; skipping it."
            return $null
        }
        if ($keyState -ne 'Present') {
            throw "Select\$Name references $controlSet, whose key state is $keyState."
        }
        return $controlSet
    }
    catch {
        $message = "Cannot resolve SYSTEM\Select\$Name to an existing control set: $($_.Exception.Message)"
        if ($Strict) { throw $message }
        Add-OfflineRepairLog -Level Warning -Message $message
        return $null
    }
}

function Get-OfflineSystemRootPath {
    <#
    .SYNOPSIS
        Returns the active ControlSet path inside the mounted BROKENSYSTEM hive.

    .DESCRIPTION
        Tolerant readers fall back to ControlSet001 with a warning when Current cannot
        be resolved (for example offline WinPE disks). Writers must pass -Strict: it
        requires a DWORD Current in 1..999 and a verifiably existing target control set.
        Access denial and indeterminate reads never become a successful strict selection.
    #>
    param([switch]$Strict)

    $name = Get-OfflineSelectedControlSetName -Name Current -Strict:$Strict
    if ($name) { return "HKLM:\BROKENSYSTEM\$name" }
    Add-OfflineRepairLog -Level Warning -Message 'Using ControlSet001 only as a tolerant read fallback; this path is not a verified write target.'
    return 'HKLM:\BROKENSYSTEM\ControlSet001'
}

function Get-OfflineControlSetName {
    <#
    .SYNOPSIS
        Returns the active ControlSet name, for example 'ControlSet001'.

    .DESCRIPTION
        Pass -Strict for a write target; it has the same contract as Get-OfflineSystemRootPath.
    #>
    param([switch]$Strict)

    return (Split-Path -Path (Get-OfflineSystemRootPath -Strict:$Strict) -Leaf)
}

function Get-OfflineReferencedControlSetName {
    <#
    .SYNOPSIS
        Returns every ControlSet referenced by Select (Current, Default, LastKnownGood).

    .DESCRIPTION
        Strict writers require a valid Current even when other references are usable.
        Missing optional references/sets are skipped; malformed or unreadable references
        throw in strict mode. Tolerant readers retain the ControlSet001 fallback when no
        usable references exist and that fallback key is present.
    #>
    param([switch]$Strict)

    $names = [System.Collections.Generic.List[string]]::new()

    foreach ($reference in @('Current', 'Default', 'LastKnownGood')) {
        $name = Get-OfflineSelectedControlSetName -Name $reference -Strict:$Strict
        if ($name -and -not $names.Contains($name)) {
            [void]$names.Add($name)
        }
    }

    if (-not $Strict -and $names.Count -eq 0 -and
        (Get-OfflineHiveKeyState -HiveKey 'HKLM\BROKENSYSTEM\ControlSet001') -eq 'Present') {
        Add-OfflineRepairLog -Level Warning -Message 'Using ControlSet001 only as a tolerant read fallback; no usable Select references were found.'
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
        Reports whether the Windows Offline Registry Library can open a hive file.

    .DESCRIPTION
        A size and 'regf' signature check only proves the file looks like a hive. The
        parsing test uses the shared offreg reader. Hive recovery happens in memory using
        matching logs beside the file; no HKLM key, scratch copy or source write is needed.

        IsValid means offreg can open the file, not that Windows will boot or that every
        hive structure is healthy. An unreconciled hive without usable logs may fail even
        though chkreg can recover it. Callers must retain their separate structural and
        recovery checks.

        Missing offreg.dll, type initialisation failures and a failed close throw: they are
        environment/cleanup failures, not a reason to restore or repair a customer's hive.
        This does not change Invoke-WithHive's writable HKLM-based contract.

    .OUTPUTS
        PSCustomObject with Path, Exists, Size, IsValid and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    Initialize-OfflineRegistryReader

    $result = [PSCustomObject]@{
        Path    = $Path
        Exists  = $false
        Size    = 0
        IsValid = $false
        Reason  = $null
    }

    $reader = $null
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

        $reader = [RslOffline.RegistryHiveReader]::Open($Path)
        $result.IsValid = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
    }
    finally {
        if ($reader) { $reader.Dispose() }
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

    if ([string]::IsNullOrWhiteSpace($WindowsDrive)) { $WindowsDrive = Get-OfflineWindowsDrive }
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
