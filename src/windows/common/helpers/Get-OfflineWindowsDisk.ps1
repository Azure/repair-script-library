<#
.SYNOPSIS
    Helper functions that locate and prepare the offline Windows installation on a
    broken OS disk attached to a rescue VM.

.DESCRIPTION
    'az vm repair create' attaches the broken OS disk to a rescue VM as a data disk.
    Before any offline repair can run, the disk must be brought online, every partition
    that matters must be reachable through a drive letter, and the correct Windows
    installation must be selected when the disk carries more than one.

    This helper does all of that. Unlike Get-Disk-Partitions.ps1 it also assigns
    temporary drive letters to partitions that have none (EFI System and Recovery
    partitions), which offline boot repairs need.

    Exposed functions:
      Get-OfflineWindowsDisk        Main entry point. Returns the resolved offline install.
      Set-OfflineDisksOnline        Bring attached virtual data disks online and writable.
      Add-PartitionDriveLetter      Assign a free drive letter to a partition via diskpart.
      Get-FreeDriveLetter           Return the next unused drive letter.
      Remove-OfflineDriveLetter     Release one drive letter this run assigned.
      Clear-OfflineDriveLetter      Release every drive letter this run assigned (finally).
      Stop-NestedRepairVm           Stop a nested Hyper-V repair VM holding the disk.

    Get-OfflineWindowsDisk publishes the selected Windows drive through the shared repair
    state, which the offline registry hive helper uses as its default Windows path.

.NOTES
    Name:   Get-OfflineWindowsDisk.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.
    The rescue VM's own system disk is always excluded from the search.
    Once a volume is chosen, Set-OfflineRepairRoot binds it, so every other helper's
    Assert-OfflineTarget gate can prove it is acting on the broken disk and not the rescue VM.

.VERSION
    v1.0: Initial version.
    v1.1: Fail closed when the rescue VM system disk cannot be resolved. Select attached
          disks by BusType (so NVMe disks are seen) rather than by model name, and exclude
          any boot/system disk and the 'Temporary Storage' resource disk. Validate the drive
          letter passed to diskpart against command injection. Check the diskpart exit code
          before reporting an online as successful. Poll for an assigned letter instead of a
          fixed sleep, and track assigned letters so Remove-OfflineDriveLetter and
          Clear-OfflineDriveLetter can release them. Add DiskNumber to the sort keys for a
          deterministic selection, and bind the chosen volume as the offline repair root.
    v1.2: Declare SupportsShouldProcess on the state-changing helpers (Set-OfflineDisksOnline,
          Stop-NestedRepairVm, Remove-OfflineDriveLetter) and guard each mutation with
          $PSCmdlet.ShouldProcess, so they honour -WhatIf. ConfirmImpact is left at the default
          (Medium), below the default $ConfirmPreference (High), so non-interactive SYSTEM runs
          are unchanged and never block on a prompt. Return the assigned-letter tracking list
          with a unary comma so it is not unrolled to $null (empty) or a detached copy, which
          otherwise made Register/Remove/Clear act on a throwaway rather than the shared list.
    v1.3: Make Clear-OfflineDriveLetter safe to call from a finally block. It now releases each
          letter in its own try/catch by delegating to Remove-OfflineDriveLetter (the single
          guarded release path), so one letter that cannot be released no longer abandons the
          rest, successfully-released letters are untracked individually instead of a blanket
          Clear() that would also drop the failures, the letters still stuck are named in a
          single Warning, and the function never throws. It declares SupportsShouldProcess so
          -WhatIf flows into the delegated calls and its behaviour matches Remove-OfflineDriveLetter.
    v1.4: Verify disk state after diskpart, skip writes to already-ready disks, and recognise
          the resource disk by its language-independent warning file as well as its label.
          Probe hive metadata in memory through offreg, without registry mounts.
    v1.5: Refuse discovery while a helper-managed guest owns its disks. Limit automatic
          shutdown to ProblemVM or an explicit Id, and serialize guest/disk hand-offs.
#>

if (-not (Get-Command Open-OfflineRegistryReader -ErrorAction SilentlyContinue) -or
    -not (Get-Command Set-OfflineWindowsDrive -ErrorAction SilentlyContinue) -or
    -not (Get-Command Enter-OfflineNestedVmLifecycle -ErrorAction SilentlyContinue) -or
    -not (Get-Command Test-OfflineNestedVmManaged -ErrorAction SilentlyContinue)) {
    try {
        . (Join-Path $PSScriptRoot 'OfflineRepairCommon.ps1')
    }
    catch {
        throw "Get-OfflineWindowsDisk.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$PSScriptRoot': $($_.Exception.Message)"
    }
}

# QueryDosDevice reads the NT object namespace, which is the only place a drive letter
# that diskpart assigned to a hidden EFI System or Recovery partition can be observed.
# mountvol and Get-Partition both report the mount manager database instead, and neither
# lists those letters, so without this the helper cannot tell that a partition already
# has one and hands out a new letter on every run until the alphabet is exhausted.
if (-not ('RslOffline.NativeDosDevice' -as [type])) {
    try {
        Add-Type -Namespace RslOffline -Name NativeDosDevice -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint QueryDosDeviceW(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -ErrorAction Stop
    }
    catch {
        # Falls back to the mountvol lookup, which is weaker but needs no compiler.
        Add-OfflineRepairLog -Level Info -Message "QueryDosDevice is unavailable, so drive letter reuse falls back to mountvol: $($_.Exception.Message)"
    }
}

function Get-DosDeviceTarget {
    <#
    .SYNOPSIS
        Returns the device a DOS device name points at, or an empty string.

    .PARAMETER Name
        A DOS device name without the \\?\ prefix, such as 'K:' or 'Volume{guid}'.

    .OUTPUTS
        A device name such as \Device\HarddiskVolume5, or '' when the name is undefined.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not ('RslOffline.NativeDosDevice' -as [type])) { return '' }

    $buffer = New-Object System.Text.StringBuilder 1024
    $length = [RslOffline.NativeDosDevice]::QueryDosDeviceW($Name, $buffer, $buffer.Capacity)
    if ($length -eq 0) { return '' }

    return $buffer.ToString()
}

function Test-DriveLetterInUse {
    <#
    .SYNOPSIS
        Returns $true when a drive letter is already taken.

    .DESCRIPTION
        Get-Volume and Get-Partition do not report drive letters that were assigned to
        hidden System or Recovery partitions, so the object namespace is consulted and
        the root path is probed directly as well. A letter that is defined but not
        reachable still counts as taken, because assigning over it would fail.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DriveLetter
    )

    $letter = $DriveLetter.TrimEnd(':', '\')
    if (-not [string]::IsNullOrWhiteSpace((Get-DosDeviceTarget -Name "${letter}:"))) { return $true }
    if (Test-OfflinePath "${letter}:\") { return $true }
    if (Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction SilentlyContinue) { return $true }
    if (Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Get-FreeDriveLetter {
    <#
    .SYNOPSIS
        Returns the next unused drive letter, searching from Z: downwards.
    #>
    param(
        [Parameter(Mandatory = $false)][string[]]$Exclude = @()
    )

    $excluded = @($Exclude | ForEach-Object { $_.TrimEnd(':', '\').ToUpperInvariant() })

    # Z down to E. A-D are reserved for the rescue VM's own system and temporary disks.
    foreach ($letter in ([char[]](90..69))) {
        if ($excluded -contains "$letter") { continue }
        if (-not (Test-DriveLetterInUse -DriveLetter "$letter")) { return "$letter" }
    }

    throw 'No free drive letter is available on the rescue VM. Remove unused mount points with "mountvol <letter>: /d" and run the script again.'
}

function Get-VolumeDriveLetterMap {
    <#
    .SYNOPSIS
        Maps each volume GUID path to the drive letters currently mounted on it.

    .DESCRIPTION
        Fallback used only when QueryDosDevice is unavailable. mountvol reports the
        mount manager database, which does not contain letters that diskpart created
        directly in the object namespace, so this is the weaker of the two sources.

    .OUTPUTS
        Hashtable keyed by volume GUID path (no trailing backslash) whose values are
        drive letter arrays in the form 'K:'.
    #>
    $map = @{}
    $currentVolume = $null

    foreach ($line in @(mountvol.exe 2>$null)) {
        $text = "$line".Trim()

        if ($text -match '^\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\?$') {
            $currentVolume = $text.TrimEnd('\')
            if (-not $map.ContainsKey($currentVolume)) { $map[$currentVolume] = @() }
            continue
        }

        if (-not $currentVolume) { continue }
        if ($text -match '^([A-Za-z]):\\?$') { $map[$currentVolume] += "$($Matches[1].ToUpperInvariant()):" }
    }

    return $map
}

function Get-DriveLetterDeviceMap {
    <#
    .SYNOPSIS
        Maps every defined drive letter to the device it points at.

    .OUTPUTS
        Hashtable keyed by drive letter in the form 'K:' whose values are device
        names such as \Device\HarddiskVolume5.
    #>
    $map = @{}

    foreach ($letter in ([char[]](67..90))) {
        $target = Get-DosDeviceTarget -Name "${letter}:"
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        $map["${letter}:"] = $target
    }

    return $map
}

function Get-PartitionExistingRoot {
    <#
    .SYNOPSIS
        Returns the drive letters already usable for a partition, or an empty array.

    .DESCRIPTION
        Reported access paths are confirmed before they are trusted, because a
        partition can advertise a letter whose drive is no longer mounted.

        Hidden EFI System and Recovery partitions never report a drive letter at all,
        so the partition's volume device is resolved instead and matched against the
        device every defined drive letter points at. That recovers a letter assigned
        by an earlier run, which is what stops each run from leaking two more letters
        until the alphabet is exhausted.
    #>
    param(
        [Parameter(Mandatory = $true)]$Partition,
        [Parameter(Mandatory = $false)][hashtable]$LetterDeviceMap = @{},
        [Parameter(Mandatory = $false)][hashtable]$VolumeMap = @{}
    )

    $existing = @($Partition.AccessPaths |
        Where-Object { $_ -and $_ -match '^[A-Za-z]:' } |
        ForEach-Object { $_.TrimEnd('\').ToUpperInvariant() } |
        Where-Object { Test-OfflinePath "$_\" })

    if ($existing.Count -gt 0) { return @($existing | Select-Object -Unique) }

    $volumePaths = @($Partition.AccessPaths | Where-Object { $_ -and $_ -match '^\\\\\?\\Volume\{' })

    # Preferred source: the object namespace, which holds letters mountvol cannot see.
    foreach ($volumePath in $volumePaths) {
        $device = Get-DosDeviceTarget -Name (($volumePath.TrimEnd('\')) -replace '^\\\\\?\\', '')
        if ([string]::IsNullOrWhiteSpace($device)) { continue }

        # Sorted so repeated runs settle on the same letter for the same partition.
        foreach ($letter in @($LetterDeviceMap.Keys | Sort-Object)) {
            if ($LetterDeviceMap[$letter] -ne $device) { continue }
            if (-not (Test-OfflinePath "$letter\")) { continue }
            return @($letter)
        }
    }

    foreach ($volumePath in $volumePaths) {
        $key = $volumePath.TrimEnd('\')
        if (-not $VolumeMap.ContainsKey($key)) { continue }

        # All letters on one volume address the same file system, so the first
        # usable one is enough and keeps later path building deterministic.
        $recovered = @($VolumeMap[$key] | Where-Object { Test-OfflinePath "$_\" } | Select-Object -First 1)
        if ($recovered.Count -gt 0) { return @($recovered) }
    }

    return @()
}

function Stop-NestedRepairVm {
    <#
    .SYNOPSIS
        Releases the Azure-created nested guest before an offline repair.

    .DESCRIPTION
        Only relevant when the repair VM was created with 'az vm repair create --enable-nested'.
        The default target is exactly one guest named ProblemVM; a custom guest requires its
        explicit Id. Other active guests block discovery rather than being turned off.

        A guest claimed by Start-NestedRepairVm is never stopped here. The owning flow must
        call Stop-NestedRepairVmGraceful and confirm Stopped before rediscovering the disk.
        Refusing, rather than merely skipping that guest, prevents disk preparation from
        proceeding while the guest still owns it. The Notes marker persists across processes.

        Returns the name only after the selected guest is confirmed Off. Does nothing when
        Hyper-V is absent. Enumeration or shutdown failures abort the hand-off.

    .PARAMETER VmId
        Exact Id of a custom, unmanaged repair guest. Omit for the Azure-created ProblemVM.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Object[]])]
    param([guid]$VmId = [guid]::Empty)

    $stopped = @()
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $stopped }

    $lease = Enter-OfflineNestedVmLifecycle
    try {
        $guests = @(Get-VM -ErrorAction Stop)
        $active = @($guests | Where-Object { $_.State -ne 'Off' })
        $managed = @($active | Where-Object { Test-OfflineNestedVmManaged -Vm $_ })
        if ($managed.Count -gt 0) {
            $names = ($managed | ForEach-Object { "'$($_.Name)' ($($_.Id))" }) -join ', '
            throw "Offline discovery refused: helper-managed guest(s) $names are still active. The owning flow must use Stop-NestedRepairVmGraceful and confirm Stopped before taking the disk back."
        }

        $target = @(if ($VmId -ne [guid]::Empty) {
                $guests | Where-Object { $_.Id -eq $VmId }
            }
            else {
                $guests | Where-Object { $_.Name -eq 'ProblemVM' }
            })

        if ($VmId -ne [guid]::Empty -and $target.Count -ne 1) {
            throw "The explicitly selected nested repair guest '$VmId' could not be resolved uniquely."
        }
        if ($active.Count -eq 0) { return $stopped }
        if ($target.Count -ne 1) {
            throw 'Active Hyper-V guests exist but there is not exactly one ProblemVM. Nothing was stopped. Select the intended unmanaged repair guest explicitly with -NestedVmId on Get-OfflineWindowsDisk.'
        }

        $other = @($active | Where-Object { $_.Id -ne $target[0].Id })
        if ($other.Count -gt 0) {
            $names = ($other | ForEach-Object { "'$($_.Name)' ($($_.Id))" }) -join ', '
            throw "Offline discovery refused: other Hyper-V guest(s) $names are active. Nothing was stopped; complete their disk hand-off explicitly first."
        }

        $vm = Get-VM -Id $target[0].Id -ErrorAction Stop
        if (-not $vm) { throw 'The selected nested repair guest disappeared before shutdown.' }
        if ($vm.State -eq 'Off') { return $stopped }
        if (Test-OfflineNestedVmManaged -Vm $vm) {
            throw "Nested guest '$($vm.Name)' was claimed by a repair flow; automatic shutdown was refused."
        }
        if ($vm.State -ne 'Running') {
            throw "Nested guest '$($vm.Name)' is '$($vm.State)', not Running or Off. Resolve that state explicitly before offline discovery."
        }
        if (-not $PSCmdlet.ShouldProcess($vm.Name, 'Turn off the selected unmanaged repair VM so its disk can be mounted offline')) {
            return $stopped
        }

        Add-OfflineRepairLog -Level Info -Message "Stopping unmanaged nested repair guest '$($vm.Name)' ($($vm.Id)) so its disk can be mounted offline."
        Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
        $after = Get-VM -Id $vm.Id -ErrorAction Stop
        if (-not $after -or $after.State -ne 'Off') {
            throw "Nested guest '$($vm.Name)' could not be confirmed Off after shutdown; disk preparation was refused."
        }
        $stopped += $vm.Name
        return $stopped
    }
    catch {
        Add-OfflineRepairLog -Level Error -Message $_.Exception.Message
        throw
    }
    finally {
        Exit-OfflineNestedVmLifecycle -Lease $lease
    }
}

function Test-TemporaryStorageDisk {
    <#
    .SYNOPSIS
        Reports whether a disk is the Azure temporary/resource disk.

    .DESCRIPTION
        The temporary/resource disk is local scratch space that is wiped on deallocation.
        It sits on the same bus as the disks being repaired and carries no attribute the
        bus-type filter would exclude, so without an explicit check it would be brought
        online and made writable like a broken OS disk. Match either the English
        'Temporary Storage' label or the language-independent DATALOSS_WARNING_README.txt
        at a volume root. Inspect existing access paths only; this check never mounts a disk.

    .OUTPUTS
        $true when any volume on the disk has either resource-disk marker.
    #>
    param(
        [Parameter(Mandatory = $true)]$Disk
    )

    try {
        foreach ($partition in @(Get-Partition -DiskNumber $Disk.Number -ErrorAction SilentlyContinue)) {
            $volumes = @($partition | Get-Volume -ErrorAction SilentlyContinue)
            $labels = @($volumes | ForEach-Object { $_.FileSystemLabel })
            if ($labels -contains 'Temporary Storage') { return $true }

            $roots = @($partition.AccessPaths) + @($volumes | ForEach-Object {
                    $_.Path
                    if ($_.DriveLetter) { "$($_.DriveLetter):\" }
                })
            foreach ($root in @($roots | Where-Object { $_ } | Select-Object -Unique)) {
                $marker = Join-OfflinePath -Root $root -ChildPath 'DATALOSS_WARNING_README.txt'
                if ($marker -and (Test-OfflinePath $marker)) { return $true }
            }
        }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not inspect resource-disk markers on disk $($Disk.Number): $($_.Exception.Message)"
    }

    return $false
}

function Set-OfflineDisksOnline {
    <#
    .SYNOPSIS
        Brings every attached virtual data disk online and clears the read-only flag.

    .DESCRIPTION
        The rescue VM's own boot/system disk and the Azure temporary/resource disk are
        never touched. Returns disk numbers confirmed online and writable. A disk that is
        already ready requires no writes; a changed disk is re-read rather than trusting
        diskpart's exit code, because 'noerr' can suppress an online/attribute failure.

        SupportsShouldProcess is declared so -WhatIf reports each disk it would online.
        ConfirmImpact is left at the default (Medium), below the default $ConfirmPreference
        (High), so the non-interactive run proceeds without a prompt.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)][int[]]$ExcludeDiskNumber = @()
    )

    $processed = @()
    # Azure SCSI disks report 'Msft Virtual Disk' but NVMe disks report 'Microsoft NVMe
    # Direct Disk', so a model-name match misses NVMe entirely; the bus type sees both. The
    # boot/system disk and the wipe-on-deallocate resource disk are excluded so a failed
    # precondition can never bring the rescue VM's live OS disk online.
    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.BusType -in @('SCSI', 'SAS', 'RAID', 'NVMe', 'File Backed Virtual') -and
            $_.Number -notin $ExcludeDiskNumber -and
            -not ($_.IsBoot -or $_.IsSystem) -and
            -not (Test-TemporaryStorageDisk -Disk $_)
        })

    foreach ($disk in $disks) {
        if (-not $disk.IsOffline -and -not $disk.IsReadOnly) {
            $processed += $disk.Number
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("disk $($disk.Number)", 'Bring online and clear the read-only flag')) { continue }

        # diskpart is used rather than Set-Disk because it succeeds on disks whose
        # partition table is damaged, which is common on the disks we are repairing.
        $commands = @("select disk $($disk.Number)")
        if ($disk.IsReadOnly) { $commands += 'attributes disk clear readonly noerr' }
        if ($disk.IsOffline) { $commands += 'online disk noerr' }
        $output = ($commands -join "`r`n") | diskpart.exe 2>&1
        $diskpartExit = $LASTEXITCODE
        $diskState = $null
        $stateError = ''
        try {
            $diskState = Get-Disk -Number $disk.Number -ErrorAction Stop
        }
        catch {
            $stateError = $_.Exception.Message
        }

        if ($diskState -and -not $diskState.IsOffline -and -not $diskState.IsReadOnly) {
            $processed += $disk.Number
            if ($diskpartExit -ne 0) {
                Add-OfflineRepairLog -Level Warning -Message "Disk $($disk.Number) is confirmed online and writable, but diskpart reported exit $diskpartExit`: $(($output | Out-String).Trim())"
            }
        }
        else {
            $stateText = if ($diskState) { "IsOffline=$($diskState.IsOffline), IsReadOnly=$($diskState.IsReadOnly)" } else { "state unavailable: $stateError" }
            Add-OfflineRepairLog -Level Warning -Message "Disk $($disk.Number) was not confirmed online and writable ($stateText; diskpart exit $diskpartExit): $(($output | Out-String).Trim())"
        }
    }

    if ($processed.Count -gt 0) {
        Add-OfflineRepairLog -Level Info -Message "Attached virtual disk(s) confirmed online and writable: $($processed -join ', ')"
    }
    else {
        Add-OfflineRepairLog -Level Warning -Message 'No attached virtual data disk was brought online on the rescue VM.'
    }

    # Give the volume stack a moment to surface the new volumes.
    Start-Sleep -Seconds 2
    return $processed
}

function Add-PartitionDriveLetter {
    <#
    .SYNOPSIS
        Assigns a free drive letter to a partition that does not have one.

    .DESCRIPTION
        Set-Partition -NewDriveLetter fails on EFI System and Recovery partitions, so
        diskpart is used, with Add-PartitionAccessPath as a fallback.

        Success is verified by probing the drive root rather than by re-reading
        Get-Partition, because the partition object never reports a drive letter for
        hidden System and Recovery partitions even after one has been assigned.

    .PARAMETER DriveLetter
        Optional letter to assign, as 'D', 'D:' or 'D:\'. When omitted a free letter is
        chosen. It is validated down to a single letter before use, because it is
        interpolated into a diskpart script where an embedded newline would inject commands.

    .OUTPUTS
        The assigned drive letter (without a colon), or $null on failure. A letter that was
        successfully assigned is tracked, so Remove-OfflineDriveLetter or
        Clear-OfflineDriveLetter can release it later.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $false)][ValidatePattern('^[A-Za-z]:?\\?$')][string]$DriveLetter
    )

    if ([string]::IsNullOrWhiteSpace($DriveLetter)) { $DriveLetter = Get-FreeDriveLetter }
    $DriveLetter = $DriveLetter.TrimEnd(':', '\').ToUpperInvariant()

    # ValidatePattern is skipped when the parameter is omitted, and TrimEnd only strips
    # trailing characters, so this re-assertion is what actually guarantees a single letter
    # reaches the here-string below. Without it an embedded newline would inject diskpart
    # commands such as 'select disk 0' / 'clean' onto the wrong disk.
    if ($DriveLetter -notmatch '^[A-Z]$') {
        throw "Invalid drive letter '$DriveLetter'. Expected a single letter A-Z."
    }

    $diskpartScript = @"
select disk $DiskNumber
select partition $PartitionNumber
assign letter=$DriveLetter
exit
"@
    $output = $diskpartScript | diskpart.exe 2>&1
    $diskpartExit = $LASTEXITCODE

    if (Wait-OfflineDriveLetterReady -DriveLetter $DriveLetter) {
        Add-OfflineRepairLog -Level Info -Message "Assigned drive letter ${DriveLetter}: to disk $DiskNumber partition $PartitionNumber."
        Register-OfflineAssignedDriveLetter -DriveLetter $DriveLetter -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
        return $DriveLetter
    }

    Add-OfflineRepairLog -Level Info -Message "diskpart did not surface ${DriveLetter}: for disk $DiskNumber partition $PartitionNumber (exit code $diskpartExit). Trying an access path. diskpart output: $(($output | Out-String).Trim())"

    # Fallback for partitions diskpart refuses to address, such as the MSR partition.
    try {
        Add-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -AccessPath "${DriveLetter}:" -ErrorAction Stop
        if (Wait-OfflineDriveLetterReady -DriveLetter $DriveLetter) {
            Add-OfflineRepairLog -Level Info -Message "Assigned drive letter ${DriveLetter}: to disk $DiskNumber partition $PartitionNumber (access path)."
            Register-OfflineAssignedDriveLetter -DriveLetter $DriveLetter -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
            return $DriveLetter
        }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not add an access path for disk $DiskNumber partition ${PartitionNumber}: $($_.Exception.Message)"
    }

    # The assignment ultimately failed. diskpart may still have half-attached the letter, so
    # release it rather than leak it and drop this partition out of every later run's alphabet.
    Clear-PartitionDriveLetterAssignment -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -DriveLetter $DriveLetter
    Add-OfflineRepairLog -Level Warning -Message "Could not assign a drive letter to disk $DiskNumber partition $PartitionNumber."
    return $null
}

function Wait-OfflineDriveLetterReady {
    <#
    .SYNOPSIS
        Waits for a freshly assigned drive letter to become reachable.

    .DESCRIPTION
        diskpart returns before the volume stack has finished surfacing the new root, and on
        a slower storage stack a single fixed sleep races it: the probe runs too early, the
        assignment is reported as failed, and the letter is leaked. Polling closes that race
        and still returns as soon as the root responds.

    .OUTPUTS
        $true once the drive root responds, $false if it never does within the timeout.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DriveLetter,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 10
    )

    $letter = $DriveLetter.TrimEnd(':', '\')
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-OfflinePath "${letter}:\") { return $true }
        Start-Sleep -Milliseconds 250
    }
    return [bool](Test-OfflinePath "${letter}:\")
}

function Get-OfflineAssignedDriveLetterList {
    <#
    .SYNOPSIS
        Returns the backing list of letters this session assigned, creating it on first use.

    .DESCRIPTION
        The list lives in the shared OfflineRepairCommon state, the same hashtable that holds
        the log buffer and the bound roots, so a caller's finally-block cleanup sees exactly
        what the discovery pass assigned. See that file's header for why the shared state is
        global rather than script-scoped.
    #>
    $state = Get-OfflineRepairState
    if (-not $state.ContainsKey('AssignedDriveLetters') -or -not $state['AssignedDriveLetters']) {
        $state['AssignedDriveLetters'] = [System.Collections.Generic.List[object]]::new()
    }
    # The unary comma returns the live List as a single object. Without it PowerShell unrolls
    # the collection on output, so an empty list comes back as $null and a populated one as a
    # detached copy, and Register/Remove/Clear would then mutate a throwaway rather than the
    # instance the shared state holds. Callers must assign the result before piping it.
    return , $state['AssignedDriveLetters']
}

function Register-OfflineAssignedDriveLetter {
    <#
    .SYNOPSIS
        Records a drive letter this session assigned, so it can be released later.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DriveLetter,
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber
    )

    $letter = $DriveLetter.TrimEnd(':', '\').ToUpperInvariant()
    $list = Get-OfflineAssignedDriveLetterList
    if ($list | Where-Object { $_.Letter -eq $letter }) { return }
    [void]$list.Add([PSCustomObject]@{ Letter = $letter; DiskNumber = $DiskNumber; PartitionNumber = $PartitionNumber })
}

function Get-OfflineAssignedDriveLetter {
    <#
    .SYNOPSIS
        Returns the drive letters this session assigned, in the form 'K:'.
    #>
    # Assign first: Get-OfflineAssignedDriveLetterList returns the live List as a single
    # object, so piping it straight from the call would hand ForEach-Object the whole list
    # instead of its entries. Piping the assigned variable enumerates the entries.
    $list = Get-OfflineAssignedDriveLetterList
    return @($list | ForEach-Object { "$($_.Letter):" })
}

function Clear-PartitionDriveLetterAssignment {
    <#
    .SYNOPSIS
        Releases a drive letter from a partition, by diskpart with an access-path fallback.

    .DESCRIPTION
        Internal. The letter is validated to a single letter before it reaches the diskpart
        script, for the same injection reason as Add-PartitionDriveLetter. Best effort: a
        letter that is already gone is not treated as an error.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $true)][string]$DriveLetter
    )

    $letter = $DriveLetter.TrimEnd(':', '\').ToUpperInvariant()
    if ($letter -notmatch '^[A-Z]$') { return }

    $diskpartScript = @"
select disk $DiskNumber
select partition $PartitionNumber
remove letter=$letter noerr
exit
"@
    $null = $diskpartScript | diskpart.exe 2>&1

    if (Test-OfflinePath "${letter}:\") {
        try { Remove-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -AccessPath "${letter}:" -ErrorAction Stop }
        catch { Add-OfflineRepairLog -Level Info -Message "Could not remove access path ${letter}: from disk $DiskNumber partition ${PartitionNumber}: $($_.Exception.Message)" }
    }
}

function Remove-OfflineDriveLetter {
    <#
    .SYNOPSIS
        Releases one drive letter this session assigned and stops tracking it.

    .DESCRIPTION
        SupportsShouldProcess is declared so -WhatIf reports the letter it would release.
        ConfirmImpact is left at the default (Medium), below the default $ConfirmPreference
        (High), so a caller's finally-block cleanup releases the letter without a prompt.

    .PARAMETER DriveLetter
        The letter to release, as 'K', 'K:' or 'K:\'.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]:?\\?$')][string]$DriveLetter
    )

    $letter = $DriveLetter.TrimEnd(':', '\').ToUpperInvariant()
    $list = Get-OfflineAssignedDriveLetterList
    $tracked = @($list | Where-Object { $_.Letter -eq $letter })
    foreach ($entry in $tracked) {
        if (-not $PSCmdlet.ShouldProcess("drive letter $($entry.Letter): (disk $($entry.DiskNumber) partition $($entry.PartitionNumber))", 'Release drive letter')) { continue }
        Clear-PartitionDriveLetterAssignment -DiskNumber $entry.DiskNumber -PartitionNumber $entry.PartitionNumber -DriveLetter $entry.Letter
        Add-OfflineRepairLog -Level Info -Message "Released drive letter $($entry.Letter): from disk $($entry.DiskNumber) partition $($entry.PartitionNumber)."
        [void]$list.Remove($entry)
    }
}

function Clear-OfflineDriveLetter {
    <#
    .SYNOPSIS
        Releases every drive letter this session assigned. For a caller's finally block.

    .DESCRIPTION
        The discovery pass assigns temporary letters to the EFI System and Recovery
        partitions, and every run would otherwise leak them until the alphabet is exhausted.
        A caller runs this in a finally so the letters are handed back even when the repair
        in between throws.

        Because it runs in a finally, it must never throw: a throw here would replace the
        real repair exception and hide the actual failure from the operator. So every letter
        is released in its own try/catch - one letter that cannot be released no longer
        abandons the rest. Each letter that IS released is untracked individually (by the
        delegated Remove-OfflineDriveLetter), so nothing blanket-clears the list while it
        still holds failures and a later attempt does not retry a letter already handed back.
        Anything still stuck is named in a single Warning rather than passed off as clean.

        Every release is delegated to Remove-OfflineDriveLetter instead of calling
        Clear-PartitionDriveLetterAssignment directly, so there is exactly one guarded release
        path: Remove-OfflineDriveLetter owns the ShouldProcess gate, the diskpart call and the
        untracking, and this function cannot drift from it. SupportsShouldProcess is declared
        here only to expose -WhatIf/-Confirm and let the preference flow into those delegated
        calls; this function performs no state change of its own, which is why it does not call
        ShouldProcess itself. Under -WhatIf it therefore releases nothing and reports each
        letter, exactly as Remove-OfflineDriveLetter does for a single letter.

    .OUTPUTS
        None. Letters that could not be released are surfaced with a Warning and left tracked
        for a later attempt; nothing is written to the pipeline, so a bare call in a caller's
        finally block does not pollute that caller's output.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Snapshot the letters first: Remove-OfflineDriveLetter mutates the shared tracking list as
    # it releases each one, so iterating the live list would skip entries.
    $failed = @()
    foreach ($letter in @(Get-OfflineAssignedDriveLetter)) {
        try {
            Remove-OfflineDriveLetter -DriveLetter $letter
        }
        catch {
            $failed += "$letter ($($_.Exception.Message))"
        }
    }
    if ($failed.Count -gt 0) {
        Add-OfflineRepairLog -Level Warning -Message "Drive-letter cleanup could not release: $($failed -join '; '). They remain tracked for a later attempt."
    }
}

function Get-OfflineWindowsInstallCandidate {
    <#
    .SYNOPSIS
        Builds a scored candidate object for one offline Windows installation.

    .DESCRIPTION
        Scoring prefers an installation that has both core hives, the boot loader
        binary expected for the disk's firmware generation, and the highest build
        number, and penalises an installation that is mid-setup.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AccessPath,
        [Parameter(Mandatory = $true)]$PartitionInfo,
        [Parameter(Mandatory = $true)][int]$Generation
    )

    $normalizedPath = if ($AccessPath -match '\\$') { $AccessPath } else { "$AccessPath\" }
    $windowsRoot = Join-OfflinePath -Root $normalizedPath -ChildPath 'Windows'
    $systemHivePath = Join-OfflinePath -Root $windowsRoot -ChildPath 'System32\Config\SYSTEM'
    $softwareHivePath = Join-OfflinePath -Root $windowsRoot -ChildPath 'System32\Config\SOFTWARE'
    $winloadName = if ($Generation -eq 2) { 'System32\winload.efi' } else { 'System32\winload.exe' }
    $expectedWinload = Join-OfflinePath -Root $windowsRoot -ChildPath $winloadName

    $candidate = [ordered]@{
        AccessPath          = $normalizedPath
        Drive               = $normalizedPath.TrimEnd('\').ToUpperInvariant()
        DiskNumber          = $PartitionInfo.DiskNumber
        PartitionNumber     = $PartitionInfo.PartitionNumber
        PartitionType       = "$($PartitionInfo.Type)"
        IsActive            = [bool]$PartitionInfo.IsActive
        WindowsRoot         = $windowsRoot
        SystemHivePresent   = Test-OfflinePath $systemHivePath
        SoftwareHivePresent = Test-OfflinePath $softwareHivePath
        HasExpectedWinload  = Test-OfflinePath $expectedWinload
        ProductName         = ''
        CurrentBuildNumber  = ''
        GuestComputerName   = ''
        SetupInProgress     = $false
        ProbeStatus         = 'NotProbed'
        Score               = 0
        Selected            = $false
    }

    if ($candidate.SystemHivePresent -and $candidate.SoftwareHivePresent) {
        # Unreadable metadata lowers a candidate's score but must not hide the disk that
        # needs repairing. A close failure, unlike a read failure, aborts discovery.
        $probeNotes = [System.Collections.Generic.List[string]]::new()

        foreach ($hiveName in @('SOFTWARE', 'SYSTEM')) {
            $hivePath = if ($hiveName -eq 'SOFTWARE') { $softwareHivePath } else { $systemHivePath }
            $reader = $null
            try {
                $reader = Open-OfflineRegistryReader -Path $hivePath
                if ($hiveName -eq 'SOFTWARE') {
                    $cvKey = 'Microsoft\Windows NT\CurrentVersion'
                    $candidate.ProductName = [string]$reader.ReadString($cvKey, 'ProductName')
                    $candidate.CurrentBuildNumber = [string]$reader.ReadString($cvKey, 'CurrentBuildNumber')
                    if (-not $candidate.ProductName -or -not $candidate.CurrentBuildNumber) {
                        [void]$probeNotes.Add('SOFTWARE product name or build number is absent.')
                    }
                }
                else {
                    $currentSet = $reader.ReadDword('Select', 'Current')
                    if ($null -eq $currentSet -or $currentSet -lt 1 -or $currentSet -gt 999) {
                        [void]$probeNotes.Add('SYSTEM\Select\Current is absent or invalid; the active control set cannot be identified.')
                    }
                    else {
                        $controlSetName = 'ControlSet{0:d3}' -f $currentSet
                        $candidate.GuestComputerName = [string]$reader.ReadString("$controlSetName\Control\ComputerName\ComputerName", 'ComputerName')
                        if (-not $candidate.GuestComputerName) {
                            [void]$probeNotes.Add("SYSTEM\$controlSetName guest computer name is absent.")
                        }
                    }

                    $setupType = $reader.ReadDword('Setup', 'SetupType')
                    $cmdLine = $reader.ReadString('Setup', 'CmdLine')
                    if ($null -eq $setupType) { [void]$probeNotes.Add('SYSTEM\Setup\SetupType is absent.') }
                    if (($null -ne $setupType -and $setupType -ne 0) -or -not [string]::IsNullOrWhiteSpace($cmdLine)) {
                        $candidate.SetupInProgress = $true
                    }
                }
            }
            catch {
                [void]$probeNotes.Add("$hiveName read failed: $($_.Exception.Message)")
            }
            finally {
                if ($reader) { $reader.Dispose() }
            }
        }

        if ($probeNotes.Count -eq 0) {
            $candidate.ProbeStatus = 'OK'
        }
        else {
            $candidate.ProbeStatus = $probeNotes -join '; '
            Add-OfflineRepairLog -Level Warning -Message "Offline hive probe of $normalizedPath has incomplete metadata, which may lower this installation's score: $($candidate.ProbeStatus)"
        }
    }
    else {
        $candidate.ProbeStatus = "Skipped: SYSTEM hive present = $($candidate.SystemHivePresent), SOFTWARE hive present = $($candidate.SoftwareHivePresent)"
    }

    if (Test-OfflinePath (Join-OfflinePath -Root $normalizedPath -ChildPath '$WINDOWS.~BT')) { $candidate.SetupInProgress = $true }

    $score = 0
    if ($candidate.SystemHivePresent) { $score += 10 }
    if ($candidate.SoftwareHivePresent) { $score += 10 }
    if ($candidate.HasExpectedWinload) { $score += 30 } else { $score -= 25 }
    if ($candidate.ProductName) { $score += 10 }

    $buildInt = 0
    if ([int]::TryParse($candidate.CurrentBuildNumber, [ref]$buildInt)) {
        $score += [Math]::Min([int]($buildInt / 1000), 30)
    }
    if ($candidate.SetupInProgress) { $score -= 20 }

    $candidate.Score = $score
    return [PSCustomObject]$candidate
}

function Get-OfflineWindowsDisk {
    <#
    .SYNOPSIS
        Locates the offline Windows installation on the attached broken OS disk.

    .DESCRIPTION
        Releases an unmanaged Azure-created nested repair VM, brings the attached virtual disks
        online, assigns drive letters to partitions that have none, then selects the
        best Windows installation and its matching boot partition. Active helper-managed
        or unrelated guests block discovery before disks or drive letters are changed.

        Publishes the selected Windows drive through the shared repair state.

    .PARAMETER DiskNumber
        Restrict the search to a specific disk number.

    .PARAMETER WindowsDrive
        Skip discovery and use this drive letter as the offline Windows volume.

    .PARAMETER NestedVmId
        Exact Id of a custom unmanaged repair guest. Omit for the Azure-created ProblemVM.

    .OUTPUTS
        PSCustomObject with DiskNumber, PartitionStyle, Generation, WindowsDrive,
        WindowsPath, PartitionNumber, BootDrive, BcdStorePath, ProductName, BuildNumber,
        GuestComputerName, SetupInProgress, PartitionRoots, AssignedDriveLetters and
        Candidates. AssignedDriveLetters holds the letters this run assigned; pass each to
        Remove-OfflineDriveLetter, or call Clear-OfflineDriveLetter, in the caller's finally.

    .EXAMPLE
        $offline = Get-OfflineWindowsDisk
        Invoke-WithHive 'SYSTEM' { Get-ItemProperty "$(Get-OfflineSystemRootPath)\Services\disk" }
    #>
    param(
        [Parameter(Mandatory = $false)][int]$DiskNumber = -1,
        [Parameter(Mandatory = $false)][string]$WindowsDrive,
        [Parameter(Mandatory = $false)][guid]$NestedVmId = [guid]::Empty
    )

    # The rescue VM's own OS disk must be known before anything is brought online, because
    # every exclusion below keys off it. A real disk number is >= 0, so leaving this at a
    # sentinel would make the exclusion match nothing and expose the live OS disk. Fail
    # closed rather than warn and carry on.
    try {
        $systemDiskNumber = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop).DiskNumber
    }
    catch {
        throw "Could not determine the rescue VM's own system disk number, so the broken disk cannot be told apart from it: $($_.Exception.Message)"
    }

    $lease = Enter-OfflineNestedVmLifecycle
    try {
        $null = Stop-NestedRepairVm -VmId $NestedVmId
        $onlineDiskNumbers = @(Set-OfflineDisksOnline -ExcludeDiskNumber @($systemDiskNumber | Where-Object { $_ -ge 0 }))
    }
    finally {
        Exit-OfflineNestedVmLifecycle -Lease $lease
    }

    # Select by bus type, not model name: Azure NVMe disks report 'Microsoft NVMe Direct
    # Disk', which the old '*Virtual Disk*' match missed. The rescue VM's own system disk,
    # any boot/system disk, and the 'Temporary Storage' resource disk are all excluded so a
    # broken precondition can never route the repair onto the live OS.
    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.BusType -in @('SCSI', 'SAS', 'RAID', 'NVMe', 'File Backed Virtual') -and
            $_.Number -ne $systemDiskNumber -and
            $_.Number -in $onlineDiskNumbers -and
            -not ($_.IsOffline -or $_.IsReadOnly) -and
            -not ($_.IsBoot -or $_.IsSystem) -and
            -not (Test-TemporaryStorageDisk -Disk $_) -and
            ($DiskNumber -lt 0 -or $_.Number -eq $DiskNumber)
        })

    if ($disks.Count -eq 0) {
        throw 'No attached broken OS disk was found. Create the rescue VM with "az vm repair create" first.'
    }

    # Give every partition a drive letter. EFI System and Recovery partitions have none
    # by default, and offline boot repairs cannot reach them without one.
    # Get-Partition never reports a letter for those partitions even after assignment,
    # so the letters are tracked here and used for all later path building.
    $partitionRoots = @{}
    $volumeMap = Get-VolumeDriveLetterMap
    $letterDeviceMap = Get-DriveLetterDeviceMap
    foreach ($disk in $disks) {
        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            $key = "$($disk.Number)-$($part.PartitionNumber)"

            $existing = @(Get-PartitionExistingRoot -Partition $part -LetterDeviceMap $letterDeviceMap -VolumeMap $volumeMap)
            if ($existing.Count -gt 0) {
                $partitionRoots[$key] = @($existing)
                continue
            }

            # The Microsoft Reserved partition holds no file system and cannot be mounted.
            if ("$($part.Type)" -eq 'Reserved') { continue }
            if ($part.Size -lt 1MB) { continue }

            $letter = Add-PartitionDriveLetter -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
            if ($letter) {
                $partitionRoots[$key] = @("${letter}:")

                # Keep the map current so a partition that shares this volume is not
                # handed a second letter later in the same pass.
                $newDevice = Get-DosDeviceTarget -Name "${letter}:"
                if (-not [string]::IsNullOrWhiteSpace($newDevice)) { $letterDeviceMap["${letter}:"] = $newDevice }
            }
        }
    }

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($disk in $disks) {
        $generation = if ($disk.PartitionStyle -eq 'GPT') { 2 } elseif ($disk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            foreach ($accessPath in @($partitionRoots["$($disk.Number)-$($part.PartitionNumber)"])) {
                if (-not $accessPath) { continue }
                if (-not (Test-OfflinePath (Join-OfflinePath -Root $accessPath -ChildPath 'Windows\System32\ntdll.dll'))) { continue }

                $normalized = if ($accessPath -match '\\$') { $accessPath } else { "$accessPath\" }
                if ($candidates | Where-Object { $_.AccessPath -eq $normalized } | Select-Object -First 1) { continue }

                [void]$candidates.Add((Get-OfflineWindowsInstallCandidate -AccessPath $normalized -PartitionInfo $part -Generation $generation))
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($WindowsDrive)) {
        $wanted = $WindowsDrive.TrimEnd(':', '\').ToUpperInvariant() + ':'
        $forced = @($candidates | Where-Object { $_.Drive -eq $wanted })
        if ($forced.Count -eq 0) {
            throw "No offline Windows installation was found on drive $wanted."
        }
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        $forced | ForEach-Object { [void]$candidates.Add($_) }
    }

    if ($candidates.Count -eq 0) {
        throw 'No offline Windows installation was found on the attached disk(s).'
    }

    # DiskNumber is the final key so that two installations with an equal score and build
    # settle on the same disk every run instead of ordering nondeterministically.
    $sorted = @($candidates | Sort-Object @{ Expression = 'Score'; Descending = $true },
        @{ Expression = { [int]($_.CurrentBuildNumber -as [int]) }; Descending = $true }, PartitionNumber, DiskNumber)
    $selected = $sorted[0]
    foreach ($candidate in $sorted) { $candidate.Selected = ($candidate.Drive -eq $selected.Drive) }

    if ($sorted.Count -gt 1) {
        Add-OfflineRepairLog -Level Warning -Message "$($sorted.Count) Windows installations found on the attached disk(s). Selected $($selected.Drive) (score $($selected.Score))."
    }

    $selectedDisk = Get-Disk -Number $selected.DiskNumber -ErrorAction SilentlyContinue
    $generation = if ($selectedDisk.PartitionStyle -eq 'GPT') { 2 } elseif ($selectedDisk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

    # Locate the boot partition and its BCD store on the same disk.
    $bootDrive = $null
    $bcdStorePath = $null
    foreach ($part in (Get-Partition -DiskNumber $selected.DiskNumber -ErrorAction SilentlyContinue)) {
        foreach ($accessPath in @($partitionRoots["$($selected.DiskNumber)-$($part.PartitionNumber)"])) {
            if (-not $accessPath) { continue }
            $efiBcd = Join-OfflinePath -Root $accessPath -ChildPath 'EFI\Microsoft\Boot\BCD'
            $biosBcd = Join-OfflinePath -Root $accessPath -ChildPath 'Boot\BCD'

            if ($generation -eq 2 -and (Test-OfflinePath $efiBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $efiBcd; break
            }
            if ($generation -ne 2 -and (Test-OfflinePath $biosBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $biosBcd; break
            }
        }
        if ($bootDrive) { break }
    }

    if (-not $bootDrive) {
        # The BCD file may be missing while the system partition itself is intact.
        foreach ($part in (Get-Partition -DiskNumber $selected.DiskNumber -ErrorAction SilentlyContinue)) {
            $isBootPartition = ("$($part.Type)" -eq 'System') -or ($generation -ne 2 -and $part.IsActive)
            if (-not $isBootPartition) { continue }
            $root = @($partitionRoots["$($selected.DiskNumber)-$($part.PartitionNumber)"]) | Select-Object -First 1
            if ($root) {
                $bootDrive = $root.TrimEnd('\')
                $bcdStorePath = if ($generation -eq 2) { Join-OfflinePath -Root $bootDrive -ChildPath 'EFI\Microsoft\Boot\BCD' } else { Join-OfflinePath -Root $bootDrive -ChildPath 'Boot\BCD' }
                Add-OfflineRepairLog -Level Warning -Message "No BCD store was found at $bcdStorePath, but the boot partition is present at $bootDrive."
                break
            }
        }
    }

    if (-not $bootDrive) {
        Add-OfflineRepairLog -Level Warning -Message 'No boot partition was found on the attached disk. Boot configuration repairs will not be available.'
    }

    # Bind the chosen volume as the offline repair root. This is what lets every other
    # helper's Assert-OfflineTarget gate prove it is writing to the broken disk and not to
    # the rescue VM. Set-OfflineRepairRoot throws if this somehow resolved to the rescue
    # VM's own system drive, which is the fail-closed behaviour we want. The boot/EFI
    # partition is a separate volume on the same disk that BCD repairs write to, so it is
    # bound too or the gate would refuse them.
    $null = Set-OfflineWindowsDrive -WindowsDrive $selected.Drive
    if ($bootDrive) {
        $bootRoot = "$bootDrive".TrimEnd('\')
        if ($bootRoot -match '^[A-Za-z]:$' -and $bootRoot -ne $selected.Drive) {
            $null = Set-OfflineRepairRoot -Path $bootRoot
        }
    }

    $result = [PSCustomObject]@{
        DiskNumber           = $selected.DiskNumber
        PartitionStyle       = "$($selectedDisk.PartitionStyle)"
        Generation           = $generation
        WindowsDrive         = $selected.Drive
        WindowsPath          = $selected.WindowsRoot
        PartitionNumber      = $selected.PartitionNumber
        BootDrive            = $bootDrive
        BcdStorePath         = $bcdStorePath
        ProductName          = $selected.ProductName
        BuildNumber          = $selected.CurrentBuildNumber
        GuestComputerName    = $selected.GuestComputerName
        SetupInProgress      = $selected.SetupInProgress
        ProbeStatus          = $selected.ProbeStatus
        PartitionRoots       = $partitionRoots
        AssignedDriveLetters = Get-OfflineAssignedDriveLetter
        Candidates           = $sorted
    }

    Add-OfflineRepairLog -Level Info -Message "Offline Windows: $($result.WindowsPath) (disk $($result.DiskNumber), Gen$($result.Generation), $($result.ProductName) build $($result.BuildNumber))"
    if ($result.GuestComputerName) { Add-OfflineRepairLog -Level Info -Message "Guest computer name: $($result.GuestComputerName)" }
    if ($result.BootDrive) { Add-OfflineRepairLog -Level Info -Message "Boot partition: $($result.BootDrive) (BCD: $($result.BcdStorePath))" }

    return $result
}
