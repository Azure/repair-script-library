<#
.SYNOPSIS
    Helper functions for driving a nested Hyper-V guest that already exists on a rescue VM.

.DESCRIPTION
    'az vm repair create --enable-nested' builds the nested guest for us. It picks a SKU that
    supports nested virtualization, derives the guest generation from the source VM, installs the
    Hyper-V role, restarts the rescue VM across the reboot the role install needs, and then runs
    win-enable-nested-hyperv.ps1 a second time to create 'ProblemVM' with the broken OS disk
    attached and started.

    None of that is repeated here. This helper covers only what a *scenario script* needs once the
    guest exists, which is the part every existing consumer improvises:

      - Find the guest deterministically. Twelve scripts in this library run a bare 'Get-VM' with no
        name filter and assign the result straight to a variable. That silently yields an array if
        more than one guest is ever present, and $null with no explanation if the role is installed
        but no guest was created.
      - Hand the disk between host and guest. The disk can only be online in one place at a time:
        the host needs it online to edit files offline, and the guest cannot start unless the host
        has it offline.
      - Wait for the guest to actually boot, and report honestly when it did not. This is what lets
        a caller verify a repair that only takes effect inside the running guest, instead of
        starting the VM and asserting success.

    Exposed functions:
      Test-NestedRepairVmSupported   Is the Hyper-V role, its PowerShell module and vmms usable here.
      Get-NestedRepairVm             Resolve exactly one nested guest, or explain why it cannot.
      Connect-NestedRepairVmDisk     Attach the offline disk to the guest and point its boot order at it.
      Set-NestedRepairVmManaged      Persist the ownership marker that prevents automatic discovery shutdown.
      Start-NestedRepairVm           Take the disk offline on the host, attach it and start the guest.
      Wait-NestedRepairVmBoot        Block until the guest reports a heartbeat, or time out.
      Stop-NestedRepairVmGraceful    Ask the guest to shut down cleanly, pulling the power only if needed.

    The reverse direction already exists and is not duplicated here:
      Stop-NestedRepairVm            (Get-OfflineWindowsDisk.ps1) stop the guest holding the disk.
      Set-OfflineDisksOnline         (Get-OfflineWindowsDisk.ps1) bring the disk back to the host.

    A scenario script that needs the guest to run therefore follows this cycle:

      Stop-NestedRepairVm            # guest releases the disk
      Set-OfflineDisksOnline         # host takes the disk
      ... edit the offline disk ...
      Start-NestedRepairVm           # host releases the disk, guest boots and applies the change
      Wait-NestedRepairVmBoot        # observe that it really booted
      Stop-NestedRepairVmGraceful    # confirm Stopped before taking the disk back
      Set-OfflineDisksOnline         # host takes it back to verify the result

    Starting or adopting a running guest records a marker in its Notes without replacing existing
    notes. Discovery refuses while any marked guest is active; it must not just skip the guest and
    online its disks. The marker survives a new PowerShell process. A shared host mutex serializes
    the short ownership/disk transitions, not an entire repair session. Callers must still sequence
    their offline edits, guest execution and verified shutdown.

.NOTES
    Name:   Use-NestedRepairVm.ps1
    Requires: common/setup/init.ps1 dot-sourced first (for the Log-* functions), and
              common/helpers/OfflineRepairCommon.ps1 (for Add-OfflineRepairLog).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.

    A heartbeat proves the guest booted far enough to run Integration Services. Its absence does
    not prove the opposite, because a guest can be up with the service disabled. Every function
    here reports what it observed and never converts a timeout into success.

.VERSION
    v1.0: Initial version.
    v1.1: Reliability fixes to the resource lifecycle so a failed operation never leaves the rescue VM
          worse off while reporting success.
            - Start-NestedRepairVm restores, in a finally, exactly the disks it took offline whenever the
              guest does not end up running; attaches the disks it actually offlined instead of the raw
              request; treats "already running" as success only when the requested disk is truly attached;
              and fits the guest's startup memory to the host, retrying with dynamic memory on a memory
              failure.
            - Wait-NestedRepairVmBoot stops on every terminal state (Off, Paused, Saved, PausedCritical).
            - Connect-NestedRepairVmDisk fails, rather than warning, when a Generation 2 guest cannot be
              pointed at its disk.
            - Stop-NestedRepairVmGraceful returns the real reason when the shutdown request itself fails.
            - An all-skipped disk set (every requested disk unreadable or the rescue VM's own) is reported
              as a failure at both ends instead of starting a diskless guest that only burns the timeout.
            - Guests are resolved by Id, not by a name Get-VM treats as a wildcard; vmms must be running.
    v1.2: Mark helper-managed guests persistently and serialize lifecycle transitions with discovery.
          Report an unconfirmed or failed forced shutdown as failure, never as a completed hand-off.
#>

# Resolve the offline-repair core against this file's own folder, so a scenario loads the same
# helper wherever it dot-sources this from, and fail loudly here rather than at the first log call.
if (-not (Get-Command -Name Add-OfflineRepairLog -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name Enter-OfflineNestedVmLifecycle -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name Test-OfflineNestedVmManaged -ErrorAction SilentlyContinue)) {
    $dependencyPath = Join-Path -Path $PSScriptRoot -ChildPath 'OfflineRepairCommon.ps1'
    try {
        . $dependencyPath
    }
    catch {
        throw "Use-NestedRepairVm.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$dependencyPath': $($_.Exception.Message)"
    }
}
foreach ($required in @('Add-OfflineRepairLog', 'Get-OfflineNestedVmOwnershipTag',
        'Test-OfflineNestedVmManaged', 'Enter-OfflineNestedVmLifecycle', 'Exit-OfflineNestedVmLifecycle')) {
    if (-not (Get-Command -Name $required -ErrorAction SilentlyContinue)) {
        throw "Use-NestedRepairVm.ps1 requires '$required', which OfflineRepairCommon.ps1 did not define."
    }
}

# The name 'az vm repair create --enable-nested' gives the guest it builds.
$script:NestedRepairVmDefaultName = 'ProblemVM'

function Test-NestedRepairVmSupported {
    <#
    .SYNOPSIS
        Reports whether this machine can drive a nested Hyper-V guest.

    .DESCRIPTION
        Checks the three things a caller actually depends on: the Hyper-V role being installed, the
        Hyper-V PowerShell module being present so Get-VM exists, and the Virtual Machine Management
        service (vmms) actually running. They are independent: the role and module can be present while
        vmms is stopped or disabled, in which case every later call against a guest fails with a
        confusing error, so that case is reported here as not supported.

    .OUTPUTS
        PSCustomObject with Supported, RoleInstalled, ModuleAvailable, ServiceRunning and Reason.
    #>
    $result = [PSCustomObject]@{
        Supported       = $false
        RoleInstalled   = $false
        ModuleAvailable = $false
        ServiceRunning  = $false
        Reason          = $null
    }

    $result.ModuleAvailable = [bool](Get-Command -Name 'Get-VM' -ErrorAction SilentlyContinue)

    try {
        $feature = Get-WindowsFeature -Name 'Hyper-V' -ErrorAction Stop
        $result.RoleInstalled = [bool]$feature.Installed
    }
    catch {
        # Get-WindowsFeature is Server-only. On a client rescue image fall back to the module,
        # which is the capability the caller actually needs.
        $result.RoleInstalled = $result.ModuleAvailable
    }

    # The role and module can both be present while the Virtual Machine Management service is stopped or
    # disabled. Get-VM still exists in that state, but every later call against a guest fails with a
    # confusing error, so a stopped vmms is treated here as "not supported" with one clear reason.
    $vmms = Get-Service -Name 'vmms' -ErrorAction SilentlyContinue
    $result.ServiceRunning = ($null -ne $vmms -and $vmms.Status -eq 'Running')

    if (-not $result.RoleInstalled) {
        $result.Reason = 'the Hyper-V role is not installed on this rescue VM'
    }
    elseif (-not $result.ModuleAvailable) {
        $result.Reason = 'the Hyper-V role is installed but its PowerShell module is missing, so Get-VM is unavailable'
    }
    elseif (-not $result.ServiceRunning) {
        $result.Reason = 'the Hyper-V role is installed but its Virtual Machine Management service (vmms) is not running, so no nested guest can be managed'
    }
    else {
        $result.Supported = $true
    }

    return $result
}

function Get-NestedRepairVm {
    <#
    .SYNOPSIS
        Resolves exactly one nested Hyper-V guest on this rescue VM.

    .DESCRIPTION
        Prefers the guest that 'az vm repair create --enable-nested' creates, which is named
        'ProblemVM'. When that name is absent and exactly one guest exists, that guest is used and
        the substitution is logged. When several guests exist and none carries the expected name,
        no guess is made: picking one at random is how a repair ends up applied to the wrong disk.

    .PARAMETER Name
        Look for this guest instead of the default 'ProblemVM'.

    .OUTPUTS
        PSCustomObject with Vm, Found, Name, State, Generation and Reason. Vm is $null unless
        exactly one guest was resolved.
    #>
    param(
        [Parameter(Mandatory = $false)][string]$Name = $script:NestedRepairVmDefaultName
    )

    $result = [PSCustomObject]@{
        Vm         = $null
        Found      = $false
        Name       = $null
        State      = $null
        Generation = $null
        Reason     = $null
    }

    $support = Test-NestedRepairVmSupported
    if (-not $support.Supported) {
        $result.Reason = $support.Reason
        return $result
    }

    try {
        $all = @(Get-VM -ErrorAction Stop)
    }
    catch {
        $result.Reason = "the Hyper-V guests could not be enumerated: $($_.Exception.Message)"
        return $result
    }

    if ($all.Count -eq 0) {
        $result.Reason = 'the Hyper-V role is installed but no nested guest exists. Create the rescue VM with "az vm repair create --enable-nested" so the broken disk is attached to a guest'
        return $result
    }

    $match = @($all | Where-Object { $_.Name -eq $Name })

    if ($match.Count -eq 1) {
        $vm = $match[0]
    }
    elseif ($match.Count -gt 1) {
        $result.Reason = "more than one Hyper-V guest is named '$Name', so the correct one cannot be identified"
        return $result
    }
    elseif ($all.Count -eq 1) {
        $vm = $all[0]
        Add-OfflineRepairLog -Level Info -Message "No guest named '$Name' was found, but exactly one nested guest exists, so '$($vm.Name)' is being used."
    }
    else {
        $names = ($all | ForEach-Object { $_.Name }) -join ', '
        $result.Reason = "no guest is named '$Name' and $($all.Count) guests exist ($names), so the correct one cannot be identified. Pass -Name to choose"
        return $result
    }

    $result.Vm = $vm
    $result.Found = $true
    $result.Name = $vm.Name
    $result.State = "$($vm.State)"

    try { $result.Generation = [int]$vm.Generation } catch { $result.Generation = $null }

    return $result
}

function Connect-NestedRepairVmDisk {
    <#
    .SYNOPSIS
        Makes sure the guest actually has the disk before it is asked to boot from it.

    .DESCRIPTION
        This exists because of a defect in win-enable-nested-hyperv, which is what
        'az vm repair create --enable-nested' runs to build the guest. That script selects the
        passthrough disk with:

            get-disk | where {$_.FriendlyName -eq 'Msft Virtual Disk'}

        Every disk on an Azure VM answers to that name, including the rescue VM's own boot disk,
        so the pipeline that follows tries to take the boot disk offline. That fails, the script is
        running with -ErrorAction Stop, and it aborts before it ever reaches Add-VMHardDiskDrive.
        The guest is left created but empty, with a boot order containing only a network adapter.

        A guest in that state starts happily and then sits in its firmware finding nothing to boot,
        which looks exactly like a slow boot until the wait times out. Attaching the disk here turns
        a silent ten minute failure into a working repair.

        The disk has to be offline on the host before it can be attached, so this runs after the
        caller has taken it offline.

        For a Generation 2 guest the boot order is then pointed at that disk. If it cannot be, whether
        the firmware exposes no drive or the promotion does not take, this reports a Reason and stops
        rather than only warning, because such a guest PXE boots and never loads Windows, which the
        caller would otherwise discover only when its heartbeat wait times out.

        Being asked to attach no disk at all is treated as a failure, not a no-op. A caller that reaches
        here with an empty set has lost track of the disks it meant to repair, and silently succeeding
        would let the guest start with nothing attached.

    .PARAMETER Vm
        The guest to attach to, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER DiskNumber
        Host disk numbers that the guest must be able to boot from.

    .OUTPUTS
        PSCustomObject with Attached, AlreadyAttached, BootOrderSet and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Vm,
        [Parameter(Mandatory = $false)][int[]]$DiskNumber = @()
    )

    $result = [PSCustomObject]@{
        Attached        = @()
        AlreadyAttached = @()
        BootOrderSet    = $false
        Reason          = $null
    }

    if ($null -eq $Vm) {
        $result.Reason = 'no nested guest was supplied'
        return $result
    }

    if ($DiskNumber.Count -eq 0) {
        # Attaching nothing is never legitimate: a caller that reaches here has lost track of the disks it
        # meant to repair. Report it rather than returning a silent success, which would let the guest
        # start with no disk and boot to firmware until the caller's heartbeat wait times out.
        $result.Reason = 'no disk was supplied to attach to the nested guest'
        return $result
    }

    $generation = 1
    try { $generation = [int]$Vm.Generation } catch { $generation = 1 }

    try {
        # Address the guest by object, not by a name Get-VMHardDiskDrive would treat as a wildcard.
        $existing = @(Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop)
    }
    catch {
        $result.Reason = "the disks attached to '$($Vm.Name)' could not be read: $($_.Exception.Message)"
        return $result
    }

    $present = @($existing | ForEach-Object { $_.DiskNumber } | Where-Object { $null -ne $_ })

    foreach ($number in ($DiskNumber | Sort-Object -Unique)) {
        if ($present -contains $number) {
            $result.AlreadyAttached += $number
            continue
        }

        try {
            if ($generation -ge 2) {
                Add-VMHardDiskDrive -VM $Vm -DiskNumber $number -ControllerType SCSI -ControllerNumber 0 -ErrorAction Stop
            }
            else {
                Add-VMHardDiskDrive -VM $Vm -DiskNumber $number -ErrorAction Stop
            }
        }
        catch {
            $result.Reason = "disk $number could not be attached to '$($Vm.Name)': $($_.Exception.Message)"
            return $result
        }

        # Read it back. An attach that silently did nothing produces a guest that boots to its
        # firmware and waits, which is the failure this function exists to prevent.
        $now = @(Get-VMHardDiskDrive -VM $Vm -ErrorAction SilentlyContinue | ForEach-Object { $_.DiskNumber })
        if ($now -notcontains $number) {
            $result.Reason = "disk $number does not appear on '$($Vm.Name)' after being attached"
            return $result
        }

        Add-OfflineRepairLog -Level Info -Message "Disk $number attached to nested guest '$($Vm.Name)'."
        $result.Attached += $number
    }

    # A Generation 2 guest boots in UEFI order. The guest created by the library ships with a
    # network adapter first, so a drive has to be promoted or the guest will try to PXE boot.
    if ($generation -ge 2) {
        # A Generation 2 guest boots in UEFI order. The guest created by the library ships with a
        # network adapter first, so a drive has to be promoted or the guest will PXE boot and find
        # nothing, which looks like a slow boot until the caller's heartbeat wait times out ~10 minutes
        # later. If the boot order cannot be pointed at the disk, that is a failure, not a warning:
        # report it now so the caller does not wait out that timeout on a guest that can never boot.
        try {
            $drives = @((Get-VMFirmware -VM $Vm -ErrorAction Stop).BootOrder |
                    Where-Object { $_.BootType -eq 'Drive' })

            if ($drives.Count -eq 0) {
                $result.Reason = "nested guest '$($Vm.Name)' has no disk in its boot order, so it would PXE boot and never load Windows"
                return $result
            }

            Set-VMFirmware -VM $Vm -FirstBootDevice $drives[0] -ErrorAction Stop

            $first = @((Get-VMFirmware -VM $Vm -ErrorAction SilentlyContinue).BootOrder)[0]
            $result.BootOrderSet = ($null -ne $first -and $first.BootType -eq 'Drive')

            if (-not $result.BootOrderSet) {
                $result.Reason = "nested guest '$($Vm.Name)' still lists a non-disk device first in its boot order, so it would PXE boot and never load Windows"
                return $result
            }

            Add-OfflineRepairLog -Level Info -Message "Nested guest '$($Vm.Name)' set to boot from its disk rather than the network."
        }
        catch {
            $result.Reason = "the boot order of nested guest '$($Vm.Name)' could not be set, so it cannot be made to boot from its disk: $($_.Exception.Message)"
            return $result
        }
    }

    return $result
}

function Set-NestedRepairVmManaged {
    <#
    .SYNOPSIS
        Protects an explicitly selected guest from automatic discovery shutdown.

    .DESCRIPTION
        Appends the shared ownership tag to Notes, preserving existing text, and verifies the
        stored value by Id. An already tagged guest produces no write. This marker is persistent;
        the caller must use the explicit graceful-stop helper for later disk hand-offs.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][ValidateNotNull()]$Vm)

    $lease = Enter-OfflineNestedVmLifecycle
    try {
        $current = Get-VM -Id $Vm.Id -ErrorAction Stop
        if (-not $current) { throw "Nested guest '$($Vm.Id)' could not be resolved before recording repair ownership." }
        if (Test-OfflineNestedVmManaged -Vm $current) { return $true }
        if (-not $PSCmdlet.ShouldProcess($current.Name, 'Record repair ownership in the guest Notes')) { return $false }

        $notesProperty = $current.PSObject.Properties['Notes']
        $notes = if ($notesProperty) { [string]$notesProperty.Value } else { '' }
        $separator = if ([string]::IsNullOrEmpty($notes) -or $notes.EndsWith("`n")) { '' } else { [Environment]::NewLine }
        $updatedNotes = $notes + $separator + (Get-OfflineNestedVmOwnershipTag)
        Set-VM -VM $current -Notes $updatedNotes -ErrorAction Stop
        $after = Get-VM -Id $current.Id -ErrorAction Stop
        if (-not $after -or -not (Test-OfflineNestedVmManaged -Vm $after)) {
            throw "Repair ownership of nested guest '$($current.Name)' could not be confirmed; the guest must not be started."
        }
        Add-OfflineRepairLog -Level Info -Message "Nested guest '$($current.Name)' is marked as helper-managed; automatic discovery will not interrupt it."
        return $true
    }
    finally {
        Exit-OfflineNestedVmLifecycle -Lease $lease
    }
}

function Start-NestedRepairVm {
    <#
    .SYNOPSIS
        Releases the disk from the host and starts the nested guest.

    .DESCRIPTION
        A passthrough disk can only be claimed by one side at a time. The guest refuses to start
        while the host still holds the disk online, so the disk is taken offline first.

        Only the disks the caller names are touched. The rescue VM's own system disk is never a
        candidate, because it is not offline-able and is not what the guest boots from.

        Already running is treated as success only when the guest genuinely has the requested disk
        attached. A guest that is up but was never given the disk is reported as a failure, because
        "running" would otherwise be mistaken for "attached and repairing the right disk".
        Before success or a new start, ownership is recorded in Notes so a later discovery pass
        cannot power the guest off. Failure to record ownership refuses the start.

        If the guest does not end up running, every disk this call took offline is brought back online
        before returning, so a failed start leaves the rescue VM no worse than it was found. Disks that
        were already offline at entry are left alone. If none of the requested disks could be taken
        offline, whether unreadable or because they are the rescue VM's own system disk, the guest is
        never started, because a guest with no disk boots to firmware and only burns the caller's
        heartbeat timeout; the returned Reason names which disks were skipped and why. On a host too
        small for the guest's configured startup memory, that memory is fitted to the host's free memory
        with dynamic memory enabled, and a memory-related start failure is retried the same way before
        it is reported as one.

    .PARAMETER Vm
        The guest to start, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER DiskNumber
        Disk numbers to take offline before starting. Usually the DiskNumber of the offline
        Windows install being repaired.

    .OUTPUTS
        PSCustomObject with Started, AlreadyRunning, State, DisksOffline, DisksAttached and Reason.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Vm,
        [Parameter(Mandatory = $false)][int[]]$DiskNumber = @()
    )

    $result = [PSCustomObject]@{
        Started        = $false
        AlreadyRunning = $false
        State          = $null
        DisksOffline   = @()
        DisksAttached  = @()
        Reason         = $null
    }

    if ($null -eq $Vm) {
        $result.Reason = 'no nested guest was supplied'
        return $result
    }

    $lease = Enter-OfflineNestedVmLifecycle
    try {
        # Resolve the guest by its Id, not its name. Get-VM -Name treats its argument as a wildcard, so a
        # name containing [ ] * or ? would match the wrong guest, or several. The Id is a GUID and exact.
        $current = Get-VM -Id $Vm.Id -ErrorAction SilentlyContinue
        if ($null -eq $current) {
            $result.Reason = "the nested guest '$($Vm.Name)' no longer exists"
            return $result
        }

        if ($current.State -eq 'Running') {
            $result.AlreadyRunning = $true
            $result.State = "$($current.State)"

            # Running is not the same as attached. If the guest is already up but the requested disk was
            # never handed to it, reporting success would tell the caller a disk is present that is not.
            $requested = @($DiskNumber | Sort-Object -Unique)
            if ($requested.Count -gt 0) {
                try {
                    $attachedNow = @(Get-VMHardDiskDrive -VM $current -ErrorAction Stop |
                            ForEach-Object { $_.DiskNumber } | Where-Object { $null -ne $_ })
                }
                catch {
                    $result.Reason = "the nested guest '$($current.Name)' is already running but the disks attached to it could not be read: $($_.Exception.Message)"
                    return $result
                }

                $missing = @($requested | Where-Object { $attachedNow -notcontains $_ })
                if ($missing.Count -gt 0) {
                    $result.Reason = "the nested guest '$($current.Name)' is already running but does not have disk(s) $($missing -join ', ') attached, so it is not running on the disk this repair targets. Stop it and start it again so the disk is attached"
                    return $result
                }
            }

            try {
                if (-not (Set-NestedRepairVmManaged -Vm $current)) {
                    $result.Reason = 'the running guest was not adopted because recording repair ownership was declined'
                    return $result
                }
            }
            catch {
                $result.Reason = "the running guest could not be protected from automatic discovery: $($_.Exception.Message)"
                Add-OfflineRepairLog -Level Error -Message $result.Reason
                return $result
            }
            $result.Started = $true
            Add-OfflineRepairLog -Level Info -Message "Nested guest '$($current.Name)' is already running with the requested disk(s) attached."
            return $result
        }

        # Everything from here takes disks offline on the host, so this is where -WhatIf has to stop.
        # It returns the same shape every other exit path returns, with Started left $false, so a preview
        # run can never be mistaken by the caller for a guest that is actually up on the repaired disk.
        $requestedDisks = @($DiskNumber | Sort-Object -Unique)
        $whatIfTarget = if ($requestedDisks.Count -gt 0) {
            "nested guest '$($current.Name)' with host disk(s) $($requestedDisks -join ', ')"
        }
        else {
            "nested guest '$($current.Name)'"
        }
        if (-not $PSCmdlet.ShouldProcess($whatIfTarget, 'Take the disk(s) offline on the host, attach them and start the guest')) {
            $result.State = "$($current.State)"
            $result.Reason = 'the guest was not started because -WhatIf was specified'
            return $result
        }

        # Everything from here takes disks offline on the host. If the guest does not end up running, the
        # finally hands those disks back, so a failed start never leaves the rescue VM without volumes it
        # had at entry. Only disks THIS call took offline are restored: disks already offline at entry were
        # offline for a reason this function does not own, and disks the guest is now running on stay with
        # the guest.
        $offlined = @()      # every requested disk that is now offline, so the guest can claim and boot it
        $weOfflined = @()    # only the disks this call took offline; these are the ones the finally restores
        $skipped = @()       # why each requested disk never reached offline, so an all-skipped run can say so
        try {
            foreach ($number in ($DiskNumber | Sort-Object -Unique)) {
                try {
                    $disk = Get-Disk -Number $number -ErrorAction Stop
                }
                catch {
                    $skipped += "disk $number could not be read"
                    Add-OfflineRepairLog -Level Warning -Message "Disk $number could not be read, so it was not taken offline: $($_.Exception.Message)"
                    continue
                }

                if ($disk.IsBoot -or $disk.IsSystem) {
                    $skipped += "disk $number is the rescue VM's own system disk"
                    Add-OfflineRepairLog -Level Warning -Message "Disk $number is the rescue VM's own system disk and was left online."
                    continue
                }

                if ($disk.IsOffline) {
                    # Already offline at entry: usable by the guest, but not ours to bring back afterwards.
                    $offlined += $number
                    continue
                }

                try {
                    Set-Disk -Number $number -IsOffline $true -ErrorAction Stop
                }
                catch {
                    $result.Reason = "disk $number could not be taken offline, so the guest cannot claim it: $($_.Exception.Message)"
                    return $result
                }

                # Read it back. A disk that is still online here means the guest will fail to start for a
                # reason that would otherwise be reported as an unrelated Hyper-V error.
                $after = Get-Disk -Number $number -ErrorAction SilentlyContinue
                if ($null -eq $after -or -not $after.IsOffline) {
                    $result.Reason = "disk $number still reports as online after being taken offline, so the guest cannot claim it"
                    return $result
                }

                Add-OfflineRepairLog -Level Info -Message "Disk $number taken offline so the nested guest can claim it."
                $offlined += $number
                $weOfflined += $number
            }
            $result.DisksOffline = $offlined

            # If nothing reached the offline state there is no disk for the guest to boot, and a Hyper-V VM
            # starts perfectly well with no disk attached. Going on would set Started = $true for a guest that
            # cannot run the repair and leave the caller waiting out its full heartbeat timeout. Stop here, and
            # say whether each disk was unreadable or was the rescue VM's own, so the reason is actionable on
            # its own without having to read the log.
            if ($offlined.Count -eq 0) {
                $detail = if ($skipped.Count -gt 0) { $skipped -join '; ' } else { 'no disks were requested' }
                $result.Reason = "no disk could be taken offline for the nested guest, so it has nothing to boot: $detail"
                Add-OfflineRepairLog -Level Error -Message $result.Reason
                return $result
            }

            # The disk has to be attached before the guest is started, and it has to be offline before it
            # can be attached, so this sits between the two. Attach the disks that are actually offline now,
            # not the raw request, which may include a disk that could not be offlined. See
            # Connect-NestedRepairVmDisk for why the guest may otherwise arrive with no disk at all.
            $attach = Connect-NestedRepairVmDisk -Vm $current -DiskNumber $offlined
            if ($attach.Reason) {
                $result.Reason = $attach.Reason
                return $result
            }
            $result.DisksAttached = $attach.Attached

            try {
                if (-not (Set-NestedRepairVmManaged -Vm $current)) {
                    $result.Reason = 'the guest was not started because recording repair ownership was declined'
                    return $result
                }
            }
            catch {
                $result.Reason = "the guest could not be protected from automatic discovery and was not started: $($_.Exception.Message)"
                Add-OfflineRepairLog -Level Error -Message $result.Reason
                return $result
            }

            # A rescue VM is often small. Work out a startup-memory size that fits its free physical memory,
            # so the guest can boot even when it was configured for more than the host can spare.
            $startBytes = 0
            try { $startBytes = [int64]$current.MemoryStartup } catch { $startBytes = 0 }

            $freeBytes = 0
            try { $freeBytes = [int64]((Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).FreePhysicalMemory) * 1024 }
            catch { $freeBytes = 0 }

            $memoryFloor = 512MB    # Windows will not boot in less; also the dynamic-memory minimum used here.
            $hostHeadroom = 512MB   # Leave the host room; Hyper-V cannot hand a guest every free byte.

            $fitStartup = 0
            if ($startBytes -gt $memoryFloor) {
                if ($freeBytes -gt 0) { $fitStartup = [int64]($freeBytes - $hostHeadroom) }
                else { $fitStartup = [int64]1GB }   # free memory unreadable: a size the guest can grow from
                if ($fitStartup -gt $startBytes) { $fitStartup = $startBytes }
                if ($fitStartup -lt $memoryFloor) { $fitStartup = $memoryFloor }
                $fitStartup = [int64]([math]::Floor($fitStartup / 2MB) * 2MB)   # dynamic memory aligns to 2 MB
            }

            $startupFits = ($freeBytes -le 0) -or ($startBytes -le ($freeBytes - $hostHeadroom))

            $memoryReduced = $false
            if (-not $startupFits -and $fitStartup -gt 0 -and $fitStartup -lt $startBytes) {
                # The configured startup size will not fit free memory. Shrink it and let dynamic memory grow
                # it back if the host frees up, rather than failing before Windows even loads.
                try {
                    Set-VMMemory -VM $current -DynamicMemoryEnabled $true -MinimumBytes $memoryFloor -StartupBytes $fitStartup -MaximumBytes $startBytes -ErrorAction Stop
                    $memoryReduced = $true
                    Add-OfflineRepairLog -Level Warning -Message "Nested guest '$($current.Name)' asks for $([math]::Round($startBytes / 1GB, 2)) GB at start but only about $([math]::Round($freeBytes / 1GB, 2)) GB is free, so its startup memory was reduced to $([math]::Round($fitStartup / 1GB, 2)) GB with dynamic memory enabled."
                }
                catch {
                    Add-OfflineRepairLog -Level Warning -Message "The startup memory of '$($current.Name)' could not be reduced before starting: $($_.Exception.Message)"
                }
            }

            try {
                Start-VM -VM $current -ErrorAction Stop | Out-Null
            }
            catch {
                $startError = $_.Exception.Message

                if ($startError -notmatch 'memory') {
                    $result.Reason = "the nested guest '$($current.Name)' failed to start: $startError"
                    return $result
                }

                # The start failed for a memory reason. If a smaller footprint has not been applied yet, apply
                # it now and retry once; otherwise report the real reason, not a generic start failure.
                if ($memoryReduced -or $fitStartup -le 0 -or $fitStartup -ge $startBytes) {
                    $result.Reason = "the nested guest '$($current.Name)' could not start because the rescue VM does not have enough free memory for it: $startError"
                    return $result
                }

                try {
                    Set-VMMemory -VM $current -DynamicMemoryEnabled $true -MinimumBytes $memoryFloor -StartupBytes $fitStartup -MaximumBytes $startBytes -ErrorAction Stop
                    $memoryReduced = $true
                    Add-OfflineRepairLog -Level Warning -Message "Nested guest '$($current.Name)' could not start with its configured memory, so it was reduced to $([math]::Round($fitStartup / 1GB, 2)) GB with dynamic memory enabled and retried."
                    Start-VM -VM $current -ErrorAction Stop | Out-Null
                }
                catch {
                    $result.Reason = "the nested guest '$($current.Name)' could not start even after its memory was reduced to fit the rescue VM: $($_.Exception.Message)"
                    return $result
                }
            }

            $state = (Get-VM -Id $current.Id -ErrorAction SilentlyContinue).State
            $result.State = "$state"
            $result.Started = ($state -eq 'Running')

            if ($result.Started) {
                Add-OfflineRepairLog -Level Info -Message "Nested guest '$($current.Name)' started."
            }
            else {
                $result.Reason = "the nested guest '$($current.Name)' was asked to start but reports state '$state'"
            }
        }
        finally {
            # Restore only the disks this call took offline, and only when the guest is not running on them.
            # A guest that started owns its disks; disks already offline at entry are left as they were found.
            if (-not $result.Started) {
                foreach ($number in $weOfflined) {
                    try {
                        Set-Disk -Number $number -IsOffline $false -ErrorAction Stop
                        Add-OfflineRepairLog -Level Info -Message "Disk $number was returned online after the nested guest did not start, so the rescue VM keeps the access it had at entry."
                    }
                    catch {
                        Add-OfflineRepairLog -Level Warning -Message "Disk $number could not be returned online after the nested guest did not start: $($_.Exception.Message)"
                    }
                }
            }
        }

        return $result
    }
    finally {
        Exit-OfflineNestedVmLifecycle -Lease $lease
    }
}

function Wait-NestedRepairVmBoot {
    <#
    .SYNOPSIS
        Waits for a nested guest to boot far enough to report a heartbeat.

    .DESCRIPTION
        A repair that only takes effect inside the running guest cannot be confirmed by starting
        the VM, because Start-VM returns as soon as the VM is powered on and says nothing about
        whether Windows loaded. The Integration Services heartbeat is the first signal the host
        can see that the guest OS is actually running.

        A timeout is reported as a timeout. It is never converted into success, and it is not
        treated as proof of failure either: a guest can be running with the heartbeat service
        disabled, so the caller must still verify the repair itself.

        The wait ends early when the guest reaches a state it cannot boot out of on its own (Off,
        Paused, Saved or PausedCritical) rather than waiting out the full timeout. PausedCritical in
        particular means the host is out of memory or disk for the guest and it will never progress.

    .PARAMETER Vm
        The guest to wait for, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER TimeoutSeconds
        How long to wait for the first heartbeat. Defaults to 600, which covers a cold boot of a
        Windows Server guest on a two-processor rescue VM.

    .PARAMETER PollSeconds
        How often to re-check. Defaults to 10.

    .OUTPUTS
        PSCustomObject with Booted, Heartbeat, State, WaitedSeconds and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Vm,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 600,
        [Parameter(Mandatory = $false)][int]$PollSeconds = 10
    )

    $result = [PSCustomObject]@{
        Booted        = $false
        Heartbeat     = $null
        State         = $null
        WaitedSeconds = 0
        Reason        = $null
    }

    if ($null -eq $Vm) {
        $result.Reason = 'no nested guest was supplied'
        return $result
    }

    if ($PollSeconds -lt 1) { $PollSeconds = 1 }

    Add-OfflineRepairLog -Level Info -Message "Waiting up to $TimeoutSeconds seconds for nested guest '$($Vm.Name)' to report a heartbeat."

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $started = Get-Date

    while ((Get-Date) -lt $deadline) {
        # Resolve by Id, not by a name Get-VM would treat as a wildcard.
        $current = Get-VM -Id $Vm.Id -ErrorAction SilentlyContinue

        if ($null -eq $current) {
            $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
            $result.Reason = "the nested guest '$($Vm.Name)' disappeared while waiting for it to boot"
            return $result
        }

        $result.State = "$($current.State)"
        $heartbeat = "$($current.Heartbeat)"
        $result.Heartbeat = $heartbeat

        # Off, Paused, Saved and PausedCritical are all terminal for a boot: the guest will not reach a
        # heartbeat on its own from any of them. PausedCritical in particular means the host has run out
        # of memory or disk for the guest, so waiting out the full timeout would only delay an honest
        # failure with a misleading "no heartbeat" reason.
        if ($result.State -in @('Off', 'Paused', 'Saved', 'PausedCritical')) {
            $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
            $result.Reason = "the nested guest '$($Vm.Name)' stopped making progress in state '$($result.State)' after $($result.WaitedSeconds) seconds, so it will not report a heartbeat"
            return $result
        }

        # OkApplicationsUnknown is the normal reading for a Server guest that has booted but has no
        # application reporting through Integration Services. It still proves the OS is running.
        if ($heartbeat -like 'Ok*') {
            $result.Booted = $true
            $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
            Add-OfflineRepairLog -Level Info -Message "Nested guest '$($Vm.Name)' reported heartbeat '$heartbeat' after $($result.WaitedSeconds) seconds."
            return $result
        }

        Start-Sleep -Seconds $PollSeconds
    }

    $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
    $result.Reason = "no heartbeat after $($result.WaitedSeconds) seconds. The guest may still be booting, or Integration Services may be disabled in it, so the repair must be verified directly rather than assumed"
    Add-OfflineRepairLog -Level Warning -Message $result.Reason

    return $result
}

function Stop-NestedRepairVmGraceful {
    <#
    .SYNOPSIS
        Asks a nested guest to shut down cleanly, and only pulls the power if it will not.

    .DESCRIPTION
        Turning a Windows guest off at the power button leaves its hives and file system dirty, and
        discards anything the guest had written but not yet flushed. Here the guest has just created
        a local account, so that write matters: it is the whole point of the run. Asking the guest to
        shut down instead lets Windows commit it and close the hives cleanly, which also spares the
        disk a chkdsk on the next boot.

        One value is deliberately not covered by this. While Windows is in setup mode it owns
        SYSTEM\Setup\SetupType and rewrites it until its setup pass finishes, which cannot happen in
        a guest that is stopped on purpose part way through. That value is therefore finalised from
        the rescue VM after the disk comes back, not here.

        The power is only pulled if the guest does not stop in time, and that case is reported as a
        non-graceful stop so the caller knows what is on the disk cannot be trusted and has to be
        re-checked.

        If the shutdown request itself cannot be issued, that real reason is returned as-is rather
        than being replaced by the generic power-off message, so the true cause is not lost.

    .PARAMETER Vm
        The guest to stop, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER TimeoutSeconds
        How long to wait for the guest to stop on its own before pulling the power. Defaults to 180.

    .PARAMETER PollSeconds
        How often to re-check. Defaults to 5.

    .OUTPUTS
        An object with Stopped, Graceful, WaitedSeconds, State and Reason.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Vm,
        [int]$TimeoutSeconds = 180,
        [int]$PollSeconds = 5
    )

    $result = [PSCustomObject]@{
        Stopped       = $false
        Graceful      = $false
        WaitedSeconds = 0
        State         = $null
        Reason        = $null
    }

    if (-not $Vm) {
        $result.Reason = 'no nested guest was supplied, so there was nothing to stop'
        return $result
    }

    $lease = Enter-OfflineNestedVmLifecycle
    try {
        $name = $Vm.Name
        # Resolve and act on the guest by its Id. Get-VM (and Stop-VM -Name) treat the name as a wildcard,
        # so a name containing [ ] * or ? could match the wrong guest, or several.
        $id = $Vm.Id

        $current = Get-VM -Id $id -ErrorAction SilentlyContinue
        if (-not $current) {
            $result.Reason = "the nested guest '$name' no longer exists"
            return $result
        }

        if ($current.State -eq 'Off') {
            # Deliberately not reported as graceful. Reaching here means the guest powered off on its
            # own before it was asked to, and there is no way from the host to tell an orderly shutdown
            # apart from a crash, so the caller is told to re-check the disk rather than trust it.
            $result.Stopped = $true
            $result.State = 'Off'
            $result.Reason = "the nested guest '$name' was already off, so it is not known whether it shut down cleanly"
            Add-OfflineRepairLog -Level Info -Message $result.Reason
            return $result
        }

        # The shutdown request is the first thing that changes state, so -WhatIf stops here. Stopped stays
        # $false, which is what the caller already treats as "the guest is still running".
        if (-not $PSCmdlet.ShouldProcess("nested guest '$name'", 'Request a clean shutdown, turning it off only if it does not comply')) {
            $result.State = [string]$current.State
            $result.Reason = 'the guest was not stopped because -WhatIf was specified'
            return $result
        }

        Add-OfflineRepairLog -Level Info -Message "Asking the nested guest '$name' to shut down cleanly so anything it wrote to the registry is flushed to its disk."

        try {
            Stop-VM -VM $current -Force -AsJob -ErrorAction Stop | Out-Null
        }
        catch {
            # Return here. Falling through to the wait loop and the power-off path would overwrite this with
            # the generic "had to be turned off" reason and lose the real cause of the failed request.
            $result.State = [string]$current.State
            $result.Reason = "the shutdown request to '$name' failed: $($_.Exception.Message)"
            Add-OfflineRepairLog -Level Warning -Message $result.Reason
            return $result
        }

        $started = Get-Date
        while (((Get-Date) - $started).TotalSeconds -lt $TimeoutSeconds) {
            $current = Get-VM -Id $id -ErrorAction SilentlyContinue

            if (-not $current) {
                $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
                $result.Reason = "the nested guest '$name' disappeared while it was shutting down"
                Add-OfflineRepairLog -Level Warning -Message $result.Reason
                return $result
            }

            if ($current.State -eq 'Off') {
                $result.Stopped = $true
                $result.Graceful = $true
                $result.State = 'Off'
                $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
                Add-OfflineRepairLog -Level Info -Message "The nested guest '$name' shut down cleanly after $($result.WaitedSeconds) seconds."
                return $result
            }

            Start-Sleep -Seconds $PollSeconds
        }

        $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
        Add-OfflineRepairLog -Level Warning -Message "The nested guest '$name' did not shut down within $($result.WaitedSeconds) seconds, so its power is being turned off. Anything it wrote to the registry and that Windows had not flushed yet is lost, so the disk has to be re-checked rather than trusted."

        try {
            Stop-VM -VM $current -TurnOff -Force -ErrorAction Stop
            Start-Sleep -Seconds 3
            $current = Get-VM -Id $id -ErrorAction Stop
        }
        catch {
            $result.State = [string]$current.State
            $result.Reason = "the nested guest '$name' could not be confirmed stopped after the shutdown timeout: $($_.Exception.Message)"
            Add-OfflineRepairLog -Level Error -Message $result.Reason
            return $result
        }

        $result.State = if ($current) { [string]$current.State } else { $null }
        $result.Stopped = ($null -ne $current -and $current.State -eq 'Off')
        $result.Graceful = $false
        if ($result.Stopped) {
            $result.Reason = "the nested guest '$name' had to be turned off at the power button after $($result.WaitedSeconds) seconds"
        }
        else {
            $result.Reason = "the nested guest '$name' could not be confirmed Off after a forced shutdown; its disk must not be taken back"
            Add-OfflineRepairLog -Level Error -Message $result.Reason
        }

        return $result
    }
    finally {
        Exit-OfflineNestedVmLifecycle -Lease $lease
    }
}
