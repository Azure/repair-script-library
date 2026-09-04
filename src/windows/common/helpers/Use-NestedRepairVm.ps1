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
      Test-NestedRepairVmSupported   Is the Hyper-V role and its PowerShell module usable here.
      Get-NestedRepairVm             Resolve exactly one nested guest, or explain why it cannot.
      Start-NestedRepairVm           Take the disk offline on the host and start the guest.
      Wait-NestedRepairVmBoot        Block until the guest reports a heartbeat, or time out.

    The reverse direction already exists and is not duplicated here:
      Stop-NestedRepairVm            (Get-OfflineWindowsDisk.ps1) stop the guest holding the disk.
      Set-OfflineDisksOnline         (Get-OfflineWindowsDisk.ps1) bring the disk back to the host.

    A scenario script that needs the guest to run therefore follows this cycle:

      Stop-NestedRepairVm            # guest releases the disk
      Set-OfflineDisksOnline         # host takes the disk
      ... edit the offline disk ...
      Start-NestedRepairVm           # host releases the disk, guest boots and applies the change
      Wait-NestedRepairVmBoot        # observe that it really booted
      Stop-NestedRepairVm            # guest releases the disk again
      Set-OfflineDisksOnline         # host takes it back to verify the result

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
#>

# The name 'az vm repair create --enable-nested' gives the guest it builds.
$script:NestedRepairVmDefaultName = 'ProblemVM'

function Test-NestedRepairVmSupported {
    <#
    .SYNOPSIS
        Reports whether this machine can drive a nested Hyper-V guest.

    .DESCRIPTION
        Checks the two things a caller actually depends on: the Hyper-V role being installed, and
        the Hyper-V PowerShell module being present so Get-VM exists. They are separate features
        and either can be missing on its own.

    .OUTPUTS
        PSCustomObject with Supported, RoleInstalled, ModuleAvailable and Reason.
    #>
    $result = [PSCustomObject]@{
        Supported       = $false
        RoleInstalled   = $false
        ModuleAvailable = $false
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

    if (-not $result.RoleInstalled) {
        $result.Reason = 'the Hyper-V role is not installed on this rescue VM'
    }
    elseif (-not $result.ModuleAvailable) {
        $result.Reason = 'the Hyper-V role is installed but its PowerShell module is missing, so Get-VM is unavailable'
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

    if ($DiskNumber.Count -eq 0) { return $result }

    $generation = 1
    try { $generation = [int]$Vm.Generation } catch { $generation = 1 }

    try {
        $existing = @(Get-VMHardDiskDrive -VMName $Vm.Name -ErrorAction Stop)
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
                Add-VMHardDiskDrive -VMName $Vm.Name -DiskNumber $number -ControllerType SCSI -ControllerNumber 0 -ErrorAction Stop
            }
            else {
                Add-VMHardDiskDrive -VMName $Vm.Name -DiskNumber $number -ErrorAction Stop
            }
        }
        catch {
            $result.Reason = "disk $number could not be attached to '$($Vm.Name)': $($_.Exception.Message)"
            return $result
        }

        # Read it back. An attach that silently did nothing produces a guest that boots to its
        # firmware and waits, which is the failure this function exists to prevent.
        $now = @(Get-VMHardDiskDrive -VMName $Vm.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.DiskNumber })
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
        try {
            $drives = @((Get-VMFirmware -VMName $Vm.Name -ErrorAction Stop).BootOrder |
                    Where-Object { $_.BootType -eq 'Drive' })

            if ($drives.Count -gt 0) {
                Set-VMFirmware -VMName $Vm.Name -FirstBootDevice $drives[0] -ErrorAction Stop

                $first = @((Get-VMFirmware -VMName $Vm.Name -ErrorAction SilentlyContinue).BootOrder)[0]
                $result.BootOrderSet = ($null -ne $first -and $first.BootType -eq 'Drive')

                if ($result.BootOrderSet) {
                    Add-OfflineRepairLog -Level Info -Message "Nested guest '$($Vm.Name)' set to boot from its disk rather than the network."
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "Nested guest '$($Vm.Name)' still lists a non-disk device first in its boot order."
                }
            }
            else {
                Add-OfflineRepairLog -Level Warning -Message "Nested guest '$($Vm.Name)' has no drive in its boot order."
            }
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "The boot order of '$($Vm.Name)' could not be set: $($_.Exception.Message)"
        }
    }

    return $result
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

        Already running is treated as success, so a caller can invoke this without first checking
        state, but the return value distinguishes the two so a caller that cares can tell.

    .PARAMETER Vm
        The guest to start, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER DiskNumber
        Disk numbers to take offline before starting. Usually the DiskNumber of the offline
        Windows install being repaired.

    .OUTPUTS
        PSCustomObject with Started, AlreadyRunning, State, DisksOffline, DisksAttached and Reason.
    #>
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

    $current = Get-VM -Name $Vm.Name -ErrorAction SilentlyContinue
    if ($null -eq $current) {
        $result.Reason = "the nested guest '$($Vm.Name)' no longer exists"
        return $result
    }

    if ($current.State -eq 'Running') {
        $result.AlreadyRunning = $true
        $result.Started = $true
        $result.State = "$($current.State)"
        Add-OfflineRepairLog -Level Info -Message "Nested guest '$($Vm.Name)' is already running."
        return $result
    }

    $offlined = @()
    foreach ($number in ($DiskNumber | Sort-Object -Unique)) {
        try {
            $disk = Get-Disk -Number $number -ErrorAction Stop
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Disk $number could not be read, so it was not taken offline: $($_.Exception.Message)"
            continue
        }

        if ($disk.IsBoot -or $disk.IsSystem) {
            Add-OfflineRepairLog -Level Warning -Message "Disk $number is the rescue VM's own system disk and was left online."
            continue
        }

        if ($disk.IsOffline) {
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
    }
    $result.DisksOffline = $offlined

    # The disk has to be attached before the guest is started, and it has to be offline before it
    # can be attached, so this sits between the two. See Connect-NestedRepairVmDisk for why the
    # guest may arrive with no disk at all.
    $attach = Connect-NestedRepairVmDisk -Vm $current -DiskNumber $DiskNumber
    if ($attach.Reason) {
        $result.Reason = $attach.Reason
        return $result
    }
    $result.DisksAttached = $attach.Attached

    try {
        Start-VM -Name $Vm.Name -ErrorAction Stop | Out-Null
    }
    catch {
        $result.Reason = "the nested guest '$($Vm.Name)' failed to start: $($_.Exception.Message)"
        return $result
    }

    $state = (Get-VM -Name $Vm.Name -ErrorAction SilentlyContinue).State
    $result.State = "$state"
    $result.Started = ($state -eq 'Running')

    if ($result.Started) {
        Add-OfflineRepairLog -Level Info -Message "Nested guest '$($Vm.Name)' started."
    }
    else {
        $result.Reason = "the nested guest '$($Vm.Name)' was asked to start but reports state '$state'"
    }

    return $result
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
        $current = Get-VM -Name $Vm.Name -ErrorAction SilentlyContinue

        if ($null -eq $current) {
            $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
            $result.Reason = "the nested guest '$($Vm.Name)' disappeared while waiting for it to boot"
            return $result
        }

        $result.State = "$($current.State)"
        $heartbeat = "$($current.Heartbeat)"
        $result.Heartbeat = $heartbeat

        if ($current.State -eq 'Off') {
            $result.WaitedSeconds = [int]((Get-Date) - $started).TotalSeconds
            $result.Reason = "the nested guest '$($Vm.Name)' powered off while booting, after $($result.WaitedSeconds) seconds"
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

    .PARAMETER Vm
        The guest to stop, as returned in the Vm property of Get-NestedRepairVm.

    .PARAMETER TimeoutSeconds
        How long to wait for the guest to stop on its own before pulling the power. Defaults to 180.

    .PARAMETER PollSeconds
        How often to re-check. Defaults to 5.

    .OUTPUTS
        An object with Stopped, Graceful, WaitedSeconds, State and Reason.
    #>
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

    $name = $Vm.Name

    $current = Get-VM -Name $name -ErrorAction SilentlyContinue
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

    Add-OfflineRepairLog -Level Info -Message "Asking the nested guest '$name' to shut down cleanly so anything it wrote to the registry is flushed to its disk."

    try {
        Stop-VM -Name $name -Force -AsJob -ErrorAction Stop | Out-Null
    }
    catch {
        $result.Reason = "the shutdown request to '$name' failed: $($_.Exception.Message)"
        Add-OfflineRepairLog -Level Warning -Message $result.Reason
    }

    $started = Get-Date
    while (((Get-Date) - $started).TotalSeconds -lt $TimeoutSeconds) {
        $current = Get-VM -Name $name -ErrorAction SilentlyContinue

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

    Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $current = Get-VM -Name $name -ErrorAction SilentlyContinue
    $result.State = if ($current) { [string]$current.State } else { $null }
    $result.Stopped = (-not $current) -or ($current.State -eq 'Off')
    $result.Graceful = $false
    $result.Reason = "the nested guest '$name' had to be turned off at the power button after $($result.WaitedSeconds) seconds"

    return $result
}
