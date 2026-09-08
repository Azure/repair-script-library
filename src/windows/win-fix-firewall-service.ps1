#########################################################################################################
#
# .SYNOPSIS
#   Repairs the Windows Defender Firewall service on an offline disk, so a VM that boots but drops
#   every inbound connection - RDP included - can be reached again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM that looks alive and answers nothing. It boots, the guest agent reports Ready,
#   Remote Desktop Services is running and 3389 is listening - and from another machine on the same
#   virtual network every port is a timeout, ICMP included. The listener is fine. Nothing reaches it,
#   because the Windows Defender Firewall service is not running and the boot-time filters that
#   Windows installs before it starts are still in force, blocking everything.
#
#   Two causes are repaired, both read from the offline SYSTEM hive.
#
#   1. A loopback exemption value mpssvc cannot read.
#
#      CheckNetIsolation LoopbackExempt records app container SIDs in a value called
#      DebugedLoopbackApps, under Services\mpssvc\Parameters\AppCs, and mpssvc reads that value on
#      its start path. If it cannot read it, mpssvc terminates - then the Service Control Manager
#      restarts it, it reads the same value, and it terminates again. Thousands of cycles were
#      measured in the minutes after boot (246 to 5,611, depending on the shape of the fault),
#      the service stuck at StartPending, and Get-NetFirewallRule unable to return a single rule.
#
#      Measured on a live Server 2022 VM (build 20348), one reboot per row:
#
#        absent                                              healthy, 316 rules
#        REG_SZ,  one SID, written by CheckNetIsolation      healthy, 316 rules
#        REG_SZ,  empty                                      healthy, 316 rules
#        REG_SZ,  700 joined SIDs / 118,224 bytes            dead, "The parameter is incorrect."
#        REG_MULTI_SZ, empty                                 dead, "The data is invalid."
#        REG_MULTI_SZ, one SID                               dead, "The data is invalid."
#        REG_MULTI_SZ, 330 SIDs / 55,692 bytes               dead, "The data is invalid."
#        REG_MULTI_SZ, 700 SIDs / 133,196 bytes              dead, "The data is invalid."
#
#      Two things follow, and this script is built on both. The registry type decides on its own:
#      the supported tool writes REG_SZ, and every value of another type killed the service however
#      much or little it held - an empty REG_MULTI_SZ is as fatal as a full one. Content matters
#      too, but only within the right type, and there is no size threshold to find: an empty REG_SZ
#      and a one-SID REG_SZ are both healthy, while a REG_SZ holding a list mpssvc cannot parse is
#      not. The monolithic script this replaces treated the fault as an oversized list and carried
#      entry-count thresholds of 683 and 600. No such threshold exists.
#
#      The two failure modes look different from the firewall API as well. A wrong-type value gives
#      "There are no more endpoints available from the endpoint mapper"; unreadable REG_SZ content
#      gives "A system shutdown is in progress", which is error 0x45b - the code the monolithic
#      script documented for this fault, and which does occur, though it is the API's answer rather
#      than the service-specific error in the event log.
#
#      Windows never recovers from this on its own. The value is durable across reboots, the restart
#      loop never converges, and the machine stays unreachable until the value is removed.


#
#   2. The firewall service, or the platform underneath it, set to Disabled.
#
#      MpsSvc ships Start=2 (Automatic) and so does BFE, the Base Filtering Engine it depends on.
#      Measured identical on build 20348 and on build 26200. Disabling either leaves the boot-time
#      filters in place with nothing to replace them, which is the same unreachable VM by a different
#      route. Only Start=4 (Disabled) is treated as evidence, so a service someone deliberately left
#      demand-started is never "corrected".
#
#   The AppCs key denies read to every account, SYSTEM included, so it cannot simply be opened. The
#   monolithic script solved that by taking ownership of the key, granting itself FullControl, making
#   its change and putting the descriptor back. That mutates the security descriptor of a machine
#   that may have nothing wrong with it, and it does so during DETECTION, before anything is known.
#
#   This script does not do that. It enables SeBackupPrivilege and SeRestorePrivilege and opens the
#   key with REG_OPTION_BACKUP_RESTORE, which makes the kernel grant access on the strength of the
#   privilege and skip the DACL check altogether. The owner and the DACL are never read, never
#   written and never restored, because they are never in the way. A healthy VM produces no findings
#   and this script writes nothing at all - not to the key, and not to its security descriptor.
#
#   The trigger and the target are deliberately not the same thing:
#
#     - The TRIGGER is evidence that mpssvc is actually failing on this value. The offline System
#       event log is read for Service Control Manager records showing the firewall service
#       terminating, and the value's size is compared against the smallest size measured to break a
#       live VM. Either is enough; neither fires on a machine whose firewall service starts.
#     - The TARGET is the state measured on healthy images: the value ABSENT, not present and empty.
#       The monolithic script renamed the value to DebugedLoopbackApps_ and recreated an empty
#       DebugedLoopbackApps in its place, which leaves two artefacts on a machine that shipped with
#       neither.
#
#   Everything removed is written to the log first - every SID in the list, in order - so an
#   exemption somebody actually wanted can be put back with CheckNetIsolation once the VM is up.
#
#   "Prepare a Windows VHD or VHDX to upload to Azure"
#   (https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image) requires
#   that the firewall allows inbound Remote Desktop, but it does not describe AppCs or
#   DebugedLoopbackApps, so there is no documented target for the loopback list. The target used here
#   was measured instead.
#
# .RESOLVES
#   A VM that boots and reports healthy but refuses every inbound connection, including RDP, with
#   connection timeouts rather than refusals; a VM that does not answer ping from another VM on the
#   same virtual network while its guest agent stays Ready; the Windows Defender Firewall service
#   stuck at StartPending or cycling between running and stopped; System event log filling with
#   "The Windows Defender Firewall service terminated with the following service-specific error: The
#   data is invalid."; Get-NetFirewallRule failing with an endpoint mapper error; and RDP lost after
#   CheckNetIsolation LoopbackExempt was used in bulk, often by a test harness or a packaging script.
#
# .PARAMETER detectOnly
#   "true" to report what is wrong with the firewall service and change nothing at all.
#   Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .NOTES
#   This fault can also be repaired online, without detaching the disk: the guest agent stays Ready
#   throughout, and removing the value through Run Command brings mpssvc back within about thirty
#   seconds with no reboot. That was measured too. This script exists for the case where the agent is
#   not responding, where Run Command is not available, or where the disk has already been moved to a
#   rescue VM for another reason - and because removing the value online still needs the same
#   privileged access to a key that denies read to SYSTEM.
#
#   A firewall service that starts but has been configured to block inbound Remote Desktop is a
#   different fault with a different fix, and is not repaired here. This script is about a service
#   that cannot start at all. Nothing in the firewall's rule set or profile configuration is read or
#   written.
#
#   The crash loop is noisy: thousands of Service Control Manager records in minutes. On a machine
#   that has been failing for a while the System log will have wrapped, and evidence of whatever
#   happened before the firewall broke may be gone.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Repair-RegistryFinding uses $Finding inside script blocks passed to the offline helpers, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1
. .\src\windows\common\helpers\Use-OfflinePrivilegedRegistry.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')

$script:DocUrl = 'https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image'

# Below the active control set. mpssvc reads this key on its start path.
$script:AppCsSubPath = 'Services\mpssvc\Parameters\AppCs'
$script:LoopbackValueName = 'DebugedLoopbackApps'

# The name the monolithic script renamed the faulty value to. Not a Windows artefact: its presence
# means that script has already run here. Reported, never written.
$script:LegacyArchiveValueName = 'DebugedLoopbackApps_'

# The type CheckNetIsolation writes, measured on build 20348: REG_SZ, one 164-byte value holding a
# single app container SID. A value of this type is left alone however large it is, because it is
# what a correctly configured machine looks like. Anything else at this value name is the fault.
$script:ExpectedLoopbackValueKind = [Microsoft.Win32.RegistryValueKind]::String

# Service Control Manager. 7024 is "terminated with the following service-specific error", which is
# what the crash loop logs; the others cover a service that failed to start or terminated
# unexpectedly, so a differently shaped failure of the same service still counts as evidence.
$script:ScmProvider = 'Service Control Manager'
$script:ScmFailureEventId = @(7000, 7001, 7023, 7024, 7031, 7034)

# Enough records to prove a loop without reading a log that may hold hundreds of thousands.
$script:MaxEventsRead = 400

# Matched against the rendered message and against the event data. The display name is stored in the
# log in the language of the machine that wrote it, so a non-English installation may not match; that
# is why size alone is also sufficient evidence.
$script:FirewallEventPattern = 'MpsSvc|Windows Defender Firewall|Windows Firewall'

# MpsSvc is the firewall service. BFE is the Base Filtering Engine it depends on: with BFE disabled
# mpssvc cannot start whatever else is correct. Start=2 (Automatic) measured on 20348 and 26200.
$script:ServiceSpec = @(
    [PSCustomObject]@{ Name = 'MpsSvc'; Start = 2; Purpose = 'Windows Defender Firewall - applies the filters that let inbound traffic through' }
    [PSCustomObject]@{ Name = 'BFE'; Start = 2; Purpose = 'Base Filtering Engine - the platform the firewall service builds its filters on' }
)

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Repaired   = $false
        Data       = $Data
    }
}

function Get-FirewallCrashEvidence {
    <#
    .SYNOPSIS
        Reading the offline System log for the firewall service failing to start.

    .DESCRIPTION
        Direct evidence that this machine's firewall service is actually broken, rather than an
        inference from the size of a registry value. Best effort by design: a log that is missing,
        corrupt or written in another language returns no evidence, and the caller falls back to the
        measured size instead of refusing to act.

        The messages are rendered using the rescue VM's own copy of the Service Control Manager
        resources, so the text comes back in this machine's language regardless of the language of
        the machine being repaired.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VolumeRoot)

    $result = [PSCustomObject]@{
        Readable = $false; Count = 0; Sample = ''; LastTime = $null; LogPath = ''
    }

    $logPath = Join-Path $VolumeRoot 'Windows\System32\winevt\Logs\System.evtx'
    $result.LogPath = $logPath

    if (-not (Test-Path -LiteralPath $logPath)) {
        Add-OfflineRepairLog -Level Info -Message "No System event log at $logPath, so the size of the value is the only evidence available."
        return $result
    }

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
                Path         = $logPath
                ProviderName = $script:ScmProvider
                Id           = $script:ScmFailureEventId
            } -MaxEvents $script:MaxEventsRead -ErrorAction Stop)
        $result.Readable = $true
    }
    catch {
        # No matching records at all also lands here, which is a perfectly normal answer.
        Add-OfflineRepairLog -Level Info -Message "The offline System log produced no Service Control Manager failure records ($($_.Exception.Message))."
        return $result
    }

    $firewall = @($events | Where-Object {
            $text = "$($_.Message) $(@($_.Properties | ForEach-Object { "$($_.Value)" }) -join ' ')"
            $text -match $script:FirewallEventPattern
        })

    $result.Count = $firewall.Count
    if ($firewall.Count -gt 0) {
        $result.LastTime = $firewall[0].TimeCreated
        $result.Sample = ("$($firewall[0].Message)" -replace '\s+', ' ').Trim()
    }

    return $result
}

function Get-LoopbackListState {
    <#
    .SYNOPSIS
        Reading the loopback exemption list out of the mounted offline hive.

    .DESCRIPTION
        Goes through the privileged path rather than the registry provider, because AppCs denies
        read to every account including SYSTEM and the provider has no way to ask for the backup
        access that gets past it.

        A key that is absent, and a key that is present with no loopback value, are both healthy and
        are reported as such rather than as failures.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $path = Join-Path $SystemRoot $script:AppCsSubPath

    $state = [PSCustomObject]@{
        Path          = $path
        KeyExists     = $false
        Readable      = $false
        Present       = $false
        ByteLength    = 0
        Type          = 0
        Kind          = [Microsoft.Win32.RegistryValueKind]::Unknown
        Entries       = @()
        LegacyArchive = $false
        Error         = ''
    }

    $names = Get-OfflinePrivilegedRegistryValueName -Path $path
    if (-not $names.Ok) {
        $state.Error = $names.Error
        Add-OfflineRepairLog -Level Warning -Message "The firewall's AppCs key could not be opened: $($names.Error)"
        return $state
    }

    $state.Readable = $true
    $state.KeyExists = $names.Exists
    if (-not $names.Exists) { return $state }

    $state.LegacyArchive = (@($names.Names) -contains $script:LegacyArchiveValueName)
    if (-not (@($names.Names) -contains $script:LoopbackValueName)) { return $state }

    $value = Get-OfflinePrivilegedRegistryValue -Path $path -Name $script:LoopbackValueName
    if (-not $value.Ok) {
        $state.Error = $value.Error
        Add-OfflineRepairLog -Level Warning -Message "The loopback exemption list could not be read: $($value.Error)"
        return $state
    }

    $state.Present = $value.Found
    $state.ByteLength = $value.ByteLength
    $state.Type = $value.Type
    # The raw REG_* type numbers line up with RegistryValueKind, so a value of a type Windows does
    # not define still reports its number rather than throwing.
    $state.Kind = if ([enum]::IsDefined([Microsoft.Win32.RegistryValueKind], [int]$value.Type)) {
        [Microsoft.Win32.RegistryValueKind]$value.Type
    }
    else {
        [Microsoft.Win32.RegistryValueKind]::Unknown
    }
    $state.Entries = @($value.Strings)
    return $state
}

function Get-FirewallServiceState {
    <#
    .SYNOPSIS
        The Start value of the firewall service and the filtering engine under it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $states = foreach ($spec in $script:ServiceSpec) {
        $path = Join-Path $SystemRoot "Services\$($spec.Name)"
        $exists = Test-Path -LiteralPath $path
        $start = $null
        if ($exists) {
            $found = $false
            $read = Get-OfflineProtectedRegistryValue -Path $path -Name 'Start' -Found ([ref]$found)
            if ($found) { $start = [int]$read }
        }

        [PSCustomObject]@{ Name = $spec.Name; Spec = $spec; Path = $path; Exists = $exists; Start = $start }
    }

    return @($states)
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Everything wrong that this script is prepared to act on.

    .DESCRIPTION
        Two independent triggers, because the fault has two measured shapes.

        The registry type is conclusive on its own: CheckNetIsolation writes REG_SZ, and a value of
        any other type stopped mpssvc on every reboot tested, even when it was empty.

        A REG_SZ value is judged on the offline log instead, because REG_SZ is what a correctly
        configured machine has and there is no size or entry count that separates a good one from a
        bad one - an empty REG_SZ and a one-SID REG_SZ are both healthy. So a REG_SZ value is only
        a fault when this machine's own System log shows the firewall service failing to start.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Loopback,
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)]$Services
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if ($Loopback.Present) {
        $wrongType = ($Loopback.Kind -ne $script:ExpectedLoopbackValueKind)
        $serviceFailing = ($Evidence.Count -gt 0)

        if ($wrongType -or $serviceFailing) {
            $why = if ($wrongType -and $serviceFailing) {
                "it is $($Loopback.Kind) rather than the $($script:ExpectedLoopbackValueKind) CheckNetIsolation writes, and the offline System log holds $($Evidence.Count) firewall service failure record(s)"
            }
            elseif ($wrongType) {
                "it is $($Loopback.Kind) rather than the $($script:ExpectedLoopbackValueKind) CheckNetIsolation writes, which stopped the service on every reboot measured, whatever the value held. The offline System log holds no failure records, which only means the machine was captured before they were written"
            }
            else {
                "the offline System log holds $($Evidence.Count) firewall service failure record(s), so this machine's mpssvc is not accepting the value even though its type is right"
            }

            [void]$findings.Add((New-Finding `
                        -Cause 'LoopbackValueUnreadable' `
                        -Item $script:LoopbackValueName `
                        -Message "$($script:LoopbackValueName) is $($Loopback.Kind) holding $($Loopback.ByteLength) bytes, and the Windows Defender Firewall service cannot start with it: $why. Any readable content is written to the log before the value is removed." `
                        -Data $Loopback))
        }
        else {
            Add-OfflineRepairLog -Level Info -Message "$($script:LoopbackValueName) is $($Loopback.Kind), the type CheckNetIsolation writes, holding $(@($Loopback.Entries).Count) entry(s) in $($Loopback.ByteLength) bytes, and nothing in the offline log shows the firewall service failing. That is a supported configuration and is left alone."
        }
    }

    foreach ($service in @($Services)) {
        if (-not $service.Exists) {
            [void]$findings.Add((New-Finding `
                        -Cause 'ServiceKeyMissing' `
                        -Item $service.Name `
                        -Message "$($service.Name) has no service key. $($service.Spec.Purpose). Recreating a service key from nothing is not something this script will guess at; the installation needs repairing by hand." `
                        -Repairable $false `
                        -Data $service))
            continue
        }

        if ($service.Start -eq 4) {
            [void]$findings.Add((New-Finding `
                        -Cause 'ServiceDisabled' `
                        -Item $service.Name `
                        -Message "$($service.Name) is Disabled (Start=4). $($service.Spec.Purpose). Every supported build ships Start=$($service.Spec.Start)." `
                        -Data $service))
        }
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applying one finding. Runs with the offline SYSTEM hive already mounted.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch ($Finding.Cause) {
        'LoopbackValueUnreadable' {
            $loopback = $Finding.Data

            # Written before the removal, not after, so anything readable survives even if the
            # removal throws. The value is removed rather than emptied: an absent value is the
            # shape measured on clean images, and it needs no assumption about what the correct
            # content would have been.
            Add-OfflineRepairLog -Message "Removing $($script:LoopbackValueName) ($($loopback.Kind), $($loopback.ByteLength) bytes). Any text it held follows, and each app container can be exempted again with: CheckNetIsolation LoopbackExempt -a -p=<SID>"
            $index = 0
            foreach ($entry in @($loopback.Entries)) {
                $index++
                Add-OfflineRepairLog -Message "  [$index] $entry"
            }
            if (@($loopback.Entries).Count -eq 0) {
                Add-OfflineRepairLog -Message '  (no readable text: an empty value of the wrong type was measured to stop the service just as reliably as a full one)'
            }

            $outcome = Remove-OfflinePrivilegedRegistryValue -Path $loopback.Path -Name $script:LoopbackValueName -Confirm:$false
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "$($script:LoopbackValueName) removed. The key's owner and permissions were not touched, and the value is now absent, which is the state measured on healthy images."
                return $true
            }

            Add-OfflineRepairLog -Level Warning -Message "$($script:LoopbackValueName) could not be removed: $($outcome.Error)"
            return $false
        }

        'ServiceDisabled' {
            $service = $Finding.Data
            $outcome = Invoke-OfflineProtectedRegistryWrite -Path $service.Path -Description "$($service.Name) Start" -Action {
                Set-ItemProperty -Path $service.Path -Name 'Start' -Value ([uint32]$service.Spec.Start) -Type DWord -Force -ErrorAction Stop
            }
            if ($outcome.Written) {
                Add-OfflineRepairLog -Message "$($service.Name): Start 4 (Disabled) -> $($service.Spec.Start), the value measured on every supported build."
                return $true
            }

            Add-OfflineRepairLog -Level Warning -Message "$($service.Name) Start could not be written: $($outcome.Reason)"
            return $false
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $volumeRoot = Split-Path -Path $offline.WindowsPath -Parent

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "$($script:DocUrl) requires that the firewall allows inbound Remote Desktop, but does not describe the loopback exemption list; the target below was measured on healthy images." | Tee-Object -FilePath $logFile -Append

    # Read outside the hive: the event log is a file, and reading it does not need the hive mounted.
    $evidence = Get-FirewallCrashEvidence -VolumeRoot $volumeRoot
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $loopback = Get-LoopbackListState -SystemRoot $systemRoot
        $services = Get-FirewallServiceState -SystemRoot $systemRoot

        return [PSCustomObject]@{
            ControlSet = (Split-Path -Path $systemRoot -Leaf)
            Loopback   = $loopback
            Services   = @($services)
            Findings   = @(Get-AllFinding -Loopback $loopback -Evidence $evidence -Services $services)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    $loopback = $context.Loopback
    Log-Info "Control set $($context.ControlSet)." | Tee-Object -FilePath $logFile -Append

    if ($evidence.Readable) {
        Log-Info "Offline System log: $($evidence.Count) Service Control Manager record(s) show the firewall service failing$(if ($evidence.LastTime) { ", most recently at $($evidence.LastTime)" })." | Tee-Object -FilePath $logFile -Append
        if ($evidence.Sample) {
            Log-Info "  $($evidence.Sample)" | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Info 'Offline System log: no firewall service failure records could be read. That does not clear the machine, because the type of the loopback value decides on its own.' | Tee-Object -FilePath $logFile -Append
    }

    if (-not $loopback.Readable) {
        Log-Warning "The firewall's AppCs key could not be read, so a loopback list fault cannot be ruled out. $($loopback.Error)" | Tee-Object -FilePath $logFile -Append
    }
    elseif (-not $loopback.KeyExists) {
        Log-Info 'No AppCs key is present. That is not a fault: it is created the first time a loopback exemption is added.' | Tee-Object -FilePath $logFile -Append
    }
    elseif (-not $loopback.Present) {
        Log-Info "AppCs is present and holds no $($script:LoopbackValueName) value, which is the state measured on healthy images." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "$($script:LoopbackValueName): $($loopback.Kind), $($loopback.ByteLength) bytes, $(@($loopback.Entries).Count) readable entry(s). Expected type is $($script:ExpectedLoopbackValueKind)." | Tee-Object -FilePath $logFile -Append
    }

    if ($loopback.LegacyArchive) {
        Log-Info "AppCs also holds $($script:LegacyArchiveValueName). That is not a Windows value: it is what the monolithic repair script renamed a faulty list to, so this machine has been repaired that way before. It is reported rather than removed, because mpssvc does not read it." | Tee-Object -FilePath $logFile -Append
    }

    foreach ($service in @($context.Services)) {
        $shown = if (-not $service.Exists) { 'no service key' } elseif ($null -eq $service.Start) { '(Start not set)' } else { "Start=$($service.Start)" }
        Log-Info "  $($service.Name): $shown - $($service.Spec.Purpose)." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0) {
        Log-Output 'No firewall service fault was found. The service and the filtering engine under it are not disabled, and no loopback exemption list is stopping the service from starting. No changes were made.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = [System.Collections.Generic.List[string]]::new()

    $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

    $repairOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $done = 0
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($finding in $repairable) {
            try {
                if (Repair-Finding -Finding $finding) {
                    $finding.Repaired = $true
                    $done++
                }
            }
            catch {
                [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
            }
        }
        return [PSCustomObject]@{ Repaired = $done; Errors = @($errors) }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $repairedCount += $repairOutcome.Repaired
    foreach ($failure in @($repairOutcome.Errors)) { [void]$failed.Add($failure) }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        return @(Get-AllFinding `
                -Loopback (Get-LoopbackListState -SystemRoot $systemRoot) `
                -Evidence $evidence `
                -Services (Get-FirewallServiceState -SystemRoot $systemRoot))
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported." }

    if ($failed.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($failed.Count) repair(s) failed and $($stillRepairable.Count) issue(s) are still present." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    if ($repairedCount -gt 0) {
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM. The firewall service starts on the next boot and the machine answers inbound traffic again; any loopback exemption that was removed is listed in the log above and can be added back with CheckNetIsolation LoopbackExempt." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
