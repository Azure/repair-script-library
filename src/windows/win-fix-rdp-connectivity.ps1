#########################################################################################################
#
# .SYNOPSIS
#   Restores Remote Desktop on an offline disk, so an Azure VM that boots and is on the network but
#   refuses every RDP connection can be reached again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM that answers ping, whose guest agent may still be reporting, and whose boot
#   diagnostics show a healthy logon screen - and which refuses every RDP connection anyway. Nothing
#   is corrupt and nothing failed to start; the Terminal Server configuration simply says that remote
#   connections are not allowed, or the listener cannot negotiate a session with any client.
#
#   Every value this script writes comes from "Prepare a Windows VHD or VHDX to upload to Azure"
#   (https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image), which
#   is the supported description of how a Windows VM must be configured to be reachable in Azure.
#   The goal is a VM an engineer can get back into, not a VM restored to whatever Windows ships with.
#
#   Where the two differ, the document wins. That distinction is not theoretical: a healthy Server
#   2022 marketplace image was read before this script was written and it disagrees with the
#   document in two places - IKEEXT is Manual on the image where the document says Automatic, and
#   KeepAliveTimeout is 0 where the document says 1. Restoring "the Windows default" would put
#   IKEEXT back to a value the Azure guidance does not ask for.
#
#   That same comparison decides what counts as a fault. Those two deviations exist on a machine that
#   is perfectly reachable, so "differs from the document" cannot be the trigger for a repair - it
#   would fire on every healthy Azure VM and change two values that were never the problem. So:
#
#     - The TRIGGER is evidence that RDP is actually prevented. A healthy VM produces no findings and
#       this script writes nothing at all.
#     - The TARGET, once something is found to be broken, is the value the document specifies.
#
#   Four configurations are treated as evidence, and all four are readable and repairable offline:
#
#     1. fDenyTSConnections=1. This is "Allow remote connections to this computer" turned off. The
#        document sets it in two places - the Terminal Server key and the Group Policy copy under
#        SOFTWARE - and the policy copy wins, so a VM can have the base key correct and still refuse
#        everything. Both are checked and both are repaired; repairing one and leaving the other
#        produces a VM that is exactly as unreachable and a log that claims success.
#
#     2. A Remote Desktop service disabled (Start=4). TermService, SessionEnv and UmRdpService are
#        the listener path, and a disabled one cannot start whatever else is correct. Only Start=4
#        is treated as evidence, so a service deliberately left demand-started is never "corrected"
#        into something else. Netlogon, Netman and RemoteRegistry are also listed by the document,
#        but none of them is in the listener path - local-account RDP does not need Netlogon - so a
#        disabled one is reported and only restored under -applyAzureBaseline.
#
#     3. An out-of-range SecurityLayer, UserAuthentication or MinEncryptionLevel on the RDP-Tcp
#        listener. Windows does not clamp these - a value outside the documented set leaves the
#        listener unable to agree a security layer with any client, which reaches the user as an
#        immediate disconnect with no useful error.
#
#     4. TLS 1.2 explicitly disabled for the SCHANNEL Server side. TLS 1.2 is not in the document,
#        but the RDP listener negotiates over TLS as a server, and a hardening script that disabled
#        1.2 alongside 1.0 and 1.1 leaves it with nothing to offer; enabling it is a repair rather
#        than a downgrade, and 1.0 and 1.1 are not touched either way. Only the Server side is
#        read: the Client side governs outbound connections this VM makes, not the listener, so a
#        Client-only setting is deliberate configuration and is left alone.
#
#   Faults that belong to another script are reported with their owner named rather than repaired
#   here, so two scripts never write the same value. The owner is named as a pointer to the scenario
#   that covers the fault, not as an assertion that the run-id is present in every copy of this
#   library; each finding also states the value it expects, so the fault can be acted on either way:
#
#     - nsi, Dhcp, Dnscache and iphlpsvc disabled -> win-fix-network-connectivity
#     - BFE and mpssvc disabled                   -> win-fix-firewall-service
#     - a listener certificate that is present but broken, and its private key permissions
#                                                 -> win-fix-rdp-certificate
#
#   Four things are never done unless asked for by name, because each trades away security or
#   working configuration to gain access, and that is an operator's decision rather than a script's:
#
#     - NLA is only turned off with -disableNla. The document configures UserAuthentication=1, so
#       NLA being enabled is the supported state and is never reported as a fault.
#     - A non-standard listener port is reported, never reset, unless -resetListenerPort is passed.
#       The document specifies 3389 for an image being prepared, but a deployed VM whose port was
#       moved deliberately has a firewall rule and a network security group that followed it, and
#       resetting the port on one of those removes the access it was meant to restore. Measured on
#       a repaired VM: with the listener moved to 33890 the service started and listened on
#       0.0.0.0:33890, and the connection was still refused, because the built-in "Remote Desktop -
#       User Mode (TCP-In)" rule is scoped to 3389. A moved port needs its own rule at both layers,
#       which is why this is reported for a decision rather than repaired.
#     - The machine-wide SSL cipher suite policy is only cleared with -clearCipherSuitePolicy. It is
#       present on a healthy Azure image, carrying the platform's intended cipher order, so deleting
#       it on sight would strip working configuration off every machine this ran against. Only an
#       EMPTY suite list is treated as a fault, because that genuinely leaves nothing to negotiate.
#     - A certificate pinned to the listener (SSLCertificateSHA1Hash) is only removed with
#       -removePinnedCertificate. Step 8 of the document removes it because a pin whose private key
#       no longer resolves fails the handshake before authentication, and removing it lets Windows
#       generate a fresh self-signed listener certificate on the next start. But a pin is also how
#       a valid custom certificate is configured, and this script cannot resolve the certificate's
#       private key offline to tell the two apart, so by default the pin is reported, not removed.
#       Windows does not write the value for its own self-signed certificate - measured absent on a
#       clean Windows Server 2019 marketplace image and on a running Windows 11 host serving RDP over
#       TLS with SecurityLayer=2 - so a machine that never pinned one is never reported.
#
#   AllowEncryptionOracle is not written by this script under any parameter. Setting it to 2 makes
#   CredSSP accept the CVE-2018-0886 downgrade again, and a repair script is not the place to
#   reintroduce a remote code execution vulnerability on a machine about to go back into service.
#
#   -applyAzureBaseline applies the document's full Remote Desktop registry configuration - the
#   keep-alive, reconnect, LanAdapter and MaxInstanceCount values - rather than only what is broken.
#   It is off by default because those values do not prevent a connection and one of them differs on
#   a healthy image. Pass it when a VM's Terminal Server configuration has been edited enough that
#   returning it wholesale to the documented state is quicker than reasoning about each value.
#   Three of the documented values live under Policies\Microsoft\Windows NT\Terminal Services, so
#   on a VM with no Terminal Services policy this creates that Group Policy key. Group Policy values
#   override the local Terminal Server settings and persist until removed, which is a larger change
#   than it appears; the SOFTWARE hive backup taken before the write is the way back.
#
#   The SYSTEM and SOFTWARE hives are backed up before either is written to.
#
# .RESOLVES
#   A VM that boots and responds on the network but refuses RDP, an RDP client reporting that the
#   remote computer is not accepting connections, a session that disconnects immediately after the
#   handshake with an internal error, RDP lost after a hardening baseline or service-tuning script
#   was applied, and a VM whose Remote Desktop services were disabled by policy.
#
# .PARAMETER detectOnly
#   "true" to report the Remote Desktop configuration and what would be changed, and repair nothing.
#   No configuration is changed. It is not a pure read: a key locked against this rescue VM has to
#   have its descriptor borrowed before it can be read at all, and each one is restored immediately
#   afterwards in a finally. Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .PARAMETER applyAzureBaseline
#   "true" to also apply the documented keep-alive, reconnect, LanAdapter and MaxInstanceCount
#   values from "Prepare a Windows VHD to upload to Azure", whether or not they are currently wrong.
#   Three of those values live under the Terminal Services Group Policy key, so on a VM that has no
#   such policy this creates it, and Group Policy then overrides the local settings until removed.
#   Skipped entirely, and reported as a finding, when either the Control\Terminal Server key or the
#   RDP-Tcp listener key is missing: that is a damaged installation rather than a machine to tune,
#   and the baseline would be writing Remote Desktop settings - including a Group Policy key created
#   from nothing - onto a machine that has no Remote Desktop configuration.
#   Also restores Netlogon, Netman and RemoteRegistry to their documented startup type when one of
#   them is disabled; without this they are reported only.
#   Defaults to "false" - see the note above.
#
# .PARAMETER disableNla
#   "true" to turn Network Level Authentication off on the listener. Defaults to "false". The Azure
#   guidance enables NLA, so this is a deliberate deviation from it. Pass this only when the VM
#   cannot be reached because its clients cannot pre-authenticate - a broken machine account or an
#   unreachable domain controller - and turn it back on once the VM is in.
#
# .PARAMETER resetListenerPort
#   "true" to reset the RDP listener to port 3389, the port the document specifies. Defaults to
#   "false", because a deployed VM may have been moved off 3389 deliberately.
#
# .PARAMETER clearCipherSuitePolicy
#   "true" to remove the machine-wide SSL cipher suite policy. Defaults to "false", because this
#   policy is present and correct on a healthy Azure VM. Pass this only when the configured suite
#   list is known to exclude everything the RDP listener can offer.
#
# .PARAMETER removePinnedCertificate
#   "true" to remove a certificate pinned to the listener (SSLCertificateSHA1Hash), so Windows
#   generates a fresh self-signed listener certificate on the next start. Defaults to "false",
#   because a pin is also how a valid custom certificate is configured. Pass this when the pinned
#   certificate is known to be missing or its private key unusable; win-fix-rdp-certificate covers
#   a certificate that is present but broken.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-connectivity --run-on-repair --parameters detectOnly=true
#
#   Reports the Remote Desktop configuration found on the attached disk and what would be changed.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-connectivity --run-on-repair
#
#   Re-enables remote connections, starts Remote Desktop services that were disabled, brings
#   out-of-range listener values back into their documented set and re-enables server-side TLS 1.2
#   where it was explicitly turned off. A pinned listener certificate is reported, not removed.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-connectivity --run-on-repair --parameters removePinnedCertificate=true
#
#   Also removes a listener certificate pin whose certificate is known to be missing or unusable.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-connectivity --run-on-repair --parameters applyAzureBaseline=true resetListenerPort=true
#
#   Also applies the document's full Remote Desktop registry configuration and moves the listener
#   back to port 3389. Only pass resetListenerPort when the port was not moved deliberately.
#
# .NOTES
#   A hive that will not load at all is a different problem and belongs to
#   win-fix-registry-corruption. This script needs SYSTEM and SOFTWARE to mount before it can read
#   anything, so run that one first if either hive is damaged.
#
#   A VM that is unreachable at the network layer - no ping, no agent - is not this script's fault to
#   fix. Restore network connectivity first, by whichever scenario covers it, and come back here only
#   if RDP is still refused once the VM is on the network.
#
#   The document also requires the Windows Firewall to be ON for all three profiles, with the Remote
#   Desktop rule group enabled. Nothing in this script turns a firewall off.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$applyAzureBaseline = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$disableNla = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$resetListenerPort = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$clearCipherSuitePolicy = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$removePinnedCertificate = 'false'
)

. .\src\windows\common\setup\init.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$wantBaseline = ($applyAzureBaseline -eq 'true')
$wantDisableNla = ($disableNla -eq 'true')
$wantResetPort = ($resetListenerPort -eq 'true')
$wantClearCiphers = ($clearCipherSuitePolicy -eq 'true')
$wantRemovePin = ($removePinnedCertificate -eq 'true')

$script:TerminalServerSubPath = 'Control\Terminal Server'
$script:RdpTcpSubPath = 'Control\Terminal Server\WinStations\RDP-Tcp'
$script:TerminalServerPolicyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$script:CipherPolicyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$script:StandardRdpPort = 3389
$script:DocUrl = 'https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image'

# The services "Prepare a Windows VHD to upload to Azure" requires, with the startup type it gives
# each one. Automatic is Start=2 and Manual is Start=3.
#
#   Automatic: BFE, Dhcp, Dnscache, IKEEXT, iphlpsvc, nsi, mpssvc, RemoteRegistry
#   Manual:    Netlogon, Netman, TermService
#
# IKEEXT is the one worth knowing about: the document says Automatic, a healthy Server 2022
# marketplace image ships it Manual. The document is what a VM in Azure is supported at, so it is
# the value used when the service is found disabled - but a service that is merely Manual is not
# disabled, produces no finding, and is left alone.
#
# Owner names which script restores the value. RDP's own services are repaired here; the rest are
# reported so that two scripts never write the same value. BaselineOnly marks a service this script
# owns but that is not in the listener path: a disabled one is reported, and only restored under
# -applyAzureBaseline, so a reachable VM is never changed just because it differs from the document.
$script:ServiceSpec = @(
    [PSCustomObject]@{ Name = 'TermService'; DocStart = 3; Owner = $null; BaselineOnly = $false; Source = 'documented Manual'; Purpose = 'Remote Desktop Services - the listener itself' }
    [PSCustomObject]@{ Name = 'SessionEnv'; DocStart = 3; Owner = $null; BaselineOnly = $false; Source = 'not in the document; Windows ships it Manual'; Purpose = 'Remote Desktop Configuration' }
    [PSCustomObject]@{ Name = 'UmRdpService'; DocStart = 3; Owner = $null; BaselineOnly = $false; Source = 'not in the document; Windows ships it Manual'; Purpose = 'RD User Mode Port Redirector' }
    [PSCustomObject]@{ Name = 'Netlogon'; DocStart = 3; Owner = $null; BaselineOnly = $true; Source = 'documented Manual'; Purpose = 'Net Logon - domain logon for domain-joined VMs' }
    [PSCustomObject]@{ Name = 'Netman'; DocStart = 3; Owner = $null; BaselineOnly = $true; Source = 'documented Manual'; Purpose = 'Network Connections' }
    [PSCustomObject]@{ Name = 'RemoteRegistry'; DocStart = 2; Owner = $null; BaselineOnly = $true; Source = 'documented Automatic'; Purpose = 'Remote Registry - remote troubleshooting of this VM' }
    [PSCustomObject]@{ Name = 'nsi'; DocStart = 2; Owner = 'win-fix-network-connectivity'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'Network Store Interface - TCP/IP does not come up without it' }
    [PSCustomObject]@{ Name = 'Dhcp'; DocStart = 2; Owner = 'win-fix-network-connectivity'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'DHCP Client - no lease means no address' }
    [PSCustomObject]@{ Name = 'Dnscache'; DocStart = 2; Owner = 'win-fix-network-connectivity'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'DNS Client' }
    [PSCustomObject]@{ Name = 'iphlpsvc'; DocStart = 2; Owner = 'win-fix-network-connectivity'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'IP Helper' }
    [PSCustomObject]@{ Name = 'IKEEXT'; DocStart = 2; Owner = 'win-fix-network-connectivity'; BaselineOnly = $false; Source = 'documented Automatic, though a healthy image ships it Manual'; Purpose = 'IKE and AuthIP keying modules' }
    [PSCustomObject]@{ Name = 'BFE'; DocStart = 2; Owner = 'win-fix-firewall-service'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'Base Filtering Engine - mpssvc cannot start without it' }
    [PSCustomObject]@{ Name = 'mpssvc'; DocStart = 2; Owner = 'win-fix-firewall-service'; BaselineOnly = $false; Source = 'documented Automatic'; Purpose = 'Windows Firewall - no inbound rules means no RDP' }
)

# Documented value sets for the listener. A value outside its set is the fault; a value inside it is
# left alone even when it is not the documented target, because it is a supported configuration.
$script:ListenerValueSpec = @(
    [PSCustomObject]@{ Name = 'SecurityLayer'; Valid = @(0, 1, 2); DocValue = 2; Purpose = 'how the listener secures the connection (0 RDP, 1 negotiate, 2 TLS)' }
    [PSCustomObject]@{ Name = 'UserAuthentication'; Valid = @(0, 1); DocValue = 1; Purpose = 'whether Network Level Authentication is required' }
    [PSCustomObject]@{ Name = 'MinEncryptionLevel'; Valid = @(1, 2, 3, 4); DocValue = 3; Purpose = 'the minimum encryption the listener accepts' }
)

# The document's Remote Desktop registry configuration, steps 3 to 7. None of these prevent a
# connection on their own, so they are only written when -applyAzureBaseline is passed. Hive says
# which of the two mounted hives the value lives in.
$script:BaselineValueSpec = @(
    [PSCustomObject]@{ Name = 'LanAdapter'; Value = 0; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'the listener listens on every network interface' }
    [PSCustomObject]@{ Name = 'KeepAliveTimeout'; Value = 1; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'keep-alive timeout' }
    [PSCustomObject]@{ Name = 'fInheritReconnectSame'; Value = 1; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'inherit the reconnect setting' }
    [PSCustomObject]@{ Name = 'fReconnectSame'; Value = 0; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'reconnect from any client rather than only the original one' }
    [PSCustomObject]@{ Name = 'MaxInstanceCount'; Value = 4294967295; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'do not limit concurrent connections' }
    [PSCustomObject]@{ Name = 'KeepAliveEnable'; Value = 1; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'keep-alive enabled' }
    [PSCustomObject]@{ Name = 'KeepAliveInterval'; Value = 1; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'keep-alive interval' }
    [PSCustomObject]@{ Name = 'fDisableAutoReconnect'; Value = 0; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'automatic reconnect allowed' }
)

function ConvertTo-DwordInt32 {
    <#
    .SYNOPSIS
        Reinterprets a DWORD as the Int32 the registry API actually stores.

    .DESCRIPTION
        A REG_DWORD is 32 bits with no sign, but .NET exposes it as Int32, and both
        RegistryKey.SetValue(..., RegistryValueKind::DWord) and a plain [int] cast go through a
        CHECKED conversion that throws OverflowException above 2147483647. MaxInstanceCount is
        4294967295, so it could neither be written nor compared: the write threw, and reading the
        documented value back returned -1, which never string-matched 4294967295. The finding was
        therefore raised on every run and survived its own repair, failing the run.

        Reinterpreting the bits rather than converting the number gives the value the registry
        genuinely holds (4294967295 -> -1) and is an identity for everything that already fits.
        Returns $null for anything that is not a number, so a value of an unexpected type is treated
        as drift rather than throwing.
    #>
    param([Parameter(Mandatory = $false)][AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    $parsed = [int64]0
    if (-not [int64]::TryParse([string]$Value, [ref]$parsed)) { return $null }
    # Reject rather than silently truncate. A value outside the DWORD range is not a DWORD that was
    # read back oddly, it is a value this script has no correct interpretation of, and masking it
    # would write a number nobody chose (4294967296 would become 0).
    if ($parsed -gt 4294967295L -or $parsed -lt -2147483648L) { return $null }
    # 4294967295L, not 0xFFFFFFFF: PowerShell parses that hex literal as [int] -1, which masks to
    # the wrong value and then fails the [uint32] conversion outright.
    return [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]($parsed -band 4294967295L)), 0)
}

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'SOFTWARE')][string]$Hive,
        [Parameter(Mandatory = $false)][ValidateSet('SYSTEM', 'SOFTWARE')][string[]]$AlsoHive = @(),
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Hive       = $Hive
        # Every hive this finding's repair may write, which is what the backup pass has to cover.
        # Almost all findings write one hive; the Azure baseline writes both.
        Hives      = @(@($Hive) + @($AlsoHive) | Sort-Object -Unique)
        Repairable = $Repairable
        Data       = $Data
    }
}

function Get-OfflineValueState {
    <#
    .SYNOPSIS
        Reads one value, distinguishing "not set" from "could not be read".

    .DESCRIPTION
        Returns Value, Found and Denied rather than a bare value, because a key locked against
        Administrators returns nothing at all and that must never be reported as "not set". A repair
        that then writes a documented default over a value it never managed to read is changing
        something it never looked at.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $found = $false
    $denied = $false
    $value = Get-OfflineProtectedRegistryValue -Path $Path -Name $Name -Found ([ref]$found) -Denied ([ref]$denied)

    return [PSCustomObject]@{
        Path   = $Path
        Name   = $Name
        Value  = $value
        Found  = $found
        Denied = $denied
    }
}

function Test-ValueUnreadable {
    <#
    .SYNOPSIS
        True only when a read was refused AND never recovered.

    .DESCRIPTION
        Get-OfflineProtectedRegistryValue raises Denied the moment the first plain read is refused,
        before it takes the key and reads again, and it does not lower the flag when that retry
        succeeds. Denied on its own therefore means "was locked at some point", not "unknown", and
        testing it alone throws away values the script did in fact read.

        Every read site must ask the question through here, because both mistakes are silent: a
        recovered value treated as unreadable skips a repair, and an unreadable value treated as
        "not set" lets the script report a healthy machine it never managed to look at.
    #>
    param([Parameter(Mandatory = $false)][AllowNull()]$State)

    if ($null -eq $State) { return $false }
    return ($State.Denied -and -not $State.Found)
}

function Format-ValueForLog {
    <#
    .SYNOPSIS
        Renders a read value for the context log, keeping "unreadable" and "not set" apart.
    #>
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$State,
        [Parameter(Mandatory = $false)][string]$NotSet = '(not set)'
    )

    if ($null -eq $State) { return $NotSet }
    if (Test-ValueUnreadable -State $State) { return '(unreadable)' }
    if ($State.Found) { return "$($State.Value)" }
    return $NotSet
}

function Get-TerminalServerState {
    <#
    .SYNOPSIS
        Reads the Terminal Server configuration: the deny switch, the listener and its values.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    # Test-Path is a presence gate, not an access gate. Measured against a key an administrator
    # cannot open (HKLM:\SECURITY): Test-Path returns $true while reg query reports access denied
    # and OpenSubKey throws. So a key whose permissions were changed still reaches the protected
    # read below and still raises an unreadable finding - the gate only skips a key that genuinely
    # is not there. Recorded here because it reads like a hole and is not one.
    $tsPath = Join-Path $SystemRoot $script:TerminalServerSubPath
    $rdpPath = Join-Path $SystemRoot $script:RdpTcpSubPath
    $listenerPresent = Test-Path -LiteralPath $rdpPath
    $terminalServerPresent = Test-Path -LiteralPath $tsPath

    $listener = @()
    if ($listenerPresent) {
        foreach ($spec in $script:ListenerValueSpec) {
            $read = Get-OfflineValueState -Path $rdpPath -Name $spec.Name
            # A bare [int] cast throws on a value of the wrong type, and these keys are exactly the
            # ones a broken machine may have the wrong type in. An uncastable value is not valid,
            # which routes it to the normal "outside the documented set" repair.
            $numeric = $null
            $isNumeric = ($read.Found -and [int]::TryParse([string]$read.Value, [ref]$numeric))
            $listener += [PSCustomObject]@{
                Spec    = $spec
                Value   = $read.Value
                Found   = $read.Found
                Denied  = $read.Denied
                IsValid = ((-not $read.Found) -or ($isNumeric -and ($spec.Valid -contains $numeric)))
            }
        }
    }

    $baseline = @()
    foreach ($spec in $script:BaselineValueSpec) {
        $path = if ($spec.Scope -eq 'Listener') { $rdpPath } else { $script:TerminalServerPolicyPath }
        if (($spec.Scope -eq 'Listener') -and (-not $listenerPresent)) { continue }
        $read = Get-OfflineValueState -Path $path -Name $spec.Name
        $baseline += [PSCustomObject]@{
            Spec    = $spec
            Path    = $path
            Value   = $read.Value
            Found   = $read.Found
            # Compared as the Int32 the registry stores, so a documented DWORD above 2147483647
            # matches the value that was actually written instead of drifting forever. A value of
            # an unexpected type converts to $null and counts as drift.
            Matches = ($read.Found -and ($null -ne (ConvertTo-DwordInt32 -Value $read.Value)) -and
                       ((ConvertTo-DwordInt32 -Value $read.Value) -eq (ConvertTo-DwordInt32 -Value $spec.Value)))
            # A value that was refused and never recovered is not drift. Counting it as drift made
            # the script log "(not set)->N" about a value it never saw and then overwrite it.
            Unreadable = (Test-ValueUnreadable -State $read)
        }
    }

    $policyPresent = Test-Path -LiteralPath $script:TerminalServerPolicyPath

    return [PSCustomObject]@{
        TerminalServerPath = $tsPath
        RdpTcpPath         = $rdpPath
        ListenerPresent    = $listenerPresent
        TerminalServerKeyPresent = $terminalServerPresent
        BaseDeny           = Get-OfflineValueState -Path $tsPath -Name 'fDenyTSConnections'
        PolicyPresent      = $policyPresent
        PolicyDeny         = $(if ($policyPresent) { Get-OfflineValueState -Path $script:TerminalServerPolicyPath -Name 'fDenyTSConnections' } else { $null })
        Listener           = @($listener)
        Baseline           = @($baseline)
        Port               = $(if ($listenerPresent) { Get-OfflineValueState -Path $rdpPath -Name 'PortNumber' } else { $null })
        PinnedCertificate  = $(if ($listenerPresent) { Get-OfflineValueState -Path $rdpPath -Name 'SSLCertificateSHA1Hash' } else { $null })
    }
}

function Get-RdpServiceState {
    <#
    .SYNOPSIS
        Reads the Start value of every service the Azure guidance requires for connectivity.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $services = foreach ($spec in $script:ServiceSpec) {
        $path = Join-Path $SystemRoot "Services\$($spec.Name)"
        $exists = Test-Path -LiteralPath $path
        $start = $null
        $denied = $false
        $found = $false
        $raw = $null
        if ($exists) {
            $value = Get-OfflineValueState -Path $path -Name 'Start'
            # $null rather than a cast, so a Start of an unexpected type cannot throw mid-scan.
            if ($value.Found) { $start = ConvertTo-DwordInt32 -Value $value.Value }
            $denied = $value.Denied
            $found = $value.Found
            $raw = $value.Value
        }
        [PSCustomObject]@{
            Name     = $spec.Name
            Spec     = $spec
            Path     = $path
            Exists   = $exists
            Start    = $start
            Value    = $raw
            Found    = $found
            Denied   = $denied
            # Denied is optimistic - it is raised on the first refusal and never lowered when the
            # retry succeeds - so pairing it with Found is what separates "never read" from "read
            # after taking the key". Testing $null -eq $Start instead would call a malformed value
            # unreadable, because a non-numeric Start also converts to $null.
            Unreadable = ($denied -and -not $found)
            # Read, but not a number: neither healthy nor disabled, and not something to overwrite
            # blind. Without this it fell through as $null and the service was reported as fine.
            Malformed  = ($found -and $null -eq $start)
            Disabled = ($exists -and $start -eq 4)
        }
    }

    return @($services)
}

function Get-SchannelState {
    <#
    .SYNOPSIS
        Reads whether TLS 1.2 is explicitly disabled, and the machine-wide cipher suite policy.

    .DESCRIPTION
        Only TLS 1.2 is examined. A hardening baseline that disables 1.0 and 1.1 and leaves 1.2 on is
        healthy, common and correct, so reporting on those would fire on machines with nothing wrong.

        Only the Server side is read. The RDP listener negotiates TLS as a server; the Client side
        governs outbound connections this VM makes, so a Client-only setting does not affect RDP
        and is deliberate configuration that this script must not rewrite.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $base = Join-Path $SystemRoot 'Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
    $sides = foreach ($side in @('Server')) {
        $path = Join-Path $base $side
        $enabled = Get-OfflineValueState -Path $path -Name 'Enabled'
        $disabledByDefault = Get-OfflineValueState -Path $path -Name 'DisabledByDefault'

        # Absent means "Windows decides", which for TLS 1.2 on a supported build means enabled. Only
        # an explicit Enabled=0 or DisabledByDefault=1 is evidence of a fault.
        [PSCustomObject]@{
            Side              = $side
            Path              = $path
            Enabled           = $enabled
            DisabledByDefault = $disabledByDefault
            IsDisabled        = (((ConvertTo-DwordInt32 -Value $enabled.Value) -eq 0 -and $enabled.Found) -or
                                 ((ConvertTo-DwordInt32 -Value $disabledByDefault.Value) -eq 1 -and $disabledByDefault.Found))
            # Neither value could be read, so "Windows decides" cannot be assumed. Reported, not
            # repaired, for the same reason as every other unreadable value.
            Unreadable        = ((Test-ValueUnreadable -State $enabled) -or (Test-ValueUnreadable -State $disabledByDefault))
        }
    }

    $cipherPresent = Test-Path -LiteralPath $script:CipherPolicyPath
    $functions = $(if ($cipherPresent) { Get-OfflineValueState -Path $script:CipherPolicyPath -Name 'Functions' } else { $null })
    $functionCount = 0
    if ($functions -and $functions.Found) {
        $functionCount = @(@($functions.Value) -join ',' -split '[,;]' | Where-Object { $_ -and $_.Trim() }).Count
    }

    return [PSCustomObject]@{
        Tls12          = @($sides)
        CipherPresent  = $cipherPresent
        Functions      = $functions
        FunctionCount  = $functionCount
        FunctionsEmpty = ($null -ne $functions -and $functions.Found -and $functionCount -eq 0)
        # An empty cipher suite list stops the handshake outright, so a Functions value that could
        # not be read is not something to pass over: without this the key's silence was reported as
        # "sets no suite list, so Windows uses its own ... not treated as a fault", which is an
        # affirmative healthy statement about a value never read. Unlike the listener values there
        # is no second read in the same key to raise a finding in its place.
        FunctionsUnreadable = (Test-ValueUnreadable -State $functions)
    }
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turns the state that was read into the list of things that are actually preventing RDP.
    #>
    param(
        [Parameter(Mandatory = $true)]$TerminalServer,
        [Parameter(Mandatory = $true)]$Services,
        [Parameter(Mandatory = $true)]$Schannel
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # --- RDP administratively denied -------------------------------------------------------------
    # The deny switch decides whether anything can connect at all, so an unreadable one must never
    # fall through to the affirmative "no fault was found". Reported rather than repaired: writing a
    # documented default over a value that was never read would be changing something unexamined.
    if (Test-ValueUnreadable -State $TerminalServer.BaseDeny) {
        [void]$findings.Add((New-Finding -Cause 'RdpDenyUnreadable' -Item 'fDenyTSConnections' -Hive 'SYSTEM' -Repairable $false `
                    -Message "fDenyTSConnections could not be read at $($TerminalServer.TerminalServerPath) even after taking the key, so whether remote connections are allowed is unknown. It was left alone. Check the permissions on that key from the rescue VM."))
    }
    elseif ($TerminalServer.BaseDeny.Found -and (ConvertTo-DwordInt32 -Value $TerminalServer.BaseDeny.Value) -ne 0) {
        [void]$findings.Add((New-Finding -Cause 'RdpDeniedBase' -Item 'fDenyTSConnections' -Hive 'SYSTEM' `
                    -Data $TerminalServer.BaseDeny.Value `
                    -Message "Remote connections are turned off at $($TerminalServer.TerminalServerPath) (fDenyTSConnections=$($TerminalServer.BaseDeny.Value)). Nothing can connect until this is 0."))
    }
    elseif (-not $TerminalServer.TerminalServerKeyPresent) {
        # A missing value and a missing key read the same way here: Get-OfflineValueState reports
        # Found=$false for both, because ItemNotFound is not an access denial. They are not the same
        # fault. Creating the value would create the whole Control\Terminal Server key with it, and
        # a machine that has no Terminal Server key has lost far more than one DWORD - the same
        # reason RdpListenerMissing below refuses to fabricate a listener. Report it and stop.
        [void]$findings.Add((New-Finding -Cause 'TerminalServerKeyMissing' -Item 'Terminal Server' -Hive 'SYSTEM' -Repairable $false `
                    -Message "The Terminal Server key is missing at $($TerminalServer.TerminalServerPath). Remote Desktop keeps all of its configuration under that key, so this is a damaged Windows installation rather than a setting to correct, and creating the key would only hide it. Check that the disk attached is the one that is broken and that its SYSTEM hive is intact."))
    }
    elseif (-not $TerminalServer.BaseDeny.Found) {
        # Absence is not the same as 0 here, which is why this is not left to the branch above.
        # Measured on a Windows Server marketplace image: with the service running and the value
        # simply deleted, port 3389 stopped listening altogether, while the Terminal Services WMI
        # provider still reported AllowTSConnections=1 - so the socket is the truth and the value
        # being missing really does refuse every connection. Writing 0 is a repair rather than a
        # guess at an unexamined value: the read succeeded and returned "not present", and 0 is
        # what Azure Windows images ship.
        [void]$findings.Add((New-Finding -Cause 'RdpDenyMissing' -Item 'fDenyTSConnections' -Hive 'SYSTEM' `
                    -Message "fDenyTSConnections is missing from $($TerminalServer.TerminalServerPath). Windows stops the listener when that value is absent, so nothing can connect even though the service is set to run. It will be created as 0, which is the value Azure Windows images ship."))
    }
    if (Test-ValueUnreadable -State $TerminalServer.PolicyDeny) {
        [void]$findings.Add((New-Finding -Cause 'RdpDenyPolicyUnreadable' -Item 'fDenyTSConnections (policy)' -Hive 'SOFTWARE' -Repairable $false `
                    -Message "The Group Policy copy of fDenyTSConnections could not be read even after taking the key. The policy copy overrides the Terminal Server key, so RDP may still be denied by it. It was left alone."))
    }
    elseif ($TerminalServer.PolicyDeny -and $TerminalServer.PolicyDeny.Found -and (ConvertTo-DwordInt32 -Value $TerminalServer.PolicyDeny.Value) -ne 0) {
        [void]$findings.Add((New-Finding -Cause 'RdpDeniedPolicy' -Item 'fDenyTSConnections (policy)' -Hive 'SOFTWARE' `
                    -Message "Group Policy turns remote connections off (fDenyTSConnections=$($TerminalServer.PolicyDeny.Value) under Policies\Microsoft\Windows NT\Terminal Services). The policy copy overrides the Terminal Server key, so this alone refuses every connection."))
    }

    # --- The listener -----------------------------------------------------------------------------
    if (-not $TerminalServer.ListenerPresent) {
        [void]$findings.Add((New-Finding -Cause 'RdpListenerMissing' -Item 'RDP-Tcp' -Hive 'SYSTEM' -Repairable $false `
                    -Message "The RDP-Tcp listener key is missing at $($TerminalServer.RdpTcpPath). Recreating a listener from nothing needs the Remote Desktop role reinstalled in the guest; this script will not fabricate one."))
    }
    else {
        foreach ($value in @($TerminalServer.Listener)) {
            # Denied is set by the helper the moment the first plain read is refused, BEFORE it takes
            # the key and reads again. A recovered read therefore arrives here with Denied true and
            # Found true, and testing Denied alone threw that recovered value away and skipped a
            # repair the script had the evidence to make. Only a read that was refused AND never
            # recovered is genuinely unreadable.
            if (Test-ValueUnreadable -State $value) {
                [void]$findings.Add((New-Finding -Cause 'ListenerValueUnreadable' -Item $value.Spec.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "$($value.Spec.Name) could not be read even after taking the key. It was left alone rather than overwritten with a documented default."))
                continue
            }
            if (-not $value.IsValid) {
                [void]$findings.Add((New-Finding -Cause 'ListenerValueInvalid' -Item $value.Spec.Name -Hive 'SYSTEM' -Data $value `
                            -Message "$($value.Spec.Name)=$($value.Value) is outside the documented set ($($value.Spec.Valid -join ', ')) - $($value.Spec.Purpose). Windows does not clamp this, so the listener cannot agree a session with any client. It will be set to $($value.Spec.DocValue)."))
            }
        }

        # Neither of the two values below is routed through Test-ValueUnreadable, and deliberately:
        # both live in the RDP-Tcp key alongside the four specs just scanned, so a key this script
        # cannot read raises ListenerValueUnreadable four times over and the run can never print the
        # healthy line from an unread value. Adding a fifth and sixth unreadable finding for the same
        # single cause would be noise. The cipher suite policy is the opposite case - it sits alone
        # in its own key with nothing correlated beside it - which is why that one is checked.

        # Step 8 of the Azure guidance. A pin whose private key no longer resolves fails the
        # handshake before authentication; removing it lets Windows generate a fresh certificate.
        # A pin is also how a valid custom certificate is configured, and the key cannot be resolved
        # offline to tell the two apart, so the pin is only removed when the operator asks for it.
        if ($TerminalServer.PinnedCertificate -and $TerminalServer.PinnedCertificate.Found) {
            $pinFinding = New-Finding -Cause 'ListenerCertificatePinned' -Item 'SSLCertificateSHA1Hash' -Hive 'SYSTEM' -Repairable $wantRemovePin `
                -Message 'A certificate is pinned to the listener (SSLCertificateSHA1Hash). If its private key no longer resolves the TLS handshake fails before authentication and the client reports a generic internal error; if it is a valid custom certificate, it is working configuration.'
            if ($wantRemovePin) { $pinFinding.Message += ' -removePinnedCertificate was passed, so the pin will be removed and Windows will generate a fresh self-signed listener certificate on the next start. If RDP still fails afterwards, the certificate store or the private key permissions are the problem and win-fix-rdp-certificate owns those.' }
            else { $pinFinding.Message += ' This script cannot resolve the private key offline, so the pin was reported, not removed. If the certificate is known to be missing or unusable, re-run with -removePinnedCertificate true; win-fix-rdp-certificate covers a certificate that is present but broken.' }
            [void]$findings.Add($pinFinding)
        }

        if ($TerminalServer.Port -and $TerminalServer.Port.Found -and (ConvertTo-DwordInt32 -Value $TerminalServer.Port.Value) -ne $script:StandardRdpPort) {
            $portFinding = New-Finding -Cause 'ListenerPortNonStandard' -Item 'PortNumber' -Hive 'SYSTEM' -Repairable $wantResetPort -Data $TerminalServer.Port `
                -Message "The listener is on port $($TerminalServer.Port.Value) rather than the documented $($script:StandardRdpPort)."
            if ($wantResetPort) { $portFinding.Message += " -resetListenerPort was passed, so it will be reset to $($script:StandardRdpPort)." }
            else { $portFinding.Message += " This was left alone in case the port was moved deliberately. Be aware the built-in 'Remote Desktop - User Mode (TCP-In)' rule only allows $($script:StandardRdpPort), so a moved port needs its own Windows Firewall rule and a matching NSG rule; without both, the listener starts and connections are still refused. Re-run with -resetListenerPort true to move it back." }
            [void]$findings.Add($portFinding)
        }
    }

    # Outside the listener branch on purpose. Three of the documented values live under the policy
    # key in SOFTWARE and do not need the RDP-Tcp listener to exist; nesting this inside the branch
    # made -applyAzureBaseline silently do nothing on exactly the broken machine it was passed for.
    # Get-TerminalServerState already drops the Listener-scoped specs when the listener is missing.
    if ($wantBaseline -and ((-not $TerminalServer.TerminalServerKeyPresent) -or (-not $TerminalServer.ListenerPresent))) {
        # The baseline is tuning, and it is not applied to a machine this script has just called a
        # damaged installation. TerminalServerKeyMissing above refuses to recreate Control\Terminal
        # Server precisely because its absence means far more is gone than one key; writing the three
        # Policy-scoped values into SOFTWARE regardless would leave documented Remote Desktop tuning
        # on a machine with no Remote Desktop configuration to tune, and Set-OfflineRdpDword would
        # create the policy key from nothing to do it.
        #
        # A missing RDP-Tcp listener is held to the same test, deliberately rather than by default.
        # RdpListenerMissing above characterises it the same way - a damaged installation needing the
        # role reinstalled in the guest - and Get-TerminalServerState already drops the five
        # Listener-scoped specs when it is gone. Without this the three Policy-scoped specs would
        # survive that drop and a run would create Policies\...\Terminal Services from nothing on a
        # machine whose listener this script has just declined to rebuild: a persistent Group Policy
        # key, written for a role that is not there. The two cases differ in degree - a missing
        # Control\Terminal Server takes the listener with it, whereas a missing RDP-Tcp still leaves
        # fDenyTSConnections readable and repairable - but not in kind, so they are answered alike.
        #
        # A finding, not a log line. The operator asked for the baseline explicitly, so being told it
        # was skipped belongs where they will see it: a log Warning is flushed above the FOUND list
        # and the summary, is emitted twice because this function runs in both the detect and the
        # verification pass, and counts in neither total - so the run would report a clean success
        # without ever mentioning that the thing that was asked for did not happen. Non-repairable,
        # which puts it in the [MANUAL] list on both exits and in the unrepairable count, and which
        # keeps it out of the verification pass's still-repairable filter. This is the same shape as
        # AzureBaselineUnreadable below, the other "a baseline value was not applied" case.
        $skipReason = if (-not $TerminalServer.TerminalServerKeyPresent) {
            "the Terminal Server key is missing at $($TerminalServer.TerminalServerPath)"
        }
        else { 'the RDP-Tcp listener key is missing' }
        [void]$findings.Add((New-Finding -Cause 'AzureBaselineSkipped' -Item 'Azure RDP baseline' -Hive 'SOFTWARE' -Repairable $false `
                    -Message "-applyAzureBaseline was passed, but $skipReason, so the baseline was NOT applied. Repair the installation first; a baseline written now would configure Remote Desktop settings on a machine that has none."))
    }
    elseif ($wantBaseline) {
        $unreadable = @($TerminalServer.Baseline | Where-Object { $_.Unreadable })
        foreach ($entry in $unreadable) {
            [void]$findings.Add((New-Finding -Cause 'AzureBaselineUnreadable' -Item $entry.Spec.Name -Hive $entry.Spec.Hive -Repairable $false `
                        -Message "$($entry.Spec.Name) could not be read at $($entry.Path) even after taking the key, so it was excluded from the baseline rather than overwritten with the documented $($entry.Spec.Value)."))
        }
        $drift = @($TerminalServer.Baseline | Where-Object { -not $_.Matches -and -not $_.Unreadable })
        if ($drift.Count -gt 0) {
            # The finding carries every hive it will write. The backup pass keys off that, and this
            # is the one finding that spans both, so a single Hive left SOFTWARE modified with no
            # backup taken of it.
            $driftHives = @($drift | ForEach-Object { $_.Spec.Hive } | Sort-Object -Unique)
            [void]$findings.Add((New-Finding -Cause 'AzureBaselineRequested' -Item 'Azure RDP baseline' -Hive $driftHives[0] -AlsoHive $driftHives -Data $drift `
                        -Message "-applyAzureBaseline was passed. $($drift.Count) of $(@($TerminalServer.Baseline).Count) documented Remote Desktop value(s) do not match the guidance and will be set: $(@($drift | ForEach-Object { "$($_.Spec.Name)=$(if ($_.Found) { $_.Value } else { '(not set)' })->$($_.Spec.Value)" }) -join ', ')."))
        }
    }

    # --- Services ---------------------------------------------------------------------------------
    foreach ($service in @($Services)) {
        if (-not $service.Exists) {
            # Only RDP's own services are worth reporting as missing. A missing Netlogon on a
            # workgroup VM is normal and is not this script's business.
            if (-not $service.Spec.Owner -and $service.Name -in @('TermService', 'SessionEnv', 'UmRdpService')) {
                [void]$findings.Add((New-Finding -Cause 'RdpServiceMissing' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "The $($service.Name) service key is missing ($($service.Spec.Purpose)). That is a damaged installation rather than a configuration fault, and this script will not create one."))
            }
            continue
        }
        # An unreadable Start is not a healthy Start. Without this the value silently defaulted to
        # $null, Disabled evaluated false, and a service whose key is locked against Administrators
        # was reported as fine. Same recovered-read rule as the listener values above.
        if ($service.Unreadable) {
            [void]$findings.Add((New-Finding -Cause 'RdpServiceStartUnreadable' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "The Start value of $($service.Name) could not be read even after taking the key ($($service.Spec.Purpose)). Its state is unknown, so it was reported rather than assumed healthy or overwritten."))
            continue
        }
        if ($service.Malformed) {
            [void]$findings.Add((New-Finding -Cause 'RdpServiceStartMalformed' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "The Start value of $($service.Name) was read but is not a number ($($service.Spec.Purpose)). Windows cannot act on it, so the service is neither demonstrably healthy nor demonstrably disabled. It was reported rather than overwritten, because a value of an unexpected type usually means the key was damaged by something other than a start-type change."))
            continue
        }
        if (-not $service.Disabled) { continue }

        if ($service.Spec.Owner) {
            # Names the documented start value as well as the owning scenario. The owner is a
            # pointer, not a promise: whether a given run-id is present depends on which scenarios
            # the library has, and directing an operator to one that az vm repair run rejects is
            # worse than directing them nowhere. With the value stated they can act either way.
            [void]$findings.Add((New-Finding -Cause 'DependencyServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). RDP cannot work while it is, but this script does not own the service and did not change it. Its documented start type is Start=$($service.Spec.DocStart) ($($service.Spec.Source)); the $($service.Spec.Owner) scenario covers it where that is available."))
        }
        elseif ($service.Spec.BaselineOnly -and -not $wantBaseline) {
            # Documented, but not in the listener path, so its startup type is not evidence that RDP
            # is broken. Reported, and restored only when the operator asks for the baseline.
            [void]$findings.Add((New-Finding -Cause 'RdpServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Repairable $false -Data $service `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). It is not in the RDP listener path, so it was reported, not changed. Its documented start type is Start=$($service.Spec.DocStart) ($($service.Spec.Source)); re-run with -applyAzureBaseline true to restore it."))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'RdpServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Data $service `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). It will be set to Start=$($service.Spec.DocStart), $($service.Spec.Source)."))
        }
    }

    # --- SCHANNEL ---------------------------------------------------------------------------------
    $unreadableSides = @($Schannel.Tls12 | Where-Object { $_.Unreadable -and -not $_.IsDisabled })
    if ($unreadableSides.Count -gt 0) {
        [void]$findings.Add((New-Finding -Cause 'Tls12Unreadable' -Item 'TLS 1.2' -Hive 'SYSTEM' -Repairable $false `
                    -Message "The TLS 1.2 setting for $(@($unreadableSides | ForEach-Object { $_.Side }) -join ' and ') could not be read even after taking the key, so whether TLS 1.2 is available is unknown. It was left alone rather than enabled blindly."))
    }

    $disabledSides = @($Schannel.Tls12 | Where-Object { $_.IsDisabled })
    if ($disabledSides.Count -gt 0) {
        [void]$findings.Add((New-Finding -Cause 'Tls12Disabled' -Item 'TLS 1.2' -Hive 'SYSTEM' -Data $disabledSides `
                    -Message "TLS 1.2 is explicitly disabled for $(@($disabledSides | ForEach-Object { $_.Side }) -join ' and ') - the side the RDP listener negotiates on, so this closes the handshake. The disabling value(s) will be reversed; TLS 1.0 and 1.1 are not touched."))
    }

    if ($Schannel.FunctionsUnreadable) {
        [void]$findings.Add((New-Finding -Cause 'CipherPolicyUnreadable' -Item 'Functions' -Hive 'SOFTWARE' -Repairable $false `
                    -Message "The machine-wide SSL cipher suite policy value at $($script:CipherPolicyPath) could not be read even after taking the key, so whether it lists any cipher suite is unknown. An empty list closes the handshake, so this was reported rather than assumed harmless; inspect the value by hand."))
    }
    elseif ($Schannel.FunctionsEmpty) {
        [void]$findings.Add((New-Finding -Cause 'CipherPolicyEmpty' -Item 'Functions' -Hive 'SOFTWARE' `
                    -Message 'The machine-wide SSL cipher suite policy is present but lists no cipher suites, which leaves nothing for the TLS handshake to agree on. The empty value will be removed so Windows uses its own list.'))
    }
    elseif ($wantClearCiphers -and $Schannel.Functions -and $Schannel.Functions.Found) {
        # Gated on the Functions VALUE, not on the key. The repair removes the value and leaves the
        # key behind, so testing the key made this finding survive its own successful repair: the
        # verification pass re-raised it and the run reported failure after doing exactly what was
        # asked. Every finding has to be able to go away once it has been repaired.
        [void]$findings.Add((New-Finding -Cause 'CipherPolicyClearRequested' -Item 'Functions' -Hive 'SOFTWARE' `
                    -Message "-clearCipherSuitePolicy was passed, so the machine-wide SSL cipher suite policy ($($Schannel.FunctionCount) suite(s)) will be removed and Windows will use its own list."))
    }

    # --- Requested security reduction --------------------------------------------------------------
    # Never discovered. It only exists because the operator asked for it by name.
    if ($wantDisableNla -and $TerminalServer.ListenerPresent) {
        $nla = @($TerminalServer.Listener | Where-Object { $_.Spec.Name -eq 'UserAuthentication' })
        # An unreadable value already raises ListenerValueUnreadable above, and is not overwritten
        # blind just because the operator asked for NLA off: its current state is unknown.
        $nlaUnreadable = ($nla.Count -gt 0 -and (Test-ValueUnreadable -State $nla[0]))
        if (-not $nlaUnreadable -and ($nla.Count -eq 0 -or -not $nla[0].Found -or (ConvertTo-DwordInt32 -Value $nla[0].Value) -ne 0)) {
            [void]$findings.Add((New-Finding -Cause 'NlaDisableRequested' -Item 'UserAuthentication' -Hive 'SYSTEM' `
                        -Message '-disableNla was passed, so Network Level Authentication will be turned off (UserAuthentication=0). The Azure guidance enables NLA, so this is a deliberate deviation from it: it lets a client reach the logon screen before authenticating. Turn it back on once the VM is reachable.'))
        }
    }

    return $findings.ToArray()
}

function Set-OfflineRdpDword {
    <#
    .SYNOPSIS
        Writes one DWORD, taking the key only if the ACL refuses, and logging what changed.

    .DESCRIPTION
        A hardened VM is exactly the kind of machine that ends up needing this script, and those are
        the machines whose Terminal Server key is locked against Administrators. The write is tried
        plainly first; the descriptor is only touched when it is actually refused, and is put back in
        a finally either way.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$NewValue,
        [Parameter(Mandatory = $true)][string]$Message,
        # Opt in, not opt out. New-Item -Force on every write meant any caller with a wrong or
        # unexpected path silently created a registry key instead of failing, and this script's whole
        # position on missing keys is that it does not fabricate them: TerminalServerKeyMissing and
        #         RdpListenerMissing both refuse to, and report a damaged installation instead. Only the
                # caller whose key is legitimately absent on a healthy machine passes this - the Azure
                # baseline writing into the Terminal Services policy key. Every other caller writes under a
                # key whose presence a finding has already established (the TLS 1.2 repair only reverses a
                # value it read), so for those a missing key is a fault, not a step.
        [Parameter(Mandatory = $false)][switch]$CreateKey
    )

    # MaxInstanceCount is 4294967295, which is a valid DWORD but not a valid Int32, so it has to be
    # reinterpreted rather than converted or Set-ItemProperty throws on the checked conversion.
    $typed = ConvertTo-DwordInt32 -Value $NewValue
    if ($null -eq $typed) {
        Add-OfflineRepairLog -Level Warning -Message "$Name was not written: '$NewValue' is not a DWORD."
        return $false
    }

    $create = $CreateKey.IsPresent
    # Ahead of the existence probe, so moving that probe out of the -Action block did not also move
    # it in front of the offline-target gate. Invoke-OfflineProtectedRegistryWrite asserts this
    # itself, but only once $Action is reached; a path outside the mounted image should be refused
    # as out of scope rather than reported as a missing key, whichever answer comes first.
    Assert-OfflineTarget -Path $Path -Action "write $Name"
    if (-not $create -and -not (Test-Path -LiteralPath $Path)) {
        # Answered before the write is attempted, not by throwing inside the -Action block.
        # Invoke-OfflineProtectedRegistryWrite rethrows anything its access-denied test does not
        # recognise, so a throw here escaped Set-OfflineRdpDword entirely: the per-value diagnostic
        # below never ran, and the two callers that write several values in a loop abandoned their
        # remaining iterations and discarded changes they had already made. Returning false keeps the
        # documented contract and lets a loop finish and report what it did manage.
        Add-OfflineRepairLog -Level Warning -Message "$Name was not written: the key $Path does not exist, and this value is not one that creates it."
        return $false
    }

    $outcome = Invoke-OfflineProtectedRegistryWrite -Path $Path -Description $Name -Action {
        if ($create -and -not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $typed -Type DWord -Force -ErrorAction Stop
    }

    if ($outcome.Written) { Add-OfflineRepairLog -Message $Message }
    else { Add-OfflineRepairLog -Level Warning -Message "$Name could not be written: $($outcome.Reason)" }
    return $outcome.Written
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Repairs one finding. Returns $true when something was actually changed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $rdpPath = Join-Path $SystemRoot $script:RdpTcpSubPath

    switch -Regex ($Finding.Cause) {

        '^(RdpDeniedBase|RdpDenyMissing)$' {
            $path = Join-Path $SystemRoot $script:TerminalServerSubPath
            # RdpDeniedBase fires on any non-zero value, not just 1, so the audit line reports the
            # value actually found rather than assuming it. A value that would not convert to a
            # DWORD also reaches here, and prints as whatever was read.
            $what = if ($Finding.Cause -eq 'RdpDenyMissing') { 'absent' } else { "$($Finding.Data)" }
            return (Set-OfflineRdpDword -Path $path -Name 'fDenyTSConnections' -NewValue 0 `
                    -Message "fDenyTSConnections $what -> 0 on the Terminal Server key, so remote connections are allowed again.")
        }

        '^RdpDeniedPolicy$' {
            return (Set-OfflineRdpDword -Path $script:TerminalServerPolicyPath -Name 'fDenyTSConnections' -NewValue 0 `
                    -Message 'fDenyTSConnections 1 -> 0 on the Group Policy copy, which overrides the Terminal Server key.')
        }

        '^RdpServiceDisabled$' {
            $service = $Finding.Data
            return (Set-OfflineRdpDword -Path $service.Path -Name 'Start' -NewValue $service.Spec.DocStart `
                    -Message "$($service.Name): Start 4 (Disabled) -> $($service.Spec.DocStart), $($service.Spec.Source).")
        }

        '^ListenerValueInvalid$' {
            $value = $Finding.Data
            return (Set-OfflineRdpDword -Path $rdpPath -Name $value.Spec.Name -NewValue $value.Spec.DocValue `
                    -Message "$($value.Spec.Name): $($value.Value) -> $($value.Spec.DocValue) (was outside the documented set).")
        }

        '^ListenerPortNonStandard$' {
            if (-not $wantResetPort) { return $false }
            return (Set-OfflineRdpDword -Path $rdpPath -Name 'PortNumber' -NewValue $script:StandardRdpPort `
                    -Message "PortNumber $($Finding.Data.Value) -> $($script:StandardRdpPort), as requested by -resetListenerPort.")
        }

        '^ListenerCertificatePinned$' {
            if (-not $wantRemovePin) { return $false }
            $outcome = Invoke-OfflineProtectedValueRemoval -Path $rdpPath -Name 'SSLCertificateSHA1Hash' -StillSet {
                param($Current)
                return ($null -ne $Current)
            }
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "The pinned listener certificate was removed, so Windows generates a fresh self-signed one on the next start. $($outcome.Reason)"
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The pinned listener certificate could not be removed: $($outcome.Reason)"
            return $false
        }

        '^Tls12Disabled$' {
            $changed = $false
            # Only the value that actually disables TLS 1.2 is reversed. The key exists (a value was
            # read from it), and a value that is absent or already permissive is left exactly as found,
            # so a machine whose only fault is Enabled=0 does not also gain a DisabledByDefault entry.
            foreach ($side in @($Finding.Data)) {
                if ($side.Enabled.Found -and (ConvertTo-DwordInt32 -Value $side.Enabled.Value) -eq 0) {
                    if (Set-OfflineRdpDword -Path $side.Path -Name 'Enabled' -NewValue 1 -Message "TLS 1.2 $($side.Side): Enabled 0 -> 1.") { $changed = $true }
                }
                if ($side.DisabledByDefault.Found -and (ConvertTo-DwordInt32 -Value $side.DisabledByDefault.Value) -eq 1) {
                    if (Set-OfflineRdpDword -Path $side.Path -Name 'DisabledByDefault' -NewValue 0 -Message "TLS 1.2 $($side.Side): DisabledByDefault 1 -> 0.") { $changed = $true }
                }
            }
            return $changed
        }

        '^AzureBaselineRequested$' {
            $changed = $false
            foreach ($item in @($Finding.Data)) {
                $was = $(if ($item.Found) { $item.Value } else { '(not set)' })
                # Scoped, not blanket: the five Listener-scoped values write under RDP-Tcp, whose
                # presence Get-TerminalServerState has already established, so a missing key there is
                # a fault. Only the three Policy-scoped values write into the Terminal Services
                # policy key, which a machine that has never had the policy applied legitimately
                # does not have.
                if (Set-OfflineRdpDword -Path $item.Path -Name $item.Spec.Name -NewValue $item.Spec.Value -CreateKey:($item.Spec.Scope -eq 'Policy') `
                        -Message "$($item.Spec.Name): $was -> $($item.Spec.Value) ($($item.Spec.Purpose), per the Azure guidance).") { $changed = $true }
            }
            return $changed
        }

        '^(CipherPolicyEmpty|CipherPolicyClearRequested)$' {
            $outcome = Invoke-OfflineProtectedValueRemoval -Path $script:CipherPolicyPath -Name 'Functions' -StillSet {
                param($Current)
                return ($null -ne $Current)
            }
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "The machine-wide SSL cipher suite policy was removed, so Windows uses its own list. $($outcome.Reason)"
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The cipher suite policy could not be removed: $($outcome.Reason)"
            return $false
        }

        '^NlaDisableRequested$' {
            return (Set-OfflineRdpDword -Path $rdpPath -Name 'UserAuthentication' -NewValue 0 `
                    -Message 'UserAuthentication -> 0, so Network Level Authentication is off. This was requested with -disableNla and should be turned back on once the VM is reachable.')
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

# The caller contract in common\helpers\README.md: seed the status, then return it AFTER the
# finally, so the marker the caller parses stays at the end of the output. $STATUS_SUCCESS is a
# plain string written to the output stream, and Run Command keeps only the tail of a 4096-character
# log, so a status emitted before a long cleanup flush can be pushed out of the retained window.
# A bare `return` inside the try would exit the script and skip that trailing return, hence the
# labelled do/while: `break main` leaves the body, runs the finally, and falls through to it.
# A bare `break` or `continue` written at this level binds to :main and would abandon the backup,
# repair and verification passes, so any loop added inside this block must label its own exits.
$status = $STATUS_ERROR

try {
    # Inside the try, per the caller contract in common\helpers\README.md: a helper that fails to
    # load is caught, logged and returned as an error rather than escaping as a raw exception.
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
    . .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

    :main do {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "Target values follow $($script:DocUrl)" | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
        $terminalServer = Get-TerminalServerState -SystemRoot $systemRoot
        $services = Get-RdpServiceState -SystemRoot $systemRoot
        $schannel = Get-SchannelState -SystemRoot $systemRoot

        return [PSCustomObject]@{
            ControlSet     = (Split-Path -Path $systemRoot -Leaf)
            TerminalServer = $terminalServer
            Services       = @($services)
            Schannel       = $schannel
            Findings       = @(Get-AllFinding -TerminalServer $terminalServer -Services $services -Schannel $schannel)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    $ts = $context.TerminalServer
    Log-Info "Control set $($context.ControlSet)." | Tee-Object -FilePath $logFile -Append
    # "(not set)" would be actively misleading when the whole Terminal Server key is gone: it reads
    # as one absent DWORD under a key that exists, which is a different and much smaller fault than
    # the one TerminalServerKeyMissing reports. Get-OfflineValueState answers Found=$false for both,
    # so the distinction has to be made from the key's own presence flag.
    $baseDenyShown = if (-not $ts.TerminalServerKeyPresent) { '(no Terminal Server key)' } else { Format-ValueForLog -State $ts.BaseDeny }
    Log-Info "Terminal Server: fDenyTSConnections=$baseDenyShown, Group Policy copy $(if (Test-ValueUnreadable -State $ts.PolicyDeny) { '(unreadable)' } elseif ($ts.PolicyDeny -and $ts.PolicyDeny.Found) { "= $($ts.PolicyDeny.Value)" } else { 'not configured' })." | Tee-Object -FilePath $logFile -Append

    if ($ts.ListenerPresent) {
        foreach ($value in @($ts.Listener)) {
            $shown = if (Test-ValueUnreadable -State $value) { '(unreadable)' } elseif ($value.Found) { $value.Value } else { '(not set, Windows default)' }
            Log-Info "  RDP-Tcp $($value.Spec.Name) = $shown - $($value.Spec.Purpose)." | Tee-Object -FilePath $logFile -Append
        }
        Log-Info "  RDP-Tcp PortNumber = $(Format-ValueForLog -State $ts.Port)." | Tee-Object -FilePath $logFile -Append
    }

    $disabledServices = @($context.Services | Where-Object { $_.Disabled })
    Log-Info "Services: $(@($context.Services | Where-Object { $_.Exists }).Count) of $(@($context.Services).Count) required service key(s) present, $($disabledServices.Count) disabled." | Tee-Object -FilePath $logFile -Append
    foreach ($service in @($context.Services)) {
        # The raw value, not Format-ValueForLog: that helper takes a read-state object and asks it
        # whether the value was found, and the only thing worth printing here is the value itself.
        $shown = if (-not $service.Exists) { 'no service key' } elseif ($service.Unreadable) { '(unreadable)' } elseif ($service.Malformed) { "(Start is not a number: $($service.Value))" } elseif (-not $service.Found) { '(Start not set)' } else { "Start=$($service.Start)" }
        Log-Info "  $($service.Name): $shown, $($service.Spec.Source)." | Tee-Object -FilePath $logFile -Append
    }

    # Presence is normal here and is stated as such, so nobody reads this line as a fault.
    if ($context.Schannel.CipherPresent) {
        # Distinguishes "the key is there but sets no list" from "the key lists N suites". Testing
        # Found alone is not enough: a Functions value that exists and is empty satisfies it, and
        # that case IS the CipherPolicyEmpty fault, so the healthy sentence was printed a few lines
        # above the finding that removes the value. The suite count is what separates them.
        if ($context.Schannel.Functions -and $context.Schannel.Functions.Found -and $context.Schannel.FunctionCount -gt 0) {
            Log-Info "A machine-wide SSL cipher suite policy is configured with $($context.Schannel.FunctionCount) suite(s). That is normal on an Azure image and was not treated as a fault." | Tee-Object -FilePath $logFile -Append
        }
        elseif ($context.Schannel.FunctionsEmpty) {
            Log-Info 'A machine-wide SSL cipher suite policy is present but lists no cipher suites, which leaves nothing for the TLS handshake to agree on. That is a fault and is reported below.' | Tee-Object -FilePath $logFile -Append
        }
        elseif ($context.Schannel.FunctionsUnreadable) {
            Log-Info 'The machine-wide SSL cipher suite policy key exists but its suite list could not be read, so whether it is empty is unknown. It was reported rather than assumed normal.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info 'The machine-wide SSL cipher suite policy key exists but sets no suite list, so Windows uses its own. That is normal on an Azure image and was not treated as a fault.' | Tee-Object -FilePath $logFile -Append
        }
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    # Ahead of the detectOnly gate on purpose, so one affirmative line serves both modes. Behind it,
    # a healthy disk and one this script cannot help would both report nothing but a count, and the
    # reader could not tell which had happened.
    if ($findings.Count -eq 0) {
        Log-Output 'No Remote Desktop fault was found. Remote connections are allowed, the listener and its services are configured for them, and TLS 1.2 is available. No configuration was changed; where a descriptor had to be borrowed to read a locked object it was put back.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No configuration was changed; where a descriptor had to be borrowed to read a locked object it was put back." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    # Back up every hive that is actually about to be written.
    $hivesToWrite = @($repairable | ForEach-Object { $_.Hives } | Sort-Object -Unique)
    foreach ($hive in $hivesToWrite) {
        $backup = Backup-OfflineHiveFile -Hive $hive -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "$hive hive backed up to $backup" | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = 0
    $failed = @()

    if ($repairable.Count -gt 0) {
        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($finding in $repairable) {
                try {
                    if (Repair-Finding -Finding $finding -SystemRoot $systemRoot) {
                        $done++
                    }
                    else {
                        # A repair that returns false rather than throwing was previously neither
                        # counted nor recorded, so a run could report success for work it did not do.
                        [void]$errors.Add("$($finding.Item): the repair reported that it changed nothing.")
                        Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
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

        $repairedCount = $repairOutcome.Repaired
        $failed = @($repairOutcome.Errors)
    }

    # Verify against freshly read state rather than trusting the writes above. Guarded the same way
    # the repair pass is: on a run where nothing was repairable, nothing was backed up and nothing
    # was written, so re-reading proves nothing that detection has not already established. Mounting
    # both hives a third time for that would be pure exposure - Invoke-WithHive throws if a hive
    # will not unload, and the outer catch would turn an accurate "nothing here I can fix" into a
    # reported failure on a run that touched the disk only to read it.
    $remaining = @()
    if ($repairable.Count -gt 0) {
        $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
            return @(Get-AllFinding `
                        -TerminalServer (Get-TerminalServerState -SystemRoot $systemRoot) `
                        -Services (Get-RdpServiceState -SystemRoot $systemRoot) `
                        -Schannel (Get-SchannelState -SystemRoot $systemRoot))
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Piping $null sends one $null object down the pipeline rather than nothing at all. Only the
    # positive filter below reads a property today, and $null.Repairable is falsy, so nothing is
    # currently mis-reported here. The guard is kept so that a filter written the other way round -
    # "-not $_.Repairable", which produced an empty warning line in the sibling certificate script -
    # can be added safely.
    $remaining = @($remaining | Where-Object { $null -ne $_ })

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported." }

    # Ahead of the failure gate on purpose, so both exits carry it. Behind it, a run that repaired
    # some findings and failed others printed only the count of the ones needing a decision, and
    # never said which - on exactly the run an engineer reads most carefully. The messages the
    # operator needs are then in the last 4096 characters on both paths, which is all
    # az vm run-command keeps.
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($failed.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($failed.Count) repair(s) failed and $($stillRepairable.Count) issue(s) are still present." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_ERROR
        break main
    }

    if ($repairedCount -gt 0) {
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    }
    # Printed after the [MANUAL] list for the same reason the detect summary is: az vm run-command
    # keeps only the last 4096 characters, so a summary printed first is what a long run loses.
    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    $status = $STATUS_SUCCESS
    } while ($false)
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    $status = $STATUS_ERROR
}
finally {
    # The caller contract in common\helpers\README.md. On a throw the buffered helper entries are
    # the ones that say WHY - which hive refused to unload, which file was missing - and without
    # this they were discarded and only the exception survived. A dependency may have failed to
    # load before either function existed, hence the guards.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        try {
            Clear-OfflineDriveLetter
            if ((Get-Command Get-OfflineAssignedDriveLetter -ErrorAction SilentlyContinue) -and @(Get-OfflineAssignedDriveLetter).Count -gt 0) {
                $status = $STATUS_ERROR
                Add-OfflineRepairLog -Level Error -Message 'Temporary drive letters remain assigned. The registry repair may have completed, but cleanup is incomplete; inspect the cleanup diagnostics before swapping the disk back.'
            }
        }
        catch {
            $status = $STATUS_ERROR
            Add-OfflineRepairLog -Level Error -Message "Drive-letter cleanup failed: $($_.Exception.Message)"
        }
    }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        try {
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append -ErrorAction Stop
        }
        catch {
            $status = $STATUS_ERROR
            Log-Error "Final helper diagnostics could not be written to the detail log: $($_.Exception.Message)"
        }
    }
}

return $status
