#########################################################################################################
#
# .SYNOPSIS
#   Restores network connectivity on an offline disk, so an Azure VM that boots but cannot be
#   reached - no RDP, no agent heartbeat, "VM status not available" - comes back on the network.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   A VM can complete boot and still be completely unreachable. The guest is running, the disk is
#   healthy and nothing is corrupt - the networking configuration simply describes a machine that
#   cannot talk to an Azure virtual network. There is no error on screen, because from the guest's
#   point of view nothing failed. Boot diagnostics show a normal logon screen and the VM answers
#   nothing.
#
#   Four configurations produce that, and all four are readable and repairable offline:
#
#     1. A core networking service or driver is disabled (Start=4). Tcpip, NDIS, Afd, nsi and Dhcp
#        are load-bearing; with any of them disabled the TCP/IP stack does not come up at all. This
#        is usually the result of a "performance tuning" script, a hardening baseline applied too
#        broadly, or a Group Policy service preference that was aimed at a different tier. Eight of
#        the services checked - LanmanServer, Tcpip6, ndiscap, WinHttpAutoProxySvc, NdisWan, wanarp,
#        tunnel and IpNat - are commonly disabled on purpose as hardening and are not needed for the
#        VM to be reachable, so a disabled one is reported and left alone.
#
#     2. An interface has EnableDHCP=0. Azure assigns every NIC its address by DHCP and only
#        delivers traffic for the address the fabric allocated to that NIC, so a static address,
#        mask or gateway carried over from somewhere else leaves the VM unreachable. This is the
#        classic failure after an on-premises migration, a disk restored from a different
#        environment, or a capture-and-redeploy of a VM whose NIC was manually configured. The
#        address is not compared with the one Azure allocated, because that is not recorded on the
#        disk, so every interface with EnableDHCP=0 is returned to DHCP. That includes a deliberate
#        static configuration such as secondary IP addresses, a loopback adapter used for a
#        load-balancer floating IP or a Hyper-V virtual switch adapter. Run detectOnly=true first
#        when the VM might carry one of those.
#
#     3. A network provider is registered whose DLL is gone. Winlogon loads every provider named in
#        NetworkProvider\Order during logon and waits on it, so a stale entry left behind by a
#        partially uninstalled VPN or endpoint client hangs the session at "Please wait for the
#        Network Connections" indefinitely. The network itself is fine; nobody can log on to use it.
#
#     4. A machine-wide proxy or PAC URL is configured that the VM cannot reach. Every outbound
#        request that uses it times out, so the VM can look dead to the platform while the network is
#        technically up. Only the machine-wide Internet Settings in the SOFTWARE hive are read; the
#        WinHTTP proxy and the LocalSystem account's own proxy settings are not checked.
#
#   The first three are repaired by default. The proxy is reported but only cleared when asked for
#   by name, because a configured proxy is not by itself evidence of a fault - plenty of VMs are
#   meant to egress through one, and clearing it on those makes things worse rather than better.
#
#   Static DNS is treated the same way, and that decision came from measurement rather than from
#   theory. A healthy, fully reachable Azure VM was examined before this script was written and it
#   carried a NameServer on its active interface, set because the virtual network hands out a custom
#   DNS server. Clearing static DNS by default would have broken name resolution on exactly the
#   machines that had it configured correctly, and on a domain-joined VM pointing at a domain
#   controller it would be worse than the fault being repaired. It is reported, and cleared only
#   when clearStaticDns is passed.
#
#   That same VM also showed why NameServer on its own does not mean "overridden". Its NameServer
#   and its DhcpNameServer held the identical value, because the address it was configured with was
#   the one DHCP had already supplied. So the two are compared rather than just testing NameServer
#   for content: matching the DHCP-supplied list is called out as agreeing with DHCP and is not
#   offered for clearing, and only a NameServer that genuinely differs from DhcpNameServer is
#   treated as an override worth a second look. Without that comparison every VM on a virtual
#   network with custom DNS would be told it had a static DNS problem.
#
#   Nothing is restored to a guessed value. The Start value each service is returned to was read off
#   a healthy Server 2022 image rather than assumed, because these services do not share one: Tcpip
#   and NDIS are boot-start drivers (0), Afd and NetBT are system-start (1), Dhcp and Dnscache are
#   auto-start services (2), and netvsc - the synthetic adapter every Azure VM depends on - is
#   demand-start (3). Setting them all to "automatic", which is the obvious repair, misconfigures
#   the kernel drivers and produces a VM that still has no network.
#
#   Only Start=4 is treated as evidence. A service sitting at any other value is left exactly as it
#   is, so a deliberately demand-started service is never "corrected" into something else.
#
#   The SYSTEM and SOFTWARE hives are backed up before either is written to, by a repair or by a
#   revert, and every change is recorded in a manifest on the offline disk so revert=true can put it
#   back. The manifest is untrusted input on the way back in: every entry is checked against the
#   names this script itself writes, registry paths are rebuilt rather than read from it, and a
#   manifest with any entry that fails those checks is refused as a whole and nothing is written.
#
# .RESOLVES
#   A VM that boots normally but cannot be reached by RDP or SSH, a VM whose guest agent reports
#   "not ready" or "VM status not available" while the guest is running, a VM with no IP address or
#   an address the portal does not recognise, a VM that lost its network after a hardening baseline
#   or tuning script was applied, a migrated or restored VM that has never been reachable in Azure,
#   and a VM that connects but hangs at "Please wait for the Network Connections" during logon.
#
# .PARAMETER detectOnly
#   "true" to report the networking state and what would be changed, and make no repairs. The
#   SYSTEM and SOFTWARE hives are still loaded so they can be read, which can let Windows apply a
#   hive's pending transaction log. With revert=true, lists what would be restored and loads and
#   writes nothing. Defaults to "false".
#
# .PARAMETER clearStaticDns
#   "true" to also clear statically configured DNS servers, per interface and globally, so the VM
#   takes its DNS from DHCP. Defaults to "false", because static DNS is a normal and often required
#   configuration - see the note above. Pass this only when name resolution is known to be the
#   problem and the configured servers are known to be unreachable.
#
# .PARAMETER clearProxy
#   "true" to also disable the machine-wide proxy and remove any PAC URL, in both the 64-bit and
#   32-bit Internet Settings. Defaults to "false". Pass this when the VM is known to have no route
#   to the configured proxy.
#
# .PARAMETER revert
#   "true" to undo what a previous run of this script changed, using the manifest it left on the
#   offline disk. The manifest is deleted only when every entry in it was restored. Defaults to
#   "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached Windows installation, for example "F:". Detected automatically
#   when not supplied.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-network-connectivity --run-on-repair --parameters detectOnly=true
#
#   Reports every networking fault found on the attached disk and changes nothing.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-network-connectivity --run-on-repair
#
#   Re-enables the disabled networking services that reachability depends on, returns every
#   interface with EnableDHCP=0 to DHCP and removes orphaned network providers.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-network-connectivity --run-on-repair --parameters clearProxy=true clearStaticDns=true
#
#   As above, and additionally clears the machine proxy and any statically configured DNS servers.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-network-connectivity --run-on-repair --parameters revert=true
#
#   Puts back everything the previous run changed.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-network-connectivity --run-on-repair --parameters windowsDrive=F
#
#   Repairs the Windows installation on F: instead of the automatically detected one. Only needed
#   when more than one Windows installation is attached to the repair VM.
#
# .NOTES
#   Not ported from the source material, on purpose:
#
#     * Removal of orphaned NDIS binding components. The source enumerates
#       Control\Class\{4D36E973/4/5}\NNNN looking for components whose driver binary is missing and
#       removes them. That was measured against a real Server 2022 image and those keys hold no
#       ComponentId at all - all 28 network components live under Control\Network\<class>\<instance>
#       instead, so the detection finds nothing to act on. Worse, the rule that identifies a
#       component as third party is a "ms_" prefix on the ComponentId, and the single component on a
#       stock Azure image that does not carry that prefix is "netvsc_vfpp", the NetVsc Failover VF
#       Protocol - the Microsoft component that Accelerated Networking depends on. A removal routine
#       that cannot be exercised against a genuine orphan, and whose one live candidate is the
#       component that must never be removed, does not belong in a script that runs unattended.
#
#     * The deferred "netsh int ip reset / winsock reset / advfirewall reset" run, staged by setting
#       SetupType and CmdLine so it executes on the next boot. netsh advfirewall reset discards every
#       custom firewall rule on the VM, which on a production machine is a larger and less reversible
#       change than the fault being repaired, and none of it can be verified from the offline disk -
#       the run either worked or it did not, and the operator finds out by whether the VM comes back.
#       The registry-level repairs here address the same causes directly and can be reverted.
#
#   Known residue after returning an interface to DHCP:
#
#     If Windows had already applied the static address itself, rather than the address only being
#     present in the registry, a default route to the old static gateway remains in the persistent
#     route store and survives reboots. This was measured: a repaired VM came back on its DHCP
#     address with working connectivity and still listed the old gateway as a second default route.
#     It is inert, because Windows gives the DHCP route the better metric and routes through it, and
#     the VM is reachable.
#
#     It is not removed here. The whole of CurrentControlSet was scanned for the address, as text and
#     as raw bytes, and it is not there - the persistent route lives in NSI state this script cannot
#     read from the offline hives, and the on-disk format is undocumented binary. Editing that blind
#     to tidy a route that does not block traffic would risk the routing table to fix a cosmetic
#     problem. The repair reports it instead, with the command that clears it once the VM is up.
#
#   Relationship to win-dhcp-fix: that script sets Start, Type and ObjectName on the DHCP client
#   service itself, in both control sets. This one covers the whole "VM has no network" scenario -
#   the DHCP service is one of twenty-six services it checks, and it also handles the interface
#   configuration, network providers and proxy that win-dhcp-fix does not look at. Run this one when
#   the symptom is "the VM is unreachable"; win-dhcp-fix remains the narrower, more targeted fix when
#   the DHCP client service is known to be the only problem.
#
#   Switch-style parameters are declared as strings because az vm repair passes every parameter as a
#   name/value pair, which a PowerShell [switch] cannot accept.
#
#   Only the active control set is modified. The Start values used for restoration were measured on
#   Windows Server 2022 build 20348.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$clearStaticDns = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$clearProxy = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$doClearStaticDns = ($clearStaticDns -eq 'true')
$doClearProxy = ($clearProxy -eq 'true')

# The networking services and drivers whose absence breaks connectivity, with the Start value each
# one carries on a healthy Windows Server 2022 image.
#
# The values were read off a running, reachable VM rather than written from memory, because they are
# not uniform and the differences matter. Tcpip, NDIS and WfpLwfs are boot-start kernel drivers (0);
# Afd, NetBT, nsiproxy and ndiscap are system-start drivers (1); the client services are auto-start
# (2); and netvsc, the synthetic NIC driver every Azure VM depends on, is demand-start (3), loaded by
# PnP when the VMBus device appears. Setting the whole set to "automatic" - the obvious repair -
# gives a kernel driver a service start type and leaves the VM with no network for a second reason.
#
# Only Start=4 is treated as a fault. Any other value is left alone, so a service that is legitimately
# demand-started is never rewritten into something it was not.
$script:NetworkService = [ordered]@{
    # Boot-start kernel drivers - the stack does not exist without these.
    'Tcpip'               = 0
    'NDIS'                = 0
    'WfpLwfs'             = 0
    # System-start drivers.
    'Afd'                 = 1
    'NetBT'               = 1
    'nsiproxy'            = 1
    'ndiscap'             = 1
    # Auto-start services.
    'nsi'                 = 2
    'Dhcp'                = 2
    'Dnscache'            = 2
    'NlaSvc'              = 2
    'BFE'                 = 2
    'mpssvc'              = 2
    'LanmanWorkstation'   = 2
    'LanmanServer'        = 2
    'RpcSs'               = 2
    'DcomLaunch'          = 2
    'RpcEptMapper'        = 2
    # Demand-start, loaded on need. netvsc is the Azure synthetic adapter.
    'netvsc'              = 3
    'Tcpip6'              = 3
    'netprofm'            = 3
    'WinHttpAutoProxySvc' = 3
    'NdisWan'             = 3
    'wanarp'              = 3
    'tunnel'              = 3
    'IpNat'               = 3
}

# Services that are load-bearing rather than merely useful. Reported separately so an operator can
# see at a glance whether the finding explains a total loss of connectivity or a partial one.
$script:CriticalService = @('Tcpip', 'NDIS', 'Afd', 'nsi', 'nsiproxy', 'netvsc', 'Dhcp', 'RpcSs', 'DcomLaunch', 'BFE', 'mpssvc')

# Services that are commonly disabled on purpose - to turn off the SMB server, IPv6, packet capture,
# WPAD or RAS - and that the VM does not need in order to be reachable. A disabled one is reported
# and never re-enabled, because turning it back on would undo a deliberate hardening choice.
$script:ReportOnlyService = @('LanmanServer', 'Tcpip6', 'ndiscap', 'WinHttpAutoProxySvc', 'NdisWan', 'wanarp', 'tunnel', 'IpNat')

# The per-interface values that describe a static address. Removed when an interface is returned to
# DHCP, because leaving them behind means the stack has both a DHCP instruction and a hard-coded
# address to reconcile.
$script:StaticAddressValue = @('IPAddress', 'SubnetMask', 'DefaultGateway', 'DefaultGatewayMetric')

# Network providers shipped with Windows. Never removed, even if the DLL underneath them appears to
# be missing: a missing Microsoft provider DLL is component-store damage, and quietly deleting the
# reference to it hides that rather than repairing it. Only third-party leftovers are removed.
$script:BuiltInProvider = @('LanmanWorkstation', 'RDPNP', 'webclient', 'P9NP', 'CscNetProvider')

# The machine-wide proxy settings, in both the 64-bit and 32-bit views.
$script:ProxySubKey = @(
    'Microsoft\Windows\CurrentVersion\Internet Settings',
    'Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings'
)
$script:ProxyValue = @('ProxyServer', 'ProxyOverride', 'AutoConfigURL')

# The marker a DNS manifest entry uses for the stack-wide NameServer rather than one interface.
$script:GlobalDnsTarget = 'Tcpip\Parameters (global)'

# What a revert manifest may contain. It is read back off a disk that has been out of this script's
# hands, so every field is checked against what this script itself records before anything in it is
# written to the registry.
$script:ManifestMaxBytes = 1MB
$script:RestorableKind = @('String', 'ExpandString', 'MultiString', 'DWord')
$script:InterfaceKeyPattern = '^\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}\z'
$script:InterfaceValuePattern = '^[0-9A-Fa-f.:]*\z'
$script:DnsValuePattern = '^[0-9A-Fa-f.:, ;]*\z'
$script:ProviderOrderPattern = '^[A-Za-z0-9_ .,()&+\-]*\z'

function New-Finding {
    <#
    .SYNOPSIS
        One piece of evidence that the offline disk cannot network.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $false)][bool]$Critical = $false,
        # An observation worth printing that is not a fault. It is kept out of the fault count so a
        # healthy disk is still reported as healthy.
        [Parameter(Mandatory = $false)][bool]$Informational = $false
    )

    return [PSCustomObject]@{
        Kind          = $Kind
        Target        = $Target
        Detail        = $Detail
        Critical      = $Critical
        Informational = $Informational
    }
}

function Resolve-OfflineSystemPath {
    <#
    .SYNOPSIS
        Turns a path recorded in the offline registry into a path on the attached disk.

    .DESCRIPTION
        A registry path such as "%SystemRoot%\System32\drprov.dll" expands, on the rescue VM, against
        the rescue VM's own Windows directory - which exists and is healthy, so the file is found and
        a genuine orphan is reported as fine. Every form has to be redirected at the offline
        installation instead.

        An unrecognised form returns $null, which callers treat as "cannot be evaluated" and skip. A
        path this function does not understand is not evidence of anything, and guessing at it would
        mean removing a working provider because its path was written in a way not anticipated here.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $value = $Path.Trim().Trim('"')
    if ($value -match '^\\\?\?\\(.+)$') { $value = $Matches[1] }

    # \SystemRoot\System32\x.dll
    if ($value -match '^\\SystemRoot\\(.+)$') { return (Join-Path $WindowsPath $Matches[1]) }

    # %SystemRoot%\x or %windir%\x
    if ($value -match '^%(?:SystemRoot|windir)%\\(.+)$') { return (Join-Path $WindowsPath $Matches[1]) }

    # C:\Windows\System32\x.dll - any drive letter, redirected at the offline Windows directory.
    if ($value -match '^[A-Za-z]:\\[Ww][Ii][Nn][Dd][Oo][Ww][Ss]\\(.+)$') { return (Join-Path $WindowsPath $Matches[1]) }

    # A bare file name is resolved by the loader from System32.
    if ($value -notmatch '[\\/]') { return (Join-Path $WindowsPath "System32\$value") }

    return $null
}

function Get-OfflineValueKind {
    <#
    .SYNOPSIS
        Reads the registry type of a value, so it can be written back as what it was.

    .DESCRIPTION
        IPAddress and DefaultGateway are REG_MULTI_SZ while NameServer is REG_SZ. Restoring a
        multi-string as a string produces a value the TCP/IP stack cannot parse, so the revert has to
        record the type alongside the data rather than infer it later.

        Returns $null when the type cannot be read. Callers leave that value where it is rather than
        removing data whose type they could not record, because guessing REG_SZ for a multi-string
        would make the revert write back something the stack cannot use.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $key.GetValueKind($Name).ToString()
    }
    catch {
        return $null
    }
}

function Get-NetworkServiceState {
    <#
    .SYNOPSIS
        Reads the Start value of every networking service. Must be called with SYSTEM mounted.
    #>
    param([switch]$Strict)

    $root = Get-OfflineSystemRootPath -Strict:$Strict
    $state = [System.Collections.Generic.List[object]]::new()

    foreach ($name in $script:NetworkService.Keys) {
        $path = "$root\Services\$name"
        if (-not (Test-Path $path)) {
            # Not every service exists on every SKU or build. An absent service is not a fault and is
            # not reported as one.
            continue
        }

        $current = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Start
        [void]$state.Add([PSCustomObject]@{
                Service    = $name
                Start      = if ($null -eq $current) { -1 } else { [int]$current }
                Expected   = [int]$script:NetworkService[$name]
                Critical   = ($script:CriticalService -contains $name)
                ReportOnly = ($script:ReportOnlyService -contains $name)
            })
    }

    return $state
}

function Test-SameDnsList {
    <#
    .SYNOPSIS
        Says whether two DNS server lists name the same servers.
    .DESCRIPTION
        NameServer and DhcpNameServer are both flat strings, and the same pair of servers can be
        written with commas or spaces between them and in either order. Comparing the raw strings
        would call those different and report a static DNS override that is not one, so both sides
        are split, trimmed, sorted and compared as sets. Two empty lists are not a match, because
        "neither is configured" is not the same statement as "these agree".
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$First,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Second
    )

    $split = {
        param($text)
        if ([string]::IsNullOrWhiteSpace($text)) { return @() }
        return @($text -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object)
    }

    # @() around the call, not just inside the block: a block's output is enumerated on the way out,
    # so a one-server list comes back as a bare string and $a[$i] would index its characters.
    $a = @(& $split $First)
    $b = @(& $split $Second)
    if ($a.Count -eq 0 -or $b.Count -eq 0) { return $false }
    if ($a.Count -ne $b.Count) { return $false }

    for ($i = 0; $i -lt $a.Count; $i++) {
        if ($a[$i] -ne $b[$i]) { return $false }
    }
    return $true
}

function Get-InterfaceState {
    <#
    .SYNOPSIS
        Reads the DHCP and address configuration of every TCP/IP interface. SYSTEM must be mounted.

    .DESCRIPTION
        Only an interface that explicitly says EnableDHCP=0 is static. An absent value is left alone:
        it is ambiguous, and rewriting a key whose intent cannot be read is not a repair.

        The value name is matched case-insensitively on purpose. A stock Server 2022 image carries
        "EnableDhcp" on one of its interfaces and "EnableDHCP" on the rest, and a case-sensitive read
        reports the odd one out as unconfigured.
    #>
    param([switch]$Strict)

    $root = Get-OfflineSystemRootPath -Strict:$Strict
    $interfaceRoot = "$root\Services\Tcpip\Parameters\Interfaces"
    $state = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-Path $interfaceRoot)) {
        Add-OfflineRepairLog -Level Warning -Message "No TCP/IP interface key was found at $interfaceRoot."
        return $state
    }

    foreach ($item in @(Get-ChildItem -Path $interfaceRoot -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }

        $enableDhcp = $null
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -ieq 'EnableDHCP') { $enableDhcp = $prop.Value; break }
        }

        $static = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $script:StaticAddressValue) {
            $value = $props.$name
            if ($null -eq $value) { continue }
            $text = (@($value) -join ',').Trim()
            # A DHCP interface often carries 0.0.0.0 placeholders. They describe nothing and are not
            # reported as a static address.
            if ([string]::IsNullOrWhiteSpace($text) -or $text -match '^(0\.0\.0\.0,?)+$') { continue }
            [void]$static.Add([PSCustomObject]@{ Name = $name; Value = $value })
        }

        $nameServer = if ($null -eq $props.NameServer) { '' } else { [string]$props.NameServer }
        $dhcpNameServer = if ($null -eq $props.DhcpNameServer) { '' } else { [string]$props.DhcpNameServer }

        [void]$state.Add([PSCustomObject]@{
                Interface      = $item.PSChildName
                Path           = $item.PSPath.ToString()
                EnableDhcp     = if ($null -eq $enableDhcp) { -1 } else { [int]$enableDhcp }
                Static         = @($static)
                NameServer     = $nameServer
                DhcpNameServer = $dhcpNameServer
                DnsMatchesDhcp = (Test-SameDnsList -First $nameServer -Second $dhcpNameServer)
            })
    }

    return $state
}

function Get-GlobalNameServer {
    <#
    .SYNOPSIS
        Reads the DNS servers configured for the whole stack rather than one interface.
    #>
    param([switch]$Strict)

    $root = Get-OfflineSystemRootPath -Strict:$Strict
    $path = "$root\Services\Tcpip\Parameters"
    if (-not (Test-Path $path)) { return '' }
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).NameServer
    if ($null -eq $value) { return '' }
    return [string]$value
}

function Get-NetworkProviderState {
    <#
    .SYNOPSIS
        Reads the network provider order and works out which entries point at a DLL that is gone.

    .DESCRIPTION
        Winlogon loads every provider in this list during logon and waits for it. An entry left
        behind by a partially removed VPN or endpoint client hangs the logon indefinitely, which
        presents as a VM that accepts an RDP connection and then never reaches a desktop.

        A provider is only called orphaned when its ProviderPath is recorded, resolves to a path on
        the offline disk, and that file is definitively absent. A provider with no ProviderPath at
        all, or one whose path cannot be resolved, is left alone.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [switch]$Strict
    )

    $root = Get-OfflineSystemRootPath -Strict:$Strict
    $orderPath = "$root\Control\NetworkProvider\Order"
    $result = [PSCustomObject]@{
        ProviderOrder = ''
        HwOrder       = ''
        Providers     = @()
    }

    if (-not (Test-Path $orderPath)) { return $result }

    $result.ProviderOrder = [string](Get-ItemProperty -Path $orderPath -ErrorAction SilentlyContinue).ProviderOrder

    $hwPath = "$root\Control\NetworkProvider\HwOrder"
    if (Test-Path $hwPath) {
        $result.HwOrder = [string](Get-ItemProperty -Path $hwPath -ErrorAction SilentlyContinue).ProviderOrder
    }

    $providers = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @($result.ProviderOrder -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $providerKey = "$root\Services\$name\NetworkProvider"
        $recorded = if (Test-Path $providerKey) {
            [string](Get-ItemProperty -Path $providerKey -ErrorAction SilentlyContinue).ProviderPath
        }
        else { '' }

        $resolved = Resolve-OfflineSystemPath -Path $recorded -WindowsPath $WindowsPath
        $missing = $false
        $reason = ''

        if (-not (Test-Path $providerKey)) {
            $missing = $true
            $reason = 'the provider has no NetworkProvider key, so nothing describes what Winlogon should load'
        }
        elseif ([string]::IsNullOrWhiteSpace($recorded)) {
            $reason = 'no ProviderPath is recorded, so it cannot be judged and was left alone'
        }
        elseif ($null -eq $resolved) {
            $reason = "ProviderPath '$recorded' is in a form this script does not resolve, so it was left alone"
        }
        elseif (-not (Test-OfflinePath $resolved)) {
            $missing = $true
            $reason = "'$recorded' resolves to $resolved, which is not present on this disk"
        }
        else {
            $reason = "'$recorded' is present"
        }

        $builtIn = ($script:BuiltInProvider -contains $name)

        [void]$providers.Add([PSCustomObject]@{
                Provider     = $name
                ProviderPath = $recorded
                Resolved     = $resolved
                Missing      = $missing
                BuiltIn      = $builtIn
                Orphaned     = ($missing -and -not $builtIn)
                Reason       = $reason
            })
    }

    $result.Providers = @($providers)
    return $result
}

function Get-ProxyState {
    <#
    .SYNOPSIS
        Reads the machine-wide proxy configuration. SOFTWARE must be mounted.

    .DESCRIPTION
        ProxyEnable is absent on a stock image, so absence is normal and is not evidence. Only an
        enabled proxy or a recorded PAC URL counts - a ProxyServer left behind with ProxyEnable=0 is
        inert and is reported without being called a fault.
    #>
    $state = [System.Collections.Generic.List[object]]::new()

    foreach ($subKey in $script:ProxySubKey) {
        $path = "HKLM:\BROKENSOFTWARE\$subKey"
        if (-not (Test-Path $path)) { continue }

        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }

        $enabled = $props.ProxyEnable
        $autoConfig = [string]$props.AutoConfigURL

        [void]$state.Add([PSCustomObject]@{
                Path               = $path
                SubKey             = $subKey
                ProxyEnable        = if ($null -eq $enabled) { 0 } else { [int]$enabled }
                # Recorded so a revert removes a ProxyEnable it finds rather than inventing one that
                # was never there.
                ProxyEnablePresent = ($null -ne $enabled)
                ProxyServer        = [string]$props.ProxyServer
                ProxyOverride      = [string]$props.ProxyOverride
                AutoConfigURL      = $autoConfig
                Active             = (($null -ne $enabled -and [int]$enabled -eq 1) -or -not [string]::IsNullOrWhiteSpace($autoConfig))
            })
    }

    return $state
}

function Get-NetworkFinding {
    <#
    .SYNOPSIS
        Turns the collected state into the list of things that are actually wrong.
    #>
    param(
        [Parameter(Mandatory = $true)]$Services,
        [Parameter(Mandatory = $true)]$Interfaces,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$GlobalNameServer,
        [Parameter(Mandatory = $true)]$Providers,
        [Parameter(Mandatory = $true)]$Proxy
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($service in @($Services | Where-Object { $_.Start -eq 4 -and -not $_.ReportOnly })) {
        $detail = "Start=4 (disabled); a healthy image has Start=$($service.Expected)."
        if ($service.Critical) {
            $detail += ' This service is load-bearing - the VM is not reachable without it.'
        }
        [void]$findings.Add((New-Finding -Kind 'Service' -Target $service.Service -Detail $detail -Critical:$service.Critical))
    }

    foreach ($service in @($Services | Where-Object { $_.Start -eq 4 -and $_.ReportOnly })) {
        [void]$findings.Add((New-Finding -Kind 'ServiceReportOnly' -Target $service.Service -Informational $true `
                    -Detail "Start=4 (disabled). This is commonly done on purpose as hardening and the VM does not need it to be reachable, so it is reported and left alone."))
    }

    foreach ($interface in @($Interfaces | Where-Object { $_.EnableDhcp -eq 0 })) {
        $addresses = if (@($interface.Static).Count -gt 0) {
            ($interface.Static | ForEach-Object { "$($_.Name)=$((@($_.Value) -join ','))" }) -join ', '
        }
        else { 'no address recorded' }
        [void]$findings.Add((New-Finding -Kind 'Interface' -Target $interface.Interface -Critical $true `
                    -Detail "EnableDHCP=0 with $addresses. Azure assigns addresses by DHCP and only delivers traffic for the address it allocated to the NIC, so a static configuration from another environment leaves the VM unreachable."))
    }

    foreach ($provider in @($Providers.Providers | Where-Object { $_.Orphaned })) {
        [void]$findings.Add((New-Finding -Kind 'Provider' -Target $provider.Provider -Critical $true `
                    -Detail "Registered in NetworkProvider\Order but $($provider.Reason). Winlogon waits on every provider in that list, so logon hangs at 'Please wait for the Network Connections'."))
    }

    foreach ($provider in @($Providers.Providers | Where-Object { $_.Missing -and $_.BuiltIn })) {
        [void]$findings.Add((New-Finding -Kind 'ProviderBuiltIn' -Target $provider.Provider `
                    -Detail "Built-in provider, and $($provider.Reason). This is component damage rather than a stale registration, so it is reported and not removed - removing the reference would hide it. win-sfc-sf-corruption is the next step."))
    }

    foreach ($interface in @($Interfaces | Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameServer) })) {
        if ($interface.DnsMatchesDhcp) {
            # NameServer holds exactly what DHCP handed out, so it is not an override at all. Said
            # out loud rather than kept quiet, because seeing a DNS server listed and no comment on
            # it invites someone to go and clear it by hand.
            [void]$findings.Add((New-Finding -Kind 'DnsMatchesDhcp' -Target $interface.Interface -Informational $true `
                        -Detail "DNS server(s) '$($interface.NameServer)' match what DHCP supplied for this interface, so this is the virtual network's own DNS rather than an override. Not a fault and not offered for clearing."))
            continue
        }

        $versus = if ([string]::IsNullOrWhiteSpace($interface.DhcpNameServer)) { 'DHCP has not supplied any DNS server for this interface to compare against' }
        else { "DHCP supplied '$($interface.DhcpNameServer)' instead" }

        [void]$findings.Add((New-Finding -Kind 'StaticDns' -Target $interface.Interface `
                    -Detail "Static DNS server(s) '$($interface.NameServer)', and $versus. Reported only - a deliberate custom or domain-controller DNS setting looks exactly the same from here. Pass clearStaticDns=true to clear it."))
    }

    if (-not [string]::IsNullOrWhiteSpace($GlobalNameServer)) {
        [void]$findings.Add((New-Finding -Kind 'StaticDns' -Target $script:GlobalDnsTarget `
                    -Detail "Static DNS server(s) '$GlobalNameServer' set for the whole stack. Reported only. Pass clearStaticDns=true to clear it."))
    }

    foreach ($entry in @($Proxy | Where-Object { $_.Active })) {
        $what = if (-not [string]::IsNullOrWhiteSpace($entry.AutoConfigURL)) { "PAC URL '$($entry.AutoConfigURL)'" }
        else { "proxy '$($entry.ProxyServer)'" }
        [void]$findings.Add((New-Finding -Kind 'Proxy' -Target $entry.SubKey `
                    -Detail "Machine-wide $what is configured. If the VM cannot reach it, the guest agent and Windows Update both time out. Reported only - pass clearProxy=true to clear it."))
    }

    return $findings
}

function Get-RevertManifestPath {
    param([Parameter(Mandatory = $true)][string]$Drive)
    return (Join-Path $Drive "$scriptName-revert.json")
}

function Test-ManifestInteger {
    <#
    .SYNOPSIS
        True when a manifest field is a whole number in range. JSON numbers come back as Int32 on
        Windows PowerShell and Int64 on PowerShell 7, so both are accepted and nothing else is.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [Parameter(Mandatory = $true)][long]$Minimum,
        [Parameter(Mandatory = $true)][long]$Maximum
    )

    if (-not ($Value -is [int] -or $Value -is [long])) { return $false }
    return ([long]$Value -ge $Minimum -and [long]$Value -le $Maximum)
}

function Test-ManifestText {
    <#
    .SYNOPSIS
        True when a manifest field is a string of bounded length with no control characters, and
        matches the character set the field allows.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [Parameter(Mandatory = $false)][string]$Pattern = '',
        [Parameter(Mandatory = $false)][int]$MaxLength = 8192
    )

    if ($Value -isnot [string]) { return $false }
    if ($Value.Length -gt $MaxLength) { return $false }
    if ($Value -match '[\x00-\x1F]') { return $false }
    if ($Pattern -and $Value -notmatch $Pattern) { return $false }
    return $true
}

function Test-ManifestRemovedValue {
    <#
    .SYNOPSIS
        Checks one removed registry value recorded in a manifest. Returns '' when it is acceptable,
        otherwise why it is not.

    .DESCRIPTION
        Also used before a value is removed, so a repair never records something the revert would
        then refuse.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Entry,
        [Parameter(Mandatory = $true)][string[]]$AllowedName,
        [Parameter(Mandatory = $false)][string]$Pattern = ''
    )

    if ($Entry -isnot [System.Management.Automation.PSCustomObject]) { return 'is not an object' }
    if ($Entry.Name -isnot [string] -or $AllowedName -cnotcontains $Entry.Name) { return 'names a value this script never removes' }
    if ($Entry.Kind -isnot [string] -or $script:RestorableKind -cnotcontains $Entry.Kind) { return 'has a registry type this script never records' }

    $value = $Entry.Value
    if ($Entry.Kind -eq 'DWord') {
        if (-not (Test-ManifestInteger -Value $value -Minimum 0 -Maximum ([int]::MaxValue))) { return 'holds data that is not a valid DWORD' }
    }
    elseif ($Entry.Kind -eq 'MultiString') {
        if ($null -eq $value) { return 'holds no data' }
        $items = @($value)
        if ($items.Count -gt 64) { return 'holds more strings than this value ever carries' }
        foreach ($item in $items) {
            if (-not (Test-ManifestText -Value $item -Pattern $Pattern)) { return 'holds data that is not valid for this value' }
        }
    }
    elseif (-not (Test-ManifestText -Value $value -Pattern $Pattern)) {
        return 'holds data that is not valid for this value'
    }

    return ''
}

function Test-RevertManifest {
    <#
    .SYNOPSIS
        Checks a parsed revert manifest against what this script records. Returns '' when every entry
        is acceptable, otherwise the reason the first bad entry was refused.

    .DESCRIPTION
        The manifest is read back off the customer's disk and then drives registry writes, so it is
        treated as untrusted input. Every service, interface, value name, registry type and target
        key must be one this script itself records, and every value must have the shape and
        character set that value takes. A manifest with a single entry that fails is refused as a
        whole: a partial revert of a manifest that has been tampered with is not a restore.

        Registry paths are never taken from the manifest. The revert rebuilds them from the names
        checked here, so a recorded path cannot point a write anywhere else. Properties this script
        does not read are ignored.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()]$Manifest)

    if ($Manifest -isnot [System.Management.Automation.PSCustomObject]) { return 'its top level is not a JSON object' }

    $lists = @{}
    foreach ($name in @('Services', 'Interfaces', 'Dns', 'Proxy')) {
        $property = $Manifest.PSObject.Properties[$name]
        $entries = @()
        if ($null -ne $property -and $null -ne $property.Value) { $entries = @($property.Value) }
        if ($entries.Count -gt 512) { return "$name holds more entries than this script ever records" }
        for ($i = 0; $i -lt $entries.Count; $i++) {
            if ($entries[$i] -isnot [System.Management.Automation.PSCustomObject]) { return "$name[$i] is not an object" }
        }
        $lists[$name] = $entries
    }

    $serviceNames = @($script:NetworkService.Keys)
    $services = $lists['Services']
    for ($i = 0; $i -lt $services.Count; $i++) {
        $entry = $services[$i]
        if ($entry.Service -isnot [string] -or $serviceNames -cnotcontains $entry.Service) { return "Services[$i] names a service this script does not manage" }
        # This script only ever records a service it found disabled.
        if (-not (Test-ManifestInteger -Value $entry.OriginalStart -Minimum 4 -Maximum 4)) { return "Services[$i] records a start type this script never records" }
    }

    $interfaces = $lists['Interfaces']
    for ($i = 0; $i -lt $interfaces.Count; $i++) {
        $entry = $interfaces[$i]
        if ($entry.Interface -isnot [string] -or $entry.Interface -notmatch $script:InterfaceKeyPattern) { return "Interfaces[$i] does not name a network interface key" }
        # Only an interface found with DHCP turned off is ever recorded.
        if (-not (Test-ManifestInteger -Value $entry.OriginalEnableDhcp -Minimum 0 -Maximum 0)) { return "Interfaces[$i] records an EnableDHCP value this script never records" }
        $removed = @()
        if ($null -ne $entry.RemovedValues) { $removed = @($entry.RemovedValues) }
        if ($removed.Count -gt $script:StaticAddressValue.Count) { return "Interfaces[$i] records more removed values than this script removes" }
        for ($j = 0; $j -lt $removed.Count; $j++) {
            $problem = Test-ManifestRemovedValue -Entry $removed[$j] -AllowedName $script:StaticAddressValue -Pattern $script:InterfaceValuePattern
            if ($problem) { return "Interfaces[$i].RemovedValues[$j] $problem" }
        }
    }

    $dns = $lists['Dns']
    for ($i = 0; $i -lt $dns.Count; $i++) {
        $entry = $dns[$i]
        if ($entry.Target -isnot [string] -or ($entry.Target -cne $script:GlobalDnsTarget -and $entry.Target -notmatch $script:InterfaceKeyPattern)) {
            return "Dns[$i] does not name a network interface or the global DNS setting"
        }
        if (-not (Test-ManifestText -Value $entry.Value -Pattern $script:DnsValuePattern -MaxLength 1024)) { return "Dns[$i] does not hold a list of DNS server addresses" }
    }

    $proxy = $lists['Proxy']
    for ($i = 0; $i -lt $proxy.Count; $i++) {
        $entry = $proxy[$i]
        if ($entry.Target -isnot [string] -or $script:ProxySubKey -cnotcontains $entry.Target) { return "Proxy[$i] does not name a machine proxy settings key" }
        if ($null -ne $entry.ProxyEnable -and -not (Test-ManifestInteger -Value $entry.ProxyEnable -Minimum 0 -Maximum ([int]::MaxValue))) { return "Proxy[$i] records a ProxyEnable that is not a valid DWORD" }
        $removed = @()
        if ($null -ne $entry.RemovedValues) { $removed = @($entry.RemovedValues) }
        if ($removed.Count -gt $script:ProxyValue.Count) { return "Proxy[$i] records more removed values than this script removes" }
        for ($j = 0; $j -lt $removed.Count; $j++) {
            $problem = Test-ManifestRemovedValue -Entry $removed[$j] -AllowedName $script:ProxyValue
            if ($problem) { return "Proxy[$i].RemovedValues[$j] $problem" }
        }
    }

    foreach ($name in @('ProviderOrder', 'HwOrder')) {
        $property = $Manifest.PSObject.Properties[$name]
        if ($null -eq $property -or $null -eq $property.Value) { continue }
        if (-not (Test-ManifestText -Value $property.Value -Pattern $script:ProviderOrderPattern -MaxLength 4096)) { return "$name is not a network provider list" }
    }

    return ''
}

function Get-RevertManifestList {
    <#
    .SYNOPSIS
        The entries of one list in a manifest that Test-RevertManifest accepted. An absent list is empty.
    #>
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $property = $Manifest.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return }
    foreach ($entry in @($property.Value)) { $entry }
}

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads and checks the manifest a previous run left on the offline disk.

    .DESCRIPTION
        Returns Exists, Manifest and Problem. Exists is false when there is no manifest at all.
        Problem is set, and Manifest is $null, when a file is there but cannot be trusted - it is too
        large, unreadable, not JSON, or fails Test-RevertManifest. A caller can then tell "nothing to
        revert" apart from "refused", which a bare $null cannot.

        The top level is checked in the raw text as well as after parsing, because PowerShell 7
        unwraps a one-element JSON array into the object inside it.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Exists = $false; Manifest = $null; Problem = '' }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    $result.Exists = $true

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) {
            $result.Problem = 'it is a folder, not a file'
            return $result
        }
        if ($item.Length -gt $script:ManifestMaxBytes) {
            $result.Problem = "it is $($item.Length) bytes, far larger than any manifest this script writes"
            return $result
        }
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        $result.Problem = "it could not be read ($($_.Exception.Message))"
        return $result
    }

    if ([string]::IsNullOrWhiteSpace($content)) {
        $result.Problem = 'it is empty'
        return $result
    }
    if ($content -notmatch '^[\s\uFEFF]*\{') {
        $result.Problem = 'its top level is not a JSON object'
        return $result
    }

    try {
        $parsed = ConvertFrom-Json -InputObject $content -ErrorAction Stop
    }
    catch {
        $result.Problem = 'it is not valid JSON'
        return $result
    }

    $problem = Test-RevertManifest -Manifest $parsed
    if ($problem) {
        $result.Problem = $problem
        return $result
    }

    $result.Manifest = $parsed
    return $result
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, without discarding what an earlier run recorded.

    .DESCRIPTION
        Each run writes the same file, so a plain overwrite loses the undo information from the run
        before it. A run that returned an interface to DHCP followed by a clearProxy run would leave
        a manifest naming the proxy but not the interface, and the revert would then report success
        while restoring only half of what was changed.

        Entries are keyed by what they describe, and an existing entry always wins: it holds the
        value that was genuinely there before any run of this script touched it. The same goes for
        the provider order.

        An existing manifest that fails its checks is moved aside rather than merged or silently
        overwritten, and the merged result is checked again before it is written, so this script
        never writes a manifest its own revert would refuse.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $read = Read-RevertManifest -Path $Path
    if ($read.Exists -and $read.Problem) {
        $aside = "$Path.rejected-$(Get-Date -Format yyyyMMddHHmmss)"
        Move-Item -LiteralPath $Path -Destination $aside -Force -ErrorAction Stop
        Add-OfflineRepairLog -Level Warning -Message "The existing revert manifest was not usable ($($read.Problem)). It was moved to $aside and is not merged, so whatever it recorded cannot be reverted by this script."
    }
    elseif ($read.Manifest) {
        $existing = $read.Manifest
        foreach ($set in @(
                @{ Name = 'Services'; Key = 'Service' },
                @{ Name = 'Interfaces'; Key = 'Interface' },
                @{ Name = 'Dns'; Key = 'Target' },
                @{ Name = 'Proxy'; Key = 'Target' }
            )) {
            $kept = @(Get-RevertManifestList -Manifest $existing -Name $set.Name)
            $keptKeys = @($kept | ForEach-Object { [string]$_.($set.Key) })
            $added = @(@($Manifest.($set.Name)) | Where-Object { $null -ne $_ -and $keptKeys -notcontains [string]$_.($set.Key) })
            $Manifest.($set.Name) = @($kept + $added)
        }

        if (-not [string]::IsNullOrEmpty([string]$existing.ProviderOrder)) {
            $Manifest.ProviderOrder = [string]$existing.ProviderOrder
            if (-not [string]::IsNullOrEmpty([string]$existing.HwOrder)) {
                $Manifest.HwOrder = [string]$existing.HwOrder
            }
        }
    }

    $problem = Test-RevertManifest -Manifest $Manifest
    if ($problem) {
        throw "The revert manifest this run built would be refused by revert=true ($problem), so it was not written."
    }

    ConvertTo-Json -InputObject $Manifest -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8 -Force -ErrorAction Stop
    Add-OfflineRepairLog -Level Info -Message "Recorded what was changed in $Path"
}

function New-RemovedValueRecord {
    <#
    .SYNOPSIS
        A manifest record for a registry value that is about to be removed.

    .DESCRIPTION
        The data is copied into a plain array, integer or string matching its type. Registry reads can
        hand back an array wrapped in a PSObject, which Windows PowerShell serialises as an object
        with "value" and "Count" members instead of a JSON array - and the revert would then refuse
        the manifest.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][AllowNull()]$Value
    )

    $record = [PSCustomObject]@{ Name = $Name; Kind = $Kind; Value = $null }
    if ($Kind -eq 'MultiString') { $record.Value = [string[]]@($Value) }
    elseif ($Kind -eq 'DWord') { $record.Value = [int]$Value }
    else { $record.Value = [string]$Value }
    return $record
}

function Get-RemovableValueRecord {
    <#
    .SYNOPSIS
        The manifest record for a value about to be removed, or the reason it cannot be recorded.

    .DESCRIPTION
        Returns Record and Problem. A value is only removed when Problem is empty, so nothing is taken
        off the disk unless revert=true can put it back exactly as it was.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string[]]$AllowedName,
        [Parameter(Mandatory = $false)][string]$Pattern = ''
    )

    $kind = Get-OfflineValueKind -Path $Path -Name $Name
    if (-not $kind -or $script:RestorableKind -cnotcontains $kind) {
        return [PSCustomObject]@{ Record = $null; Problem = 'has a registry type that could not be read or cannot be restored' }
    }
    $record = New-RemovedValueRecord -Name $Name -Kind $kind -Value $Value
    return [PSCustomObject]@{
        Record  = $record
        Problem = (Test-ManifestRemovedValue -Entry $record -AllowedName $AllowedName -Pattern $Pattern)
    }
}

function Set-OfflineNetworkValue {
    <#
    .SYNOPSIS
        Writes one registry value on the offline disk, after confirming the key is inside a mounted
        offline hive. Throws on any failure.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('String', 'ExpandString', 'MultiString', 'DWord')][string]$Kind,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$Value
    )

    [void](Assert-OfflineTarget -Path $Path -Action "write $Name")
    if ($Kind -eq 'MultiString') { $data = [string[]]@($Value) }
    elseif ($Kind -eq 'DWord') { $data = [int]$Value }
    else { $data = [string]$Value }
    Set-ItemProperty -LiteralPath $Path -Name $Name -Value $data -Type $Kind -Force -ErrorAction Stop
}

function Remove-OfflineNetworkValue {
    <#
    .SYNOPSIS
        Removes one registry value on the offline disk, after confirming the key is inside a mounted
        offline hive. Throws on any failure.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    [void](Assert-OfflineTarget -Path $Path -Action "remove $Name")
    Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, clearStaticDns=$doClearStaticDns, clearProxy=$doClearProxy, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

$status = $STATUS_ERROR
try {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1

    :Main do {
        $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

        $manifestPath = Get-RevertManifestPath -Drive $offline.WindowsDrive

        # -----------------------------------------------------------------------------------------
        # Revert
        # -----------------------------------------------------------------------------------------
        if ($isRevert) {
            $read = Read-RevertManifest -Path $manifestPath
            if (-not $read.Exists) {
                Log-Output "No revert manifest was found at $manifestPath, so this script has not changed anything on this disk. No changes were made." | Tee-Object -FilePath $logFile -Append
                Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_SUCCESS
                break Main
            }
            if ($read.Problem) {
                Log-Output "The revert manifest at $manifestPath was refused because $($read.Problem). It does not match what this script records, so nothing in it is trusted. Nothing was restored and the file was left in place for inspection." | Tee-Object -FilePath $logFile -Append
                Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
                break Main
            }

            $manifest = $read.Manifest
            $services = @(Get-RevertManifestList -Manifest $manifest -Name 'Services')
            $interfaces = @(Get-RevertManifestList -Manifest $manifest -Name 'Interfaces')
            $dns = @(Get-RevertManifestList -Manifest $manifest -Name 'Dns')
            $proxy = @(Get-RevertManifestList -Manifest $manifest -Name 'Proxy')
            $providerOrder = [string]$manifest.ProviderOrder
            $hwOrder = [string]$manifest.HwOrder
            $restoresSystem = ($services.Count -gt 0 -or $interfaces.Count -gt 0 -or $dns.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($providerOrder))
            $plannedRevertCount = $services.Count + $interfaces.Count + $dns.Count + $proxy.Count + $(if ([string]::IsNullOrWhiteSpace($providerOrder)) { 0 } else { 1 })

            if ($plannedRevertCount -eq 0) {
                Log-Output "The revert manifest at $manifestPath holds nothing to restore, so no hive was loaded. No changes were made." | Tee-Object -FilePath $logFile -Append
                Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_SUCCESS
                break Main
            }

            if ($isDetectOnly) {
                Log-Output 'detectOnly=true, so nothing was restored and no hive was loaded. A revert run would restore:' | Tee-Object -FilePath $logFile -Append
                foreach ($entry in $services) { Log-Output "  $($entry.Service) Start back to $($entry.OriginalStart)." | Tee-Object -FilePath $logFile -Append }
                foreach ($entry in $interfaces) { Log-Output "  Interface $($entry.Interface) back to EnableDHCP=$($entry.OriginalEnableDhcp) with $(@($entry.RemovedValues).Count) static address value(s)." | Tee-Object -FilePath $logFile -Append }
                foreach ($entry in $dns) { Log-Output "  NameServer on $($entry.Target) back to '$($entry.Value)'." | Tee-Object -FilePath $logFile -Append }
                if (-not [string]::IsNullOrWhiteSpace($providerOrder)) { Log-Output "  NetworkProvider\Order back to '$providerOrder'." | Tee-Object -FilePath $logFile -Append }
                foreach ($entry in $proxy) { Log-Output "  The machine proxy settings in $($entry.Target)." | Tee-Object -FilePath $logFile -Append }
                Log-Output "Detect only: the manifest at $manifestPath holds $plannedRevertCount item(s) to restore. No changes were made." | Tee-Object -FilePath $logFile -Append
                Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_SUCCESS
                break Main
            }

            # Counted in $script: scope because the hive script blocks run in a child scope.
            $script:RevertCount = 0
            $script:RevertFailures = 0
            $script:RevertSkipped = 0
            $backups = [System.Collections.Generic.List[string]]::new()

            if ($restoresSystem) {
                $systemBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SYSTEM'
                [void]$backups.Add($systemBackup)
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append

                Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                    $root = Get-OfflineSystemRootPath -Strict

                    foreach ($entry in $services) {
                        $path = "$root\Services\$($entry.Service)"
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($entry.Service): the service key is no longer present, so it was not restored."
                            $script:RevertSkipped++
                            continue
                        }
                        try {
                            Set-OfflineNetworkValue -Path $path -Name 'Start' -Kind DWord -Value ([int]$entry.OriginalStart)
                            Add-OfflineRepairLog -Level Info -Message "$($entry.Service): Start restored to $($entry.OriginalStart)."
                            $script:RevertCount++
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($entry.Service): Start could not be restored ($($_.Exception.Message))."
                            $script:RevertFailures++
                        }
                    }

                    foreach ($entry in $interfaces) {
                        $path = "$root\Services\Tcpip\Parameters\Interfaces\$($entry.Interface)"
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($entry.Interface): the interface key is no longer present, so it was not restored."
                            $script:RevertSkipped++
                            continue
                        }
                        try {
                            Set-OfflineNetworkValue -Path $path -Name 'EnableDHCP' -Kind DWord -Value ([int]$entry.OriginalEnableDhcp)
                            foreach ($value in @($entry.RemovedValues)) {
                                Set-OfflineNetworkValue -Path $path -Name $value.Name -Kind $value.Kind -Value $value.Value
                            }
                            Add-OfflineRepairLog -Level Info -Message "$($entry.Interface): EnableDHCP restored to $($entry.OriginalEnableDhcp) and $(@($entry.RemovedValues).Count) address value(s) put back."
                            $script:RevertCount++
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($entry.Interface): the static address could not be fully restored ($($_.Exception.Message))."
                            $script:RevertFailures++
                        }
                    }

                    foreach ($entry in $dns) {
                        $path = if ($entry.Target -ceq $script:GlobalDnsTarget) { "$root\Services\Tcpip\Parameters" } else { "$root\Services\Tcpip\Parameters\Interfaces\$($entry.Target)" }
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($entry.Target): the key is no longer present, so the DNS setting was not restored."
                            $script:RevertSkipped++
                            continue
                        }
                        try {
                            Set-OfflineNetworkValue -Path $path -Name 'NameServer' -Kind String -Value ([string]$entry.Value)
                            Add-OfflineRepairLog -Level Info -Message "$($entry.Target): NameServer restored to '$($entry.Value)'."
                            $script:RevertCount++
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($entry.Target): NameServer could not be restored ($($_.Exception.Message))."
                            $script:RevertFailures++
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($providerOrder)) {
                        $orderPath = "$root\Control\NetworkProvider\Order"
                        if (-not (Test-Path -LiteralPath $orderPath)) {
                            Add-OfflineRepairLog -Level Warning -Message 'NetworkProvider\Order is no longer present, so the provider order was not restored.'
                            $script:RevertSkipped++
                        }
                        else {
                            try {
                                Set-OfflineNetworkValue -Path $orderPath -Name 'ProviderOrder' -Kind String -Value $providerOrder
                                Add-OfflineRepairLog -Level Info -Message "NetworkProvider\Order restored to '$providerOrder'."
                                $hwPath = "$root\Control\NetworkProvider\HwOrder"
                                if ((Test-Path -LiteralPath $hwPath) -and -not [string]::IsNullOrWhiteSpace($hwOrder)) {
                                    Set-OfflineNetworkValue -Path $hwPath -Name 'ProviderOrder' -Kind String -Value $hwOrder
                                    Add-OfflineRepairLog -Level Info -Message "NetworkProvider\HwOrder restored to '$hwOrder'."
                                }
                                $script:RevertCount++
                            }
                            catch {
                                Add-OfflineRepairLog -Level Error -Message "The network provider order could not be restored ($($_.Exception.Message))."
                                $script:RevertFailures++
                            }
                        }
                    }
                }
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            }

            if ($proxy.Count -gt 0) {
                $softwareBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SOFTWARE'
                [void]$backups.Add($softwareBackup)
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append

                Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
                    foreach ($entry in $proxy) {
                        $path = "HKLM:\BROKENSOFTWARE\$($entry.Target)"
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($entry.Target): the key is no longer present, so the proxy settings were not restored."
                            $script:RevertSkipped++
                            continue
                        }
                        try {
                            if ($null -eq $entry.ProxyEnable) {
                                # ProxyEnable was absent before the repair, so the one it wrote is removed
                                # rather than left behind as a value the image never had.
                                if ($null -ne (Get-ItemProperty -LiteralPath $path -Name 'ProxyEnable' -ErrorAction SilentlyContinue)) {
                                    Remove-OfflineNetworkValue -Path $path -Name 'ProxyEnable'
                                }
                            }
                            else {
                                Set-OfflineNetworkValue -Path $path -Name 'ProxyEnable' -Kind DWord -Value ([int]$entry.ProxyEnable)
                            }
                            foreach ($value in @($entry.RemovedValues)) {
                                Set-OfflineNetworkValue -Path $path -Name $value.Name -Kind $value.Kind -Value $value.Value
                            }
                            Add-OfflineRepairLog -Level Info -Message "$($entry.Target): proxy settings restored."
                            $script:RevertCount++
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($entry.Target): the proxy settings could not be fully restored ($($_.Exception.Message))."
                            $script:RevertFailures++
                        }
                    }
                }
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            }

            $restored = [int]$script:RevertCount
            $failed = [int]$script:RevertFailures
            $skipped = [int]$script:RevertSkipped

            if ($failed -eq 0 -and $skipped -eq 0) {
                if ($restored -gt 0) {
                    Remove-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
                    Log-Output "Restored $restored item(s) on $($offline.WindowsPath) and removed the manifest." | Tee-Object -FilePath $logFile -Append
                }
                else {
                    Log-Output "The revert manifest at $manifestPath held nothing to restore. No changes were made." | Tee-Object -FilePath $logFile -Append
                }
                if ($backups.Count -gt 0) {
                    Log-Output "Hive backup(s) taken before the revert: $($backups -join ', '). They travel back with the disk and can be deleted once the VM is confirmed healthy." | Tee-Object -FilePath $logFile -Append
                }
                $status = $STATUS_SUCCESS
            }
            else {
                Log-Output "Restored $restored of $plannedRevertCount item(s); $failed could not be written and $skipped are no longer on the disk. The manifest was kept at $manifestPath so nothing it records is lost. Hive backup(s) taken before the revert: $($backups -join ', ')." | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
            }
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            break Main
        }

        # -----------------------------------------------------------------------------------------
        # Detect
        # -----------------------------------------------------------------------------------------
        $state = Invoke-WithHive -Hive @('SYSTEM', 'SOFTWARE') -WindowsPath $offline.WindowsPath -ScriptBlock {
            return [PSCustomObject]@{
                Services         = @(Get-NetworkServiceState -Strict:(-not $isDetectOnly))
                Interfaces       = @(Get-InterfaceState -Strict:(-not $isDetectOnly))
                GlobalNameServer = (Get-GlobalNameServer -Strict:(-not $isDetectOnly))
                Providers        = (Get-NetworkProviderState -WindowsPath $offline.WindowsPath -Strict:(-not $isDetectOnly))
                Proxy            = @(Get-ProxyState)
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        Log-Info "Checked $(@($state.Services).Count) networking service(s), $(@($state.Interfaces).Count) interface(s) and $(@($state.Providers.Providers).Count) network provider(s)." | Tee-Object -FilePath $logFile -Append

        $findings = @(Get-NetworkFinding -Services $state.Services -Interfaces $state.Interfaces `
                -GlobalNameServer $state.GlobalNameServer -Providers $state.Providers -Proxy $state.Proxy)
        $faults = @($findings | Where-Object { -not $_.Informational })
        $notes = @($findings | Where-Object { $_.Informational })

        if ($faults.Count -eq 0) {
            Log-Output 'No networking fault was found on this disk. Every networking service this script repairs is enabled, no interface has DHCP turned off, no orphaned network provider is registered and no proxy is set in the machine-wide Internet Settings. The WinHTTP proxy and per-user proxy settings were not checked.' | Tee-Object -FilePath $logFile -Append
            Log-Output 'If the VM is still unreachable, check the NSG and effective security rules on the NIC, then win-fix-logon-subsystem if it answers the network but refuses a session.' | Tee-Object -FilePath $logFile -Append
            foreach ($note in $notes) {
                Log-Output "  [$($note.Kind)] $($note.Target): $($note.Detail)" | Tee-Object -FilePath $logFile -Append
            }
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        Log-Output "Found $($faults.Count) networking fault(s) on $($offline.WindowsPath):" | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $faults) {
            Log-Output "  [$($finding.Kind)] $($finding.Target): $($finding.Detail)" | Tee-Object -FilePath $logFile -Append
        }

        if ($notes.Count -gt 0) {
            Log-Output 'Also noted, and not counted as a fault:' | Tee-Object -FilePath $logFile -Append
            foreach ($note in $notes) {
                Log-Output "  [$($note.Kind)] $($note.Target): $($note.Detail)" | Tee-Object -FilePath $logFile -Append
            }
        }

        # What this run is authorised to change. Static DNS and the proxy are only ever touched when
        # asked for by name, so a finding about either is reported and then left alone. A report-only
        # service is never re-enabled.
        #
        # Each list is built inside @(), not just in its branch: an if statement's output is
        # enumerated, so a single match would otherwise come back as a bare object with no Count on
        # Windows PowerShell.
        $serviceFix = @($state.Services | Where-Object { $_.Start -eq 4 -and -not $_.ReportOnly })
        $interfaceFix = @($state.Interfaces | Where-Object { $_.EnableDhcp -eq 0 })
        $providerFix = @($state.Providers.Providers | Where-Object { $_.Orphaned })
        # An interface whose NameServer simply repeats what DHCP supplied is left alone even when
        # clearStaticDns is passed. There is nothing to clear there, and clearing it would drop the
        # virtual network's own DNS server.
        $dnsFix = @(if ($doClearStaticDns) { $state.Interfaces | Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameServer) -and -not $_.DnsMatchesDhcp } })
        $globalDnsFix = ($doClearStaticDns -and -not [string]::IsNullOrWhiteSpace($state.GlobalNameServer))
        $proxyFix = @(if ($doClearProxy) { $state.Proxy | Where-Object { $_.Active } })
        $plannedCount = $serviceFix.Count + $interfaceFix.Count + $providerFix.Count + $dnsFix.Count + $(if ($globalDnsFix) { 1 } else { 0 }) + $proxyFix.Count

        if ($isDetectOnly) {
            Log-Output '' | Tee-Object -FilePath $logFile -Append
            Log-Output 'detectOnly=true, so nothing was changed. A repair run would:' | Tee-Object -FilePath $logFile -Append
            foreach ($service in $serviceFix) {
                Log-Output "  Set $($service.Service) Start=$($service.Expected) (currently 4, disabled)." | Tee-Object -FilePath $logFile -Append
            }
            foreach ($interface in $interfaceFix) {
                Log-Output "  Return interface $($interface.Interface) to DHCP and remove $(@($interface.Static).Count) static address value(s)." | Tee-Object -FilePath $logFile -Append
            }
            foreach ($provider in $providerFix) {
                Log-Output "  Remove network provider $($provider.Provider) from NetworkProvider\Order." | Tee-Object -FilePath $logFile -Append
            }
            foreach ($interface in $dnsFix) {
                Log-Output "  Clear static DNS '$($interface.NameServer)' from interface $($interface.Interface)." | Tee-Object -FilePath $logFile -Append
            }
            if ($globalDnsFix) { Log-Output "  Clear the global static DNS '$($state.GlobalNameServer)'." | Tee-Object -FilePath $logFile -Append }
            foreach ($entry in $proxyFix) {
                Log-Output "  Disable the machine proxy in $($entry.SubKey)." | Tee-Object -FilePath $logFile -Append
            }

            if ($plannedCount -eq 0) {
                Log-Output '  Nothing. Every finding above is reported only, and needs clearStaticDns=true or clearProxy=true to be acted on.' | Tee-Object -FilePath $logFile -Append
            }
            # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character
            # log, so a summary printed first is the first thing a long run loses.
            Log-Output "Detect only: found $($faults.Count) networking fault(s), $plannedCount of which a repair run would act on. No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        if ($plannedCount -eq 0) {
            Log-Output 'Nothing was changed. Every finding above is reported only, and needs clearStaticDns=true or clearProxy=true to be acted on.' | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        # -----------------------------------------------------------------------------------------
        # Repair
        # -----------------------------------------------------------------------------------------
        #
        # These record what THIS run changed, and are the only safe source for the summary. The
        # manifest is merged with what earlier runs recorded, so counting it would credit this run
        # with an interface an earlier run returned to DHCP. Each record is added before the write
        # it describes, so a write that fails partway is still undone by revert; each counter only
        # moves once a write has been read back.
        $script:ServiceRecord = [System.Collections.Generic.List[object]]::new()
        $script:InterfaceRecord = [System.Collections.Generic.List[object]]::new()
        $script:DnsRecord = [System.Collections.Generic.List[object]]::new()
        $script:ProxyRecord = [System.Collections.Generic.List[object]]::new()
        $script:ProviderResult = $null
        $script:ServiceChanges = 0
        $script:InterfaceChanges = 0
        $script:DnsChanges = 0
        $script:ProviderChanges = 0
        $script:ProxyChanges = 0
        $script:RepairFailures = 0
        $script:ManifestWritten = $false
        $recorded = 0
        $backups = [System.Collections.Generic.List[string]]::new()

        $touchesSystem = ($serviceFix.Count -gt 0 -or $interfaceFix.Count -gt 0 -or $providerFix.Count -gt 0 -or $dnsFix.Count -gt 0 -or $globalDnsFix)

        try {
            if ($touchesSystem) {
                $systemBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SYSTEM'
                [void]$backups.Add($systemBackup)
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append

                Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                    $root = Get-OfflineSystemRootPath -Strict

                    # Services ---------------------------------------------------------------------
                    foreach ($service in $serviceFix) {
                        $path = "$root\Services\$($service.Service)"
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($service.Service): the service key is no longer present, so it was not changed."
                            $script:RepairFailures++
                            continue
                        }
                        [void]$script:ServiceRecord.Add([PSCustomObject]@{ Service = $service.Service; OriginalStart = 4 })
                        try {
                            Set-OfflineNetworkValue -Path $path -Name 'Start' -Kind DWord -Value ([int]$service.Expected)
                            $confirmed = (Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).Start
                            if ($null -ne $confirmed -and [int]$confirmed -eq [int]$service.Expected) {
                                Add-OfflineRepairLog -Level Info -Message "$($service.Service): Start 4 -> $($service.Expected)."
                                $script:ServiceChanges++
                            }
                            else {
                                Add-OfflineRepairLog -Level Error -Message "$($service.Service): Start is $confirmed after the write, not $($service.Expected)."
                                $script:RepairFailures++
                            }
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($service.Service): Start could not be written ($($_.Exception.Message))."
                            $script:RepairFailures++
                        }
                    }

                    # Interfaces -------------------------------------------------------------------
                    foreach ($interface in $interfaceFix) {
                        $path = "$root\Services\Tcpip\Parameters\Interfaces\$($interface.Interface)"
                        if ($interface.Interface -notmatch $script:InterfaceKeyPattern -or -not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($interface.Interface): the interface key is not present or is not a recognised interface key, so it was not changed."
                            $script:RepairFailures++
                            continue
                        }

                        $removed = [System.Collections.Generic.List[object]]::new()
                        $record = [PSCustomObject]@{
                            Interface          = $interface.Interface
                            OriginalEnableDhcp = 0
                            RemovedValues      = @()
                        }
                        [void]$script:InterfaceRecord.Add($record)
                        try {
                            foreach ($value in @($interface.Static)) {
                                $candidate = Get-RemovableValueRecord -Path $path -Name $value.Name -Value $value.Value `
                                    -AllowedName $script:StaticAddressValue -Pattern $script:InterfaceValuePattern
                                if ($candidate.Problem) {
                                    # Never removed unless it can be put back exactly as it was.
                                    Add-OfflineRepairLog -Level Error -Message "$($interface.Interface): $($value.Name) was left in place because it cannot be recorded for revert (it $($candidate.Problem))."
                                    $script:RepairFailures++
                                    continue
                                }
                                [void]$removed.Add($candidate.Record)
                                $record.RemovedValues = @($removed)
                                Remove-OfflineNetworkValue -Path $path -Name $value.Name
                            }

                            Set-OfflineNetworkValue -Path $path -Name 'EnableDHCP' -Kind DWord -Value 1
                            $confirmed = (Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).EnableDHCP
                            if ($null -ne $confirmed -and [int]$confirmed -eq 1) {
                                Add-OfflineRepairLog -Level Info -Message "$($interface.Interface): EnableDHCP 0 -> 1, removed $($removed.Count) static address value(s)."
                                $script:InterfaceChanges++
                            }
                            else {
                                Add-OfflineRepairLog -Level Error -Message "$($interface.Interface): EnableDHCP is $confirmed after the write, not 1."
                                $script:RepairFailures++
                            }
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($interface.Interface): could not be returned to DHCP ($($_.Exception.Message))."
                            $script:RepairFailures++
                        }
                    }

                    # Static DNS, only when asked for by name --------------------------------------
                    $dnsTargets = [System.Collections.Generic.List[object]]::new()
                    foreach ($interface in $dnsFix) {
                        [void]$dnsTargets.Add([PSCustomObject]@{
                                Target = $interface.Interface
                                Path   = "$root\Services\Tcpip\Parameters\Interfaces\$($interface.Interface)"
                                Value  = $interface.NameServer
                                Valid  = ($interface.Interface -match $script:InterfaceKeyPattern)
                            })
                    }
                    if ($globalDnsFix) {
                        [void]$dnsTargets.Add([PSCustomObject]@{
                                Target = $script:GlobalDnsTarget
                                Path   = "$root\Services\Tcpip\Parameters"
                                Value  = $state.GlobalNameServer
                                Valid  = $true
                            })
                    }
                    foreach ($target in $dnsTargets) {
                        if (-not $target.Valid -or -not (Test-Path -LiteralPath $target.Path) -or
                            -not (Test-ManifestText -Value ([string]$target.Value) -Pattern $script:DnsValuePattern -MaxLength 1024)) {
                            Add-OfflineRepairLog -Level Error -Message "$($target.Target): static DNS was left in place because it cannot be recorded for revert."
                            $script:RepairFailures++
                            continue
                        }
                        [void]$script:DnsRecord.Add([PSCustomObject]@{ Target = $target.Target; Value = [string]$target.Value })
                        try {
                            Set-OfflineNetworkValue -Path $target.Path -Name 'NameServer' -Kind String -Value ''
                            Add-OfflineRepairLog -Level Info -Message "$($target.Target): cleared static DNS '$($target.Value)'."
                            $script:DnsChanges++
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($target.Target): static DNS could not be cleared ($($_.Exception.Message))."
                            $script:RepairFailures++
                        }
                    }

                    # Network providers ------------------------------------------------------------
                    #
                    # The list is rewritten once, from the entries that survive, rather than edited by
                    # string replacement. Replacing "Name," inside the string corrupts the order when
                    # one provider name is a prefix of another.
                    if ($providerFix.Count -gt 0) {
                        $orderPath = "$root\Control\NetworkProvider\Order"
                        $orphans = @($providerFix | ForEach-Object { $_.Provider })
                        $original = [string]$state.Providers.ProviderOrder
                        $originalHw = [string]$state.Providers.HwOrder

                        if (-not (Test-ManifestText -Value $original -Pattern $script:ProviderOrderPattern -MaxLength 4096) -or
                            -not (Test-ManifestText -Value $originalHw -Pattern $script:ProviderOrderPattern -MaxLength 4096)) {
                            Add-OfflineRepairLog -Level Error -Message 'The network provider order was left alone because it holds characters that cannot be recorded for revert.'
                            $script:RepairFailures++
                        }
                        else {
                            $script:ProviderResult = [PSCustomObject]@{ Original = $original; OriginalHw = $originalHw }
                            try {
                                $kept = @($original -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $orphans -notcontains $_ })
                                $new = ($kept -join ',')
                                Set-OfflineNetworkValue -Path $orderPath -Name 'ProviderOrder' -Kind String -Value $new
                                $confirmed = [string](Get-ItemProperty -LiteralPath $orderPath -ErrorAction SilentlyContinue).ProviderOrder
                                if ($confirmed -ceq $new) {
                                    Add-OfflineRepairLog -Level Info -Message "NetworkProvider\Order '$original' -> '$new'."
                                    $script:ProviderChanges = $orphans.Count
                                }
                                else {
                                    Add-OfflineRepairLog -Level Error -Message "NetworkProvider\Order reads '$confirmed' after the write, not '$new'."
                                    $script:RepairFailures++
                                }

                                $hwPath = "$root\Control\NetworkProvider\HwOrder"
                                if ((Test-Path -LiteralPath $hwPath) -and -not [string]::IsNullOrWhiteSpace($originalHw)) {
                                    $keptHw = (@($originalHw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $orphans -notcontains $_ }) -join ',')
                                    Set-OfflineNetworkValue -Path $hwPath -Name 'ProviderOrder' -Kind String -Value $keptHw
                                    Add-OfflineRepairLog -Level Info -Message "NetworkProvider\HwOrder '$originalHw' -> '$keptHw'."
                                }
                            }
                            catch {
                                Add-OfflineRepairLog -Level Error -Message "The network provider order could not be written ($($_.Exception.Message))."
                                $script:RepairFailures++
                            }
                        }
                    }
                }
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            }

            # Proxy, only when asked for by name ---------------------------------------------------
            if ($proxyFix.Count -gt 0) {
                $softwareBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SOFTWARE'
                [void]$backups.Add($softwareBackup)
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append

                Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
                    foreach ($entry in $proxyFix) {
                        $path = "HKLM:\BROKENSOFTWARE\$($entry.SubKey)"
                        if (-not (Test-Path -LiteralPath $path)) {
                            Add-OfflineRepairLog -Level Warning -Message "$($entry.SubKey): the key is no longer present, so the proxy was not changed."
                            $script:RepairFailures++
                            continue
                        }

                        $removed = [System.Collections.Generic.List[object]]::new()
                        $record = [PSCustomObject]@{
                            Target        = $entry.SubKey
                            ProxyEnable   = if ($entry.ProxyEnablePresent) { [int]$entry.ProxyEnable } else { $null }
                            RemovedValues = @()
                        }
                        [void]$script:ProxyRecord.Add($record)
                        try {
                            $props = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
                            foreach ($name in $script:ProxyValue) {
                                $current = $props.$name
                                if ($null -eq $current) { continue }
                                $candidate = Get-RemovableValueRecord -Path $path -Name $name -Value $current -AllowedName $script:ProxyValue
                                if ($candidate.Problem) {
                                    Add-OfflineRepairLog -Level Error -Message "$($entry.SubKey): $name was left in place because it cannot be recorded for revert (it $($candidate.Problem))."
                                    $script:RepairFailures++
                                    continue
                                }
                                [void]$removed.Add($candidate.Record)
                                $record.RemovedValues = @($removed)
                                Remove-OfflineNetworkValue -Path $path -Name $name
                            }

                            Set-OfflineNetworkValue -Path $path -Name 'ProxyEnable' -Kind DWord -Value 0
                            $confirmed = (Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).ProxyEnable
                            if ($null -ne $confirmed -and [int]$confirmed -eq 0) {
                                Add-OfflineRepairLog -Level Info -Message "$($entry.SubKey): ProxyEnable set to 0 and $($removed.Count) proxy value(s) removed."
                                $script:ProxyChanges++
                            }
                            else {
                                Add-OfflineRepairLog -Level Error -Message "$($entry.SubKey): ProxyEnable is $confirmed after the write, not 0."
                                $script:RepairFailures++
                            }
                        }
                        catch {
                            Add-OfflineRepairLog -Level Error -Message "$($entry.SubKey): the proxy could not be cleared ($($_.Exception.Message))."
                            $script:RepairFailures++
                        }
                    }
                }
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            }
        }
        finally {
            # Written even when a hive block or its unload threw, so whatever was already changed on
            # the disk can still be reverted.
            $manifest = [PSCustomObject]@{
                Services      = @($script:ServiceRecord)
                Interfaces    = @($script:InterfaceRecord)
                Dns           = @($script:DnsRecord)
                Proxy         = @($script:ProxyRecord)
                ProviderOrder = ''
                HwOrder       = ''
            }
            if ($script:ProviderResult) {
                $manifest.ProviderOrder = $script:ProviderResult.Original
                $manifest.HwOrder = $script:ProviderResult.OriginalHw
            }
            $recorded = @($script:ServiceRecord).Count + @($script:InterfaceRecord).Count + @($script:DnsRecord).Count + @($script:ProxyRecord).Count + $(if ($script:ProviderResult) { 1 } else { 0 })
            if ($recorded -gt 0) {
                try {
                    Write-RevertManifest -Path $manifestPath -Manifest $manifest
                    $script:ManifestWritten = $true
                }
                catch {
                    Add-OfflineRepairLog -Level Error -Message "The revert manifest could not be written to $manifestPath ($($_.Exception.Message)). Use the hive backup(s) to undo this run."
                }
            }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        }

        # Re-read, so the summary reports what the disk now says rather than what was intended.
        $after = Invoke-WithHive -Hive @('SYSTEM', 'SOFTWARE') -WindowsPath $offline.WindowsPath -ScriptBlock {
            return [PSCustomObject]@{
                Services         = @(Get-NetworkServiceState -Strict)
                Interfaces       = @(Get-InterfaceState -Strict)
                GlobalNameServer = (Get-GlobalNameServer -Strict)
                Providers        = (Get-NetworkProviderState -WindowsPath $offline.WindowsPath -Strict)
                Proxy            = @(Get-ProxyState)
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $remaining = [System.Collections.Generic.List[string]]::new()
        foreach ($service in @($after.Services | Where-Object { $_.Start -eq 4 -and -not $_.ReportOnly })) { [void]$remaining.Add("service $($service.Service)") }
        foreach ($interface in @($after.Interfaces | Where-Object { $_.EnableDhcp -eq 0 })) { [void]$remaining.Add("interface $($interface.Interface)") }
        foreach ($provider in @($after.Providers.Providers | Where-Object { $_.Orphaned })) { [void]$remaining.Add("provider $($provider.Provider)") }
        foreach ($interface in $dnsFix) {
            $now = @($after.Interfaces | Where-Object { $_.Interface -eq $interface.Interface })
            if ($now.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($now[0].NameServer)) { [void]$remaining.Add("static DNS on $($interface.Interface)") }
        }
        if ($globalDnsFix -and -not [string]::IsNullOrWhiteSpace($after.GlobalNameServer)) { [void]$remaining.Add('global static DNS') }
        if ($doClearProxy) {
            foreach ($entry in @($after.Proxy | Where-Object { $_.Active })) { [void]$remaining.Add("proxy $($entry.SubKey)") }
        }

        $changes = [int]$script:ServiceChanges + [int]$script:InterfaceChanges + [int]$script:DnsChanges + [int]$script:ProviderChanges + [int]$script:ProxyChanges
        $failures = [int]$script:RepairFailures

        $did = [System.Collections.Generic.List[string]]::new()
        if ([int]$script:ServiceChanges -gt 0) { [void]$did.Add("re-enabled $([int]$script:ServiceChanges) networking service(s)") }
        if ([int]$script:InterfaceChanges -gt 0) { [void]$did.Add("returned $([int]$script:InterfaceChanges) interface(s) to DHCP") }
        if ([int]$script:ProviderChanges -gt 0) { [void]$did.Add("removed $([int]$script:ProviderChanges) orphaned network provider(s)") }
        if ([int]$script:DnsChanges -gt 0) { [void]$did.Add("cleared static DNS on $([int]$script:DnsChanges) target(s)") }
        if ([int]$script:ProxyChanges -gt 0) { [void]$did.Add("cleared the machine proxy in $([int]$script:ProxyChanges) location(s)") }

        $summary = $did -join ', '
        if ([string]::IsNullOrEmpty($summary)) {
            Log-Output "No change could be confirmed on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "$($summary.Substring(0, 1).ToUpper())$($summary.Substring(1)): $changes change(s) on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
        }

        if ($remaining.Count -gt 0) {
            # Log-Output, not Log-Warning: only Log-Output reaches the summary az prints, and the one
            # line that says the repair did not fully work has to be visible there.
            Log-Output "These are still misconfigured after the repair: $($remaining -join ', '). Check the detail log; if they persist the SYSTEM or SOFTWARE hive itself may be damaged." | Tee-Object -FilePath $logFile -Append
        }
        if ($failures -gt 0) {
            Log-Output "$failures change(s) could not be made or confirmed. The detail log names each one." | Tee-Object -FilePath $logFile -Append
        }
        if ($remaining.Count -eq 0 -and $failures -eq 0) {
            Log-Output 'Every networking fault this script was asked to repair is now clear on this disk.' | Tee-Object -FilePath $logFile -Append
        }

        if ([int]$script:InterfaceChanges -gt 0) {
            Log-Output 'The interface(s) returned to DHCP will take their address from the Azure fabric on the next boot. If the VM was deliberately given a static address, set it on the NIC in Azure instead so the fabric and the guest agree.' | Tee-Object -FilePath $logFile -Append

            # Measured, not assumed. A VM repaired this way came back on its DHCP address with working
            # connectivity, and still listed a default route to the old static gateway. The route is
            # inert - Windows gives the DHCP route a better metric and uses it - but it survives
            # reboots, so it is called out with a command scoped to exactly that gateway.
            $oldGateways = @($script:InterfaceRecord | ForEach-Object { @($_.RemovedValues) } |
                    Where-Object { $_.Name -eq 'DefaultGateway' } | ForEach-Object { @($_.Value) } |
                    Where-Object { $_ -and $_ -ne '0.0.0.0' } | Sort-Object -Unique)
            foreach ($gateway in $oldGateways) {
                Log-Output "A persistent default route to the old gateway $gateway can remain if Windows had already applied the static address. It does not block traffic, because the DHCP route wins on metric. To remove it once the VM is back: Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -NextHop $gateway -Confirm:`$false" | Tee-Object -FilePath $logFile -Append
            }
        }

        if ($script:ManifestWritten) {
            Log-Output "What was changed is recorded in $manifestPath. To undo it, run this script again with --parameters revert=true before restoring the disk." | Tee-Object -FilePath $logFile -Append
        }
        elseif ($recorded -gt 0) {
            Log-Output 'The revert manifest could not be written, so revert=true cannot undo this run. Use the hive backup(s) below instead.' | Tee-Object -FilePath $logFile -Append
        }
        if ($backups.Count -gt 0) {
            Log-Output "Hive backup(s): $($backups -join ', '). They and the manifest travel back with the disk and can be deleted once the VM is confirmed healthy." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append

        if ($remaining.Count -gt 0 -or $failures -gt 0 -or ($recorded -gt 0 -and -not $script:ManifestWritten)) {
            $status = $STATUS_ERROR
        }
        else {
            $status = $STATUS_SUCCESS
        }
    } while ($false)
}
catch {
    $status = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
}
finally {
    # A dependency may have failed to load before these functions became available.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        try {
            Clear-OfflineDriveLetter
            if (@(Get-OfflineAssignedDriveLetter).Count -gt 0) {
                $status = $STATUS_ERROR
                Add-OfflineRepairLog -Level Error -Message 'Temporary drive letters remain assigned. Registry repair may have completed, but cleanup is incomplete; inspect the cleanup diagnostics before proceeding.'
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
