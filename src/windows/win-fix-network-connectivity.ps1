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
#        broadly, or a Group Policy service preference that was aimed at a different tier.
#
#     2. An interface has EnableDHCP=0 and a static address. Azure assigns every NIC its address by
#        DHCP, and the platform does not route traffic for an address the fabric did not allocate,
#        so a statically addressed VM is unreachable even when the address happens to be the right
#        one. This is the classic failure after an on-premises migration, a disk restored from a
#        different environment, or a capture-and-redeploy of a VM whose NIC was manually configured.
#
#     3. A network provider is registered whose DLL is gone. Winlogon loads every provider named in
#        NetworkProvider\Order during logon and waits on it, so a stale entry left behind by a
#        partially uninstalled VPN or endpoint client hangs the session at "Please wait for the
#        Network Connections" indefinitely. The network itself is fine; nobody can log on to use it.
#
#     4. A machine-wide proxy or PAC URL is configured that the VM cannot reach. Every outbound
#        request from the guest agent and from Windows Update goes through it and times out, so the
#        VM looks dead to the platform while the network is technically up.
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
#   The SYSTEM and SOFTWARE hives are backed up before either is written to, and every change is
#   recorded in a manifest on the offline disk so "-revert true" can put it back.
#
# .RESOLVES
#   A VM that boots normally but cannot be reached by RDP or SSH, a VM whose guest agent reports
#   "not ready" or "VM status not available" while the guest is running, a VM with no IP address or
#   an address the portal does not recognise, a VM that lost its network after a hardening baseline
#   or tuning script was applied, a migrated or restored VM that has never been reachable in Azure,
#   and a VM that connects but hangs at "Please wait for the Network Connections" during logon.
#
# .PARAMETER detectOnly
#   "true" to report the networking state and what would be changed, and make no changes at all.
#   Defaults to "false".
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
#   offline disk. Defaults to "false".
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
#   Re-enables disabled networking services, returns statically addressed interfaces to DHCP and
#   removes orphaned network providers.
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
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1

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
$script:CriticalService = @('Tcpip', 'NDIS', 'Afd', 'nsi', 'nsiproxy', 'netvsc', 'Dhcp', 'RpcSs', 'DcomLaunch')

# The per-interface values that describe a static address. Removed when an interface is returned to
# DHCP, because leaving them behind means the stack has both a DHCP instruction and a hard-coded
# address to reconcile.
$script:StaticAddressValue = @('IPAddress', 'SubnetMask', 'DefaultGateway', 'DefaultGatewayMetric')

# Network providers shipped with Windows. Never removed, even if the DLL underneath them appears to
# be missing: a missing Microsoft provider DLL is component-store damage, and quietly deleting the
# reference to it hides that rather than repairing it. Only third-party leftovers are removed.
$script:BuiltInProvider = @('LanmanWorkstation', 'RDPNP', 'webclient', 'P9NP')

# The machine-wide proxy settings, in both the 64-bit and 32-bit views.
$script:ProxySubKey = @(
    'Microsoft\Windows\CurrentVersion\Internet Settings',
    'Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings'
)
$script:ProxyValue = @('ProxyServer', 'ProxyOverride', 'AutoConfigURL')

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
        return 'String'
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
            # Not every service exists on every SKU or build - Ndu, for one, is absent on Server
            # 2022. An absent service is not a fault and is not reported as one.
            continue
        }

        $current = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Start
        [void]$state.Add([PSCustomObject]@{
                Service  = $name
                Start    = if ($null -eq $current) { -1 } else { [int]$current }
                Expected = [int]$script:NetworkService[$name]
                Critical = ($script:CriticalService -contains $name)
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

    $a = & $split $First
    $b = & $split $Second
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
                Path          = $path
                SubKey        = $subKey
                ProxyEnable   = if ($null -eq $enabled) { 0 } else { [int]$enabled }
                ProxyServer   = [string]$props.ProxyServer
                ProxyOverride = [string]$props.ProxyOverride
                AutoConfigURL = $autoConfig
                Active        = (($null -ne $enabled -and [int]$enabled -eq 1) -or -not [string]::IsNullOrWhiteSpace($autoConfig))
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

    foreach ($service in @($Services | Where-Object { $_.Start -eq 4 })) {
        $detail = "Start=4 (disabled); a healthy image has Start=$($service.Expected)."
        if ($service.Critical) {
            $detail += ' This service is load-bearing - the TCP/IP stack does not come up without it.'
        }
        [void]$findings.Add((New-Finding -Kind 'Service' -Target $service.Service -Detail $detail -Critical:$service.Critical))
    }

    foreach ($interface in @($Interfaces | Where-Object { $_.EnableDhcp -eq 0 })) {
        $addresses = if (@($interface.Static).Count -gt 0) {
            ($interface.Static | ForEach-Object { "$($_.Name)=$((@($_.Value) -join ','))" }) -join ', '
        }
        else { 'no address recorded' }
        [void]$findings.Add((New-Finding -Kind 'Interface' -Target $interface.Interface -Critical $true `
                    -Detail "EnableDHCP=0 with $addresses. Azure assigns addresses by DHCP and does not route traffic for an address the fabric did not allocate, so this interface cannot reach the network."))
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
        [void]$findings.Add((New-Finding -Kind 'StaticDns' -Target 'Tcpip\Parameters (global)' `
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

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads the manifest a previous run left on the offline disk.

    .DESCRIPTION
        ConvertFrom-Json emits a JSON array as a single pipeline item, so the result is assigned
        before it is wrapped. Wrapping the pipeline directly produces one element holding the whole
        array, and the revert then silently restores nothing.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }

    try {
        $parsed = $content | ConvertFrom-Json
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The revert manifest at $Path could not be read ($($_.Exception.Message))."
        return $null
    }

    return $parsed
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
        value that was genuinely there before any run of this script touched it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $existing = Read-RevertManifest -Path $Path
    if ($existing) {
        foreach ($set in @(
                @{ Name = 'Services'; Key = 'Service' },
                @{ Name = 'Interfaces'; Key = 'Interface' },
                @{ Name = 'Dns'; Key = 'Target' },
                @{ Name = 'Proxy'; Key = 'Target' }
            )) {
            $known = @(@($Manifest.($set.Name)) | ForEach-Object { $_.($set.Key) })
            $carried = @(@($existing.($set.Name)) | Where-Object { $known -notcontains $_.($set.Key) })
            if ($carried.Count -gt 0) {
                $Manifest.($set.Name) = @(@($Manifest.($set.Name)) + $carried)
            }
        }

        if ([string]::IsNullOrEmpty($Manifest.ProviderOrder) -and $existing.ProviderOrder) {
            $Manifest.ProviderOrder = $existing.ProviderOrder
            $Manifest.HwOrder = $existing.HwOrder
        }
    }

    ConvertTo-Json -InputObject $Manifest -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8 -Force
    Add-OfflineRepairLog -Level Info -Message "Recorded what was changed in $Path"
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, clearStaticDns=$doClearStaticDns, clearProxy=$doClearProxy, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $manifestPath = Get-RevertManifestPath -Drive $offline.WindowsDrive

    # ---------------------------------------------------------------------------------------------
    # Revert
    # ---------------------------------------------------------------------------------------------
    if ($isRevert) {
        $manifest = Read-RevertManifest -Path $manifestPath
        if ($null -eq $manifest) {
            Log-Output "No revert manifest was found at $manifestPath, so this script has not changed anything on this disk. No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        $script:RevertCount = 0
        $services = @($manifest.Services)
        $interfaces = @($manifest.Interfaces)
        $dns = @($manifest.Dns)
        $providerOrder = [string]$manifest.ProviderOrder

        if ($services.Count -gt 0 -or $interfaces.Count -gt 0 -or $dns.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($providerOrder)) {
            Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                $root = Get-OfflineSystemRootPath -Strict

                foreach ($entry in $services) {
                    $path = "$root\Services\$($entry.Service)"
                    if (-not (Test-Path $path)) {
                        Add-OfflineRepairLog -Level Warning -Message "$($entry.Service): the service key is no longer present, so it was not restored."
                        continue
                    }
                    $current = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Start
                    Set-ItemProperty -Path $path -Name Start -Value ([int]$entry.OriginalStart) -Type DWord -Force
                    Add-OfflineRepairLog -Level Info -Message "$($entry.Service): Start $current -> $($entry.OriginalStart) (restored)."
                    $script:RevertCount++
                }

                foreach ($entry in $interfaces) {
                    $path = "$root\Services\Tcpip\Parameters\Interfaces\$($entry.Interface)"
                    if (-not (Test-Path $path)) {
                        Add-OfflineRepairLog -Level Warning -Message "$($entry.Interface): the interface key is no longer present, so it was not restored."
                        continue
                    }
                    Set-ItemProperty -Path $path -Name 'EnableDHCP' -Value ([int]$entry.OriginalEnableDhcp) -Type DWord -Force
                    foreach ($value in @($entry.RemovedValues)) {
                        Set-ItemProperty -Path $path -Name $value.Name -Value $value.Value -Type $value.Kind -Force
                    }
                    Add-OfflineRepairLog -Level Info -Message "$($entry.Interface): EnableDHCP restored to $($entry.OriginalEnableDhcp) and $(@($entry.RemovedValues).Count) address value(s) put back."
                    $script:RevertCount++
                }

                foreach ($entry in $dns) {
                    if (-not (Test-Path $entry.Path)) {
                        Add-OfflineRepairLog -Level Warning -Message "$($entry.Target): the key is no longer present, so the DNS setting was not restored."
                        continue
                    }
                    Set-ItemProperty -Path $entry.Path -Name 'NameServer' -Value $entry.Value -Type String -Force
                    Add-OfflineRepairLog -Level Info -Message "$($entry.Target): NameServer restored to '$($entry.Value)'."
                    $script:RevertCount++
                }

                if (-not [string]::IsNullOrWhiteSpace($providerOrder)) {
                    $orderPath = "$root\Control\NetworkProvider\Order"
                    if (Test-Path $orderPath) {
                        Set-ItemProperty -Path $orderPath -Name 'ProviderOrder' -Value $providerOrder -Type String -Force
                        Add-OfflineRepairLog -Level Info -Message "NetworkProvider\Order restored to '$providerOrder'."
                        $script:RevertCount++
                    }
                    $hwPath = "$root\Control\NetworkProvider\HwOrder"
                    if ((Test-Path $hwPath) -and -not [string]::IsNullOrWhiteSpace($manifest.HwOrder)) {
                        Set-ItemProperty -Path $hwPath -Name 'ProviderOrder' -Value ([string]$manifest.HwOrder) -Type String -Force
                        Add-OfflineRepairLog -Level Info -Message "NetworkProvider\HwOrder restored to '$($manifest.HwOrder)'."
                    }
                }
            }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        }

        $proxy = @($manifest.Proxy)
        if ($proxy.Count -gt 0) {
            Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
                foreach ($entry in $proxy) {
                    $path = "HKLM:\BROKENSOFTWARE\$($entry.Target)"
                    if (-not (Test-Path $path)) {
                        Add-OfflineRepairLog -Level Warning -Message "$($entry.Target): the key is no longer present, so the proxy settings were not restored."
                        continue
                    }
                    if ($null -ne $entry.ProxyEnable) {
                        Set-ItemProperty -Path $path -Name 'ProxyEnable' -Value ([int]$entry.ProxyEnable) -Type DWord -Force
                    }
                    foreach ($value in @($entry.RemovedValues)) {
                        Set-ItemProperty -Path $path -Name $value.Name -Value $value.Value -Type $value.Kind -Force
                    }
                    Add-OfflineRepairLog -Level Info -Message "$($entry.Target): proxy settings restored."
                    $script:RevertCount++
                }
            }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        }

        # $script:RevertCount is used because the hive script block runs in a child scope.
        $restored = [int]$script:RevertCount

        if ($restored -gt 0) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
            Log-Output "Restored $restored item(s) and removed the manifest." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'The revert manifest held nothing that could be restored. No changes were made.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # ---------------------------------------------------------------------------------------------
    # Detect
    # ---------------------------------------------------------------------------------------------
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
        Log-Output 'No networking fault was found on this disk. Every networking service is enabled, every interface takes its address from DHCP, no orphaned network provider is registered and no machine proxy is configured.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'The VM is unreachable for some other reason. Check the NSG and effective security rules on the NIC, then win-fix-logon-subsystem if it answers the network but refuses a session.' | Tee-Object -FilePath $logFile -Append
        foreach ($note in $notes) {
            Log-Output "  [$($note.Kind)] $($note.Target): $($note.Detail)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
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
    # asked for by name, so a finding about either is reported and then left alone.
    $serviceFix = @($state.Services | Where-Object { $_.Start -eq 4 })
    $interfaceFix = @($state.Interfaces | Where-Object { $_.EnableDhcp -eq 0 })
    $providerFix = @($state.Providers.Providers | Where-Object { $_.Orphaned })
    # An interface whose NameServer simply repeats what DHCP supplied is left alone even when
    # clearStaticDns is passed. There is nothing to clear there, and clearing it would drop the
    # virtual network's own DNS server.
    $dnsFix = if ($doClearStaticDns) { @($state.Interfaces | Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameServer) -and -not $_.DnsMatchesDhcp }) } else { @() }
    $globalDnsFix = ($doClearStaticDns -and -not [string]::IsNullOrWhiteSpace($state.GlobalNameServer))
    $proxyFix = if ($doClearProxy) { @($state.Proxy | Where-Object { $_.Active }) } else { @() }

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
        $plannedCount = @($serviceFix).Count + @($interfaceFix).Count + @($providerFix).Count + @($dnsFix).Count + $(if ($globalDnsFix) { 1 } else { 0 }) + @($proxyFix).Count

        if ($plannedCount -eq 0) {
            Log-Output '  Nothing. Every finding above is reported only, and needs clearStaticDns=true or clearProxy=true to be acted on.' | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses. Until this line existed a
        # detect run named every fault and then never said how many, or how many it would act on.
        Log-Output "Detect only: found $($faults.Count) networking fault(s), $plannedCount of which a repair run would act on. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # ---------------------------------------------------------------------------------------------
    # Repair
    # ---------------------------------------------------------------------------------------------
    $manifest = [PSCustomObject]@{
        Services      = @()
        Interfaces    = @()
        Dns           = @()
        Proxy         = @()
        ProviderOrder = ''
        HwOrder       = ''
    }
    $changes = 0

    # These record what THIS run changed, and are the only safe source for the summary. The manifest
    # is deliberately merged with what earlier runs recorded, so counting it would credit this run
    # with an interface an earlier run returned to DHCP. They are initialised here rather than inside
    # the branches that fill them so a run that skips a branch reports nothing for it instead of
    # reading a stale or undefined value.
    $script:ServiceChanges = 0
    $script:InterfaceRecord = [System.Collections.Generic.List[object]]::new()
    $script:DnsRecord = [System.Collections.Generic.List[object]]::new()
    $script:ProxyRecord = [System.Collections.Generic.List[object]]::new()
    $script:ProviderResult = $null

    $touchesSystem = ($serviceFix.Count -gt 0 -or $interfaceFix.Count -gt 0 -or $providerFix.Count -gt 0 -or $dnsFix.Count -gt 0 -or $globalDnsFix)

    if ($touchesSystem) {
        $systemBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SYSTEM'
        Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append

        Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $root = Get-OfflineSystemRootPath -Strict

            # Services -------------------------------------------------------------------------
            foreach ($service in $serviceFix) {
                $path = "$root\Services\$($service.Service)"
                if (-not (Test-Path $path)) { continue }
                Set-ItemProperty -Path $path -Name Start -Value ([int]$service.Expected) -Type DWord -Force
                $confirmed = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Start
                if ([int]$confirmed -eq [int]$service.Expected) {
                    Add-OfflineRepairLog -Level Info -Message "$($service.Service): Start 4 -> $($service.Expected)."
                    $script:ServiceChanges++
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "$($service.Service): Start is still $confirmed after the write, so it was not changed."
                }
            }

            # Interfaces -----------------------------------------------------------------------
            foreach ($interface in $interfaceFix) {
                $path = "$root\Services\Tcpip\Parameters\Interfaces\$($interface.Interface)"
                if (-not (Test-Path $path)) { continue }

                $removed = [System.Collections.Generic.List[object]]::new()
                foreach ($value in @($interface.Static)) {
                    [void]$removed.Add([PSCustomObject]@{
                            Name  = $value.Name
                            Value = $value.Value
                            Kind  = (Get-OfflineValueKind -Path $path -Name $value.Name)
                        })
                    Remove-ItemProperty -Path $path -Name $value.Name -Force -ErrorAction SilentlyContinue
                }

                Set-ItemProperty -Path $path -Name 'EnableDHCP' -Value 1 -Type DWord -Force
                $confirmed = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).EnableDHCP
                if ([int]$confirmed -eq 1) {
                    [void]$script:InterfaceRecord.Add([PSCustomObject]@{
                            Interface          = $interface.Interface
                            OriginalEnableDhcp = 0
                            RemovedValues      = @($removed)
                        })
                    Add-OfflineRepairLog -Level Info -Message "$($interface.Interface): EnableDHCP 0 -> 1, removed $(@($removed).Count) static address value(s)."
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "$($interface.Interface): EnableDHCP is still $confirmed after the write."
                }
            }

            # Static DNS, only when asked for by name ------------------------------------------
            foreach ($interface in $dnsFix) {
                $path = "$root\Services\Tcpip\Parameters\Interfaces\$($interface.Interface)"
                if (-not (Test-Path $path)) { continue }
                [void]$script:DnsRecord.Add([PSCustomObject]@{
                        Target = $interface.Interface
                        Path   = $path
                        Value  = $interface.NameServer
                    })
                Set-ItemProperty -Path $path -Name 'NameServer' -Value '' -Type String -Force
                Add-OfflineRepairLog -Level Info -Message "$($interface.Interface): cleared static DNS '$($interface.NameServer)'."
            }

            if ($globalDnsFix) {
                $path = "$root\Services\Tcpip\Parameters"
                [void]$script:DnsRecord.Add([PSCustomObject]@{
                        Target = 'Tcpip\Parameters (global)'
                        Path   = $path
                        Value  = $state.GlobalNameServer
                    })
                Set-ItemProperty -Path $path -Name 'NameServer' -Value '' -Type String -Force
                Add-OfflineRepairLog -Level Info -Message "Cleared the global static DNS '$($state.GlobalNameServer)'."
            }

            # Network providers ----------------------------------------------------------------
            #
            # The list is rewritten once, from the entries that survive, rather than edited by
            # string replacement. Replacing "Name," inside the string corrupts the order when one
            # provider name is a prefix of another.
            if ($providerFix.Count -gt 0) {
                $orderPath = "$root\Control\NetworkProvider\Order"
                $orphans = @($providerFix | ForEach-Object { $_.Provider })
                $original = [string]$state.Providers.ProviderOrder
                $kept = @($original -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $orphans -notcontains $_ })
                $new = ($kept -join ',')

                Set-ItemProperty -Path $orderPath -Name 'ProviderOrder' -Value $new -Type String -Force
                Add-OfflineRepairLog -Level Info -Message "NetworkProvider\Order '$original' -> '$new'."

                $originalHw = [string]$state.Providers.HwOrder
                $hwPath = "$root\Control\NetworkProvider\HwOrder"
                if ((Test-Path $hwPath) -and -not [string]::IsNullOrWhiteSpace($originalHw)) {
                    $keptHw = @($originalHw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $orphans -notcontains $_ })
                    Set-ItemProperty -Path $hwPath -Name 'ProviderOrder' -Value ($keptHw -join ',') -Type String -Force
                    Add-OfflineRepairLog -Level Info -Message "NetworkProvider\HwOrder '$originalHw' -> '$($keptHw -join ',')'."
                }

                $script:ProviderResult = [PSCustomObject]@{ Original = $original; OriginalHw = $originalHw; Removed = @($orphans) }
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $manifest.Services = @($serviceFix | ForEach-Object { [PSCustomObject]@{ Service = $_.Service; OriginalStart = 4 } })
        $manifest.Interfaces = @($script:InterfaceRecord)
        $manifest.Dns = @($script:DnsRecord)
        if ($script:ProviderResult) {
            $manifest.ProviderOrder = $script:ProviderResult.Original
            $manifest.HwOrder = $script:ProviderResult.OriginalHw
        }

        $changes += [int]$script:ServiceChanges
        $changes += @($script:InterfaceRecord).Count
        $changes += @($script:DnsRecord).Count
        if ($script:ProviderResult) { $changes += @($script:ProviderResult.Removed).Count }
    }

    # Proxy, only when asked for by name ------------------------------------------------------
    if ($proxyFix.Count -gt 0) {
        $softwareBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SOFTWARE'
        Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append

        $script:ProxyRecord = [System.Collections.Generic.List[object]]::new()
        Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            foreach ($entry in $proxyFix) {                if (-not (Test-Path $entry.Path)) { continue }

                $removed = [System.Collections.Generic.List[object]]::new()
                foreach ($name in $script:ProxyValue) {
                    $current = (Get-ItemProperty -Path $entry.Path -ErrorAction SilentlyContinue).$name
                    if ($null -eq $current) { continue }
                    [void]$removed.Add([PSCustomObject]@{
                            Name  = $name
                            Value = $current
                            Kind  = (Get-OfflineValueKind -Path $entry.Path -Name $name)
                        })
                    Remove-ItemProperty -Path $entry.Path -Name $name -Force -ErrorAction SilentlyContinue
                }

                Set-ItemProperty -Path $entry.Path -Name 'ProxyEnable' -Value 0 -Type DWord -Force
                [void]$script:ProxyRecord.Add([PSCustomObject]@{
                        Target        = $entry.SubKey
                        ProxyEnable   = $entry.ProxyEnable
                        RemovedValues = @($removed)
                    })
                Add-OfflineRepairLog -Level Info -Message "$($entry.SubKey): ProxyEnable set to 0 and $(@($removed).Count) proxy value(s) removed."
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $manifest.Proxy = @($script:ProxyRecord)
        $changes += @($script:ProxyRecord).Count
    }

    # ---------------------------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------------------------
    if ($changes -eq 0) {
        Log-Output 'Nothing was changed. Every finding above is reported only, and needs clearStaticDns=true or clearProxy=true to be acted on.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    Write-RevertManifest -Path $manifestPath -Manifest $manifest
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Re-read, so the summary reports what the disk now says rather than what was intended.
    $after = Invoke-WithHive -Hive @('SYSTEM', 'SOFTWARE') -WindowsPath $offline.WindowsPath -ScriptBlock {
        return [PSCustomObject]@{
            Services   = @(Get-NetworkServiceState -Strict)
            Interfaces = @(Get-InterfaceState -Strict)
            Providers  = (Get-NetworkProviderState -WindowsPath $offline.WindowsPath -Strict)
            Proxy      = @(Get-ProxyState)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $remaining = [System.Collections.Generic.List[string]]::new()
    foreach ($service in @($after.Services | Where-Object { $_.Start -eq 4 })) { [void]$remaining.Add("service $($service.Service)") }
    foreach ($interface in @($after.Interfaces | Where-Object { $_.EnableDhcp -eq 0 })) { [void]$remaining.Add("interface $($interface.Interface)") }
    foreach ($provider in @($after.Providers.Providers | Where-Object { $_.Orphaned })) { [void]$remaining.Add("provider $($provider.Provider)") }
    if ($doClearProxy) {
        foreach ($entry in @($after.Proxy | Where-Object { $_.Active })) { [void]$remaining.Add("proxy $($entry.SubKey)") }
    }

    $did = [System.Collections.Generic.List[string]]::new()
    if ([int]$script:ServiceChanges -gt 0) { [void]$did.Add("re-enabled $([int]$script:ServiceChanges) networking service(s)") }
    if (@($script:InterfaceRecord).Count -gt 0) { [void]$did.Add("returned $(@($script:InterfaceRecord).Count) interface(s) to DHCP") }
    if ($script:ProviderResult) { [void]$did.Add("removed $(@($script:ProviderResult.Removed).Count) orphaned network provider(s)") }
    if (@($script:DnsRecord).Count -gt 0) { [void]$did.Add("cleared static DNS on $(@($script:DnsRecord).Count) target(s)") }
    if (@($script:ProxyRecord).Count -gt 0) { [void]$did.Add("cleared the machine proxy in $(@($script:ProxyRecord).Count) location(s)") }

    $summary = $did -join ', '
    if ([string]::IsNullOrEmpty($summary)) {
        # Unreachable while the $changes -eq 0 guard above returns, but the count and the per-run
        # records are maintained separately. If they ever disagree, report the count rather than
        # calling Substring on an empty string and failing the run over a summary line.
        Log-Output "$changes change(s) on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "$($summary.Substring(0, 1).ToUpper())$($summary.Substring(1)): $changes change(s) on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
    }

    if ($remaining.Count -gt 0) {
        # Log-Output, not Log-Warning: only Log-Output reaches the summary az prints, and the one
        # line that says the repair did not fully work has to be visible there.
        Log-Output "These are still misconfigured after the repair: $($remaining -join ', '). Re-run this script; if they persist the SYSTEM hive itself may be damaged." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output 'Every networking fault this script repairs is now clear on this disk.' | Tee-Object -FilePath $logFile -Append
    }

    if (@($script:InterfaceRecord).Count -gt 0) {
        Log-Output 'The interface(s) returned to DHCP will take their address from the Azure fabric on the next boot. If the VM was deliberately given a static address, set it on the NIC in Azure instead so the fabric and the guest agree.' | Tee-Object -FilePath $logFile -Append
        # Measured, not assumed. A VM repaired this way came back on its DHCP address with working
        # connectivity, and still listed a default route to the old static gateway. The route is
        # inert - Windows gives the DHCP route a better metric and uses it - but it is untidy and it
        # survives reboots, so it is called out with the command that clears it rather than left for
        # someone to find later and misread as the repair having failed.
        Log-Output "If the static address had already been applied by Windows, a default route to the old gateway can remain in the persistent route store. It is not in the registry this script can reach offline, and it does not block traffic because the DHCP route wins on metric. To tidy it once the VM is back: Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object NextHop -ne (Get-NetIPConfiguration).IPv4DefaultGateway.NextHop | Remove-NetRoute -Confirm:`$false" | Tee-Object -FilePath $logFile -Append
    }

    Log-Output "Re-run with -revert true to undo this, or run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
