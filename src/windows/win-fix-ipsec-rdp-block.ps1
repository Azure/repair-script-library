#########################################################################################################
#
# .SYNOPSIS
#   Turns off an IPsec connection security rule that requires inbound IPsec for Remote Desktop, so an
#   Azure VM that boots, is on the network and times out on every RDP attempt can be reached again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM whose guest agent is Ready, whose boot diagnostics show a logon screen, whose
#   Remote Desktop listener is configured correctly and whose firewall allows TCP 3389 - and every
#   RDP attempt still ends in a bare timeout. Nothing is refused and nothing is logged as a drop.
#
#   The cause is a connection security rule (an "IPsec rule", New-NetIPsecRule, or the Connection
#   Security Rules node in wf.msc) whose action requires inbound security. Windows then demands a
#   completed IPsec negotiation before it accepts any inbound packet in the rule's scope. An RDP
#   client with no matching IPsec policy cannot complete it, so the SYN is silently discarded inside
#   the Windows Filtering Platform. A rule with no protocol, port or address scope covers ALL
#   inbound traffic, and the VM is cut off completely apart from what the Azure platform itself
#   carries.
#
#   Rules are read from both stores Windows enforces:
#
#     - the local store, SYSTEM\<control set>\Services\SharedAccess\Parameters\FirewallPolicy\
#       ConSecRules, which is where New-NetIPsecRule and wf.msc write;
#     - the Group Policy store, SOFTWARE\Policies\Microsoft\WindowsFirewall\ConSecRules, which is
#       where a domain or local GPO's rules are cached.
#
#   Each rule is parsed with the grammar in [MS-GPFAS] section 2.2.6.2
#   (https://learn.microsoft.com/openspecs/windows_protocols/ms-gpfas/885f236b-39f5-4a83-bac8-3c5459e88a9a).
#
#   TRIGGER. A rule is repaired only when the offline disk shows it demands inbound IPsec for RDP,
#   which a client with no matching IPsec policy cannot satisfy: it is Active, its
#   action is Secure or SecureServer (the two that require inbound security), and its protocol and
#   local port scope include TCP on the port the RDP listener actually uses. Boundary and
#   DoNotSecure rules, inactive rules, and rules scoped to another protocol or port are left alone.
#   A healthy disk produces no findings and this script writes nothing at all.
#
#   TARGET. The rule's Active=TRUE token is changed to Active=FALSE. That is the same state
#   Disable-NetIPsecRule leaves, so the rule is turned off rather than deleted: its name,
#   authentication sets and scope are all kept, and it can be turned back on with
#   Enable-NetIPsecRule once the VM is reachable and its policy is understood. Every other byte of
#   the rule string is preserved, and the result is read back, re-parsed and confirmed inactive
#   before the repair is counted.
#
#   REPORTED BUT NEVER CHANGED. Anything whose effect cannot be proven from a dismounted disk is
#   reported as needing a decision, because changing it would be a change the evidence did not
#   justify:
#
#     - a rule scoped by address, by remote port, by interface or interface type, or by a local
#       port keyword such as RPC - whether it applies depends on the client and the network;
#     - a tunnel-mode rule, or one carrying a token this check does not evaluate;
#     - a rule whose Active or Action token is repeated or has an unexpected value, a rule string
#       that does not follow the grammar, or a value that is not a REG_SZ;
#     - a store or rule that could not be read, so "no rules found" is never reported for a key
#       that was simply locked;
#     - a local rule on a machine where Group Policy turns local connection security rules off
#       (AllowLocalIPsecPolicyMerge=0) for some but not all of the rule's profiles - which profile
#       is active is not knowable offline. Where Group Policy turns them off for every profile the
#       rule applies to, the rule is not enforced and is not a finding.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-ipsec-rdp-block --run-on-repair
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-ipsec-rdp-block --run-on-repair --parameters detectOnly=true
#
#   Reports every connection security rule that blocks or may block Remote Desktop and changes
#   nothing.
#
# .PARAMETER detectOnly
#   "true" to report what was found and change nothing at all. Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .NOTES
#   There is no revert switch. Before anything is written the hive that holds the rule is backed up
#   next to itself on the customer's disk, and that copy is the rollback. Once the VM is reachable,
#   Enable-NetIPsecRule -Name '<rule id>' turns a rule back on, and Remove-NetIPsecRule -Name
#   '<rule id>' removes one that should not exist. Both need the BFE and MpsSvc services running.
#
#   A rule delivered by Group Policy comes back at the next policy refresh unless the GPO that
#   delivers it is changed. Turning it off here only restores access long enough to do that.
#
#   A firewall that blocks inbound TCP 3389, a firewall service that will not start, and Remote
#   Desktop turned off in the Terminal Server configuration are different faults. They are covered
#   handled separately (the firewall service by win-fix-firewall-service), and nothing in the
#   firewall's rule set, profile configuration or the Terminal Server configuration is written
#   here. This script needs SYSTEM and SOFTWARE to mount before it can read anything; if either
#   hive is damaged, repair the hive first.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Parameters are used inside script blocks passed to the offline helpers, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')

$script:LocalStoreSubPath = 'Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules'
$script:PolicyStorePath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\WindowsFirewall\ConSecRules'
$script:PolicyFirewallPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\WindowsFirewall'
$script:RdpTcpSubPath = 'Control\Terminal Server\WinStations\RDP-Tcp'
$script:StandardRdpPort = 3389
$script:SpecUrl = 'https://learn.microsoft.com/openspecs/windows_protocols/ms-gpfas/885f236b-39f5-4a83-bac8-3c5459e88a9a'

# The profile names a rule's Profile token uses, mapped to the Group Policy key that carries
# AllowLocalIPsecPolicyMerge for that profile.
$script:ProfileKey = [ordered]@{ Domain = 'DomainProfile'; Private = 'PrivateProfile'; Public = 'PublicProfile' }

# Every token [MS-GPFAS] 2.2.6.2 defines for a connection security rule. A token outside this list
# is one this check cannot reason about, so a rule carrying it is reported rather than repaired.
$script:KnownTokens = @(
    'Action', 'Profile', 'Protocol', 'EP1Port', 'EP2Port', 'EP1Port2_10', 'EP2Port2_10', 'IF', 'IFType',
    'Auth1Set', 'Auth2Set', 'Crypto2Set', 'EP1_4', 'EP2_4', 'EP1_6', 'EP2_6', 'Name', 'Desc', 'EmbedCtxt',
    'Active', 'Platform', 'SkipVer', 'Platform2', 'SecureInClearOut', 'ByPassTunnel', 'Authz',
    'RTunnel4', 'RTunnel6', 'LTunnel4', 'LTunnel6', 'RTunnel4_2', 'RTunnel6_2', 'LTunnel4_2', 'LTunnel6_2',
    'RTunnelFqdn', 'RTunEndpts4', 'RTunEndpts6', 'KeyMod', 'KeyManagerDictate', 'KeyManagerNotify',
    'FwdLifetime', 'TransportMachineAuthzSDDL', 'TransportUserAuthzSDDL', 'SecurityRealmEnabled'
)

# Tokens that narrow where a rule applies in a way the offline disk cannot resolve: tunnel
# endpoints, an interface or interface type, and a version-skip marker.
$script:UnresolvableTokens = @(
    'RTunnel4', 'RTunnel6', 'LTunnel4', 'LTunnel6', 'RTunnel4_2', 'RTunnel6_2', 'LTunnel4_2', 'LTunnel6_2',
    'RTunnelFqdn', 'RTunEndpts4', 'RTunEndpts6', 'IF', 'IFType', 'SkipVer'
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
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'SOFTWARE')][string]$Hive,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Hive       = $Hive
        Hives      = @($Hive)
        Repairable = $Repairable
        Data       = $Data
    }
}

function Get-ConSecToken {
    <#
    .SYNOPSIS
        Every value a parsed rule holds for one token, as a string array that may be empty.
    #>
    param($Tokens, [Parameter(Mandatory = $true)][string]$Name)

    if ($Tokens -and $Tokens.ContainsKey($Name)) { return [string[]]@($Tokens[$Name]) }
    return [string[]]@()
}

function ConvertFrom-ConSecRuleString {
    <#
    .SYNOPSIS
        Parsing one connection security rule string, [MS-GPFAS] 2.2.6.2.

    .DESCRIPTION
        v2.31|Action=SecureServer|Name=X|Desc=|Active=TRUE|Auth1Set=...|EmbedCtxt=|

        The rule id is the registry value NAME, not a token. Tokens may legitimately repeat
        (EP1Port, EP1_4, Profile), so every token is collected as a list.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RuleString,
        [Parameter(Mandatory = $false)][string]$RuleId = ''
    )

    $tokens = @{}
    $version = ''
    $malformed = $false
    $lastName = ''
    $segments = $RuleString -split '\|'

    for ($i = 0; $i -lt $segments.Count; $i++) {
        $segment = $segments[$i]
        if ($i -eq 0) {
            if ($segment -match '^v[\d.]+$') { $version = $segment.Substring(1) }
            else { $malformed = $true }
            continue
        }
        if ([string]::IsNullOrEmpty($segment)) { continue }

        $split = $segment.IndexOf('=')
        if ($split -lt 1) {
            # A literal '|' inside a free-text Name= or Desc= lands here. Appending it back to the
            # previous token keeps the original text intact instead of inventing a token, and the
            # rule is marked so it is never treated as fully understood.
            if ($lastName -and $tokens[$lastName].Count -gt 0) {
                $tokens[$lastName][$tokens[$lastName].Count - 1] += '|' + $segment
            }
            $malformed = $true
            continue
        }

        $name = $segment.Substring(0, $split)
        if (-not $tokens.ContainsKey($name)) { $tokens[$name] = [System.Collections.Generic.List[string]]::new() }
        $tokens[$name].Add($segment.Substring($split + 1))
        $lastName = $name
    }

    return [PSCustomObject]@{
        RuleId    = $RuleId
        Version   = $version
        Tokens    = $tokens
        Malformed = $malformed
    }
}

function Test-ConSecPortCoverage {
    <#
    .SYNOPSIS
        Whether a rule's port scope includes a port.

    .DESCRIPTION
        $true  - the port falls inside the declared scope, or no scope was declared.
        $false - the port falls outside it.
        $null  - the scope holds an entry this check cannot evaluate (a keyword such as RPC), so
                 coverage is genuinely unknown. Callers must not collapse that into either answer.
    #>
    param(
        [Parameter(Mandatory = $false)][string[]]$SinglePorts = @(),
        [Parameter(Mandatory = $false)][string[]]$PortRanges = @(),
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port
    )

    $entries = @(@($SinglePorts) + @($PortRanges) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($entries.Count -eq 0) { return $true }

    $unknown = $false
    foreach ($entry in $entries) {
        if ($entry -match '^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
        elseif ($entry -match '^\s*(\d{1,5})\s*$') {
            if ($Port -eq [int]$Matches[1]) { return $true }
        }
        else { $unknown = $true }
    }
    if ($unknown) { return $null }
    return $false
}

function Get-ConSecRuleRdpImpact {
    <#
    .SYNOPSIS
        Deciding what one parsed rule does to an inbound Remote Desktop connection.

    .DESCRIPTION
        Verdicts:
          Inert       - not enforced (Active absent or FALSE).
          NotBlocking - enforced, but cannot drop an unsecured inbound RDP connection.
          Suppressed  - a local rule Group Policy turns off for every profile it applies to.
          Blocking    - proven from the disk to require inbound IPsec for RDP. The only repairable verdict.
          Conditional - requires inbound IPsec on a scope that may include RDP, but proving it needs
                        something the offline disk cannot tell (client address, active profile ...).
          Unknown     - the Action is absent, repeated or not one this check recognises.
          Ambiguous   - Active is repeated or holds a value other than TRUE or FALSE.
          Malformed   - the rule string does not follow the grammar and Active=TRUE appears in it.

        SuppressedProfiles and UnknownMergeProfiles are only passed for the local store: Group Policy
        can turn local rules off per profile, but never its own.
    #>
    param(
        [Parameter(Mandatory = $true)]$Rule,
        [Parameter(Mandatory = $false)][ValidateRange(1, 65535)][int]$RdpPort = 3389,
        [Parameter(Mandatory = $false)][bool]$RdpPortKnown = $true,
        [Parameter(Mandatory = $false)][string[]]$SuppressedProfiles = @(),
        [Parameter(Mandatory = $false)][string[]]$UnknownMergeProfiles = @()
    )

    $tokens = $Rule.Tokens
    $actions = @(Get-ConSecToken $tokens 'Action')
    $actives = @(Get-ConSecToken $tokens 'Active')
    $protocols = @(Get-ConSecToken $tokens 'Protocol')
    $ep1Ports = @(Get-ConSecToken $tokens 'EP1Port')
    $ep1Ranges = @(Get-ConSecToken $tokens 'EP1Port2_10')
    $ep2Ports = @(Get-ConSecToken $tokens 'EP2Port')
    $ep2Ranges = @(Get-ConSecToken $tokens 'EP2Port2_10')
    $addresses = @(@('EP1_4', 'EP1_6', 'EP2_4', 'EP2_6') | ForEach-Object { Get-ConSecToken $tokens $_ })
    $authSets = @(@('Auth1Set', 'Auth2Set') | ForEach-Object { Get-ConSecToken $tokens $_ })
    $profiles = @(Get-ConSecToken $tokens 'Profile')
    $action = $actions | Select-Object -First 1

    $result = [ordered]@{
        RuleId    = $Rule.RuleId
        Name      = (@(Get-ConSecToken $tokens 'Name') | Select-Object -First 1)
        Action    = $action
        Active    = $false
        Verdict   = 'NotBlocking'
        Reason    = ''
        Unscoped  = $false
        Profiles  = [string[]]$profiles
        AuthSets  = [string[]]$authSets
        Malformed = [bool]$Rule.Malformed
    }

    $activeTrue = @($actives | Where-Object { $_ -ieq 'TRUE' })

    # An absent Active token means FALSE ([MS-GPFAS] 2.2.6.2), and a rule with no TRUE anywhere in
    # it cannot be enforced however badly the rest of it is formed.
    if ($activeTrue.Count -eq 0 -and @($actives | Where-Object { $_ -ine 'FALSE' }).Count -eq 0) {
        $result.Verdict = 'Inert'
        $result.Reason = 'the rule is stored but Active is not TRUE, so it is not enforced'
        return [PSCustomObject]$result
    }

    if ($Rule.Malformed) {
        if ($activeTrue.Count -eq 0) {
            $result.Verdict = 'Inert'
            $result.Reason = 'the rule string does not follow the grammar, but nothing in it sets Active=TRUE'
            return [PSCustomObject]$result
        }
        $result.Verdict = 'Malformed'
        $result.Reason = 'the rule string does not follow the [MS-GPFAS] grammar (a missing version prefix, or a segment with no "=", such as a "|" inside its name or description), so how Windows reads it cannot be determined'
        return [PSCustomObject]$result
    }

    if ($actives.Count -ne 1 -or $activeTrue.Count -ne 1) {
        $result.Verdict = 'Ambiguous'
        $result.Reason = "Active appears $($actives.Count) time(s) with value(s) $($actives -join ', '); the grammar allows exactly one TRUE or FALSE, so whether the rule is enforced cannot be determined"
        return [PSCustomObject]$result
    }
    $result.Active = $true

    if ($actions.Count -ne 1) {
        $result.Verdict = 'Unknown'
        $result.Reason = "Action appears $($actions.Count) time(s)$(if ($actions.Count) { " ($($actions -join ', '))" }); the grammar requires exactly one, so the rule's effect on RDP could not be determined"
        return [PSCustomObject]$result
    }

    # Only the two require-inbound actions can drop an unsecured inbound SYN. Boundary requests
    # security and falls back to clear text; DoNotSecure exempts.
    if ($action -ieq 'Boundary' -or $action -ieq 'DoNotSecure') {
        $result.Reason = "Action=$action does not require inbound security"
        return [PSCustomObject]$result
    }
    if (@('SecureServer', 'Secure') -notcontains $action) {
        $result.Verdict = 'Unknown'
        $result.Reason = "Action=$action is not a recognised connection security action, so its effect on RDP could not be determined"
        return [PSCustomObject]$result
    }

    # Profile absent means every profile.
    $unknownProfiles = @($profiles | Where-Object { $script:ProfileKey.Keys -notcontains $_ })
    $ruleProfiles = if ($profiles.Count -eq 0) { @($script:ProfileKey.Keys) } else { @($profiles | Where-Object { $script:ProfileKey.Keys -contains $_ } | Sort-Object -Unique) }
    $suppressed = @($ruleProfiles | Where-Object { $SuppressedProfiles -contains $_ })
    $mergeUnknown = @($ruleProfiles | Where-Object { $UnknownMergeProfiles -contains $_ })
    if ($unknownProfiles.Count -eq 0 -and $ruleProfiles.Count -gt 0 -and $suppressed.Count -eq $ruleProfiles.Count) {
        $result.Verdict = 'Suppressed'
        $result.Reason = "Action=$action requires inbound security, but Group Policy sets AllowLocalIPsecPolicyMerge=0 for every profile the rule applies to ($($ruleProfiles -join ', ')), so local connection security rules are not enforced"
        return [PSCustomObject]$result
    }

    # Protocol absent means every protocol. RDP is TCP, IP protocol 6.
    if ($protocols.Count -gt 0) {
        $numeric = @($protocols | Where-Object { $_ -match '^\d{1,3}$' } | ForEach-Object { [int]$_ })
        if ($numeric.Count -ne $protocols.Count) {
            $result.Verdict = 'Conditional'
            $result.Reason = "Action=$action requires inbound security and the Protocol scope ($($protocols -join ', ')) could not be evaluated offline"
            return [PSCustomObject]$result
        }
        if ($numeric -notcontains 6) {
            $result.Reason = "Action=$action requires inbound security but the rule is scoped to IP protocol $($numeric -join ', '), not TCP (6)"
            return [PSCustomObject]$result
        }
    }

    # Endpoint 1 is the local machine for an inbound connection, so EP1Port is the listener port.
    $localPortList = @(@($ep1Ports + $ep1Ranges) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $localCoverage = Test-ConSecPortCoverage -SinglePorts $ep1Ports -PortRanges $ep1Ranges -Port $RdpPort
    if ($RdpPortKnown -and $false -eq $localCoverage) {
        $result.Reason = "Action=$action requires inbound security but the local port scope ($($localPortList -join ', ')) does not include the RDP port $RdpPort"
        return [PSCustomObject]$result
    }

    $addressList = @($addresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $remotePortList = @(@($ep2Ports + $ep2Ranges) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $presentTokens = @($tokens.Keys)
    $unresolvable = @($presentTokens | Where-Object { $script:UnresolvableTokens -contains $_ } | Sort-Object)
    $unknownTokens = @($presentTokens | Where-Object { $script:KnownTokens -notcontains $_ } | Sort-Object)
    $result.Unscoped = ($localPortList.Count -eq 0 -and $remotePortList.Count -eq 0 -and $addressList.Count -eq 0 -and $protocols.Count -eq 0 -and $unresolvable.Count -eq 0)

    # Anything that cannot be resolved from a dismounted disk downgrades the verdict to Conditional.
    # Reporting a scoped rule as a confirmed block would invite a repair that changes something the
    # evidence never proved was at fault.
    $uncertain = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $localCoverage) {
        $uncertain.Add("the local port scope ($($localPortList -join ', ')) uses a keyword this check cannot resolve offline")
    }
    elseif (-not $RdpPortKnown -and $localPortList.Count -gt 0) {
        $uncertain.Add("the rule is scoped to local port(s) $($localPortList -join ', ') and the RDP listener port could not be read")
    }
    if ($addressList.Count -gt 0) {
        $uncertain.Add("the rule is address-scoped ($($addressList -join ', ')) and the client address is not knowable offline")
    }
    if ($remotePortList.Count -gt 0) {
        $uncertain.Add("the rule restricts the remote port ($($remotePortList -join ', ')) while an RDP client's source port is ephemeral")
    }
    if ($unresolvable.Count -gt 0) {
        $uncertain.Add("the rule is narrowed by $($unresolvable -join ', ') (tunnel, interface or version scope), which cannot be resolved offline")
    }
    if ($unknownTokens.Count -gt 0) {
        $uncertain.Add("the rule carries token(s) this check does not recognise ($($unknownTokens -join ', '))")
    }
    if ($unknownProfiles.Count -gt 0) {
        $uncertain.Add("the Profile scope holds value(s) this check does not recognise ($($unknownProfiles -join ', '))")
    }
    if ($suppressed.Count -gt 0) {
        $uncertain.Add("Group Policy sets AllowLocalIPsecPolicyMerge=0 for $($suppressed -join ', ') but not for every profile the rule applies to, and which profile is active is not knowable offline")
    }
    if ($mergeUnknown.Count -gt 0) {
        $uncertain.Add("whether Group Policy allows local connection security rules for $($mergeUnknown -join ', ') could not be read")
    }

    if ($uncertain.Count -gt 0) {
        $result.Verdict = 'Conditional'
        $result.Reason = "Action=$action requires inbound IPsec on a scope that can include TCP port $RdpPort, but $($uncertain -join '; ')"
    }
    elseif ($result.Unscoped) {
        $result.Verdict = 'Blocking'
        $result.Reason = "Action=$action requires inbound IPsec and the rule carries no protocol, port or address scope, so it applies to ALL inbound traffic including RDP on TCP $RdpPort"
    }
    else {
        $result.Verdict = 'Blocking'
        $result.Reason = "Action=$action requires inbound IPsec on a scope that includes TCP port $RdpPort"
    }
    return [PSCustomObject]$result
}

function Get-ConSecRuleDescription {
    <#
    .SYNOPSIS
        A one-line description of a rule for the log: its name, id, action, profiles and auth sets.
    #>
    param([Parameter(Mandatory = $true)]$Impact)

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("'$(if ([string]::IsNullOrWhiteSpace($Impact.Name)) { '(unnamed)' } else { $Impact.Name })'")
    $parts.Add("id $($Impact.RuleId)")
    if ($Impact.Action) { $parts.Add("Action=$($Impact.Action)") }
    $parts.Add("Profile=$(if (@($Impact.Profiles).Count -gt 0) { @($Impact.Profiles) -join '+' } else { 'all' })")
    if (@($Impact.AuthSets).Count -gt 0) { $parts.Add("auth set(s) $(@($Impact.AuthSets) -join ', ')") }
    return ($parts -join ', ')
}

function Get-ConSecRuleDisabledString {
    <#
    .SYNOPSIS
        The rule string with exactly its Active token flipped to FALSE, or $null.

    .DESCRIPTION
        Every other byte of the rule is left alone. Returns $null when the string does not hold
        exactly one Active=TRUE segment, so a caller can never write a string it did not fully
        understand. The last segment of a rule normally ends in "|", but the lookahead also accepts
        the end of the string, so a rule written without the trailing separator is not refused.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$RuleString)

    $pattern = '(?<=\|)Active=TRUE(?=\||$)'
    # Not named $matches: that is an automatic variable, and shadowing it would silently break any
    # -match in this scope.
    $hits = [regex]::Matches($RuleString, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($hits.Count -ne 1) { return $null }
    return [regex]::Replace($RuleString, $pattern, 'Active=FALSE', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function ConvertFrom-RegistryStringByte {
    <#
    .SYNOPSIS
        The exact text of a REG_SZ value, without the terminating NUL.
    #>
    param([Parameter(Mandatory = $false)][AllowNull()][byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Count -eq 0) { return '' }
    return [System.Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char]0)
}

function Test-OfflineRegistryKeyPath {
    <#
    .SYNOPSIS
        Whether a key exists in a loaded offline hive, found without ever opening a missing key.

    .DESCRIPTION
        The privileged helpers open keys with RegCreateKeyEx, which treats a missing key as an
        error rather than "absent" and, for a missing parent, creates the parent before removing
        only the leaf. Walking down from the hive root and listing each existing parent's subkeys
        answers the question without either problem, so a probe never writes to the customer's
        hive. Ok is $false only when a parent that exists could not be listed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Exists = $false; Error = '' }

    $match = [regex]::Match($Path, '^(HKLM:\\[^\\]+)\\?(.*)$')
    if (-not $match.Success) {
        $result.Error = "$Path is not a path under a loaded hive."
        return $result
    }

    $current = $match.Groups[1].Value
    foreach ($segment in @($match.Groups[2].Value.Split('\') | Where-Object { $_ })) {
        $children = Get-OfflinePrivilegedRegistrySubKeyName -Path $current
        if (-not $children.Ok) {
            $result.Error = "$current could not be listed ($($children.Error))"
            return $result
        }
        $child = @($children.Names | Where-Object { $_ -eq $segment }) | Select-Object -First 1
        if (-not $child) {
            $result.Ok = $true
            return $result
        }
        $current = Join-Path $current $child
    }

    $result.Ok = $true
    $result.Exists = $true
    return $result
}

function Get-RdpListenerPort {
    <#
    .SYNOPSIS
        The TCP port the offline RDP-Tcp listener is configured to use.

    .DESCRIPTION
        Known is $false when the value exists but could not be read or is not a usable port. The
        port then falls back to 3389, and any rule scoped to particular local ports is reported
        rather than judged against a number that may be wrong.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $path = Join-Path $SystemRoot $script:RdpTcpSubPath
    $state = [PSCustomObject]@{ Port = $script:StandardRdpPort; Known = $true; Note = '' }

    $key = Test-OfflineRegistryKeyPath -Path $path
    if (-not $key.Ok) {
        $state.Known = $false
        $state.Note = "the RDP-Tcp key could not be checked ($($key.Error)); $($script:StandardRdpPort) is assumed and port-scoped rules are reported rather than judged"
        return $state
    }
    if (-not $key.Exists) {
        $state.Note = "the RDP-Tcp key is not present, so $($script:StandardRdpPort) is assumed"
        return $state
    }

    $value = Get-OfflinePrivilegedRegistryValue -Path $path -Name 'PortNumber'
    if (-not $value.Ok) {
        $state.Known = $false
        $state.Note = "PortNumber could not be read ($($value.Error)); $($script:StandardRdpPort) is assumed and port-scoped rules are reported rather than judged"
        return $state
    }
    if (-not $value.Found) {
        $state.Note = "PortNumber is not set, so the listener uses the default $($script:StandardRdpPort)"
        return $state
    }

    # 4 is REG_DWORD.
    if ($value.Type -ne 4 -or $value.ByteLength -ne 4) {
        $state.Known = $false
        $state.Note = "PortNumber is type $($value.Type), $($value.ByteLength) byte(s), not a REG_DWORD; $($script:StandardRdpPort) is assumed and port-scoped rules are reported rather than judged"
        return $state
    }

    $port = [System.BitConverter]::ToUInt32($value.Bytes, 0)
    if ($port -lt 1 -or $port -gt 65535) {
        $state.Known = $false
        $state.Note = "PortNumber is $port, which is not a TCP port; $($script:StandardRdpPort) is assumed and port-scoped rules are reported rather than judged"
        return $state
    }

    $state.Port = [int]$port
    $state.Note = "PortNumber is $port"
    return $state
}

function Get-LocalRuleMergeState {
    <#
    .SYNOPSIS
        Which profiles Group Policy stops local connection security rules from applying to.

    .DESCRIPTION
        AllowLocalIPsecPolicyMerge=0 under a Group Policy profile key means only Group Policy's own
        connection security rules are enforced for that profile, and every rule in the local store
        is ignored. Absent, or any other value, means local rules are merged in, which is the
        Windows default.
    #>
    [CmdletBinding()]
    param()

    $state = [PSCustomObject]@{ Suppressed = @(); Unknown = @(); Notes = @() }
    $suppressed = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()

    foreach ($profileName in @($script:ProfileKey.Keys)) {
        $path = Join-Path $script:PolicyFirewallPath $script:ProfileKey[$profileName]
        # No Group Policy profile key at all is the usual case and means local rules are merged.
        $key = Test-OfflineRegistryKeyPath -Path $path
        if (-not $key.Ok) {
            [void]$unknown.Add($profileName)
            [void]$notes.Add("$profileName could not be checked ($($key.Error))")
            continue
        }
        if (-not $key.Exists) { continue }
        $value = Get-OfflinePrivilegedRegistryValue -Path $path -Name 'AllowLocalIPsecPolicyMerge'
        if (-not $value.Ok) {
            [void]$unknown.Add($profileName)
            [void]$notes.Add("$profileName could not be read ($($value.Error))")
            continue
        }
        if (-not $value.Found) { continue }
        if ($value.Type -ne 4 -or $value.ByteLength -ne 4) {
            [void]$unknown.Add($profileName)
            [void]$notes.Add("$profileName is type $($value.Type), $($value.ByteLength) byte(s), not a REG_DWORD")
            continue
        }
        $merge = [System.BitConverter]::ToUInt32($value.Bytes, 0)
        [void]$notes.Add("$profileName=$merge")
        if ($merge -eq 0) { [void]$suppressed.Add($profileName) }
    }

    $state.Suppressed = @($suppressed)
    $state.Unknown = @($unknown)
    $state.Notes = @($notes)
    return $state
}

function Get-ConSecStoreState {
    <#
    .SYNOPSIS
        Reading and judging every rule in one connection security rule store.

    .DESCRIPTION
        Goes through the privileged path rather than the registry provider, so a key that has been
        locked down is still read. A store that could not be opened, and a rule that could not be
        read, are recorded as such - "no rules" is never reported for a key that was simply locked.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'SOFTWARE')][string]$Hive,
        [Parameter(Mandatory = $true)]$RdpPort,
        [Parameter(Mandatory = $false)]$MergeState = $null
    )

    $state = [PSCustomObject]@{
        Path      = $Path
        Label     = $Label
        Hive      = $Hive
        Readable  = $false
        KeyExists = $false
        Error     = ''
        Rules     = @()
    }

    $key = Test-OfflineRegistryKeyPath -Path $Path
    if (-not $key.Ok) {
        $state.Error = $key.Error
        Add-OfflineRepairLog -Level Warning -Message "The $Label connection security rule store could not be opened: $($key.Error)"
        return $state
    }
    if (-not $key.Exists) {
        $state.Readable = $true
        return $state
    }

    $names = Get-OfflinePrivilegedRegistryValueName -Path $Path
    if (-not $names.Ok) {
        $state.Error = $names.Error
        Add-OfflineRepairLog -Level Warning -Message "The $Label connection security rule store could not be opened: $($names.Error)"
        return $state
    }

    $state.Readable = $true
    $state.KeyExists = $names.Exists
    if (-not $names.Exists) { return $state }

    $suppressed = if ($MergeState) { @($MergeState.Suppressed) } else { @() }
    $mergeUnknown = if ($MergeState) { @($MergeState.Unknown) } else { @() }

    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($valueName in @($names.Names | Sort-Object)) {
        # The key's default value is not a rule: every rule is a named value whose name is its id.
        if ([string]::IsNullOrEmpty($valueName)) { continue }

        $entry = [PSCustomObject]@{
            RuleId    = $valueName
            Path      = $Path
            Readable  = $false
            Error     = ''
            Type      = 0
            Raw       = ''
            Impact    = $null
            NewString = $null
        }

        $value = Get-OfflinePrivilegedRegistryValue -Path $Path -Name $valueName
        if (-not $value.Ok -or -not $value.Found) {
            $entry.Error = if ($value.Error) { $value.Error } else { 'the value was listed but could not be found when read' }
            [void]$rules.Add($entry)
            continue
        }

        $entry.Readable = $true
        $entry.Type = $value.Type
        # 1 is REG_SZ, the only type [MS-GPFAS] defines for a rule. Anything else is reported and
        # never parsed, because how the firewall service treats it is not documented.
        if ($value.Type -ne 1) {
            [void]$rules.Add($entry)
            continue
        }

        $entry.Raw = ConvertFrom-RegistryStringByte -Bytes $value.Bytes
        $parsed = ConvertFrom-ConSecRuleString -RuleString $entry.Raw -RuleId $valueName
        # A NUL inside the string means whatever reads it may stop early and see a different rule.
        if ($entry.Raw.IndexOf([char]0) -ge 0) { $parsed.Malformed = $true }

        $entry.Impact = Get-ConSecRuleRdpImpact -Rule $parsed -RdpPort $RdpPort.Port -RdpPortKnown $RdpPort.Known `
            -SuppressedProfiles $suppressed -UnknownMergeProfiles $mergeUnknown
        if ($entry.Impact.Verdict -eq 'Blocking') {
            $entry.NewString = Get-ConSecRuleDisabledString -RuleString $entry.Raw
        }
        [void]$rules.Add($entry)
    }

    $state.Rules = @($rules)
    return $state
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turning the store readings into findings.
    #>
    param([Parameter(Mandatory = $true)][object[]]$Stores)

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($store in $Stores) {
        if (-not $store.Readable) {
            [void]$findings.Add((New-Finding -Cause 'StoreUnreadable' -Item $store.Label -Hive $store.Hive -Repairable $false `
                        -Message "The $($store.Label) connection security rule store could not be read, so a rule blocking RDP cannot be ruled out ($($store.Error)). Check it once the VM is reachable with Get-NetIPsecRule -PolicyStore ActiveStore."))
            continue
        }

        foreach ($rule in @($store.Rules)) {
            $item = "$($store.Label) rule $($rule.RuleId)"

            if (-not $rule.Readable) {
                [void]$findings.Add((New-Finding -Cause 'RuleUnreadable' -Item $item -Hive $store.Hive -Repairable $false `
                            -Message "$($store.Label) store: rule $($rule.RuleId) could not be read ($($rule.Error)), so whether it blocks RDP is unknown. Left unchanged."))
                continue
            }
            if ($rule.Type -ne 1) {
                [void]$findings.Add((New-Finding -Cause 'RuleValueNotString' -Item $item -Hive $store.Hive -Repairable $false `
                            -Message "$($store.Label) store: rule $($rule.RuleId) is registry type $($rule.Type), not REG_SZ, so it cannot be parsed and how the firewall service treats it is undocumented. Left unchanged."))
                continue
            }

            $impact = $rule.Impact
            $description = Get-ConSecRuleDescription -Impact $impact
            $data = [PSCustomObject]@{
                Path        = $rule.Path
                RuleId      = $rule.RuleId
                Raw         = $rule.Raw
                NewString   = $rule.NewString
                Label       = $store.Label
                Description = $description
                IsPolicy    = ($store.Hive -eq 'SOFTWARE')
            }

            switch ($impact.Verdict) {
                'Blocking' {
                    if ($null -eq $rule.NewString) {
                        [void]$findings.Add((New-Finding -Cause 'RuleRequiresIpsec' -Item $item -Hive $store.Hive -Repairable $false -Data $data `
                                    -Message "$($store.Label) store: $description - $($impact.Reason). Its Active token could not be isolated for a byte-exact change, so it was left unchanged; turn it off once reachable with Disable-NetIPsecRule -Name '$($rule.RuleId)'."))
                    }
                    else {
                        [void]$findings.Add((New-Finding -Cause 'RuleRequiresIpsec' -Item $item -Hive $store.Hive -Data $data `
                                    -Message "$($store.Label) store: $description - $($impact.Reason)."))
                    }
                }
                'Conditional' {
                    [void]$findings.Add((New-Finding -Cause 'RuleScopeUnresolved' -Item $item -Hive $store.Hive -Repairable $false -Data $data `
                                -Message "$($store.Label) store: $description - $($impact.Reason). Left unchanged; its scope could not be proven from the offline disk."))
                }
                'Unknown' {
                    [void]$findings.Add((New-Finding -Cause 'RuleActionUnknown' -Item $item -Hive $store.Hive -Repairable $false -Data $data `
                                -Message "$($store.Label) store: $description - $($impact.Reason). Left unchanged."))
                }
                'Ambiguous' {
                    [void]$findings.Add((New-Finding -Cause 'RuleActiveAmbiguous' -Item $item -Hive $store.Hive -Repairable $false -Data $data `
                                -Message "$($store.Label) store: $description - $($impact.Reason). Left unchanged."))
                }
                'Malformed' {
                    [void]$findings.Add((New-Finding -Cause 'RuleMalformed' -Item $item -Hive $store.Hive -Repairable $false -Data $data `
                                -Message "$($store.Label) store: $description - $($impact.Reason). Left unchanged."))
                }
                default { }
            }
        }
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Turning off one rule. Runs with both offline hives already mounted.

    .DESCRIPTION
        The value is read again first and must still hold exactly the string that was judged; a rule
        that changed since detection is not written. After the write the value is read back,
        re-parsed and must judge Inert, or the repair is reported as failed.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    if ($Finding.Cause -ne 'RuleRequiresIpsec') { return $false }
    $rule = $Finding.Data

    $current = Get-OfflinePrivilegedRegistryValue -Path $rule.Path -Name $rule.RuleId
    if (-not $current.Ok -or -not $current.Found -or $current.Type -ne 1) {
        throw "the rule could not be read again before the write ($(if ($current.Error) { $current.Error } else { "found=$($current.Found), type $($current.Type)" }))."
    }
    if ((ConvertFrom-RegistryStringByte -Bytes $current.Bytes) -cne $rule.Raw) {
        throw 'the rule changed since it was judged; it was not written.'
    }

    Add-OfflineRepairLog -Message "$($rule.Label) store, rule $($rule.RuleId): Active=TRUE -> Active=FALSE. Original value: $($rule.Raw)"

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($rule.NewString + [char]0)
    $outcome = Set-OfflinePrivilegedRegistryValue -Path $rule.Path -Name $rule.RuleId -Type 1 -Bytes $bytes -Confirm:$false
    if (-not $outcome.Written) {
        throw "the write failed: $($outcome.Error)"
    }

    $after = Get-OfflinePrivilegedRegistryValue -Path $rule.Path -Name $rule.RuleId
    if (-not $after.Ok -or -not $after.Found -or $after.Type -ne 1) {
        throw 'the rule was written but could not be read back as a REG_SZ. The hive backup holds the original.'
    }
    $afterImpact = Get-ConSecRuleRdpImpact -Rule (ConvertFrom-ConSecRuleString -RuleString (ConvertFrom-RegistryStringByte -Bytes $after.Bytes) -RuleId $rule.RuleId)
    if ($afterImpact.Verdict -ne 'Inert') {
        throw "the rule reads back as $($afterImpact.Verdict) rather than inactive. The hive backup holds the original."
    }

    Add-OfflineRepairLog -Message "$($rule.Label) store, rule $($rule.RuleId): confirmed inactive on read-back."
    return $true
}

function Get-ConSecContext {
    <#
    .SYNOPSIS
        Everything detection needs, read with both hives mounted.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $rdpPort = Get-RdpListenerPort -SystemRoot $SystemRoot
    $merge = Get-LocalRuleMergeState
    $local = Get-ConSecStoreState -Path (Join-Path $SystemRoot $script:LocalStoreSubPath) -Label 'Local' -Hive 'SYSTEM' -RdpPort $rdpPort -MergeState $merge
    $policy = Get-ConSecStoreState -Path $script:PolicyStorePath -Label 'Group Policy' -Hive 'SOFTWARE' -RdpPort $rdpPort

    return [PSCustomObject]@{
        ControlSet = (Split-Path -Path $SystemRoot -Leaf)
        RdpPort    = $rdpPort
        Merge      = $merge
        Stores     = @($local, $policy)
        Findings   = @(Get-AllFinding -Stores @($local, $policy))
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

# The caller contract in common\helpers\README.md: seed the status, then return it AFTER the
# finally, so the marker the caller parses stays at the end of the output. A bare `return` inside
# the try would exit the script and skip that trailing return, hence the labelled do/while:
# `break main` leaves the body, runs the finally, and falls through to it. A bare `break` or
# `continue` written at this level binds to :main, so any loop added inside this block must label
# its own exits.
$status = $STATUS_ERROR

try {
    # Inside the try, per the caller contract: a helper that fails to load is caught, logged and
    # returned as an error rather than escaping as a raw exception.
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
    . .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1
    . .\src\windows\common\helpers\Use-OfflinePrivilegedRegistry.ps1

    :main do {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "Connection security rules are parsed with the grammar in $($script:SpecUrl)" | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
        return (Get-ConSecContext -SystemRoot $systemRoot)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet). RDP listener: $($context.RdpPort.Note)." | Tee-Object -FilePath $logFile -Append
    if (@($context.Merge.Notes).Count -gt 0) {
        Log-Info "Group Policy AllowLocalIPsecPolicyMerge: $(@($context.Merge.Notes) -join '; ')." | Tee-Object -FilePath $logFile -Append
    }

    $ruleCount = 0
    foreach ($store in @($context.Stores)) {
        if (-not $store.Readable) {
            Log-Warning "$($store.Label) store: could not be read. $($store.Error)" | Tee-Object -FilePath $logFile -Append
            continue
        }
        if (-not $store.KeyExists) {
            Log-Info "$($store.Label) store: no ConSecRules key, so it holds no connection security rules." | Tee-Object -FilePath $logFile -Append
            continue
        }
        Log-Info "$($store.Label) store: $(@($store.Rules).Count) rule(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($rule in @($store.Rules)) {
            $ruleCount++
            if ($rule.Impact) {
                Log-Info "  [$($rule.Impact.Verdict)] $(Get-ConSecRuleDescription -Impact $rule.Impact) - $($rule.Impact.Reason)." | Tee-Object -FilePath $logFile -Append
            }
        }
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    # Ahead of the detectOnly gate on purpose, so one affirmative line serves both modes.
    if ($findings.Count -eq 0) {
        Log-Output "No IPsec connection security rule blocks Remote Desktop. $ruleCount rule(s) were read from the local and Group Policy stores and none requires inbound IPsec for TCP port $($context.RdpPort.Port). No registry values were changed." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character
        # log, so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    # Back up every hive that is actually about to be written.
    $hivesToWrite = @($repairable | ForEach-Object { $_.Hives } | Sort-Object -Unique)
    foreach ($hive in $hivesToWrite) {
        $backup = Backup-OfflineHiveFile -Hive $hive -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "$hive hive backed up to $backup. This copy is the rollback; it stays on the disk after 'az vm repair restore' and can be deleted once the VM is confirmed healthy." | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = 0
    $failed = @()
    $repairedRules = @()

    if ($repairable.Count -gt 0) {
        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
            if ((Split-Path -Path $systemRoot -Leaf) -ne $context.ControlSet) {
                throw 'Select\Current changed since detection; refusing to write the previously captured registry paths.'
            }
            $done = [System.Collections.Generic.List[object]]::new()
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($finding in $repairable) {
                try {
                    if (Repair-Finding -Finding $finding) {
                        [void]$done.Add($finding.Data)
                    }
                    else {
                        [void]$errors.Add("$($finding.Item): the repair reported that it changed nothing.")
                        Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
                    }
                }
                catch {
                    [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                    Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))"
                }
            }
            return [PSCustomObject]@{ Repaired = @($done); Errors = @($errors) }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $repairedRules = @($repairOutcome.Repaired)
        $repairedCount = $repairedRules.Count
        $failed = @($repairOutcome.Errors)
    }

    # Verify against freshly read state rather than trusting the writes above. Only when something
    # was repairable: otherwise nothing was written and re-reading proves nothing new.
    $remaining = @()
    if ($repairable.Count -gt 0) {
        $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
            return @((Get-ConSecContext -SystemRoot $systemRoot).Findings)
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Piping $null sends one $null object down the pipeline rather than nothing at all.
    $remaining = @($remaining | Where-Object { $null -ne $_ })

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # What to do with each rule once the VM is reachable. A turned-off rule is still configured.
    foreach ($rule in $repairedRules) {
        Log-Output "  Turned off $($rule.Label) rule $($rule.Description)." | Tee-Object -FilePath $logFile -Append
        if ($rule.IsPolicy) {
            Log-Output "    It was delivered by Group Policy and returns at the next policy refresh unless the GPO that delivers it is changed." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "    Once reachable, remove it with Remove-NetIPsecRule -Name '$($rule.RuleId)', or turn it back on with Enable-NetIPsecRule -Name '$($rule.RuleId)' (BFE and MpsSvc must be running)." | Tee-Object -FilePath $logFile -Append
        }
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported; Remote Desktop may still be blocked until they are resolved." }

    # Ahead of the failure gate on purpose, so both exits carry the rules that need a decision.
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
    # the ones that say WHY, and without this they were discarded and only the exception survived.
    # A dependency may have failed to load before either function existed, hence the guards.
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
