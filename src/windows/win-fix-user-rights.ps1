#########################################################################################################
#
# .SYNOPSIS
#   Repairs user rights that a removed Group Policy left tattooed, so a VM that refuses RDP - or
#   refuses every logon - can be signed into again. Works on the running VM or on its disk.
#
# .DESCRIPTION
#   Runs in one of two modes, chosen by how it is launched rather than by a parameter:
#
#     az vm repair run ... --run-id win-fix-user-rights                   ONLINE  - repairs this VM
#     az vm repair run ... --run-id win-fix-user-rights --run-on-repair   OFFLINE - repairs the disk
#
#   ONLINE FIRST. A user-rights lockout stops people signing in; it does not stop the machine
#   running or the guest agent answering. So the usual case needs no rescue VM at all: Run Command
#   executes as NT AUTHORITY\SYSTEM, and Windows rewrites its own policy through secedit - the
#   supported writer, which also recreates a deleted account entry itself. Escalate to OFFLINE only
#   when the VM cannot boot or the agent does not answer.
#
#   The mode is discovered, not declared, because the extension gives the script no way to know
#   which way it was launched: an attached offline Windows installation means OFFLINE, and its
#   absence means the machine underfoot is the target. Getting that wrong is safe in the direction
#   that matters - a rescue VM has default rights, so an ONLINE run there finds nothing to repair
#   and writes nothing.
#
#   THE FAULT
#
#   User rights are not Group Policy settings in the usual sense. When a GPO assigns "Deny log on
#   through Remote Desktop Services", the Local Security Authority writes that assignment into its
#   own policy database on the machine. Removing the GPO, unlinking it, or moving the VM out of the
#   OU does NOT take the assignment away: nothing goes back to undo it. The setting is left behind -
#   tattooed - and the VM keeps refusing logons for a policy that no longer exists anywhere.
#
#   The usual presentation is an Azure VM that is running, reachable on 3389, with the Remote Desktop
#   service healthy and the firewall open, that still answers every RDP attempt with
#   "The connection was denied because the user account is not authorized for remote login."
#   Nothing in the network path is wrong, so the network path is not where the repair belongs.
#
#   WHAT THIS REPAIR CHANGES, AND WHAT IT REFUSES TO
#
#   Logon rights live in the SECURITY hive as one bitmask per account. Offline, the repair rewrites
#   the bits behind the fault in place, on the disk, while it is attached to the rescue VM. Online,
#   it never touches the hive at all - secedit does the writing.
#
#   The line the script draws is between correcting an entry and inventing policy structure.
#   Overwriting an existing four-byte ActSysAc value - type preserved, result read back and compared
#   byte for byte - cannot change the shape of the database.
#
#   The fault can also delete an account outright: LSA drops an entry from Policy\Accounts when its
#   last right is taken away, so emptying SeRemoteInteractiveLogonRight removes Remote Desktop Users
#   entirely. That entry is recreated, because repairing only the surviving group leaves the group
#   most VMs actually put their RDP users in locked out - measured on Server 2022 20348, where after
#   such a repair an administrator could sign in over RDP and a member of Remote Desktop Users could
#   not.
#
#   What an entry contains was measured, not assumed. LSA was asked to create one through secedit
#   and the result read back: exactly three subkeys - ActSysAc, SecDesc and Sid - and no Privilgs at
#   all, because LSA omits it when the account holds no privileges. That removed the one field whose
#   encoding would have had to be invented, and inventing LSA policy structure is how offline tools
#   produce a database that cannot be parsed. An LSA that cannot read its own policy database stops
#   the machine with 0xC000021A, and that is not recoverable by dropping in a clean SECURITY hive,
#   because the same hive holds the machine account password and the DPAPI backup keys.
#
#   So nothing in a recreated entry is authored here: the security descriptor is copied from an
#   account already present in the same hive, the SID comes from SecurityIdentifier.GetBinaryForm
#   and was compared byte for byte with what LSA wrote for that SID, and the mask is the same value
#   written everywhere else. If the descriptor cannot be read, the entry is not created and the gap
#   is reported with the online command that closes it.
#
#   WHY NOT SECEDIT OFFLINE
#
#   secedit is the supported writer for user rights, and the ONLINE mode uses it for exactly that
#   reason. It cannot run against an offline disk: it
#   talks to a live LSA through the policy API, not to a hive file. Reaching it from here means
#   arming SYSTEM\Setup\CmdLine and letting the VM repair itself on the next boot - which works,
#   and was measured working, but cannot clean up after itself. See WHY THIS IS NOT DONE WITH
#   SECEDIT below for what that leaves behind.
#
#   DETECTION, AND WHY A HEALTHY DISK IS LEFT ALONE
#
#   The library rule is that nothing is changed on a VM whose rights are fine, so the fault is
#   confirmed from the offline disk first. Logon rights are readable without a live LSA:
#
#     SECURITY\Policy\Accounts\<SID>\ActSysAc
#
#   holds a 4-byte SECURITY_ACCESS mask in the subkey's default value - note that ActSysAc is a
#   subkey, not a value on the account key. The SECURITY hive denies read to every account including
#   SYSTEM, so it is read through the backup-restore path in Use-OfflineProtectedResource.ps1.
#
#   The mask bits were measured against 'secedit /export /areas USER_RIGHTS' on a live Server 2022,
#   build 20348, across all 12 accounts that carry rights - the decode below agrees with secedit on
#   every one of them:
#
#     0x001 Interactive         0x040 DenyInteractive        BUILTIN\Users              0x003
#     0x002 Network             0x080 DenyNetwork            Everyone                   0x002
#     0x004 Batch               0x100 DenyBatch              BUILTIN\Backup Operators   0x007
#     0x010 Service             0x200 DenyService            BUILTIN\Administrators     0x407
#     0x020 Proxy               0x800 DenyRemoteInteractive  BUILTIN\Remote Desktop U.  0x400
#     0x400 RemoteInteractive                                NT SERVICE\ALL SERVICES    0x010
#
#   A finding is only raised for a state that actually refuses a logon:
#
#     - DenyRemoteInteractive / DenyInteractive / DenyNetwork on a broad group. This is the tattoo
#       itself. A deny right beats every allow right it meets, so one of these on Administrators,
#       Users, Everyone or Authenticated Users locks the corresponding logon type out.
#     - MissingRemoteInteractive - neither Administrators nor Remote Desktop Users can log on
#       through Remote Desktop Services, so nobody can RDP in.
#     - MissingInteractive - Administrators cannot log on at the console either, which is what turns
#       a lost RDP session into a VM with no way in at all.
#     - MissingServiceLogon - NT SERVICE\ALL SERVICES lost SeServiceLogonRight, which stops services
#       from starting and can present as 0xC000021A rather than as a logon failure.
#
#   A deny right on a service account or a narrow single-user SID is reported as context and is not
#   a finding: denying one account is how deny rights are legitimately used.
#
#   On a healthy disk every check passes, no finding is produced, and this script writes nothing.
#
#   WHAT THE REPAIR WRITES
#
#   The two mask bits behind the finding, straight into the offline LSA policy database:
#
#     SECURITY\Policy\Accounts\<SID>\ActSysAc   (default value, REG_NONE, 4 bytes little-endian)
#
#   The target state matches what the shipped template inf\defltbase.inf would produce for these
#   rights - SeRemoteInteractiveLogonRight held by Administrators and Remote Desktop Users, and the
#   deny rights empty - measured against it on Server 2022 20348. The difference is blast radius:
#   applying the template resets EVERY user right on the machine to the shipped default, discarding
#   any deliberate customisation on a VM that was only refusing a logon. Writing the mask changes
#   the bits named in the finding and carries every other bit across untouched.
#
#   WHY THIS IS NOT DONE WITH SECEDIT
#
#   secedit needs a running LSA, so an offline repair can only schedule it - the previous design
#   armed SYSTEM\Setup\CmdLine and set SetupType=2 so the session manager would run it before the
#   logon UI. That works, and it was measured working. What it cannot do is clean up after itself:
#   Windows rewrites SetupType when the setup pass completes, which is AFTER the payload has exited,
#   so no write from inside the payload survives. Measured on Server 2022 20348 - the payload ran to
#   completion, cleared SetupType twice, and the disk still came back SetupType=2 with an empty
#   CmdLine, re-entering the setup boot path on every boot thereafter.
#
#   Writing the hive directly finishes the repair while the disk is still attached to the rescue VM.
#   Nothing is armed, nothing is left in Windows\Temp, and the VM needs no extra boot.
#
#   A disk still carrying that residue from an earlier version is detected as StaleSetupType and
#   reset to 0.
#
#   Reference: "User Rights Assignment"
#   https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment
#
# .RESOLVES
#   RDP or console logon refused by a tattooed user right after the GPO that set it was removed.
#   The repair completes offline, so the disk does not have to be able to boot for it to apply.
#
# .PARAMETER detectOnly
#   Report what is on the disk and change nothing.
#
# .PARAMETER revert
#   Put the logon-right masks recorded by the last repair back as they were, and clear any Setup
#   hook left behind by an earlier version of this script. An account entry the repair recreated is
#   deliberately left in place - deleting one to reimpose a lockout is the riskier write and not a
#   rollback worth doing automatically - so revert names it and reports itself as partial.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, when it should not be auto-detected. Offline
#   mode only; it is ignored on a running machine, which has no attached installation to point at.
#
# .PARAMETER force
#   Carry on past a clean detect instead of returning early. The plan is built from the same
#   conditions detect reports, so on a healthy disk it comes out empty and nothing is written -
#   force cannot turn this into a blanket reset of the machine's user rights.
#
# .EXAMPLE
#   # Online first - no rescue VM. Detect, then repair.
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --parameters detectOnly=true --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --verbose
#
# .EXAMPLE
#   # Offline - only when the VM cannot boot or its agent does not answer.
#   az vm repair create -g sourceRG -n sourceVM --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --run-on-repair --verbose
#   az vm repair restore -g sourceRG -n sourceVM --yes
#
# .NOTES
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The repair is finished when 'az vm repair run' returns. Nothing is armed on the disk and the VM
#   needs no extra boot, so 'az vm repair restore' and starting the VM is all that remains.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Values are consumed inside script blocks passed to the offline hive helpers, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$force = 'false',
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
$isRevert = ($revert -eq 'true')
$isForced = ($force -eq 'true')

# Residue an earlier version of this script wrote into Windows\Temp. The repair no longer creates
# any of these - they are still named so a run can recognise and clear what it finds.
$script:PayloadRelativePath = 'Temp\win-fix-user-rights.cmd'
$script:ResultRelativePath = 'Temp\win-fix-user-rights.result'
$script:ManifestRelativePath = 'Temp\win-fix-user-rights-revert.json'

# Registry value types. Passed explicitly on every write because the LSA policy database stores its
# values as REG_NONE, and rewriting the same bytes as REG_BINARY changes the shape of the value.
$script:RegNone = 0
$script:RegBinary = 3

# What this run is repairing, in words, for the operator-facing messages. Both modes share the same
# detect and repair code, so the messages are shared too - but "no account on this disk holds ..."
# is wrong and confusing when the thing being repaired is the running machine. Set at mode
# detection; defaulted here so a message can never render an empty noun.
$script:TargetNoun = 'this disk'

# SECURITY_ACCESS_* from ntsecapi.h. Measured against secedit on Server 2022 20348 - see the header.
$script:LogonRightBits = [ordered]@{
    0x0001 = 'SeInteractiveLogonRight'
    0x0002 = 'SeNetworkLogonRight'
    0x0004 = 'SeBatchLogonRight'
    0x0010 = 'SeServiceLogonRight'
    0x0020 = 'SeProxyLogonRight'
    0x0040 = 'SeDenyInteractiveLogonRight'
    0x0080 = 'SeDenyNetworkLogonRight'
    0x0100 = 'SeDenyBatchLogonRight'
    0x0200 = 'SeDenyServiceLogonRight'
    0x0400 = 'SeRemoteInteractiveLogonRight'
    0x0800 = 'SeDenyRemoteInteractiveLogonRight'
}

# Individual bits the repair acts on. Named separately from LogonRightBits because that table is
# keyed by integer and an OrderedDictionary indexed by an integer binds to the positional overload
# rather than the key - see ConvertTo-LogonRightName, where the same trap reported every healthy
# disk as broken.
$script:BitInteractive = [uint32]0x0001
$script:BitService = [uint32]0x0010
$script:BitDenyService = [uint32]0x0200
$script:BitRemoteInteractive = [uint32]0x0400

# Deny bits that lock out administration when they sit on a broad group. Iterated with
# GetEnumerator so the name comes from the entry rather than from an integer lookup.
$script:DenyBitsOnBroadGroups = [ordered]@{
    0x0040 = 'SeDenyInteractiveLogonRight'
    0x0080 = 'SeDenyNetworkLogonRight'
    0x0800 = 'SeDenyRemoteInteractiveLogonRight'
}

# Groups broad enough that denying them locks out administration itself. A deny right on one of
# these is the tattoo; a deny right on a single service account is normal administration.
$script:BroadSids = [ordered]@{
    'S-1-1-0'       = 'Everyone'
    'S-1-5-11'      = 'Authenticated Users'
    'S-1-5-32-544'  = 'BUILTIN\Administrators'
    'S-1-5-32-545'  = 'BUILTIN\Users'
    'S-1-5-32-555'  = 'BUILTIN\Remote Desktop Users'
}

# Each grant bit and the deny bit that overrides it. Deny wins in LSA, so restoring a grant without
# clearing its partner leaves the account exactly as locked out as before.
$script:GrantToDenyBit = [ordered]@{
    0x0001 = 0x0040  # Interactive        -> DenyInteractive
    0x0002 = 0x0080  # Network            -> DenyNetwork
    0x0004 = 0x0100  # Batch              -> DenyBatch
    0x0010 = 0x0200  # Service            -> DenyService
    0x0400 = 0x0800  # RemoteInteractive  -> DenyRemoteInteractive
}

# The rights a human signs in with, and the only ones this repair restores from the template. The
# other grants in defltbase.inf are deliberately left alone: SeNetworkLogonRight ships with Everyone
# on it and hardening baselines remove that on purpose, so "resetting it to default" would undo a
# deliberate decision to fix a fault that has nothing to do with signing in. Those still get
# reported, so an operator can see the deviation and act on it.
$script:SignInGrantBits = [uint32](0x0001 -bor 0x0400)

$script:SidAdministrators = 'S-1-5-32-544'
$script:SidRemoteDesktopUsers = 'S-1-5-32-555'
$script:SidAllServices = 'S-1-5-80-0'

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
    }
}

function Write-OperatorLog {
    <#
    .SYNOPSIS
        Flushes buffered helper narration to the detail log, promoting only Warning and Error.

    .DESCRIPTION
        Run Command returns at most 4096 characters and keeps the tail, and Log-Info reaches stdout
        exactly as Log-Output does, each line carrying a ~31-character level and timestamp prefix.
        Narration that only helps after the fact therefore goes to the log file on disk, so the
        returned log keeps the findings and the conclusion.

        Warnings are not demoted, because some of them change what the operator does next.
    #>
    param([Parameter(Mandatory = $false)][string]$LogPath = $logFile)

    foreach ($entry in @(Get-OfflineRepairLog)) {
        $line = "[$($entry.Level)] $($entry.Message)"
        switch ($entry.Level) {
            'Error' { Log-Error $entry.Message | Tee-Object -FilePath $LogPath -Append }
            'Warning' { Log-Warning $entry.Message | Tee-Object -FilePath $LogPath -Append }
            default { $line | Out-File -FilePath $LogPath -Append }
        }
    }
    Clear-OfflineRepairLog
}

function ConvertTo-LogonRightName {
    <#
    .SYNOPSIS
        Decodes a SECURITY_ACCESS mask into the SeXxx right names it carries.
    #>
    param([Parameter(Mandatory = $true)][uint32]$Mask)

    # Enumerated, not indexed. LogonRightBits is an OrderedDictionary keyed by integers, and an
    # integer in the indexer binds to the positional overload: $LogonRightBits[0x0400] asks for the
    # item at index 1024, which is out of range and comes back empty, while $LogonRightBits[0x0004]
    # quietly returns the fifth entry. Decoding through the indexer reported every healthy disk as
    # having lost its logon rights - measured on a stock 20348 disk, not theorised.
    $names = @()
    foreach ($entry in $script:LogonRightBits.GetEnumerator()) {
        if ($Mask -band $entry.Key) { $names += $entry.Value }
    }
    return , $names
}

function Resolve-SidFriendlyName {
    <#
    .SYNOPSIS
        Best-effort friendly name for a SID, falling back to the SID itself.

    .DESCRIPTION
        Well-known SIDs resolve on the rescue VM because they are the same everywhere. A SID local
        to the broken machine will not resolve here, and that is not an error - it is reported as
        the raw SID, which is still what the operator needs to see.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)

    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function Get-OfflineLogonRight {
    <#
    .SYNOPSIS
        Reads the logon rights of every account in the offline LSA policy database.

    .DESCRIPTION
        SECURITY\Policy\Accounts holds one subkey per account that has been granted a logon right or
        a privilege. The mask lives in the default value of the ActSysAc SUBKEY, not in a value on
        the account key - measured, because assuming otherwise reads nothing and reports a broken
        disk as healthy.

        The whole hive denies read to every account including SYSTEM, so both the enumeration and
        the read go through the backup-restore path.

    .OUTPUTS
        PSCustomObject with Ok, Accounts (array of Sid/Name/Mask/Rights) and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $result = [PSCustomObject]@{ Ok = $false; Accounts = @(); Reason = $null }

    try {
        Mount-OfflineHive -WindowsPath $WindowsPath -Hive 'SECURITY'
    }
    catch {
        $result.Reason = "the SECURITY hive could not be loaded: $($_.Exception.Message)"
        return $result
    }

    try {
        $accountsPath = 'HKLM\BROKENSECURITY\Policy\Accounts'

        $listing = Get-OfflinePrivilegedRegistrySubKeyName -Path $accountsPath
        if (-not $listing.Ok) {
            $result.Reason = "the account list could not be read: $($listing.Error)"
            return $result
        }
        if (-not $listing.Exists) {
            $result.Reason = 'SECURITY\Policy\Accounts is not present on this disk'
            return $result
        }

        $accounts = New-Object System.Collections.ArrayList

        foreach ($sid in @($listing.Names)) {
            $value = Get-OfflinePrivilegedRegistryValue -Path "$accountsPath\$sid\ActSysAc" -Name ''

            # An account with privileges but no logon rights has no ActSysAc subkey at all. That is
            # a normal shape, not a read failure, and it carries no logon right to judge.
            if (-not $value.Ok -or -not $value.Found) { continue }
            if ($value.ByteLength -lt 4) { continue }

            $mask = [System.BitConverter]::ToUInt32($value.Bytes, 0)

            [void]$accounts.Add([PSCustomObject]@{
                    Sid    = $sid
                    Name   = (Resolve-SidFriendlyName -Sid $sid)
                    Mask   = $mask
                    Type   = $value.Type
                    Rights = (ConvertTo-LogonRightName -Mask $mask)
                })
        }

        $result.Accounts = @($accounts)
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Reason = "the logon rights could not be read: $($_.Exception.Message)"
        return $result
    }
    finally {
        # Assigned to $null because Dismount-OfflineHive returns $true, and a finally block still
        # writes to the output stream after the return above has run. Unsuppressed, the caller
        # receives the result object AND a bare True, so $rights becomes a two-element array.
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' } catch { }
    }
}

function Get-AdjustedLogonRightMask {
    <#
    .SYNOPSIS
        Applies a set/clear pair to a logon-right mask without leaving uint32 range.

    .DESCRIPTION
        -bnot on a [uint32] returns a signed Int64 in PowerShell, so 'mask -band (-bnot 0x400)'
        silently widens the whole expression to 64 bits. BitConverter::GetBytes would then emit
        eight bytes, and an eight-byte write into a four-byte ActSysAc value corrupts the policy
        database of a machine that was only missing one right. XOR against the 32-bit all-ones
        constant keeps every intermediate inside uint32.
    #>
    param(
        [Parameter(Mandatory = $true)][uint32]$Mask,
        [Parameter(Mandatory = $false)][uint32]$Set = 0,
        [Parameter(Mandatory = $false)][uint32]$Clear = 0
    )

    $cleared = [uint32]($Mask -band ([uint32]4294967295 -bxor $Clear))
    return [uint32]($cleared -bor $Set)
}

function ConvertFrom-SecurityTemplateRights {
    <#
    .SYNOPSIS
        Decodes the [Privilege Rights] section of a security template into per-SID logon masks.

    .DESCRIPTION
        Used for both halves of this repair, which is deliberate: the shipped defaults and the
        machine's current state are the same file format, so reading them with one parser means the
        comparison cannot drift between a template and an export.

        Only the ten logon rights are decoded, because those are the bits that live in ActSysAc and
        decide whether an account can sign in at all. Privileges are ignored: they are stored
        separately, they are not what locks anyone out, and this repair does not touch them.

        RID-relative entries such as &-501 are skipped. Resolving them needs the machine SID, they
        only ever name Guest in the shipped template, and Guest is not how anyone recovers a VM.

    .OUTPUTS
        PSCustomObject with Ok, Grants (SID -> uint32 mask), RightCount, Skipped and Error.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{
        Ok = $false; Grants = @{}; RightCount = 0; Skipped = @(); Error = ''
    }

    try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop }
    catch {
        $result.Error = "$Path could not be read: $($_.Exception.Message)"
        return $result
    }

    $byName = @{}
    foreach ($entry in $script:LogonRightBits.GetEnumerator()) { $byName[$entry.Value] = [uint32]$entry.Key }

    $inSection = $false
    $grants = @{}
    $skipped = New-Object System.Collections.ArrayList

    foreach ($line in $lines) {
        $trimmed = "$line".Trim()
        if ($trimmed -match '^\[') {
            if ($inSection) { break }
            $inSection = ($trimmed -match '^\[Privilege Rights\]$')
            continue
        }
        if (-not $inSection -or $trimmed -eq '' -or $trimmed.StartsWith(';')) { continue }

        $split = $trimmed.IndexOf('=')
        if ($split -lt 1) { continue }

        $rightName = $trimmed.Substring(0, $split).Trim()
        if (-not $byName.ContainsKey($rightName)) { continue }

        $bit = [uint32]$byName[$rightName]
        $result.RightCount++

        foreach ($token in ($trimmed.Substring($split + 1) -split ',')) {
            $sid = "$token".Trim()
            if ($sid -eq '') { continue }
            if ($sid.StartsWith('*')) { $sid = $sid.Substring(1).Trim() }
            if ($sid -notmatch '^S-1-') { [void]$skipped.Add("$rightName=$sid"); continue }

            if (-not $grants.ContainsKey($sid)) { $grants[$sid] = [uint32]0 }
            $grants[$sid] = [uint32]($grants[$sid] -bor $bit)
        }
    }

    if ($result.RightCount -eq 0) {
        $result.Error = "$Path has no [Privilege Rights] section this script can read"
        return $result
    }

    $result.Grants = $grants
    $result.Skipped = @($skipped)
    $result.Ok = $true
    return $result
}

function Get-ShippedLogonRightDefault {
    <#
    .SYNOPSIS
        The logon rights Windows itself ships as the default, read from the disk being repaired.

    .DESCRIPTION
        A user-rights lockout is rarely one of the two examples this script was built against. It is
        usually a Group Policy that assigned user rights too narrowly and replaced the shipped list,
        because user-rights assignment is replace and not merge - one over-restrictive policy strips
        every principal the setting does not name. So the repair needs to know what the default
        actually is, for any right, rather than carrying an opinion about two SIDs.

        Windows ships that answer on the disk. %windir%\inf\defltbase.inf is the same template
        'secedit /configure /cfg %windir%\inf\defltbase.inf /areas USER_RIGHTS' applies, and its
        [Privilege Rights] section names every right and the SIDs that hold it. Reading it off the
        disk being repaired means the answer is correct for that build and that SKU, rather than for
        the build this script was written on. A domain controller has its own defaults, so
        defltdc.inf is preferred when the disk is one - detected by ntds.dit rather than by mounting
        another hive.

        Only the ten logon rights are decoded, because those are the bits that live in ActSysAc and
        decide whether an account can sign in at all. Privileges are left entirely alone: they are
        stored in a separate variable-length Privilgs value, they are not what locks anyone out, and
        rewriting them would mean authoring a structure LSA normally owns.

        RID-relative entries such as &-501 are skipped. Resolving them needs the machine SID, they
        only ever name Guest in the shipped template, and Guest is not how anyone recovers a VM.

    .OUTPUTS
        PSCustomObject with Ok, TemplatePath, Grants (SID -> uint32 mask), RightCount and Error.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $result = [PSCustomObject]@{
        Ok           = $false
        TemplatePath = $null
        Grants       = @{}
        RightCount   = 0
        Skipped      = @()
        Error        = ''
    }

    $candidates = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath (Join-Path $WindowsPath 'NTDS\ntds.dit')) {
        [void]$candidates.Add('defltdc.inf')
    }
    [void]$candidates.Add('defltbase.inf')
    [void]$candidates.Add('defltsv.inf')

    $template = $null
    foreach ($candidate in $candidates) {
        $path = Join-Path $WindowsPath "inf\$candidate"
        if (Test-Path -LiteralPath $path) { $template = $path; break }
    }

    if (-not $template) {
        $result.Error = "no security template was found under $WindowsPath\inf, so the shipped defaults could not be read from this disk"
        return $result
    }
    $result.TemplatePath = $template

    $parsed = ConvertFrom-SecurityTemplateRights -Path $template
    if (-not $parsed.Ok) {
        $result.Error = $parsed.Error
        return $result
    }

    $result.Grants = $parsed.Grants
    $result.RightCount = $parsed.RightCount
    $result.Skipped = $parsed.Skipped
    $result.Ok = $true
    return $result
}

function Get-LiveLogonRight {
    <#
    .SYNOPSIS
        Reads the running machine's logon rights, in the same shape as the offline reader.

    .DESCRIPTION
        The online half of this repair. A user-rights lockout does not stop the machine running or
        the guest agent answering - it stops people signing in - so the VM is usually still up and
        reachable through Run Command, which executes as SYSTEM and needs no logon right at all.
        That makes the whole rescue-VM cycle unnecessary for the common case.

        secedit exports the same [Privilege Rights] format the shipped template uses, so the same
        parser reads both and the comparison cannot drift between the two halves. The result is
        shaped exactly like Get-OfflineLogonRight's, so detection runs unchanged in either mode.

    .OUTPUTS
        PSCustomObject with Ok, Accounts (Sid/Name/Mask/Rights/Type), ExportPath and Reason.
    #>
    param()

    $result = [PSCustomObject]@{ Ok = $false; Accounts = @(); ExportPath = $null; Reason = $null }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $export = Join-Path $env:TEMP "win-fix-user-rights-export-$stamp.inf"

    try {
        $null = & secedit.exe /export /areas USER_RIGHTS /cfg $export /quiet 2>&1
    }
    catch {
        $result.Reason = "secedit could not export the current user rights: $($_.Exception.Message)"
        return $result
    }

    if (-not (Test-Path -LiteralPath $export)) {
        $result.Reason = "secedit did not produce an export at $export, so the current user rights could not be read"
        return $result
    }
    $result.ExportPath = $export

    $parsed = ConvertFrom-SecurityTemplateRights -Path $export
    if (-not $parsed.Ok) {
        $result.Reason = $parsed.Error
        return $result
    }

    $accounts = New-Object System.Collections.ArrayList
    foreach ($sid in $parsed.Grants.Keys) {
        $mask = [uint32]$parsed.Grants[$sid]
        [void]$accounts.Add([PSCustomObject]@{
                Sid    = $sid
                Name   = (Resolve-SidFriendlyName -Sid $sid)
                Mask   = $mask
                Type   = $script:RegNone
                Rights = (ConvertTo-LogonRightName -Mask $mask)
            })
    }

    $result.Accounts = @($accounts)
    $result.Ok = $true
    return $result
}

function Repair-LiveLogonRight {
    <#
    .SYNOPSIS
        Applies the planned mask changes to the running machine through secedit.

    .DESCRIPTION
        Windows writes its own policy here. secedit is the supported writer, so LSA authors every
        structure the change needs - including recreating an account entry that an over-restrictive
        policy deleted outright, which is the one thing the offline path has to assemble by hand.

        Only the rights that actually change are named in the template. That matters, because
        user-rights assignment is replace and not merge: any right named here has its holder list
        replaced wholesale, and every right left out is untouched. So each line is written as the
        full intended holder list - the accounts that already hold it, plus the ones being restored
        - which keeps a deliberate grant to a custom group in place instead of quietly dropping it.

    .OUTPUTS
        PSCustomObject with Ok, Applied (right names), TemplatePath and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Absent
    )

    $result = [PSCustomObject]@{ Ok = $false; Applied = @(); TemplatePath = $null; Reason = $null }

    # Where every account ends up: current mask, overridden by the plan, plus the accounts that have
    # no entry at all and are being put back.
    $desired = @{}
    foreach ($account in $Accounts) { $desired[$account.Sid] = [uint32]$account.Mask }

    $changedBits = [uint32]0
    foreach ($item in $Plan) {
        $desired[$item.Sid] = [uint32]$item.NewMask
        $changedBits = [uint32]($changedBits -bor ([uint32]$item.OldMask -bxor [uint32]$item.NewMask))
    }
    foreach ($item in $Absent) {
        $existing = [uint32]0
        if ($desired.ContainsKey($item.Sid)) { $existing = [uint32]$desired[$item.Sid] }
        $desired[$item.Sid] = [uint32]($existing -bor [uint32]$item.Mask)
        $changedBits = [uint32]($changedBits -bor [uint32]$item.Mask)
    }

    if ($changedBits -eq 0) {
        $result.Ok = $true
        $result.Reason = 'nothing to apply'
        return $result
    }

    $body = New-Object System.Collections.ArrayList
    $applied = New-Object System.Collections.ArrayList

    foreach ($entry in $script:LogonRightBits.GetEnumerator()) {
        $bit = [uint32]$entry.Key
        if (($changedBits -band $bit) -eq 0) { continue }

        $holders = @($desired.Keys | Where-Object { ([uint32]$desired[$_] -band $bit) -ne 0 } | Sort-Object)
        $rendered = ($holders | ForEach-Object { "*$_" }) -join ','

        [void]$body.Add("$($entry.Value) = $rendered")
        [void]$applied.Add($entry.Value)
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $template = Join-Path $env:TEMP "win-fix-user-rights-apply-$stamp.inf"
    $database = Join-Path $env:TEMP "win-fix-user-rights-apply-$stamp.sdb"

    $content = @(
        '[Unicode]'
        'Unicode=yes'
        '[Version]'
        'signature="$CHICAGO$"'
        'Revision=1'
        '[Privilege Rights]'
    ) + @($body)

    try {
        # secedit requires UTF-16 when the template declares Unicode=yes.
        Set-Content -LiteralPath $template -Value $content -Encoding Unicode -ErrorAction Stop
    }
    catch {
        $result.Reason = "the repair template could not be written to $template : $($_.Exception.Message)"
        return $result
    }
    $result.TemplatePath = $template

    $output = & secedit.exe /configure /db $database /cfg $template /areas USER_RIGHTS /quiet 2>&1
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        $result.Reason = "secedit /configure returned $code : $(($output | Out-String).Trim())"
        return $result
    }

    $result.Applied = @($applied)
    $result.Ok = $true
    return $result
}

function Get-AbsentGrantTarget {
    <#
    .SYNOPSIS
        Accounts the shipped default grants a logon right to that have no entry on this disk.

    .DESCRIPTION
        LSA removes an account's entry from Policy\Accounts once its last right is taken away, so
        an over-restrictive policy can leave a group with no entry at all rather than an empty one -
        measured on Server 2022 20348, where emptying SeRemoteInteractiveLogonRight through secedit
        deleted S-1-5-32-555 outright, because that right was the only one it held. Any group that
        holds a single right by default is one policy away from disappearing the same way.

        These are the accounts the shipped template grants a sign-in right to that have no entry on
        this disk. New-OfflineLogonRightAccount puts them back; this exists so the repair can tell
        the difference between an account it corrected and one it had to recreate, and so the gap is
        still reported when recreating it is not possible.

    .OUTPUTS
        Array of PSCustomObject with Sid, Name, Right and Mask.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][hashtable]$DefaultGrants
    )

    $present = @{}
    foreach ($a in $Accounts) { $present[$a.Sid] = $true }

    $absent = New-Object System.Collections.ArrayList
    foreach ($sid in $DefaultGrants.Keys) {
        if ($present.ContainsKey($sid)) { continue }

        $wanted = [uint32]([uint32]$DefaultGrants[$sid] -band $script:SignInGrantBits)
        if ($wanted -eq 0) { continue }

        [void]$absent.Add([PSCustomObject]@{
                Sid   = $sid
                Name  = (Resolve-SidFriendlyName -Sid $sid)
                Right = ((ConvertTo-LogonRightName -Mask $wanted) -join ', ')
                Mask  = $wanted
            })
    }
    return @($absent)
}

function Get-LogonRightRepairPlan {
    <#
    .SYNOPSIS
        Turns the decoded accounts into the exact per-account mask changes the repair will make.

    .DESCRIPTION
        The plan is derived from the same conditions Get-UserRightsFinding reports, so the repair
        can never act on something detect did not report. Only the bits named here are touched:
        every other bit of the account's mask is carried across untouched, which is the difference
        between this and applying defltbase.inf, where every user right on the machine returns to
        the shipped default and any deliberate customisation is lost.

        Only the bits named here are touched: every other bit of the account's mask is carried
        across untouched, which is the difference between this and applying defltbase.inf wholesale
        with secedit, where every user right on the machine returns to the shipped default and any
        deliberate customisation is lost. The template is read for what the default *is*, not
        applied as a whole.

        An account that is absent from Policy\Accounts is not planned here, because there is no mask
        to adjust. Get-AbsentGrantTarget reports those and the repair recreates them separately.

    .OUTPUTS
        Array of PSCustomObject with Sid, Name, OldMask, NewMask, Type and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][hashtable]$DefaultGrants
    )

    $byName = @{}
    foreach ($a in $Accounts) { $byName[$a.Sid] = $a }

    $set = @{}
    $clear = @{}
    $why = @{}

    function Add-Change {
        param($Sid, [uint32]$SetBits, [uint32]$ClearBits, $Reason)
        if (-not $set.ContainsKey($Sid)) { $set[$Sid] = [uint32]0; $clear[$Sid] = [uint32]0; $why[$Sid] = @() }
        $set[$Sid] = [uint32]($set[$Sid] -bor $SetBits)
        $clear[$Sid] = [uint32]($clear[$Sid] -bor $ClearBits)
        $why[$Sid] += $Reason
    }

    # 1. Deny rights tattooed on a broad group. Deny overrides allow, so these come off first.
    foreach ($sid in $script:BroadSids.Keys) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }
        foreach ($entry in $script:DenyBitsOnBroadGroups.GetEnumerator()) {
            if (($account.Mask -band $entry.Key) -eq 0) { continue }
            Add-Change -Sid $sid -SetBits 0 -ClearBits ([uint32]$entry.Key) `
                -Reason "clear $($entry.Value)"
        }
    }

    # 2. Every account the shipped template grants a sign-in right to, that is missing it here. This
    #    is the general case of the fault: a policy replaced the shipped list and dropped principals
    #    from it. Restoring is additive - a grant this disk has that the template does not is left
    #    alone, because a deliberate grant to a custom group is not a fault to be repaired.
    foreach ($sid in $DefaultGrants.Keys) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }

        $wanted = [uint32]([uint32]$DefaultGrants[$sid] -band $script:SignInGrantBits)
        if ($wanted -eq 0) { continue }

        $mask = [uint32]$account.Mask
        $missing = [uint32]($wanted -band (-bnot $mask))
        if ($missing -ne 0) {
            $reason = (ConvertTo-LogonRightName -Mask $missing | ForEach-Object { "grant $_" }) -join ', '
            Add-Change -Sid $sid -SetBits $missing -ClearBits 0 -Reason $reason
        }

        # Deny overrides allow, so a grant restored while its partner deny is still tattooed changes
        # nothing the account can actually do. The shipped template leaves all five deny rights
        # empty, so a deny sitting on a default grantee is by definition not the default.
        $denies = [uint32]0
        foreach ($pair in $script:GrantToDenyBit.GetEnumerator()) {
            if (([uint32]$pair.Key -band $wanted) -eq 0) { continue }
            if (($mask -band [uint32]$pair.Value) -eq 0) { continue }
            $denies = [uint32]($denies -bor [uint32]$pair.Value)
        }
        if ($denies -ne 0) {
            $reason = (ConvertTo-LogonRightName -Mask $denies | ForEach-Object { "clear $_" }) -join ', '
            Add-Change -Sid $sid -SetBits 0 -ClearBits $denies -Reason $reason
        }
    }
    $svc = $byName[$script:SidAllServices]
    if ($null -ne $svc) {
        if (([uint32]$svc.Mask -band $script:BitService) -eq 0) {
            Add-Change -Sid $script:SidAllServices -SetBits $script:BitService -ClearBits 0 `
                -Reason 'grant SeServiceLogonRight'
        }
        if (([uint32]$svc.Mask -band $script:BitDenyService) -ne 0) {
            Add-Change -Sid $script:SidAllServices -SetBits 0 -ClearBits $script:BitDenyService `
                -Reason 'clear SeDenyServiceLogonRight'
        }
    }

    $plan = New-Object System.Collections.ArrayList
    foreach ($sid in $set.Keys) {
        $account = $byName[$sid]

        # An account with no entry cannot have a mask corrected - there is nothing to correct. It
        # needs its entry recreated instead, which is a different operation with different inputs,
        # so it is deliberately not smuggled into this plan. Writing ActSysAc on its own would
        # produce an account key holding a mask but no Sid and no SecDesc, and LSA reading a
        # malformed policy database is a 0xC000021A that no hive substitution recovers from.
        if ($null -eq $account) { continue }

        $old = [uint32]$account.Mask
        $new = Get-AdjustedLogonRightMask -Mask $old -Set $set[$sid] -Clear $clear[$sid]
        if ($new -eq $old) { continue }
        [void]$plan.Add([PSCustomObject]@{
                Sid = $sid; Name = $account.Name; OldMask = $old; NewMask = $new
                Type = $account.Type; Reason = ($why[$sid] -join ', ')
            })
    }

    # Emitted as plain output, not comma-wrapped. The ",@(...)" idiom defeats unrolling, which is
    # right when a caller assigns the result directly - but every caller here normalises with @(),
    # and the two together stop cancelling out: an empty plan arrives as one element holding an
    # empty array, and a multi-entry plan arrives as one element holding all of them, whose .Sid
    # member-enumerates into a single space-joined string. A one-entry plan is the only shape that
    # survives, which is why this stayed hidden.
    return @($plan)
}

function Set-OfflineLogonRight {
    <#
    .SYNOPSIS
        Writes the planned masks into the offline LSA policy database.

    .DESCRIPTION
        Every write is read back and compared by Set-OfflinePrivilegedRegistryValue before it is
        counted, so a hive that silently refuses the write is reported as a failure rather than as
        a repair. The registry type is carried from the read: the mask is REG_NONE, and rewriting
        it as REG_BINARY would change the shape of the value even with identical bytes.

    .OUTPUTS
        PSCustomObject with Ok, Applied, Failed and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan
    )

    $result = [PSCustomObject]@{ Ok = $false; Applied = @(); Failed = @(); Reason = $null }

    if ($Plan.Count -eq 0) {
        $result.Ok = $true
        return $result
    }

    try {
        Mount-OfflineHive -WindowsPath $WindowsPath -Hive 'SECURITY'
    }
    catch {
        $result.Reason = "the SECURITY hive could not be loaded: $($_.Exception.Message)"
        return $result
    }

    try {
        $applied = New-Object System.Collections.ArrayList
        $failed = New-Object System.Collections.ArrayList

        foreach ($entry in $Plan) {
            $path = "HKLM\BROKENSECURITY\Policy\Accounts\$($entry.Sid)\ActSysAc"
            $bytes = [System.BitConverter]::GetBytes([uint32]$entry.NewMask)

            $write = Set-OfflinePrivilegedRegistryValue -Path $path -Name '' `
                -Type ([int]$entry.Type) -Bytes $bytes -Confirm:$false

            if ($write.Written) { [void]$applied.Add($entry) }
            else {
                [void]$failed.Add([PSCustomObject]@{ Entry = $entry; Error = $write.Error })
            }
        }

        $result.Applied = @($applied)
        $result.Failed = @($failed)
        $result.Ok = ($failed.Count -eq 0)
        if (-not $result.Ok) { $result.Reason = ($failed | ForEach-Object { $_.Error }) -join '; ' }
        return $result
    }
    catch {
        $result.Reason = "the logon rights could not be written: $($_.Exception.Message)"
        return $result
    }
    finally {
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' } catch { }
    }
}

function New-OfflineLogonRightAccount {
    <#
    .SYNOPSIS
        Recreates a Policy\Accounts entry that the fault deleted, holding one logon right.

    .DESCRIPTION
        LSA removes an account from Policy\Accounts when its last right is taken away, so the fault
        this script repairs can delete BUILTIN\Remote Desktop Users outright. Restoring only the
        surviving group would leave the population most VMs actually put RDP users in locked out.

        What an entry contains was not guessed at. It was measured by letting LSA create one through
        secedit on Server 2022 20348 and reading back what it wrote, which is exactly three subkeys:

          ActSysAc  REG_NONE  the logon-right mask, four bytes little-endian
          SecDesc   REG_NONE  the account security descriptor
          Sid       REG_NONE  the binary SID

        There is no Privilgs subkey. LSA omits it entirely when the account holds no privileges,
        which removes the one field whose encoding would otherwise have had to be invented - and
        inventing LSA policy structure is how offline tools produce a database that cannot be parsed.

        None of the three is authored here either. SecDesc is copied from an account already present
        in this same hive rather than carried as a constant, so it matches the disk being repaired;
        it was byte-identical across every account sampled. The SID is produced by
        SecurityIdentifier.GetBinaryForm and was compared byte for byte with the entry LSA wrote for
        the same SID. The mask is the same value written anywhere else in this repair.

    .OUTPUTS
        PSCustomObject with Ok, Created and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][uint32]$Mask,
        [Parameter(Mandatory = $true)][string]$DonorSid
    )

    $result = [PSCustomObject]@{ Ok = $false; Created = $false; Reason = $null }

    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $sidBytes = New-Object byte[] $sidObject.BinaryLength
        $sidObject.GetBinaryForm($sidBytes, 0)
    }
    catch {
        $result.Reason = "$Sid is not a SID this script can encode: $($_.Exception.Message)"
        return $result
    }

    try {
        Mount-OfflineHive -WindowsPath $WindowsPath -Hive 'SECURITY'
    }
    catch {
        $result.Reason = "the SECURITY hive could not be loaded: $($_.Exception.Message)"
        return $result
    }

    try {
        $root = "HKLM\BROKENSECURITY\Policy\Accounts"

        $donor = Get-OfflinePrivilegedRegistryValue -Path "$root\$DonorSid\SecDesc" -Name ''
        if (-not $donor.Ok -or -not $donor.Found -or $null -eq $donor.Bytes -or $donor.Bytes.Count -eq 0) {
            $result.Reason = "no security descriptor could be read from $DonorSid on this disk to copy, and this script will not author one"
            return $result
        }

        $newKey = New-OfflinePrivilegedRegistryKey -Path "$root\$Sid" -Confirm:$false
        if (-not $newKey.Ok) {
            $result.Reason = $newKey.Error
            return $result
        }

        # The account key itself carries an empty default value, which is what LSA leaves there.
        $null = Set-OfflinePrivilegedRegistryValue -Path "$root\$Sid" -Name '' `
            -Type $script:RegBinary -Bytes ([byte[]]@()) -Confirm:$false

        $values = @(
            @{ Key = 'ActSysAc'; Bytes = [System.BitConverter]::GetBytes([uint32]$Mask) }
            @{ Key = 'SecDesc'; Bytes = [byte[]]$donor.Bytes }
            @{ Key = 'Sid'; Bytes = $sidBytes }
        )

        foreach ($value in $values) {
            $path = "$root\$Sid\$($value.Key)"
            $made = New-OfflinePrivilegedRegistryKey -Path $path -Confirm:$false
            if (-not $made.Ok) {
                $result.Reason = $made.Error
                return $result
            }
            $write = Set-OfflinePrivilegedRegistryValue -Path $path -Name '' `
                -Type $script:RegNone -Bytes $value.Bytes -Confirm:$false
            if (-not $write.Written) {
                $result.Reason = "$($value.Key) could not be written: $($write.Error)"
                return $result
            }
        }

        # Read the mask back through the same decoder used everywhere else, so the entry is proven
        # to be readable as an account rather than merely written.
        $check = Get-OfflinePrivilegedRegistryValue -Path "$root\$Sid\ActSysAc" -Name ''
        if (-not $check.Ok -or -not $check.Found -or $check.Bytes.Count -ne 4) {
            $result.Reason = 'the entry was created but its mask does not read back as four bytes'
            return $result
        }
        if ([System.BitConverter]::ToUInt32([byte[]]$check.Bytes, 0) -ne $Mask) {
            $result.Reason = 'the entry was created but its mask does not read back as the value written'
            return $result
        }

        $result.Created = $newKey.Created
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Reason = "the account entry could not be created: $($_.Exception.Message)"
        return $result
    }
    finally {
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' } catch { }
    }
}

function Get-OfflineSetupState {
    <#
    .SYNOPSIS
        Reads SYSTEM\Setup\SetupType and CmdLine from the offline disk.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $state = [PSCustomObject]@{ Available = $false; SetupType = 0; CmdLine = ''; Reason = $null }

    try {
        $props = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            if (-not (Test-Path $key)) { return $null }
            return Get-ItemProperty -Path $key -ErrorAction Stop
        }
    }
    catch {
        $state.Reason = "the SYSTEM hive could not be read: $($_.Exception.Message)"
        return $state
    }

    if ($null -eq $props) {
        $state.Reason = 'the SYSTEM\Setup key is not present on this disk'
        return $state
    }

    $state.Available = $true
    if ($null -ne $props.SetupType) { $state.SetupType = [int]$props.SetupType }
    if ($null -ne $props.CmdLine) { $state.CmdLine = "$($props.CmdLine)".Trim() }

    return $state
}


function Restore-OfflineSetupHook {
    <#
    .SYNOPSIS
        Puts SYSTEM\Setup back the way it was found.

    .DESCRIPTION
        Restores the recorded values rather than assuming the healthy state, so a disk that
        legitimately carried a setup command keeps it. An empty recorded CmdLine means the value was
        absent or blank, and it is removed rather than written as an empty string.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][int]$SetupType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CmdLine
    )

    $result = [PSCustomObject]@{ Restored = $false; Reason = $null }

    $targetSetupType = $SetupType
    $targetCmdLine = $CmdLine

    try {
        $readBack = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            Set-ItemProperty -Path $key -Name 'SetupType' -Value $targetSetupType -Type DWord -Force -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($targetCmdLine)) {
                Remove-ItemProperty -Path $key -Name 'CmdLine' -Force -ErrorAction SilentlyContinue
            }
            else {
                Set-ItemProperty -Path $key -Name 'CmdLine' -Value $targetCmdLine -Type String -Force -ErrorAction Stop
            }
            $props = Get-ItemProperty -Path $key -ErrorAction Stop
            return [PSCustomObject]@{ CmdLine = "$($props.CmdLine)"; SetupType = [int]$props.SetupType }
        }
    }
    catch {
        $result.Reason = "the Setup hook could not be restored: $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $readBack -or $readBack.SetupType -ne $SetupType) {
        $result.Reason = "SetupType did not read back as $SetupType after being restored"
        return $result
    }

    $result.Restored = $true
    return $result
}


function Get-AttachedWindowsInstallation {
    <#
        .SYNOPSIS
            Returns the drive roots of any Windows installation attached to this machine other than
            the one it booted from.

        .DESCRIPTION
            Used only to tell "there is genuinely no offline disk here" apart from "the disk is
            there and something went wrong looking at it". Those two must not be confused: the
            first is the normal online case, while the second, if it were treated as online, would
            repair the rescue VM's own rights and report success while the patient disk was never
            touched.

            Deliberately independent of Get-OfflineWindowsDisk so it cannot fail the same way for
            the same reason. It looks for the SECURITY hive rather than just a Windows folder,
            because the hive is what this repair actually needs.
    #>
    [CmdletBinding()]
    param()

    $systemRoot = "$($env:SystemDrive)".TrimEnd('\')
    $found = @()

    foreach ($vol in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter })) {
        $root = "$($vol.DriveLetter):"
        if ($root -eq $systemRoot) { continue }
        if (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\config\SECURITY')) { $found += $root }
    }

    return $found
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, so -revert has something to undo rather than a guess.

    .DESCRIPTION
        The mask each account held before the repair is what gets recorded. Reverting to a
        remembered value is the only honest undo: recomputing a 'healthy' mask would put the disk
        into a state it was never in, and on a machine whose rights were deliberately customised
        that is a second fault rather than a rollback.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][array]$Recreated = @()
    )

    try {
        $manifest = [PSCustomObject]@{
            Script   = 'win-fix-user-rights'
            Written  = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            # Recorded so revert can say what it is deliberately NOT undoing. An entry the fault
            # deleted is put back by this repair, and revert leaves it: deleting an LSA account
            # entry to reimpose a lockout is not a rollback anyone wants, and it is the riskier
            # write of the two. Naming it is the difference between a revert that is partial and
            # one that is partial without saying so.
            Recreated = @($Recreated | ForEach-Object {
                    [PSCustomObject]@{ Sid = [string]$_.Sid; Name = [string]$_.Name; Right = [string]$_.Right }
                })
            Accounts = @($Plan | ForEach-Object {
                    [PSCustomObject]@{
                        Sid          = $_.Sid
                        Name         = $_.Name
                        PreviousMask = [uint32]$_.OldMask
                        AppliedMask  = [uint32]$_.NewMask
                        Type         = [int]$_.Type
                    }
                })
        }
        $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath $ManifestPath -Encoding ascii -Force
        return $true
    }
    catch {
        return $false
    }
}

function Read-RevertManifest {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    }
    catch { return $null }
}

function Get-UserRightsFinding {
    <#
    .SYNOPSIS
        Turns the decoded logon rights into the set of states that actually refuse a logon.

    .DESCRIPTION
        Only a state that stops somebody signing in is a finding. AppLocker taught this library the
        lesson directly: a setting being present is not a fault, and reporting it as one produces a
        script that rewrites healthy machines.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][hashtable]$DefaultGrants
    )

    $findings = New-Object System.Collections.ArrayList
    $byName = @{}
    foreach ($a in $Accounts) { $byName[$a.Sid] = $a }

    # 0. The general fault: an account the shipped template grants a sign-in right to that no longer
    #    holds it here. User-rights assignment is replace and not merge, so one over-restrictive
    #    policy strips every principal it does not name - and LSA deletes the account from
    #    Policy\Accounts altogether when that right was the only one it held.
    foreach ($sid in $DefaultGrants.Keys) {
        $wanted = [uint32]([uint32]$DefaultGrants[$sid] -band $script:SignInGrantBits)
        if ($wanted -eq 0) { continue }

        $friendly = Resolve-SidFriendlyName -Sid $sid
        $wantedNames = (ConvertTo-LogonRightName -Mask $wanted) -join ', '
        $account = $byName[$sid]

        if ($null -eq $account) {
            [void]$findings.Add((New-Finding -Cause 'MissingAccountEntry' -Item "$friendly / $wantedNames" `
                        -Message "$friendly has no entry in $($script:TargetNoun)'s LSA policy database, so it holds no logon right at all. Windows grants it $wantedNames by default on this build, and LSA removes an account outright once its last right is taken away - which is what an over-restrictive user-rights policy does."))
            continue
        }

        $missing = [uint32]($wanted -band (-bnot [uint32]$account.Mask))
        if ($missing -ne 0) {
            $missingNames = (ConvertTo-LogonRightName -Mask $missing) -join ', '
            [void]$findings.Add((New-Finding -Cause 'MissingDefaultLogonRight' -Item "$friendly / $missingNames" `
                        -Message "$friendly does not hold $missingNames, which Windows grants it by default on this build. Its mask is 0x$('{0:X4}' -f [uint32]$account.Mask)."))
        }
    }

    # 1. A deny right tattooed on a broad group. This is the fault the scenario is named for.
    $denyMap = [ordered]@{
        'SeDenyRemoteInteractiveLogonRight' = 'log on through Remote Desktop Services'
        'SeDenyInteractiveLogonRight'       = 'log on locally'
        'SeDenyNetworkLogonRight'           = 'access this computer from the network'
    }

    foreach ($sid in $script:BroadSids.Keys) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }

        foreach ($right in $denyMap.Keys) {
            if ($account.Rights -notcontains $right) { continue }
            [void]$findings.Add((New-Finding -Cause 'TattooedDenyRight' -Item "$($script:BroadSids[$sid]) / $right" `
                        -Message "$($script:BroadSids[$sid]) is denied '$($denyMap[$right])'. A deny right overrides every allow right, so this refuses that logon type for the whole group even though no Group Policy still sets it."))
        }
    }

    # 2. Nobody at all can reach the machine. This is deliberately not a per-account check - a
    #    custom group holding RDP instead of the shipped pair is somebody's decision, not a fault,
    #    and finding 0 above already reports each default grantee that is missing its right. What
    #    matters here is the state where the right is held by nobody whatsoever, because that is a
    #    lockout no matter how the policy got there.
    $holders = @{}
    foreach ($account in $Accounts) {
        foreach ($right in @($account.Rights)) {
            if (-not $holders.ContainsKey($right)) { $holders[$right] = New-Object System.Collections.ArrayList }
            [void]$holders[$right].Add($account.Name)
        }
    }

    if (-not $holders.ContainsKey('SeRemoteInteractiveLogonRight')) {
        [void]$findings.Add((New-Finding -Cause 'MissingRemoteInteractiveLogon' -Item 'SeRemoteInteractiveLogonRight' `
                    -Message "No account on $($script:TargetNoun) holds 'Allow log on through Remote Desktop Services', so nobody can sign in over RDP however healthy the listener, the certificate and the firewall are."))
    }

    # 3. Console logon is gone too, which is what removes the last way in.
    if (-not $holders.ContainsKey('SeInteractiveLogonRight')) {
        [void]$findings.Add((New-Finding -Cause 'MissingInteractiveLogon' -Item 'SeInteractiveLogonRight' `
                    -Message "No account on $($script:TargetNoun) holds 'Allow log on locally', so nobody can sign in at the console either - which is what turns a refused RDP session into a VM with no way in at all."))
    }

    # 4. Services cannot start. This presents as 0xC000021A far more often than as a logon failure.
    $svc = $byName[$script:SidAllServices]
    if ($null -ne $svc) {
        if ($svc.Rights -notcontains 'SeServiceLogonRight') {
            [void]$findings.Add((New-Finding -Cause 'MissingServiceLogon' -Item 'SeServiceLogonRight' `
                        -Message "NT SERVICE\ALL SERVICES does not hold 'Log on as a service', which stops service accounts starting and can present as a 0xC000021A stop rather than a logon failure."))
        }
        if ($svc.Rights -contains 'SeDenyServiceLogonRight') {
            [void]$findings.Add((New-Finding -Cause 'TattooedDenyRight' -Item 'NT SERVICE\ALL SERVICES / SeDenyServiceLogonRight' `
                        -Message "NT SERVICE\ALL SERVICES is denied 'Log on as a service', which stops service accounts starting."))
        }
    }

    # Not comma-wrapped. The caller collects this with @(), and a comma wrap plus that @() nest the
    # array one level deeper: three findings arrive as a single item whose .Cause member-enumerates
    # to all three names and whose .Item resolves to the IList indexer rather than a value.
    return @($findings)
}

#########################################################################################################
# Main
#########################################################################################################

try {
    Log-Output "START: Running script $scriptName" | Tee-Object -FilePath $logFile -Append
    $scriptStartTime | Out-File -FilePath $logFile -Append

    Clear-OfflineRepairLog

    # Which side of the fault this run is on. Nothing chooses here: the caller already did, by
    # deciding where to run the script. 'az vm repair run --run-on-repair' puts it on a rescue VM
    # with the patient disk attached; without that flag the same script id runs on the live VM
    # through Run Command, as SYSTEM, which needs no logon right and is why it still works when
    # nobody can sign in. The offline disk is the discriminator, so the script simply reports which
    # situation it is in rather than being told.
    #
    # Getting this wrong is safe in the direction that matters: run online on a rescue VM by
    # mistake and that VM's rights are already the default, so detect returns nothing and nothing
    # is written.
    # Get-OfflineWindowsDisk throws when it finds no attached Windows installation. On a rescue VM
    # that is a genuine failure, but online it is simply the correct answer, so the absence has to
    # be read rather than allowed to end the run. It is confirmed independently before it is
    # believed: a helper that failed for some other reason while a patient disk really is attached
    # must stay loud, or this run would quietly repair the rescue VM's own rights and call it a fix.
    $offline = $null
    $offlineProbeError = $null
    try { $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive }
    catch { $offlineProbeError = $_ }
    Write-OperatorLog

    if ($offlineProbeError -and @(Get-AttachedWindowsInstallation).Count -gt 0) { throw $offlineProbeError }

    $script:OnlineMode = ($offlineProbeError -or -not $offline -or -not $offline.WindowsPath)

    if ($script:OnlineMode) {
        $windowsPath = $env:windir
        $script:TargetNoun = 'this machine'
        Log-Output "MODE: online. No offline Windows installation is attached, so this is the machine being repaired and Windows writes its own policy through secedit." | Tee-Object -FilePath $logFile -Append
        Log-Output "      To repair a VM that cannot boot or whose agent does not answer, attach its disk with 'az vm repair create' and re-run with --run-on-repair." | Tee-Object -FilePath $logFile -Append
    }
    else {
        $windowsPath = $offline.WindowsPath
        $script:TargetNoun = 'this disk'
        Log-Output "MODE: offline. Repairing the attached installation at $windowsPath." | Tee-Object -FilePath $logFile -Append
    }

    # Files an earlier version of this script left on the disk. Nothing is written to any of them
    # now - they are resolved so the run can clear residue it finds.
    $payloadPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:PayloadRelativePath
    $resultPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ResultRelativePath
    $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output 'REVERT: putting the recorded logon-right masks back.' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -ManifestPath $manifestPath
        if ($null -eq $manifest) {
            Log-Warning 'No revert manifest was found, so there is nothing recorded to undo.' | Tee-Object -FilePath $logFile -Append
        }

        $restoredCount = 0

        if ($null -ne $manifest -and $null -ne $manifest.Accounts) {
            # NewMask carries PreviousMask on purpose: reverting is the same write in the other
            # direction, so it goes through the same verified path rather than a second one.
            $undo = @(@($manifest.Accounts) | ForEach-Object {
                    [PSCustomObject]@{
                        Sid = "$($_.Sid)"; Name = "$($_.Name)"
                        OldMask = [uint32]$_.AppliedMask; NewMask = [uint32]$_.PreviousMask
                        Type = [int]$_.Type; Reason = 'revert'
                    }
                })

            if ($script:OnlineMode) {
                # Read live first. secedit rewrites each named right in full, so the current holder
                # list is what stops the undo from stripping every other account off the rights it
                # touches. Detect has not run at this point, so nothing else has read it yet.
                $liveNow = Get-LiveLogonRight
                if (-not $liveNow.Ok) {
                    Log-Error "The current logon rights could not be read, so the undo was not applied: $($liveNow.Reason)." | Tee-Object -FilePath $logFile -Append
                    return $STATUS_ERROR
                }

                $backResult = Repair-LiveLogonRight -Accounts @($liveNow.Accounts) -Plan @($undo) -Absent @()
                if ($backResult.Ok) {
                    $back = [PSCustomObject]@{ Applied = @($undo); Failed = @() }
                }
                else {
                    $back = [PSCustomObject]@{ Applied = @(); Failed = @(@{ Entry = @{ Name = 'secedit' }; Error = $backResult.Reason }) }
                }
            }
            else {
                $back = Set-OfflineLogonRight -WindowsPath $windowsPath -Plan $undo
            }

            foreach ($entry in @($back.Applied)) {
                Log-Output ("Reverted {0} to 0x{1:X4}." -f $entry.Name, $entry.NewMask) | Tee-Object -FilePath $logFile -Append
                $restoredCount++
            }
            foreach ($failure in @($back.Failed)) {
                Log-Warning "$($failure.Entry.Name) could not be reverted: $($failure.Error)" | Tee-Object -FilePath $logFile -Append
            }
        }

        # Earlier versions of this script armed a Setup hook instead of writing the hive. A disk
        # repaired by one of those is still carrying it, and SetupType is the half the payload
        # could never clear from inside its own boot, so clear it here. Offline only: SYSTEM\Setup
        # on a running machine is the live boot state, not residue for this script to tidy.
        $legacy = if ($script:OnlineMode) { [PSCustomObject]@{ Available = $false } } else { Get-OfflineSetupState -WindowsPath $windowsPath }
        if ($legacy.Available -and ($legacy.SetupType -ne 0 -or $legacy.CmdLine -like '*win-fix-user-rights*')) {
            $cleared = Restore-OfflineSetupHook -WindowsPath $windowsPath -SetupType 0 -CmdLine ''
            if ($cleared.Restored) {
                Log-Output 'Cleared a Setup hook left by an earlier version of this script.' | Tee-Object -FilePath $logFile -Append
                $restoredCount++
            }
        }

        foreach ($stale in @($payloadPath, $resultPath)) {
            if (Test-Path -LiteralPath $stale) {
                Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $stale) {
                    Log-Warning "'$stale' could not be removed." | Tee-Object -FilePath $logFile -Append
                }
                else {
                    Log-Output "Removed '$stale'." | Tee-Object -FilePath $logFile -Append
                    $restoredCount++
                }
            }
        }

        if (Test-Path -LiteralPath $manifestPath) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
        }

        # Filtered, not just wrapped. A manifest written by an earlier version has no Recreated
        # property at all, and @($null) is a one-element array holding $null - which would report a
        # kept entry with no name and turn every revert into a "partial" one.
        $kept = @($manifest.Recreated | Where-Object { $_ -and $_.Name })
        foreach ($entry in $kept) {
            Log-Output ("Kept {0}: the policy entry this repair recreated is left in place." -f $entry.Name) | Tee-Object -FilePath $logFile -Append
        }

        if ($kept.Count -gt 0) {
            Log-Output 'The masks above are back to what they were before this script ran. The account entries listed as kept are not put back the way they were found: undoing those means deleting an LSA account entry to reimpose a lockout, which is the riskier of the two writes and not a rollback worth performing automatically.' | Tee-Object -FilePath $logFile -Append
            Log-Output ("So this is a partial revert: {0} account(s) can still sign in that could not before the repair. To remove one, run 'secedit /export /areas USER_RIGHTS' on the running VM, drop the SID from the right and re-import." -f $kept.Count) | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'The masks above are back to what they were before this script ran, so the logon rights are once again whatever they were on arrival - including the fault, if the disk arrived with one.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "REVERT COMPLETE: restored $restoredCount item(s)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Detect
    #####################################################################################################
    if ($script:OnlineMode) {
        $rights = Get-LiveLogonRight
        $source = 'the running machine (secedit /export)'
    }
    else {
        $rights = Get-OfflineLogonRight -WindowsPath $windowsPath
        $source = 'the offline SECURITY hive'
    }
    Write-OperatorLog

    if (-not $rights.Ok) {
        Log-Error "The current user rights could not be read from $source, so nothing is armed: $($rights.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "Read logon rights for $(@($rights.Accounts).Count) account(s) from $source." | Tee-Object -FilePath $logFile -Append

    # The full table goes to the detail log; the returned log keeps the findings.
    foreach ($account in @($rights.Accounts)) {
        "  $($account.Sid) [$($account.Name)] mask=0x$('{0:X4}' -f $account.Mask) $(@($account.Rights) -join ', ')" |
            Out-File -FilePath $logFile -Append
    }

    # What the defaults actually are is read from the disk being repaired rather than carried as an
    # opinion, so the answer is right for this build and this SKU. A lockout is usually a policy
    # that replaced the shipped list, and it is rarely one of the two examples this was built on.
    $shipped = Get-ShippedLogonRightDefault -WindowsPath $windowsPath
    if ($shipped.Ok) {
        Log-Output "Shipped defaults read from $($shipped.TemplatePath): $($shipped.RightCount) logon right(s) across $($shipped.Grants.Count) account(s)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning "The shipped defaults could not be read from $($script:TargetNoun) ($($shipped.Error)). Falling back to the built-in defaults for the two groups Windows grants RDP to." | Tee-Object -FilePath $logFile -Append
        $shipped.Grants = @{
            $script:SidAdministrators     = [uint32]($script:BitInteractive -bor $script:BitRemoteInteractive)
            $script:SidRemoteDesktopUsers = [uint32]$script:BitRemoteInteractive
            $script:SidAllServices        = [uint32]$script:BitService
        }
    }

    $findings = @(Get-UserRightsFinding -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

    # SYSTEM\Setup is read for reporting only now: the repair writes to the SECURITY hive and never
    # touches it. An unreadable SYSTEM hive is worth saying out loud, but it is not a reason to
    # refuse a logon-right repair that does not depend on it. Skipped online, where SYSTEM\Setup is
    # the live machine's own boot state rather than something this script has any business reading.
    $setupState = if ($script:OnlineMode) { [PSCustomObject]@{ Available = $true; SetupType = 0; CmdLine = '' } } else { Get-OfflineSetupState -WindowsPath $windowsPath }
    if (-not $setupState.Available) {
        Log-Warning "SYSTEM\Setup could not be read on this disk ($($setupState.Reason)), so the boot-time state is unknown. The logon-right repair does not depend on it, so it continues." | Tee-Object -FilePath $logFile -Append
    }

    # A setup command already pointing at something real is a servicing or provisioning step. The
    # repair no longer touches SYSTEM\Setup at all, so this does not block anything - it is
    # reported because an operator looking at a machine that will not sign in needs to know the
    # image is part way through something.
    $hookInUse = ($setupState.Available -and $setupState.SetupType -ne 0 -and
        -not [string]::IsNullOrWhiteSpace($setupState.CmdLine) -and
        $setupState.CmdLine -notlike '*win-fix-user-rights*')

    if ($hookInUse) {
        $findings += New-Finding -Cause 'SetupHookInUse' -Item 'CmdLine' -Repairable $false `
            -Message "SYSTEM\Setup is already in setup mode running '$($setupState.CmdLine)'. That is left alone: this script repairs the LSA policy database directly and never arms a boot-time command."
    }

    # A SetupType left armed with nothing to run is residue from an earlier version of this script,
    # which cleared CmdLine from inside its own payload but could never make SetupType stick -
    # Windows rewrites it when the setup pass completes, after the payload has exited. Measured on
    # Server 2022 20348: the payload's write succeeded and was overwritten, leaving SetupType=2 with
    # an empty CmdLine on every boot thereafter.
    $staleSetupType = ($setupState.Available -and $setupState.SetupType -ne 0 -and
        [string]::IsNullOrWhiteSpace($setupState.CmdLine))

    if ($staleSetupType) {
        $findings += New-Finding -Cause 'StaleSetupType' -Item 'SetupType' `
            -Message "SYSTEM\Setup\SetupType is $($setupState.SetupType) with no CmdLine to run. The machine re-enters the setup boot path on every boot for nothing, and this is left behind by an earlier version of this repair. It is reset to 0."
    }

    #####################################################################################################
    # Report
    #####################################################################################################
    foreach ($finding in $findings) {
        $tag = if ($finding.Repairable) { 'FOUND' } else { 'FOUND (not repairable here)' }
        Log-Output "  [$tag] $($finding.Cause) - $($finding.Item)" | Tee-Object -FilePath $logFile -Append
        Log-Output "           $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
    # so a summary printed first is the first thing a long run loses.
    if ($findings.Count -eq 0) {
        Log-Output 'No user-rights fault was found: every logon right this script checks is in a state that permits sign-in.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "Detect found $($findings.Count) issue(s)." | Tee-Object -FilePath $logFile -Append
    }

    if ($isDetectOnly) {
        Log-Output "DETECT ONLY: nothing was changed on $($script:TargetNoun)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Repair
    #####################################################################################################
    $repairable = @($findings | Where-Object { $_.Repairable })

    if ($repairable.Count -eq 0 -and -not $isForced) {
        Log-Output "Nothing was changed: $($script:TargetNoun) has no user-rights fault to repair." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0 -and $isForced) {
        Log-Warning 'FORCED: no fault was detected. The plan is derived from the same conditions detect reports, so on a disk that is already healthy it comes out empty and nothing is written.' | Tee-Object -FilePath $logFile -Append
    }

    $plan = @(Get-LogonRightRepairPlan -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

    # Absent accounts carry no mask, so they never appear in the plan. Counting them here as well
    # is what stops a disk whose only remaining fault is a deleted entry from being declared healthy
    # and returned untouched - the plan is legitimately empty in exactly that case.
    $absentTargets = @(Get-AbsentGrantTarget -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

    # Stated before the first write, not after. A repair that reports only what it managed to do
    # cannot be checked against what it intended to do, and the SID is carried alongside the name
    # so an entry that resolves to nothing is still identifiable.
    Log-Output ("Plan: {0} mask change(s), {1} account entry/entries to recreate." -f $plan.Count, $absentTargets.Count) | Tee-Object -FilePath $logFile -Append
    foreach ($entry in $plan) {
        Log-Output ("  PLAN [{0}] {1}: 0x{2:X4} -> 0x{3:X4} ({4})" -f $entry.Sid, $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
    }

    if ($plan.Count -eq 0 -and $absentTargets.Count -eq 0 -and -not $staleSetupType) {
        Log-Output "Nothing was changed: the logon-right masks on $($script:TargetNoun) already permit sign-in." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Written before the first hive write, not after. A run that dies part way still needs an undo
    # record for whatever it managed to change.
    [void](Write-RevertManifest -ManifestPath $manifestPath -Plan $plan -Recreated $absentTargets)

    if ($script:OnlineMode) {
        # One secedit call carries both halves: the mask corrections and any account entry the
        # policy deleted outright. Windows recreates the entry itself, so nothing here has to
        # assemble LSA policy structure by hand.
        $absentTargets = @($absentTargets)
        $applyResult = Repair-LiveLogonRight -Accounts @($rights.Accounts) -Plan @($plan) -Absent $absentTargets

        Log-Output '' | Tee-Object -FilePath $logFile -Append

        if (-not $applyResult.Ok) {
            Log-Error "  [FAILED] secedit could not apply the repair: $($applyResult.Reason)" | Tee-Object -FilePath $logFile -Append
            $write = [PSCustomObject]@{
                Ok      = $false
                Reason  = $applyResult.Reason
                Applied = @()
                Failed  = @(@{ Entry = @{ Name = 'secedit' }; Error = $applyResult.Reason })
            }
        }
        else {
            foreach ($entry in @($plan)) {
                Log-Output ("  [FIXED] {0}: 0x{1:X4} -> 0x{2:X4} ({3})" -f $entry.Name, $entry.OldMask, $entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
            }

            # Reported separately because these accounts have no mask to move from: the policy
            # deleted the entry outright, so there is no "0x... -> 0x..." to show. Leaving them out
            # of the output entirely would under-report the repair - the RDP group most VMs rely on
            # is usually exactly this case.
            foreach ($target in $absentTargets) {
                Log-Output ("  [FIXED] {0}: entry recreated by Windows, granted {1}" -f $target.Name, $target.Right) | Tee-Object -FilePath $logFile -Append
            }

            Log-Output ("  Applied through secedit, rewriting only: {0}" -f (@($applyResult.Applied) -join ', ')) | Tee-Object -FilePath $logFile -Append
            $write = [PSCustomObject]@{
                Ok      = $true
                Reason  = ''
                Applied = @(@($plan) + @($absentTargets))
                Failed  = @()
            }
        }
    }
    else {
        $write = Set-OfflineLogonRight -WindowsPath $windowsPath -Plan $plan

        Log-Output '' | Tee-Object -FilePath $logFile -Append
        foreach ($entry in @($write.Applied)) {
            Log-Output ("  [FIXED] {0}: 0x{1:X4} -> 0x{2:X4} ({3})" -f $entry.Name, $entry.OldMask, $entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
        }
        foreach ($failure in @($write.Failed)) {
            $label = if ([string]::IsNullOrWhiteSpace($failure.Entry.Name)) { "SID $($failure.Entry.Sid)" } else { $failure.Entry.Name }
            Log-Error ("  [FAILED] {0}: {1}" -f $label, $failure.Error) | Tee-Object -FilePath $logFile -Append
        }
    }

    # SetupType is cleared last. It is not part of the logon-rights fault, so a failure to write the
    # policy database must not be masked by a successful tidy-up of somebody else's residue.
    if ($staleSetupType -and -not $script:OnlineMode) {
        $cleared = Restore-OfflineSetupHook -WindowsPath $windowsPath -SetupType 0 -CmdLine ''
        if ($cleared.Restored) {
            Log-Output '  [FIXED] SYSTEM\Setup\SetupType reset to 0, so the disk no longer re-enters the setup boot path.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "SetupType could not be reset: $($cleared.Reason)" | Tee-Object -FilePath $logFile -Append
        }
    }

    if (-not $write.Ok) {
        Log-Error "The logon rights could not be fully repaired: $($write.Reason)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # The disk is handed back with no boot-time work outstanding. This is asserted rather than
    # assumed: the previous design armed SYSTEM\Setup and could not clear it again from inside the
    # boot it started, so the one thing worth proving is that nothing here left that state behind.
    $final = if ($script:OnlineMode) { [PSCustomObject]@{ Available = $false } } else { Get-OfflineSetupState -WindowsPath $windowsPath }
    if ($final.Available -and ($final.SetupType -ne 0 -or -not [string]::IsNullOrWhiteSpace($final.CmdLine))) {
        Log-Warning "SYSTEM\Setup still reads SetupType=$($final.SetupType) CmdLine='$($final.CmdLine)'. That is not this repair, but the VM will run it on the next boot." | Tee-Object -FilePath $logFile -Append
    }

    # The shipped default grants RDP to two groups. When the fault deleted one of them outright,
    # repairing only the survivor leaves the group most VMs actually put their RDP users in still
    # locked out - measured: administrators could sign in, Remote Desktop Users could not. So the
    # entry is put back, from values read off this same disk. Gated on the finding, so a healthy
    # disk that simply has no such group is still left alone.
    #
    # Done before the closing count, not after it, so a run that recreates an entry cannot report
    # "REPAIRED 0 account(s)" above the line saying which account it just put back.
    $recreated = 0
    $rdpFaultFound = @($repairable | Where-Object { $_.Cause -eq 'MissingAccountEntry' }).Count -gt 0
    if ($rdpFaultFound -and -not $script:OnlineMode) {
        foreach ($absent in $absentTargets) {
            $made = New-OfflineLogonRightAccount -WindowsPath $windowsPath -Sid $absent.Sid `
                -Mask ([uint32]$absent.Mask) -DonorSid $script:SidAdministrators

            if ($made.Ok) {
                $recreated++
                Log-Output ("  [FIXED] {0}: policy entry recreated holding {1} (0x{2:X4})" -f $absent.Name, $absent.Right, [uint32]$absent.Mask) | Tee-Object -FilePath $logFile -Append
            }
            else {
                Log-Warning "  [NOT RESTORED] $($absent.Name) has no entry in this disk's LSA policy database and one could not be created: $($made.Reason)" | Tee-Object -FilePath $logFile -Append
                Log-Output "                 Access is still restored through BUILTIN\Administrators above. To put the group back once the VM is up, run as administrator:" | Tee-Object -FilePath $logFile -Append
                Log-Output '                 secedit /export /areas USER_RIGHTS /cfg %temp%\ur.inf  then add the SID to SeRemoteInteractiveLogonRight and re-import with secedit /configure /areas USER_RIGHTS' | Tee-Object -FilePath $logFile -Append
            }
        }
    }

    if ($script:OnlineMode) {
        Log-Output "REPAIRED $($write.Applied.Count) account(s) through secedit on the running machine." | Tee-Object -FilePath $logFile -Append
        Log-Output 'Only the rights listed above were rewritten; every other user right on this machine was left as it was.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'The change is effective immediately - no reboot is needed for a logon right to take effect.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        # Two different operations, counted separately: a mask corrected in place is not the same
        # repair as an account entry rebuilt from nothing, and collapsing them hides which happened.
        Log-Output ("REPAIRED {0} mask(s) and recreated {1} account entry/entries in the offline LSA policy database." -f $write.Applied.Count, $recreated) | Tee-Object -FilePath $logFile -Append
        Log-Output 'Only the logon-right bits listed above were changed; no other user right on this disk was touched.' | Tee-Object -FilePath $logFile -Append
    }

    if ($script:OnlineMode) {
        Log-Output 'Sign-in is possible again now: LSA applies a logon right at the next logon attempt, so nothing further is needed.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'If RDP is still refused, the cause is no longer user rights - check the listener, the firewall and the certificate.' | Tee-Object -FilePath $logFile -Append
    }
    elseif ($final.Available) {
        Log-Output "Verified on this disk: SetupType=$($final.SetupType), no boot-time command armed." | Tee-Object -FilePath $logFile -Append
        Log-Output "Run 'az vm repair restore' and start the VM; the rights are already correct, so no extra boot is needed." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output 'SYSTEM\Setup could not be read back, so the boot-time state is unverified. This repair never writes to it.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Run 'az vm repair restore' and start the VM; the rights are already correct, so no extra boot is needed." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
