#########################################################################################################
#
# .SYNOPSIS
#   Repairs user rights that a removed Group Policy left tattooed, so a VM that refuses RDP - or
#   refuses every logon - can be signed into again. Works on the running VM or on its disk.
#
# .DESCRIPTION
#   Runs in one of two modes:
#
#     az vm repair run ... --run-id win-fix-user-rights                                   ONLINE
#     az vm repair run ... --run-id win-fix-user-rights --run-on-repair --parameters mode=offline
#
#   ONLINE FIRST. A user-rights lockout stops people signing in; it does not stop the machine
#   running or the guest agent answering. So the usual case needs no rescue VM at all: Run Command
#   executes as NT AUTHORITY\SYSTEM, and Windows rewrites its own policy through secedit - the
#   supported writer, which also recreates a deleted account entry itself. Escalate to OFFLINE only
#   when the VM cannot boot or the agent does not answer.
#
#   The extension does not tell the script which way it was launched, so 'mode' says it. The
#   default, mode=auto, only goes online when the machine shows no sign of an attached data disk
#   that could hold another Windows installation; it never brings a disk online or assigns a drive
#   letter to find out. When such a disk is present, auto runs the offline discovery and, if that
#   fails, stops and asks for mode=online or mode=offline rather than guessing - a guess in either
#   direction would repair the wrong machine or report a broken disk as healthy.
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
#   Nothing is armed and the VM needs no extra boot. SYSTEM\Setup is read for reporting only and is
#   never written: a SetupType other than 0 is reported as context, because it can be legitimate
#   servicing or provisioning state that this script has no way to tell apart from residue.
#
#   Before the first offline write the SECURITY hive file is copied next to itself
#   (SECURITY.bak-<timestamp>), and the masks it changes are recorded in
#   Windows\Temp\win-fix-user-rights-revert.json for revert=true.
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
#   Put the logon-right masks recorded by the first repair back as they were. Revert reports
#   success, and deletes the record, only when every recorded mask was written back and reads back
#   as recorded; otherwise it returns an error and keeps the record so it can be retried. An account
#   entry the repair recreated is deliberately left in place - deleting one to reimpose a lockout is
#   the riskier write and not a rollback worth doing automatically - so revert names it and reports
#   itself as partial. Revert never touches SYSTEM\Setup.
#
# .PARAMETER mode
#   auto (default), online or offline. online repairs the machine the script runs on and never looks
#   for an attached disk. offline requires an attached Windows installation and fails without one -
#   use it with --run-on-repair. auto picks online only when no attached data disk is visible.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, when it should not be auto-detected. Implies
#   an offline run under mode=auto, and is refused with mode=online.
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
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --run-on-repair --parameters mode=offline --verbose
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
    [Parameter(Mandatory = $false)][ValidateSet('auto', 'online', 'offline', IgnoreCase = $true)][string]$mode = 'auto',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$isForced = ($force -eq 'true')

# The undo record for revert=true, relative to the target's Windows directory.
$script:ManifestRelativePath = 'Temp\win-fix-user-rights-revert.json'

# Registry value types. Passed explicitly on every write because the LSA policy database stores its
# values as REG_NONE, and rewriting the same bytes as REG_BINARY changes the shape of the value.
$script:RegNone = 0

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

# When a sign-in right counts as a lockout, and what is restored to end it. A right is locked out
# only when none of its Holders has it: those are the groups an administrator (or, for RDP, the
# Remote Desktop Users group) signs in through. Any other difference from the shipped template is
# reported but left alone, because a hardening baseline that limits "Allow log on locally" or RDP
# to Administrators is a deliberate decision, not a fault. Broad-group deny rights are cleared by
# the repair regardless, so grants alone decide whether a lockout remains. Keyed by integer:
# iterate with GetEnumerator only.
$script:LockoutRules = [ordered]@{
    0x0001 = [PSCustomObject]@{
        Holders = @('S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0')
        Restore = @('S-1-5-32-544')
    }
    0x0400 = [PSCustomObject]@{
        Holders = @('S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0')
        Restore = @('S-1-5-32-544', 'S-1-5-32-555')
    }
}

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

function Get-LogonRightRestoreTarget {
    <#
    .SYNOPSIS
        The sign-in bits to restore, per SID, to end a real lockout - and nothing else.

    .DESCRIPTION
        For each rule in LockoutRules, the right is locked out only when no Holder group has it.
        Only then are the Restore groups given the right back, and only where the shipped template
        grants it to them. A hardened VM where Administrators can still sign in returns nothing.

    .OUTPUTS
        Hashtable of SID -> uint32 mask of the bits to restore.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][hashtable]$DefaultGrants
    )

    $bySid = @{}
    foreach ($a in $Accounts) { $bySid[$a.Sid] = $a }

    $targets = @{}
    foreach ($rule in $script:LockoutRules.GetEnumerator()) {
        $bit = [uint32]$rule.Key
        $held = $false
        foreach ($sid in $rule.Value.Holders) {
            $account = $bySid[$sid]
            if ($null -ne $account -and ([uint32]$account.Mask -band $bit) -ne 0) { $held = $true; break }
        }
        if ($held) { continue }

        foreach ($sid in $rule.Value.Restore) {
            if (-not $DefaultGrants.ContainsKey($sid)) { continue }
            if (([uint32]$DefaultGrants[$sid] -band $bit) -eq 0) { continue }
            $existing = [uint32]0
            if ($targets.ContainsKey($sid)) { $existing = [uint32]$targets[$sid] }
            $targets[$sid] = [uint32]($existing -bor $bit)
        }
    }
    return $targets
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
            # The subkeys are listed before ActSysAc is read. An account with privileges but no logon
            # rights has no ActSysAc subkey at all, which is a normal shape and carries no logon right
            # to judge - and asking the native reader for a key that is not there is not a pure read.
            $children = Get-OfflinePrivilegedRegistrySubKeyName -Path "$accountsPath\$sid"
            if (-not $children.Ok) {
                $result.Reason = "the entry for $sid could not be listed: $($children.Error)"
                return $result
            }
            if (@($children.Names) -notcontains 'ActSysAc') { continue }

            # Present but unreadable is a failed read, not a missing right. Skipping it would report
            # an account with a deny right as one with no rights at all, and on the account that
            # holds the lockout that turns a broken disk into a clean detect.
            $value = Get-OfflinePrivilegedRegistryValue -Path "$accountsPath\$sid\ActSysAc" -Name ''
            if (-not $value.Ok) {
                $result.Reason = "the logon-right mask of $sid could not be read: $($value.Error)"
                return $result
            }
            if (-not $value.Found) { continue }
            if ($value.ByteLength -lt 4) {
                $result.Reason = "the logon-right mask of $sid is $($value.ByteLength) byte(s) long instead of 4"
                return $result
            }

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
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' }
        catch { Add-OfflineRepairLog -Level Warning -Message "The SECURITY hive could not be unloaded after the read: $($_.Exception.Message)" }
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
        PSCustomObject with Ok, Accounts (Sid/Name/Mask/Rights/Type), Skipped (right=holder entries
        that are not SIDs) and Reason. The export file is deleted before returning.
    #>
    param()

    $result = [PSCustomObject]@{ Ok = $false; Accounts = @(); Skipped = @(); Reason = $null }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $export = Join-Path $env:TEMP "win-fix-user-rights-export-$stamp.inf"

    try {
        # A file already at this path would be parsed as if secedit had just written it.
        if (Test-Path -LiteralPath $export) { Remove-Item -LiteralPath $export -Force -ErrorAction Stop }

        $output = & secedit.exe /export /areas USER_RIGHTS /cfg $export /quiet 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $result.Reason = "secedit /export returned $exitCode`: $((@($output) | Out-String).Trim())"
            return $result
        }

        if (-not (Test-Path -LiteralPath $export)) {
            $result.Reason = "secedit did not produce an export at $export, so the current user rights could not be read"
            return $result
        }

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
        $result.Skipped = @($parsed.Skipped)
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Reason = "secedit could not export the current user rights: $($_.Exception.Message)"
        return $result
    }
    finally {
        if (Test-Path -LiteralPath $export) {
            Remove-Item -LiteralPath $export -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $export) {
                Add-OfflineRepairLog -Level Warning -Message "The temporary export '$export' could not be deleted."
            }
        }
    }
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

        Holders that the export listed by name rather than by SID cannot be carried across, so a
        right that has one is refused rather than rewritten without it. The template, database and
        secedit log files are deleted before returning.

    .OUTPUTS
        PSCustomObject with Ok, Applied (right names), TemplatePath and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Absent,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$Skipped = @()
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

    $unresolved = @($Skipped | Where-Object { $applied -contains ("$_" -split '=', 2)[0] })
    if ($unresolved.Count -gt 0) {
        $result.Reason = "these holders are listed by name rather than SID and would be dropped from the rights being rewritten: $($unresolved -join '; ')"
        return $result
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $template = Join-Path $env:TEMP "win-fix-user-rights-apply-$stamp.inf"
    $database = Join-Path $env:TEMP "win-fix-user-rights-apply-$stamp.sdb"
    $scratch = @($template, $database, [System.IO.Path]::ChangeExtension($database, '.jfm'))

    $content = @(
        '[Unicode]'
        'Unicode=yes'
        '[Version]'
        'signature="$CHICAGO$"'
        'Revision=1'
        '[Privilege Rights]'
    ) + @($body)

    try {
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
    finally {
        foreach ($file in $scratch) {
            if (-not (Test-Path -LiteralPath $file)) { continue }
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $file) {
                Add-OfflineRepairLog -Level Warning -Message "The temporary file '$file' could not be deleted."
            }
        }
    }
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

        These are the accounts the repair has to give a sign-in right back to, to end a real lockout
        (see Get-LogonRightRestoreTarget), that have no entry here. New-OfflineLogonRightAccount puts
        them back; this exists so the repair can tell the difference between an account it corrected
        and one it had to recreate, and so the gap is still reported when recreating it is not
        possible. A default grantee that is absent while nobody is locked out is not returned.

    .OUTPUTS
        Array of PSCustomObject with Sid, Name, Right and Mask.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][hashtable]$DefaultGrants
    )

    $present = @{}
    foreach ($a in $Accounts) { $present[$a.Sid] = $true }

    $restore = Get-LogonRightRestoreTarget -Accounts $Accounts -DefaultGrants $DefaultGrants

    $absent = New-Object System.Collections.ArrayList
    foreach ($sid in @($restore.Keys | Sort-Object)) {
        if ($present.ContainsKey($sid)) { continue }

        $wanted = [uint32]$restore[$sid]
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
        between this and applying defltbase.inf wholesale with secedit, where every user right on
        the machine returns to the shipped default and any deliberate customisation is lost. The
        template is read for what the default *is*, not applied as a whole, and a sign-in right is
        only given back when nobody who should hold it does (see Get-LogonRightRestoreTarget).

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

    # 2. A sign-in right nobody who should hold it still holds. Only that is a lockout: a hardened
    #    baseline that limits the right to Administrators is left alone, because a deliberate
    #    restriction is not a fault to be repaired. Restoring is additive. The partner deny rights
    #    on the restored groups are broad-group denies, so step 1 has already planned their removal.
    $restore = Get-LogonRightRestoreTarget -Accounts $Accounts -DefaultGrants $DefaultGrants
    foreach ($sid in @($restore.Keys | Sort-Object)) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }

        $mask = [uint32]$account.Mask
        $missing = [uint32]([uint32]$restore[$sid] -band (-bnot $mask))
        if ($missing -ne 0) {
            $reason = (ConvertTo-LogonRightName -Mask $missing | ForEach-Object { "grant $_" }) -join ', '
            Add-Change -Sid $sid -SetBits $missing -ClearBits 0 -Reason $reason
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
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' }
        catch { Add-OfflineRepairLog -Level Warning -Message "The SECURITY hive could not be unloaded after the logon rights were written: $($_.Exception.Message)" }
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

        $values = @(
            @{ Key = 'ActSysAc'; Bytes = [System.BitConverter]::GetBytes([uint32]$Mask) }
            @{ Key = 'SecDesc'; Bytes = [byte[]]$donor.Bytes }
            @{ Key = 'Sid'; Bytes = $sidBytes }
        )

        if ($newKey.Created) {
            $result.Created = $true

            # The account key itself carries an empty REG_NONE default value, which is what LSA leaves.
            $default = Set-OfflinePrivilegedRegistryValue -Path "$root\$Sid" -Name '' `
                -Type $script:RegNone -Bytes ([byte[]]@()) -Confirm:$false
            if (-not $default.Written) {
                $result.Reason = "the account key's default value could not be written: $($default.Error)"
                return $result
            }
        }
        else {
            # The account entry exists but carried no logon right - an account that still holds
            # privileges keeps its key when its last logon right goes. Only the missing ActSysAc is
            # added; the existing SecDesc, Sid and default value belong to LSA and are not rewritten.
            # An entry that already has ActSysAc was written by something else since detect ran.
            $existing = Get-OfflinePrivilegedRegistrySubKeyName -Path "$root\$Sid"
            if (-not $existing.Ok) {
                $result.Reason = "the existing entry for $Sid could not be listed: $($existing.Error)"
                return $result
            }
            if (@($existing.Names) -contains 'ActSysAc') {
                $result.Reason = "an entry for $Sid with a logon-right mask already exists on this disk, so it was not overwritten"
                return $result
            }
            if (@($existing.Names) -notcontains 'Sid' -or @($existing.Names) -notcontains 'SecDesc') {
                $result.Reason = "the existing entry for $Sid has no Sid or SecDesc subkey, so it is not an entry this script will add a mask to"
                return $result
            }
            $values = @($values | Where-Object { $_.Key -eq 'ActSysAc' })
        }

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

        $result.Ok = $true
        return $result
    }
    catch {
        $result.Reason = "the account entry could not be created: $($_.Exception.Message)"
        return $result
    }
    finally {
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' }
        catch { Add-OfflineRepairLog -Level Warning -Message "The SECURITY hive could not be unloaded after recreating $Sid : $($_.Exception.Message)" }
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

        A manifest that already exists is kept, not overwritten. It holds the masks from before the
        first repair; a second run would record the already-repaired masks as "previous", and a
        revert would then restore the repair instead of the original state.

    .OUTPUTS
        PSCustomObject with Ok, Kept and Error.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][array]$Recreated = @()
    )

    $result = [PSCustomObject]@{ Ok = $false; Kept = $false; Error = $null }

    if (Test-Path -LiteralPath $ManifestPath) {
        $result.Kept = $true
        $result.Ok = $true
        return $result
    }

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
        $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath $ManifestPath -Encoding ascii -Force -ErrorAction Stop
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
        return $result
    }
}

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads the revert manifest, telling "there is none" apart from "it cannot be read".

    .OUTPUTS
        PSCustomObject with Exists, Manifest and Error.
    #>
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $result = [PSCustomObject]@{ Exists = $false; Manifest = $null; Error = $null }
    if (-not (Test-Path -LiteralPath $ManifestPath)) { return $result }
    $result.Exists = $true

    try {
        $raw = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { throw 'the file is empty' }
        $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $manifest -or $manifest.Script -ne 'win-fix-user-rights') { throw 'the file is not a manifest written by this script' }
        $result.Manifest = $manifest
    }
    catch { $result.Error = "$($_.Exception.Message)" }
    return $result
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

    # 0. A sign-in right that nobody who should hold it still holds. User-rights assignment is
    #    replace and not merge, so one over-restrictive policy strips every principal it does not
    #    name - and LSA deletes the account from Policy\Accounts altogether when that right was the
    #    only one it held. Only a real lockout is repairable (see Get-LogonRightRestoreTarget); any
    #    other difference from the shipped template is reported and left as it is, because a
    #    hardening baseline removes these grants deliberately while an administrator can still sign in.
    $restore = Get-LogonRightRestoreTarget -Accounts $Accounts -DefaultGrants $DefaultGrants
    foreach ($sid in @($DefaultGrants.Keys | Sort-Object)) {
        $wanted = [uint32]([uint32]$DefaultGrants[$sid] -band $script:SignInGrantBits)
        if ($wanted -eq 0) { continue }

        $friendly = Resolve-SidFriendlyName -Sid $sid
        $account = $byName[$sid]
        $held = [uint32]0
        if ($null -ne $account) { $held = [uint32]$account.Mask }

        $missing = [uint32]($wanted -band (-bnot $held))
        if ($missing -eq 0) { continue }

        $restoreBits = [uint32]0
        if ($restore.ContainsKey($sid)) { $restoreBits = [uint32]([uint32]$restore[$sid] -band $missing) }
        $reportBits = [uint32]($missing -band (-bnot $restoreBits))

        if ($restoreBits -ne 0) {
            $names = (ConvertTo-LogonRightName -Mask $restoreBits) -join ', '
            if ($null -eq $account) {
                [void]$findings.Add((New-Finding -Cause 'MissingAccountEntry' -Item "$friendly / $names" `
                            -Message "$friendly has no entry in $($script:TargetNoun)'s LSA policy database, so it holds no logon right at all, and no group an administrator signs in through holds $names. Windows grants it $names by default on this build, and LSA removes an account outright once its last right is taken away - which is what an over-restrictive user-rights policy does."))
            }
            else {
                [void]$findings.Add((New-Finding -Cause 'MissingDefaultLogonRight' -Item "$friendly / $names" `
                            -Message "$friendly does not hold $names, and no group an administrator signs in through does either. Windows grants it $names by default on this build. Its mask is 0x$('{0:X4}' -f [uint32]$account.Mask)."))
            }
        }

        if ($reportBits -ne 0) {
            $names = (ConvertTo-LogonRightName -Mask $reportBits) -join ', '
            [void]$findings.Add((New-Finding -Cause 'DefaultLogonRightDeviation' -Item "$friendly / $names" -Repairable $false `
                        -Message "$friendly does not hold $names, which Windows grants it by default on this build. Another group an administrator signs in through still holds it, so this is not a lockout and is left as it is: hardening baselines remove these grants deliberately."))
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
                        -Message "$($script:BroadSids[$sid]) is denied '$($denyMap[$right])'. A deny right overrides every allow right, so this refuses that logon type for the whole group. It may be left behind by a policy that has since been removed, or still applied by one; confirm with 'gpresult /scope computer /v' on the VM before relying on the repair surviving the next policy refresh."))
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

function Test-OfflineDiskCandidate {
    <#
    .SYNOPSIS
        Reports whether this machine shows any sign of an attached disk that could hold another
        Windows installation, without changing anything to find out.

    .DESCRIPTION
        Used by mode=auto to decide whether the offline discovery should run at all. That discovery
        stops nested guests, brings disks online and assigns drive letters, which is right on a
        rescue VM and wrong on the live VM this script usually runs on - so it must not run there
        just to learn that there is nothing to find.

        Read-only: a lettered volume holding Windows\System32\config\SECURITY, or a data disk on the
        bus the offline discovery searches that is offline or carries an unlettered partition. The
        Azure temporary disk is excluded, the same way the offline discovery excludes it.

    .OUTPUTS
        $true when a candidate is visible.
    #>
    [CmdletBinding()]
    param()

    if (@(Get-AttachedWindowsInstallation).Count -gt 0) { return $true }

    $busTypes = @('SCSI', 'SAS', 'RAID', 'NVMe', 'File Backed Virtual')
    $canTestTemporary = [bool](Get-Command -Name Test-TemporaryStorageDisk -ErrorAction SilentlyContinue)

    foreach ($disk in @(Get-Disk -ErrorAction SilentlyContinue)) {
        if ($null -eq $disk) { continue }
        if ($busTypes -notcontains "$($disk.BusType)") { continue }
        if ($disk.IsBoot -or $disk.IsSystem) { continue }

        if ($canTestTemporary) {
            $isTemporary = $false
            try { $isTemporary = [bool](Test-TemporaryStorageDisk -Disk $disk) } catch { $isTemporary = $false }
            if ($isTemporary) { continue }
        }

        if ($disk.IsOffline) { return $true }

        foreach ($partition in @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            if ($null -eq $partition) { continue }
            if ("$($partition.Type)" -eq 'Reserved') { continue }
            if ([uint64]$partition.Size -lt 1MB) { continue }
            if (-not $partition.DriveLetter -or [char]$partition.DriveLetter -eq [char]0) { return $true }
        }
    }

    return $false
}

function Resolve-RunMode {
    <#
    .SYNOPSIS
        Decides whether this run repairs the running machine or an attached disk.

    .DESCRIPTION
        mode=online never calls the offline discovery, so it has no side effects on the disks of the
        machine it runs on. mode=offline requires an attached installation and fails without one.
        mode=auto goes online only when Test-OfflineDiskCandidate sees nothing, and fails closed -
        asking for an explicit mode - when a candidate is visible but the discovery fails. Guessing
        online there would repair the rescue VM and report the patient disk as fixed.

    .OUTPUTS
        PSCustomObject with Mode, Offline, WindowsPath, GuestComputerName, Reason and Error.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('auto', 'online', 'offline')][string]$Mode,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$WindowsDrive = ''
    )

    $result = [PSCustomObject]@{ Mode = $null; Offline = $false; WindowsPath = $null; GuestComputerName = $null; Reason = $null; Error = $null }
    $requested = $Mode.ToLowerInvariant()
    $hasDrive = -not [string]::IsNullOrWhiteSpace($WindowsDrive)

    if ($requested -eq 'online') {
        if ($hasDrive) {
            $result.Error = "windowsDrive=$WindowsDrive names an attached installation, but mode=online repairs the machine the script runs on. Use mode=offline with windowsDrive, or drop windowsDrive."
            return $result
        }
        $result.Mode = 'online'
        $result.WindowsPath = $env:windir
        $result.Reason = 'mode=online was requested'
        return $result
    }

    if ($requested -eq 'auto' -and -not $hasDrive -and -not (Test-OfflineDiskCandidate)) {
        $result.Mode = 'online'
        $result.WindowsPath = $env:windir
        $result.Reason = 'mode=auto found no attached data disk that could hold another Windows installation'
        return $result
    }

    $discovery = @{}
    if ($hasDrive) { $discovery['WindowsDrive'] = $WindowsDrive }
    try { $disk = Get-OfflineWindowsDisk @discovery }
    catch {
        if ($requested -eq 'offline') {
            $result.Error = "mode=offline needs an attached Windows installation and none could be used: $($_.Exception.Message)"
        }
        else {
            $result.Error = "mode=auto saw an attached data disk but could not identify an offline Windows installation on it ($($_.Exception.Message)). Nothing was changed. Re-run with mode=online to repair this machine, or with mode=offline (optionally windowsDrive) on a rescue VM."
        }
        return $result
    }

    if ($null -eq $disk -or [string]::IsNullOrWhiteSpace("$($disk.WindowsPath)")) {
        $result.Error = 'The offline discovery returned no Windows path, so there is no installation to repair. Nothing was changed.'
        return $result
    }

    $result.Mode = 'offline'
    $result.Offline = $true
    $result.WindowsPath = "$($disk.WindowsPath)"
    if ($disk.PSObject.Properties['GuestComputerName']) { $result.GuestComputerName = "$($disk.GuestComputerName)" }
    $result.Reason = if ($requested -eq 'offline') { 'mode=offline was requested' } elseif ($hasDrive) { "windowsDrive=$WindowsDrive was given" } else { 'mode=auto found an attached Windows installation' }
    return $result
}

function Test-LogonRightApplied {
    <#
    .SYNOPSIS
        Compares a fresh read of the logon rights with what a write was meant to leave behind.

    .DESCRIPTION
        Only the bits a plan entry changes are compared, so an unrelated bit that moved for some
        other reason does not fail the check. An account that should exist but has no entry counts
        as holding nothing.

    .OUTPUTS
        Array of mismatch descriptions; empty when every planned bit reads back as intended.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Absent
    )

    $bySid = @{}
    foreach ($account in $Accounts) { $bySid["$($account.Sid)"] = [uint32]$account.Mask }

    $mismatch = New-Object System.Collections.ArrayList
    foreach ($entry in $Plan) {
        $changed = [uint32]([uint32]$entry.OldMask -bxor [uint32]$entry.NewMask)
        $current = [uint32]0
        if ($bySid.ContainsKey("$($entry.Sid)")) { $current = [uint32]$bySid["$($entry.Sid)"] }
        $wanted = [uint32]([uint32]$entry.NewMask -band $changed)
        $got = [uint32]($current -band $changed)
        if ($got -ne $wanted) {
            [void]$mismatch.Add(("{0} [{1}]: bits 0x{2:X4} should read 0x{3:X4} but read 0x{4:X4}" -f $entry.Name, $entry.Sid, $changed, $wanted, $got))
        }
    }

    foreach ($entry in $Absent) {
        $mask = [uint32]$entry.Mask
        if (-not $bySid.ContainsKey("$($entry.Sid)")) {
            [void]$mismatch.Add(("{0} [{1}]: still has no policy entry" -f $entry.Name, $entry.Sid))
            continue
        }
        $current = [uint32]$bySid["$($entry.Sid)"]
        if (($current -band $mask) -ne $mask) {
            [void]$mismatch.Add(("{0} [{1}]: should hold 0x{2:X4} but its mask is 0x{3:X4}" -f $entry.Name, $entry.Sid, $mask, $current))
        }
    }

    return @($mismatch)
}

function Invoke-LogonRightRevert {
    <#
    .SYNOPSIS
        Puts the logon-right bits recorded by the first repair back, and proves it.

    .DESCRIPTION
        Only the bits the repair changed are reverted, against a fresh read of the current masks, so
        a right granted or removed since the repair is left as it is. Every write is read back. The
        record is deleted only when every recorded bit reads back as it was before the repair; on
        any failure it is kept so the revert can be retried. SYSTEM is never read or written.

        Log lines stream to the output; the run status is left in $script:RevertStatus.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][bool]$Online
    )

    $script:RevertStatus = $STATUS_ERROR
    $source = if ($Online) { 'the running machine (secedit /export)' } else { 'the offline SECURITY hive' }

    Log-Output 'REVERT: putting back the logon-right bits recorded by the first repair.' | Tee-Object -FilePath $logFile -Append

    $read = Read-RevertManifest -ManifestPath $ManifestPath
    if (-not $read.Exists) {
        Log-Warning "No revert record was found at $ManifestPath, so there is nothing recorded to undo. Nothing was changed." | Tee-Object -FilePath $logFile -Append
        $script:RevertStatus = $STATUS_SUCCESS
        return
    }
    if ($read.Error) {
        Log-Error "REVERT FAILED: the revert record at $ManifestPath could not be read ($($read.Error)). Nothing was changed and the record was kept." | Tee-Object -FilePath $logFile -Append
        return
    }

    $recorded = @(@($read.Manifest.Accounts) | Where-Object { $_ -and $_.Sid })
    $recreated = @(@($read.Manifest.Recreated) | Where-Object { $_ -and $_.Name })

    $current = if ($Online) { Get-LiveLogonRight } else { Get-OfflineLogonRight -WindowsPath $WindowsPath }
    Write-OperatorLog
    if (-not $current.Ok) {
        Log-Error "REVERT FAILED: the current logon rights could not be read from $source ($($current.Reason)). Nothing was changed and the record was kept." | Tee-Object -FilePath $logFile -Append
        return
    }

    $bySid = @{}
    foreach ($account in @($current.Accounts)) { $bySid["$($account.Sid)"] = $account }

    $undo = New-Object System.Collections.ArrayList
    $missing = New-Object System.Collections.ArrayList
    foreach ($record in $recorded) {
        $previous = [uint32]$record.PreviousMask
        $changed = [uint32]($previous -bxor [uint32]$record.AppliedMask)
        if ($changed -eq 0) { continue }

        $account = $bySid["$($record.Sid)"]
        if ($null -eq $account) {
            # Offline, a mask can only be written into an entry that exists; building one here would
            # be inventing structure to reimpose a state, which revert never does.
            if (-not $Online) { [void]$missing.Add($record); continue }
            $mask = [uint32]0
            $type = [int]$script:RegNone
        }
        else {
            $mask = [uint32]$account.Mask
            $type = [int]$account.Type
        }

        $restoreSet = [uint32]($previous -band $changed)
        $target = Get-AdjustedLogonRightMask -Mask $mask -Set $restoreSet -Clear ([uint32]($changed -bxor $restoreSet))
        if ($target -eq $mask) { continue }

        [void]$undo.Add([PSCustomObject]@{
                Sid = "$($record.Sid)"; Name = "$($record.Name)"; OldMask = $mask; NewMask = $target
                Type = $type; Reason = 'revert'
            })
    }

    if ($missing.Count -gt 0) {
        foreach ($record in $missing) {
            Log-Error ("  [NOT REVERTED] {0} [{1}] has no policy entry on this disk any more, so its recorded mask cannot be written back." -f $record.Name, $record.Sid) | Tee-Object -FilePath $logFile -Append
        }
        Log-Error "REVERT FAILED: $($missing.Count) recorded account(s) have no entry. Nothing was changed and the record at $ManifestPath was kept." | Tee-Object -FilePath $logFile -Append
        return
    }

    foreach ($entry in $undo) {
        Log-Output ("  PLAN [{0}] {1}: 0x{2:X4} -> 0x{3:X4} (revert)" -f $entry.Sid, $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask) | Tee-Object -FilePath $logFile -Append
    }

    if ($undo.Count -gt 0) {
        if ($Online) {
            $apply = Repair-LiveLogonRight -Accounts @($current.Accounts) -Plan @($undo) -Absent @() -Skipped @($current.Skipped)
            Write-OperatorLog
            if (-not $apply.Ok) {
                Log-Error "REVERT INCOMPLETE: secedit could not apply the revert ($($apply.Reason)). The record at $ManifestPath was kept so the revert can be retried." | Tee-Object -FilePath $logFile -Append
                return
            }
        }
        else {
            $backup = $null
            try { $backup = Backup-OfflineHiveFile -WindowsPath $WindowsPath -Hive 'SECURITY' }
            catch { $backup = $null; Add-OfflineRepairLog -Level Error -Message "The SECURITY hive could not be backed up: $($_.Exception.Message)" }
            Write-OperatorLog
            if (-not $backup -or -not (Test-Path -LiteralPath $backup)) {
                Log-Error "REVERT FAILED: the SECURITY hive could not be backed up, so nothing was written. The record at $ManifestPath was kept." | Tee-Object -FilePath $logFile -Append
                return
            }
            Log-Output "SECURITY hive backed up to $backup before the revert." | Tee-Object -FilePath $logFile -Append

            $write = Set-OfflineLogonRight -WindowsPath $WindowsPath -Plan @($undo)
            Write-OperatorLog
            foreach ($failure in @($write.Failed)) {
                Log-Error ("  [FAILED] {0}: {1}" -f $failure.Entry.Name, $failure.Error) | Tee-Object -FilePath $logFile -Append
            }
            if (-not $write.Ok) {
                Log-Error "REVERT INCOMPLETE: not every mask could be written back ($($write.Reason)). The record at $ManifestPath was kept so the revert can be retried; the hive as it was before this revert is at $backup." | Tee-Object -FilePath $logFile -Append
                return
            }
        }

        $after = if ($Online) { Get-LiveLogonRight } else { Get-OfflineLogonRight -WindowsPath $WindowsPath }
        Write-OperatorLog
        if (-not $after.Ok) {
            Log-Error "REVERT INCOMPLETE: the logon rights could not be read back from $source ($($after.Reason)), so the revert is unverified. The record at $ManifestPath was kept." | Tee-Object -FilePath $logFile -Append
            return
        }

        $mismatch = @(Test-LogonRightApplied -Accounts @($after.Accounts) -Plan @($undo) -Absent @())
        if ($mismatch.Count -gt 0) {
            foreach ($line in $mismatch) { Log-Error "  [NOT REVERTED] $line" | Tee-Object -FilePath $logFile -Append }
            Log-Error "REVERT INCOMPLETE: $($mismatch.Count) account(s) do not read back as recorded. The record at $ManifestPath was kept so the revert can be retried." | Tee-Object -FilePath $logFile -Append
            return
        }
        $bySid = @{}
        foreach ($account in @($after.Accounts)) { $bySid["$($account.Sid)"] = $account }

        foreach ($entry in $undo) {
            Log-Output ("  [REVERTED] {0}: 0x{1:X4} -> 0x{2:X4}, read back" -f $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask) | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Output 'Every recorded bit already reads as it did before the repair, so nothing needed writing.' | Tee-Object -FilePath $logFile -Append
    }

    Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $ManifestPath) {
        Log-Error "REVERT INCOMPLETE: the masks were reverted and verified, but the record at $ManifestPath could not be deleted. Delete it before running the repair again, or that repair will keep this stale record." | Tee-Object -FilePath $logFile -Append
        return
    }

    # Only entries that exist now are reported as kept; one the repair failed to recreate was never there.
    $kept = @($recreated | Where-Object { $bySid.ContainsKey("$($_.Sid)") })
    foreach ($entry in $kept) {
        Log-Output ("  [KEPT] {0}: the policy entry the repair recreated is left in place, holding {1}." -f $entry.Name, $entry.Right) | Tee-Object -FilePath $logFile -Append
    }

    if ($kept.Count -gt 0) {
        Log-Output "Recreated entries are not removed: that means deleting an LSA account entry to reimpose a lockout, the riskier write. To remove one, export with 'secedit /export /areas USER_RIGHTS' on the running VM, drop the SID from the right and re-import." | Tee-Object -FilePath $logFile -Append
        Log-Output ("REVERT COMPLETE (partial): {0} mask(s) written back and verified; {1} recreated entry/entries kept. The record was deleted." -f $undo.Count, $kept.Count) | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output ("REVERT COMPLETE: {0} mask(s) written back and verified. The bits the repair changed are as they were before it ran. The record was deleted." -f $undo.Count) | Tee-Object -FilePath $logFile -Append
    }
    $script:RevertStatus = $STATUS_SUCCESS
}

#########################################################################################################
# Main
#########################################################################################################

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName" | Tee-Object -FilePath $logFile -Append
$status = $STATUS_ERROR

try {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
    . .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
    . .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1
    . .\src\windows\common\helpers\Use-OfflinePrivilegedRegistry.ps1

    :Main do {
        Clear-OfflineRepairLog

        # Which machine is being repaired. The extension does not say which way it launched the
        # script, so 'mode' does; auto only goes online when nothing that could be the patient disk
        # is visible, and fails closed rather than guessing when the discovery fails.
        $run = Resolve-RunMode -Mode $mode -WindowsDrive $windowsDrive
        Write-OperatorLog
        if ($run.Error) {
            Log-Error $run.Error | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        $isOffline = [bool]$run.Offline
        $windowsPath = $run.WindowsPath
        if ($isOffline) {
            $script:TargetNoun = 'this disk'
            $guest = if ([string]::IsNullOrWhiteSpace($run.GuestComputerName)) { 'unknown' } else { $run.GuestComputerName }
            Log-Output "MODE: offline ($($run.Reason)). Repairing the attached installation at $windowsPath (computer name: $guest)." | Tee-Object -FilePath $logFile -Append
        }
        else {
            $script:TargetNoun = 'this machine'
            Log-Output "MODE: online ($($run.Reason)). Repairing the machine this runs on ($env:COMPUTERNAME); Windows writes its own policy through secedit." | Tee-Object -FilePath $logFile -Append
            Log-Output "      For a VM that cannot boot or whose agent does not answer, attach its disk with 'az vm repair create' and re-run with --run-on-repair and mode=offline." | Tee-Object -FilePath $logFile -Append
        }

        $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath
        if ([string]::IsNullOrWhiteSpace($manifestPath)) {
            Log-Error "The revert record path could not be built from '$windowsPath', so nothing was changed." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        #################################################################################################
        # Revert
        #################################################################################################
        if ($isRevert) {
            Invoke-LogonRightRevert -ManifestPath $manifestPath -WindowsPath $windowsPath -Online (-not $isOffline)
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $script:RevertStatus
            break Main
        }

        #################################################################################################
        # Detect
        #################################################################################################
        if ($isOffline) {
            $rights = Get-OfflineLogonRight -WindowsPath $windowsPath
            $source = 'the offline SECURITY hive'
        }
        else {
            $rights = Get-LiveLogonRight
            $source = 'the running machine (secedit /export)'
        }
        Write-OperatorLog

        if (-not $rights.Ok) {
            Log-Error "The current user rights could not be read from $source, so nothing was changed: $($rights.Reason)." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        Log-Output "Read logon rights for $(@($rights.Accounts).Count) account(s) from $source." | Tee-Object -FilePath $logFile -Append

        # The full table goes to the detail log; the returned log keeps the findings.
        foreach ($account in @($rights.Accounts)) {
            "  $($account.Sid) [$($account.Name)] mask=0x$('{0:X4}' -f $account.Mask) $(@($account.Rights) -join ', ')" |
                Out-File -FilePath $logFile -Append
        }

        # The defaults are read from the installation being repaired, so they are right for its
        # build and SKU.
        $shipped = Get-ShippedLogonRightDefault -WindowsPath $windowsPath
        Write-OperatorLog
        if ($shipped.Ok) {
            Log-Output "Shipped defaults read from $($shipped.TemplatePath): $($shipped.RightCount) logon right(s) across $($shipped.Grants.Count) account(s)." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "The shipped defaults could not be read from $($script:TargetNoun) ($($shipped.Error)). Falling back to the built-in defaults for Administrators, Remote Desktop Users and NT SERVICE\ALL SERVICES." | Tee-Object -FilePath $logFile -Append
            $shipped.Grants = @{
                $script:SidAdministrators     = [uint32]($script:BitInteractive -bor $script:BitRemoteInteractive)
                $script:SidRemoteDesktopUsers = [uint32]$script:BitRemoteInteractive
                $script:SidAllServices        = [uint32]$script:BitService
            }
        }

        $findings = @(Get-UserRightsFinding -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

        # SYSTEM\Setup is read for reporting only and never written: a SetupType other than 0 can be
        # legitimate servicing or provisioning state, and nothing here can tell it apart from residue.
        # Not read online, where it is the running machine's own boot state.
        $setupState = $null
        if ($isOffline) {
            $setupState = Get-OfflineSetupState -WindowsPath $windowsPath
            Write-OperatorLog
            if (-not $setupState.Available) {
                Log-Warning "SYSTEM\Setup could not be read on this disk ($($setupState.Reason)), so the boot-time state is unknown. The logon-right repair does not depend on it." | Tee-Object -FilePath $logFile -Append
            }
            elseif ($setupState.SetupType -ne 0 -and -not [string]::IsNullOrWhiteSpace($setupState.CmdLine)) {
                $findings += New-Finding -Cause 'SetupHookInUse' -Item 'SYSTEM\Setup' -Repairable $false `
                    -Message "SYSTEM\Setup is in setup mode (SetupType=$($setupState.SetupType)) running '$($setupState.CmdLine)'. Left as it is: it may be servicing or provisioning, and this repair never writes SYSTEM\Setup."
            }
            elseif ($setupState.SetupType -ne 0) {
                $findings += New-Finding -Cause 'SetupTypeNonZero' -Item 'SYSTEM\Setup' -Repairable $false `
                    -Message "SYSTEM\Setup\SetupType is $($setupState.SetupType) with no CmdLine. Left as it is: it may be servicing or provisioning state, and this repair never writes SYSTEM\Setup."
            }
        }

        #################################################################################################
        # Report
        #################################################################################################
        foreach ($finding in $findings) {
            $tag = if ($finding.Repairable) { 'FOUND' } else { 'FOUND (not repairable here)' }
            Log-Output "  [$tag] $($finding.Cause) - $($finding.Item)" | Tee-Object -FilePath $logFile -Append
            Log-Output "           $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }

        # The count comes after the list: Run Command keeps the tail of a 4096-character log.
        $repairable = @($findings | Where-Object { $_.Repairable })
        if ($findings.Count -eq 0) {
            Log-Output "No user-rights fault was found: every logon right this script checks on $($script:TargetNoun) permits sign-in." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "Detect found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair." | Tee-Object -FilePath $logFile -Append
        }

        if ($isDetectOnly) {
            Log-Output "DETECT ONLY: nothing was changed on $($script:TargetNoun)." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        #################################################################################################
        # Repair
        #################################################################################################
        if ($repairable.Count -eq 0 -and -not $isForced) {
            Log-Output "Nothing was changed: $($script:TargetNoun) has no user-rights fault this script repairs." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        if ($repairable.Count -eq 0 -and $isForced) {
            Log-Warning 'FORCED: no repairable fault was detected. The plan is derived from the same conditions detect reports, so on a healthy installation it comes out empty and nothing is written.' | Tee-Object -FilePath $logFile -Append
        }

        $plan = @(Get-LogonRightRepairPlan -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

        # Absent accounts carry no mask, so they never appear in the plan; counted separately so a
        # deleted entry is not mistaken for a healthy installation.
        $absentTargets = @(Get-AbsentGrantTarget -Accounts @($rights.Accounts) -DefaultGrants $shipped.Grants)

        foreach ($entry in $plan) {
            Log-Output ("  PLAN [{0}] {1}: 0x{2:X4} -> 0x{3:X4} ({4})" -f $entry.Sid, $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
        }
        foreach ($target in $absentTargets) {
            Log-Output ("  PLAN [{0}] {1}: recreate the policy entry holding {2} (0x{3:X4})" -f $target.Sid, $target.Name, $target.Right, [uint32]$target.Mask) | Tee-Object -FilePath $logFile -Append
        }
        Log-Output ("Plan: {0} mask change(s), {1} account entry/entries to recreate." -f $plan.Count, $absentTargets.Count) | Tee-Object -FilePath $logFile -Append

        if ($plan.Count -eq 0 -and $absentTargets.Count -eq 0) {
            Log-Output "Nothing was changed: the logon-right masks on $($script:TargetNoun) already permit sign-in." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        # Written before the first write, so a run that dies part way still has an undo record.
        $record = Write-RevertManifest -ManifestPath $manifestPath -Plan $plan -Recreated $absentTargets
        if (-not $record.Ok) {
            Log-Error "The revert record could not be written to $manifestPath ($($record.Error)), so nothing was changed." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }
        if ($record.Kept) {
            Log-Warning "A revert record from an earlier repair already exists at $manifestPath and was kept, so revert=true returns to the state before that first repair. This run's changes are not recorded separately." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "Revert record written to $manifestPath." | Tee-Object -FilePath $logFile -Append
        }

        $failed = $false
        $recreated = 0
        $backupPath = $null

        if ($isOffline) {
            try { $backupPath = Backup-OfflineHiveFile -WindowsPath $windowsPath -Hive 'SECURITY' }
            catch { $backupPath = $null; Add-OfflineRepairLog -Level Error -Message "The SECURITY hive could not be backed up: $($_.Exception.Message)" }
            Write-OperatorLog
            if (-not $backupPath -or -not (Test-Path -LiteralPath $backupPath)) {
                Log-Error 'The SECURITY hive could not be backed up, so nothing was written.' | Tee-Object -FilePath $logFile -Append
                $status = $STATUS_ERROR
                break Main
            }
            Log-Output "SECURITY hive backed up to $backupPath before the first write." | Tee-Object -FilePath $logFile -Append

            $write = Set-OfflineLogonRight -WindowsPath $windowsPath -Plan $plan
            Write-OperatorLog
            foreach ($entry in @($write.Applied)) {
                Log-Output ("  [FIXED] {0}: 0x{1:X4} -> 0x{2:X4} ({3})" -f $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
            }
            foreach ($failure in @($write.Failed)) {
                $label = if ([string]::IsNullOrWhiteSpace($failure.Entry.Name)) { "SID $($failure.Entry.Sid)" } else { $failure.Entry.Name }
                Log-Error ("  [FAILED] {0}: {1}" -f $label, $failure.Error) | Tee-Object -FilePath $logFile -Append
            }
            if (-not $write.Ok) {
                Log-Error "The logon-right masks could not all be written: $($write.Reason)." | Tee-Object -FilePath $logFile -Append
                $failed = $true
            }

            # An entry the fault deleted is recreated only after the masks were written cleanly.
            $adminBits = [uint32]0
            $adminAccount = @($rights.Accounts | Where-Object { $_.Sid -eq $script:SidAdministrators }) | Select-Object -First 1
            if ($null -ne $adminAccount) { $adminBits = [uint32]$adminAccount.Mask }
            $adminPlan = @($plan | Where-Object { $_.Sid -eq $script:SidAdministrators }) | Select-Object -First 1
            if ($null -ne $adminPlan) { $adminBits = [uint32]$adminPlan.NewMask }
            $adminsHoldRdp = (($adminBits -band $script:BitRemoteInteractive) -ne 0)

            if (-not $failed) {
                foreach ($absent in $absentTargets) {
                    $made = New-OfflineLogonRightAccount -WindowsPath $windowsPath -Sid $absent.Sid `
                        -Mask ([uint32]$absent.Mask) -DonorSid $script:SidAdministrators
                    Write-OperatorLog

                    if ($made.Ok) {
                        $recreated++
                        Log-Output ("  [FIXED] {0}: policy entry recreated holding {1} (0x{2:X4})" -f $absent.Name, $absent.Right, [uint32]$absent.Mask) | Tee-Object -FilePath $logFile -Append
                    }
                    else {
                        $failed = $true
                        Log-Error "  [NOT RESTORED] $($absent.Name) has no entry in this disk's LSA policy database and one could not be created: $($made.Reason)" | Tee-Object -FilePath $logFile -Append
                        if ($adminsHoldRdp) {
                            Log-Output '                 BUILTIN\Administrators can still sign in over RDP. To put the group back once the VM is up, run as administrator:' | Tee-Object -FilePath $logFile -Append
                        }
                        else {
                            Log-Output '                 To put the group back once the VM is up, run as administrator:' | Tee-Object -FilePath $logFile -Append
                        }
                        Log-Output '                 secedit /export /areas USER_RIGHTS /cfg %temp%\ur.inf, add the SID to the right, then secedit /configure /db %temp%\ur.sdb /cfg %temp%\ur.inf /areas USER_RIGHTS' | Tee-Object -FilePath $logFile -Append
                    }
                }
            }
        }
        else {
            # One secedit call carries both halves: the mask corrections and any account entry the
            # policy deleted outright, which Windows recreates itself.
            $apply = Repair-LiveLogonRight -Accounts @($rights.Accounts) -Plan @($plan) -Absent @($absentTargets) -Skipped @($rights.Skipped)
            Write-OperatorLog
            if (-not $apply.Ok) {
                Log-Error "  [FAILED] secedit could not apply the repair: $($apply.Reason)" | Tee-Object -FilePath $logFile -Append
                $failed = $true
            }
            else {
                Log-Output ("  secedit rewrote only: {0}" -f (@($apply.Applied) -join ', ')) | Tee-Object -FilePath $logFile -Append
            }
        }

        if ($failed) {
            Log-Error "REPAIR INCOMPLETE on $($script:TargetNoun). The revert record at $manifestPath holds the masks from before the first repair; revert=true puts back whatever was written." | Tee-Object -FilePath $logFile -Append
            if ($backupPath) {
                Log-Output "The SECURITY hive as it was before this run is at $backupPath." | Tee-Object -FilePath $logFile -Append
            }
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        # Read back: a write counts only if a fresh read shows it.
        $after = if ($isOffline) { Get-OfflineLogonRight -WindowsPath $windowsPath } else { Get-LiveLogonRight }
        Write-OperatorLog
        if (-not $after.Ok) {
            Log-Error "The logon rights could not be read back from $source ($($after.Reason)), so the repair is unverified." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        $mismatch = @(Test-LogonRightApplied -Accounts @($after.Accounts) -Plan @($plan) -Absent @($absentTargets))
        foreach ($line in $mismatch) {
            Log-Error "  [NOT APPLIED] $line" | Tee-Object -FilePath $logFile -Append
        }
        if ($mismatch.Count -gt 0) {
            Log-Error "REPAIR INCOMPLETE: $($mismatch.Count) planned change(s) do not read back. revert=true puts back whatever was written." | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_ERROR
            break Main
        }

        if (-not $isOffline) {
            foreach ($entry in $plan) {
                Log-Output ("  [FIXED] {0}: 0x{1:X4} -> 0x{2:X4} ({3}), read back" -f $entry.Name, [uint32]$entry.OldMask, [uint32]$entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
            }
            foreach ($target in $absentTargets) {
                Log-Output ("  [FIXED] {0}: entry recreated by Windows holding {1}, read back" -f $target.Name, $target.Right) | Tee-Object -FilePath $logFile -Append
            }
            Log-Output ("REPAIRED {0} mask(s) and {1} account entry/entries through secedit on this machine, verified by a fresh export." -f $plan.Count, $absentTargets.Count) | Tee-Object -FilePath $logFile -Append
            Log-Output 'Only the rights listed above were rewritten. A logon right applies at the next logon attempt; no reboot is needed.' | Tee-Object -FilePath $logFile -Append
            Log-Output "If a domain policy still assigns the right, it returns at the next policy refresh - check with 'gpresult /h' on the VM." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output ("REPAIRED {0} mask(s) and recreated {1} account entry/entries in the offline LSA policy database, verified by reading the hive back." -f $plan.Count, $recreated) | Tee-Object -FilePath $logFile -Append
            Log-Output 'Only the logon-right bits listed above were changed; no other user right on this disk was touched.' | Tee-Object -FilePath $logFile -Append
            if ($setupState -and $setupState.Available -and $setupState.SetupType -eq 0 -and [string]::IsNullOrWhiteSpace($setupState.CmdLine)) {
                Log-Output 'Verified on this disk: SetupType=0 and no boot-time command is armed.' | Tee-Object -FilePath $logFile -Append
            }
            Log-Output "Run 'az vm repair restore' and start the VM; no extra boot is needed. $backupPath can be deleted once the VM is healthy." | Tee-Object -FilePath $logFile -Append
        }

        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
    } while ($false)
}
catch {
    $status = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
}
finally {
    if (Get-Command -Name Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
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

    if (Get-Command -Name Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        try {
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append -ErrorAction Stop
        }
        catch {
            $status = $STATUS_ERROR
            Log-Error "Final helper diagnostics could not be written to the detail log: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
        }
    }
}

return $status
