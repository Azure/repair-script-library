#########################################################################################################
#
# .SYNOPSIS
#   Clears local Group Policy on an offline Windows disk so a VM locked out by its own policy can be
#   logged on to again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is a deliberate blanket reset, not a targeted repair. It is a separate script for exactly
#   that reason: every other script in this family only writes what it can prove is broken, while
#   this one clears a whole subsystem because the operator has decided a local policy is the cause.
#   Nothing here is inferred, so nothing here runs unless it is asked for by name.
#
#   What it clears:
#     1. %SystemRoot%\System32\GroupPolicy and GroupPolicyUsers. These hold registry.pol, the
#        machine and user startup/logon script definitions, and the local security policy database.
#     2. Every subkey of SOFTWARE\Policies. That is the branch Group Policy authors, and it holds
#        Software Restriction Policies, AppLocker rules and the interactive logon restrictions.
#
#   The folders are renamed aside rather than deleted, so the change can be undone by renaming them
#   back, and the SOFTWARE hive is backed up before the registry side is touched. Both undo paths are
#   written to the log before the change is made. A policy folder that exists but holds no file is
#   left alone, because Windows ships those folders and their presence is not evidence of anything.
#
#   Before changing anything the script reports what is actually configured, and calls out the three
#   policies that genuinely stop a logon: Software Restriction Policies with a Disallowed default,
#   AppLocker in enforce mode, and machine startup or user logon scripts. If none of those are set it
#   says so, so an operator can tell whether this script is even aimed at the right problem before
#   letting it clear anything.
#
# .RESOLVES
#   A VM that boots but cannot be logged on to because of its own local policy: Software Restriction
#   Policies set to Disallowed, AppLocker enforcing rules that do not permit userinit.exe or
#   explorer.exe, a machine startup or user logon script that hangs or fails, an interactive logon
#   policy that blocks the account, and a logon that is refused immediately after the credentials are
#   accepted.
#
# .PARAMETER detectOnly
#   "true" to report what is configured and what would be cleared, and make no changes at all.
#   Defaults to "false".
#
# .PARAMETER scope
#   How much of local Group Policy to clear. Defaults to "targeted".
#     "targeted" - acts only on what detection proved is refusing the logon: Software Restriction
#                  Policies at Disallowed, AppLocker in enforce mode, or a policy startup/logon
#                  script. When one of those is found, the policy folders are renamed aside and only
#                  those key(s) are removed; the rest of SOFTWARE\Policies is left alone. When none
#                  of them is found, nothing is changed at all, because Windows ships a gpt.ini and
#                  a Registry.pol and their presence is not evidence of a fault. This is the default
#                  because it repairs the lockout without discarding unrelated policy, and leaves a
#                  disk that policy is not breaking exactly as it was.
#     "files"    - the GroupPolicy, GroupPolicyUsers and AppLocker folders only, and no registry
#                  change at all. Fully reversible by renaming them back, and it matches the reset
#                  procedure Microsoft documents, so it is the most conservative option.
#     "registry" - the blanket registry reset only: every SOFTWARE\Policies branch that holds a
#                  value, less the preserved trust material.
#     "all"      - "registry" plus the folders. The escape hatch for when a policy is clearly the
#                  cause but detection cannot say which one. Read the warning it prints.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-reset-group-policy --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-reset-group-policy --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-reset-group-policy --parameters scope=files --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-reset-group-policy --parameters scope=all --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Where this sits relative to what Microsoft documents. The reset Microsoft documents is deleting
#   %WinDir%\System32\GroupPolicy and GroupPolicyUsers and then running "gpupdate /force", and for
#   AppLocker, deleting the files under %WinDir%\System32\AppLocker. Scope "files" is exactly that,
#   minus the gpupdate, which a machine that cannot boot obviously cannot run. Microsoft does not
#   document deleting keys under SOFTWARE\Policies as a repair step at all; that part is this
#   script's own, which is why it is scoped to the two keys detection can prove are blocking, and why
#   the blanket form is opt-in.
#
#   Documented alternatives worth trying first when the machine can still be started. Microsoft's
#   documented recovery from a Software Restriction Policy lockout is Safe Mode: "software
#   restriction policies do not apply when Windows is started in Safe Mode", so booting the VM into
#   Safe Mode, logging on as a local administrator and correcting the policy there avoids offline
#   editing entirely. This script is for the case where that is not available - the VM will not boot
#   far enough, or Safe Mode cannot be reached.
#
#   Not used here: "secedit /configure /cfg %windir%\inf\defltbase.inf". That resets security policy,
#   including user rights, which is a different fault from the Group Policy files this script owns.
#   It is the accepted fix for user rights left tattooed after a GPO is removed - internal TSGs cover
#   it and it is used in the field for exactly that - but it belongs to win-fix-user-rights, gated
#   behind detection, not to a blanket policy reset here.
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Run this only after win-fix-logon-subsystem has come back clean. That script repairs the values
#   the logon actually depends on - Winlogon, Session Manager, the profile list and the setup-mode
#   command - and a fault there looks the same from the outside as a policy lockout. There is no
#   overlap between the two: this script never touches those values, and that one never touches
#   policy.
#
#   A domain-joined VM re-applies its domain policy at the next refresh, so on a domain member this
#   clears the local policy for good and the domain policy only until the VM can reach a domain
#   controller. If the blocking policy came from the domain, this buys one logon, and the policy has
#   to be fixed at the domain for the fix to stick.
#
#   Only the subkeys of SOFTWARE\Policies are removed. SOFTWARE\Microsoft\Windows\CurrentVersion\
#   Policies is deliberately left alone despite the name: it holds the default UAC configuration on a
#   stock image and is not written by Group Policy alone, so clearing it would change a machine that
#   never had a policy applied to it.
#
#   SOFTWARE\Policies is never empty in practice. A stock image carries a branch no administrator
#   created, and a domain member also holds everything its GPOs push - on a freshly joined Server 2022
#   that is already dozens of keys, the policy-managed firewall rules among them. That is why the
#   default is "targeted" rather than a blanket wipe: on a normal machine the blanket reset discards
#   a great deal of policy that was never the problem. A domain member rebuilds that branch at the
#   next refresh once it can reach a domain controller; a workgroup or MDM-managed machine has
#   nothing to rebuild it from, so there the loss is permanent. Read the reported key list before
#   choosing "all".
#
#   "targeted" removes only what detection proved can refuse a logon on its own: Software Restriction
#   Policies with a default level of Disallowed, and AppLocker with a collection in enforce mode. If
#   neither is set, the registry is not touched at all and the script says so, rather than clearing
#   policy on the off chance. The policy folders are still renamed aside in that case, because they
#   are the source the policy would be re-applied from and renaming them is reversible.
#
#   Not everything under SOFTWARE\Policies is the kind of policy that can refuse a logon, and two
#   branches are never cleared. Microsoft\SystemCertificates holds the enterprise root and
#   intermediate CAs, the Disallowed store listing certificates the organisation has explicitly
#   distrusted, and the EFS recovery agent certificate. Microsoft\Cryptography holds the TLS cipher
#   suite order. Clearing those cannot fix a logon, and it would quietly weaken the machine: dropping
#   the Disallowed store re-trusts certificates somebody deliberately revoked, and dropping the EFS
#   certificate can cost access to encrypted files. They are reported as preserved, not as failures.
#
#   Windows protects a few keys inside the policy branch. SOFTWARE\Policies\Microsoft\Windows\Appx is
#   owned by TrustedInstaller with a DACL that withholds DELETE from SYSTEM and Administrators, so no
#   caller short of TrustedInstaller can remove it. Those keys are reported and left in place: they
#   ship with the operating system, no administrator authored them, and none of them can refuse a
#   logon. The branch above such a key survives with them, so "SOFTWARE\Policies\Microsoft" remaining
#   afterwards is the expected result and not a failed run. Taking ownership to force them out would
#   weaken a Windows protection and buy nothing.
#
#   Local security policy that was applied through secedit rather than registry.pol lives in the SAM
#   and SECURITY hives and is not cleared here. Account lockout and password policy survive this
#   script.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('targeted', 'all', 'files', 'registry', IgnoreCase = $true)][string]$scope = 'targeted',
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

# 'targeted' clears the policy files and only the two registry keys that can refuse a logon.
# 'all' and 'registry' are the blanket reset: everything under SOFTWARE\Policies that holds a value.
$isTargeted = ($scope -eq 'targeted')
$clearFiles = ($scope -eq 'targeted' -or $scope -eq 'all' -or $scope -eq 'files')
$clearRegistry = ($scope -eq 'targeted' -or $scope -eq 'all' -or $scope -eq 'registry')

# The folders that hold local policy. Everything under them is policy, which is what makes renaming
# the folder aside a safe way to clear it.
#
# System32\AppLocker is the AppLocker policy cache the Application Identity service reads. Microsoft
# documents deleting its contents as the way to clear AppLocker rules, so the registry side alone is
# not enough: leave the cache in place and the rules can still be enforced.
# See https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/delete-an-applocker-rule
$script:PolicyFolders = @('System32\GroupPolicy', 'System32\GroupPolicyUsers', 'System32\AppLocker')

# The keys that can refuse a logon on their own, which is all that 'targeted' removes. Anything else
# under SOFTWARE\Policies is left alone unless the operator asks for the blanket reset.
$script:TargetedPolicyKeys = @{
    Safer     = 'Microsoft\Windows\Safer\CodeIdentifiers'
    AppLocker = 'Microsoft\Windows\SrpV2'
}

# Keys left behind because Windows itself refuses to delete them. Declared here so the summary can
# read it even when the registry side never runs: @($null).Count is 1, not 0.
$script:ProtectedPolicyKeys = [System.Collections.Generic.List[string]]::new()

# Keys left behind only because a protected key sits somewhere beneath them. These are ordinary
# SYSTEM-owned keys and are reported separately, because calling them protected would be wrong.
$script:RetainedParentKeys = [System.Collections.Generic.List[string]]::new()

# Branches under SOFTWARE\Policies that are never cleared, relative to that key.
#
# SOFTWARE\Policies is the branch Group Policy manages, but not all of it is the kind of policy that
# can refuse a logon. These two hold trust material: SystemCertificates carries the enterprise root
# and intermediate CAs, the Disallowed store that records certificates the organisation has
# explicitly distrusted, and the EFS recovery agent certificate; Cryptography carries the TLS cipher
# suite order. Clearing them cannot fix a logon, and it silently weakens the machine - removing the
# Disallowed store re-trusts revoked certificates, and removing the EFS certificate can cost access
# to encrypted files. A domain member gets them back at the next policy refresh, but a workgroup or
# MDM-managed machine does not, and none of it is recoverable from anything but the hive backup.
$script:PreservedPolicyPaths = @(
    'Microsoft\SystemCertificates',
    'Microsoft\Cryptography'
)

# Keys left untouched on purpose, by the rule above.
$script:PreservedPolicyKeys = [System.Collections.Generic.List[string]]::new()

function Test-PreservedPolicyPath {
    <#
    .SYNOPSIS
        Says whether a path under SOFTWARE\Policies is one this script must not clear.

    .OUTPUTS
        'self'     the path is preserved, or sits inside something preserved.
        'ancestor' something preserved sits below the path, so it cannot be deleted wholesale.
        'no'       neither, so the path can be cleared normally.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $RelativePath
    )

    foreach ($preserved in $script:PreservedPolicyPaths) {
        if ($RelativePath -eq $preserved -or $RelativePath.StartsWith("$preserved\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return 'self'
        }
        if ($preserved.StartsWith("$RelativePath\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return 'ancestor'
        }
    }

    return 'no'
}

# Software Restriction Policy default levels. 0 is the one that locks a machine out: everything is
# disallowed unless a rule explicitly allows it, and the logon needs userinit.exe and explorer.exe.
$script:SaferLevels = @{
    0      = 'Disallowed'
    4096   = 'Basic User'
    262144 = 'Unrestricted'
}

function Get-PolicyFileState {
    <#
    .SYNOPSIS
        Reads the file side of local Group Policy: which folders exist, what is in them, and whether
        any startup or logon scripts are defined.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $present = [System.Collections.Generic.List[object]]::new()
    $empty = [System.Collections.Generic.List[string]]::new()
    $scripts = [System.Collections.Generic.List[string]]::new()
    $totalFiles = 0

    foreach ($relative in $script:PolicyFolders) {
        $folder = Join-OfflinePath -Root $WindowsPath -ChildPath $relative
        if (-not (Test-OfflinePath $folder)) { continue }

        $files = @(Get-ChildItem -LiteralPath $folder -Recurse -Force -File -ErrorAction SilentlyContinue)

        # Windows ships these folders, so their existence is not evidence of anything. Only a folder
        # that actually holds a file is policy, and only that is worth renaming aside.
        if ($files.Count -eq 0) {
            [void]$empty.Add($relative)
            continue
        }

        $totalFiles += $files.Count

        [void]$present.Add([PSCustomObject]@{
                Path      = $folder
                Relative  = $relative
                FileCount = $files.Count
                Files     = @($files | ForEach-Object { $_.FullName.Substring($folder.Length).TrimStart('\') })
            })

        # Scripts defined here run as SYSTEM at boot or as the user at logon, before the desktop is
        # usable. One that hangs holds the boot or the logon open with no visible error.
        foreach ($file in $files) {
            if ($file.Name -match '^(ps)?scripts\.ini$' -or $file.FullName -match '\\Scripts\\(Startup|Shutdown|Logon|Logoff)\\') {
                [void]$scripts.Add($file.FullName.Substring($folder.Length).TrimStart('\'))
            }
        }
    }

    return [PSCustomObject]@{
        Folders    = @($present)
        Empty      = @($empty)
        FileCount  = $totalFiles
        Scripts    = @($scripts)
        HasContent = ($present.Count -gt 0)
    }
}

function Get-PolicyRegistryState {
    <#
    .SYNOPSIS
        Reads the registry side of local Group Policy from the mounted SOFTWARE hive, and identifies
        the two policies that can refuse a logon outright.

    .DESCRIPTION
        Must be called inside Invoke-WithHive -Hive 'SOFTWARE', which mounts the offline hive at
        HKLM:\BROKENSOFTWARE.

        A branch counts as policy only when a value exists somewhere in it. Keys on their own
        enforce nothing, and some of them cannot be deleted, so counting a key as policy would make
        this script find work to do on a disk it has already cleared.
    #>

    $root = 'HKLM:\BROKENSOFTWARE\Policies'
    $keys = @()
    $empty = @()
    if (Test-Path $root) {
        foreach ($branch in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            # Policy is expressed as values, so a branch of empty keys enforces nothing. The
            # difference matters after this script has already run: what is left under Policies is
            # the shells of keys Windows would not let go, and counting those as policy would make
            # every later run repeat the work and copy the whole hive again for nothing.
            #
            # Preserved branches are skipped for the same reason. They keep their values by design,
            # so counting them would make this script find work it has already decided not to do.
            $values = 0
            foreach ($key in @($branch) + @(Get-ChildItem -Path $branch.PSPath -Recurse -ErrorAction SilentlyContinue)) {
                $rel = $key.Name -replace '^HKEY_LOCAL_MACHINE\\BROKENSOFTWARE\\Policies\\?', ''
                if ((Test-PreservedPolicyPath -RelativePath $rel) -eq 'self') { continue }
                try { $values += $key.ValueCount } catch { $null = $_ }
                if ($values -gt 0) { break }
            }
            if ($values -gt 0) { $keys += $branch.PSChildName } else { $empty += $branch.PSChildName }
        }
    }

    # Software Restriction Policies. DefaultLevel 0 means deny by default.
    $safer = $null
    $saferPath = "$root\Microsoft\Windows\Safer\CodeIdentifiers"
    if (Test-Path $saferPath) {
        $saferKey = Get-ItemProperty -Path $saferPath -ErrorAction SilentlyContinue
        if ($null -ne $saferKey) {
            $level = $saferKey.DefaultLevel
            $safer = [PSCustomObject]@{
                DefaultLevel = $level
                LevelName    = if ($null -ne $level -and $script:SaferLevels.ContainsKey([int]$level)) { $script:SaferLevels[[int]$level] } else { "unknown ($level)" }
                Blocking     = ($null -ne $level -and [int]$level -eq 0)
                RuleCount    = @(Get-ChildItem -Path $saferPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\{' }).Count
            }
        }
    }

    # AppLocker. EnforcementMode 1 on any collection means the rules are enforced, not audited.
    $appLocker = $null
    $srpV2Path = "$root\Microsoft\Windows\SrpV2"
    if (Test-Path $srpV2Path) {
        $enforced = [System.Collections.Generic.List[string]]::new()
        foreach ($collection in @(Get-ChildItem -Path $srpV2Path -ErrorAction SilentlyContinue)) {
            $mode = (Get-ItemProperty -Path $collection.PSPath -ErrorAction SilentlyContinue).EnforcementMode
            if ($null -ne $mode -and [int]$mode -eq 1) { [void]$enforced.Add($collection.PSChildName) }
        }
        $appLocker = [PSCustomObject]@{
            Collections = @(Get-ChildItem -Path $srpV2Path -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
            Enforced    = @($enforced)
            Blocking    = ($enforced.Count -gt 0)
        }
    }

    return [PSCustomObject]@{
        Keys       = @($keys)
        EmptyKeys  = @($empty)
        Safer      = $safer
        AppLocker  = $appLocker
        HasContent = ($keys.Count -gt 0)
    }
}

function Clear-PolicyFile {
    <#
    .SYNOPSIS
        Renames each local Group Policy folder aside. Renaming rather than deleting keeps the change
        reversible, and the undo command is logged before the rename is attempted.

    .OUTPUTS
        The number of folders that were renamed.
    #>
    param(
        [Parameter(Mandatory = $true)]$PolicyFile,
        [Parameter(Mandatory = $true)][string]$Stamp
    )

    $changes = 0

    foreach ($folder in @($PolicyFile.Folders)) {
        $newName = "$(Split-Path -Path $folder.Path -Leaf).bak-$Stamp"
        $target = Join-Path -Path (Split-Path -Path $folder.Path -Parent) -ChildPath $newName
        Add-OfflineRepairLog -Message "To undo: Rename-Item -LiteralPath '$target' -NewName '$(Split-Path -Path $folder.Path -Leaf)'"
        try {
            Rename-Item -LiteralPath $folder.Path -NewName $newName -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "Renamed $($folder.Path) to $target ($($folder.FileCount) file(s))."
            $changes++
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not rename $($folder.Path) ($($_.Exception.Message))."
        }
    }

    return $changes
}

function Remove-OfflineRegistryKeyTree {
    <#
    .SYNOPSIS
        Removes a key and everything beneath it from the mounted offline hive, bottom up.

    .DESCRIPTION
        Neither Remove-Item -Recurse nor DeleteSubKeyTree nor "reg delete /f" can clear the policy
        branch of a real hive on their own. All three fail the whole subtree when a single key in it
        cannot be deleted, and Windows ships such keys: SOFTWARE\Policies\Microsoft\Windows\Appx is
        owned by NT SERVICE\TrustedInstaller with a protected DACL that grants SYSTEM and
        Administrators CCDCLCSWRPWPRC - create, delete and enumerate children, but not DELETE on the
        key itself. Only TrustedInstaller can remove it.

        So the subtree delete is tried first because it is one call and it succeeds for everything
        an administrator authored, and when it fails this walks the children and deletes bottom up,
        so a protected key costs only itself and its ancestors instead of the entire branch.

        Protected keys are left alone by design. They ship with the operating system, are not
        operator-authored policy, and hold nothing that can refuse a logon. Taking ownership of a
        TrustedInstaller-owned key to delete it would weaken a Windows protection for no benefit.

        A key that survives is separated from a key that is protected. Appx is protected; the
        Microsoft and Windows keys above it are ordinary SYSTEM-owned keys that survive only because
        a key beneath them did. The two are told apart by the exception type rather than its text,
        because the text is localised: refusing the delete raises UnauthorizedAccessException, while
        holding a surviving child raises InvalidOperationException.

        Any key that has to stay has its values stripped, because a retained key that still holds
        policy would leave the reset incomplete. That is never more destructive than this function
        already intends, since the key was queued for deletion in the first place.

        Success is decided by re-testing each path, not by the absence of an exception.

    .OUTPUTS
        The display paths of the keys that survived, which is empty when the whole tree went.
    #>
    # SupportsShouldProcess is deliberately not declared. This runs unattended under the repair
    # extension, where a confirmation prompt has no console to answer it and wedges the run for as
    # long as the Run Command allows. Whether to write at all is decided by the caller: detectOnly
    # returns long before this is reached.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ParentPath,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Display,

        # Mandatory rejects an empty collection unless this is present, and the list is empty on
        # every call that has nothing to report yet.
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $Survivors
    )

    $full = "$ParentPath\$Name"
    $lastError = $null

    $relative = $Display -replace '^SOFTWARE\\Policies\\?', ''
    $preserved = Test-PreservedPolicyPath -RelativePath $relative

    if ($preserved -eq 'self') {
        # Trust material, not logon policy. Left exactly as it is, values included.
        $Survivors.Add($Display)
        $script:PreservedPolicyKeys.Add($Display)
        Add-OfflineRepairLog -Message "Kept $Display, which holds certificate or cryptography trust material rather than logon policy."
        return
    }

    # The subtree delete is all or nothing, so it cannot be used when something below has to stay.
    if ($preserved -ne 'ancestor') {
        try {
            $parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ParentPath, $true)
            if ($null -ne $parent) {
                try { $parent.DeleteSubKeyTree($Name, $false) } finally { $parent.Close() }
            }
        }
        catch {
            # Expected when the subtree holds a key Windows protects. Handled by the walk below.
            $lastError = $_.Exception.Message
        }

        if (-not (Test-Path -LiteralPath "HKLM:\$full")) { return }
    }

    $childNames = @()
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($full, $true)
        if ($null -ne $key) {
            try { $childNames = @($key.GetSubKeyNames()) } finally { $key.Close() }
        }
    }
    catch {
        # Cannot enumerate, so nothing below can be reached. The key is recorded as a survivor.
        $lastError = $_.Exception.Message
    }

    foreach ($child in $childNames) {
        Remove-OfflineRegistryKeyTree -ParentPath $full -Name $child -Display "$Display\$child" -Survivors $Survivors
    }

    # The children are gone or accounted for, so this key may now be deletable on its own.
    $accessDenied = $false
    try {
        $parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ParentPath, $true)
        if ($null -ne $parent) {
            try { $parent.DeleteSubKey($Name, $false) } finally { $parent.Close() }
        }
    }
    catch {
        # Protected, or still holds a protected child. PowerShell wraps a failure raised inside a
        # .NET method, so the exception that says which one it is is the innermost.
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $lastError = $inner.Message
        $accessDenied = ($inner -is [System.UnauthorizedAccessException]) -or
                        ($inner -is [System.Security.SecurityException])
    }

    if (-not (Test-Path -LiteralPath "HKLM:\$full")) { return }

    $Survivors.Add($Display)
    if (-not $lastError) { $lastError = 'no error reported' }

    # The key has to stay, so take the policy out of it. Windows refuses the delete here, not the
    # edit, and a retained key that still held policy would leave the reset half done.
    $valuesCleared = 0
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($full, $true)
        if ($null -ne $key) {
            try {
                foreach ($valueName in @($key.GetValueNames())) {
                    try { $key.DeleteValue($valueName, $false); $valuesCleared++ }
                    catch { $null = $_ }
                }
            }
            finally { $key.Close() }
        }
    }
    catch {
        # Cannot open it for write, so its values stay. Said plainly in the message below.
        $null = $_
    }

    $note = if ($valuesCleared -gt 0) { " Cleared $valuesCleared value(s) from it." } else { '' }

    if ($accessDenied) {
        $script:ProtectedPolicyKeys.Add($Display)
        Add-OfflineRepairLog -Message "Kept $Display because Windows refuses to delete it ($lastError).$note"
    }
    else {
        $script:RetainedParentKeys.Add($Display)
        Add-OfflineRepairLog -Message "Kept $Display because a key beneath it survived ($lastError).$note"
    }
}

function Clear-PolicyRegistry {
    <#
    .SYNOPSIS
        Removes the named keys under SOFTWARE\Policies from the mounted hive. SOFTWARE\Policies
        itself is kept, because Windows expects the key to exist and recreates the branch under it
        on the next policy refresh.

    .DESCRIPTION
        Must be called inside Invoke-WithHive -Hive 'SOFTWARE'. The undo path is the SOFTWARE hive
        backup taken before this runs.

        KeyPaths are relative to SOFTWARE\Policies and may be any depth, which is what lets the same
        code serve both modes: 'targeted' passes the two keys that refuse a logon, such as
        Microsoft\Windows\Safer\CodeIdentifiers, while the blanket reset passes the top-level
        branches that were found to hold policy. A branch of empty keys enforces nothing, and some of
        those keys cannot be deleted at all, so removing them would be a change with no symptom
        behind it.

        Keys that cannot be deleted are left in place and reported through
        $script:ProtectedPolicyKeys and $script:RetainedParentKeys, so the caller can tell them
        apart from a real failure.

    .OUTPUTS
        The number of keys that were cleared.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $KeyPaths
    )

    $changes = 0
    $script:ProtectedPolicyKeys = [System.Collections.Generic.List[string]]::new()
    $script:RetainedParentKeys = [System.Collections.Generic.List[string]]::new()
    $script:PreservedPolicyKeys = [System.Collections.Generic.List[string]]::new()

    foreach ($relative in $KeyPaths) {
        if (-not (Test-Path -LiteralPath "HKLM:\BROKENSOFTWARE\Policies\$relative")) { continue }

        $survivors = [System.Collections.Generic.List[string]]::new()
        $branch = "SOFTWARE\Policies\$relative"

        # Split the last segment off so a nested path and a top-level branch take the same path.
        $split = $relative.LastIndexOf('\')
        $leaf = if ($split -ge 0) { $relative.Substring($split + 1) } else { $relative }
        $parent = if ($split -ge 0) { "BROKENSOFTWARE\Policies\$($relative.Substring(0, $split))" } else { 'BROKENSOFTWARE\Policies' }

        Remove-OfflineRegistryKeyTree -ParentPath $parent -Name $leaf `
            -Display $branch -Survivors $survivors

        if ($survivors.Count -eq 0) {
            Add-OfflineRepairLog -Message "Removed $branch."
            $changes++
            continue
        }

        Add-OfflineRepairLog -Message "Cleared the policy under $branch. $($survivors.Count) empty key(s) could not be deleted and were left in place."
        $changes++
    }

    return $changes
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, scope=$scope)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $policyFile = Get-PolicyFileState -WindowsPath $offline.WindowsPath
    $policyRegistry = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-PolicyRegistryState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Report the current state before deciding anything.
    if ($policyFile.HasContent) {
        Log-Info "Local Group Policy files: $($policyFile.FileCount) file(s) across $(@($policyFile.Folders).Count) folder(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($folder in @($policyFile.Folders)) {
            Log-Info "  $($folder.Relative): $($folder.FileCount) file(s)$(if ($folder.FileCount -gt 0) { " ($(@($folder.Files) -join ', '))" })" | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        $emptyFolders = @($policyFile.Empty)
        $emptyNote = ''
        if ($emptyFolders.Count -gt 0) {
            $emptyNote = if ($emptyFolders.Count -eq 1) {
                " ($($emptyFolders[0]) exists but is empty, which is how Windows ships it, so it is left alone)"
            }
            else {
                " ($($emptyFolders -join ' and ') exist but are empty, which is how Windows ships them, so they are left alone)"
            }
        }
        Log-Info "Local Group Policy files: nothing configured$emptyNote." | Tee-Object -FilePath $logFile -Append
    }

    if ($policyRegistry.HasContent) {
        Log-Info "SOFTWARE\Policies holds policy in $(@($policyRegistry.Keys).Count) key(s): $(@($policyRegistry.Keys) -join ', ')." | Tee-Object -FilePath $logFile -Append
    }
    elseif (@($policyRegistry.EmptyKeys).Count -gt 0) {
        Log-Info "SOFTWARE\Policies holds no policy. $(@($policyRegistry.EmptyKeys).Count) key(s) are present ($(@($policyRegistry.EmptyKeys) -join ', ')) but hold no values anywhere beneath them, so they enforce nothing." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info 'SOFTWARE\Policies is empty.' | Tee-Object -FilePath $logFile -Append
    }

    # The three things that actually refuse a logon, called out so the operator can see whether this
    # script is even aimed at the right problem.
    $blockers = 0
    if ($null -ne $policyRegistry.Safer) {
        if ($policyRegistry.Safer.Blocking) {
            Log-Warning "BLOCKING: Software Restriction Policies default level is Disallowed with $($policyRegistry.Safer.RuleCount) explicit rule(s). Every executable is denied unless a rule allows it, which includes userinit.exe and explorer.exe, so the logon cannot complete." | Tee-Object -FilePath $logFile -Append
            $blockers++
        }
        else {
            Log-Info "Software Restriction Policies are configured, default level $($policyRegistry.Safer.LevelName), $($policyRegistry.Safer.RuleCount) rule(s). Not a lockout by itself." | Tee-Object -FilePath $logFile -Append
        }
    }

    if ($null -ne $policyRegistry.AppLocker) {
        if ($policyRegistry.AppLocker.Blocking) {
            Log-Warning "BLOCKING: AppLocker is enforcing rules for $(@($policyRegistry.AppLocker.Enforced) -join ', '). If those rules do not permit the logon binaries, the logon is refused." | Tee-Object -FilePath $logFile -Append
            $blockers++
        }
        else {
            Log-Info "AppLocker rules exist for $(@($policyRegistry.AppLocker.Collections) -join ', ') but none are in enforce mode." | Tee-Object -FilePath $logFile -Append
        }
    }

    if (@($policyFile.Scripts).Count -gt 0) {
        Log-Warning "BLOCKING: $(@($policyFile.Scripts).Count) policy script definition(s) present ($(@($policyFile.Scripts) -join ', ')). Startup scripts run as SYSTEM before the logon UI and logon scripts run before the desktop, so one that hangs holds the boot or the logon open with no visible error." | Tee-Object -FilePath $logFile -Append
        $blockers++
    }

    if ($blockers -eq 0 -and ($policyFile.HasContent -or $policyRegistry.HasContent)) {
        Log-Info 'None of the policies that can refuse a logon on their own are set. Local policy is configured but is not an obvious cause, so confirm the symptom before clearing it.' | Tee-Object -FilePath $logFile -Append
    }

    # In targeted mode the registry side acts only on what detection proved is blocking. In blanket
    # mode it acts on every branch that holds a value.
    $targetKeys = [System.Collections.Generic.List[string]]::new()
    if ($isTargeted) {
        if ($null -ne $policyRegistry.Safer -and $policyRegistry.Safer.Blocking) {
            [void]$targetKeys.Add($script:TargetedPolicyKeys.Safer)
        }
        if ($null -ne $policyRegistry.AppLocker -and $policyRegistry.AppLocker.Blocking) {
            [void]$targetKeys.Add($script:TargetedPolicyKeys.AppLocker)
        }
    }
    else {
        foreach ($branch in @($policyRegistry.Keys)) { [void]$targetKeys.Add($branch) }
    }

    # Targeted scope acts only on what detection proved, on both halves. The registry side is
    # already gated on Blocking; the file side has to be too, or the default scope renames the
    # local policy of a disk where nothing is refusing the logon. Windows ships gpt.ini and a
    # Registry.pol, so "the folder has files in it" is not evidence of a fault. Scopes files and
    # all stay blanket on purpose, and are the documented way to clear policy that detection
    # cannot prove is blocking.
    $filesToClear = if ($clearFiles -and (-not $isTargeted -or $blockers -gt 0)) { @($policyFile.Folders).Count } else { 0 }
    $keysToClear = if ($clearRegistry) { @($targetKeys).Count } else { 0 }

    if ($isDetectOnly) {
        if ($isTargeted -and $filesToClear -eq 0 -and $keysToClear -eq 0) {
            $note = if ($policyFile.HasContent -or $policyRegistry.HasContent) {
                "Local Group Policy is configured ($($policyFile.FileCount) file(s), $(@($policyRegistry.Keys).Count) key(s) holding values), but none of it is a policy that refuses a logon by itself, so nothing would be changed."
            }
            else { 'No local Group Policy is configured on this disk, so nothing would be changed.' }
            Log-Output "Detect only (scope 'targeted'): $note No changes were made." | Tee-Object -FilePath $logFile -Append
        }
        else {
            $keyNote = if ($isTargeted) {
                if ($keysToClear -gt 0) { "remove $keysToClear blocking key(s) ($(@($targetKeys) -join ', '))" }
                else { 'remove no registry keys' }
            }
            else {
                "remove $keysToClear SOFTWARE\Policies key(s)"
            }
            Log-Output "Detect only (scope '$scope'): would rename $filesToClear policy folder(s) holding $($policyFile.FileCount) file(s) and $keyNote. No changes were made." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($filesToClear -eq 0 -and $keysToClear -eq 0) {
        if ($isTargeted -and ($policyFile.HasContent -or $policyRegistry.HasContent)) {
            Log-Output "Nothing to clear in scope 'targeted'. Local Group Policy is configured on this disk, but none of it is a policy that refuses a logon by itself, so a policy is not what is stopping the logon and nothing was changed. If a policy is still suspected, re-run with scope 'files' to set the policy files aside, or scope 'all' to clear SOFTWARE\Policies wholesale, and read the warning that comes with it." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output "Nothing to clear in scope '$scope'. No local Group Policy is configured on this disk, so a policy is not what is stopping the logon. No changes were made." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isTargeted) {
        Log-Info "Clearing local Group Policy, targeted. The policy files are renamed aside and only the key(s) that refuse a logon are removed: $(if ($keysToClear -gt 0) { @($targetKeys) -join ', ' } else { 'none, so the registry is left untouched' }). The rest of SOFTWARE\Policies is left in place." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning 'Clearing local Group Policy. This is a blanket reset, not a targeted repair: every setting under SOFTWARE\Policies that holds a value goes, which on a real machine includes policy firewall rules, Remote Desktop settings, BITS and telemetry settings, not only the policy that is refusing the logon. A domain-joined VM re-applies all of it at the next policy refresh; a workgroup or MDM-managed VM does not, and the only way back is the hive backup taken above. Certificate and cryptography trust material is left alone. Scope "targeted" does the same repair without the collateral damage.' | Tee-Object -FilePath $logFile -Append
    }

    # Back up the hive only when the registry side is actually going to be written.
    if ($keysToClear -gt 0) {
        $backup = Backup-OfflineHiveFile -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SOFTWARE hive backed up to $backup" | Tee-Object -FilePath $logFile -Append
    }

    $fileChanges = 0
    if ($filesToClear -gt 0) {
        $fileChanges = Clear-PolicyFile -PolicyFile $policyFile -Stamp $scriptStartTime
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    $registryChanges = 0
    if ($keysToClear -gt 0) {
        # Read inside the script block, which runs in a child scope, so this is set at script scope.
        $script:KeyPathsToClear = @($targetKeys)
        $registryChanges = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            return (Clear-PolicyRegistry -KeyPaths $script:KeyPathsToClear)
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remainingFile = Get-PolicyFileState -WindowsPath $offline.WindowsPath
    $script:KeyPathsToVerify = @($targetKeys)
    $remainingRegistry = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $state = Get-PolicyRegistryState
        # Checked here because HKLM:\BROKENSOFTWARE only exists while the hive is mounted.
        $stillThere = @($script:KeyPathsToVerify | Where-Object { Test-Path -LiteralPath "HKLM:\BROKENSOFTWARE\Policies\$_" })
        return ($state | Add-Member -NotePropertyName TargetsStillPresent -NotePropertyValue $stillThere -PassThru)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillPresent = @()
    if ($clearFiles -and $remainingFile.HasContent) {
        $stillPresent += "$(@($remainingFile.Folders).Count) policy folder(s)"
    }
    if ($clearRegistry -and $isTargeted) {
        # Targeted mode leaves the rest of SOFTWARE\Policies standing on purpose, so the only
        # question is whether the keys it aimed at are gone.
        $notGone = @($remainingRegistry.TargetsStillPresent)
        if ($notGone.Count -gt 0) {
            $stillPresent += "$($notGone.Count) blocking key(s) ($($notGone -join ', '))"
        }
    }
    elseif ($clearRegistry -and $remainingRegistry.HasContent) {
        # A branch that only survives because the operating system protects a key inside it is an
        # expected outcome, not a failure. Anything else genuinely did not clear.
        $protectedKeys = @($script:ProtectedPolicyKeys)
        $unexplained = @($remainingRegistry.Keys | Where-Object {
                $branch = "SOFTWARE\Policies\$_"
                -not @($protectedKeys | Where-Object { $_ -eq $branch -or $_ -like "$branch\*" })
            })
        if ($unexplained.Count -gt 0) {
            $stillPresent += "$($unexplained.Count) SOFTWARE\Policies key(s) ($($unexplained -join ', '))"
        }
    }

    $keyLabel = if ($isTargeted) { 'blocking' } else { 'SOFTWARE\Policies' }
    $summary = "Renamed $fileChanges of $filesToClear policy folder(s) and removed $registryChanges of $keysToClear $keyLabel key(s)."

    if ($stillPresent.Count -gt 0) {
        Log-Error "$summary Still present: $($stillPresent -join ', ')." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append

    if (@($script:PreservedPolicyKeys).Count -gt 0) {
        Log-Info "Not cleared on purpose: $(@($script:PreservedPolicyKeys).Count) branch(es) holding trust material ($(@($script:PreservedPolicyKeys) -join ', ')). These carry the enterprise root and intermediate CAs, the store of certificates the organisation has distrusted, the EFS recovery agent certificate and the TLS cipher suite order. None of that can refuse a logon, and clearing it would weaken the machine rather than repair it." | Tee-Object -FilePath $logFile -Append
    }

    if (@($script:ProtectedPolicyKeys).Count -gt 0 -or @($script:RetainedParentKeys).Count -gt 0) {
        $protected = @($script:ProtectedPolicyKeys)
        $retained = @($script:RetainedParentKeys)
        $detail = "Left in place: $($protected.Count + $retained.Count) empty key(s) that hold no policy."

        if ($protected.Count -gt 0) {
            $detail += " Windows refuses to delete $($protected.Count) of them ($($protected -join ', ')): they are owned by NT SERVICE\TrustedInstaller with a DACL that grants SYSTEM and Administrators everything except delete on the key itself. They ship with Windows, are not operator-authored policy, and hold nothing that can refuse a logon, so taking ownership to remove them would weaken a Windows protection for no benefit."
        }
        if ($retained.Count -gt 0) {
            $detail += " The other $($retained.Count) ($($retained -join ', ')) are ordinary keys that remain only because they sit above one of those, and a key cannot be deleted while a child of it survives."
        }

        Log-Info $detail | Tee-Object -FilePath $logFile -Append
    }
    if ($fileChanges -gt 0) {
        Log-Output "The renamed folders are still on the disk. Rename them back to undo this, using the commands recorded above." | Tee-Object -FilePath $logFile -Append
    }
    if ($registryChanges -gt 0) {
        Log-Output "The removed keys are recoverable from the SOFTWARE hive backup taken above." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
