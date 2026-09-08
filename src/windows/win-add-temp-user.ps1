#########################################################################################################
# .SYNOPSIS
#   Adds a local administrator to an offline Windows disk using the Setup CmdLine hook, then boots the
#   disk in the nested Hyper-V guest so the account is really created, and verifies that it exists.
#
# .DESCRIPTION
#   When an Azure VM has no usable administrative account, the account has to be created from outside.
#   There are two hooks that run early enough to do that, and they fail in different situations:
#
#     1. A machine startup script under Windows\System32\GroupPolicy. This is what the library's
#        existing win-create-troubleshooting-user does. On a domain-joined VM the domain's own policy
#        can replace the local Group Policy state, and the startup script then never runs.
#
#     2. SYSTEM\Setup\SetupType plus SYSTEM\Setup\CmdLine. The session manager runs CmdLine in a
#        SYSTEM console session before the logon UI appears, and it is not Group Policy, so domain
#        policy does not affect it. That is the hook this script uses.
#
#   Use this script when the VM is domain joined, or when win-create-troubleshooting-user has already
#   been tried and the account did not appear.
#
#   The account is created by the guest itself, not by editing the SAM offline. Editing SAM offline
#   means writing binary account structures by hand, which is how offline password tools corrupt an
#   account database. Instead the disk is booted in the nested Hyper-V guest that
#   'az vm repair create --enable-nested' provides, the guest runs one command at boot, and the disk
#   comes back to the rescue VM so the result can be read.
#
#   Because the guest does the work, this script can verify it. It reads back two independent signals:
#
#     - The result file the payload writes, which carries the exit code of each command it ran.
#     - The offline SAM hive, where a local account appears as a key under
#       SAM\Domains\Account\Users\Names.
#
#   If neither confirms the account, the run reports failure. It never reports success for an account
#   it did not observe.
#
#   The payload deletes itself and clears the hook it ran from, so the password is not left in a file
#   on the disk and the VM does not re-enter setup mode on its next boot.
#
# .RESOLVES
#   Lost or disabled local administrator on a VM that still boots. Not a no-boot repair: the disk has
#   to be able to boot in the nested guest for the account to be created.
#
# .PARAMETER username
#   Account to create. Defaults to 'azrepairadmin'. Must not already exist on the disk.
#
# .PARAMETER password
#   Password for the account. When omitted a compliant password is generated and printed once.
#
# .PARAMETER detectOnly
#   Report what is on the disk and change nothing.
#
# .PARAMETER revert
#   Undo the Setup hook and remove the payload. The account itself is reported, not deleted, because
#   deleting an account means editing SAM offline.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, when it should not be auto-detected.
#
# .PARAMETER bootTimeoutSeconds
#   How long to wait for the nested guest to report a heartbeat. Defaults to 600.
#
# .EXAMPLE
#   az vm repair create -g sourceRG -n sourceVM --enable-nested --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-add-temp-user --run-on-repair --verbose
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-add-temp-user --parameters detectOnly=true --run-on-repair --verbose
#
# .NOTES
#   Requires the rescue VM to have been created with --enable-nested. That flag makes the CLI pick a
#   SKU that supports nested virtualization, derive the guest generation from the source VM, install
#   the Hyper-V role, restart the rescue VM, and create the guest with the broken disk attached.
#   Without it there is no guest to boot and this script reports that and stops.
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The password is printed to the run output because that is the only way it reaches the engineer.
#   It is not written to the log file, and the payload that carries it is deleted from the disk.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'az vm repair run delivers --parameters as plain strings, so a SecureString cannot cross this boundary. The value is validated here, kept out of the log file, and the payload carrying it deletes itself.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
    Justification = 'Matches the library contract used by win-create-troubleshooting-user: the caller supplies username and password as separate run parameters.')]
Param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^(([a-zA-Z0-9]|[^/[\]:|+=;,?*%@])){1,19}$")]
    [ValidateScript({ $_ -notin @('1', '123', 'a', 'actuser', 'adm', 'admin', 'admin1', 'admin2', 'administrator', 'aspnet', 'backup', 'console', 'david', 'guest', 'john', 'owner', 'root', 'server', 'sql', 'support_388945a0', 'support', 'sys', 'test', 'test1', 'test2', 'test3', 'user', 'user1', 'user2', 'user3', 'user4', 'user5', 'nul', 'con', 'com', 'lpt') })]
    [string]$username = 'azrepairadmin',

    # An empty password is allowed and means "generate one"; anything supplied must satisfy Windows
    # complexity now, because discovering that after the nested boot would waste the whole cycle.
    [Parameter(Mandatory = $false)]
    [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) { return $true }
            if ($_.Length -lt 12 -or $_.Length -gt 123) { throw 'password must be 12-123 characters.' }
            $notReserved = $_ -notin @('password', 'pa$$word', 'pa$$w0rd', 'password123', '123456', 'admin', 'administrator', 'admin123', 'letmein', 'welcome', 'qwerty', 'abc123', 'password1', 'welcome123', 'Password!', 'Password1', 'Password22')
            if (-not $notReserved) { throw 'password is on the list of well-known passwords.' }
            $met = @(($_ -cmatch '[a-z]'), ($_ -cmatch '[A-Z]'), ($_ -match '[0-9]'), ($_ -match '\W')) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
            if ($met -lt 3) { throw 'password must contain at least three of: lowercase, uppercase, digit, special character.' }
            return $true
        })]
    [string]$password = '',

    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = '',
    [Parameter(Mandatory = $false)][ValidateRange(60, 3600)][int]$bootTimeoutSeconds = 600
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-NestedRepairVm.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')

# Where the payload and its result live inside the guest's own Windows directory. Windows\Temp is
# used rather than a new folder so nothing is left behind that the image did not already have.
$script:PayloadRelativePath = 'Temp\win-add-temp-user.cmd'
$script:ResultRelativePath = 'Temp\win-add-temp-user.result'
$script:ManifestRelativePath = 'Temp\win-add-temp-user-revert.json'

# SetupType 2 is 'setup in progress', which is the state that makes the session manager run CmdLine
# before the logon UI. 0 is the settled state a healthy installation sits in.
$script:SetupTypeRunCmdLine = 2

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

function New-TempUserPassword {
    <#
    .SYNOPSIS
        Generates a password that satisfies the Azure Windows complexity rules.

    .DESCRIPTION
        Azure requires 12 to 123 characters with three of: lower case, upper case, digit, special.
        One character of each class is placed first so the result cannot accidentally miss a class,
        then the whole string is shuffled so those positions are not predictable.
    #>
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digit = '23456789'
    $special = '!@#$%^&*()-_=+'

    $chars = @(
        $lower[(Get-Random -Maximum $lower.Length)]
        $upper[(Get-Random -Maximum $upper.Length)]
        $digit[(Get-Random -Maximum $digit.Length)]
        $special[(Get-Random -Maximum $special.Length)]
    )

    $all = $lower + $upper + $digit + $special
    for ($i = 0; $i -lt 12; $i++) {
        $chars += $all[(Get-Random -Maximum $all.Length)]
    }

    return -join ($chars | Sort-Object { Get-Random })
}

function Test-TempUserName {
    <#
    .SYNOPSIS
        Rejects names Windows will not accept, before the guest is booted to find out.

    .DESCRIPTION
        A name that 'net user' refuses produces a failed payload and a wasted boot cycle, so the
        cheap checks are done here. Windows forbids these characters outright, forbids a name that
        is only dots and spaces, and caps the length at 20 characters.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)

    $result = [PSCustomObject]@{ Valid = $false; Reason = $null }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        $result.Reason = 'the user name is empty'
        return $result
    }

    if ($Name.Length -gt 20) {
        $result.Reason = "the user name is $($Name.Length) characters and Windows allows at most 20"
        return $result
    }

    if ($Name -match '["/\\\[\]:;|=,+*?<>@]') {
        $result.Reason = 'the user name contains a character Windows does not allow in an account name'
        return $result
    }

    if ($Name.Trim([char]'.', [char]' ') -eq '') {
        $result.Reason = 'the user name is only dots and spaces'
        return $result
    }

    $result.Valid = $true
    return $result
}

function Get-OfflineLocalUserName {
    <#
    .SYNOPSIS
        Lists the local account names recorded in an offline SAM hive.

    .DESCRIPTION
        Every local account has a key named after it under SAM\Domains\Account\Users\Names. Reading
        the key names is enough to tell whether an account exists, and needs none of the binary
        parsing that reading account attributes would.

        The SAM hive carries restrictive permissions that survive being loaded offline, so this read
        can be denied even when running as SYSTEM. That is reported rather than treated as 'no
        accounts exist', because the difference matters: one means the account is absent, the other
        means we could not tell.

    .OUTPUTS
        PSCustomObject with Readable, Names and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $result = [PSCustomObject]@{
        Readable = $false
        Names    = @()
        Reason   = $null
    }

    try {
        $names = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SAM' -ScriptBlock {
            $namesKey = 'HKLM:\BROKENSAM\SAM\Domains\Account\Users\Names'
            if (-not (Test-Path $namesKey)) { return $null }
            return @(Get-ChildItem -Path $namesKey -ErrorAction Stop | ForEach-Object { $_.PSChildName })
        }
    }
    catch {
        $result.Reason = "the SAM hive could not be read: $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $names) {
        $result.Reason = 'the SAM hive loaded but the account name key was not present, so local accounts could not be listed'
        return $result
    }

    $result.Readable = $true
    $result.Names = @($names)
    return $result
}

function Test-OfflineLocalUser {
    <#
    .SYNOPSIS
        Reports whether one named account exists in the offline SAM.

    .OUTPUTS
        PSCustomObject with Known, Exists and Reason. Known is false when SAM could not be read, in
        which case Exists carries no meaning.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = [PSCustomObject]@{ Known = $false; Exists = $false; Reason = $null }

    $listing = Get-OfflineLocalUserName -WindowsPath $WindowsPath
    if (-not $listing.Readable) {
        $result.Reason = $listing.Reason
        return $result
    }

    $result.Known = $true
    $result.Exists = [bool](@($listing.Names) | Where-Object { $_ -eq $Name })
    return $result
}

function Get-OfflineSetupState {
    <#
    .SYNOPSIS
        Reads SYSTEM\Setup\SetupType and CmdLine from the offline disk.

    .OUTPUTS
        PSCustomObject with Available, SetupType, CmdLine and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $state = [PSCustomObject]@{
        Available = $false
        SetupType = 0
        CmdLine   = ''
        Reason    = $null
    }

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

function Set-OfflineSetupHook {
    <#
    .SYNOPSIS
        Points SYSTEM\Setup\CmdLine at the payload and puts the disk into setup mode.

    .DESCRIPTION
        The command is written as 'cmd.exe /c "<payload>"'. The program part is cmd.exe, which
        always exists in System32, so win-fix-logon-subsystem resolves it and classifies the entry
        as an active setup command rather than a dangling one it should clear.

        Every value is read back after being written. A hive write that silently fails would
        otherwise be reported as a successful repair, and the guest would boot without the hook.

    .OUTPUTS
        PSCustomObject with Applied, PreviousSetupType, PreviousCmdLine and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$GuestPayloadPath
    )

    $result = [PSCustomObject]@{
        Applied           = $false
        PreviousSetupType = 0
        PreviousCmdLine   = ''
        Reason            = $null
    }

    $before = Get-OfflineSetupState -WindowsPath $WindowsPath
    if (-not $before.Available) {
        $result.Reason = $before.Reason
        return $result
    }

    $result.PreviousSetupType = $before.SetupType
    $result.PreviousCmdLine = $before.CmdLine

    $command = 'cmd.exe /c "{0}"' -f $GuestPayloadPath
    $setupType = $script:SetupTypeRunCmdLine

    try {
        # Invoke-WithHive runs the block with '& $ScriptBlock' and passes no arguments, so the block
        # reads $command and $setupType from this scope rather than taking parameters.
        $readBack = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            Set-ItemProperty -Path $key -Name 'CmdLine' -Value $command -Type String -Force -ErrorAction Stop
            Set-ItemProperty -Path $key -Name 'SetupType' -Value $setupType -Type DWord -Force -ErrorAction Stop
            $props = Get-ItemProperty -Path $key -ErrorAction Stop
            return [PSCustomObject]@{ CmdLine = "$($props.CmdLine)"; SetupType = [int]$props.SetupType }
        }
    }
    catch {
        $result.Reason = "the Setup hook could not be written: $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $readBack) {
        $result.Reason = 'the Setup hook was written but could not be read back'
        return $result
    }

    if ($readBack.CmdLine -ne $command) {
        $result.Reason = "CmdLine reads back as '$($readBack.CmdLine)' instead of '$command'"
        return $result
    }

    if ($readBack.SetupType -ne $script:SetupTypeRunCmdLine) {
        $result.Reason = "SetupType reads back as $($readBack.SetupType) instead of $($script:SetupTypeRunCmdLine)"
        return $result
    }

    $result.Applied = $true
    return $result
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
        # As in Set-OfflineSetupHook, the block reads from this scope because Invoke-WithHive
        # passes no arguments to it.
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

function Write-TempUserPayload {
    <#
    .SYNOPSIS
        Writes the batch file the guest runs at boot.

    .DESCRIPTION
        The payload does four things, in this order:

          1. Creates the account and puts it in the local Administrators and Remote Desktop Users
             groups, recording the exit code of each command.
          2. Writes those exit codes to a result file, which is how the rescue VM learns what
             happened inside a guest it cannot otherwise see.
          3. Resets the Setup hook, in the same form Repair-AzVMDisk.ps1 uses. Windows owns that
             value while it is in setup mode and puts it back until its own setup pass finishes, so
             this reset does not survive a guest that is stopped part way through and the rescue VM
             clears it afterwards. It is kept here because it is what makes the disk self-heal if it
             is ever booted normally without that step.
          4. Deletes itself, so the password does not remain in a readable file on the disk.

        Step 4 is why the payload is written by this script rather than reused: it is single use by
        design. The library's existing Group Policy based script leaves its command file, and the
        password in it, on the disk permanently. It is also the signal that the payload ran to the
        end, since it is the last line: if the file is still there, the run stopped early.

        The file is written as ASCII with CRLF because cmd.exe will not reliably parse a batch file
        saved as UTF-8 with a byte order mark.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
        Justification = 'The payload is a .cmd file that hands the password to net.exe, so it has to be plain text by the time it is written. The file deletes itself after it runs.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'The payload needs both values to build the net user command line.')]
    param(
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$GuestResultPath,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $result = [PSCustomObject]@{ Written = $false; Reason = $null }

    $parent = Split-Path -Path $PayloadPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        try { New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null }
        catch {
            $result.Reason = "the payload folder '$parent' could not be created: $($_.Exception.Message)"
            return $result
        }
    }

    $lines = @(
        '@echo off'
        'setlocal'
        'set RESULT=' + $GuestResultPath
        'net user "' + $UserName + '" "' + $Password + '" /add /y'
        'set RC_ADD=%ERRORLEVEL%'
        'net localgroup Administrators "' + $UserName + '" /add'
        'set RC_ADMIN=%ERRORLEVEL%'
        'net localgroup "Remote Desktop Users" "' + $UserName + '" /add'
        'set RC_RDP=%ERRORLEVEL%'
        'net user "' + $UserName + '" /active:yes'
        'set RC_ACTIVE=%ERRORLEVEL%'
        '> "%RESULT%" echo user=' + $UserName
        '>> "%RESULT%" echo add=%RC_ADD%'
        '>> "%RESULT%" echo admin=%RC_ADMIN%'
        '>> "%RESULT%" echo rdp=%RC_RDP%'
        '>> "%RESULT%" echo active=%RC_ACTIVE%'
        '>> "%RESULT%" echo done=1'
        'reg add "HKLM\SYSTEM\Setup" /v SetupType /t REG_DWORD /d 0 /f'
        'reg delete "HKLM\SYSTEM\Setup" /v CmdLine /f'
        'endlocal'
        'del /f /q "%~f0"'
    )

    try {
        $text = ($lines -join "`r`n") + "`r`n"
        [System.IO.File]::WriteAllText($PayloadPath, $text, [System.Text.Encoding]::ASCII)
    }
    catch {
        $result.Reason = "the payload could not be written to '$PayloadPath': $($_.Exception.Message)"
        return $result
    }

    if (-not (Test-Path -LiteralPath $PayloadPath)) {
        $result.Reason = "the payload was written to '$PayloadPath' but the file is not there"
        return $result
    }

    $written = (Get-Item -LiteralPath $PayloadPath).Length
    if ($written -le 0) {
        $result.Reason = "the payload at '$PayloadPath' is empty"
        return $result
    }

    $result.Written = $true
    return $result
}

function Read-TempUserResult {
    <#
    .SYNOPSIS
        Reads the result file the payload wrote inside the guest.

    .OUTPUTS
        PSCustomObject with Present, Complete, User, Codes and Reason. Complete is true only when
        the payload reached its final line, which distinguishes a payload that failed part way
        through from one that never ran.
    #>
    param([Parameter(Mandatory = $true)][string]$ResultPath)

    $result = [PSCustomObject]@{
        Present  = $false
        Complete = $false
        User     = $null
        Codes    = @{}
        Reason   = $null
    }

    if (-not (Test-Path -LiteralPath $ResultPath)) {
        $result.Reason = 'the payload did not leave a result file, so it did not run'
        return $result
    }

    $result.Present = $true

    try {
        $lines = @(Get-Content -LiteralPath $ResultPath -ErrorAction Stop)
    }
    catch {
        $result.Reason = "the result file could not be read: $($_.Exception.Message)"
        return $result
    }

    foreach ($line in $lines) {
        $text = "$line".Trim()
        if ($text -notmatch '^([A-Za-z]+)=(.*)$') { continue }
        $name = $Matches[1].ToLowerInvariant()
        $value = $Matches[2].Trim()

        if ($name -eq 'user') { $result.User = $value }
        else { $result.Codes[$name] = $value }
    }

    $result.Complete = ($result.Codes.ContainsKey('done') -and $result.Codes['done'] -eq '1')
    if (-not $result.Complete) {
        $result.Reason = 'the payload left a result file but did not reach its final line, so it failed part way through'
    }

    return $result
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, merging with anything a previous run recorded.

    .DESCRIPTION
        The manifest is the only record of the values that were on the disk before the hook was
        written. Overwriting it would discard a previous run's undo data, so existing fields are
        carried forward unless this run has something newer to say.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][hashtable]$Entry
    )

    $existing = $null
    if (Test-Path -LiteralPath $ManifestPath) {
        try { $existing = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json }
        catch { $existing = $null }
    }

    $merged = @{}
    if ($null -ne $existing) {
        foreach ($property in $existing.PSObject.Properties) { $merged[$property.Name] = $property.Value }
    }
    foreach ($key in $Entry.Keys) { $merged[$key] = $Entry[$key] }

    $parent = Split-Path -Path $ManifestPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }

    ($merged | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $ManifestPath -Encoding UTF8 -Force
}

function Read-RevertManifest {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

#########################################################################################################
# Main
#########################################################################################################

try {
    Log-Output "START: Running script $scriptName" | Tee-Object -FilePath $logFile -Append
    $scriptStartTime | Out-File -FilePath $logFile -Append

    Clear-OfflineRepairLog

    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if (-not $offline -or -not $offline.WindowsPath) {
        Log-Error 'No offline Windows installation was found on the attached disk.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $windowsPath = $offline.WindowsPath
    Log-Output "Offline Windows installation: $windowsPath" | Tee-Object -FilePath $logFile -Append

    $payloadPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:PayloadRelativePath
    $resultPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ResultRelativePath
    $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath

    # The guest sees its own Windows directory, which is not the drive letter it has on the rescue VM.
    $guestWindows = 'C:\Windows'
    $guestPayloadPath = "$guestWindows\$($script:PayloadRelativePath)"
    $guestResultPath = "$guestWindows\$($script:ResultRelativePath)"

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output 'REVERT: undoing the Setup hook and removing the payload.' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -ManifestPath $manifestPath
        if ($null -eq $manifest) {
            Log-Warning 'No revert manifest was found, so there is nothing recorded to undo.' | Tee-Object -FilePath $logFile -Append
        }

        $restoredCount = 0

        if ($null -ne $manifest -and $null -ne $manifest.PreviousSetupType) {
            $restore = Restore-OfflineSetupHook -WindowsPath $windowsPath `
                -SetupType ([int]$manifest.PreviousSetupType) `
                -CmdLine "$($manifest.PreviousCmdLine)"

            if ($restore.Restored) {
                Log-Output "Setup hook restored to SetupType=$([int]$manifest.PreviousSetupType)." | Tee-Object -FilePath $logFile -Append
                $restoredCount++
            }
            else {
                Log-Warning "The Setup hook could not be restored: $($restore.Reason)" | Tee-Object -FilePath $logFile -Append
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

        if ($null -ne $manifest -and $manifest.UserName) {
            $check = Test-OfflineLocalUser -WindowsPath $windowsPath -Name "$($manifest.UserName)"
            if ($check.Known -and $check.Exists) {
                Log-Warning "The account '$($manifest.UserName)' still exists on this disk. It is not deleted here, because deleting an account means editing the SAM hive by hand. Remove it from inside the VM with: net user `"$($manifest.UserName)`" /delete" | Tee-Object -FilePath $logFile -Append
            }
        }

        if (Test-Path -LiteralPath $manifestPath) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
        }

        Log-Output "REVERT COMPLETE: restored $restoredCount item(s)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Detect
    #####################################################################################################
    $findings = New-Object System.Collections.ArrayList

    $nameCheck = Test-TempUserName -Name $username
    if (-not $nameCheck.Valid) {
        Log-Error "The requested user name cannot be used: $($nameCheck.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $setupState = Get-OfflineSetupState -WindowsPath $windowsPath
    if (-not $setupState.Available) {
        Log-Error "The Setup hook cannot be used on this disk: $($setupState.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "SYSTEM\Setup\SetupType is $($setupState.SetupType)." | Tee-Object -FilePath $logFile -Append
    if (-not [string]::IsNullOrWhiteSpace($setupState.CmdLine)) {
        Log-Output "SYSTEM\Setup\CmdLine is '$($setupState.CmdLine)'." | Tee-Object -FilePath $logFile -Append
    }

    $userState = Test-OfflineLocalUser -WindowsPath $windowsPath -Name $username
    if ($userState.Known) {
        if ($userState.Exists) {
            [void]$findings.Add((New-Finding -Cause 'AccountAlreadyExists' -Item $username -Repairable $false `
                        -Message "A local account named '$username' already exists on this disk. Choose another name with -username, or reset that account's password instead of creating a new one."))
        }
        else {
            Log-Output "No local account named '$username' exists on this disk." | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Warning "The existing local accounts could not be listed: $($userState.Reason)" | Tee-Object -FilePath $logFile -Append
        Log-Warning 'The run continues, but a name collision cannot be ruled out in advance and will surface as a failed payload.' | Tee-Object -FilePath $logFile -Append
    }

    # A setup command that is already present and points at something real is a genuine servicing or
    # provisioning step. Overwriting it would destroy work the image is in the middle of.
    if ($setupState.SetupType -ne 0 -and -not [string]::IsNullOrWhiteSpace($setupState.CmdLine) -and
        $setupState.CmdLine -notlike "*$($script:PayloadRelativePath.Replace('\','*'))*") {
        [void]$findings.Add((New-Finding -Cause 'SetupHookInUse' -Item 'CmdLine' -Repairable $false `
                    -Message "SYSTEM\Setup is already in setup mode running '$($setupState.CmdLine)'. That is left alone, because overwriting it would discard a servicing or provisioning step this image is part way through. Let the VM finish that boot, or clear it with win-fix-logon-subsystem, then run this script again."))
    }

    $vmState = Get-NestedRepairVm
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if (-not $vmState.Found) {
        [void]$findings.Add((New-Finding -Cause 'NoNestedGuest' -Item 'ProblemVM' -Repairable $false `
                    -Message "There is no nested Hyper-V guest to boot this disk in: $($vmState.Reason). This repair needs one, because the account is created by the running guest rather than by editing SAM offline. Re-create the rescue VM with 'az vm repair create --enable-nested'."))
    }
    else {
        Log-Output "Nested guest '$($vmState.Name)' found, generation $($vmState.Generation), state $($vmState.State)." | Tee-Object -FilePath $logFile -Append
    }

    $blocking = @($findings | Where-Object { -not $_.Repairable })

    if ($findings.Count -eq 0) {
        Log-Output "DETECT: ready to create '$username' through the Setup hook." | Tee-Object -FilePath $logFile -Append
    }
    else {
        foreach ($finding in $findings) {
            $prefix = if ($finding.Repairable) { 'REPAIRABLE' } else { 'BLOCKING  ' }
            Log-Output "  [$prefix] $($finding.Cause): $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "DETECT: $($findings.Count) finding(s)." | Tee-Object -FilePath $logFile -Append
    }

    if ($isDetectOnly) {
        Log-Output 'DETECT ONLY: nothing was changed.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($blocking.Count -gt 0) {
        Log-Error 'Cannot continue while a blocking finding is present. Nothing was changed.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    #####################################################################################################
    # Repair
    #####################################################################################################
    $effectivePassword = $password
    $generated = $false
    if ([string]::IsNullOrWhiteSpace($effectivePassword)) {
        $effectivePassword = New-TempUserPassword
        $generated = $true
    }

    # A stale result file from an earlier run would be read as this run's outcome.
    if (Test-Path -LiteralPath $resultPath) {
        Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    }

    Log-Output "REPAIR: writing the payload to '$payloadPath'." | Tee-Object -FilePath $logFile -Append
    $payload = Write-TempUserPayload -PayloadPath $payloadPath -GuestResultPath $guestResultPath `
        -UserName $username -Password $effectivePassword

    if (-not $payload.Written) {
        Log-Error "The payload could not be written: $($payload.Reason)" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $hook = Set-OfflineSetupHook -WindowsPath $windowsPath -GuestPayloadPath $guestPayloadPath
    if (-not $hook.Applied) {
        Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
        Log-Error "The Setup hook could not be applied: $($hook.Reason)" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "Setup hook applied: SetupType=$($script:SetupTypeRunCmdLine), CmdLine runs the payload." | Tee-Object -FilePath $logFile -Append

    Write-RevertManifest -ManifestPath $manifestPath -Entry @{
        UserName          = $username
        PreviousSetupType = $hook.PreviousSetupType
        PreviousCmdLine   = $hook.PreviousCmdLine
        PayloadPath       = $payloadPath
        AppliedUtc        = (Get-Date).ToUniversalTime().ToString('o')
    }

    #####################################################################################################
    # Boot the guest so the payload runs
    #####################################################################################################
    Log-Output "BOOT: starting nested guest '$($vmState.Name)' so the payload runs." | Tee-Object -FilePath $logFile -Append

    $diskNumbers = @()
    if ($null -ne $offline.DiskNumber) { $diskNumbers = @([int]$offline.DiskNumber) }

    $start = Start-NestedRepairVm -Vm $vmState.Vm -DiskNumber $diskNumbers
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if (-not $start.Started) {
        Log-Error "The nested guest did not start: $($start.Reason)" | Tee-Object -FilePath $logFile -Append
        Log-Error 'The Setup hook is still in place. Re-run with -revert true to undo it.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $boot = Wait-NestedRepairVmBoot -Vm $vmState.Vm -TimeoutSeconds $bootTimeoutSeconds
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($boot.Booted) {
        Log-Output "The guest booted after $($boot.WaitedSeconds) seconds. Allowing the payload to finish." | Tee-Object -FilePath $logFile -Append
        # The heartbeat arrives when the OS is up. The payload runs before the logon UI, so it has
        # usually already completed by this point, but a slow guest is given a little longer.
        Start-Sleep -Seconds 30
    }
    else {
        Log-Warning "The guest did not report a heartbeat: $($boot.Reason)" | Tee-Object -FilePath $logFile -Append
        Log-Warning 'The result is read back anyway, because a guest can run the payload without Integration Services reporting.' | Tee-Object -FilePath $logFile -Append
    }

    #####################################################################################################
    # Verify
    #####################################################################################################
    Log-Output 'VERIFY: taking the disk back to read the result.' | Tee-Object -FilePath $logFile -Append

    # The guest is asked to shut down rather than switched off. The payload clears the Setup hook by
    # writing to the registry, and that write lives in a loaded hive until Windows flushes it, which
    # it always does on an orderly shutdown. Pulling the power instead throws that write away while
    # keeping the files the payload wrote, so the run looks successful and the hook is still armed.
    $graceful = Stop-NestedRepairVmGraceful -Vm $vmState.Vm
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if (-not $graceful.Graceful) {
        Log-Warning "The guest did not shut down cleanly: $($graceful.Reason). The Setup hook is re-checked below and repaired from here if the payload's own reset was lost." | Tee-Object -FilePath $logFile -Append
    }

    $null = Stop-NestedRepairVm
    $null = Set-OfflineDisksOnline
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # The drive letters are re-resolved because the disk went away and came back.
    $offlineAfter = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($offlineAfter -and $offlineAfter.WindowsPath) {
        $windowsPath = $offlineAfter.WindowsPath
        $resultPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ResultRelativePath
        $payloadPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:PayloadRelativePath
        $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath
    }

    $payloadResult = Read-TempUserResult -ResultPath $resultPath
    $samCheck = Test-OfflineLocalUser -WindowsPath $windowsPath -Name $username

    $payloadSaysCreated = ($payloadResult.Complete -and $payloadResult.Codes['add'] -eq '0')
    $samSaysCreated = ($samCheck.Known -and $samCheck.Exists)

    if ($payloadResult.Present) {
        Log-Output "The payload reported: add=$($payloadResult.Codes['add']), admin=$($payloadResult.Codes['admin']), rdp=$($payloadResult.Codes['rdp']), active=$($payloadResult.Codes['active'])." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning $payloadResult.Reason | Tee-Object -FilePath $logFile -Append
    }

    if ($samCheck.Known) {
        Log-Output "The offline SAM $(if ($samSaysCreated) { 'contains' } else { 'does not contain' }) an account named '$username'." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Warning "The offline SAM could not confirm the account: $($samCheck.Reason)" | Tee-Object -FilePath $logFile -Append
    }

    # The payload deletes itself, so it being gone is a signal that it ran to completion.
    if (Test-Path -LiteralPath $payloadPath) {
        Log-Warning 'The payload is still on the disk, which means it did not run to completion. Removing it now so the password is not left in a file.' | Tee-Object -FilePath $logFile -Append
        Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $resultPath) {
        Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    }

    if (-not $payloadSaysCreated -and -not $samSaysCreated) {
        Log-Error "FAILED: neither the payload result nor the offline SAM confirms that '$username' was created." | Tee-Object -FilePath $logFile -Append
        Log-Error 'The Setup hook has been left in place so the guest can be booted again, or re-run with -revert true to undo it.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # Windows owns SYSTEM\Setup\SetupType while it is in setup mode and keeps rewriting it until its
    # setup pass completes. That pass cannot complete in a guest that is deliberately shut down part
    # way through, so the value is normally still 2 here even though the payload did reset it. The
    # payload keeps its own reset anyway, because it is what makes the disk self-heal if it is ever
    # booted normally without this step. Clearing it from the rescue VM is the expected finish, not
    # a sign that anything went wrong, so it is only reported as a problem when the write fails.
    $setupAfter = Get-OfflineSetupState -WindowsPath $windowsPath
    if ($setupAfter.Available -and $setupAfter.SetupType -ne 0) {
        Log-Output 'FINALIZE: clearing the Setup hook from here, because Windows re-arms it until a setup pass it was not allowed to finish completes.' | Tee-Object -FilePath $logFile -Append
        $restore = Restore-OfflineSetupHook -WindowsPath $windowsPath -SetupType $hook.PreviousSetupType -CmdLine $hook.PreviousCmdLine

        $setupFinal = Get-OfflineSetupState -WindowsPath $windowsPath
        if ((-not $restore.Restored) -or ($setupFinal.Available -and $setupFinal.SetupType -ne 0)) {
            Log-Warning "The Setup hook could not be cleared: $($restore.Reason)" | Tee-Object -FilePath $logFile -Append
            Log-Warning "SetupType is still $($setupFinal.SetupType), so this VM would boot into setup mode. Re-run with -revert true before restoring the disk." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'The Setup hook is cleared, so the VM will boot normally.' | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Output 'The Setup hook is already clear, so the VM will boot normally.' | Tee-Object -FilePath $logFile -Append
    }

    if (Test-Path -LiteralPath $manifestPath) {
        Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
    }

    Log-Output '' | Tee-Object -FilePath $logFile -Append
    Log-Output "SUCCESS: '$username' was created and confirmed$(if ($payloadSaysCreated -and $samSaysCreated) { ' by both the payload result and the offline SAM' } elseif ($samSaysCreated) { ' by the offline SAM' } else { ' by the payload result' })." | Tee-Object -FilePath $logFile -Append

    if ($payloadResult.Complete -and $payloadResult.Codes['admin'] -ne '0') {
        Log-Warning "Adding '$username' to the local Administrators group returned $($payloadResult.Codes['admin']), so the account may not be an administrator." | Tee-Object -FilePath $logFile -Append
    }

    # Printed, never logged. This is the only route the password has to the engineer.
    Log-Output '' | Tee-Object -FilePath $logFile -Append
    Log-Output "  User name: $username"
    if ($generated) {
        Log-Output "  Password:  $effectivePassword"
        Log-Output '  This password was generated for this run and is not written to the log file. Copy it now.'
    }
    else {
        Log-Output '  Password:  the value passed to -password.'
    }
    Log-Output ''

    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM, then sign in with that account." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
