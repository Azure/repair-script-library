#########################################################################################################
#
# .SYNOPSIS
#   Repairs the logon subsystem of an offline Windows disk: Winlogon, Session Manager, the profile
#   list and the setup-mode command.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". Every value the
#   logon path depends on is checked against the binary it actually points at, only the entries that
#   are provably broken are changed, and the result is re-checked. A healthy disk produces no writes.
#
#   Detection, in boot order:
#     1. Session Manager SubSystems\Windows. Smss.exe starts the Windows subsystem from the first
#        executable in this value. A missing, zero-byte or untrusted image terminates the initial
#        session process with 0xC000021A. When LastKnownGood names a different, valid Microsoft
#        image, its exact REG_EXPAND_SZ value is copied to the active control set.
#     2. Session Manager BootExecute. Smss.exe runs these native images before Win32 starts. An
#        entry whose binary is missing hangs the VM at a black screen with no error, because there
#        is no subsystem loaded yet to report one. The Windows default "autocheck autochk *" is
#        always kept, and its absence is itself reported.
#     3. Session Manager SetupExecute. Same execution context, normally empty.
#     4. Setup mode. A non-zero SYSTEM\Setup\SetupType makes the session manager run
#        SYSTEM\Setup\CmdLine before the logon UI appears. A dangling command there stalls the boot,
#        and it is a common leftover from an earlier repair attempt, because that key is the hook
#        password-reset and user-rights tools use.
#     5. Winlogon Shell and Userinit. Both are comma separated lists of commands. An entry whose
#        binary is missing produces 0xC000021A, because Winlogon treats the failure to start
#        userinit.exe as a critical system process failure.
#     6. ProfileList. A SID carrying a .bak twin, or the temporary-profile bit in State, is the
#        "We can't sign in to your account" / "User Profile Service failed the logon" pattern.
#     7. RPC hosting. RpcSs and RpcEptMapper are both -k rpcss services, so Windows starts them in
#        one shared svchost process. Svchost groups services by their exact command line, so if
#        RpcEptMapper's ImagePath stops being character-for-character what RpcSs has, the endpoint
#        mapper lands in a process of its own. Local RPC and COM interface resolution then fails,
#        and DWM and LogonUI crash and restart in a loop with no desktop ever appearing.
#
#   Repair changes only what detection found. Dangling list entries are dropped individually, the
#   surviving entries are preserved in order, and the Windows default is written back only when
#   removing the broken entries would otherwise leave the value empty. A customised shell or an
#   extra Userinit command whose binary is present is reported and deliberately left alone.
#
#   Every executable named by these values is checked for existence, non-zero length, SHA-256
#   readability and signature state. Required Windows binaries must resolve to a trusted Microsoft
#   image. Optional third-party commands are never deleted merely because they are unsigned; they
#   are reported for operator review.
#
# .RESOLVES
#   Stop error 0xC000021A STATUS_SYSTEM_PROCESS_TERMINATED, a black screen before the logon UI,
#   "The User Profile Service service failed the sign-in", "We can't sign in to your account" and
#   logons that land in a temporary profile, a VM that hangs on "Please wait" or re-enters setup
#   on every boot, and a logon screen that never paints because DWM and LogonUI crash in a loop
#   after the RPC endpoint mapper was split out of the shared RPC host process.
#
# .PARAMETER detectOnly
#   "true" to report what would be changed and make no writes at all. Defaults to "false".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-logon-subsystem --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-logon-subsystem --parameters detectOnly=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The Windows default for Userinit is written using the guest's own SystemRoot, read from
#   SOFTWARE\Microsoft\Windows NT\CurrentVersion, rather than a hardcoded C:\Windows. A guest whose
#   Windows directory is not on C: would otherwise be given a value that cannot resolve at boot.
#
#   A hive that will not load at all is a different problem and belongs to
#   win-fix-registry-corruption. This script needs SYSTEM and SOFTWARE to mount before it can read
#   anything, so run that one first if either hive is damaged.
#
#   SubSystems\Windows is restored only from Select\LastKnownGood, and only when that control set is
#   different from Current, carries a REG_EXPAND_SZ value, and its first executable is a non-zero,
#   hash-readable Microsoft image. No default command line is invented.
#
#   ExcludeFromKnownDlls entries are reported and never removed. Legitimate application compatibility
#   shims use them, so removing them blindly can break working software, but they are also a DLL
#   preloading vector and worth an operator's attention.
#
#   A ProfileImagePath pointing at a directory that no longer exists is reported and not repaired.
#   Deleting the profile entry would let the user log on with a brand new profile and silently
#   abandon the old one, which is a data loss decision an operator has to make deliberately.
#
#   Autoruns under Run, RunOnce and the Startup folders are deliberately out of scope. They are
#   started by userinit.exe and the shell after a successful logon, so they cannot stop a boot, and a
#   VM affected by one is still reachable online where it can be fixed without a disk swap.
#
#   The RPC hosting repair only ever copies RpcSs's own ImagePath onto RpcEptMapper, and only when
#   everything else about both services is still stock: shared-process type, automatic start, the
#   NetworkService account, the COM Infrastructure group, RpcSs holding a REG_EXPAND_SZ
#   %SystemRoot%\system32\svchost.exe -k rpcss command, and RpcEptMapper already naming that same
#   executable and arguments including the -p protection flag when present. Anything else is
#   reported and left alone, because a genuinely customised RPC configuration is not this script's
#   to overwrite. No command line is invented.
#
# .VERSION
#   v1.2: Detect and repair an RpcEptMapper ImagePath that no longer shares the RpcSs svchost host.
#   v1.1: Validate every resolved executable and repair SubSystems\Windows from LastKnownGood.
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
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

# The only BootExecute entry Windows ships with. Restored when removing dangling entries would
# otherwise leave the value empty, because an empty BootExecute means autochk never runs and a dirty
# volume is then mounted without being checked.
$script:DefaultBootExecute = 'autocheck autochk *'

# Winlogon values are comma separated lists. Each list has one binary that must be present for the
# logon to complete; everything else in the list is optional and is preserved when it resolves.
$script:WinlogonValueSpec = @(
    [PSCustomObject]@{
        Name          = 'Userinit'
        Required      = 'userinit.exe'
        TrailingComma = $true
        Purpose       = 'starts the user session, applies the profile and launches the shell'
    }
    [PSCustomObject]@{
        Name          = 'Shell'
        Required      = 'explorer.exe'
        TrailingComma = $false
        Purpose       = 'the desktop shell userinit.exe launches'
    }
)

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    # This only builds an object in memory and touches nothing on the disk, so ShouldProcess would
    # add a prompt with no console to answer it. Suppressed rather than implemented on purpose.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
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
        Repairable = $Repairable
        Repaired   = $false
        Data       = $Data
    }
}

function Resolve-LogonCommand {
    <#
    .SYNOPSIS
        Resolves one command from a logon value to a file on the offline disk.

    .DESCRIPTION
        The values this script reads hold commands, not plain paths: they can carry arguments, be
        quoted, use the guest's drive letter, or name a bare executable that the loader finds on the
        system path. Only the program part is resolved, and it is looked for in System32 and in the
        Windows directory, which is where every binary these values legitimately reference lives.

        Existence is decided against the offline disk, so a value naming a binary the guest no longer
        has is correctly reported as dangling even though the string itself looks valid.

    .OUTPUTS
        PSCustomObject with Command, Binary, Resolved, Exists and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Command,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $result = [PSCustomObject]@{
        Command         = $Command
        Binary          = $null
        Resolved        = $null
        Present         = $false
        Exists          = $false
        Length          = [int64]0
        SHA256          = ''
        SignatureStatus = 'FileNotFound'
        IsSigned        = $false
        IsMicrosoft     = $false
        IsLikelyMicrosoft = $false
        HashUnreadable  = $false
        MetadataUnreadable = $false
        Reason          = $null
    }

    $text = "$Command".Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        $result.Reason = 'the entry is empty'
        return $result
    }

    # A quoted program keeps its spaces; an unquoted one ends at the first space.
    if ($text.StartsWith('"')) {
        $close = $text.IndexOf('"', 1)
        $binary = if ($close -gt 1) { $text.Substring(1, $close - 1) } else { $text.Trim('"') }
    }
    else {
        $binary = ($text -split '\s+', 2)[0]
    }

    $binary = $binary.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($binary)) {
        $result.Reason = 'no program name could be read from the entry'
        return $result
    }
    $result.Binary = $binary

    # A wildcard is an argument to the preceding program, never a program itself.
    if ($binary -eq '*') {
        $result.Reason = 'the entry is an argument, not a program'
        return $result
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($binary -match '[\\/]' -or $binary -match '^[A-Za-z]:' -or $binary -match '^%') {
        $imagePath = $binary
        if ($imagePath -match '(?i)^%SystemRoot%(?:\\|$)') {
            $imagePath = $WindowsPath + $imagePath.Substring(('%SystemRoot%').Length)
        }
        elseif ($imagePath -match '(?i)^\\SystemRoot(?:\\|$)') {
            $imagePath = $WindowsPath + $imagePath.Substring(('\SystemRoot').Length)
        }
        elseif ($imagePath -match '(?i)^%windir%(?:\\|$)') {
            $imagePath = $WindowsPath + $imagePath.Substring(('%windir%').Length)
        }
        [void]$candidates.Add((Resolve-OfflineImagePath -ImagePath $imagePath -WindowsDrive $WindowsDrive))
    }
    else {
        $names = if ([System.IO.Path]::GetExtension($binary)) { @($binary) } else { @("$binary.exe", "$binary.com") }
        foreach ($name in $names) {
            [void]$candidates.Add((Join-OfflinePath -Root $WindowsPath -ChildPath "System32\$name"))
            [void]$candidates.Add((Join-OfflinePath -Root $WindowsPath -ChildPath $name))
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $signature = Test-OfflineFileSignature -FilePath $candidate
        if ($signature.Status -eq 'FileNotFound') { continue }

        $item = $null
        $metadataUnreadable = $false
        try { $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { $item = $null }
        catch {
            # -ErrorAction SilentlyContinue here used to return $null for ANY failure, so a file
            # that is present but locked, ACL-denied or on a failing sector was reported as "the
            # path is not a file" - and that reason drives four repairable causes that DELETE the
            # entry from BootExecute, SetupExecute, Userinit or Shell, or clear SetupType. A failed
            # read must not become authority for a write. Only ItemNotFoundException above is proof
            # the file is absent; everything else is an unknown and is reported as one.
            $metadataUnreadable = $true
        }

        $result.Resolved = $candidate
        $result.MetadataUnreadable = $metadataUnreadable
        $result.Present = ($null -ne $item -and -not $item.PSIsContainer)
        $result.Length = if ($result.Present) { [int64]$item.Length } else { [int64]0 }
        $result.SignatureStatus = $signature.Status
        $result.IsSigned = $signature.IsSigned
        $result.IsMicrosoft = $signature.IsMicrosoft
        $result.IsLikelyMicrosoft = $signature.IsLikelyMicrosoft

        if ($metadataUnreadable) {
            $result.Reason = "the file is there but could not be read, so whether it can start could not be established: $candidate"
            return $result
        }
        if (-not $result.Present) {
            $result.Reason = "the path is not a file: $candidate"
            return $result
        }
        if ($signature.Status -eq 'ZeroByte' -or $result.Length -eq 0) {
            $result.Reason = "the binary is 0 bytes: $candidate"
            return $result
        }

        try {
            $result.SHA256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            # A hash that cannot be READ is not evidence that the binary is bad. Without this flag
            # the empty SHA256 below fails Test-ResolutionIntegrity exactly as a corrupt binary
            # would, and for SubSystems\Windows that failure authorises overwriting the live value
            # from LastKnownGood - a write driven by an I/O error on a healthy csrss.exe.
            $result.HashUnreadable = $true
            $result.Reason = "the binary exists but its SHA-256 could not be read: $candidate"
        }

        # Exists means the command can at least be started. Signature and hash trust are tracked
        # separately so an unsigned third-party command is reported rather than silently removed.
        $result.Exists = $true
        return $result
    }

    $result.Resolved = $candidates[0]
    $result.Reason = "the binary was not found on the offline disk (looked for $($candidates -join ', '))"
    return $result
}

function Test-ResolutionIntegrity {
    <#
    .SYNOPSIS
        Tests the evidence gathered for one resolved executable.

    .DESCRIPTION
        All commands need a non-zero file and a readable SHA-256. Required Windows executables also
        have to be identified as Microsoft by Test-OfflineFileSignature. Optional third-party
        commands need a valid signature to pass this check, but a failed check is report-only.

        The Microsoft test uses IsLikelyMicrosoft rather than IsMicrosoft, because the status
        gate on the line above has already excluded everything Authenticode rejected. What
        remains is either cryptographically valid or catalog signed, and a catalog signed
        inbox binary cannot be proven from the rescue VM: the catalogs that would verify
        winlogon.exe and lsass.exe live on the offline image and are not registered here.
        Requiring cryptographic proof at this point would reject every healthy offline
        binary and make the scenario refuse to repair anything.
    #>
    param(
        [Parameter(Mandatory = $false)]$Resolution,
        [Parameter(Mandatory = $false)][switch]$RequireMicrosoft
    )

    if ($null -eq $Resolution -or -not $Resolution.Exists) { return $false }
    if ($Resolution.Length -le 0 -or "$($Resolution.SHA256)" -notmatch '^[A-Fa-f0-9]{64}$') { return $false }
    if ($Resolution.SignatureStatus -notin @('Valid', 'CatalogSigned')) { return $false }
    if ($RequireMicrosoft) { return [bool]$Resolution.IsLikelyMicrosoft }
    return [bool]($Resolution.IsSigned -or $Resolution.SignatureStatus -eq 'CatalogSigned')
}

function Get-WindowsSubsystemValueState {
    <#
    .SYNOPSIS
        Reads SubSystems\Windows without expanding REG_EXPAND_SZ and validates its first executable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ControlSet,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $subKeyPath = "BROKENSYSTEM\$ControlSet\Control\Session Manager\SubSystems"
    $state = [PSCustomObject]@{
        ControlSet = $ControlSet
        KeyPath    = "HKLM:\$subKeyPath"
        KeyPresent = $false
        Present    = $false
        ValueKind  = ''
        Raw         = ''
        Resolution  = $null
    }

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath)
    if ($null -eq $key) { return $state }

    try {
        $state.KeyPresent = $true
        if ($key.GetValueNames() -notcontains 'Windows') { return $state }

        $state.Present = $true
        $state.ValueKind = $key.GetValueKind('Windows').ToString()
        $raw = $key.GetValue(
            'Windows',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($raw -is [string]) {
            $state.Raw = [string]$raw
            $state.Resolution = Resolve-LogonCommand `
                -Command $state.Raw `
                -WindowsPath $WindowsPath `
                -WindowsDrive $WindowsDrive
        }
    }
    finally {
        $key.Close()
    }

    return $state
}

function Get-GuestSystemRoot {
    <#
    .SYNOPSIS
        Returns the guest's own view of its Windows directory, for example "C:\Windows".

    .DESCRIPTION
        Needed because a repaired value is read by the guest at its next boot, where the offline
        drive letter this rescue VM sees is meaningless. Falls back to C:\Windows only when the
        value is absent, which is the same assumption Windows setup makes.
    #>
    $current = Get-ItemProperty 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    foreach ($value in @($current.SystemRoot, $current.PathName)) {
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -match '^[A-Za-z]:\\') { return $value.TrimEnd('\') }
    }
    return 'C:\Windows'
}

function Get-WinlogonState {
    <#
    .SYNOPSIS
        Reads Winlogon Shell and Userinit and resolves every command in each of them.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $state = [PSCustomObject]@{
        KeyPath        = $keyPath
        Available      = $false
        Reason         = $null
        GuestSystemRoot = Get-GuestSystemRoot
        Values         = @()
    }

    if (-not (Test-Path $keyPath)) {
        $state.Reason = "the Winlogon key is not present at $keyPath"
        return $state
    }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    $values = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in $script:WinlogonValueSpec) {
        $raw = $props.$($spec.Name)
        $entries = @()
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $entries = @("$raw" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        $resolutions = @($entries | ForEach-Object {
                Resolve-LogonCommand -Command $_ -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
            })

        $requiredResolution = @($resolutions | Where-Object {
                $_.Exists -and (Split-Path -Path $_.Resolved -Leaf) -ieq $spec.Required
            } | Select-Object -First 1)

        $default = if ($spec.Name -eq 'Userinit') { "$($state.GuestSystemRoot)\system32\userinit.exe" } else { 'explorer.exe' }
        $defaultResolution = Resolve-LogonCommand `
            -Command $default `
            -WindowsPath $WindowsPath `
            -WindowsDrive $WindowsDrive

        [void]$values.Add([PSCustomObject]@{
                Name          = $spec.Name
                Purpose       = $spec.Purpose
                Required      = $spec.Required
                TrailingComma = $spec.TrailingComma
                Present       = ($null -ne $raw)
                Raw           = "$raw"
                Resolutions   = $resolutions
                Dangling      = @($resolutions | Where-Object { -not $_.Exists -and -not $_.MetadataUnreadable })
                Unreadable    = @($resolutions | Where-Object { $_.MetadataUnreadable })
                Good          = @($resolutions | Where-Object { $_.Exists })
                HasRequired   = ($requiredResolution.Count -gt 0)
                RequiredResolution = if ($requiredResolution.Count -gt 0) { $requiredResolution[0] } else { $null }
                RequiredIntegrityOk = if ($requiredResolution.Count -gt 0) {
                    Test-ResolutionIntegrity -Resolution $requiredResolution[0] -RequireMicrosoft
                }
                else {
                    $false
                }
                Default       = $default
                DefaultResolution = $defaultResolution
                DefaultIntegrityOk = Test-ResolutionIntegrity -Resolution $defaultResolution -RequireMicrosoft
            })
    }

    $state.Values = @($values)
    return $state
}

function Get-SessionManagerState {
    <#
    .SYNOPSIS
        Reads the Session Manager lists that run before Win32 starts and resolves each entry.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = "$SystemRoot\Control\Session Manager"
    $controlSet = Split-Path -Path $SystemRoot -Leaf
    $lastKnownGoodControlSet = Get-OfflineSelectedControlSetName -Name LastKnownGood

    $state = [PSCustomObject]@{
        KeyPath              = $keyPath
        ControlSet           = $controlSet
        Available            = $false
        Reason               = $null
        WindowsSubsystem     = Get-WindowsSubsystemValueState `
            -ControlSet $controlSet `
            -WindowsPath $WindowsPath `
            -WindowsDrive $WindowsDrive
        LastKnownGoodControlSet = $lastKnownGoodControlSet
        LastKnownGoodIsDistinct = (
            -not [string]::IsNullOrWhiteSpace($lastKnownGoodControlSet) -and
            $lastKnownGoodControlSet -ne $controlSet)
        LastKnownGoodWindowsSubsystem = $null
        BootExecute          = @()
        BootExecutePresent   = $false
        DefaultBootExecuteResolution = Resolve-LogonCommand `
            -Command 'autochk.exe' `
            -WindowsPath $WindowsPath `
            -WindowsDrive $WindowsDrive
        SetupExecute         = @()
        ExcludeFromKnownDlls = @()
    }

    if ($state.LastKnownGoodIsDistinct) {
        $state.LastKnownGoodWindowsSubsystem = Get-WindowsSubsystemValueState `
            -ControlSet $lastKnownGoodControlSet `
            -WindowsPath $WindowsPath `
            -WindowsDrive $WindowsDrive
    }

    if (-not (Test-Path $keyPath)) {
        $state.Reason = "the Session Manager key is not present at $keyPath"
        return $state
    }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    $state.BootExecutePresent = ($null -ne $props.BootExecute)

    foreach ($valueName in @('BootExecute', 'SetupExecute')) {
        $entries = @($props.$valueName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
        $resolved = foreach ($entry in $entries) {
            # "autocheck autochk *" is the default. Its program is the second token, because
            # autocheck is the native subsystem prefix rather than an image name.
            $isDefault = ($entry -match '^autocheck\s+autochk\b')
            $program = if ($entry -match '^autocheck\s+(\S+)') { $Matches[1] } else { $entry }

            $resolution = Resolve-LogonCommand -Command $program -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
            [PSCustomObject]@{
                Entry      = $entry
                IsDefault  = $isDefault
                Resolution = $resolution
                Exists     = $resolution.Exists
                Unreadable = $resolution.MetadataUnreadable
                Vendor     = if ($resolution.Exists) { (Get-Item -LiteralPath $resolution.Resolved -ErrorAction SilentlyContinue).VersionInfo.CompanyName } else { $null }
            }
        }
        $state.$valueName = @($resolved)
    }

    $state.ExcludeFromKnownDlls = @($props.ExcludeFromKnownDlls | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    return $state
}

function Get-SetupModeState {
    <#
    .SYNOPSIS
        Reads the setup-mode hook that runs before the logon UI appears.

    .DESCRIPTION
        A non-zero SetupType makes the session manager run CmdLine in a SYSTEM console session
        before anyone can log on. It is the hook that offline password-reset and user-rights tools
        use, so a leftover entry from an earlier repair attempt is a realistic cause of a VM that
        never reaches the logon screen.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = 'HKLM:\BROKENSYSTEM\Setup'
    $state = [PSCustomObject]@{
        KeyPath             = $keyPath
        Available           = $false
        SetupType           = 0
        CmdLine             = ''
        SystemSetupInProgress = 0
        Resolution          = $null
    }

    if (-not (Test-Path $keyPath)) { return $state }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    if ($null -ne $props.SetupType) { $state.SetupType = [int]$props.SetupType }
    if ($null -ne $props.SystemSetupInProgress) { $state.SystemSetupInProgress = [int]$props.SystemSetupInProgress }
    $state.CmdLine = "$($props.CmdLine)".Trim()

    if (-not [string]::IsNullOrWhiteSpace($state.CmdLine)) {
        $state.Resolution = Resolve-LogonCommand -Command $state.CmdLine -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
    }

    return $state
}

function Get-ProfileListState {
    <#
    .SYNOPSIS
        Reads the machine profile list and flags the entries that stop a user logging on.

    .DESCRIPTION
        Three separate conditions are reported. A SID with a .bak twin means the profile service
        failed to load the real profile and created a replacement, which is what produces "We can't
        sign in to your account". The temporary-profile bit in State is the same failure recorded on
        a single key. A ProfileImagePath pointing at a directory that is gone is reported only,
        because choosing to abandon a profile is an operator's decision.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $basePath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $state = [PSCustomObject]@{
        KeyPath   = $basePath
        Available = $false
        Reason    = $null
        Profiles  = @()
    }

    if (-not (Test-Path $basePath)) {
        $state.Reason = "the ProfileList key is not present at $basePath"
        return $state
    }
    $state.Available = $true

    $profiles = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($key in @(Get-ChildItem $basePath -ErrorAction SilentlyContinue)) {
        $name = $key.PSChildName

        # Only real user accounts. Built-in service SIDs never carry these faults and their
        # profiles are recreated by Windows, so acting on them adds risk without benefit.
        if ($name -notmatch '^S-1-5-21-') { continue }
        # Handle each SID once, from its primary key.
        if ($name -match '\.(bak|old)$') { continue }

        $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        $bakPath = "$basePath\$name.bak"
        $hasBak = Test-Path $bakPath
        $bakProps = if ($hasBak) { Get-ItemProperty $bakPath -ErrorAction SilentlyContinue } else { $null }

        # Resolve-OfflineImagePath is for binaries and trims its result at the file extension, so a
        # profile directory is translated here instead: swap the guest's drive letter for the one
        # this rescue VM mounted the disk on.
        $guestPath = "$($props.ProfileImagePath)"
        $offlinePath = $null
        if ($guestPath -match '^[A-Za-z]:\\(.*)$') {
            $offlinePath = Join-OfflinePath -Root $WindowsDrive -ChildPath $Matches[1]
        }

        $profileState = if ($null -ne $props.State) { [int]$props.State } else { 0 }
        [void]$profiles.Add([PSCustomObject]@{
                Sid                = $name
                KeyPath            = "$basePath\$name"
                BakKeyPath         = $bakPath
                HasBak             = $hasBak
                State              = $profileState
                IsTemporary        = (($profileState -band 0x8) -ne 0)
                RefCount           = $props.RefCount
                GuestProfilePath   = $guestPath
                OfflineProfilePath = $offlinePath
                ProfileExists      = ($null -ne $offlinePath -and (Test-OfflinePath $offlinePath))
                BakProfilePath     = if ($null -ne $bakProps) { "$($bakProps.ProfileImagePath)" } else { $null }
            })
    }

    $state.Profiles = @($profiles)
    return $state
}

function Get-RpcHostingState {
    <#
    .SYNOPSIS
        Reads the RpcSs and RpcEptMapper command lines and reports whether they still share a host.

    .DESCRIPTION
        svchost groups services by the exact command line it is launched with, not by the -k tag
        alone. So if RpcEptMapper's ImagePath stops being character-for-character what RpcSs has -
        typically by being rewritten with a quoted, fully expanded path such as
        "C:\Windows\system32\svchost.exe" -k rpcss - the two services land in separate processes.
        The endpoint mapper then lives outside the RPC service's process, local RPC and COM
        interface resolution stops working, and the visible result is DWM and LogonUI failing and
        restarting in a loop with no desktop ever appearing.

        The comparison is made after expanding the guest's own environment variables, because
        %SystemRoot%\system32\svchost.exe and C:\Windows\system32\svchost.exe name the same file but
        are not the same command line. Quotes and spacing are deliberately preserved: normalising
        them away would hide the exact difference that causes the split.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$GuestSystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $controlSet = Split-Path -Path $SystemRoot -Leaf
    $state = [PSCustomObject]@{
        ControlSet   = $controlSet
        Available    = $false
        Reason       = $null
        RpcSs        = $null
        RpcEptMapper = $null
        HasMismatch  = $false
        CanRepair    = $false
    }

    foreach ($name in @('RpcSs', 'RpcEptMapper')) {
        $subKeyPath = "BROKENSYSTEM\$controlSet\Services\$name"
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath)
        if ($null -eq $key) {
            $state.Reason = "the $name service key is not present at HKLM:\$subKeyPath"
            return $state
        }
        try {
            $raw = $key.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($raw -isnot [string] -or [string]::IsNullOrWhiteSpace($raw)) {
                $state.Reason = "$name has no usable ImagePath value"
                return $state
            }
            $state.$name = [PSCustomObject]@{
                Name       = $name
                KeyPath    = "HKLM:\$subKeyPath"
                ImagePath  = $raw
                ValueKind  = $key.GetValueKind('ImagePath').ToString()
                Effective  = ''
                Type       = $key.GetValue('Type', $null)
                Start      = $key.GetValue('Start', $null)
                ObjectName = $key.GetValue('ObjectName', $null)
                Group      = $key.GetValue('Group', $null)
            }
        }
        finally { $key.Close() }
    }
    $state.Available = $true

    # Expand with the guest's Windows directory, never this rescue VM's. The two disagree whenever
    # the offline disk is mounted on a different letter, and using the wrong one would invent a
    # mismatch that does not exist on the guest.
    $guestDrive = $GuestSystemRoot.Substring(0, 2)
    foreach ($service in @($state.RpcSs, $state.RpcEptMapper)) {
        $expanded = $service.ImagePath
        foreach ($pair in @(
                @{ Pattern = '(?i)%SystemRoot%'; Value = $GuestSystemRoot },
                @{ Pattern = '(?i)%windir%'; Value = $GuestSystemRoot },
                @{ Pattern = '(?i)%SystemDrive%'; Value = $guestDrive })) {
            $expanded = [regex]::Replace($expanded, $pair.Pattern, ($pair.Value -replace '\$', '$$$$'))
        }
        $service.Effective = $expanded
    }

    if (@($state.RpcSs, $state.RpcEptMapper | Where-Object { $_.Effective.Contains('%') }).Count -gt 0) {
        $state.Reason = 'an RPC ImagePath still contains an environment variable this script cannot resolve offline'
        return $state
    }

    $state.HasMismatch = -not [string]::Equals(
        $state.RpcSs.Effective, $state.RpcEptMapper.Effective, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $state.HasMismatch) {
        $state.Reason = 'both RPC services name the same command line, so they share one svchost host process'
        return $state
    }

    # Repair is copying RpcSs's value onto RpcEptMapper, so it is only safe when everything else
    # about both services is still stock. Anything customised is reported and left alone.
    foreach ($service in @($state.RpcSs, $state.RpcEptMapper)) {
        if ($service.ValueKind -ne 'ExpandString' -and $service.Name -eq 'RpcSs') {
            $state.Reason = 'RpcSs ImagePath is not REG_EXPAND_SZ, so it is not the stock value to copy from'
            return $state
        }
        if ($service.Type -ne 32 -or $service.Start -ne 2 -or
            $service.ObjectName -ine 'NT AUTHORITY\NetworkService' -or $service.Group -ine 'COM Infrastructure') {
            $state.Reason = 'automatic repair needs both RPC services to keep their stock shared-process type, automatic start, NetworkService account and COM Infrastructure group'
            return $state
        }
    }

    $reference = [regex]::Match($state.RpcSs.ImagePath, '(?i)^%SystemRoot%\\system32\\svchost\.exe(?<Args> -k rpcss(?: -p)?)$')
    $mapper = [regex]::Match($state.RpcEptMapper.Effective, '(?i)^(?:"(?<Exe>[^"]+)"|(?<Exe>[^\s"]+))(?<Args> -k rpcss(?: -p)?)$')
    if (-not $reference.Success -or -not $mapper.Success -or $GuestSystemRoot -match '\s' -or
        $mapper.Groups['Exe'].Value -ine "$GuestSystemRoot\system32\svchost.exe" -or
        $mapper.Groups['Args'].Value -ine $reference.Groups['Args'].Value) {
        # -p is the service-protection flag. Copying a value that drops it would silently lower the
        # protection level of a service that had it, so a difference there is never auto-repaired.
        $state.Reason = 'automatic repair needs RpcSs to hold the stock expandable svchost command and RpcEptMapper to name that same executable and arguments, including the -p protection flag when present'
        return $state
    }

    $svchost = Resolve-LogonCommand -Command $state.RpcSs.ImagePath -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
    if (-not $svchost.Exists -or $svchost.Length -eq 0) {
        $state.Reason = 'the svchost.exe the RPC services name is missing or empty on the offline disk'
        return $state
    }

    $state.CanRepair = $true
    $state.Reason = 'RpcEptMapper can be given the same command line RpcSs already has'
    return $state
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Builds the findings list from evidence only.

    .DESCRIPTION
        A value being non-default is never a finding on its own. A value only becomes one when the
        binary it names is missing from the offline disk, or when the value that has to be there to
        reach a desktop is not there at all. That keeps a customised but working configuration
        untouched, which matters because a blanket reset of these keys is itself a way to break a VM.
    #>
    param(
        [Parameter(Mandatory = $true)]$Winlogon,
        [Parameter(Mandatory = $true)]$SessionManager,
        [Parameter(Mandatory = $true)]$SetupMode,
        [Parameter(Mandatory = $true)]$ProfileList,
        [Parameter(Mandatory = $true)]$RpcHosting
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- Session Manager, runs first at boot ------------------------------------------------------
    if ($SessionManager.Available) {
        $subsystem = $SessionManager.WindowsSubsystem
        $subsystemKindUsable = (
            $subsystem.ValueKind -eq 'ExpandString' -or
            (
                $subsystem.ValueKind -eq 'String' -and
                $subsystem.Raw -notmatch '%[^%]+%'
            ))
        $subsystemUsable = (
            $subsystem.KeyPresent -and
            $subsystem.Present -and
            $subsystemKindUsable -and
            (Test-ResolutionIntegrity -Resolution $subsystem.Resolution -RequireMicrosoft))

        if (-not $subsystemUsable) {
            $lastKnownGood = $SessionManager.LastKnownGoodWindowsSubsystem
            $lastKnownGoodUsable = (
                $SessionManager.LastKnownGoodIsDistinct -and
                $null -ne $lastKnownGood -and
                $lastKnownGood.KeyPresent -and
                $lastKnownGood.Present -and
                $lastKnownGood.ValueKind -eq 'ExpandString' -and
                (Test-ResolutionIntegrity -Resolution $lastKnownGood.Resolution -RequireMicrosoft))

            $activeReason = if (-not $subsystem.KeyPresent) {
                "the key $($subsystem.KeyPath) is missing"
            }
            elseif (-not $subsystem.Present) {
                'the Windows value is missing'
            }
            elseif ($subsystem.ValueKind -notin @('String', 'ExpandString')) {
                "the Windows value has registry type $($subsystem.ValueKind), not a string type"
            }
            elseif ($subsystem.ValueKind -eq 'String' -and $subsystem.Raw -match '%[^%]+%') {
                'the Windows value is REG_SZ but contains an environment-variable token that Session Manager will not expand'
            }
            elseif ($null -eq $subsystem.Resolution) {
                'the Windows value does not contain a readable executable'
            }
            elseif (-not $subsystem.Resolution.Exists) {
                $subsystem.Resolution.Reason
            }
            elseif ("$($subsystem.Resolution.SHA256)" -notmatch '^[A-Fa-f0-9]{64}$') {
                "the executable could not be SHA-256 verified: $($subsystem.Resolution.Resolved)"
            }
            else {
                "the executable is not a trusted Microsoft image (signature status $($subsystem.Resolution.SignatureStatus)): $($subsystem.Resolution.Resolved)"
            }

            $replacementDiffers = (
                $lastKnownGoodUsable -and
                (
                    -not $subsystem.Present -or
                    $subsystem.ValueKind -ne 'ExpandString' -or
                    -not [string]::Equals(
                        $subsystem.Raw,
                        $lastKnownGood.Raw,
                        [System.StringComparison]::Ordinal)
                ))

            # Evidence that could not be READ is not evidence of a fault. When the only thing
            # against the active value is that its executable could not be hashed, or could not be
            # opened at all, the value may be perfectly correct and the disk perfectly healthy, so
            # this reports and changes nothing. Without this gate an I/O error on a healthy
            # csrss.exe overwrites the live value from LastKnownGood.
            $subsystemEvidenceUnreadable = (
                $null -ne $subsystem.Resolution -and
                ($subsystem.Resolution.HashUnreadable -or $subsystem.Resolution.MetadataUnreadable))

            if ($subsystem.KeyPresent -and $replacementDiffers -and -not $subsystemEvidenceUnreadable) {
                [void]$findings.Add((New-Finding -Cause 'WindowsSubsystemBroken' -Item 'SubSystems\Windows' -Hive 'SYSTEM' `
                            -Message "Session Manager SubSystems\Windows cannot start the Windows subsystem because $activeReason. LastKnownGood $($lastKnownGood.ControlSet) carries a REG_EXPAND_SZ value whose first executable is a non-zero, hash-readable Microsoft image at $($lastKnownGood.Resolution.Resolved). Its exact value will be copied to the active control set." `
                            -Data ([PSCustomObject]@{
                                    Replacement = $lastKnownGood.Raw
                                    SourceControlSet = $lastKnownGood.ControlSet
                                })))
            }
            else {
                $fallbackReason = if ($subsystemEvidenceUnreadable) {
                    if ($subsystem.Resolution.MetadataUnreadable) {
                        "the active executable could not be opened to establish anything about it, which is a failure to gather evidence rather than proof the value is wrong, and an unreadable file is not authority to overwrite a live value"
                    }
                    else {
                        "the active executable could not be SHA-256 read, which is a failure to gather evidence rather than proof the value is wrong, and an unreadable file is not authority to overwrite a live value"
                    }
                }
                elseif (-not $subsystem.KeyPresent) {
                    "the active $($subsystem.KeyPath) key does not exist, so there is nowhere to write the value"
                }
                elseif (-not $SessionManager.LastKnownGoodIsDistinct) {
                    'Select\LastKnownGood does not name a different control set'
                }
                elseif ($null -eq $lastKnownGood -or -not $lastKnownGood.KeyPresent) {
                    "the LastKnownGood SubSystems key is unavailable in $($SessionManager.LastKnownGoodControlSet)"
                }
                elseif (-not $lastKnownGood.Present) {
                    "LastKnownGood $($lastKnownGood.ControlSet) has no Windows value"
                }
                elseif ($lastKnownGood.ValueKind -ne 'ExpandString') {
                    "LastKnownGood $($lastKnownGood.ControlSet) stores Windows as $($lastKnownGood.ValueKind), not REG_EXPAND_SZ"
                }
                elseif ($null -eq $lastKnownGood.Resolution -or -not $lastKnownGood.Resolution.Exists) {
                    "the LastKnownGood executable is unavailable"
                }
                elseif (-not (Test-ResolutionIntegrity -Resolution $lastKnownGood.Resolution -RequireMicrosoft)) {
                    "the LastKnownGood executable is not a hash-readable trusted Microsoft image"
                }
                else {
                    'the LastKnownGood value is identical to the active value, so copying it would not repair the fault'
                }

                [void]$findings.Add((New-Finding -Cause 'WindowsSubsystemNoSafeFallback' -Item 'SubSystems\Windows' -Hive 'SYSTEM' -Repairable $false `
                            -Message "Session Manager SubSystems\Windows cannot start the Windows subsystem because $activeReason. It was not changed because $fallbackReason. If the value is correct but its binary is damaged, repair the Windows files with win-sfc-sf-corruption." `
                            -Data $subsystem))
            }
        }

        foreach ($valueName in @('BootExecute', 'SetupExecute')) {
            $entries = @($SessionManager.$valueName)

            # An entry whose file could not be read is neither dangling nor good. It is excluded
            # from the removal set so a failed read cannot delete it, and included in the keep set
            # so the rewrite that removes a genuinely dangling sibling does not delete it either.
            foreach ($unreadable in @($entries | Where-Object { $_.Unreadable })) {
                [void]$findings.Add((New-Finding -Cause "${valueName}CommandUnreadable" -Item $unreadable.Entry -Hive 'SYSTEM' -Repairable $false `
                            -Message "Session Manager $valueName runs '$($unreadable.Entry)' before Win32 starts, and $($unreadable.Resolution.Reason). It was left in place: a file that could not be read is not a file that is missing, and removing it on that evidence would break a boot that currently works. Check the disk for I/O errors or a restrictive ACL on that path." `
                            -Data $unreadable))
            }

            $dangling = if ($valueName -eq 'BootExecute') {
                @($entries | Where-Object { -not $_.IsDefault -and -not $_.Exists -and -not $_.Unreadable })
            }
            else {
                @($entries | Where-Object { -not $_.Exists -and -not $_.Unreadable })
            }
            if ($dangling.Count -eq 0) { continue }

            $keep = if ($valueName -eq 'BootExecute') {
                @($entries | Where-Object { $_.IsDefault -or $_.Exists -or $_.Unreadable } | ForEach-Object { $_.Entry })
            }
            else {
                @($entries | Where-Object { $_.Exists -or $_.Unreadable } | ForEach-Object { $_.Entry })
            }
            foreach ($bad in $dangling) {
                [void]$findings.Add((New-Finding -Cause "${valueName}Dangling" -Item $bad.Entry -Hive 'SYSTEM' `
                            -Message "Session Manager $valueName runs '$($bad.Entry)' before Win32 starts, but $($bad.Resolution.Reason). Smss.exe waits on an image it cannot start, so the VM stops at a black screen with no error text. The entry will be removed and the remaining $($keep.Count) entry(s) kept." `
                            -Data ([PSCustomObject]@{ ValueName = $valueName; Keep = $keep; Remove = $bad.Entry })))
            }
        }

        $bootEntries = @($SessionManager.BootExecute)
        $defaultEntries = @($bootEntries | Where-Object { $_.IsDefault })
        $hasDefault = ($defaultEntries.Count -gt 0)

        foreach ($defaultEntry in $defaultEntries) {
            if (Test-ResolutionIntegrity -Resolution $defaultEntry.Resolution -RequireMicrosoft) { continue }
            $detail = if (-not $defaultEntry.Resolution.Exists) {
                $defaultEntry.Resolution.Reason
            }
            elseif ("$($defaultEntry.Resolution.SHA256)" -notmatch '^[A-Fa-f0-9]{64}$') {
                "its SHA-256 could not be read from $($defaultEntry.Resolution.Resolved)"
            }
            else {
                "its image is not trusted as Microsoft (signature status $($defaultEntry.Resolution.SignatureStatus))"
            }
            [void]$findings.Add((New-Finding -Cause 'BootExecuteDefaultBinaryInvalid' -Item $defaultEntry.Entry -Hive 'SYSTEM' -Repairable $false `
                        -Message "Session Manager BootExecute carries the Windows default '$($defaultEntry.Entry)', but $detail. Rewriting the registry entry would still point at the same damaged file; use win-sfc-sf-corruption." `
                        -Data $defaultEntry))
        }

        foreach ($valueName in @('BootExecute', 'SetupExecute')) {
            foreach ($entry in @($SessionManager.$valueName | Where-Object { $_.Exists })) {
                if ($entry.IsDefault) { continue }
                if (Test-ResolutionIntegrity -Resolution $entry.Resolution) { continue }
                [void]$findings.Add((New-Finding -Cause 'SessionManagerCommandIntegrity' -Item "$valueName $($entry.Entry)" -Hive 'SYSTEM' -Repairable $false `
                            -Message "Session Manager $valueName runs '$($entry.Entry)' from $($entry.Resolution.Resolved), but its integrity could not be established (signature $($entry.Resolution.SignatureStatus), SHA-256 '$($entry.Resolution.SHA256)'). It exists and was not removed because third-party boot commands can be legitimate." `
                            -Data $entry))
            }
        }

        # When every BootExecute entry is dangling, removing them would leave the value empty, so the
        # dangling repair writes the default back itself. Raising a separate finding here as well
        # would describe one write as two, and the second would find nothing left to do.
        $repairableBootDangling = @($bootEntries | Where-Object { -not $_.IsDefault -and -not $_.Exists -and -not $_.Unreadable })
        $bootSurvives = (@($bootEntries | Where-Object { $_.IsDefault -or $_.Exists -or $_.Unreadable }).Count -gt 0)
        $defaultRestoredByDanglingRepair = ($repairableBootDangling.Count -gt 0 -and -not $bootSurvives)

        if (-not $hasDefault -and $SessionManager.BootExecutePresent -and -not $defaultRestoredByDanglingRepair) {
            if (Test-ResolutionIntegrity -Resolution $SessionManager.DefaultBootExecuteResolution -RequireMicrosoft) {
                [void]$findings.Add((New-Finding -Cause 'BootExecuteDefaultMissing' -Item 'BootExecute' -Hive 'SYSTEM' `
                            -Message "Session Manager BootExecute does not run the Windows default '$($script:DefaultBootExecute)', so autochk never runs and a volume left dirty by the failure is mounted without being checked. The default will be restored; autochk.exe is a non-zero, hash-readable Microsoft image." `
                            -Data ([PSCustomObject]@{ ValueName = 'BootExecute'; Keep = @($bootEntries | Where-Object { $_.Exists -or $_.Unreadable } | ForEach-Object { $_.Entry }) })))
            }
            else {
                [void]$findings.Add((New-Finding -Cause 'BootExecuteDefaultUnavailable' -Item 'BootExecute' -Hive 'SYSTEM' -Repairable $false `
                            -Message "Session Manager BootExecute does not run the Windows default '$($script:DefaultBootExecute)', but it was not restored because autochk.exe is missing, zero length, hash-unreadable or not a trusted Microsoft image. Repair the Windows files with win-sfc-sf-corruption first." `
                            -Data $SessionManager.DefaultBootExecuteResolution))
            }
        }

        foreach ($dll in @($SessionManager.ExcludeFromKnownDlls)) {
            [void]$findings.Add((New-Finding -Cause 'ExcludedKnownDll' -Item $dll -Hive 'SYSTEM' -Repairable $false `
                        -Message "'$dll' is listed in ExcludeFromKnownDlls, so the loader takes it from the application directory instead of the KnownDlls section. Application compatibility shims use this legitimately, so it is reported rather than removed, but it is also how a DLL is preloaded ahead of the system copy and is worth confirming."))
        }
    }
    else {
        [void]$findings.Add((New-Finding -Cause 'SessionManagerMissing' -Item 'Session Manager' -Hive 'SYSTEM' -Repairable $false `
                    -Message "$($SessionManager.Reason). Without it the session manager has no configuration to start from, which is registry damage rather than a logon fault: run win-fix-registry-corruption against this disk."))
    }

    # -- Setup mode, runs before the logon UI -----------------------------------------------------
    if ($SetupMode.Available -and $SetupMode.SetupType -ne 0) {
        if ([string]::IsNullOrWhiteSpace($SetupMode.CmdLine)) {
            [void]$findings.Add((New-Finding -Cause 'SetupTypeWithoutCommand' -Item 'SetupType' -Hive 'SYSTEM' `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) but CmdLine is empty, so the VM enters setup mode at boot and has nothing to run there. SetupType will be set back to 0." `
                        -Data $SetupMode))
        }
        elseif ($null -ne $SetupMode.Resolution -and $SetupMode.Resolution.MetadataUnreadable) {
            [void]$findings.Add((New-Finding -Cause 'SetupModeCommandUnreadable' -Item 'CmdLine' -Hive 'SYSTEM' -Repairable $false `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) and CmdLine runs '$($SetupMode.CmdLine)' before the logon UI, and $($SetupMode.Resolution.Reason). SetupType was NOT cleared: a command that could not be read is not a command that is missing, and clearing setup mode on that evidence would abandon a servicing or provisioning step that is genuinely meant to run. Check the disk for I/O errors or a restrictive ACL on that path." `
                        -Data $SetupMode))
        }
        elseif ($null -ne $SetupMode.Resolution -and -not $SetupMode.Resolution.Exists) {
            [void]$findings.Add((New-Finding -Cause 'SetupModeDanglingCommand' -Item 'CmdLine' -Hive 'SYSTEM' `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) and CmdLine runs '$($SetupMode.CmdLine)' before the logon UI, but $($SetupMode.Resolution.Reason). The boot stalls in setup mode waiting on a command that cannot start. This is the hook offline password and user-rights tools use, so it is most likely a leftover from an earlier repair. SetupType will be set back to 0 and CmdLine cleared." `
                        -Data $SetupMode))
        }
        else {
            $integrity = if (Test-ResolutionIntegrity -Resolution $SetupMode.Resolution) {
                "signature $($SetupMode.Resolution.SignatureStatus), SHA-256 $($SetupMode.Resolution.SHA256)"
            }
            else {
                "integrity not established: signature $($SetupMode.Resolution.SignatureStatus), SHA-256 '$($SetupMode.Resolution.SHA256)'"
            }
            [void]$findings.Add((New-Finding -Cause 'SetupModeActive' -Item 'CmdLine' -Hive 'SYSTEM' -Repairable $false `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) and CmdLine runs '$($SetupMode.CmdLine)' before the logon UI ($integrity). The command exists on the disk, so this may be a servicing or provisioning step that is genuinely meant to run and it has been left alone. If the VM hangs before the logon screen, clear SetupType and CmdLine by hand." `
                        -Data $SetupMode))
        }
    }

    # -- Winlogon ---------------------------------------------------------------------------------
    if ($Winlogon.Available) {
        foreach ($value in @($Winlogon.Values)) {
            if ($value.HasRequired -and -not $value.RequiredIntegrityOk) {
                $required = $value.RequiredResolution
                [void]$findings.Add((New-Finding -Cause 'WinlogonRequiredBinaryInvalid' -Item $value.Required -Hive 'SOFTWARE' -Repairable $false `
                            -Message "Winlogon $($value.Name) names the required Windows binary $($required.Resolved), but it is not a hash-readable trusted Microsoft image (signature $($required.SignatureStatus), SHA-256 '$($required.SHA256)'). The value was left unchanged because rewriting it around an untrusted required image is unsafe; use win-sfc-sf-corruption." `
                            -Data $required))
                continue
            }

            if (-not $value.HasRequired -and -not $value.DefaultIntegrityOk) {
                $required = $value.DefaultResolution
                $detail = if ($null -eq $required) {
                    'the default path could not be resolved'
                }
                elseif (-not $required.Exists) {
                    $required.Reason
                }
                elseif ("$($required.SHA256)" -notmatch '^[A-Fa-f0-9]{64}$') {
                    $required.Reason
                }
                else {
                    "the image is not trusted as Microsoft (signature status $($required.SignatureStatus))"
                }
                [void]$findings.Add((New-Finding -Cause 'WinlogonRequiredBinaryUnavailable' -Item $value.Required -Hive 'SOFTWARE' -Repairable $false `
                            -Message "Winlogon $($value.Name) does not have a usable $($value.Required), and its Windows default at $($required.Resolved) cannot be restored because $detail. The value was left unchanged because rewriting it would still leave logon without its required image; use win-sfc-sf-corruption." `
                            -Data $required))
                continue
            }

            if (-not $value.Present -or $value.Resolutions.Count -eq 0) {
                [void]$findings.Add((New-Finding -Cause 'WinlogonValueMissing' -Item $value.Name -Hive 'SOFTWARE' `
                            -Message "Winlogon has no usable $($value.Name) value, which $($value.Purpose). Winlogon treats that as a critical system process failure and bugchecks with 0xC000021A. It will be set to the Windows default '$($value.Default)'." `
                            -Data $value))
                continue
            }

            foreach ($unreadable in @($value.Unreadable)) {
                [void]$findings.Add((New-Finding -Cause 'WinlogonCommandUnreadable' -Item "$($value.Name) $($unreadable.Command)" -Hive 'SOFTWARE' -Repairable $false `
                            -Message "Winlogon $($value.Name) runs '$($unreadable.Command)', and $($unreadable.Reason). It was neither removed nor counted as working: a file that could not be read is not a file that is missing, and removing it on that evidence would break a logon that currently works. It is kept in the value if $($value.Name) is rewritten. Check the disk for I/O errors or a restrictive ACL on that path." `
                            -Data $unreadable))
            }

            # One finding per value, not per broken entry. The repair rewrites the whole value in a
            # single write, so splitting this into several findings would report repairs that never
            # happened: the first write already corrects everything the others would have asked for.
            if ($value.Dangling.Count -gt 0 -or -not $value.HasRequired) {
                $reasons = [System.Collections.Generic.List[string]]::new()
                foreach ($bad in @($value.Dangling)) {
                    [void]$reasons.Add("it runs '$($bad.Command)', but $($bad.Reason)")
                }
                if (-not $value.HasRequired) {
                    [void]$reasons.Add("it never runs $($value.Required), which $($value.Purpose)")
                }

                $plan = if ($value.Dangling.Count -gt 0) { "The $($value.Dangling.Count) broken entry(s) will be removed and the $($value.Good.Count + $value.Unreadable.Count) other(s) kept" } else { 'The working entries will be kept' }
                if (-not $value.HasRequired) { $plan += ", and '$($value.Default)' added ahead of them" }

                [void]$findings.Add((New-Finding -Cause 'WinlogonValueBroken' -Item $value.Name -Hive 'SOFTWARE' `
                            -Message "Winlogon $($value.Name) is set to '$($value.Raw)' and cannot complete a logon: $($reasons -join '; '). Winlogon treats this as a critical system process failure and bugchecks with 0xC000021A. $plan." `
                            -Data $value))
            }
            else {
                $extraResolutions = @($value.Good | Where-Object { (Split-Path -Path $_.Resolved -Leaf) -ine $value.Required })
                $extra = @($extraResolutions | ForEach-Object { $_.Command })
                if ($extra.Count -gt 0) {
                    $details = @($extraResolutions | ForEach-Object {
                            "'$($_.Command)' (signature $($_.SignatureStatus), SHA-256 '$($_.SHA256)')"
                        })
                    [void]$findings.Add((New-Finding -Cause 'WinlogonExtraCommand' -Item $value.Name -Hive 'SOFTWARE' -Repairable $false `
                                -Message "Winlogon $($value.Name) also runs $($details -join ', ') at every logon. Each file exists and none was removed, but anything started from this value runs before the desktop appears and is worth confirming as expected." `
                                -Data $value))
                }
            }
        }
    }
    else {
        [void]$findings.Add((New-Finding -Cause 'WinlogonKeyMissing' -Item 'Winlogon' -Hive 'SOFTWARE' -Repairable $false `
                    -Message "$($Winlogon.Reason). The key itself being gone is registry damage rather than a logon fault: run win-fix-registry-corruption against this disk."))
    }

    # -- Profile list ------------------------------------------------------------------------------
    foreach ($userProfile in @($ProfileList.Profiles)) {
        if ($userProfile.HasBak) {
            [void]$findings.Add((New-Finding -Cause 'ProfileBakDuplicate' -Item $userProfile.Sid -Hive 'SOFTWARE' `
                        -Message "Profile $($userProfile.Sid) has a .bak twin, which is what the profile service leaves behind when it cannot load the real profile and signs the user into a replacement. Primary points at '$($userProfile.GuestProfilePath)' and the .bak at '$($userProfile.BakProfilePath)'. The .bak entry will be made primary again and the replacement kept aside as .old." `
                        -Data $userProfile))
            continue
        }

        if ($userProfile.IsTemporary) {
            [void]$findings.Add((New-Finding -Cause 'ProfileTemporaryFlag' -Item $userProfile.Sid -Hive 'SOFTWARE' `
                        -Message "Profile $($userProfile.Sid) has the temporary-profile bit set in State ($($userProfile.State)), so every logon lands in a throwaway profile and changes are discarded at sign-out. The bit will be cleared and State returned to $($userProfile.State -band (-bnot 0x8))." `
                        -Data $userProfile))
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($userProfile.GuestProfilePath) -and -not $userProfile.ProfileExists) {
            [void]$findings.Add((New-Finding -Cause 'ProfileDirectoryMissing' -Item $userProfile.Sid -Hive 'SOFTWARE' -Repairable $false `
                        -Message "Profile $($userProfile.Sid) points at '$($userProfile.GuestProfilePath)', which does not exist on the disk, so the profile service fails this user's logon. It is reported and not repaired: removing the entry lets the user in with an empty new profile and abandons whatever is left of the old one, which is a data loss decision to make deliberately." `
                        -Data $userProfile))
        }
    }

    # -- RPC hosting, which the logon UI depends on ------------------------------------------------
    if ($RpcHosting.Available -and $RpcHosting.HasMismatch) {
        $detail = "RpcSs runs '$($RpcHosting.RpcSs.ImagePath)' and RpcEptMapper runs '$($RpcHosting.RpcEptMapper.ImagePath)'"
        if ($RpcHosting.CanRepair) {
            [void]$findings.Add((New-Finding -Cause 'RpcHostSplit' -Item 'RpcEptMapper' -Hive 'SYSTEM' `
                        -Message "$detail, so svchost starts them in two separate processes instead of one shared RPC host. The endpoint mapper then sits outside the RPC service's process, local RPC and COM interface resolution fails, and DWM and LogonUI crash and restart in a loop with no desktop ever appearing. RpcEptMapper will be given the same command line RpcSs already has." `
                        -Data $RpcHosting))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'RpcHostSplit' -Item 'RpcEptMapper' -Hive 'SYSTEM' -Repairable $false `
                        -Message "$detail, so svchost starts them in two separate processes instead of one shared RPC host, which can leave DWM and LogonUI crashing in a loop before any desktop appears. It is reported and not repaired: $($RpcHosting.Reason)." `
                        -Data $RpcHosting))
        }
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for. Returns $true when something was written.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    switch -Regex ($Finding.Cause) {
        '^WindowsSubsystemBroken$' {
            $data = $Finding.Data
            $controlSet = Split-Path -Path $SystemRoot -Leaf
            $subKeyPath = "BROKENSYSTEM\$controlSet\Control\Session Manager\SubSystems"
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $true)
            if ($null -eq $key) {
                throw "The active SubSystems key is no longer available: HKLM:\$subKeyPath"
            }

            try {
                $present = ($key.GetValueNames() -contains 'Windows')
                $existing = if ($present) {
                    [string]$key.GetValue(
                        'Windows',
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                }
                else {
                    ''
                }
                $kind = if ($present) { $key.GetValueKind('Windows') } else { $null }

                if ($present -and
                    $kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString -and
                    [string]::Equals($existing, $data.Replacement, [System.StringComparison]::Ordinal)) {
                    return $false
                }

                $key.SetValue(
                    'Windows',
                    [string]$data.Replacement,
                    [Microsoft.Win32.RegistryValueKind]::ExpandString)
            }
            finally {
                $key.Close()
            }

            Add-OfflineRepairLog -Message "SubSystems\Windows: copied the exact REG_EXPAND_SZ value from $($data.SourceControlSet) to $controlSet."
            return $true
        }

        '^(BootExecute|SetupExecute)Dangling$' {
            $data = $Finding.Data
            $keyPath = "$SystemRoot\Control\Session Manager"
            $current = @((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).$($data.ValueName))
            $keep = @($current | Where-Object { $_.Trim() -ne $data.Remove })

            # An earlier finding on the same value may already have removed this entry.
            if ($keep.Count -eq $current.Count -and $current.Count -gt 0) { return $false }

            if ($keep.Count -gt 0) {
                Set-ItemProperty -Path $keyPath -Name $data.ValueName -Value ([string[]]$keep) -Type MultiString -Force -ErrorAction Stop
            }
            elseif ($data.ValueName -eq 'BootExecute') {
                # Never leave BootExecute empty: that silently disables the boot-time volume check.
                Set-ItemProperty -Path $keyPath -Name 'BootExecute' -Value ([string[]]@($script:DefaultBootExecute)) -Type MultiString -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "BootExecute had no surviving entry, so the Windows default '$($script:DefaultBootExecute)' was written back."
            }
            else {
                Remove-ItemProperty -Path $keyPath -Name 'SetupExecute' -Force -ErrorAction Stop
            }

            Add-OfflineRepairLog -Message "$($data.ValueName): removed '$($data.Remove)'."
            return $true
        }

        '^BootExecuteDefaultMissing$' {
            $keyPath = "$SystemRoot\Control\Session Manager"
            $current = @((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).BootExecute | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if (@($current | Where-Object { $_ -match '^autocheck\s+autochk\b' }).Count -gt 0) { return $false }

            $value = @($script:DefaultBootExecute) + $current
            Set-ItemProperty -Path $keyPath -Name 'BootExecute' -Value ([string[]]$value) -Type MultiString -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "BootExecute: added the Windows default '$($script:DefaultBootExecute)' ahead of $($current.Count) existing entry(s)."
            return $true
        }

        '^(SetupTypeWithoutCommand|SetupModeDanglingCommand)$' {
            $keyPath = 'HKLM:\BROKENSYSTEM\Setup'
            $before = $Finding.Data
            Set-ItemProperty -Path $keyPath -Name 'SetupType' -Value 0 -Type DWord -Force -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($before.CmdLine)) {
                Set-ItemProperty -Path $keyPath -Name 'CmdLine' -Value '' -Type String -Force -ErrorAction Stop
            }
            Add-OfflineRepairLog -Message "Setup: SetupType $($before.SetupType) -> 0, CmdLine '$($before.CmdLine)' -> empty. The VM will boot straight to the logon screen instead of into setup mode."
            return $true
        }

        '^Winlogon(ValueMissing|ValueBroken)$' {
            $value = $Finding.Data
            $keyPath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

            # Entries whose file could not be read are kept alongside the ones that resolved. They
            # are not in Good, because nothing about them was proven, but dropping them here would
            # delete them from the value just as surely as the dangling repair does - the write is
            # the whole value, not a removal. Filtering Resolutions rather than concatenating Good
            # and Unreadable also preserves the operator's original ordering.
            $keep = @($value.Resolutions | Where-Object { $_.Exists -or $_.MetadataUnreadable } | ForEach-Object { $_.Command })
            $parts = if ($value.HasRequired) { $keep } else { @($value.Default) + $keep }
            if ($parts.Count -eq 0) { $parts = @($value.Default) }

            $newValue = ($parts -join ',')
            if ($value.TrailingComma) { $newValue = "$newValue," }

            $existing = "$((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).$($value.Name))"
            if ($existing -eq $newValue) { return $false }

            Set-ItemProperty -Path $keyPath -Name $value.Name -Value $newValue -Type String -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "Winlogon $($value.Name): '$existing' -> '$newValue'."
            return $true
        }

        '^ProfileBakDuplicate$' {
            $userProfile = $Finding.Data
            $basePath = Split-Path -Path $userProfile.KeyPath -Parent
            $oldPath = "$($userProfile.KeyPath).old"

            if (-not (Test-Path $userProfile.BakKeyPath)) { return $false }
            if (Test-Path $oldPath) { Remove-Item -Path $oldPath -Recurse -Force -ErrorAction Stop }

            Rename-Item -Path $userProfile.KeyPath -NewName "$($userProfile.Sid).old" -Force -ErrorAction Stop
            Rename-Item -Path $userProfile.BakKeyPath -NewName $userProfile.Sid -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($userProfile.Sid): the replacement profile entry was renamed to .old and the .bak entry restored as the primary one."

            $restored = "$basePath\$($userProfile.Sid)"
            $props = Get-ItemProperty $restored -ErrorAction SilentlyContinue

            $state = if ($null -ne $props.State) { [int]$props.State } else { 0 }
            if (($state -band 0x8) -ne 0) {
                $newState = $state -band (-bnot 0x8)
                Set-ItemProperty -Path $restored -Name 'State' -Value $newState -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): State $state -> $newState (temporary-profile bit cleared)."
            }
            if ($null -ne $props.RefCount -and [int]$props.RefCount -ne 0) {
                Set-ItemProperty -Path $restored -Name 'RefCount' -Value 0 -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): RefCount $($props.RefCount) -> 0, so the profile is not treated as still loaded."
            }
            return $true
        }

        '^ProfileTemporaryFlag$' {
            $userProfile = $Finding.Data
            $props = Get-ItemProperty $userProfile.KeyPath -ErrorAction SilentlyContinue
            $state = if ($null -ne $props.State) { [int]$props.State } else { 0 }
            if (($state -band 0x8) -eq 0) { return $false }

            $newState = $state -band (-bnot 0x8)
            Set-ItemProperty -Path $userProfile.KeyPath -Name 'State' -Value $newState -Type DWord -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($userProfile.Sid): State $state -> $newState (temporary-profile bit cleared)."

            if ($null -ne $props.RefCount -and [int]$props.RefCount -ne 0) {
                Set-ItemProperty -Path $userProfile.KeyPath -Name 'RefCount' -Value 0 -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): RefCount $($props.RefCount) -> 0."
            }
            return $true
        }

        '^RpcHostSplit$' {
            $data = $Finding.Data
            $controlSet = Split-Path -Path $SystemRoot -Leaf
            $subKeyPath = "BROKENSYSTEM\$controlSet\Services\RpcEptMapper"
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $true)
            if ($null -eq $key) {
                throw "The RpcEptMapper service key is no longer available: HKLM:\$subKeyPath"
            }

            try {
                $before = [string]$key.GetValue(
                    'ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $replacement = [string]$data.RpcSs.ImagePath

                if ([string]::Equals($before, $replacement, [System.StringComparison]::Ordinal) -and
                    $key.GetValueKind('ImagePath') -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                    return $false
                }

                # REG_EXPAND_SZ is required, not cosmetic: writing the same text as REG_SZ leaves
                # %SystemRoot% unexpanded at boot and the service fails to start at all.
                $key.SetValue('ImagePath', $replacement, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            }
            finally {
                $key.Close()
            }

            Add-OfflineRepairLog -Message "RpcEptMapper ImagePath: '$before' -> '$replacement' (REG_EXPAND_SZ), so it shares one svchost host process with RpcSs again."
            Add-OfflineRepairLog -Message "RpcEptMapper: to undo this after the VM boots, run: reg add `"HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`" /v ImagePath /t REG_EXPAND_SZ /d `"$before`" /f"
            return $true
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
        $winlogon = Get-WinlogonState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $sessionManager = Get-SessionManagerState -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $setupMode = Get-SetupModeState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $profileList = Get-ProfileListState -WindowsDrive $offline.WindowsDrive
        $rpcHosting = Get-RpcHostingState -SystemRoot $systemRoot -GuestSystemRoot $winlogon.GuestSystemRoot `
            -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive

        return [PSCustomObject]@{
            ControlSet     = (Split-Path -Path $systemRoot -Leaf)
            Winlogon       = $winlogon
            SessionManager = $sessionManager
            SetupMode      = $setupMode
            ProfileList    = $profileList
            RpcHosting     = $rpcHosting
            Findings       = @(Get-AllFinding -Winlogon $winlogon -SessionManager $sessionManager -SetupMode $setupMode -ProfileList $profileList -RpcHosting $rpcHosting)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet): guest Windows directory $($context.Winlogon.GuestSystemRoot)." | Tee-Object -FilePath $logFile -Append
    foreach ($value in @($context.Winlogon.Values)) {
        Log-Info "Winlogon $($value.Name) = '$($value.Raw)' ($($value.Good.Count) of $($value.Resolutions.Count) entry(s) resolve to a file on the disk)." | Tee-Object -FilePath $logFile -Append
        foreach ($resolution in @($value.Resolutions)) {
            Log-Info "  $($resolution.Binary): path='$($resolution.Resolved)', bytes=$($resolution.Length), signature=$($resolution.SignatureStatus), sha256='$($resolution.SHA256)'." | Tee-Object -FilePath $logFile -Append
        }
    }
    if ($context.SessionManager.Available) {
        $subsystem = $context.SessionManager.WindowsSubsystem
        Log-Info "SubSystems\Windows $($subsystem.ControlSet): type=$($subsystem.ValueKind), executable='$($subsystem.Resolution.Resolved)', bytes=$($subsystem.Resolution.Length), signature=$($subsystem.Resolution.SignatureStatus), sha256='$($subsystem.Resolution.SHA256)'." | Tee-Object -FilePath $logFile -Append
        if ($context.SessionManager.LastKnownGoodIsDistinct -and
            $null -ne $context.SessionManager.LastKnownGoodWindowsSubsystem) {
            $lastKnownGood = $context.SessionManager.LastKnownGoodWindowsSubsystem
            Log-Info "SubSystems\Windows $($lastKnownGood.ControlSet) (LastKnownGood): type=$($lastKnownGood.ValueKind), executable='$($lastKnownGood.Resolution.Resolved)', bytes=$($lastKnownGood.Resolution.Length), signature=$($lastKnownGood.Resolution.SignatureStatus), sha256='$($lastKnownGood.Resolution.SHA256)'." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info "SubSystems\Windows: Select\LastKnownGood does not provide a distinct readable fallback control set." | Tee-Object -FilePath $logFile -Append
        }

        Log-Info "Session Manager: $(@($context.SessionManager.BootExecute).Count) BootExecute entry(s), $(@($context.SessionManager.SetupExecute).Count) SetupExecute entry(s), $(@($context.SessionManager.ExcludeFromKnownDlls).Count) ExcludeFromKnownDlls entry(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($entry in @($context.SessionManager.BootExecute)) {
            $who = if ($entry.IsDefault) { 'Windows default' } elseif ($entry.Vendor) { "from '$($entry.Vendor)'" } else { 'no version information' }
            Log-Info "  BootExecute '$($entry.Entry)': $(if ($entry.Exists) { "resolves to $($entry.Resolution.Resolved), bytes=$($entry.Resolution.Length), signature=$($entry.Resolution.SignatureStatus), sha256='$($entry.Resolution.SHA256)', $who" } else { $entry.Resolution.Reason })" | Tee-Object -FilePath $logFile -Append
        }
        foreach ($entry in @($context.SessionManager.SetupExecute)) {
            Log-Info "  SetupExecute '$($entry.Entry)': $(if ($entry.Exists) { "resolves to $($entry.Resolution.Resolved), bytes=$($entry.Resolution.Length), signature=$($entry.Resolution.SignatureStatus), sha256='$($entry.Resolution.SHA256)'" } else { $entry.Resolution.Reason })" | Tee-Object -FilePath $logFile -Append
        }
    }
    if ($context.SetupMode.SystemSetupInProgress -eq 1) {
        Log-Warning 'SYSTEM\Setup\SystemSetupInProgress is 1, so the guest believes Windows setup has not finished. That is normal only for a VM captured mid-Sysprep, and it was left alone.' | Tee-Object -FilePath $logFile -Append
    }
    Log-Info "Profile list: $(@($context.ProfileList.Profiles).Count) user profile(s)." | Tee-Object -FilePath $logFile -Append
    if ($context.RpcHosting.Available) {
        Log-Info "RPC hosting $($context.RpcHosting.ControlSet): RpcSs='$($context.RpcHosting.RpcSs.ImagePath)' ($($context.RpcHosting.RpcSs.ValueKind)), RpcEptMapper='$($context.RpcHosting.RpcEptMapper.ImagePath)' ($($context.RpcHosting.RpcEptMapper.ValueKind)); $($context.RpcHosting.Reason)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "RPC hosting: not assessed because $($context.RpcHosting.Reason)." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    # Ahead of the detectOnly gate on purpose, so one affirmative line serves both modes. A detect
    # run on a healthy disk that says nothing leaves it indistinguishable from one this script
    # cannot judge, and the whole point of naming what was checked is to let the caller move on.
    if ($findings.Count -eq 0) {
        Log-Output 'No logon subsystem fault was found. The Windows subsystem and required logon binaries are non-zero, hash-readable Microsoft images; every optional command resolves; the RPC service and its endpoint mapper still share one svchost host process; and the VM is not held in setup mode. No changes were made.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count goes after the list on purpose. Run Command returns at most 4096 characters and
        # keeps the tail, so a summary printed first is the first thing a long detect run loses -
        # which is how a run once reported every finding truncated away and still looked successful.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Back up only the hives that are actually about to be written.
    $hivesToWrite = @($repairable | ForEach-Object { $_.Hive } | Sort-Object -Unique)
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

        $repairedCount = $repairOutcome.Repaired
        $failed = @($repairOutcome.Errors)
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict
        $winlogonAfter = Get-WinlogonState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        return @(Get-AllFinding `
                -Winlogon $winlogonAfter `
                -SessionManager (Get-SessionManagerState -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive) `
                -SetupMode (Get-SetupModeState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive) `
                -ProfileList (Get-ProfileListState -WindowsDrive $offline.WindowsDrive) `
                -RpcHosting (Get-RpcHostingState -SystemRoot $systemRoot -GuestSystemRoot $winlogonAfter.GuestSystemRoot `
                    -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive))
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
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
finally {
    # A dependency may have failed to load before these functions became available.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        Clear-OfflineDriveLetter
    }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        Write-OfflineRepairLog
    }
}
