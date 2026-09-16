#########################################################################################################
#
# .SYNOPSIS
#   Repairs corrupted or unloadable registry hives on an offline Windows disk.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". Every hive is
#   validated, only the damaged ones are repaired, and the result is re-validated. A healthy disk
#   produces no writes at all.
#
#   Detection, per hive:
#     1. The hive file is missing.
#     2. The hive file is 0 bytes.
#     3. The hive file does not start with the 'regf' signature.
#     4. Windows itself cannot parse the hive. This is the authoritative check: a scratch copy of
#        the hive and its transaction logs is loaded with reg.exe, so a hive that is merely dirty
#        is recovered by log replay and correctly reported as healthy, and the file on the offline
#        disk is never modified by the check.
#     5. chkreg.exe reports repairable structural damage in a hive that still loads.
#
#   Repair escalates only as far as it needs to, per hive:
#     a. chkreg.exe /R /C on a scratch copy. The result must load through reg.exe before it is
#        allowed anywhere near the disk, so a failed repair can never replace a working hive.
#     b. Restore from Windows\System32\Config\RegBack, only for the hives chkreg could not repair
#        and only when allowRegBack=true is passed. The RegBack set is validated first: every
#        candidate must load, SYSTEM and SOFTWARE must both be present, SAM and SECURITY are
#        restored only as a pair, and any hive whose timestamp is out of step with the core set
#        is excluded rather than mixed in.
#
#   The original file is copied next to itself before any replacement, and a restore that fails
#   part way through rolls every hive it touched back to the file it started with.
#
# .RESOLVES
#   Stop error 0xC0000218 STATUS_CANNOT_LOAD_REGISTRY_FILE, stop error 0x74 BAD_SYSTEM_CONFIG_INFO,
#   "Windows failed to load because the system registry file is missing or corrupt", and boot loops
#   that follow a storage failure, an unclean shutdown during servicing, or a restore that left a
#   truncated hive behind.
#
# .PARAMETER detectOnly
#   "true" to report what would be changed and make no writes at all. Defaults to "false".
#
# .PARAMETER allowRegBack
#   "true" to allow a RegBack restore for the hives chkreg could not repair in place. Defaults
#   to "false". The periodic backup is disabled by default on Windows 10 1803 and later, so
#   RegBack is usually empty or stale, and a restore rolls local account passwords, and on a
#   domain joined VM the machine account password, back to the time of the backup. RegBack is
#   therefore a last resort the operator opts into: when the periodic backup was enabled and
#   RegBack holds a consistent set that covers the hives still damaged, the script says so and
#   prints the command to opt in. In every other case it is skipped without comment.
#
# .PARAMETER hive
#   Limit the run to a single hive: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT or COMPONENTS.
#   Defaults to "all".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters allowRegBack=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters hive=SOFTWARE --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   chkreg.exe ships in this repository at src\windows\common\tools\chkreg.exe and is used from
#   there, so the script needs no network access on the rescue VM.
#
#   A hive that is structurally sound but semantically wrong is a different problem. A missing
#   Winlogon or Session Manager key belongs to win-fix-logon-subsystem, and boot storage driver
#   settings belong to win-fix-inaccessible-boot-device.
#
#   Only hives that are actually damaged are repaired or restored. A RegBack copy is always
#   older than the file it replaces, so restoring a healthy hive would silently revert working
#   configuration. SAM and SECURITY are the one exception and only between themselves: they are
#   sealed with the SysKey held in SYSTEM and cross-reference each other, so if one has to be
#   restored its partner is restored from the same backup. When that happens, local account
#   passwords revert to their state at backup time, and on a domain joined VM the machine
#   account password reverts with them, so the domain trust may need repairing after boot.
#   Every file the script replaces is copied to <name>.bak-<timestamp> first.
#
#   After recovery, consider re-enabling the periodic RegBack backup on the repaired VM with
#   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager
#   EnablePeriodicBackup = 1, so a future incident has a recent restore point.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$allowRegBack = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('all', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', IgnoreCase = $true)][string]$hive = 'all',
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
$isRegBackAllowed = ($allowRegBack -eq 'true')
$hiveFilter = if ($hive -eq 'all') { $null } else { $hive.ToUpperInvariant() }

function Write-OperatorLog {
    <#
    .SYNOPSIS
        Flushes buffered helper narration, keeping the returned log inside its budget.

    .DESCRIPTION
        az vm repair run returns at most 4096 characters and keeps the tail, so step by
        step narration goes to the detail log on disk only. Warnings and errors are still
        surfaced, because those are the lines that change what the operator does next:
        a RegBack restore reverting account passwords is not a detail.

        Call this only at script level, for the same reason Write-OfflineRepairLog carries
        that restriction: it writes to the output stream.
    #>
    $entries = @(Get-OfflineRepairLog)
    Clear-OfflineRepairLog
    if ($entries.Count -eq 0) { return }

    foreach ($entry in $entries) {
        if ([string]::IsNullOrEmpty($entry.Message)) { continue }
        "[$($entry.Level) $(Get-Date)]$($entry.Message)" | Out-File -FilePath $logFile -Append -ErrorAction SilentlyContinue
    }

    foreach ($entry in $entries) {
        if ([string]::IsNullOrEmpty($entry.Message)) { continue }
        switch ($entry.Level) {
            'Warning' { Log-Warning $entry.Message }
            'Error' { Log-Error $entry.Message }
            'Output' { Log-Output $entry.Message }
        }
    }
}

# SYSTEM and SOFTWARE are required for the OS to start at all, so a problem with either is an
# error. The rest degrade the installation without stopping the boot, so they are reported as
# warnings and repaired opportunistically.
function Get-OfflineHiveSpec {
    @(
        [PSCustomObject]@{ Name = 'SYSTEM'; Required = $true; Description = 'machine configuration, drivers and services' }
        [PSCustomObject]@{ Name = 'SOFTWARE'; Required = $true; Description = 'installed software and OS settings' }
        [PSCustomObject]@{ Name = 'SAM'; Required = $false; Description = 'local accounts' }
        [PSCustomObject]@{ Name = 'SECURITY'; Required = $false; Description = 'local security policy' }
        [PSCustomObject]@{ Name = 'DEFAULT'; Required = $false; Description = 'default user profile' }
        [PSCustomObject]@{ Name = 'COMPONENTS'; Required = $false; Description = 'servicing component store' }
    )
}

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        # Whether chkreg can actually fix this is only known once a repair has been attempted
        # on a scratch copy, so detection starts at $false and earns the answer.
        Repairable = $false
        Repaired   = $false
        Data       = $Data
    }
}

function Get-ChkRegPath {
    <#
    .SYNOPSIS
        Returns the path of the in-repo chkreg.exe, or an empty string when it is unavailable.
    #>
    $candidate = Join-Path (Get-Location).Path 'src\windows\common\tools\chkreg.exe'
    if (Test-OfflinePath $candidate) { return $candidate }

    Add-OfflineRepairLog -Level Warning -Message "chkreg.exe was not found at $candidate. Structural repair is unavailable and only RegBack restore can be used."
    return ''
}

function Invoke-ChkReg {
    <#
    .SYNOPSIS
        Runs chkreg.exe against a hive file and reports what it found.

    .DESCRIPTION
        Always runs on a scratch copy, never on the file on the offline disk. In repair mode
        chkreg writes its fixes back into the file it was given, so the repaired hive is the
        scratch copy itself and the caller validates that copy before it goes near the disk.

        The result is taken from the exit code, not from the message text. Measured on
        Windows Server 2022 with the copy of chkreg.exe shipped in this repository:

            healthy    exit 0    "Hive validated successfully, no errors found."
            damaged    exit 1009 "Errors detected during hive validation (Error = 1009)."
            repaired   exit 0    "Error found and fixed during hive validation."
                                 "Fixes written back successfully."

        Matching on wording is unreliable: none of those strings contain the word "corrupt",
        and a check that looks for it silently reports every damaged hive as healthy.

    .OUTPUTS
        PSCustomObject with Ran, FoundProblem, RepairedPath, ExitCode and Output.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ChkRegPath,
        [Parameter(Mandatory = $true)][string]$HivePath,
        [Parameter(Mandatory = $true)][string]$ScratchDir,
        [Parameter(Mandatory = $false)][bool]$Repair = $false
    )

    $result = [PSCustomObject]@{
        Ran          = $false
        FoundProblem = $false
        RepairedPath = ''
        ExitCode     = $null
        Output       = ''
    }

    $working = Join-Path $ScratchDir (Split-Path -Path $HivePath -Leaf)
    if (-not (Test-OfflinePath $ScratchDir)) { New-Item -Path $ScratchDir -ItemType Directory -Force | Out-Null }
    Copy-Item -LiteralPath $HivePath -Destination $working -Force -ErrorAction Stop
    foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
        if (Test-OfflinePath "$HivePath$suffix") {
            Copy-Item -LiteralPath "$HivePath$suffix" -Destination "$working$suffix" -Force -ErrorAction SilentlyContinue
        }
    }

    # chkreg writes progress to stderr, so both streams are coerced to plain strings to keep
    # PowerShell from turning ordinary output into NativeCommandError records.
    if ($Repair) {
        $raw = & $ChkRegPath /F "$working" /R 2>&1 | ForEach-Object { "$_" }
    }
    else {
        $raw = & $ChkRegPath /F "$working" 2>&1 | ForEach-Object { "$_" }
    }
    $exitCode = $LASTEXITCODE

    $result.Ran = $true
    $result.ExitCode = $exitCode
    $result.Output = (@($raw) -join ' | ').Trim()

    if ($Repair) {
        # chkreg /R rewrites the file it was handed, so the repaired hive is the scratch copy.
        $result.FoundProblem = ($exitCode -ne 0)
        $result.RepairedPath = if ($exitCode -eq 0) { $working } else { '' }
    }
    else {
        $result.FoundProblem = ($exitCode -ne 0)
    }

    return $result
}

function Resolve-RegBackSource {
    <#
    .SYNOPSIS
        Decides whether one RegBack file can be used, recovering it first when it needs it.

    .DESCRIPTION
        A RegBack copy is frequently left unreconciled: the backup is taken while the hive is
        being flushed, so the base block carries a primary sequence one ahead of the secondary
        one. Windows normally settles that by replaying the transaction logs, but RegBack keeps
        no logs, so reg.exe rejects the file with ERROR_BADDB and it looks corrupt.

        Measured on this repository's copy of chkreg.exe against a Windows Server 2022 RegBack
        set, both SECURITY (sequence 197/196) and DEFAULT (43/42) had valid base block checksums
        and intact bodies, and were rejected only for being unreconciled. Discarding them would
        disable the fallback precisely when it is needed.

        So a candidate that fails validation gets exactly one recovery attempt with chkreg /R,
        which rolls the sequence back to the last write Windows confirmed as durable and
        discards the unconfirmed one. That is the conservative direction: nothing is assumed to
        have completed. The recovered copy is then only accepted if it both loads and passes a
        fresh structural check, and it is that copy, not the untouched RegBack file, that the
        caller restores. Restoring the raw file would hand the same unreconciled hive to the
        boot loader with its logs already moved aside.

    .OUTPUTS
        PSCustomObject with IsUsable, Path, Reconciled and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $false)][string]$ChkRegPath = '',
        [Parameter(Mandatory = $false)][string]$ScratchDir = ''
    )

    $result = [PSCustomObject]@{ IsUsable = $false; Path = $SourcePath; Reconciled = $false; Reason = '' }
    $canUseChkReg = ($ChkRegPath -and $ScratchDir)

    $validation = Test-OfflineHiveFile -Path $SourcePath
    if ($validation.IsValid) {
        if (-not $canUseChkReg) {
            $result.IsUsable = $true
            return $result
        }

        # Opening with offreg is not a full structural check, so a backup must also pass
        # chkreg before it is treated as a usable source.
        $check = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $SourcePath -ScratchDir (Join-OfflinePath -Root $ScratchDir -ChildPath 'regback-check') -Repair $false
        if (-not $check.FoundProblem) {
            $result.IsUsable = $true
            return $result
        }
        $result.Reason = "The backup fails chkreg validation (exit $($check.ExitCode))."
    }
    else {
        $result.Reason = "The backup does not load: $($validation.Reason)"
    }

    if (-not $canUseChkReg) { return $result }

    $fix = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $SourcePath -ScratchDir (Join-OfflinePath -Root $ScratchDir -ChildPath 'regback-fix') -Repair $true
    if (-not $fix.RepairedPath) {
        $result.Reason = "$($result.Reason) chkreg could not recover it (exit $($fix.ExitCode))."
        return $result
    }

    $recheck = Test-OfflineHiveFile -Path $fix.RepairedPath
    if (-not $recheck.IsValid) {
        $result.Reason = "$($result.Reason) The recovered copy still does not load ($($recheck.Reason))"
        return $result
    }

    $verify = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $fix.RepairedPath -ScratchDir (Join-OfflinePath -Root $ScratchDir -ChildPath 'regback-verify') -Repair $false
    if ($verify.FoundProblem) {
        $result.Reason = "$($result.Reason) The recovered copy still fails chkreg (exit $($verify.ExitCode))."
        return $result
    }

    $result.IsUsable = $true
    $result.Path = $fix.RepairedPath
    $result.Reconciled = $true
    $result.Reason = "$($result.Reason) chkreg recovered it and the recovered copy loads and validates cleanly."
    return $result
}

function Get-RegBackPlan {
    <#
    .SYNOPSIS
        Chooses which RegBack hives may safely be restored together.

    .DESCRIPTION
        A RegBack directory is not automatically a usable backup set. Every candidate must load,
        SYSTEM and SOFTWARE must both be usable or nothing is restored, SAM and SECURITY are only
        valid as a pair because they cross-reference each other, and any hive whose timestamp is
        out of step with the core set is excluded rather than mixed with hives from another point
        in time.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $false)][string]$ChkRegPath = '',
        [Parameter(Mandatory = $false)][string]$ScratchDir = '',
        [Parameter(Mandatory = $false)][timespan]$MaximumSkew = ([timespan]::FromHours(24))
    )

    $regBack = Join-OfflinePath -Root $ConfigPath -ChildPath 'RegBack'
    $usable = @()
    $excluded = @()

    if (-not (Test-OfflinePath $regBack)) {
        return [PSCustomObject]@{ CanRestore = $false; Hives = @(); Excluded = @(); Reason = "RegBack directory not found at $regBack." }
    }

    foreach ($spec in (Get-OfflineHiveSpec)) {
        $source = Join-OfflinePath -Root $regBack -ChildPath $spec.Name
        if (-not (Test-OfflinePath $source)) {
            $excluded += [PSCustomObject]@{ Name = $spec.Name; Reason = 'Not present in RegBack.' }
            continue
        }

        $prepared = Resolve-RegBackSource -SourcePath $source -ChkRegPath $ChkRegPath -ScratchDir $ScratchDir
        if (-not $prepared.IsUsable) {
            $excluded += [PSCustomObject]@{ Name = $spec.Name; Reason = $prepared.Reason }
            continue
        }
        if ($prepared.Reconciled) {
            Add-OfflineRepairLog -Message "RegBack $($spec.Name): $($prepared.Reason)"
        }

        $usable += [PSCustomObject]@{
            Name       = $spec.Name
            Required   = $spec.Required
            SourcePath = $prepared.Path
            LivePath   = (Join-OfflinePath -Root $ConfigPath -ChildPath $spec.Name)
            # The timestamp always comes from the RegBack file itself. A recovered copy is
            # written now, and using its timestamp would defeat the skew check that keeps
            # hives from different restore points from being mixed.
            WrittenUtc = (Get-Item -LiteralPath $source -Force).LastWriteTimeUtc
        }
    }

    $core = @($usable | Where-Object { $_.Required })
    $missingCore = @(@('SYSTEM', 'SOFTWARE') | Where-Object { $_ -notin @($core.Name) })
    if ($missingCore.Count -gt 0) {
        return [PSCustomObject]@{
            CanRestore = $false
            Hives      = @()
            Excluded   = @($excluded)
            Reason     = "RegBack has no usable $($missingCore -join ' and ') hive, so it is not a complete backup set."
        }
    }

    $newestCore = (@($core.WrittenUtc) | Sort-Object -Descending | Select-Object -First 1)
    $selected = @($core)
    foreach ($candidate in @($usable | Where-Object { -not $_.Required })) {
        $skew = [timespan]::FromTicks([math]::Abs(($candidate.WrittenUtc - $newestCore).Ticks))
        if ($skew -gt $MaximumSkew) {
            $excluded += [PSCustomObject]@{ Name = $candidate.Name; Reason = "Written $([math]::Round($skew.TotalHours, 1)) hours away from the core set." }
            continue
        }
        $selected += $candidate
    }

    # SAM and SECURITY reference each other, so restoring one without the other breaks logon.
    $hasSam = @($selected | Where-Object { $_.Name -eq 'SAM' }).Count -eq 1
    $hasSecurity = @($selected | Where-Object { $_.Name -eq 'SECURITY' }).Count -eq 1
    if ($hasSam -ne $hasSecurity) {
        $selected = @($selected | Where-Object { $_.Name -notin @('SAM', 'SECURITY') })
        $excluded += [PSCustomObject]@{ Name = 'SAM/SECURITY'; Reason = 'The identity hives must be restored as a pair and only one of them is usable.' }
    }

    return [PSCustomObject]@{ CanRestore = $true; Hives = @($selected); Excluded = @($excluded); Reason = '' }
}

function Test-RegBackMaintained {
    <#
    .SYNOPSIS
        Reports whether the offline installation was still refreshing RegBack.

    .DESCRIPTION
        Windows 10 1803 and later stop refreshing Windows\System32\Config\RegBack unless
        HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager
        EnablePeriodicBackup is set to 1, which is why the directory is normally present but
        holds nothing but 0 byte files. A complete looking set with that value absent is a
        leftover from before the upgrade and can be years old, so it is precisely the backup
        that must not be offered as a repair.

        SYSTEM is read from a scratch copy and never mounted from the offline disk, so a
        detectOnly run keeps its promise to make no writes at all.

        Anything that stops the value being read counts as not maintained: with no way to
        confirm the backup was being refreshed, the conservative answer is to leave RegBack be.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $systemHive = Join-OfflinePath -Root $ConfigPath -ChildPath 'SYSTEM'
    if (-not (Test-OfflinePath $systemHive)) { return $false }

    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("rsl-regback-{0}" -f [guid]::NewGuid().ToString('N'))
    $mountKey = "RSLREGBACK$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $mounted = $false
    try {
        Copy-Item -LiteralPath $systemHive -Destination $scratch -Force -ErrorAction Stop
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
            if (Test-OfflinePath "$systemHive$suffix") {
                Copy-Item -LiteralPath "$systemHive$suffix" -Destination "$scratch$suffix" -Force -ErrorAction SilentlyContinue
            }
        }

        $null = & reg.exe load "HKLM\$mountKey" $scratch 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
        $mounted = $true

        $current = (Get-ItemProperty -Path "HKLM:\$mountKey\Select" -ErrorAction SilentlyContinue).Current
        $controlSet = if ($current) { 'ControlSet{0:d3}' -f [int]$current } else { 'ControlSet001' }
        $value = (Get-ItemProperty -Path "HKLM:\$mountKey\$controlSet\Control\Session Manager\Configuration Manager" -ErrorAction SilentlyContinue).EnablePeriodicBackup
        if ($null -eq $value) { return $false }
        return ([int]$value -eq 1)
    }
    catch {
        Add-OfflineRepairLog -Message "The periodic backup setting could not be read from SYSTEM ($($_.Exception.Message)), so RegBack is treated as not maintained."
        return $false
    }
    finally {
        if ($mounted) {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            & reg.exe unload "HKLM\$mountKey" 2>&1 | Out-Null
        }
        foreach ($suffix in @('', '.LOG', '.LOG1', '.LOG2')) {
            if (Test-Path -LiteralPath "$scratch$suffix") { Remove-Item -LiteralPath "$scratch$suffix" -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Get-RegBackSuggestion {
    <#
    .SYNOPSIS
        Decides whether RegBack is worth offering for the hives chkreg could not repair.

    .DESCRIPTION
        RegBack is a last resort, so it is only ever considered for hives that survived the
        in-place repair still damaged, and it is only mentioned when it would actually work:
        the periodic backup has to have been enabled, the set has to be internally consistent,
        and it has to contain at least one of the hives still outstanding.

        Anything short of that is silent. Telling an operator that a directory of 0 byte files
        was rejected is noise in a 4096 character log, and on a stock installation it is the
        normal state rather than a finding, so the detail on disk is where it belongs.

    .OUTPUTS
        PSCustomObject with Available, Hives and WrittenUtc.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $false)][string[]]$Wanted = @(),
        [Parameter(Mandatory = $false)][string]$ChkRegPath = '',
        [Parameter(Mandatory = $false)][string]$ScratchDir = ''
    )

    $none = [PSCustomObject]@{ Available = $false; Hives = @(); WrittenUtc = $null }
    if ($Wanted.Count -eq 0) { return $none }

    if (-not (Test-RegBackMaintained -ConfigPath $ConfigPath)) {
        Add-OfflineRepairLog -Message 'RegBack skipped: the periodic backup was not enabled on this installation, so any copy present is stale by definition.'
        return $none
    }

    $plan = Get-RegBackPlan -ConfigPath $ConfigPath -ChkRegPath $ChkRegPath -ScratchDir $ScratchDir
    foreach ($item in @($plan.Excluded)) {
        Add-OfflineRepairLog -Message "RegBack excluded $($item.Name): $($item.Reason)"
    }
    if (-not $plan.CanRestore) {
        Add-OfflineRepairLog -Message "RegBack skipped: $($plan.Reason)"
        return $none
    }

    $covered = @($plan.Hives | Where-Object { $_.Name -in $Wanted })
    if ($covered.Count -eq 0) {
        Add-OfflineRepairLog -Message 'RegBack skipped: the usable set does not contain any of the hives that are still damaged.'
        return $none
    }

    return [PSCustomObject]@{
        Available  = $true
        Hives      = @($covered.Name)
        WrittenUtc = (@($covered.WrittenUtc) | Sort-Object -Descending | Select-Object -First 1)
    }
}

function Get-RegBackOfferText {
    <#
    .SYNOPSIS
        The one wording used wherever RegBack is offered, so detect and repair cannot diverge.
    #>
    param(
        [Parameter(Mandatory = $true)]$Suggestion
    )

    return ("RegBack holds a usable backup from {0} UTC covering {1}. Re-run with --parameters allowRegBack=true to use it as a last resort: it reverts local account passwords, and on a domain joined VM the machine account password, to that time." -f `
            $Suggestion.WrittenUtc.ToString('yyyy-MM-dd HH:mm'), ($Suggestion.Hives -join ', '))
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Validates every in-scope hive and returns one finding per problem.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $false)][string]$HiveFilter = $null,
        [Parameter(Mandatory = $false)][string]$ChkRegPath = '',
        [Parameter(Mandatory = $true)][string]$ScratchDir
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in (Get-OfflineHiveSpec)) {
        if ($HiveFilter -and $spec.Name -ne $HiveFilter) { continue }

        $path = Join-OfflinePath -Root $ConfigPath -ChildPath $spec.Name
        $validation = Test-OfflineHiveFile -Path $path

        if (-not $validation.Exists) {
            # An absent optional hive is normal on many images, so only the required ones are reported.
            if ($spec.Required) {
                [void]$findings.Add((New-Finding -Cause 'HiveMissing' -Item $spec.Name `
                            -Message "the $($spec.Name) hive file is missing from $ConfigPath, so Windows cannot read its $($spec.Description)" `
                            -Data ([PSCustomObject]@{ Path = $path; Spec = $spec })))
            }
            else {
                Add-OfflineRepairLog -Message "$($spec.Name): not present on this image, which is normal for an optional hive."
            }
            continue
        }

        if ($validation.IsValid) {
            Add-OfflineRepairLog -Message "$($spec.Name): opens with offreg ($($validation.Size) bytes)."

            if ($ChkRegPath) {
                $check = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $path -ScratchDir $ScratchDir -Repair $false
                if ($check.FoundProblem) {
                    [void]$findings.Add((New-Finding -Cause 'HiveDamaged' -Item $spec.Name `
                                -Message "the $($spec.Name) hive still loads but chkreg reports repairable structural damage, which degrades $($spec.Description) and can bugcheck later" `
                                -Data ([PSCustomObject]@{ Path = $path; Spec = $spec; ChkRegOutput = $check.Output })))
                }
                else {
                    Add-OfflineRepairLog -Message "$($spec.Name): chkreg found no structural damage."
                }
            }
            continue
        }

        $cause = if ($validation.Size -eq 0) { 'HiveEmpty' } else { 'HiveUnloadable' }
        [void]$findings.Add((New-Finding -Cause $cause -Item $spec.Name `
                    -Message "the $($spec.Name) hive cannot be opened for offline validation ($($validation.Reason)); its recovery logs and structure must be checked before it can be verified for $($spec.Description)" `
                    -Data ([PSCustomObject]@{ Path = $path; Spec = $spec; Reason = $validation.Reason })))
    }

    return @($findings)
}

function Repair-HiveInPlace {
    <#
    .SYNOPSIS
        Repairs one hive with chkreg and installs the result only if Windows can load it.

    .DESCRIPTION
        With -TestOnly the identical work is done on the scratch copy and the function returns
        before anything is written to the offline disk. Detection uses that mode so the label it
        prints is the outcome of a real repair attempt rather than an assumption, and so detect
        and repair can never disagree about whether a hive is fixable.

    .OUTPUTS
        $true when the hive on disk was replaced with a repaired copy, or with -TestOnly when
        the repair attempt succeeded and would have been installed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$ChkRegPath,
        [Parameter(Mandatory = $true)][string]$ScratchDir,
        [Parameter(Mandatory = $false)][switch]$TestOnly
    )

    # A rejected repair is expected during detection, where it is what produces the [MANUAL]
    # label, so it is recorded without raising the operator facing level.
    $failLevel = if ($TestOnly) { 'Info' } else { 'Warning' }

    $path = $Finding.Data.Path
    if (-not (Test-OfflinePath $path)) {
        Add-OfflineRepairLog -Message "$($Finding.Item): no file to repair in place."
        return $false
    }
    if ((Get-Item -LiteralPath $path -Force).Length -eq 0) {
        Add-OfflineRepairLog -Message "$($Finding.Item): the file is 0 bytes, so chkreg has nothing to work with."
        return $false
    }

    $repair = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $path -ScratchDir $ScratchDir -Repair $true
    if (-not $repair.RepairedPath -or -not (Test-OfflinePath $repair.RepairedPath)) {
        Add-OfflineRepairLog -Level $failLevel -Message "$($Finding.Item): chkreg could not repair the hive (exit $($repair.ExitCode))."
        Add-OfflineRepairLog -Message "$($Finding.Item): chkreg reported: $($repair.Output)"
        return $false
    }

    # The repaired file must prove itself twice before it is allowed to replace a file on the
    # disk: it has to load, and it has to pass a fresh chkreg check. Loading alone is too weak,
    # because reg.exe loads a hive whose bins are damaged without complaining.
    $validation = Test-OfflineHiveFile -Path $repair.RepairedPath
    if (-not $validation.IsValid) {
        Add-OfflineRepairLog -Level $failLevel -Message "$($Finding.Item): the chkreg output still does not load ($($validation.Reason)), so the file on disk was left alone."
        return $false
    }

    $recheck = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $repair.RepairedPath -ScratchDir (Join-Path $ScratchDir 'verify') -Repair $false
    if ($recheck.FoundProblem) {
        Add-OfflineRepairLog -Level $failLevel -Message "$($Finding.Item): the chkreg output still fails validation (exit $($recheck.ExitCode)), so the file on disk was left alone."
        return $false
    }

    if ($TestOnly) {
        Add-OfflineRepairLog -Message "$($Finding.Item): a chkreg repair succeeds on a scratch copy, so this hive can be fixed in place."
        return $true
    }

    $backup = "$path.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $path -Destination $backup -Force -ErrorAction Stop
    Copy-Item -LiteralPath $repair.RepairedPath -Destination $path -Force -ErrorAction Stop

    $after = Test-OfflineHiveFile -Path $path
    if (-not $after.IsValid) {
        Copy-Item -LiteralPath $backup -Destination $path -Force -ErrorAction SilentlyContinue
        Add-OfflineRepairLog -Level Warning -Message "$($Finding.Item): the replaced file did not validate on disk, so the original was put back from $backup."
        return $false
    }

    # The logs describe the file that was just replaced and would be replayed over the repair.
    foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
        if (Test-OfflinePath "$path$suffix") {
            Move-Item -LiteralPath "$path$suffix" -Destination "$path$suffix.bak-$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue
        }
    }

    Add-OfflineRepairLog -Message "$($Finding.Item): repaired with chkreg and verified. Original saved as $backup."
    return $true
}

function Restore-HiveFromRegBack {
    <#
    .SYNOPSIS
        Restores the selected RegBack hives, rolling every touched file back if any step fails.

    .OUTPUTS
        String array of the hive names that were restored.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string[]]$Wanted
    )

    $targets = @($Plan.Hives | Where-Object { $_.Name -in $Wanted })
    if ($targets.Count -eq 0) { return @() }

    # Only damaged hives are restored. Every RegBack copy is older than the file it replaces,
    # so restoring a healthy hive is a silent regression: a month old SYSTEM reverts driver and
    # service configuration, and a month old SOFTWARE reverts installed software state. A VM
    # whose only real problem was one small hive must not lose either.
    #
    # SAM and SECURITY are the exception, and only between themselves. Both are sealed with the
    # SysKey held in SYSTEM and they cross-reference each other, so a current SAM beside a
    # restored SECURITY is an inconsistent account database. When one of them has to be
    # restored, its partner comes from the same backup or neither is touched.
    $identity = @('SAM', 'SECURITY')
    if (@($targets | Where-Object { $_.Name -in $identity }).Count -gt 0) {
        $partner = @($Plan.Hives | Where-Object { $_.Name -in $identity -and $_.Name -notin @($targets.Name) })
        if ($partner.Count -gt 0) {
            $targets += $partner
            Add-OfflineRepairLog -Level Warning -Message "Restoring $(@($partner.Name) -join ' and ') from RegBack as well, because the account and security hives are sealed together and only work as a matched pair."
        }
        Add-OfflineRepairLog -Level Warning -Message 'The account hives are being replaced with older copies. Local account passwords revert to their state at backup time, and on a domain joined VM the machine account password reverts too, so the domain trust may need to be repaired after the VM boots.'
    }

    $stamp = Get-Date -Format yyyyMMddHHmmss
    $touched = [System.Collections.Generic.List[PSCustomObject]]::new()
    $restored = [System.Collections.Generic.List[string]]::new()

    try {
        foreach ($item in $targets) {
            $backup = $null
            if (Test-OfflinePath $item.LivePath) {
                $backup = "$($item.LivePath).bak-$stamp"
                Copy-Item -LiteralPath $item.LivePath -Destination $backup -Force -ErrorAction Stop
            }
            [void]$touched.Add([PSCustomObject]@{ LivePath = $item.LivePath; Backup = $backup })

            Copy-Item -LiteralPath $item.SourcePath -Destination $item.LivePath -Force -ErrorAction Stop

            $sourceHash = (Get-FileHash -LiteralPath $item.SourcePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $liveHash = (Get-FileHash -LiteralPath $item.LivePath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($sourceHash -ne $liveHash) { throw "the restored $($item.Name) hive does not match its RegBack source." }

            # Stale logs describe the hive that was just replaced and would undo the restore.
            foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
                if (Test-OfflinePath "$($item.LivePath)$suffix") {
                    Move-Item -LiteralPath "$($item.LivePath)$suffix" -Destination "$($item.LivePath)$suffix.bak-$stamp" -Force -ErrorAction SilentlyContinue
                }
            }

            [void]$restored.Add($item.Name)
            Add-OfflineRepairLog -Message "$($item.Name): restored from RegBack and hash verified."
        }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "RegBack restore failed ($($_.Exception.Message)). Rolling back every hive that was touched."
        for ($i = $touched.Count - 1; $i -ge 0; $i--) {
            $entry = $touched[$i]
            try {
                if ($entry.Backup -and (Test-OfflinePath $entry.Backup)) {
                    Copy-Item -LiteralPath $entry.Backup -Destination $entry.LivePath -Force -ErrorAction Stop
                }
                elseif (Test-OfflinePath $entry.LivePath) {
                    Remove-Item -LiteralPath $entry.LivePath -Force -ErrorAction Stop
                }
            }
            catch {
                Add-OfflineRepairLog -Level Warning -Message "Rollback of $($entry.LivePath) failed: $($_.Exception.Message)"
            }
        }
        throw
    }

    return @($restored)
}

Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, allowRegBack=$isRegBackAllowed, hive=$hive)" | Tee-Object -FilePath $logFile -Append

$scratchDir = Join-Path $env:TEMP "rsl-chkreg-$scriptStartTime"

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OperatorLog

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $configPath = Join-OfflinePath -Root $offline.WindowsPath -ChildPath 'System32\Config'
    if (-not (Test-OfflinePath $configPath)) {
        throw "The registry directory was not found at $configPath."
    }

    New-Item -Path $scratchDir -ItemType Directory -Force | Out-Null
    $chkRegPath = Get-ChkRegPath
    Write-OperatorLog
    if ($chkRegPath) { Log-Info "Using chkreg.exe from $chkRegPath" | Tee-Object -FilePath $logFile -Append }

    $findings = @(Get-AllFinding -ConfigPath $configPath -HiveFilter $hiveFilter -ChkRegPath $chkRegPath -ScratchDir $scratchDir)
    Write-OperatorLog

    # Per finding detail goes to the detail log; the repair narration below would push it
    # out of the returned log's 4096 character tail anyway. The authoritative list is
    # printed next to the final summary.
    foreach ($finding in $findings) {
        "[Info $(Get-Date)]FOUND [$($finding.Cause)] $($finding.Message)" | Out-File -FilePath $logFile -Append -ErrorAction SilentlyContinue
    }

    if ($findings.Count -eq 0) {
        Log-Output "No registry hive corruption was found in $configPath. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        # Every label is the outcome of a real chkreg repair on a scratch copy, never an
        # assumption. Measured 2026-09-02: with RegBack empty, a hardcoded [FIXABLE] promised
        # three repairs where the repair run could only deliver one, so the label is now earned.
        foreach ($finding in $findings) {
            $finding.Repairable = $false
            if ($chkRegPath -and $finding.Cause -ne 'HiveMissing') {
                try {
                    $finding.Repairable = Repair-HiveInPlace -Finding $finding -ChkRegPath $chkRegPath -ScratchDir $scratchDir -TestOnly
                }
                catch {
                    Add-OfflineRepairLog -Message "$($finding.Item): the in place repair could not be tested ($($_.Exception.Message))."
                }
            }
        }

        $manual = @($findings | Where-Object { -not $_.Repairable })
        $suggestion = Get-RegBackSuggestion -ConfigPath $configPath -Wanted ([string[]]@($manual | ForEach-Object { $_.Item })) -ChkRegPath $chkRegPath -ScratchDir $scratchDir
        Write-OperatorLog

        # Count last: the returned log keeps only its tail, so a summary printed ahead of
        # its own evidence is what survives when the list behind it is truncated away.
        foreach ($finding in $findings) {
            $label = if ($finding.Repairable) { '[FIXABLE]' } else { '[MANUAL]' }
            Log-Output "  $label $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        $fixableCount = @($findings | Where-Object { $_.Repairable }).Count
        Log-Output "Detect only: found $($findings.Count) damaged hive(s), $fixableCount repairable in place. No changes were made." | Tee-Object -FilePath $logFile -Append
        if ($manual.Count -gt 0 -and -not $suggestion.Available) {
            Log-Output "$($manual.Count) hive(s) cannot be repaired from what is on this disk and need a source image or a disk level repair." | Tee-Object -FilePath $logFile -Append
        }
        if ($suggestion.Available) {
            Log-Output (Get-RegBackOfferText -Suggestion $suggestion) | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedInPlace = [System.Collections.Generic.List[string]]::new()
    $needRegBack = [System.Collections.Generic.List[string]]::new()

    foreach ($finding in $findings) {
        if ($chkRegPath -and $finding.Cause -ne 'HiveMissing') {
            # A failure repairing one hive must not abandon the others: it falls through to the
            # RegBack path for this hive and the run carries on.
            $inPlace = $false
            try {
                $inPlace = Repair-HiveInPlace -Finding $finding -ChkRegPath $chkRegPath -ScratchDir $scratchDir
            }
            catch {
                Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): in place repair could not run ($($_.Exception.Message))."
            }
            if ($inPlace) {
                $finding.Repaired = $true
                [void]$repairedInPlace.Add($finding.Item)
                Write-OperatorLog
                continue
            }
        }
        Write-OperatorLog
        [void]$needRegBack.Add($finding.Item)
    }

    $restored = @()
    $suggestion = [PSCustomObject]@{ Available = $false; Hives = @(); WrittenUtc = $null }
    if ($needRegBack.Count -gt 0) {
        if (-not $isRegBackAllowed) {
            # RegBack is a last resort the operator opts into, so the run stops at the in place
            # repair and only raises RegBack when it would genuinely help. On a stock disk the
            # directory holds nothing but 0 byte files, and reporting that as a failed fallback
            # would spend the operator's attention on the normal state of every modern install.
            $suggestion = Get-RegBackSuggestion -ConfigPath $configPath -Wanted ([string[]]@($needRegBack)) -ChkRegPath $chkRegPath -ScratchDir $scratchDir
            Write-OperatorLog
        }
        else {
            $plan = Get-RegBackPlan -ConfigPath $configPath -ChkRegPath $chkRegPath -ScratchDir $scratchDir

            foreach ($item in @($plan.Excluded)) {
                Add-OfflineRepairLog -Message "RegBack excluded $($item.Name): $($item.Reason)"
            }
            Write-OperatorLog

            if (-not $plan.CanRestore) {
                Log-Warning "RegBack cannot be used: $($plan.Reason)" | Tee-Object -FilePath $logFile -Append
            }
            else {
                $restored = @(Restore-HiveFromRegBack -Plan $plan -Wanted ([string[]]@($needRegBack)))
                Write-OperatorLog
                foreach ($finding in $findings) {
                    if ($finding.Item -in $restored) { $finding.Repaired = $true }
                }

                # A hive dragged in by the identity pair rule has had its in place repair
                # overwritten by the older backup, so reporting it as repaired in place would
                # misdescribe what is now on disk.
                foreach ($name in @($repairedInPlace | Where-Object { $_ -in $restored })) {
                    [void]$repairedInPlace.Remove($name)
                    Log-Warning "$($name) was repaired in place, but has been replaced from RegBack to stay matched with its partner hive. The in place repair no longer applies." | Tee-Object -FilePath $logFile -Append
                }
            }
        }
    }

    # Verify against freshly read files rather than trusting the writes above.
    $remaining = @(Get-AllFinding -ConfigPath $configPath -HiveFilter $hiveFilter -ChkRegPath $chkRegPath -ScratchDir $scratchDir)
    Write-OperatorLog

    foreach ($finding in $remaining) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = @($findings | Where-Object { $_.Repaired }).Count
    $summary = "Repaired $repairedCount of $($findings.Count) damaged hive(s) in $configPath."
    if ($repairedInPlace.Count -gt 0) { $summary += " Repaired in place: $($repairedInPlace -join ', ')." }
    if ($restored.Count -gt 0) { $summary += " Restored from RegBack: $($restored -join ', ')." }

    if ($remaining.Count -gt 0) {
        Log-Error "$summary $($remaining.Count) hive(s) are still damaged and need a source image or a disk level repair." | Tee-Object -FilePath $logFile -Append
        if ($suggestion.Available) {
            Log-Output (Get-RegBackOfferText -Suggestion $suggestion) | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "Every replaced hive was saved next to itself with a .bak-<timestamp> suffix." | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Write-OperatorLog
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
finally {
    Write-OperatorLog
    if ($scratchDir -and (Test-Path -LiteralPath $scratchDir)) {
        Remove-Item -LiteralPath $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    "$(Get-Date -f yyyyMMddHHmmss)" | Out-File -FilePath $logFile -Append
}
