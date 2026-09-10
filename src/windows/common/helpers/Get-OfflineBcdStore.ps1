<#
.SYNOPSIS
    Helper functions for reading and modifying the Boot Configuration Data (BCD) store
    of an offline Windows installation attached to a rescue VM.

.DESCRIPTION
    Wraps bcdedit.exe /store so that repair scripts can inspect boot loader entries,
    resolve the correct loader identifier, and apply changes safely against the offline
    store rather than the rescue VM's own boot configuration.

    Exposed functions:
      Get-BcdStorePath          Build the store path for a boot drive and firmware generation.
      Test-BcdStorePath         Test whether a BCD store exists (handles Hidden+System stores).
      Get-BcdStoreItem          Return the FileInfo for a BCD store.
      Assert-OfflineBcdStorePath Throw unless a store path is an offline store, not the rescue VM's.
      Invoke-BcdEnum            Run a read-only bcdedit enumeration and report its exit code.
      Get-BcdInventory          Parse the whole store into a structured object.
      Get-BcdLoaderDetail      Parse a single loader entry.
      Get-BcdBootLoaderId       Resolve the identifier of the real (non-setup) OS loader.
      Get-BcdPreferredOsGuid    Resolve the preferred OS loader GUID.
      Backup-BcdStore           Copy the store before it is modified.
      Invoke-BcdEdit            Run a bcdedit command against the offline store.

    Untrusted input
    ---------------
    Everything this file parses comes off the broken VM's disk, so every identifier,
    device string and element name is attacker-controllable. Two consequences shape the
    implementation:

      * bcdedit is never invoked through a shell. Invoke-BcdEdit takes an argument
        ARRAY and passes it to the executable directly, so a value such as
        '{default} & format d:' is one literal argument to bcdedit rather than a second
        command. A store parsed out of the broken disk therefore cannot execute code on
        the rescue VM.
      * The store path is validated before it is used, and a store on the rescue VM's own
        system drive is rejected outright, so a degraded caller cannot rewrite the boot
        configuration the rescue VM is currently running from.

.NOTES
    Name:   Get-OfflineBcdStore.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.
    Every function targets an offline store explicitly. None of them ever modifies the
    rescue VM's own BCD.

.VERSION
    v1.0: Initial version.
    v1.1: Invoke-BcdEdit no longer runs bcdedit through cmd.exe and takes -Arguments
          (string[]) instead of a -Command string; store paths and boot drives are
          validated and the rescue VM's own drive is rejected; bcdedit exit codes are
          inspected on the read paths so an enumeration failure is no longer reported as
          an empty store; Backup-BcdStore verifies the copy before reporting success.
#>

if (-not (Get-Command Add-OfflineRepairLog -ErrorAction SilentlyContinue)) {
    try {
        . (Join-Path $PSScriptRoot 'OfflineRepairCommon.ps1')
    }
    catch {
        throw "Get-OfflineBcdStore.ps1 could not load its dependency OfflineRepairCommon.ps1 from '$PSScriptRoot': $($_.Exception.Message)"
    }
}

function Assert-OfflineBcdStorePath {
    <#
    .SYNOPSIS
        Throws unless a BCD store path is a plausible offline store outside the rescue VM's
        own system drive.

    .DESCRIPTION
        The rescue VM boots from its own BCD store. Rewriting that store instead of the
        broken VM's makes the rescue VM itself unbootable, which is unrecoverable without
        a second rescue pass. Because the drive letter reaches this file from a chain of
        upstream lookups that can degrade quietly, the check is made here, at the point of
        use, rather than trusted from the caller.

        Where the shared offline root is bound (Get-OfflineWindowsDisk does this), the
        store must also fall under it. That covers the case where a store sits on some
        third attached disk that is neither the rescue VM's nor the one being repaired.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if ([string]::IsNullOrWhiteSpace($StorePath)) {
        throw 'Refusing to run bcdedit: the store path is empty.'
    }

    if ($StorePath -notmatch '^[A-Za-z]:\\') {
        throw "Refusing to run bcdedit against '$StorePath': it is not rooted on a drive, so it would resolve against the rescue VM's current directory."
    }

    $storeDrive = $StorePath.Substring(0, 2).ToUpperInvariant()
    $rescueDrive = ''
    if ($env:SystemDrive) { $rescueDrive = $env:SystemDrive.TrimEnd('\').ToUpperInvariant() }

    if ($rescueDrive -and $storeDrive -eq $rescueDrive) {
        throw "Refusing to run bcdedit against '$StorePath': it is on the rescue VM's own system drive ($rescueDrive). Modifying it would break the rescue VM's own boot configuration."
    }

    # Only enforced once a root is bound; some callers legitimately inspect a store before
    # the offline volume has been selected.
    if ((Get-Command Get-OfflineRepairRoot -ErrorAction SilentlyContinue) -and (Get-OfflineRepairRoot)) {
        Assert-OfflineTarget -Path $StorePath -Action 'run bcdedit against'
    }
}

function Invoke-BcdEnum {
    <#
    .SYNOPSIS
        Runs a read-only bcdedit enumeration and reports whether it actually succeeded.

    .DESCRIPTION
        bcdedit writes its errors to stdout and returns a non-zero exit code. Merging the
        streams and ignoring the code makes "the store could not be opened" indistinguishable
        from "the store is empty", and an empty inventory is what makes a repair script decide
        the store must be rebuilt. The exit code is therefore returned alongside the text so
        callers can tell the two apart.

    .OUTPUTS
        PSCustomObject with Success, ExitCode and Text.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]]$Arguments
    )

    $raw = & bcdedit.exe /store $StorePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    return [PSCustomObject]@{
        Success  = ($exitCode -eq 0)
        ExitCode = $exitCode
        Text     = ($raw -join "`n")
    }
}

function Get-BcdStorePath {
    <#
    .SYNOPSIS
        Returns the BCD store path for a boot drive, based on the firmware generation.

    .PARAMETER Generation
        1 for BIOS/MBR (Gen1), 2 for UEFI/GPT (Gen2).

    .PARAMETER BootDrive
        The drive holding the offline boot partition, for example 'D:'. Only a bare drive
        root is accepted. An unvalidated value here is how a store path silently becomes
        the rescue VM's own, so the pattern is enforced rather than trimmed into shape.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$Generation,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z]:\\?$')]
        [string]$BootDrive
    )

    $BootDrive = $BootDrive.TrimEnd('\')
    if ($Generation -eq 1) { return "$BootDrive\Boot\BCD" }
    return "$BootDrive\EFI\Microsoft\Boot\BCD"
}

function Get-BcdStoreItem {
    <#
    .SYNOPSIS
        Returns the FileInfo for a BCD store, including Hidden + System stores.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if ([string]::IsNullOrWhiteSpace($StorePath)) { return $null }

    $item = Get-Item -LiteralPath $StorePath -ErrorAction SilentlyContinue
    if ($item) { return $item }

    # Windows Server 2012 R2 commonly marks the BCD store Hidden + System.
    # Retry with -Force so healthy legacy stores are not reported as missing.
    return Get-Item -LiteralPath $StorePath -Force -ErrorAction SilentlyContinue
}

function Test-BcdStorePath {
    <#
    .SYNOPSIS
        Returns $true when a BCD store exists at the given path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    return $null -ne (Get-BcdStoreItem -StorePath $StorePath)
}

function Get-BcdTextSection {
    <#
    .SYNOPSIS
        Splits bcdedit output into Title/Body sections using its underline separators.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text
    )

    $sections = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lines = @($Text -split "`r?`n")
    $lineIndex = 0

    while ($lineIndex -lt $lines.Count) {
        $currentLine = $lines[$lineIndex]
        $nextLine = if (($lineIndex + 1) -lt $lines.Count) { $lines[$lineIndex + 1] } else { '' }

        if (-not [string]::IsNullOrWhiteSpace($currentLine) -and $nextLine -match '^-{3,}\s*$') {
            $title = $currentLine.Trim()
            $lineIndex += 2
            $bodyLines = [System.Collections.Generic.List[string]]::new()

            while ($lineIndex -lt $lines.Count) {
                $probeLine = $lines[$lineIndex]
                $probeNextLine = if (($lineIndex + 1) -lt $lines.Count) { $lines[$lineIndex + 1] } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($probeLine) -and $probeNextLine -match '^-{3,}\s*$') { break }
                [void]$bodyLines.Add($probeLine)
                $lineIndex++
            }

            $body = (($bodyLines | Where-Object { $null -ne $_ }) -join "`n").Trim()
            if (-not [string]::IsNullOrWhiteSpace($body)) {
                [void]$sections.Add([PSCustomObject]@{ Title = $title; Body = $body })
            }
            continue
        }
        $lineIndex++
    }

    return @($sections)
}

function ConvertTo-BcdLoaderObject {
    <#
    .SYNOPSIS
        Parses the common loader fields out of a bcdedit section body.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Body,
        [Parameter(Mandatory = $false)][string]$Title = ''
    )

    $identifier = [regex]::Match($Body, '(?im)^\s*identifier\s+(.+)$').Groups[1].Value.Trim()
    if ([string]::IsNullOrWhiteSpace($identifier)) { return $null }

    $description = [regex]::Match($Body, '(?im)^\s*description\s+(.+)$').Groups[1].Value.Trim()
    $device = [regex]::Match($Body, '(?im)^\s*device\s+(.+)$').Groups[1].Value.Trim()
    $osdevice = [regex]::Match($Body, '(?im)^\s*osdevice\s+(.+)$').Groups[1].Value.Trim()
    $path = [regex]::Match($Body, '(?im)^\s*path\s+(.+)$').Groups[1].Value.Trim()
    $systemroot = [regex]::Match($Body, '(?im)^\s*systemroot\s+(.+)$').Groups[1].Value.Trim()

    $isOsLoader = ($Title -match '^Windows Boot Loader$') -or ($path -match '(?i)\\winload\.(efi|exe)$')
    if (-not $isOsLoader) { return $null }

    $partitionDrive = ''
    foreach ($bcdValue in @($osdevice, $device)) {
        $partitionMatch = [regex]::Match($bcdValue, '(?im)\bpartition\s*=\s*([A-Z]:)')
        if ($partitionMatch.Success) {
            $partitionDrive = $partitionMatch.Groups[1].Value.ToUpperInvariant()
            break
        }
    }

    return [PSCustomObject]@{
        Identifier     = $identifier
        Description    = $description
        Device         = $device
        OsDevice       = $osdevice
        Path           = $path
        SystemRoot     = $systemroot
        PartitionDrive = $partitionDrive
        IsSetupEntry   = (($description -match '(?i)windows setup|setup') -or ($path -match '(?i)setup'))
    }
}

function Get-BcdInventory {
    <#
    .SYNOPSIS
        Returns a structured view of an offline BCD store.

    .DESCRIPTION
        EnumSucceeded distinguishes a store that genuinely has no loader entries from one
        that could not be read at all. Callers that rebuild a store on the strength of an
        empty inventory must check it, otherwise a locked or access-denied store looks
        identical to an empty one and gets needlessly rebuilt.

    .OUTPUTS
        PSCustomObject with StorePath, Exists, EnumSucceeded, EnumExitCode, RawText,
        DefaultId, Timeout, DisplayBootMenu and Loaders.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    $inventory = [ordered]@{
        StorePath       = $StorePath
        Exists          = $false
        EnumSucceeded   = $false
        EnumExitCode    = $null
        RawText         = ''
        DefaultId       = ''
        Timeout         = ''
        DisplayBootMenu = ''
        Loaders         = @()
    }

    if (-not (Test-BcdStorePath -StorePath $StorePath)) {
        return [PSCustomObject]$inventory
    }

    $inventory.Exists = $true

    $enum = Invoke-BcdEnum -StorePath $StorePath -Arguments @('/enum', 'all')
    $inventory.EnumSucceeded = $enum.Success
    $inventory.EnumExitCode = $enum.ExitCode
    $inventory.RawText = $enum.Text

    if (-not $enum.Success) {
        Add-OfflineRepairLog -Level Warning -Message "bcdedit could not enumerate $StorePath (exit $($enum.ExitCode)): $($enum.Text.Trim())"
        return [PSCustomObject]$inventory
    }

    $loaders = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($section in (Get-BcdTextSection -Text $inventory.RawText)) {
        $title = $section.Title
        $body = $section.Body

        if ($title -match '^Windows Boot Manager$' -or $body -match '(?im)^\s*identifier\s+\{bootmgr\}\s*$') {
            $inventory.DefaultId = [regex]::Match($body, '(?im)^\s*default\s+(.+)$').Groups[1].Value.Trim()
            $inventory.Timeout = [regex]::Match($body, '(?im)^\s*timeout\s+(.+)$').Groups[1].Value.Trim()
            $inventory.DisplayBootMenu = [regex]::Match($body, '(?im)^\s*displaybootmenu\s+(.+)$').Groups[1].Value.Trim()
            continue
        }

        $loader = ConvertTo-BcdLoaderObject -Body $body -Title $title
        if ($loader) { [void]$loaders.Add($loader) }
    }

    $inventory.Loaders = @($loaders)
    return [PSCustomObject]$inventory
}

function Get-BcdLoaderDetail {
    <#
    .SYNOPSIS
        Returns the parsed details of a single BCD loader entry.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][string]$Identifier
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) { return $null }

    $enum = Invoke-BcdEnum -StorePath $StorePath -Arguments @('/enum', $Identifier)
    if (-not $enum.Success) {
        Add-OfflineRepairLog -Level Warning -Message "bcdedit could not enumerate $Identifier in $StorePath (exit $($enum.ExitCode))."
        return $null
    }

    $text = $enum.Text
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $device = [regex]::Match($text, '(?im)^\s*device\s+(.+)$').Groups[1].Value.Trim()
    $osdevice = [regex]::Match($text, '(?im)^\s*osdevice\s+(.+)$').Groups[1].Value.Trim()
    $path = [regex]::Match($text, '(?im)^\s*path\s+(.+)$').Groups[1].Value.Trim()
    $systemroot = [regex]::Match($text, '(?im)^\s*systemroot\s+(.+)$').Groups[1].Value.Trim()
    $description = [regex]::Match($text, '(?im)^\s*description\s+(.+)$').Groups[1].Value.Trim()

    $partitionDrive = ''
    foreach ($bcdValue in @($osdevice, $device)) {
        $partitionMatch = [regex]::Match($bcdValue, '(?im)\bpartition\s*=\s*([A-Z]:)')
        if ($partitionMatch.Success) {
            $partitionDrive = $partitionMatch.Groups[1].Value.ToUpperInvariant()
            break
        }
    }

    return [PSCustomObject]@{
        Identifier     = $Identifier
        Description    = $description
        Device         = $device
        OsDevice       = $osdevice
        Path           = $path
        SystemRoot     = $systemroot
        PartitionDrive = $partitionDrive
        RawText        = $text
        IsSetupEntry   = (($description -match '(?i)windows setup|setup') -or ($path -match '(?i)setup'))
    }
}

function Select-BcdPreferredLoader {
    <#
    .SYNOPSIS
        Picks the real OS loader from a set of loaders, preferring the default entry
        and always skipping Windows Setup entries.
    #>
    param(
        [Parameter(Mandatory = $false)][PSCustomObject[]]$Loaders = @(),
        [Parameter(Mandatory = $false)][string]$DefaultId = ''
    )

    $preferred = @($Loaders | Where-Object { $_.Identifier -eq $DefaultId -and -not $_.IsSetupEntry } | Select-Object -First 1)
    if (-not $preferred) { $preferred = @($Loaders | Where-Object { -not $_.IsSetupEntry } | Select-Object -First 1) }
    if (-not $preferred) { $preferred = @($Loaders | Select-Object -First 1) }

    if ($preferred) { return $preferred[0] }
    return $null
}

function Get-BcdPreferredOsGuid {
    <#
    .SYNOPSIS
        Returns the GUID of the preferred (non-setup) OS loader in an offline store.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) { return '' }

    $inventory = Get-BcdInventory -StorePath $StorePath
    $preferred = Select-BcdPreferredLoader -Loaders @($inventory.Loaders) -DefaultId $inventory.DefaultId

    if ($preferred) { return [string]$preferred.Identifier }
    return ''
}

function Get-BcdBootLoaderId {
    <#
    .SYNOPSIS
        Resolves the identifier to pass to bcdedit for the real OS loader entry.

    .DESCRIPTION
        Returns the {default} alias only when it unambiguously refers to the preferred
        loader, otherwise the explicit GUID. Falls back to parsing 'bcdedit /enum' when
        the structured lookup finds nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) {
        Add-OfflineRepairLog -Level Warning -Message "BCD store not found at $StorePath."
        return $null
    }

    $inventory = Get-BcdInventory -StorePath $StorePath
    $preferredLoader = Select-BcdPreferredLoader -Loaders @($inventory.Loaders) -DefaultId $inventory.DefaultId

    $identifier = ''
    if ($preferredLoader) {
        $canUseDefaultAlias = $false
        if ($inventory.DefaultId) {
            if ($preferredLoader.Identifier -eq $inventory.DefaultId) {
                $canUseDefaultAlias = $true
            }
            elseif ($inventory.DefaultId -eq '{default}' -and @($inventory.Loaders).Count -eq 1) {
                $canUseDefaultAlias = $true
            }
        }
        $identifier = if ($canUseDefaultAlias) { [string]$inventory.DefaultId } else { [string]$preferredLoader.Identifier }
    }

    if ([string]::IsNullOrWhiteSpace($identifier)) {
        $enum = Invoke-BcdEnum -StorePath $StorePath -Arguments @('/enum')
        if (-not $enum.Success) {
            Add-OfflineRepairLog -Level Warning -Message "bcdedit could not enumerate $StorePath (exit $($enum.ExitCode)), so the boot loader identifier is unknown."
            return $null
        }

        $fallbackIdentifier = [regex]::Match($enum.Text, '(?is)Windows Boot Loader.*?^\s*identifier\s+([^\r\n]+)',
            [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value.Trim()

        if (-not [string]::IsNullOrWhiteSpace($fallbackIdentifier)) { return $fallbackIdentifier }

        Add-OfflineRepairLog -Level Warning -Message "Could not determine the boot loader identifier in $StorePath."
        return $null
    }

    return $identifier
}

function Backup-BcdStore {
    <#
    .SYNOPSIS
        Copies a BCD store before it is modified, so a failed repair can be reverted.

    .DESCRIPTION
        The copy is verified before success is reported. A backup that was never written
        is worse than no backup at all, because the caller goes on to modify the store
        believing it can roll back.

    .OUTPUTS
        The full path of the backup file.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) { throw "BCD store not found at $StorePath." }

    $source = Get-BcdStoreItem -StorePath $StorePath
    $backup = "$StorePath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $StorePath -Destination $backup -Force -ErrorAction Stop

    $copy = Get-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    if (-not $copy) { throw "The BCD store backup was reported as written but $backup does not exist." }
    if ($source -and $copy.Length -ne $source.Length) {
        throw "The BCD store backup at $backup is $($copy.Length) bytes but the store is $($source.Length) bytes."
    }

    Add-OfflineRepairLog -Level Info -Message "Backed up the BCD store to $backup"
    return $backup
}

function Invoke-BcdEdit {
    <#
    .SYNOPSIS
        Runs a bcdedit command against an offline store and validates the exit code.

    .DESCRIPTION
        bcdedit is invoked directly, never through cmd.exe, and the arguments are passed
        as an array. Identifiers and element names reaching this function are parsed out
        of the broken VM's own store, so they are untrusted: building a single command
        line from them and handing it to a shell would let a crafted store run arbitrary
        commands on the rescue VM as SYSTEM. Passing an array keeps each element a literal
        argument to bcdedit no matter what it contains.

        The store path is validated and a store on the rescue VM's own system drive is
        refused, so a degraded caller cannot rewrite the boot configuration that the
        rescue VM is running from.

    .PARAMETER StorePath
        Full path to the offline BCD store.

    .PARAMETER Arguments
        The bcdedit arguments that follow '/store <path>', one array element per argument.

    .OUTPUTS
        PSCustomObject with Success, ExitCode and Output.

    .EXAMPLE
        Invoke-BcdEdit -StorePath $store -Arguments @('/set', $loaderId, 'hypervisorlaunchtype', 'Off')
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]]$Arguments
    )

    Assert-OfflineBcdStorePath -StorePath $StorePath

    if (-not (Test-BcdStorePath -StorePath $StorePath)) {
        throw "Refusing to run bcdedit: no BCD store exists at $StorePath."
    }

    Add-OfflineRepairLog -Level Info -Message "Running: bcdedit.exe /store `"$StorePath`" $($Arguments -join ' ')"

    $output = & bcdedit.exe /store $StorePath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $trimmed = $output.Trim()

    if ($exitCode -ne 0) {
        Add-OfflineRepairLog -Level Warning -Message "bcdedit returned exit code ${exitCode}: $trimmed"
    }
    elseif ($trimmed) {
        Add-OfflineRepairLog -Level Info -Message $trimmed
    }

    return [PSCustomObject]@{
        Success  = ($exitCode -eq 0)
        ExitCode = $exitCode
        Output   = $trimmed
    }
}
