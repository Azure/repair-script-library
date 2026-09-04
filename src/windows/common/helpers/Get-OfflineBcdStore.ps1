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
      Get-BcdInventory          Parse the whole store into a structured object.
      Get-BcdLoaderDetails      Parse a single loader entry.
      Get-BcdBootLoaderId       Resolve the identifier of the real (non-setup) OS loader.
      Get-BcdPreferredOsGuid    Resolve the preferred OS loader GUID.
      Backup-BcdStore           Copy the store before it is modified.
      Invoke-BcdEdit            Run a bcdedit command against the offline store.

.NOTES
    Name:   Get-OfflineBcdStore.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.
    Every function targets an offline store explicitly. None of them ever modifies the
    rescue VM's own BCD.

.VERSION
    v1.0: Initial version.
#>

if (-not (Get-Command Add-OfflineRepairLog -ErrorAction SilentlyContinue)) {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
}

function Get-BcdStorePath {
    <#
    .SYNOPSIS
        Returns the BCD store path for a boot drive, based on the firmware generation.

    .PARAMETER Generation
        1 for BIOS/MBR (Gen1), 2 for UEFI/GPT (Gen2).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$Generation,
        [Parameter(Mandatory = $true)][string]$BootDrive
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

function Get-BcdTextSections {
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

    .OUTPUTS
        PSCustomObject with StorePath, RawText, DefaultId, Timeout, DisplayBootMenu and Loaders.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    $inventory = [ordered]@{
        StorePath       = $StorePath
        RawText         = ''
        DefaultId       = ''
        Timeout         = ''
        DisplayBootMenu = ''
        Loaders         = @()
    }

    if (-not (Test-BcdStorePath -StorePath $StorePath)) {
        return [PSCustomObject]$inventory
    }

    $raw = & bcdedit.exe /store $StorePath /enum all 2>&1
    $inventory.RawText = ($raw -join "`n")

    $loaders = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($section in (Get-BcdTextSections -Text $inventory.RawText)) {
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

function Get-BcdLoaderDetails {
    <#
    .SYNOPSIS
        Returns the parsed details of a single BCD loader entry.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][string]$Identifier
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) { return $null }

    $raw = & bcdedit.exe /store $StorePath /enum $Identifier 2>&1
    $text = ($raw -join "`n")
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
        $rawEnum = & bcdedit.exe /store $StorePath /enum 2>&1
        $enumText = ($rawEnum -join "`n")
        $fallbackIdentifier = [regex]::Match($enumText, '(?is)Windows Boot Loader.*?^\s*identifier\s+([^\r\n]+)',
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

    .OUTPUTS
        The full path of the backup file.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    if (-not (Test-BcdStorePath -StorePath $StorePath)) { throw "BCD store not found at $StorePath." }

    $backup = "$StorePath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $StorePath -Destination $backup -Force
    Add-OfflineRepairLog -Level Info -Message "Backed up the BCD store to $backup"
    return $backup
}

function Invoke-BcdEdit {
    <#
    .SYNOPSIS
        Runs a bcdedit command against an offline store and validates the exit code.

    .PARAMETER Command
        The bcdedit arguments that follow '/store <path>', for example:
        '/set {default} recoveryenabled No'

    .OUTPUTS
        PSCustomObject with Success, ExitCode and Output.

    .EXAMPLE
        Invoke-BcdEdit -StorePath $store -Command "/set $loaderId hypervisorlaunchtype Off"
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][string]$Command
    )

    $fullCmd = "bcdedit.exe /store `"$StorePath`" $Command"
    Add-OfflineRepairLog -Level Info -Message "Running: $fullCmd"

    $output = & cmd.exe /c $fullCmd 2>&1 | Out-String
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
