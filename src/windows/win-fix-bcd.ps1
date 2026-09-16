#########################################################################################################
#
# .SYNOPSIS
#   Repairs the boot configuration of an offline Windows disk so the firmware can find and start
#   Windows again. Targets the "Boot Configuration Data" family of failures, not a damaged partition.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". It answers the
#   question "why can the boot manager not start this Windows installation" using only evidence read
#   from the offline disk, and then changes only what the evidence names.
#
#   The script repairs in two tiers, and which tier runs is decided by the evidence:
#
#     Tier 1, targeted. The BCD store is structurally sound and individual values are wrong, for
#     example the loader points at a partition that no longer exists after a disk swap. Each wrong
#     value is corrected with its own "bcdedit /set". Everything the store carries that is not a
#     finding is left exactly as it was, so serial console settings, custom timeouts and any other
#     deliberate configuration survive the repair.
#
#     Tier 2, rebuild. The store is missing, unreadable, or carries no Windows Boot Loader entry at
#     all, so there is nothing to correct. The store is rebuilt with bcdboot and the Azure serial
#     console settings are applied to the fresh store. This is deliberately the second choice: a
#     rebuild discards any customisation the old store held.
#
#   Causes detected:
#     1. The BCD store is missing or zero length.
#     2. The store carries no Windows Boot Loader entry.
#     3. The boot manager binary is missing or zero length on the system partition
#        (bootmgr on Gen1, EFI\Microsoft\Boot\bootmgfw.efi on Gen2).
#     4. The loader "device" or "osdevice" reads "unknown", which is what a BCD written against a
#        different disk layout looks like after the disk is attached somewhere else.
#     5. The loader "device" or "osdevice" names a partition other than the Windows partition.
#     6. The loader "path" is not the winload binary for this firmware generation.
#     7. The loader "systemroot" does not match the Windows directory actually on the disk.
#     8. The default boot entry is unset, unresolvable, or points at a Windows Setup entry, so the
#        firmware starts something that is not this Windows installation.
#     9. The {bootmgr} entry's own device or path is wrong.
#    10. imcdevice or imchivename is present, which bugchecks the guest with 0x67.
#    11. Gen1 only: the boot partition is missing its Active flag, so the BIOS never reads its
#        boot sector.
#
#   Reported but never repaired here:
#     - The winload binary named by the BCD is missing from the Windows partition. That is a
#       damaged Windows installation rather than a boot configuration fault, and rewriting the BCD
#       to point at a file that is not there fixes nothing. Use win-sfc-sf-corruption.
#     - No boot partition exists at all. There is nothing to write a BCD store to. That is the
#       win-fix-boot-partition scenario.
#     - BCD-Template is missing from the Windows installation while a rebuild is required. bcdboot
#       seeds a new store from that file and cannot run without it. The script stops before it
#       renames anything, so the existing store is left intact.
#
# .RESOLVES
#   0xC000000E  "A required device isn't connected or can't be accessed"
#   0xC000000F  "The application or operating system couldn't be loaded because a required file
#               is missing or contains errors" - the loader path names a binary that is not there
#   0xC0000225  "The boot selection failed because a required device is inaccessible"
#   0xC0000034  "The Boot Configuration Data file is missing some required information"
#   "The Boot Configuration Data file is missing" / "Boot Device Not Found" after a disk swap,
#   a restore from backup, an interrupted in place upgrade, or a botched partition change.
#
# .PARAMETER detectOnly
#   "true" to report the findings and make no writes at all. Defaults to "false".
#
# .PARAMETER rebuild
#   "true" to force the tier 2 rebuild even when the store could be repaired in place. Use it when
#   the store is so inconsistent that targeted repair is not trusted. Defaults to "false", because
#   a rebuild discards customisation that a targeted repair preserves.
#
# .PARAMETER revert
#   "true" to restore the BCD store this script backed up on its last run and undo the Active flag
#   change, using the manifest it wrote. Defaults to "false".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-bcd --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-bcd --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-bcd --parameters rebuild=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-bcd --parameters revert=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Every bcdedit call targets the offline store explicitly with /store. The rescue VM's own boot
#   configuration is never read and never written.
#
#   The store is copied to "<store>.bak-<timestamp>" before the first write, and the path is
#   recorded in <windowsDrive>\win-fix-bcd-revert.json together with any Active flag
#   change, so -revert puts both back.
#
#   Stale Windows Setup loader entries are not deleted. A leftover entry is harmless while the
#   default points at the real installation, so the repair moves the default instead of removing
#   the operator's entries. A rebuild collapses them because it starts a fresh store.
#
#   Related scenarios, deliberately not folded in because they are different problems:
#     win-fix-boot-partition    the system partition itself is damaged or missing
#     win-toggle-safe-mode      the safeboot flag is set
#     win-fix-code-integrity    testsigning or nointegritychecks is set
#     win-LKGC                  boot the previous control set instead
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$rebuild = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Get-OfflineBcdStore.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRebuildForced = ($rebuild -eq 'true')
$isRevert = ($revert -eq 'true')

function Write-OperatorLog {
    <#
    .SYNOPSIS
        Flushes buffered helper narration, keeping the returned log inside its budget.

    .DESCRIPTION
        az vm repair run returns at most 4096 characters and keeps the tail, so step by
        step narration goes to the detail log on disk only. Warnings and errors are still
        surfaced, because those are the lines that change what the operator does next.

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

# A BCD value that reads "unknown" is bcdedit telling us the device it recorded cannot be resolved
# on this machine. It is the signature of a store written against a different disk layout.
$script:UnknownDevicePattern = '(?i)\bunknown\b'

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.

    .PARAMETER Tier
        'Targeted' when a bcdedit /set corrects it, 'Rebuild' when only bcdboot can.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)][ValidateSet('Targeted', 'Rebuild', 'None')][string]$Tier = 'Targeted',
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Tier       = $Tier
        Repaired   = $false
        Data       = $Data
    }
}

function Get-ExpectedBootState {
    <#
    .SYNOPSIS
        Derives what this disk's boot configuration should say, from the disk itself.

    .DESCRIPTION
        Nothing here is a constant guess. The Windows directory name is read from the path the disk
        helper resolved, so an installation in \Windows.old or a non standard directory produces the
        systemroot that actually matches it rather than a hard coded '\Windows'.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $windowsDirectory = Split-Path -Path $Offline.WindowsPath -Leaf
    $systemRoot = "\$windowsDirectory"
    $loaderFile = if ($Offline.Generation -eq 2) { 'winload.efi' } else { 'winload.exe' }

    return [PSCustomObject]@{
        SystemRoot      = $systemRoot
        LoaderPath      = "$systemRoot\System32\$loaderFile"
        LoaderFile      = (Join-OfflinePath -Root $Offline.WindowsPath -ChildPath "System32\$loaderFile")
        DevicePartition = "partition=$($Offline.WindowsDrive)"
        BootMgrPath     = if ($Offline.Generation -eq 2) { '\EFI\Microsoft\Boot\bootmgfw.efi' } else { '\bootmgr' }
        BootMgrDevice   = "partition=$($Offline.BootDrive)"
        BootMgrFile     = if ($Offline.Generation -eq 2) {
            Join-OfflinePath -Root $Offline.BootDrive -ChildPath 'EFI\Microsoft\Boot\bootmgfw.efi'
        }
        else {
            Join-OfflinePath -Root $Offline.BootDrive -ChildPath 'bootmgr'
        }
    }
}

function Get-BootManagerFinding {
    <#
    .SYNOPSIS
        Checks that the binary the firmware actually starts is present on the system partition.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Expected
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $signature = Test-OfflineFileSignature -FilePath $Expected.BootMgrFile
    if ($signature.Status -eq 'FileNotFound') {
        [void]$findings.Add((New-Finding -Cause 'BootManagerBinary' -Item $Expected.BootMgrFile `
                    -Message "The boot manager binary is missing: $($Expected.BootMgrFile). The firmware has nothing to start." `
                    -Tier 'Rebuild'))
    }
    elseif ($signature.Status -eq 'ZeroByte') {
        [void]$findings.Add((New-Finding -Cause 'BootManagerBinary' -Item $Expected.BootMgrFile `
                    -Message "The boot manager binary is zero length: $($Expected.BootMgrFile)." `
                    -Tier 'Rebuild'))
    }
    elseif ($signature.Confidence -eq 'High' -and -not $signature.IsMicrosoft) {
        # Authenticode answered definitively and the answer was bad: an invalid signature, a
        # hash mismatch, or a valid signature belonging to someone other than Microsoft. That
        # is real evidence of a damaged or replaced boot manager, so it escalates to Rebuild.
        [void]$findings.Add((New-Finding -Cause 'BootManagerBinary' -Item $Expected.BootMgrFile `
                    -Message "The boot manager binary is not a Microsoft file (status $($signature.Status)): $($Expected.BootMgrFile)." `
                    -Tier 'Rebuild'))
    }
    elseif (-not $signature.IsLikelyMicrosoft) {
        # No cryptographic answer and the file does not identify itself as Microsoft either.
        [void]$findings.Add((New-Finding -Cause 'BootManagerBinary' -Item $Expected.BootMgrFile `
                    -Message "The boot manager binary could not be identified as a Microsoft file (status $($signature.Status)): $($Expected.BootMgrFile)." `
                    -Tier 'Rebuild'))
    }
    elseif ($signature.Confidence -ne 'High') {
        # The binary says it is Microsoft but nothing proved it. This is the ordinary result
        # for a catalog signed inbox binary, because the catalogs that would verify it live on
        # the offline image and are not registered on the rescue VM. Rebuilding the store on
        # that signal alone would fire on healthy VMs, so it is reported and nothing more.
        Add-OfflineRepairLog -Level Warning -Message "The boot manager binary at $($Expected.BootMgrFile) reports itself as Microsoft but could not be cryptographically verified (status $($signature.Status)). Continuing, because an offline image's catalogs are not available to the rescue VM."
    }
    else {
        Add-OfflineRepairLog -Level Info -Message "Boot manager binary present: $($Expected.BootMgrFile) ($($signature.Status))."
    }

    # The removable media fallback. Azure Gen2 guests boot through the firmware entry that names
    # bootmgfw.efi, so a missing fallback does not stop this VM. It is still worth naming, because a
    # cleared NVRAM boot entry makes the fallback the only path left.
    if ($Offline.Generation -eq 2) {
        $fallback = Join-OfflinePath -Root $Offline.BootDrive -ChildPath 'EFI\Boot\bootx64.efi'
        if (-not (Test-OfflinePath $fallback)) {
            Add-OfflineRepairLog -Level Warning -Message "The removable media fallback loader $fallback is missing. The firmware boot entry is the only remaining path to bootmgfw.efi."
        }
    }

    return @($findings)
}

function Get-BcdStoreFinding {
    <#
    .SYNOPSIS
        Checks the store file itself, before anything tries to parse it.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $item = Get-BcdStoreItem -StorePath $Offline.BcdStorePath

    if (-not $item) {
        [void]$findings.Add((New-Finding -Cause 'BcdStore' -Item $Offline.BcdStorePath `
                    -Message "The BCD store is missing: $($Offline.BcdStorePath)." -Tier 'Rebuild'))
        return @($findings)
    }

    if ($item.Length -eq 0) {
        [void]$findings.Add((New-Finding -Cause 'BcdStore' -Item $Offline.BcdStorePath `
                    -Message "The BCD store is zero length: $($Offline.BcdStorePath)." -Tier 'Rebuild'))
        return @($findings)
    }

    Add-OfflineRepairLog -Level Info -Message "BCD store present: $($Offline.BcdStorePath) ($($item.Length) bytes)."
    return @($findings)
}

function Get-BcdEntryFinding {
    <#
    .SYNOPSIS
        Compares every boot critical value in the store against what this disk says it should be.

    .DESCRIPTION
        Only values that stop the guest booting are treated as faults. Anything else the store
        carries is left alone, so a deliberately customised configuration is never rewritten.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Inventory
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $loaders = @($Inventory.Loaders)

    if ($loaders.Count -eq 0) {
        [void]$findings.Add((New-Finding -Cause 'BcdLoaderEntry' -Item $Offline.BcdStorePath `
                    -Message 'The BCD store carries no Windows Boot Loader entry, so there is no OS entry to correct.' `
                    -Tier 'Rebuild'))
        return @($findings)
    }

    # imcdevice / imchivename survive an image capture and make the kernel load a hive that is not
    # there. The guest bugchecks 0x67 CONFIG_INITIALIZATION_FAILED before anything else can be seen.
    foreach ($imcValue in @('imcdevice', 'imchivename')) {
        if ($Inventory.RawText -match "(?im)^\s*$imcValue\s+\S") {
            [void]$findings.Add((New-Finding -Cause 'BcdImcHive' -Item $imcValue `
                        -Message "The BCD store carries '$imcValue', which bugchecks the guest with 0x67 CONFIG_INITIALIZATION_FAILED." `
                        -Data $imcValue))
        }
    }

    $realLoaders = @($loaders | Where-Object { -not $_.IsSetupEntry })
    $setupLoaders = @($loaders | Where-Object { $_.IsSetupEntry })

    if ($setupLoaders.Count -gt 0) {
        $setupSummary = ($setupLoaders | ForEach-Object { if ($_.Description) { $_.Description } else { $_.Identifier } }) -join '; '
        Add-OfflineRepairLog -Level Warning -Message "The store carries $($setupLoaders.Count) Windows Setup loader entry(ies): $setupSummary. They are left in place; only the default entry matters for boot."
    }
    if ($loaders.Count -gt 1) {
        $loaderSummary = ($loaders | ForEach-Object {
                $description = if ($_.Description) { $_.Description } else { $_.Identifier }
                if ($_.PartitionDrive) { "$description@$($_.PartitionDrive)" } else { $description }
            }) -join '; '
        Add-OfflineRepairLog -Level Warning -Message "The store carries $($loaders.Count) Windows Boot Loader entries: $loaderSummary."
    }

    $preferred = Select-BcdPreferredLoader -Loaders $loaders -DefaultId $Inventory.DefaultId
    if (-not $preferred) {
        [void]$findings.Add((New-Finding -Cause 'BcdLoaderEntry' -Item $Offline.BcdStorePath `
                    -Message 'No usable Windows Boot Loader entry could be selected from the store.' -Tier 'Rebuild'))
        return @($findings)
    }

    # The default is what the firmware actually starts. A store full of correct entries still fails
    # to boot when the default names a Setup entry or an identifier that is no longer present.
    $defaultId = "$($Inventory.DefaultId)".Trim()
    $defaultResolves = $false
    if ($defaultId) {
        $defaultResolves = ($defaultId -eq '{default}') -or (@($loaders | Where-Object { $_.Identifier -eq $defaultId }).Count -gt 0)
    }
    $defaultEntry = @($loaders | Where-Object { $_.Identifier -eq $defaultId } | Select-Object -First 1)

    if (-not $defaultId) {
        [void]$findings.Add((New-Finding -Cause 'BcdDefaultEntry' -Item '{bootmgr} default' `
                    -Message "The boot manager has no default entry set. Expected the Windows loader $($preferred.Identifier)." `
                    -Data $preferred.Identifier))
    }
    elseif (-not $defaultResolves) {
        [void]$findings.Add((New-Finding -Cause 'BcdDefaultEntry' -Item '{bootmgr} default' `
                    -Message "The default boot entry is '$defaultId', which is not present in the store. Expected the Windows loader $($preferred.Identifier)." `
                    -Data $preferred.Identifier))
    }
    elseif ($defaultEntry.Count -gt 0 -and $defaultEntry[0].IsSetupEntry -and $realLoaders.Count -gt 0) {
        [void]$findings.Add((New-Finding -Cause 'BcdDefaultEntry' -Item '{bootmgr} default' `
                    -Message "The default boot entry is the Windows Setup entry '$($defaultEntry[0].Description)'. The firmware starts Setup instead of Windows. Expected $($preferred.Identifier)." `
                    -Data $preferred.Identifier))
    }

    # The {bootmgr} entry's own device and path. A store that points its boot manager at a partition
    # that no longer resolves fails before any OS entry is read.
    $bootMgrSection = @(Get-BcdTextSection -Text $Inventory.RawText | Where-Object {
            $_.Title -match '^Windows Boot Manager$' -or $_.Body -match '(?im)^\s*identifier\s+\{bootmgr\}\s*$'
        } | Select-Object -First 1)
    if ($bootMgrSection.Count -gt 0) {
        $bootMgrDevice = [regex]::Match($bootMgrSection[0].Body, '(?im)^\s*device\s+(.+)$').Groups[1].Value.Trim()
        $bootMgrPath = [regex]::Match($bootMgrSection[0].Body, '(?im)^\s*path\s+(.+)$').Groups[1].Value.Trim()

        if ($bootMgrDevice -match $script:UnknownDevicePattern) {
            [void]$findings.Add((New-Finding -Cause 'BcdBootManagerValue' -Item '{bootmgr} device' `
                        -Message "The boot manager device reads '$bootMgrDevice'. Expected $($Expected.BootMgrDevice)." `
                        -Data @{ Identifier = '{bootmgr}'; Value = 'device'; Expected = $Expected.BootMgrDevice }))
        }
        if ($bootMgrPath -and -not [string]::Equals($bootMgrPath, $Expected.BootMgrPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$findings.Add((New-Finding -Cause 'BcdBootManagerValue' -Item '{bootmgr} path' `
                        -Message "The boot manager path is '$bootMgrPath'. Expected '$($Expected.BootMgrPath)'." `
                        -Data @{ Identifier = '{bootmgr}'; Value = 'path'; Expected = $Expected.BootMgrPath }))
        }
    }

    # The preferred loader's own values, which is where a disk swap does its damage.
    $loaderId = $preferred.Identifier
    $checks = @(
        @{ Value = 'device'; Actual = $preferred.Device; Expected = $Expected.DevicePartition; Compare = 'Partition' },
        @{ Value = 'osdevice'; Actual = $preferred.OsDevice; Expected = $Expected.DevicePartition; Compare = 'Partition' },
        @{ Value = 'path'; Actual = $preferred.Path; Expected = $Expected.LoaderPath; Compare = 'Exact' },
        @{ Value = 'systemroot'; Actual = $preferred.SystemRoot; Expected = $Expected.SystemRoot; Compare = 'Exact' }
    )

    foreach ($check in $checks) {
        $actual = "$($check.Actual)".Trim()

        if ($check.Compare -eq 'Partition') {
            if ($actual -match $script:UnknownDevicePattern) {
                [void]$findings.Add((New-Finding -Cause 'BcdLoaderValue' -Item "$($check.Value)" `
                            -Message "The loader $($check.Value) reads '$actual', which means the partition it was written for cannot be resolved on this disk. Expected $($check.Expected)." `
                            -Data @{ Identifier = $loaderId; Value = $check.Value; Expected = $check.Expected }))
                continue
            }
            # A ramdisk or VHD device is a deliberate configuration, not a fault this script owns.
            if ($actual -match '(?i)ramdisk|vhd|locate') {
                Add-OfflineRepairLog -Level Warning -Message "The loader $($check.Value) is '$actual', which is not a plain partition reference. It was left alone."
                continue
            }
            $partitionMatch = [regex]::Match($actual, '(?i)\bpartition\s*=\s*([A-Z]:)')
            if ($partitionMatch.Success) {
                $namedDrive = $partitionMatch.Groups[1].Value.ToUpperInvariant()
                if ($namedDrive -ne $Offline.WindowsDrive.ToUpperInvariant()) {
                    [void]$findings.Add((New-Finding -Cause 'BcdLoaderValue' -Item "$($check.Value)" `
                                -Message "The loader $($check.Value) names partition $namedDrive, but the Windows installation is on $($Offline.WindowsDrive). Expected $($check.Expected)." `
                                -Data @{ Identifier = $loaderId; Value = $check.Value; Expected = $check.Expected }))
                }
            }
            continue
        }

        if (-not $actual) {
            [void]$findings.Add((New-Finding -Cause 'BcdLoaderValue' -Item "$($check.Value)" `
                        -Message "The loader has no $($check.Value) value. Expected '$($check.Expected)'." `
                        -Data @{ Identifier = $loaderId; Value = $check.Value; Expected = $check.Expected }))
            continue
        }
        if (-not [string]::Equals($actual, $check.Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$findings.Add((New-Finding -Cause 'BcdLoaderValue' -Item "$($check.Value)" `
                        -Message "The loader $($check.Value) is '$actual'. Expected '$($check.Expected)'." `
                        -Data @{ Identifier = $loaderId; Value = $check.Value; Expected = $check.Expected }))
        }
    }

    # The file the loader entry names has to exist, or correcting the entry achieves nothing.
    if (-not (Test-OfflinePath $Expected.LoaderFile)) {
        [void]$findings.Add((New-Finding -Cause 'LoaderBinaryMissing' -Item $Expected.LoaderFile `
                    -Message "The OS loader binary is missing from the Windows partition: $($Expected.LoaderFile). This is a damaged Windows installation, not a boot configuration fault, so the BCD was not rewritten to point at a file that is not there. Repair the installation with win-sfc-sf-corruption." `
                    -Repairable $false -Tier 'None'))
    }

    return @($findings)
}

function Get-BootPartitionFlagFinding {
    <#
    .SYNOPSIS
        Gen1 only: without the Active flag the BIOS never reads the partition's boot sector.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Offline.Generation -ne 1) { return @($findings) }

    $bootPartition = Get-BootPartitionObject -Offline $Offline
    if (-not $bootPartition) {
        Add-OfflineRepairLog -Level Warning -Message 'The boot partition object could not be resolved, so the Active flag was not checked.'
        return @($findings)
    }

    if (-not $bootPartition.IsActive) {
        [void]$findings.Add((New-Finding -Cause 'BootPartitionActive' -Item "Disk $($Offline.DiskNumber) partition $($bootPartition.PartitionNumber)" `
                    -Message "The boot partition is not marked Active, so the BIOS has no partition to read a boot sector from." `
                    -Data $bootPartition.PartitionNumber))
    }
    else {
        Add-OfflineRepairLog -Level Info -Message "Boot partition $($bootPartition.PartitionNumber) Active flag is set."
    }

    return @($findings)
}

function Get-BootPartitionObject {
    <#
    .SYNOPSIS
        Resolves the partition object behind the boot drive letter.

    .DESCRIPTION
        Get-Partition never reports a DriveLetter for a partition the disk helper mounted with
        Add-PartitionAccessPath, so the access paths are matched instead.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    if (-not $Offline.BootDrive) { return $null }
    $wanted = $Offline.BootDrive.TrimEnd('\')

    foreach ($partition in (Get-Partition -DiskNumber $Offline.DiskNumber -ErrorAction SilentlyContinue)) {
        foreach ($accessPath in @($partition.AccessPaths)) {
            if ($accessPath -and $accessPath.TrimEnd('\') -eq $wanted) { return $partition }
        }
    }
    return $null
}

function Test-BcdTemplate {
    <#
    .SYNOPSIS
        bcdboot seeds a new store from BCD-Template in the source installation.

    .DESCRIPTION
        Without it bcdboot fails with BFSVC error 0xc000000f and creates nothing. Checking first
        means a rebuild that cannot succeed never gets as far as renaming the existing store.

        A copy is deliberately not taken from the rescue VM. The template carries version specific
        defaults, and seeding a store from a different build produces a guest that boots in ways
        that are hard to diagnose later.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $templatePath = Join-OfflinePath -Root $Offline.WindowsPath -ChildPath 'System32\config\BCD-Template'
    return [PSCustomObject]@{
        Path    = $templatePath
        Present = (Test-OfflinePath $templatePath)
    }
}

function Invoke-TargetedBcdRepair {
    <#
    .SYNOPSIS
        Corrects individual values with bcdedit, leaving everything else in the store untouched.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][PSCustomObject[]]$Findings
    )

    foreach ($finding in $Findings) {
        $command = $null

        switch ($finding.Cause) {
            'BcdDefaultEntry' {
                $command = @('/set', '{bootmgr}', 'default', [string]$finding.Data)
            }
            'BcdImcHive' {
                # Handled by the sweep below, which covers {bootmgr} and every loader entry.
                $command = $null
            }
            { $_ -in @('BcdLoaderValue', 'BcdBootManagerValue') } {
                $command = @('/set', [string]$finding.Data.Identifier, [string]$finding.Data.Value, [string]$finding.Data.Expected)
            }
        }

        if (-not $command) { continue }

        $result = Invoke-BcdEdit -StorePath $StorePath -Arguments $command
        if ($result.Success) {
            $finding.Repaired = $true
            Add-OfflineRepairLog -Level Info -Message "Repaired $($finding.Cause) / $($finding.Item)."
        }
        else {
            Add-OfflineRepairLog -Level Warning -Message "Failed to repair $($finding.Cause) / $($finding.Item): bcdedit exit $($result.ExitCode)."
        }
    }

    # imcdevice and imchivename can sit on {bootmgr} or on any loader entry, and bcdedit only
    # removes a value from the one entry it is given. Every entry in the store is inspected and the
    # value is deleted only from the entries that actually carry it, so a healthy entry is never
    # touched and a successful repair never logs a spurious 'Element not found' warning.
    $imcFindings = @($Findings | Where-Object { $_.Cause -eq 'BcdImcHive' })
    if ($imcFindings.Count -gt 0) {
        $inventory = Get-BcdInventory -StorePath $StorePath
        foreach ($imcFinding in $imcFindings) {
            $cleared = 0
            foreach ($section in (Get-BcdTextSection -Text $inventory.RawText)) {
                if ($section.Body -notmatch "(?im)^\s*$($imcFinding.Data)\s+\S") { continue }
                if ($section.Body -notmatch '(?im)^\s*identifier\s+(\S+)') { continue }
                $target = $Matches[1]

                $sweep = Invoke-BcdEdit -StorePath $StorePath -Arguments @('/deletevalue', [string]$target, [string]$imcFinding.Data)
                if ($sweep.Success) {
                    $cleared++
                    Add-OfflineRepairLog -Level Info -Message "Cleared $($imcFinding.Data) from $target."
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "Could not clear $($imcFinding.Data) from $target."
                }
            }

            $imcFinding.Repaired = ($cleared -gt 0)
            if ($cleared -eq 0) {
                Add-OfflineRepairLog -Level Warning -Message "Found $($imcFinding.Data) in the store but could not locate the entry that carries it."
            }
        }
    }
}

function Invoke-BcdRebuild {
    <#
    .SYNOPSIS
        Rebuilds the store from scratch with bcdboot, restoring the old one if bcdboot fails.

    .OUTPUTS
        PSCustomObject with Success, Reason and BackupPath.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $result = [PSCustomObject]@{ Success = $false; Reason = ''; BackupPath = '' }

    $template = Test-BcdTemplate -Offline $Offline
    if (-not $template.Present) {
        $result.Reason = "bcdboot cannot rebuild the store because BCD-Template is missing from the Windows installation: $($template.Path). Nothing was changed. Restore that file from an installation of the same build, then run this script again."
        return $result
    }

    # Move rather than delete: bcdboot will not overwrite a store it considers valid, and a rename
    # keeps the original recoverable if bcdboot fails half way through.
    $storePath = $Offline.BcdStorePath
    $backupPath = ''
    if (Test-BcdStorePath -StorePath $storePath) {
        $backupPath = "$storePath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
        Move-Item -LiteralPath $storePath -Destination $backupPath -Force
        $result.BackupPath = $backupPath
        Add-OfflineRepairLog -Level Info -Message "Moved the existing store to $backupPath."
    }
    else {
        Add-OfflineRepairLog -Level Warning -Message "No store to back up at $storePath. bcdboot will create a fresh one."
    }

    $windowsSource = $Offline.WindowsPath
    $systemTarget = $Offline.BootDrive.TrimEnd('\')
    $firmware = if ($Offline.Generation -eq 1) { 'BIOS' } else { 'UEFI' }
    $command = "bcdboot `"$windowsSource`" /s $systemTarget /f $firmware"

    Add-OfflineRepairLog -Level Info -Message "Running: $command"
    $output = & cmd.exe /c "$command 2>&1" | Out-String
    $exitCode = $LASTEXITCODE
    Add-OfflineRepairLog -Level Info -Message "bcdboot output: $($output.Trim())"

    if ($exitCode -ne 0) {
        if ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
            Move-Item -LiteralPath $backupPath -Destination $storePath -Force
            Add-OfflineRepairLog -Level Warning -Message "bcdboot failed with exit code $exitCode. The original store was put back."
            $result.BackupPath = ''
        }
        $result.Reason = "bcdboot failed with exit code ${exitCode}: $($output.Trim())"
        return $result
    }

    if (-not (Test-BcdStorePath -StorePath $storePath)) {
        if ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
            Move-Item -LiteralPath $backupPath -Destination $storePath -Force
            $result.BackupPath = ''
        }
        $result.Reason = "bcdboot reported success but no store was created at $storePath. The original store was put back."
        return $result
    }

    $result.Success = $true
    Set-AzureSerialConsoleSetting -StorePath $storePath
    return $result
}

function Set-AzureSerialConsoleSetting {
    <#
    .SYNOPSIS
        Applies the Azure boot settings to a store that bcdboot has just created.

    .DESCRIPTION
        Only ever called on the rebuild path. A fresh store carries stock defaults and none of the
        settings an Azure guest needs, so applying them is not overwriting anyone's configuration.
        The targeted path deliberately does not call this, because there the operator's settings are
        still present and must be preserved.

        Recovery is turned off and the boot status policy set to ignore all failures because a guest
        that stops at the recovery screen cannot be reached in Azure: there is no console to click
        through it, so the VM simply never comes back.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    $loaderId = Get-BcdBootLoaderId -StorePath $StorePath
    if (-not $loaderId) {
        Add-OfflineRepairLog -Level Warning -Message 'The rebuilt store has no resolvable loader identifier, so the Azure boot settings were not applied.'
        return
    }

    $commands = @(
        , @('/set', '{bootmgr}', 'default', [string]$loaderId)
        , @('/set', '{bootmgr}', 'displaybootmenu', 'yes')
        , @('/set', '{bootmgr}', 'timeout', '5')
        , @('/set', '{bootmgr}', 'bootems', 'yes')
        , @('/set', [string]$loaderId, 'recoveryenabled', 'No')
        , @('/set', [string]$loaderId, 'bootstatuspolicy', 'IgnoreAllFailures')
        , @('/ems', [string]$loaderId, 'on')
        , @('/emssettings', 'EMSPORT:1', 'EMSBAUDRATE:115200')
    )

    foreach ($command in $commands) {
        $result = Invoke-BcdEdit -StorePath $StorePath -Arguments $command
        if (-not $result.Success) {
            Add-OfflineRepairLog -Level Warning -Message "Azure boot setting '$($command -join ' ')' returned exit code $($result.ExitCode)."
        }
    }
    Add-OfflineRepairLog -Level Info -Message 'Applied the Azure serial console and boot policy settings to the rebuilt store.'
}

function Set-BootPartitionActive {
    <#
    .SYNOPSIS
        Sets the Active flag on the Gen1 boot partition.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)][int]$PartitionNumber
    )

    try {
        Set-Partition -DiskNumber $Offline.DiskNumber -PartitionNumber $PartitionNumber -IsActive $true -ErrorAction Stop
        Add-OfflineRepairLog -Level Info -Message "Set the Active flag on disk $($Offline.DiskNumber) partition $PartitionNumber."
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Failed to set the Active flag on disk $($Offline.DiskNumber) partition $PartitionNumber : $($_.Exception.Message)"
        return $false
    }
}

function Get-RevertManifestPath {
    param([Parameter(Mandatory = $true)][string]$Drive)
    return (Join-Path $Drive "$scriptName-revert.json")
}

function Save-RevertManifest {
    <#
    .SYNOPSIS
        Records what to put back, so -revert does not have to guess.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$BackupPath = '',
        [Parameter(Mandatory = $false)][int]$ActivatedPartition = 0
    )

    $manifestPath = Get-RevertManifestPath -Drive $Offline.WindowsDrive
    $manifest = [PSCustomObject]@{
        Script             = $scriptName
        Timestamp          = $scriptStartTime
        StorePath          = $Offline.BcdStorePath
        BackupPath         = $BackupPath
        DiskNumber         = $Offline.DiskNumber
        ActivatedPartition = $ActivatedPartition
    }

    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Add-OfflineRepairLog -Level Info -Message "Wrote the revert manifest to $manifestPath."
}

function Invoke-Revert {
    <#
    .SYNOPSIS
        Puts back the store this script backed up, and undoes the Active flag change.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline
    )

    $manifestPath = Get-RevertManifestPath -Drive $Offline.WindowsDrive
    if (-not (Test-OfflinePath $manifestPath)) {
        Add-OfflineRepairLog -Level Warning -Message "No revert manifest was found at $manifestPath. There is nothing recorded to put back."
        return $false
    }

    # ConvertFrom-Json returns the whole object as one pipeline item.
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    $reverted = $false
    if ($manifest.BackupPath -and (Test-OfflinePath $manifest.BackupPath)) {
        Copy-Item -LiteralPath $manifest.BackupPath -Destination $manifest.StorePath -Force
        Add-OfflineRepairLog -Level Info -Message "Restored $($manifest.StorePath) from $($manifest.BackupPath)."
        $reverted = $true
    }
    elseif (-not $manifest.BackupPath) {
        # A rebuild that ran against a missing store has no earlier store to put back. Deleting the
        # rebuilt one would only recreate the original no-boot, so the store is deliberately left.
        Add-OfflineRepairLog -Level Warning -Message "There was no BCD store on the disk when this script ran, so the store it built is the only one there is and is left in place."
    }
    else {
        Add-OfflineRepairLog -Level Warning -Message "The recorded BCD backup is not available: $($manifest.BackupPath)."
    }

    if ($manifest.ActivatedPartition -gt 0) {
        try {
            Set-Partition -DiskNumber $manifest.DiskNumber -PartitionNumber $manifest.ActivatedPartition -IsActive $false -ErrorAction Stop
            Add-OfflineRepairLog -Level Info -Message "Cleared the Active flag this script set on partition $($manifest.ActivatedPartition)."
            $reverted = $true
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Failed to clear the Active flag on partition $($manifest.ActivatedPartition): $($_.Exception.Message)"
        }
    }

    return $reverted
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Runs the whole detect phase and returns every finding in one list.
    #>
    param(
        [Parameter(Mandatory = $true)]$Offline,
        [Parameter(Mandatory = $true)]$Expected
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($finding in (Get-BootManagerFinding -Offline $Offline -Expected $Expected)) { [void]$findings.Add($finding) }

    $storeFindings = @(Get-BcdStoreFinding -Offline $Offline)
    foreach ($finding in $storeFindings) { [void]$findings.Add($finding) }

    # Only parse the store when the file itself is sound. bcdedit against a missing or truncated
    # store produces noise that would be reported as a second, invented fault.
    if ($storeFindings.Count -eq 0) {
        $inventory = Get-BcdInventory -StorePath $Offline.BcdStorePath
        foreach ($finding in (Get-BcdEntryFinding -Offline $Offline -Expected $Expected -Inventory $inventory)) {
            [void]$findings.Add($finding)
        }
    }

    foreach ($finding in (Get-BootPartitionFlagFinding -Offline $Offline)) { [void]$findings.Add($finding) }

    return @($findings)
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, rebuild=$isRebuildForced, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OperatorLog

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber)), Gen$($offline.Generation) / $($offline.PartitionStyle)." | Tee-Object -FilePath $logFile -Append

    if (-not $offline.BootDrive) {
        Log-Error "No boot partition was found on disk $($offline.DiskNumber), so there is nowhere to read or write a BCD store. This is a damaged or missing system partition rather than a boot configuration fault. Use run id win-fix-boot-partition." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Info "Boot partition: $($offline.BootDrive), BCD store: $($offline.BcdStorePath)." | Tee-Object -FilePath $logFile -Append

    if ($isRevert) {
        $reverted = Invoke-Revert -Offline $offline
        Write-OperatorLog
        if ($reverted) {
            Log-Output 'Revert complete. The boot configuration this script changed has been put back.' | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }
        Log-Error 'Revert found nothing it could put back. See the detail log.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $expected = Get-ExpectedBootState -Offline $offline
    Log-Info "Expected loader: device/osdevice $($expected.DevicePartition), path '$($expected.LoaderPath)', systemroot '$($expected.SystemRoot)'." | Tee-Object -FilePath $logFile -Append

    $findings = @(Get-AllFinding -Offline $offline -Expected $expected)
    Write-OperatorLog

    $repairable = @($findings | Where-Object { $_.Repairable })
    $needsRebuild = @($repairable | Where-Object { $_.Tier -eq 'Rebuild' }).Count -gt 0

    if ($isDetectOnly) {
        if ($findings.Count -eq 0) {
            Log-Output 'Detect only: the boot configuration on this disk is consistent. No changes were made.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            # The returned log keeps only its last 4096 characters, so the count is printed
            # after the list it counts. Truncation then eats the oldest finding rather than
            # the summary, and never leaves a bare total with nothing behind it.
            foreach ($finding in $findings) {
                Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
            }
            if ($needsRebuild -or $isRebuildForced) {
                Log-Output '  Repair would rebuild the store with bcdboot, because there is no sound entry left to correct.' | Tee-Object -FilePath $logFile -Append
            }
            Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0 -and -not $isRebuildForced) {
        Log-Output 'No boot configuration fault was found. The boot manager, the BCD store and the Windows loader entry all agree with this disk. No changes were made.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0 -and -not $isRebuildForced) {
        Log-Error "Found $($findings.Count) issue(s), none of which this script can repair:" | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $findings) { Log-Error "  $($finding.Message)" | Tee-Object -FilePath $logFile -Append }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # The full list goes to the detail log and is repeated next to the final summary.
    # Printing it here as well would spend the returned log's 4096 character budget on
    # text that the repair narration below would then push out of the tail.
    foreach ($finding in $findings) {
        "[Output $(Get-Date)]  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Out-File -FilePath $logFile -Append -ErrorAction SilentlyContinue
    }
    Log-Output "Found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. Repairing now." | Tee-Object -FilePath $logFile -Append

    $backupPath = ''
    $activatedPartition = 0

    if ($needsRebuild -or $isRebuildForced) {
        if ($isRebuildForced -and -not $needsRebuild) {
            Log-Info 'Rebuild was requested explicitly, so the store is rebuilt rather than corrected in place.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info 'The store has no sound entry left to correct, so it is rebuilt with bcdboot.' | Tee-Object -FilePath $logFile -Append
        }

        $rebuildResult = Invoke-BcdRebuild -Offline $offline
        Write-OperatorLog

        if (-not $rebuildResult.Success) {
            Log-Error $rebuildResult.Reason | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }

        $backupPath = $rebuildResult.BackupPath
        foreach ($finding in @($findings | Where-Object { $_.Repairable })) { $finding.Repaired = $true }
    }
    else {
        $backupPath = Backup-BcdStore -StorePath $offline.BcdStorePath
        Invoke-TargetedBcdRepair -StorePath $offline.BcdStorePath -Findings @($repairable | Where-Object { $_.Cause -ne 'BootPartitionActive' })
        Write-OperatorLog
    }

    foreach ($finding in @($repairable | Where-Object { $_.Cause -eq 'BootPartitionActive' })) {
        if (Set-BootPartitionActive -Offline $offline -PartitionNumber ([int]$finding.Data)) {
            $finding.Repaired = $true
            $activatedPartition = [int]$finding.Data
        }
    }
    Write-OperatorLog

    Save-RevertManifest -Offline $offline -BackupPath $backupPath -ActivatedPartition $activatedPartition
    Write-OperatorLog

    # Verify by detecting again. The repair is only finished when the disk itself says so.
    $remaining = @(Get-AllFinding -Offline $offline -Expected $expected)
    Write-OperatorLog

    $stillBroken = @($remaining | Where-Object { $_.Repairable })
    $manualOnly = @($remaining | Where-Object { -not $_.Repairable })

    if ($stillBroken.Count -gt 0) {
        Log-Error "Repair ran but $($stillBroken.Count) issue(s) are still present:" | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $stillBroken) { Log-Error "  $($finding.Message)" | Tee-Object -FilePath $logFile -Append }
        if ($backupPath) { Log-Output "The original store is available at $backupPath, or run this script again with revert=true." | Tee-Object -FilePath $logFile -Append }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $repairedCount = @($findings | Where-Object { $_.Repaired }).Count
    # Lists first, count last: the returned log keeps only its tail, so a summary printed
    # ahead of its own evidence is what survives when everything else is truncated away.
    foreach ($finding in @($findings | Where-Object { $_.Repaired })) {
        Log-Output "  [REPAIRED] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    foreach ($finding in $manualOnly) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Boot configuration repaired: $repairedCount issue(s) corrected and verified against the disk." | Tee-Object -FilePath $logFile -Append
    if ($backupPath) { Log-Output "The previous BCD store was kept at $backupPath." | Tee-Object -FilePath $logFile -Append }
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
