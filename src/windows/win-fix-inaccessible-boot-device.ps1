#########################################################################################################
#
# .SYNOPSIS
#   Repairs the offline registry causes of stop error 0x7B INACCESSIBLE_BOOT_DEVICE.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". It detects
#   every known registry cause of 0x7B, repairs only the settings that are actually wrong, and then
#   re-checks. A healthy disk produces no writes at all.
#
#   Causes detected and repaired:
#     1. Boot storage driver load order. A boot-critical storage or bus driver whose Start value is
#        not boot-start (acpi, pci, vmbus, storvsc, disk, partmgr, volmgr, mountmgr and related)
#        leaves the OS volume unreachable when the kernel initialises. Missing required service keys
#        are recreated from the inbox driver binary when that binary is present and Microsoft signed.
#     2. StartOverride values that disable a driver the Start value has already enabled.
#     3. Device class UpperFilters and LowerFilters on the storage classes (DiskDrive, HDC,
#        SCSIAdapter, System, Volume). Dangling filters whose driver binary is missing or zero bytes
#        are removed because they hang or bugcheck the boot, and third-party filters are removed
#        because they are the usual cause after a backup, encryption or endpoint agent failure.
#     4. UpperFilters and LowerFilters on boot-critical PCI and VMBus device instances, which break
#        boot bus enumeration before any storage driver runs.
#     5. Missing Hyper-V ACPI enumeration keys (VMBus and Hyper_V_Gen_Counter_V1 not mapped to the
#        newer MSFT1000 and MSFT1002 device IDs), which stops synthetic device detection on images
#        migrated from another hypervisor.
#     6. A SAN policy that keeps newly discovered disks offline after a disk migration.
#
#   The script never rewrites a value that is already correct, so it is safe to run repeatedly and
#   will not disturb a legitimately customised configuration.
#
# .RESOLVES
#   Stop error 0x7B INACCESSIBLE_BOOT_DEVICE, and the boot loops and "Inaccessible boot device"
#   recovery screens that follow it. Typical triggers are a failed backup or endpoint security
#   agent, a P2V or cross-hypervisor migration, an unsupported driver cleanup, or a restore of a
#   registry hive from a machine with a different storage stack.
#
# .PARAMETER detectOnly
#   "true" to report what would be changed and make no writes at all. Defaults to "false".
#
# .PARAMETER strictFilters
#   "true" to keep only the known inbox filters for each device class and remove every other entry,
#   including Microsoft-signed ones that are not part of the default set. Defaults to "false", which
#   keeps Microsoft-signed filters and removes only dangling and third-party entries.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-inaccessible-boot-device --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-inaccessible-boot-device --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-inaccessible-boot-device --parameters strictFilters=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Only registry causes are handled here. A 0x7B whose cause is an unloadable hive belongs to
#   win-fix-registry-corruption. A 0x7B whose cause is a damaged BCD store is out of scope for this
#   script, and no run id in this library owns BCD repair yet.
#
#   The SYSTEM hive file is backed up next to itself before the first write.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$strictFilters = 'false',
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
$isStrict = ($strictFilters -eq 'true')

# Boot-critical storage and bus drivers. AllowedStarts lists every Start value that is valid for a
# healthy image, so a driver is only corrected when its value is outside that set.
#   CanRecreate marks the service keys whose inbox driver is self-contained enough to rebuild from
#   the binary alone. The others carry image-specific state and are reported instead.
#   ExpectedStartOverride is only checked for the drivers where a single value is correct on every
#   supported image, which is why storport and the class drivers are excluded from that check.
# fvevol is deliberately absent: whether its key is required depends on the OS volume being
# BitLocker encrypted, which cannot be determined reliably from the offline hive.
function Get-BootStorageDriverSpec {
    @(
        [PSCustomObject]@{ Name = 'acpi'; Binary = 'acpi.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $false; ErrorControl = 3; Group = 'Boot Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'ACPI platform bus' }
        [PSCustomObject]@{ Name = 'pci'; Binary = 'pci.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $true; ErrorControl = 3; Group = 'Boot Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'PCI boot bus' }
        [PSCustomObject]@{ Name = 'vdrvroot'; Binary = 'vdrvroot.sys'; Start = 0; AllowedStarts = [int[]]@(0, 1, 3); Required = $true; CanRecreate = $false; ErrorControl = 1; Group = 'System Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'virtual drive root enumerator' }
        [PSCustomObject]@{ Name = 'intelide'; Binary = 'intelide.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $false; CanRecreate = $false; ErrorControl = 3; Group = 'System Bus Extender'; CheckStartOverride = $true; ExpectedStartOverride = 3; Description = 'legacy IDE controller' }
        [PSCustomObject]@{ Name = 'pciide'; Binary = 'pciide.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $false; CanRecreate = $false; ErrorControl = 3; Group = 'System Bus Extender'; CheckStartOverride = $true; ExpectedStartOverride = 3; Description = 'PCI IDE controller' }
        [PSCustomObject]@{ Name = 'atapi'; Binary = 'atapi.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $false; CanRecreate = $false; ErrorControl = 3; Group = 'SCSI Miniport'; CheckStartOverride = $true; ExpectedStartOverride = 3; Description = 'IDE channel driver' }
        [PSCustomObject]@{ Name = 'storahci'; Binary = 'storahci.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $false; CanRecreate = $false; ErrorControl = 3; Group = 'SCSI Miniport'; CheckStartOverride = $true; ExpectedStartOverride = 3; Description = 'AHCI storage miniport' }
        [PSCustomObject]@{ Name = 'vmbus'; Binary = 'vmbus.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $false; ErrorControl = 3; Group = 'Boot Bus Extender'; CheckStartOverride = $true; ExpectedStartOverride = 0; Description = 'Hyper-V VMBus' }
        [PSCustomObject]@{ Name = 'storvsc'; Binary = 'storvsc.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $false; ErrorControl = 3; Group = 'SCSI Miniport'; CheckStartOverride = $true; ExpectedStartOverride = 0; Description = 'Hyper-V synthetic storage' }
        [PSCustomObject]@{ Name = 'storport'; Binary = 'storport.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $false; CanRecreate = $false; ErrorControl = 3; Group = 'SCSI Miniport'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'storage port driver' }
        [PSCustomObject]@{ Name = 'disk'; Binary = 'disk.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $true; ErrorControl = 3; Group = 'SCSI Class'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'disk class driver' }
        [PSCustomObject]@{ Name = 'partmgr'; Binary = 'partmgr.sys'; Start = 0; AllowedStarts = [int[]]@(0, 1); Required = $true; CanRecreate = $true; ErrorControl = 3; Group = 'Boot Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'partition manager' }
        [PSCustomObject]@{ Name = 'volmgr'; Binary = 'volmgr.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $true; ErrorControl = 3; Group = 'System Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'volume manager' }
        [PSCustomObject]@{ Name = 'mountmgr'; Binary = 'mountmgr.sys'; Start = 0; AllowedStarts = [int[]]@(0); Required = $true; CanRecreate = $false; ErrorControl = 1; Group = 'System Bus Extender'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'mount point manager' }
        [PSCustomObject]@{ Name = 'volsnap'; Binary = 'volsnap.sys'; Start = 1; AllowedStarts = [int[]]@(0, 1, 3); Required = $true; CanRecreate = $false; ErrorControl = 3; Group = 'Filter'; CheckStartOverride = $false; ExpectedStartOverride = $null; Description = 'volume shadow copy filter' }
    )
}

# Device classes whose filter drivers sit in the boot storage path. The network class is deliberately
# absent: its filters cause a connectivity symptom rather than a 0x7B, so touching them here would be
# a change this script has no evidence for.
function Get-StorageClassFilterSpec {
    @(
        [PSCustomObject]@{ GUID = '{4d36e967-e325-11ce-bfc1-08002be10318}'; Name = 'DiskDrive'; SafeFilters = [string[]]@('partmgr', 'fvevol', 'iorate', 'storqosflt', 'wcifs', 'ehstorclass', 'storflt') }
        [PSCustomObject]@{ GUID = '{4d36e96a-e325-11ce-bfc1-08002be10318}'; Name = 'HDC'; SafeFilters = [string[]]@('iasf', 'iastorf', 'iaStorAV') }
        [PSCustomObject]@{ GUID = '{4d36e97b-e325-11ce-bfc1-08002be10318}'; Name = 'SCSIAdapter'; SafeFilters = [string[]]@('iaStorAV') }
        [PSCustomObject]@{ GUID = '{4d36e97d-e325-11ce-bfc1-08002be10318}'; Name = 'System'; SafeFilters = [string[]]@() }
        [PSCustomObject]@{ GUID = '{71a27cdd-812a-11d0-bec7-08002be2092f}'; Name = 'Volume'; SafeFilters = [string[]]@('volsnap', 'fvevol', 'rdyboost', 'spldr', 'volmgrx', 'iorate', 'storqosflt') }
    )
}

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Data       = $Data
        Repaired   = $false
    }
}

function Get-BootStorageDriverFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($spec in (Get-BootStorageDriverSpec)) {
        $svcPath = "$SystemRoot\Services\$($spec.Name)"
        $binaryPath = Join-OfflinePath -Root $WindowsPath -ChildPath "System32\drivers\$($spec.Binary)"

        if (-not (Test-Path $svcPath)) {
            if (-not $spec.Required) { continue }

            $signature = Test-OfflineFileSignature -FilePath $binaryPath
            # IsLikelyMicrosoft, not IsMicrosoft. Driver binaries on an offline image are
            # catalog signed, and the catalogs that would verify them are on that image
            # rather than registered on the rescue VM, so cryptographic proof is normally
            # unavailable. Requiring it here would make the scenario decline to rebuild a
            # service key for a perfectly healthy inbox driver.
            $canRecreate = $spec.CanRecreate -and $signature.IsLikelyMicrosoft
            $reason = if ($signature.IsLikelyMicrosoft) { '' } elseif ($spec.CanRecreate) { " (driver binary is $($signature.Status), cannot rebuild the key from it)" } else { ' (this key carries image-specific state and is not safe to rebuild)' }

            [void]$findings.Add((New-Finding -Cause 'DriverServiceKey' -Item $spec.Name `
                        -Message "$($spec.Name) service key is missing, so the $($spec.Description) cannot take part in boot storage enumeration$reason" `
                        -Repairable $canRecreate -Data ([PSCustomObject]@{ Spec = $spec; ServicePath = $svcPath; BinaryPath = $binaryPath })))
            continue
        }

        $props = Get-ItemProperty -Path $svcPath -ErrorAction SilentlyContinue
        $currentStart = if ($null -ne $props) { $props.Start } else { $null }

        if ($null -eq $currentStart) {
            [void]$findings.Add((New-Finding -Cause 'DriverStart' -Item $spec.Name `
                        -Message "$($spec.Name) has no Start value, so the boot storage load order is incomplete" `
                        -Data ([PSCustomObject]@{ Spec = $spec; ServicePath = $svcPath; Current = '(missing)' })))
        }
        elseif ([int]$currentStart -notin @($spec.AllowedStarts)) {
            $expected = (@($spec.AllowedStarts) | ForEach-Object { [string]$_ }) -join ' or '
            [void]$findings.Add((New-Finding -Cause 'DriverStart' -Item $spec.Name `
                        -Message "$($spec.Name) Start=$currentStart but $expected is required, so the $($spec.Description) does not load early enough" `
                        -Data ([PSCustomObject]@{ Spec = $spec; ServicePath = $svcPath; Current = "$currentStart" })))
        }

        if (-not $spec.CheckStartOverride -or $null -eq $spec.ExpectedStartOverride) { continue }

        $overridePath = "$svcPath\StartOverride"
        if (-not (Test-Path $overridePath)) { continue }

        $expectedOverride = [int]$spec.ExpectedStartOverride
        $overrideProps = Get-ItemProperty -Path $overridePath -ErrorAction SilentlyContinue
        foreach ($prop in @($overrideProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            if ($null -eq $prop.Value) { continue }
            if ([int]$prop.Value -eq $expectedOverride) { continue }

            [void]$findings.Add((New-Finding -Cause 'DriverStartOverride' -Item "$($spec.Name)\$($prop.Name)" `
                        -Message "$($spec.Name) StartOverride\$($prop.Name)=$($prop.Value) overrides the Start value and should be $expectedOverride" `
                        -Data ([PSCustomObject]@{ Spec = $spec; OverridePath = $overridePath; ValueName = $prop.Name; Current = "$($prop.Value)"; Expected = $expectedOverride })))
        }
    }

    return @($findings)
}

function Get-ClassFilterFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $false)][bool]$Strict = $false
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($classSpec in (Get-StorageClassFilterSpec)) {
        $classPath = "$SystemRoot\Control\Class\$($classSpec.GUID)"
        if (-not (Test-Path $classPath)) { continue }

        foreach ($filterType in @('UpperFilters', 'LowerFilters')) {
            $raw = (Get-ItemProperty -Path $classPath -ErrorAction SilentlyContinue).$filterType
            $current = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
            if ($current.Count -eq 0) { continue }

            $keep = [System.Collections.Generic.List[string]]::new()
            $drop = [System.Collections.Generic.List[object]]::new()

            foreach ($filter in $current) {
                $imagePathRaw = (Get-ItemProperty -Path "$SystemRoot\Services\$filter" -ErrorAction SilentlyContinue).ImagePath
                $resolved = if ($imagePathRaw) { Resolve-OfflineImagePath -ImagePath $imagePathRaw -WindowsDrive $WindowsDrive } else { $null }
                $item = if ($resolved) { Get-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue } else { $null }

                if (-not $imagePathRaw) {
                    [void]$drop.Add([PSCustomObject]@{ Filter = $filter; Reason = 'the service key has no ImagePath, so the filter is dangling' })
                    continue
                }
                if (-not $item) {
                    [void]$drop.Add([PSCustomObject]@{ Filter = $filter; Reason = "the driver binary is missing at $resolved, so the filter is dangling" })
                    continue
                }
                if ($item.Length -eq 0) {
                    [void]$drop.Add([PSCustomObject]@{ Filter = $filter; Reason = "the driver binary at $resolved is zero bytes" })
                    continue
                }

                if ($classSpec.SafeFilters -icontains $filter) { [void]$keep.Add($filter); continue }

                $company = "$($item.VersionInfo.CompanyName)"
                if (-not $Strict -and $company -match 'Microsoft') { [void]$keep.Add($filter); continue }

                $reason = if ($Strict) { "it is not one of the inbox filters for this class (company '$company')" } else { "it is a third-party filter (company '$(if ($company) { $company } else { 'unknown' })')" }
                [void]$drop.Add([PSCustomObject]@{ Filter = $filter; Reason = $reason })
            }

            if ($drop.Count -eq 0) { continue }

            $summary = (@($drop) | ForEach-Object { "$($_.Filter) because $($_.Reason)" }) -join '; '
            [void]$findings.Add((New-Finding -Cause 'ClassFilter' -Item "$($classSpec.Name) $filterType" `
                        -Message "$($classSpec.Name) $filterType must drop $summary" `
                        -Data ([PSCustomObject]@{ ClassPath = $classPath; FilterType = $filterType; Keep = [string[]]@($keep); Drop = @($drop) })))
        }
    }

    return @($findings)
}

function Get-DeviceInstanceFilterFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $bootBusServices = [string[]]@('pci', 'vmbus')
    $enumRoot = "$SystemRoot\Enum\ACPI"
    if (-not (Test-Path $enumRoot)) { return @($findings) }

    foreach ($device in @(Get-ChildItem -Path $enumRoot -ErrorAction SilentlyContinue)) {
        foreach ($instance in @(Get-ChildItem -Path $device.PSPath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $props -or $bootBusServices -inotcontains $props.Service) { continue }

            foreach ($filterType in @('UpperFilters', 'LowerFilters')) {
                $active = @($props.$filterType | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
                if ($active.Count -eq 0) { continue }

                $deviceId = "ACPI\$($device.PSChildName)\$($instance.PSChildName)"
                [void]$findings.Add((New-Finding -Cause 'DeviceInstanceFilter' -Item "$deviceId $filterType" `
                            -Message "$deviceId is served by $($props.Service) and its $filterType holds $($active -join ', '), which runs before storage and blocks boot bus enumeration" `
                            -Data ([PSCustomObject]@{ RegistryPath = "$($instance.PSPath)"; FilterType = $filterType; Filters = [string[]]$active })))
            }
        }
    }

    return @($findings)
}

function Get-AcpiEnumMappingFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $pairs = @(
        [PSCustomObject]@{ Source = 'VMBus'; Target = 'MSFT1000'; Description = 'Hyper-V VMBus root device' }
        [PSCustomObject]@{ Source = 'Hyper_V_Gen_Counter_V1'; Target = 'MSFT1002'; Description = 'Hyper-V generation counter' }
    )

    foreach ($pair in $pairs) {
        $sourcePath = "$SystemRoot\Enum\ACPI\$($pair.Source)"
        $targetPath = "$SystemRoot\Enum\ACPI\$($pair.Target)"
        if (-not (Test-Path $sourcePath)) { continue }
        if (Test-Path $targetPath) { continue }

        [void]$findings.Add((New-Finding -Cause 'AcpiEnumMapping' -Item "$($pair.Source) -> $($pair.Target)" `
                    -Message "the $($pair.Description) is enumerated only as $($pair.Source), so Windows builds that look for $($pair.Target) cannot detect it" `
                    -Data ([PSCustomObject]@{ SourcePath = $sourcePath; TargetPath = $targetPath; Source = $pair.Source; Target = $pair.Target })))
    }

    return @($findings)
}

function Get-SanPolicyFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $sanPath = "$SystemRoot\Services\partmgr\Parameters"
    if (-not (Test-Path $sanPath)) { return @($findings) }

    $current = (Get-ItemProperty -Path $sanPath -ErrorAction SilentlyContinue).SanPolicy
    if ($null -eq $current) { return @($findings) }

    # 1 OnlineAll and 2 OfflineShared both bring an internal boot disk online and are left alone.
    # 3 OfflineAll and 4 OfflineInternal keep newly discovered internal disks offline, which strands
    # the OS volume after the disk is presented on a different controller.
    if ([int]$current -notin @(3, 4)) { return @($findings) }

    $name = if ([int]$current -eq 3) { 'OfflineAll' } else { 'OfflineInternal' }
    [void]$findings.Add((New-Finding -Cause 'SanPolicy' -Item 'partmgr SanPolicy' `
                -Message "SAN policy is $current ($name), which keeps a newly discovered internal disk offline after a controller or platform change" `
                -Data ([PSCustomObject]@{ RegistryPath = $sanPath; Current = "$current" })))

    return @($findings)
}

function Get-AllFinding {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $false)][bool]$Strict = $false
    )

    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($finding in @(Get-BootStorageDriverFinding -SystemRoot $SystemRoot -WindowsPath $WindowsPath)) { [void]$all.Add($finding) }
    foreach ($finding in @(Get-ClassFilterFinding -SystemRoot $SystemRoot -WindowsDrive $WindowsDrive -Strict $Strict)) { [void]$all.Add($finding) }
    foreach ($finding in @(Get-DeviceInstanceFilterFinding -SystemRoot $SystemRoot)) { [void]$all.Add($finding) }
    foreach ($finding in @(Get-AcpiEnumMappingFinding -SystemRoot $SystemRoot)) { [void]$all.Add($finding) }
    foreach ($finding in @(Get-SanPolicyFinding -SystemRoot $SystemRoot)) { [void]$all.Add($finding) }
    return @($all)
}

function Repair-Finding {
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $data = $Finding.Data

    switch ($Finding.Cause) {
        'DriverServiceKey' {
            $spec = $data.Spec
            New-Item -Path $data.ServicePath -Force | Out-Null
            Set-ItemProperty -Path $data.ServicePath -Name Type -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $data.ServicePath -Name Start -Value $spec.Start -Type DWord -Force
            Set-ItemProperty -Path $data.ServicePath -Name ErrorControl -Value $spec.ErrorControl -Type DWord -Force
            Set-ItemProperty -Path $data.ServicePath -Name ImagePath -Value "system32\drivers\$($spec.Binary)" -Type ExpandString -Force
            if ($spec.Group) { Set-ItemProperty -Path $data.ServicePath -Name Group -Value $spec.Group -Type String -Force }
            Add-OfflineRepairLog -Message "Recreated service key $($spec.Name) with Start=$($spec.Start), ErrorControl=$($spec.ErrorControl), Group='$($spec.Group)', ImagePath=system32\drivers\$($spec.Binary)"
        }
        'DriverStart' {
            $spec = $data.Spec
            Set-ItemProperty -Path $data.ServicePath -Name Start -Value $spec.Start -Type DWord -Force
            Add-OfflineRepairLog -Message "$($spec.Name) Start: $($data.Current) -> $($spec.Start)"
        }
        'DriverStartOverride' {
            Set-ItemProperty -Path $data.OverridePath -Name $data.ValueName -Value $data.Expected -Type DWord -Force
            Add-OfflineRepairLog -Message "$($Finding.Item) StartOverride: $($data.Current) -> $($data.Expected)"
        }
        'ClassFilter' {
            if (@($data.Keep).Count -gt 0) {
                Set-ItemProperty -Path $data.ClassPath -Name $data.FilterType -Value ([string[]]@($data.Keep)) -Type MultiString -Force
            }
            else {
                # Leaving an empty MultiString behind is not the same as having no filters at all.
                Remove-ItemProperty -Path $data.ClassPath -Name $data.FilterType -Force
            }
            Add-OfflineRepairLog -Message "$($Finding.Item): removed $((@($data.Drop) | ForEach-Object { $_.Filter }) -join ', '), kept $(if (@($data.Keep).Count) { @($data.Keep) -join ', ' } else { '(none)' })"
        }
        'DeviceInstanceFilter' {
            Remove-ItemProperty -Path $data.RegistryPath -Name $data.FilterType -Force
            Add-OfflineRepairLog -Message "$($Finding.Item): removed $($data.Filters -join ', ')"
        }
        'AcpiEnumMapping' {
            $regRoot = $SystemRoot -replace '^HKLM:', 'HKLM'
            $sourceReg = "$regRoot\Enum\ACPI\$($data.Source)"
            $targetReg = "$regRoot\Enum\ACPI\$($data.Target)"
            $output = reg.exe copy "$sourceReg" "$targetReg" /s /f 2>&1 | Out-String
            if (-not (Test-Path $data.TargetPath)) { throw "reg copy did not create $targetReg. $($output.Trim())" }
            Add-OfflineRepairLog -Message "Copied ACPI enumeration key $($data.Source) to $($data.Target)"
        }
        'SanPolicy' {
            Set-ItemProperty -Path $data.RegistryPath -Name SanPolicy -Value 1 -Type DWord -Force
            Add-OfflineRepairLog -Message "SAN policy: $($data.Current) -> 1 (OnlineAll)"
        }
        default { throw "No repair is implemented for cause '$($Finding.Cause)'." }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, strictFilters=$isStrict)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $summary = @()
    $repairedCount = 0
    $unrepairable = @()
    $remaining = @()

    $result = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
        $controlSet = Split-Path -Path $systemRoot -Leaf
        Add-OfflineRepairLog -Message "Checking control set $controlSet"

        $findings = @(Get-AllFinding -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive -Strict $isStrict)

        return [PSCustomObject]@{
            SystemRoot = $systemRoot
            ControlSet = $controlSet
            Findings   = $findings
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $findings = @($result.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($findings.Count -eq 0) {
        Log-Output "No 0x7B causes were found in control set $($result.ControlSet). No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0) {
        Log-Warning "Found $($findings.Count) issue(s) but none can be repaired by this script." | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $unrepairable) {
            Log-Warning "  $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

    $repairResult = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict
        $repaired = 0
        $failed = [System.Collections.Generic.List[string]]::new()

        foreach ($finding in $repairable) {
            try {
                Repair-Finding -Finding $finding -SystemRoot $systemRoot
                $finding.Repaired = $true
                $repaired++
            }
            catch {
                [void]$failed.Add("$($finding.Item): $($_.Exception.Message)")
                Add-OfflineRepairLog -Level Warning -Message "Could not repair $($finding.Item): $($_.Exception.Message)"
            }
        }

        # Verify against a freshly read state rather than trusting the writes above.
        $still = @(Get-AllFinding -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive -Strict $isStrict)

        return [PSCustomObject]@{
            Repaired  = $repaired
            Failed    = @($failed)
            Remaining = $still
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $repairedCount = $repairResult.Repaired
    $remaining = @($repairResult.Remaining)
    $stillRepairable = @($remaining | Where-Object { $_.Repairable })

    foreach ($failure in @($repairResult.Failed)) {
        Log-Warning "Repair failed: $failure" | Tee-Object -FilePath $logFile -Append
    }
    foreach ($finding in $remaining) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) in control set $($result.ControlSet)."
    if ($unrepairable.Count -gt 0) {
        $summary += " $($unrepairable.Count) issue(s) need a source image or a different script."
    }

    if ($stillRepairable.Count -gt 0) {
        Log-Error "$summary $($stillRepairable.Count) repairable issue(s) are still present after the repair." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "SYSTEM hive backup: $backup" | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
finally {
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    "$(Get-Date -f yyyyMMddHHmmss)" | Out-File -FilePath $logFile -Append
}
