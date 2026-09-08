#########################################################################################################
#
# .SYNOPSIS
#   Finds the driver that Code Integrity is blocking and disables that driver, instead of turning
#   off the protection.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". It answers the
#   question "which driver is stopping this VM from booting" using evidence taken from the offline
#   disk, and disables only the driver that evidence names. Memory Integrity, Credential Guard and
#   VBS stay enabled.
#
#   The rule this script is built around: a protection being enabled is not a fault. Millions of
#   VMs run Memory Integrity and Credential Guard without trouble, so "HVCI is on" is never
#   reported as a problem and never triggers a change. Something is only repaired when there is
#   positive evidence that it is what broke this particular VM.
#
#   Evidence sources, in order of authority:
#     1. The Code Integrity operational event log on the offline disk
#        (System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx). Events 3033 and
#        3077 name the exact image that was refused, and 3004 and 3023 record signature failures.
#        This is the only evidence strong enough to justify disabling a driver on its own.
#     2. A portable executable scan of the third party kernel drivers, looking for a section that
#        stays writable and executable after load, which is the classic reason a driver is rejected
#        under Memory Integrity. Sections discarded after initialisation, such as INIT, are ignored:
#        a stock Windows Server 2022 image carries about fifteen inbox storage drivers with one, so
#        counting them would bury the real finding. This is reported as corroboration and as a lead
#        for the engineer, but it never disables anything by itself, because a section flagged this
#        way is not proof that this driver is what failed.
#     3. The offline Secure Boot state paired with the boot configuration. Test signing or disabled
#        integrity checks will stop a Secure Boot machine from booting, which is a provable
#        conflict rather than a guess.
#
#   Causes detected and repaired:
#     1. A third party driver named in a Code Integrity block event. Repaired by setting Start=4 on
#        that one service, so Windows stops trying to load it.
#     2. Test signing enabled in the boot configuration while the guest last booted with Secure
#        Boot on. Repaired by turning test signing off.
#     3. Integrity checks disabled in the boot configuration on the same Secure Boot guest.
#        Repaired by removing the override.
#
#   Reported but never repaired automatically:
#     - A third party driver with a writable and executable section while Memory Integrity is on.
#       Reported with the section names so the engineer can decide.
#     - Any boot critical or Azure platform driver, even when the evidence names it. Disabling the
#       storage or bus driver the VM boots through trades this failure for a 0x7B, so the script
#       reports it and stops.
#
#   Turning the protection off is available with -disableProtection true, and is deliberately not
#   the default. Use it when no culprit could be named, or when the named driver is one the VM
#   cannot boot without. It clears only the values that are actually set and prints the commands to
#   restore them.
#
# .RESOLVES
#   Boot failures after Memory Integrity, Credential Guard, VBS or driver signing changes, where
#   the guest bugchecks or loops before logon. Typical triggers are enabling Memory Integrity on an
#   image carrying an incompatible third party driver, an endpoint agent update shipping a driver
#   that fails Code Integrity, or test signing left on after driver development.
#
# .PARAMETER detectOnly
#   "true" to report the evidence and make no writes at all. Defaults to "false".
#
# .PARAMETER disableProtection
#   "true" to clear the Memory Integrity, Credential Guard and LSA protection settings that are
#   actually enabled. Last resort. Defaults to "false".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-code-integrity --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-code-integrity --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-code-integrity --parameters disableProtection=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The Secure Boot state cannot be read from an offline registry hive. Windows keeps it in
#   Control\SecureBoot\State, which is a volatile key: it is recreated from the firmware at every
#   boot and never written to the hive file, so on an attached disk it is simply absent. It is read
#   from the Measured Boot log instead - see Get-OfflineSecureBootState in OfflineRepairCommon.ps1.
#   An absent log is reported as unknown rather than as "off".
#
#   testsigning and nointegritychecks are reported as context and are never repaired. This was
#   measured rather than assumed, on Server 2022 Gen2 with Secure Boot and vTPM enabled:
#     - bcdedit inside the running guest refuses to set either one, with "The value is protected by
#       Secure Boot policy and cannot be modified or deleted".
#     - Setting either one offline does persist to the disk: the value survives a dismount, an
#       offline/online cycle and a remount.
#     - Booting a disk carrying either value succeeds anyway. The guest reaches Ready and the value
#       is gone from the store afterwards, so the boot manager drops it.
#   An earlier version of this script raised these as findings that claimed the guest "cannot boot".
#   That claim was wrong in both directions: the state is not fatal, and it does not survive to be
#   the cause of anything. Clearing them offline would have been a change with no evidence behind it.
#
#   Credential Guard enabled with a UEFI lock (Control\Lsa\LsaCfgFlags=1) also sets an EFI firmware
#   variable that a registry change cannot clear. That case is reported, because clearing it needs
#   the guest to boot once with the Microsoft opt-out tool, which this script cannot do.
#
#   The SYSTEM hive file and the BCD store are backed up next to themselves before the first write.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$disableProtection = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Get-OfflineBcdStore.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isProtectionDisableAllowed = ($disableProtection -eq 'true')

# Drivers the VM boots through. Even when Code Integrity names one of these, disabling it swaps a
# code integrity failure for an INACCESSIBLE_BOOT_DEVICE, so the script reports and stops instead.
$script:BootCriticalDriver = @(
    'acpi', 'pci', 'vmbus', 'storvsc', 'storahci', 'stornvme', 'storport', 'disk', 'partmgr',
    'volmgr', 'volmgrx', 'volsnap', 'mountmgr', 'fltmgr', 'ntfs', 'refs', 'vdrvroot', 'msisadrv',
    'pcw', 'fvevol', 'iorate', 'wof', 'clfs', 'ksecdd', 'cng', 'winload', 'intelide', 'atapi',
    'ataport', 'amdsata', 'iastorv', 'iastora', 'vhdmp', 'spaceport'
)

# Vendors whose drivers an Azure VM can genuinely need for storage, networking or GPU. Disabling
# one of these to work around a code integrity failure usually costs connectivity or the disk.
$script:PlatformVendorPattern = (@(
        'Mellanox', 'NVIDIA', 'Intel', 'Advanced Micro Devices', 'AMD', 'Chelsio', 'Marvell', 'Broadcom'
    ) | ForEach-Object { [regex]::Escape($_) }) -join '|'

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
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
        Repaired   = $false
        Data       = $Data
    }
}

function Get-PeWritableExecutableSection {
    <#
    .SYNOPSIS
        Returns the sections of a driver image that are both writable and executable.

    .DESCRIPTION
        Memory Integrity refuses to map a page that is writable and executable at the same time, so
        an image carrying such a section is a candidate for the failure. Only the headers are read:
        the DOS stub points at the PE signature, the COFF header gives the section count and the
        size of the optional header, and the section table follows the optional header.

        A discardable section such as INIT is reported separately, because it is freed once the
        driver has initialised and is a much weaker signal than a permanent writable and executable
        data section.

    .OUTPUTS
        PSCustomObject with Parsed, Sections and Reason. Sections carry Name and Discardable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $result = [PSCustomObject]@{ Parsed = $false; Sections = @(); Reason = '' }

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $header = New-Object byte[] 8192
            $read = $stream.Read($header, 0, 8192)
        }
        finally { $stream.Dispose() }
    }
    catch {
        $result.Reason = "unreadable ($($_.Exception.Message))"
        return $result
    }

    if ($read -lt 512) { $result.Reason = 'file is too small to be a PE image'; return $result }
    if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) { $result.Reason = 'not a PE image (no MZ header)'; return $result }

    $peOffset = [BitConverter]::ToInt32($header, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 24) -ge $read) { $result.Reason = 'PE header offset is out of range'; return $result }
    if ([System.Text.Encoding]::ASCII.GetString($header, $peOffset, 4) -ne "PE`0`0") { $result.Reason = 'PE signature missing'; return $result }

    $sectionCount = [BitConverter]::ToUInt16($header, $peOffset + 6)
    $optionalHeaderSize = [BitConverter]::ToUInt16($header, $peOffset + 20)
    $tableStart = $peOffset + 24 + $optionalHeaderSize
    if ($sectionCount -le 0 -or $sectionCount -gt 96) { $result.Reason = "implausible section count ($sectionCount)"; return $result }
    if (($tableStart + ($sectionCount * 40)) -gt $read) { $result.Reason = 'section table extends past the header block'; return $result }

    $IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    $IMAGE_SCN_MEM_EXECUTE = 0x20000000
    $IMAGE_SCN_MEM_WRITE = 0x80000000

    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = $tableStart + ($i * 40)
        $name = [System.Text.Encoding]::ASCII.GetString($header, $entry, 8).TrimEnd([char]0, ' ')
        $characteristics = [BitConverter]::ToUInt32($header, $entry + 36)

        if ((($characteristics -band $IMAGE_SCN_MEM_EXECUTE) -ne 0) -and (($characteristics -band $IMAGE_SCN_MEM_WRITE) -ne 0)) {
            [void]$found.Add([PSCustomObject]@{
                    Name        = $name
                    Discardable = (($characteristics -band $IMAGE_SCN_MEM_DISCARDABLE) -ne 0)
                })
        }
    }

    $result.Parsed = $true
    $result.Sections = @($found)
    return $result
}

function Get-CodeIntegrityBlockedFile {
    <#
    .SYNOPSIS
        Reads the offline Code Integrity log and returns the images it refused to load.

    .DESCRIPTION
        Events 3033 and 3077 name the image that did not meet the signing requirement, and 3004 and
        3023 record signature validation failures. The rendered message is preferred because it
        carries the full path, and the raw event XML is used when the provider cannot render it on
        the rescue VM.

    .OUTPUTS
        PSCustomObject with Available, Reason and Files. Files carry FileName, EventIds, Count and
        LastSeenUtc.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $result = [PSCustomObject]@{ Available = $false; Reason = ''; Files = @() }

    $logPath = Join-OfflinePath -Root $WindowsPath -ChildPath 'System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx'
    if (-not (Test-OfflinePath $logPath)) {
        $result.Reason = "the Code Integrity log is not present at $logPath"
        return $result
    }

    $events = @()
    try {
        $events = @(Get-WinEvent -Path $logPath -FilterXPath "*[System[(EventID=3033 or EventID=3077 or EventID=3023 or EventID=3004)]]" -MaxEvents 200 -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            $result.Available = $true
            $result.Reason = 'the Code Integrity log contains no block events'
            return $result
        }
        $result.Reason = "the Code Integrity log could not be read ($($_.Exception.Message))"
        return $result
    }

    $byFile = @{}
    foreach ($record in $events) {
        $text = ''
        try { $text = [string]$record.Message } catch { $text = '' }
        if ([string]::IsNullOrWhiteSpace($text)) {
            try { $text = [string]$record.ToXml() } catch { $text = '' }
        }
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($match in [regex]::Matches($text, '(?i)[^\s\\/"<>]+\.sys')) {
            $fileName = $match.Value.ToLowerInvariant()
            if (-not $byFile.ContainsKey($fileName)) {
                $byFile[$fileName] = [PSCustomObject]@{
                    FileName    = $fileName
                    EventIds    = [System.Collections.Generic.List[int]]::new()
                    Count       = 0
                    LastSeenUtc = [datetime]::MinValue
                }
            }
            $entry = $byFile[$fileName]
            $entry.Count++
            if (-not $entry.EventIds.Contains([int]$record.Id)) { [void]$entry.EventIds.Add([int]$record.Id) }
            if ($record.TimeCreated -and $record.TimeCreated.ToUniversalTime() -gt $entry.LastSeenUtc) {
                $entry.LastSeenUtc = $record.TimeCreated.ToUniversalTime()
            }
        }
    }

    $result.Available = $true
    $result.Files = @($byFile.Values | Sort-Object -Property Count -Descending)
    if ($result.Files.Count -eq 0) { $result.Reason = 'the Code Integrity log has block events but none named a driver image' }
    return $result
}

function Get-KernelDriverInventory {
    <#
    .SYNOPSIS
        Lists the kernel and file system drivers configured to load, with vendor and image details.

    .DESCRIPTION
        Only Type 1 and 2 services are drivers, and only Start 0, 1 and 2 load early enough to stop
        a boot. The image path is resolved onto the offline disk so the binary can be inspected.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $inventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $servicesRoot = "$SystemRoot\Services"
    if (-not (Test-Path $servicesRoot)) { return @() }

    foreach ($key in (Get-ChildItem $servicesRoot -ErrorAction SilentlyContinue)) {
        $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $properties) { continue }
        if ([int]($properties.Type) -notin @(1, 2)) { continue }
        if ([int]($properties.Start) -notin @(0, 1, 2)) { continue }
        if (-not $properties.ImagePath) { continue }

        $resolved = Resolve-OfflineImagePath -ImagePath ([string]$properties.ImagePath) -WindowsDrive $WindowsDrive
        $vendor = ''
        $exists = Test-OfflinePath $resolved
        if ($exists) {
            $versionInfo = (Get-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue).VersionInfo
            if ($versionInfo -and $versionInfo.CompanyName) { $vendor = $versionInfo.CompanyName.Trim() }
        }

        [void]$inventory.Add([PSCustomObject]@{
                Service       = $key.PSChildName
                KeyPath       = $key.PSPath
                ImagePathRaw  = [string]$properties.ImagePath
                ResolvedPath  = $resolved
                FileName      = (Split-Path -Path $resolved -Leaf).ToLowerInvariant()
                Exists        = $exists
                Start         = [int]$properties.Start
                Vendor        = $vendor
                IsMicrosoft   = ($vendor -match 'Microsoft')
                IsPlatform    = ($vendor -and $vendor -match $script:PlatformVendorPattern)
                IsBootCritical = ($key.PSChildName.ToLowerInvariant() -in $script:BootCriticalDriver)
            })
    }

    return @($inventory)
}

function Get-ProtectionState {
    <#
    .SYNOPSIS
        Reads the current VBS, Memory Integrity, Credential Guard, LSA and Secure Boot settings.

    .DESCRIPTION
        This is context, not a verdict. Every value here can be enabled on a perfectly healthy VM,
        so nothing in this function produces a finding on its own.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][PSCustomObject]$SecureBoot
    )

    $hvciPath = "$SystemRoot\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $deviceGuardPath = "$SystemRoot\Control\DeviceGuard"
    $lsaPath = "$SystemRoot\Control\Lsa"
    $policyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Windows\DeviceGuard'

    $hvci = Get-ItemProperty -Path $hvciPath -ErrorAction SilentlyContinue
    $deviceGuard = Get-ItemProperty -Path $deviceGuardPath -ErrorAction SilentlyContinue
    $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
    $policy = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HvciEnabled       = ([int]($hvci.Enabled) -eq 1)
        HvciLocked        = ([int]($hvci.Locked) -eq 1)
        HvciPath          = $hvciPath
        DeviceGuardPath   = $deviceGuardPath
        DeviceGuardLsaCfg = [int]($deviceGuard.LsaCfgFlags)
        DeviceGuardVbs    = [int]($deviceGuard.EnableVirtualizationBasedSecurity)
        DeviceGuardReqPsf = [int]($deviceGuard.RequirePlatformSecurityFeatures)
        LsaPath           = $lsaPath
        LsaCfgFlags       = [int]($lsa.LsaCfgFlags)
        RunAsPPL          = [int]($lsa.RunAsPPL)
        CredentialGuard   = (([int]($lsa.LsaCfgFlags) -in @(1, 2)) -or ([int]($deviceGuard.LsaCfgFlags) -in @(1, 2)))
        CgUefiLock        = ([int]($lsa.LsaCfgFlags) -eq 1)
        PolicyPath        = $policyPath
        PolicyVbs         = [int]($policy.EnableVirtualizationBasedSecurity)
        PolicyHvci        = [int]($policy.HypervisorEnforcedCodeIntegrity)
        SecureBootKnown   = $SecureBoot.Known
        SecureBootEnabled = $SecureBoot.Enabled
        SecureBootSource  = $SecureBoot.Source
    }
}

function Get-BcdSigningState {
    <#
    .SYNOPSIS
        Reads the signing related overrides from the offline boot configuration.
    #>
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$StorePath = ''
    )

    $state = [PSCustomObject]@{ Available = $false; LoaderId = ''; TestSigning = $false; NoIntegrityChecks = $false }
    if ([string]::IsNullOrWhiteSpace($StorePath)) { return $state }
    if (-not (Test-BcdStorePath -StorePath $StorePath)) { return $state }

    $loaderId = Get-BcdPreferredOsGuid -StorePath $StorePath
    if (-not $loaderId) { return $state }

    $details = Get-BcdLoaderDetail -StorePath $StorePath -Identifier $loaderId
    if (-not $details) { return $state }

    $state.Available = $true
    $state.LoaderId = $loaderId
    $state.TestSigning = [bool]([regex]::Match($details.RawText, '(?im)^\s*testsigning\s+Yes\s*$').Success)
    $state.NoIntegrityChecks = [bool]([regex]::Match($details.RawText, '(?im)^\s*nointegritychecks\s+Yes\s*$').Success)
    return $state
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Builds the findings list from evidence only.

    .DESCRIPTION
        A protection being enabled is deliberately absent from this function. The only things that
        become findings are a driver the guest actually refused to load. Boot configuration
        overrides are reported as context only - see the note in the file header.
    #>
    param(
        [Parameter(Mandatory = $true)]$BlockEvidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][PSCustomObject[]]$Drivers
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($blocked in @($BlockEvidence.Files)) {
        $driver = @($Drivers | Where-Object { $_.FileName -eq $blocked.FileName } | Select-Object -First 1)
        if ($driver.Count -eq 0) {
            Add-OfflineRepairLog -Level Info -Message "Code Integrity refused $($blocked.FileName), but no driver service loads that image, so there is nothing to disable."
            continue
        }
        $driver = $driver[0]

        if ($driver.IsMicrosoft) {
            [void]$findings.Add((New-Finding -Cause 'BlockedMicrosoftDriver' -Item $driver.Service -Repairable $false `
                        -Message "Code Integrity refused the Microsoft driver $($blocked.FileName) (service $($driver.Service), events $($blocked.EventIds -join '/')). A Microsoft driver failing this check points at a damaged binary or a servicing problem rather than a third party driver, so it is reported instead of disabled."))
            continue
        }

        if ($driver.IsBootCritical -or $driver.IsPlatform) {
            $why = if ($driver.IsBootCritical) { 'the VM boots through it' } else { "it is an Azure platform driver from $($driver.Vendor)" }
            [void]$findings.Add((New-Finding -Cause 'BlockedCriticalDriver' -Item $driver.Service -Repairable $false `
                        -Message "Code Integrity refused $($blocked.FileName) (service $($driver.Service)), but $why. Disabling it would trade this failure for a lost disk or lost network, so it is reported instead. Update or replace the driver, or use -disableProtection true to boot once with the protection off."))
            continue
        }

        [void]$findings.Add((New-Finding -Cause 'BlockedDriver' -Item $driver.Service `
                    -Message "Code Integrity refused $($blocked.FileName) from $(if ($driver.Vendor) { $driver.Vendor } else { 'an unidentified vendor' }) $($blocked.Count) time(s), last at $($blocked.LastSeenUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC (events $($blocked.EventIds -join '/')). Service $($driver.Service) currently has Start=$($driver.Start) and will keep failing every boot." `
                    -Data $driver))
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    switch ($Finding.Cause) {
        'BlockedDriver' {
            $driver = $Finding.Data
            $keyPath = "$SystemRoot\Services\$($driver.Service)"
            if (-not (Test-Path $keyPath)) { throw "The service key $keyPath is no longer present." }
            Set-ItemProperty -Path $keyPath -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($driver.Service): Start $($driver.Start) -> 4 (disabled). Memory Integrity and Credential Guard were left untouched."
            Add-OfflineRepairLog -Message "$($driver.Service): to undo this after the VM boots, run: reg add `"HKLM\SYSTEM\CurrentControlSet\Services\$($driver.Service)`" /v Start /t REG_DWORD /d $($driver.Start) /f"
            return $true
        }
        default { return $false }
    }
}

function Disable-Protection {
    <#
    .SYNOPSIS
        Clears the Memory Integrity, Credential Guard and LSA protection values that are set.

    .DESCRIPTION
        Only reached when the operator passes -disableProtection true. Each value is written only
        when it is actually enabled, and the command to restore it is logged first.

    .OUTPUTS
        The number of values that were changed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Protection
    )

    $changed = 0
    $set = {
        param($Path, $Name, $Current, $LiveKey)
        if ($null -eq $Current -or [int]$Current -eq 0) { return $false }
        if (-not (Test-Path $Path)) { return $false }
        Add-OfflineRepairLog -Level Warning -Message "Restore with: reg add `"$LiveKey`" /v $Name /t REG_DWORD /d $Current /f"
        Set-ItemProperty -Path $Path -Name $Name -Value 0 -Type DWord -Force -ErrorAction Stop
        Add-OfflineRepairLog -Message "$Name : $Current -> 0"
        return $true
    }

    if (& $set $Protection.HvciPath 'Enabled' $(if ($Protection.HvciEnabled) { 1 } else { 0 }) 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity') { $changed++ }
    if (& $set $Protection.HvciPath 'Locked' $(if ($Protection.HvciLocked) { 1 } else { 0 }) 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity') { $changed++ }
    if (& $set $Protection.LsaPath 'LsaCfgFlags' $Protection.LsaCfgFlags 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa') { $changed++ }
    if (& $set $Protection.LsaPath 'RunAsPPL' $Protection.RunAsPPL 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa') { $changed++ }
    if (& $set $Protection.DeviceGuardPath 'LsaCfgFlags' $Protection.DeviceGuardLsaCfg 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard') { $changed++ }
    if (& $set $Protection.DeviceGuardPath 'EnableVirtualizationBasedSecurity' $Protection.DeviceGuardVbs 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard') { $changed++ }
    if (& $set $Protection.DeviceGuardPath 'RequirePlatformSecurityFeatures' $Protection.DeviceGuardReqPsf 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard') { $changed++ }
    if (& $set $Protection.PolicyPath 'EnableVirtualizationBasedSecurity' $Protection.PolicyVbs 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') { $changed++ }
    if (& $set $Protection.PolicyPath 'HypervisorEnforcedCodeIntegrity' $Protection.PolicyHvci 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') { $changed++ }

    if ($Protection.CgUefiLock) {
        Add-OfflineRepairLog -Level Warning -Message 'Credential Guard was enabled with a UEFI lock, which also sets an EFI firmware variable. The registry change alone will not clear it: boot the guest once with the Microsoft Credential Guard opt-out tool to remove the firmware variable.'
    }

    return $changed
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, disableProtection=$isProtectionDisableAllowed)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $blockEvidence = Get-CodeIntegrityBlockedFile -WindowsPath $offline.WindowsPath
    if (-not $blockEvidence.Available) {
        Log-Warning "Code Integrity evidence is unavailable: $($blockEvidence.Reason)" | Tee-Object -FilePath $logFile -Append
    }
    elseif ($blockEvidence.Files.Count -eq 0) {
        Log-Info "Code Integrity log read successfully: $($blockEvidence.Reason)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "Code Integrity refused $($blockEvidence.Files.Count) image(s): $(@($blockEvidence.Files.FileName) -join ', ')" | Tee-Object -FilePath $logFile -Append
    }

    $secureBootState = Get-OfflineSecureBootState -WindowsDrive $offline.WindowsDrive

    $bcdState = Get-BcdSigningState -StorePath $offline.BcdStorePath

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $protection = Get-ProtectionState -SystemRoot $systemRoot -SecureBoot $secureBootState
        $drivers = @(Get-KernelDriverInventory -SystemRoot $systemRoot -WindowsDrive $offline.WindowsDrive)
        $findings = @(Get-AllFinding -BlockEvidence $blockEvidence -Drivers $drivers)

        return [PSCustomObject]@{
            SystemRoot = $systemRoot
            ControlSet = (Split-Path -Path $systemRoot -Leaf)
            Protection = $protection
            Drivers    = $drivers
            Findings   = $findings
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $protection = $context.Protection
    $thirdParty = @($context.Drivers | Where-Object { -not $_.IsMicrosoft })

    # Context only. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet): Memory Integrity $(if ($protection.HvciEnabled) { 'on' } else { 'off' })$(if ($protection.HvciLocked) { ' (locked)' }), Credential Guard $(if ($protection.CredentialGuard) { 'on' } else { 'off' })$(if ($protection.CgUefiLock) { ' (UEFI lock)' }), LSA protection $(if ($protection.RunAsPPL -eq 1) { 'on' } else { 'off' }), Secure Boot $(if (-not $protection.SecureBootKnown) { "unknown ($($protection.SecureBootSource))" } elseif ($protection.SecureBootEnabled) { 'on' } else { 'off' })" | Tee-Object -FilePath $logFile -Append
    $bcdOverride = @()
    if ($bcdState.TestSigning) { $bcdOverride += 'testsigning' }
    if ($bcdState.NoIntegrityChecks) { $bcdOverride += 'nointegritychecks' }
    if ($bcdOverride.Count -eq 0) {
        Log-Info 'Boot configuration: no signing overrides are set.' | Tee-Object -FilePath $logFile -Append
    }
    elseif ($protection.SecureBootEnabled) {
        Log-Info "Boot configuration: $($bcdOverride -join ' and ') set while Secure Boot is on. Measured on this platform, the boot manager drops these at the next boot and the guest starts normally, so this is context and not a boot fault." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "Boot configuration: $($bcdOverride -join ' and ') set with Secure Boot off, so driver signing is relaxed. That does not stop a boot, but it can explain how an unsigned or tampered driver was allowed to load." | Tee-Object -FilePath $logFile -Append
    }
    Log-Info "$($context.Drivers.Count) kernel driver(s) configured to load, $($thirdParty.Count) of them non-Microsoft." | Tee-Object -FilePath $logFile -Append

    # Corroborating evidence. Reported as a lead, never repaired: a writable and executable section
    # makes a driver a candidate, not a culprit.
    #
    # A discardable section such as INIT is excluded. It is freed once the driver has initialised,
    # and measurement on a stock Windows Server 2022 image shows around fifteen inbox storage
    # drivers carrying one, so treating it as a signal would bury the real finding in noise.
    if ($protection.HvciEnabled) {
        $discardableOnly = 0
        foreach ($driver in $thirdParty) {
            if (-not $driver.Exists) { continue }
            $scan = Get-PeWritableExecutableSection -Path $driver.ResolvedPath
            if (-not $scan.Parsed) {
                Add-OfflineRepairLog -Level Info -Message "$($driver.Service): image not scanned ($($scan.Reason))."
                continue
            }

            $permanent = @($scan.Sections | Where-Object { -not $_.Discardable })
            if ($permanent.Count -eq 0) {
                if ($scan.Sections.Count -gt 0) { $discardableOnly++ }
                continue
            }

            $describe = @($permanent | ForEach-Object { $_.Name }) -join ', '
            $alreadyFound = @($context.Findings | Where-Object { $_.Item -eq $driver.Service }).Count -gt 0
            $note = if ($alreadyFound) { 'This matches the Code Integrity evidence above.' } else { 'No Code Integrity event names it, so it is a lead only and nothing was changed for it.' }
            Log-Warning "SUSPECT $($driver.Service) ($($driver.FileName), $(if ($driver.Vendor) { $driver.Vendor } else { 'unknown vendor' })) keeps section(s) writable and executable after load: $describe. Memory Integrity refuses such images. $note" | Tee-Object -FilePath $logFile -Append
        }
        if ($discardableOnly -gt 0) {
            Log-Info "$discardableOnly driver(s) have a writable and executable section that is discarded after initialisation. That is normal and was not treated as evidence." | Tee-Object -FilePath $logFile -Append
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Output "[$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = @()

    if ($repairable.Count -gt 0) {
        $needsHive = @($repairable | Where-Object { $_.Cause -eq 'BlockedDriver' }).Count -gt 0
        if ($needsHive) {
            $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append
        }


        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath
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

    $protectionChanges = 0
    if ($isProtectionDisableAllowed) {
        Log-Warning 'Disabling the protection was explicitly requested. This lowers the security posture of the VM and should be reverted once the driver is fixed.' | Tee-Object -FilePath $logFile -Append
        if ($repairedCount -eq 0) {
            $backupForProtection = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            Log-Info "SYSTEM hive backed up to $backupForProtection" | Tee-Object -FilePath $logFile -Append
        }
        $protectionChanges = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath
            return (Disable-Protection -Protection (Get-ProtectionState -SystemRoot $systemRoot -SecureBoot $secureBootState))
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        if ($protectionChanges -eq 0) {
            Log-Info 'No protection value needed clearing: they were already off.' | Tee-Object -FilePath $logFile -Append
        }
    }

    if ($findings.Count -eq 0 -and $protectionChanges -eq 0) {
        Log-Output 'No code integrity boot failure was found. Nothing on this disk shows a driver being refused, and the boot configuration is consistent with the Secure Boot state. No changes were made.' | Tee-Object -FilePath $logFile -Append
        if ($protection.HvciEnabled -or $protection.CredentialGuard) {
            Log-Output 'Memory Integrity or Credential Guard is enabled, which is normal and was deliberately left alone. Re-run with -disableProtection true only if you have separate evidence that it is the cause.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        return @(Get-AllFinding -BlockEvidence $blockEvidence `
                -Drivers @(Get-KernelDriverInventory -SystemRoot $systemRoot -WindowsDrive $offline.WindowsDrive))
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($protectionChanges -gt 0) { $summary += " Cleared $protectionChanges protection value(s) on request." }
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
