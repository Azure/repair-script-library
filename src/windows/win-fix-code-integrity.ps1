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
#        All four carry the same weight here, and this is the only evidence strong enough to
#        justify disabling a driver on its own. It has to be current to mean that: a refusal older
#        than 30 days, or one whose timestamp could not be read, is reported as a lead and never
#        repaired, because an evtx file on an attached disk can outlive the problem it recorded.
#     2. A portable executable scan of the third party kernel drivers, looking for a section that
#        stays writable and executable after load, which is the classic reason a driver is rejected
#        under Memory Integrity. Sections discarded after initialisation, such as INIT, are ignored:
#        a stock Windows Server 2022 image carries about fifteen inbox storage drivers with one, so
#        counting them would bury the real finding. This is reported as corroboration and as a lead
#        for the engineer, but it never disables anything by itself, because a section flagged this
#        way is not proof that this driver is what failed.
#     3. The offline Secure Boot state paired with the boot configuration. Test signing and
#        disabled integrity checks are read and reported alongside it, as context for how an
#        unsigned driver was allowed to load. Neither is repaired - see the note below for the
#        measurements behind that decision.
#
#   Causes detected and repaired:
#     1. A third party driver named in a recent Code Integrity block event, whose image could
#        actually be checked on the offline disk. Repaired by setting Start=4 on that one service,
#        so Windows stops trying to load it.
#
#   Reported but never repaired automatically:
#     - A Code Integrity refusal that is older than 30 days or carries no readable timestamp. The
#       driver is named so the engineer can act on it, but stale evidence never authorises a write.
#     - A named driver whose image is missing, empty, unreadable or not parseable by Authenticode.
#       Nothing can be proven about a file that cannot be read, so it stays a lead.
#     - A third party driver with a writable and executable section while Memory Integrity is on.
#       Reported with the section names so the engineer can decide.
#     - Any boot critical or Azure platform driver, even when the evidence names it. Disabling the
#       storage or bus driver the VM boots through trades this failure for a 0x7B, so the script
#       reports it and stops.
#     - Any driver that is signed by Microsoft, or that claims to be, even when the evidence names
#       it. That points at a damaged binary or a servicing problem, not a third party fault.
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
#   The BCD store is never written, so it is never backed up. Every hive this script writes is
#   backed up next to itself with a .bak-<timestamp> suffix while it is unmounted, before the first
#   write: SYSTEM when a driver is disabled, and SYSTEM and SOFTWARE when -disableProtection true
#   clears protection values. Those backups are files on the OS disk, so they survive
#   "az vm repair restore" and stay available on the recovered VM.
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
            $read = 0
            # Stream.Read is allowed to return a short count; keep asking until the header block is
            # full or the file ends, so a short read cannot look like a truncated image.
            while ($read -lt 8192) {
                $chunk = $stream.Read($header, $read, 8192 - $read)
                if ($chunk -le 0) { break }
                $read += $chunk
            }
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
        PSCustomObject with Available, Reason and Files. Files carry FileName, Paths, EventIds,
        Count, LastSeenUtc and Dated. Dated is false when no record for that image carried a
        readable timestamp, which the caller must treat as evidence it cannot date rather than as
        recent. Paths holds every distinct full image path the records named, which the caller
        needs to tell two drivers with the same file name apart; it is empty when the provider
        rendered the name without a path.
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
        # No -MaxEvents cap. The cap used to be 200, which silently discarded the oldest matching
        # records: a noisy log can hold more than that inside the authorisation window, and the
        # image that actually stopped the boot is not guaranteed to be among the newest. Dropping
        # it reports a clean disk. The Code Integrity channel is a small, size-capped log, so
        # reading all of its matching records is bounded by the file itself.
        $events = @(Get-WinEvent -Path $logPath -FilterXPath "*[System[(EventID=3033 or EventID=3077 or EventID=3023 or EventID=3004)]]" -ErrorAction Stop)
    }
    catch {
        # The message is localised, so it cannot be matched. The error identity is not.
        if (($_.FullyQualifiedErrorId -split ',', 2)[0] -eq 'NoMatchingEventsFound') {
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

        $carriesTime = ($null -ne $record.TimeCreated)
        if ($carriesTime) { $recordUtc = $record.TimeCreated.ToUniversalTime() } else { $recordUtc = [datetime]::MinValue }

        # Matched with the path separators left in, unlike the original expression which excluded
        # them and so kept only the last segment. Two services can load different drivers that
        # happen to share a file name, and a basename on its own cannot tell them apart - the
        # uniqueness check in Get-AllFinding needs the full path to refuse an ambiguous repair.
        foreach ($match in [regex]::Matches($text, '(?i)[^\s"''<>(),;]*[^\s\\/"''<>(),;]+\.sys')) {
            $raw = $match.Value.Trim()
            $fileName = (($raw -split '[\\/]')[-1]).ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($fileName)) { continue }
            if (-not $byFile.ContainsKey($fileName)) {
                $byFile[$fileName] = [PSCustomObject]@{
                    FileName    = $fileName
                    Paths       = [System.Collections.Generic.List[string]]::new()
                    EventIds    = [System.Collections.Generic.List[int]]::new()
                    Count       = 0
                    LastSeenUtc = [datetime]::MinValue
                    Dated       = $false
                }
            }
            $entry = $byFile[$fileName]
            if ($raw -match '[\\/]') {
                $normalised = $raw.ToLowerInvariant()
                if (-not $entry.Paths.Contains($normalised)) { [void]$entry.Paths.Add($normalised) }
            }
            $entry.Count++
            if (-not $entry.EventIds.Contains([int]$record.Id)) { [void]$entry.EventIds.Add([int]$record.Id) }
            if ($carriesTime) {
                $entry.Dated = $true
                if ($recordUtc -gt $entry.LastSeenUtc) { $entry.LastSeenUtc = $recordUtc }
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

        Trust is taken from Test-OfflineFileSignature, not from the version resource alone: a valid
        Authenticode signature naming Microsoft protects a driver even when CompanyName is blank,
        and a Microsoft CompanyName claim is still honoured on top of it because a false negative
        here would disable an inbox driver.

        ImageCheckable is false when nothing could be established about the binary - it is missing,
        empty, unreadable or not parseable by Authenticode. That is not the same as "unsigned", and
        the caller must not treat it as proof of a culprit.

        A denied read is never converted into an absent key or a clean inventory. Enumeration and
        property failures throw, because a driver that silently drops out of this list is a driver
        the repair will never consider.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $inventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $servicesRoot = "$SystemRoot\Services"
    $rootState = Get-OfflineHiveKeyState -HiveKey $servicesRoot
    if ($rootState -eq 'Absent') { return @() }
    if ($rootState -ne 'Present') {
        throw "The services list at $servicesRoot could not be read: its state is indeterminate, so the driver inventory would be unknown rather than empty."
    }

    $keys = @()
    try { $keys = @(Get-ChildItem -LiteralPath $servicesRoot -ErrorAction Stop) }
    catch { throw "The services list at $servicesRoot is unreadable, so no driver can be ruled out: $($_.Exception.Message)" }

    foreach ($key in $keys) {
        # LiteralPath, because a service name is allowed to contain characters that -Path would
        # read as a wildcard, and a key that silently matched nothing would drop a driver.
        try { $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop }
        catch { throw "The service key $($key.PSPath) is unreadable, so it cannot be ruled out as the culprit: $($_.Exception.Message)" }
        if ($null -eq $properties) { continue }
        if ([int]($properties.Type) -notin @(1, 2)) { continue }
        if ([int]($properties.Start) -notin @(0, 1, 2)) { continue }
        if (-not $properties.ImagePath) { continue }

        $resolved = Resolve-OfflineImagePath -ImagePath ([string]$properties.ImagePath) -WindowsDrive $WindowsDrive

        # Resolve-OfflineImagePath returns anything it does not recognise unchanged, so a UNC or
        # relative ImagePath survives as a path that is not on the disk being repaired. Reading
        # that file's signature would take authorisation to disable a service on the guest from a
        # file on the rescue VM or on the network. Refuse it: an image outside the bound offline
        # image is never checkable, and never counts as a Microsoft driver.
        $insideRoot = $true
        try { [void](Assert-OfflineTarget -Path $resolved -Action 'read the driver image of') }
        catch { $insideRoot = $false }

        if ($insideRoot) {
            $exists = Test-OfflinePath $resolved
            $signature = Test-OfflineFileSignature -FilePath $resolved
        }
        else {
            $exists = $false
            $signature = [PSCustomObject]@{ Status = 'OutsideOfflineImage'; IsLikelyMicrosoft = $false; VersionCompany = '' }
        }
        $vendor = if ($signature.VersionCompany) { $signature.VersionCompany.Trim() } else { '' }

        # Nothing could be established about the file itself. Neither trusted nor untrusted.
        $checkable = ($insideRoot -and ($signature.Status -notin @('FileNotFound', 'ZeroByte', 'Error', 'NotVerifiable')))

        [void]$inventory.Add([PSCustomObject]@{
                Service        = $key.PSChildName
                KeyPath        = $key.PSPath
                ImagePathRaw   = [string]$properties.ImagePath
                ResolvedPath   = $resolved
                FileName       = (Split-Path -Path $resolved -Leaf).ToLowerInvariant()
                Exists         = $exists
                Start          = [int]$properties.Start
                Vendor         = $vendor
                Signature      = $signature.Status
                ImageCheckable = $checkable
                OutsideRoot    = (-not $insideRoot)
                # Proven by signature, or claimed by the version resource. Either one is enough to
                # leave the driver alone; only a third party binary is ever disabled. An image
                # outside the offline disk proves nothing either way, so it is never trusted here.
                IsMicrosoft    = ($insideRoot -and ($signature.IsLikelyMicrosoft -or ($vendor -match 'Microsoft')))
                IsPlatform     = ($vendor -and $vendor -match $script:PlatformVendorPattern)
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

        Every value is read with Get-OfflineRegistryDword, which returns null only for a value that
        is genuinely absent and throws on a denied read or a wrong value type. "Access denied" and
        "not configured" look identical through Get-ItemProperty -ErrorAction SilentlyContinue, and
        reporting a protection as off when it could not be read would be reporting the opposite of
        the truth. An absent value still means unconfigured, which is the normal case.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][PSCustomObject]$SecureBoot
    )

    $hvciPath = "$SystemRoot\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $deviceGuardPath = "$SystemRoot\Control\DeviceGuard"
    $lsaPath = "$SystemRoot\Control\Lsa"
    $policyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Windows\DeviceGuard'

    $hvciEnabled = Get-OfflineRegistryDword -Key $hvciPath -Name 'Enabled'
    $hvciLocked = Get-OfflineRegistryDword -Key $hvciPath -Name 'Locked'
    $deviceGuardLsaCfg = Get-OfflineRegistryDword -Key $deviceGuardPath -Name 'LsaCfgFlags'
    $deviceGuardVbs = Get-OfflineRegistryDword -Key $deviceGuardPath -Name 'EnableVirtualizationBasedSecurity'
    $deviceGuardReqPsf = Get-OfflineRegistryDword -Key $deviceGuardPath -Name 'RequirePlatformSecurityFeatures'
    $lsaCfgFlags = Get-OfflineRegistryDword -Key $lsaPath -Name 'LsaCfgFlags'
    $runAsPpl = Get-OfflineRegistryDword -Key $lsaPath -Name 'RunAsPPL'
    $policyVbs = Get-OfflineRegistryDword -Key $policyPath -Name 'EnableVirtualizationBasedSecurity'
    $policyHvci = Get-OfflineRegistryDword -Key $policyPath -Name 'HypervisorEnforcedCodeIntegrity'

    return [PSCustomObject]@{
        # The effective state, not just the scenario key. HVCI can be turned on by policy alone,
        # and deriving this from Scenarios\... by itself reports Memory Integrity off on a VM where
        # it is actually enforced - which then skips the corroborating PE scan that is gated on it.
        # The raw scenario value is kept beside it, because the restore log has to say what was
        # really set rather than what was in effect.
        HvciEnabled       = (([int]$hvciEnabled -eq 1) -or ([int]$policyHvci -eq 1))
        HvciScenario      = [int]$hvciEnabled
        HvciLocked        = ([int]$hvciLocked -eq 1)
        HvciPath          = $hvciPath
        DeviceGuardPath   = $deviceGuardPath
        DeviceGuardLsaCfg = [int]$deviceGuardLsaCfg
        DeviceGuardVbs    = [int]$deviceGuardVbs
        DeviceGuardReqPsf = [int]$deviceGuardReqPsf
        LsaPath           = $lsaPath
        LsaCfgFlags       = [int]$lsaCfgFlags
        RunAsPPL          = [int]$runAsPpl
        CredentialGuard   = (([int]$lsaCfgFlags -in @(1, 2)) -or ([int]$deviceGuardLsaCfg -in @(1, 2)))
        CgUefiLock        = ([int]$lsaCfgFlags -eq 1)
        PolicyPath        = $policyPath
        PolicyVbs         = [int]$policyVbs
        PolicyHvci        = [int]$policyHvci
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

function Get-ImagePathTail {
    <#
    .SYNOPSIS
        The last few path segments of an image path, lowercased, for comparing two spellings.

    .DESCRIPTION
        A Code Integrity record names an image the way the kernel saw it - "\??\C:\Windows\..."
        or "\Device\HarddiskVolume2\Windows\..." - and the registry names the same file as
        "\SystemRoot\System32\drivers\foo.sys", which the helpers resolve onto whatever letter the
        rescue VM gave the disk. None of those strings are equal, but their tails are, and the
        tail is what distinguishes two drivers that share a file name.
    #>
    param(
        [Parameter(Mandatory = $false)][AllowNull()][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $false)][int]$Segments = 3
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $parts = @(($Path.ToLowerInvariant() -split '[\\/]') | Where-Object { $_ -and $_ -ne '??' })
    if ($parts.Count -eq 0) { return '' }
    $take = [Math]::Min($Segments, $parts.Count)
    return (($parts[($parts.Count - $take)..($parts.Count - 1)]) -join '\')
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Builds the findings list from evidence only.

    .DESCRIPTION
        A protection being enabled is deliberately absent from this function. The only things that
        become findings are a driver the guest actually refused to load. Boot configuration
        overrides are reported as context only - see the note in the file header.

        Only one shape of finding is repairable: a third party driver, whose image could actually
        be checked, named by a refusal recent enough to still describe this disk. Everything else
        that evidence names is kept as a visible manual lead. Dropping it would report the disk as
        clean, which is worse than reporting something the script will not act on by itself.

    .PARAMETER MaxEventAgeDay
        How recent a refusal has to be to authorise a write. An evtx file on an attached disk
        outlives the problem it recorded: the driver may already have been updated, or the log may
        have been carried over from an earlier image. Defaults to 30 days.
    #>
    param(
        [Parameter(Mandatory = $true)]$BlockEvidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][PSCustomObject[]]$Drivers,
        [Parameter(Mandatory = $false)][int]$MaxEventAgeDay = 30
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-$MaxEventAgeDay)

    # Not being able to read the evidence is not the same as there being none. Without this the
    # findings list comes back empty, the run takes the no-findings branch, and a disk whose log
    # could not be inspected is reported as one where nothing was refused - the single conclusion
    # the evidence cannot support. It fails closed instead, as a finding nobody can miss.
    if (-not $BlockEvidence.Available) {
        [void]$findings.Add((New-Finding -Cause 'EvidenceUnavailable' -Item 'Code Integrity log' -Repairable $false `
                    -Message "The Code Integrity evidence could not be read: $($BlockEvidence.Reason). Nothing can be shown to have been refused, and nothing can be ruled out either, so no change was made and this disk is not being reported as healthy. Inspect System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx by hand, or pursue the boot failure by another route."))
        return @($findings)
    }

    foreach ($blocked in @($BlockEvidence.Files)) {
        $candidates = @($Drivers | Where-Object { $_.FileName -eq $blocked.FileName })
        if ($candidates.Count -eq 0) {
            # Reported, not dropped. The .DESCRIPTION above promises that evidence this script
            # cannot act on stays visible; logging it at Info and continuing let the run reach the
            # no-findings branch and call the disk clean while the guest's own log named an image
            # it had refused to load.
            $where = if ($blocked.Paths.Count -gt 0) { " (recorded as $($blocked.Paths -join ', '))" } else { '' }
            [void]$findings.Add((New-Finding -Cause 'BlockedImageNotInInventory' -Item $blocked.FileName -Repairable $false `
                        -Message "Code Integrity refused $($blocked.FileName) $($blocked.Count) time(s) (events $($blocked.EventIds -join '/'))$where, but no kernel driver service on this disk is configured to load that image. There is no service to disable, so it is reported for a decision: the image may be loaded by something other than a service entry, or the service may already have been removed while the log kept the record."))
            continue
        }

        # A file name is not an identity. Two services can load different binaries that share one,
        # and the refusal only authorises acting on the one the record actually named - so when the
        # name is ambiguous, the full path decides, and if it cannot, nothing is disabled.
        if ($candidates.Count -gt 1) {
            $matched = @()
            if ($blocked.Paths.Count -gt 0) {
                $eventTails = @($blocked.Paths | ForEach-Object { Get-ImagePathTail -Path $_ } | Where-Object { $_ })
                $matched = @($candidates | Where-Object {
                        ((Get-ImagePathTail -Path $_.ResolvedPath) -in $eventTails) -or
                        ((Get-ImagePathTail -Path $_.ImagePathRaw) -in $eventTails)
                    })
            }

            if ($matched.Count -eq 1) {
                $candidates = $matched
            }
            else {
                [void]$findings.Add((New-Finding -Cause 'BlockedDriverAmbiguous' -Item (@($candidates.Service) -join ', ') -Repairable $false `
                            -Message "Code Integrity refused $($blocked.FileName) (events $($blocked.EventIds -join '/')), but $($candidates.Count) driver services on this disk load an image with that name: $((@($candidates | ForEach-Object { "$($_.Service) -> $($_.ResolvedPath)" })) -join '; '). $(if ($blocked.Paths.Count -gt 0) { "The recorded path(s) $($blocked.Paths -join ', ') did not single one out." } else { 'The records did not carry a full path.' }) Disabling the wrong one would break a working driver and leave the real fault in place, so it is reported instead. Identify the refused image by hand, then set Start=4 on that service."))
                continue
            }
        }

        $driver = $candidates[0]
        $seen = if ($blocked.Dated) { "last at $($blocked.LastSeenUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC" } else { 'with no readable timestamp' }

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

        if (-not $driver.ImageCheckable) {
            [void]$findings.Add((New-Finding -Cause 'BlockedUncheckableImage' -Item $driver.Service -Repairable $false `
                        -Message "Code Integrity refused $($blocked.FileName) (service $($driver.Service), events $($blocked.EventIds -join '/'), $seen), but nothing could be established about the image on this disk ($($driver.Signature)) at $($driver.ResolvedPath). An unreadable file is not evidence that this driver is the culprit, so it is reported for a decision instead of disabled. Check the image by hand, then set Start=4 on the service if it is the right one."))
            continue
        }

        if (-not $blocked.Dated) {
            [void]$findings.Add((New-Finding -Cause 'BlockedDriverUndatedEvidence' -Item $driver.Service -Repairable $false `
                        -Message "Code Integrity refused $($blocked.FileName) from $(if ($driver.Vendor) { $driver.Vendor } else { 'an unidentified vendor' }) $($blocked.Count) time(s) (service $($driver.Service), events $($blocked.EventIds -join '/')), but no record carried a readable timestamp, so the refusal cannot be shown to describe the current state of this disk. It is reported for a decision instead of disabled."))
            continue
        }

        if ($blocked.LastSeenUtc -lt $cutoffUtc) {
            [void]$findings.Add((New-Finding -Cause 'BlockedDriverStaleEvidence' -Item $driver.Service -Repairable $false `
                        -Message "Code Integrity refused $($blocked.FileName) from $(if ($driver.Vendor) { $driver.Vendor } else { 'an unidentified vendor' }) $($blocked.Count) time(s), $seen (service $($driver.Service), events $($blocked.EventIds -join '/')). That is more than $MaxEventAgeDay days old, so the driver may already have been fixed. It is reported for a decision instead of disabled."))
            continue
        }

        [void]$findings.Add((New-Finding -Cause 'BlockedDriver' -Item $driver.Service `
                    -Message "Code Integrity refused $($blocked.FileName) from $(if ($driver.Vendor) { $driver.Vendor } else { 'an unidentified vendor' }) $($blocked.Count) time(s), $seen (events $($blocked.EventIds -join '/')). Service $($driver.Service) currently has Start=$($driver.Start) and will keep failing every boot." `
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
            # LiteralPath on both, for the reason the inventory already gives: a service name is
            # allowed to contain characters that -Path reads as a wildcard. Enumerating with
            # -LiteralPath and then writing with -Path is the mismatch that lets a name like
            # "foo[1]" test one key and write a different one, or none at all.
            if (-not (Test-Path -LiteralPath $keyPath)) { throw "The service key $keyPath is no longer present." }
            # Through the protected writer, which proves the key is inside the mounted offline
            # image before it writes and handles a TrustedInstaller-owned key. Writing directly
            # skipped the gate that every other repair in the library passes through.
            $outcome = Invoke-OfflineProtectedRegistryWrite -Path $keyPath -Description "$($driver.Service) Start" -Action {
                Set-ItemProperty -LiteralPath $keyPath -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction Stop
            }
            if (-not $outcome.Written) {
                throw "The Start value of $($driver.Service) could not be written: $($outcome.Reason)"
            }
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
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        Add-OfflineRepairLog -Level Warning -Message "Restore with: reg add `"$LiveKey`" /v $Name /t REG_DWORD /d $Current /f"
        # Through the protected writer, which asserts the key belongs to the mounted offline image
        # before anything is written, and takes a TrustedInstaller-owned key only when the plain
        # write is actually refused. A bare Set-ItemProperty here bypassed the fail-closed gate
        # that every other writer in the library goes through.
        $outcome = Invoke-OfflineProtectedRegistryWrite -Path $Path -Description "$Name" -Action {
            Set-ItemProperty -LiteralPath $Path -Name $Name -Value 0 -Type DWord -Force -ErrorAction Stop
        }
        if (-not $outcome.Written) {
            Add-OfflineRepairLog -Level Warning -Message "$Name could not be cleared: $($outcome.Reason)"
            return $false
        }
        Add-OfflineRepairLog -Message "$Name : $Current -> 0"
        return $true
    }

    if (& $set $Protection.HvciPath 'Enabled' $Protection.HvciScenario 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity') { $changed++ }
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

$status = $STATUS_ERROR

try {
    # A labelled single-pass loop. A bare "return" at script scope would leave the finally
    # block's cleanup and buffered log output unwritten, so early exits break out instead.
    :Main do {
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
            $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
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
        # Every state below distinguishes "unknown" from "off". Reporting something as off because
        # it could not be read is reporting the opposite of what is known, and the operator acts on
        # these lines.
        $lsaState = switch ([int]$protection.RunAsPPL) {
            1 { 'on' }
            2 { 'on (locked)' }
            default { 'off' }
        }
        Log-Info "Control set $($context.ControlSet): Memory Integrity $(if ($protection.HvciEnabled) { 'on' } else { 'off' })$(if ($protection.HvciLocked) { ' (locked)' }), Credential Guard $(if ($protection.CredentialGuard) { 'on' } else { 'off' })$(if ($protection.CgUefiLock) { ' (UEFI lock)' }), LSA protection $lsaState, Secure Boot $(if (-not $protection.SecureBootKnown) { "unknown ($($protection.SecureBootSource))" } elseif ($protection.SecureBootEnabled) { 'on' } else { 'off' })" | Tee-Object -FilePath $logFile -Append
        $bcdOverride = @()
        if ($bcdState.TestSigning) { $bcdOverride += 'testsigning' }
        if ($bcdState.NoIntegrityChecks) { $bcdOverride += 'nointegritychecks' }
        if (-not $bcdState.Available) {
            Log-Info 'Boot configuration: the boot configuration data could not be read, so whether any signing override is set is unknown. An unreadable store is not evidence that there are none.' | Tee-Object -FilePath $logFile -Append
        }
        elseif ($bcdOverride.Count -eq 0) {
            Log-Info 'Boot configuration: no signing overrides are set.' | Tee-Object -FilePath $logFile -Append
        }
        elseif (-not $protection.SecureBootKnown) {
            Log-Info "Boot configuration: $($bcdOverride -join ' and ') set, with the Secure Boot state unknown ($($protection.SecureBootSource)). If Secure Boot is on the boot manager drops these at the next boot; if it is off, driver signing is relaxed and that can explain how an unsigned or tampered driver was allowed to load." | Tee-Object -FilePath $logFile -Append
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

        # Ahead of the detect gate on purpose. The findings above are printed by a loop, so on a
        # healthy disk it prints nothing and the only thing left would be a count - and "found 0
        # issue(s)" differs from "found 2 issue(s), 0 of which this script can repair" by a single
        # digit in a log the operator skims. The repair path has its own affirmative line further
        # down, after any protection change, so this one is scoped to detect mode and nothing on
        # the -disableProtection path is short-circuited.
        if ($findings.Count -eq 0 -and $isDetectOnly) {
            Log-Output 'Detect only: no Code Integrity driver refusals were found on this disk. The Code Integrity log was read and named no image that a driver service is configured to load. No changes were made.' | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
        }

        if ($isDetectOnly) {
            Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            $status = $STATUS_SUCCESS
            break Main
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
                $systemRoot = Get-OfflineSystemRootPath -Strict
                # The findings were built under an earlier mount, against whichever control set
                # Select\Current named then. This remount re-reads it, and every repair below
                # writes under the root it returns - so if it now names a different control set,
                # the writes would land in one the evidence was never gathered from. Refuse rather
                # than write to a service key chosen by a selector that moved underneath us.
                $repairControlSet = Split-Path -Path $systemRoot -Leaf
                if ($repairControlSet -ne $context.ControlSet) {
                    throw "The selected control set changed between detection and repair ($($context.ControlSet) -> $repairControlSet). Nothing was written. Re-run the script so the findings are rebuilt against the control set that would actually be written."
                }
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
            # Both hives are written below - SYSTEM for Control\DeviceGuard and Control\Lsa,
            # SOFTWARE for the DeviceGuard policy values - so both are backed up first, while they
            # are still unmounted. SYSTEM may already have been backed up by the driver repair.
            if ($repairedCount -eq 0) {
                $backupForProtection = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                Log-Info "SYSTEM hive backed up to $backupForProtection" | Tee-Object -FilePath $logFile -Append
            }
            $softwareBackup = Backup-OfflineHiveFile -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append
            $protectionChanges = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
                $systemRoot = Get-OfflineSystemRootPath -Strict
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
            $status = $STATUS_SUCCESS
            break Main
        }

        # Verify against freshly read state rather than trusting the writes above. Only SYSTEM is
        # read here, so SOFTWARE is not mounted: every extra hive is another unload that can fail.
        $remaining = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
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
            $status = $STATUS_ERROR
            break Main
        }

        Log-Output $summary | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $unrepairable) {
            Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        if ($repairedCount -gt 0) {
            Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
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
    # A dependency may have failed to load before these functions became available.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        try {
            Clear-OfflineDriveLetter
            if (@(Get-OfflineAssignedDriveLetter).Count -gt 0) {
                $status = $STATUS_ERROR
                Add-OfflineRepairLog -Level Error -Message 'Temporary drive letters remain assigned. The repair may have completed, but cleanup is incomplete; inspect the cleanup diagnostics before proceeding.'
            }
        }
        catch {
            $status = $STATUS_ERROR
            Add-OfflineRepairLog -Level Error -Message "Drive-letter cleanup failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        try {
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append -ErrorAction Stop
        }
        catch {
            $status = $STATUS_ERROR
            Log-Error "Final helper diagnostics could not be written to the detail log: $($_.Exception.Message)"
        }
    }
}
return $status
