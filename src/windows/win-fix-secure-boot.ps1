#########################################################################################################
# .SYNOPSIS
#   Repairs the signed boot chain a Generation 2 VM starts through, when those files are stale,
#   corrupt or missing.
#
# .DESCRIPTION
#   A Gen2 VM starts by having its firmware run \EFI\Microsoft\Boot\bootmgfw.efi from the EFI System
#   Partition. That boot manager loads winload.efi, which loads ci.dll, the kernel and the Code
#   Integrity policy files. Every one of those is signed, and every one of them is checked before
#   the next is allowed to run.
#
#   When one of them is corrupt or missing, the chain stops. The usual result is 0xc0430001 -
#   STATUS_ERROR_LOADING_REGISTRY, reported by winload before anything has started. There is no
#   event log to read afterwards, because nothing ever got far enough to write one.
#
#   Evidence used, in order:
#     1. The digital signature of every file in the boot chain, and of the boot manager on the EFI
#        System Partition. This is the same evidence the firmware and the boot manager themselves
#        use, so a file that fails here is precisely a file the boot chain will refuse.
#     2. The Secure Boot state the guest last booted with, read from the Measured Boot log. This is
#        reported as context either way and is never itself treated as a fault.
#
#   Causes detected and repaired:
#     1. A boot manager missing from the EFI System Partition, or present with a signature that no
#        longer verifies because it was truncated, zeroed or overwritten. The fallback loader is
#        restored from the working boot manager already on the EFI System Partition where there is
#        one, because that is the file this VM has actually been booting; otherwise from the copy
#        Windows stages.
#     2. A boot chain file on the Windows partition whose signature no longer verifies. Repaired
#        with a targeted "sfc /SCANFILE" against that one file, which sources the replacement from
#        the guest's own store and so is always the right build.
#
#   Reported but never repaired automatically:
#     - A file whose signature is well formed but is not trusted by the rescue VM. That describes
#       the rescue VM's certificate store, not the guest's file, so it is reported and left alone.
#     - A boot manager that is missing or unusable when the staged copy is missing or unusable too.
#       Copying a boot manager from anywhere other than this installation is how a VM ends up
#       running a different build's loader, so the script stops and says what is missing.
#
# .RESOLVES
#   Gen2 boot failures in the loader, before the kernel starts and before any event log exists.
#   Typically 0xc0430001, a Secure Boot violation screen, or a VM that returns to the firmware boot
#   menu because the boot manager it was pointed at is gone or unreadable.
#
#   This script does NOT cover:
#     - A driver being refused once Windows is running. That leaves Code Integrity events behind
#       and is handled by win-fix-code-integrity.
#     - Boot configuration content - a missing, empty or wrong BCD store. Use win-fix-bcd.
#     - A missing or unreadable EFI System Partition itself, as opposed to bad files on a healthy
#       one. Use win-fix-boot-partition.
#     - Component store corruption in general. This script only ever touches the fixed list of boot
#       chain files below and never runs a full scan. If corruption is broader, use
#       win-sfc-sf-corruption.
#
# .PARAMETER detectOnly
#   'true' reports what is wrong and changes nothing at all. No file is written and sfc is never
#   invoked, because offline sfc repairs even when asked only to verify - see .NOTES.
#
# .PARAMETER revert
#   'true' puts back every file this script replaced, using the backups it took, and restores the
#   original state.
#
# .PARAMETER windowsDrive
#   Skips discovery and uses this drive letter as the offline Windows volume.
#
# .NOTES
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The boot manager on the EFI System Partition is NOT expected to match the copy Windows stages
#   at Windows\Boot\EFI\bootmgfw.efi, and a difference is never treated as staleness. Measured on a
#   healthy, currently booting Server 2022 Azure Edition VM with Secure Boot on: the EFI System
#   Partition held bootmgfw.efi version 10.0.28000.322 at 3,086,728 bytes, while the operating
#   system was 10.0.20348 and staged 10.0.20348.5139 at 2,118,640 bytes. The file on the EFI System
#   Partition matched none of the six copies of bootmgfw.efi in the component store. Secure Boot
#   servicing updates that boot manager on its own schedule, ahead of the operating system, as part
#   of the signing certificate and SBAT revocation work - so the newer, unmatched file is the
#   correct one. Replacing it with the staged copy would roll back a security update, and where the
#   firmware's SBAT level has already moved past that older boot manager it would be self-revoked
#   and refused, turning a VM that boots into one that does not.
#
#   For the same reason there is no check on SKUSiPolicy.p7b. The same healthy VM had no
#   SKUSiPolicy.p7b on its EFI System Partition at all while booting with Secure Boot enabled, so
#   its absence is a normal state. The copy under Windows\System32\SecureBootUpdates is the
#   servicing stack's source for that policy, not evidence that the partition should carry it.
#
#   Integrity is decided by the file's digital signature, NOT by comparing it with the copies in the
#   component store. The store comparison cannot work: the files under System32 are hard links to
#   their component store copy, so corrupting one corrupts the other and the two still agree.
#   Measured on a Server 2022 disk with winload.efi deliberately corrupted, the store comparison
#   reported it as matching a copy in the store - a false negative on a file that was plainly broken
#   - while its signature had already stopped verifying. Signature verification also costs far less:
#   thirteen files verified in 2.18 seconds against 193 seconds to index 15,286 component store
#   directories.
#
#   The boot manager Secure Boot servicing installs is signed by the Windows UEFI CA 2023 and still
#   verifies as Valid on a Server 2022 rescue VM, so the newer signing chain does not cause a false
#   positive. A well formed signature that this rescue VM does not trust is reported and never
#   repaired, because that describes the rescue VM rather than the guest.
#
#   Offline "sfc /VERIFYFILE" REPAIRS, despite its own help text saying "No repair operation is
#   performed". Measured on a Server 2022 disk with winload.efi deliberately corrupted, /VERIFYFILE
#   logged "Cannot repair member file 'winload.efi' ... hash mismatch" and then "Repairing file
#   \??\C:\Windows\System32\winload.efi from store", rewriting both the store copy and the file. It
#   is therefore never used, and detection is done by hashing instead. That is also why sfc is not
#   run at all under -detectOnly.
#
#   sfc's exit code is 0 whether or not it found anything, and it writes UTF-16 to the console,
#   which is unreadable when captured. Only /OFFLOGFILE is parsed, for the [SR] lines.
#
#   The boot chain files are owned by NT SERVICE\TrustedInstaller and deny write even to SYSTEM, so
#   every write goes through Copy-OfflineProtectedFile, which captures the original security
#   descriptor, takes ownership only when a plain attempt was actually refused, and replays the
#   whole descriptor afterwards. A repaired guest boots with TrustedInstaller owning its system
#   files again.
#
#   The Secure Boot state cannot be read from an offline registry hive. Windows keeps it in
#   Control\SecureBoot\State, which is a volatile key: it is recreated from the firmware at every
#   boot and never written to the hive file. It is read from the Measured Boot log instead - see
#   Get-OfflineSecureBootState in OfflineRepairCommon.ps1.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')

$script:BackupSuffix = ".$scriptName-backup-$scriptStartTime"
# A file this script creates has no content to back up, so its record has to be a marker on the
# disk. An in-memory note would not survive the run, and -revert is a separate run.
$script:AbsentMarkerSuffix = '.absent'
$script:BackupManifest = [System.Collections.Generic.List[PSCustomObject]]::new()

# The boot chain, in the order the firmware and the loader walk it. Optional entries are absent on
# healthy installations often enough that their absence is not a fault: winresume.efi only exists
# where hibernation was configured, and the Hyper-V loader only where virtualisation based security
# is in use. Everything else is present on every Gen2 Server image, so a missing one is a finding.
$script:BootChainFile = @(
    @{ RelativePath = 'Windows\Boot\EFI\bootmgfw.efi'; Label = 'Windows-staged boot manager'; Optional = $false }
    @{ RelativePath = 'Windows\System32\winload.efi'; Label = 'OS loader (winload.efi)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\winresume.efi'; Label = 'resume loader (winresume.efi)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\ci.dll'; Label = 'Code Integrity engine (ci.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\ntoskrnl.exe'; Label = 'NT kernel (ntoskrnl.exe)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\hal.dll'; Label = 'hardware abstraction layer (hal.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\kdcom.dll'; Label = 'kernel debug transport (kdcom.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\pshed.dll'; Label = 'platform hardware error driver (pshed.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\drivers\clfs.sys'; Label = 'Common Log File System driver (clfs.sys)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\hvloader.dll'; Label = 'Hyper-V loader (hvloader.dll)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\hvix64.exe'; Label = 'Hyper-V hypervisor image (hvix64.exe)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\SiPolicy.p7b'; Label = 'Code Integrity policy (SiPolicy.p7b)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\Driver.stl'; Label = 'driver revocation list (Driver.stl)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\DriverSiPolicy.p7b'; Label = 'driver signing policy (DriverSiPolicy.p7b)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\SecureBootUpdates\SKUSiPolicy.p7b'; Label = 'Secure Boot SKU policy source (SKUSiPolicy.p7b)'; Optional = $false }
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

function Get-FileHashValue {
    <#
    .SYNOPSIS
        SHA256 of a file, or an empty string when it cannot be read.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not hash $Path : $($_.Exception.Message)"
        return ''
    }
}

function Get-PeImageInfo {
    <#
    .SYNOPSIS
        Reads the PE header of an image to learn its architecture.

    .DESCRIPTION
        Used only to work out which fallback loader name this installation needs. Whether a file is
        intact is decided by its signature instead - see Get-SignatureState.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{
        Exists    = $false
        IsPe      = $false
        Machine   = 0
        Subsystem = 0
        IsEfi     = $false
        Length    = 0
    }

    if (-not (Test-OfflinePath $Path)) { return $result }
    $result.Exists = $true

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $result.Length = $stream.Length
            $header = New-Object byte[] 1024
            $read = $stream.Read($header, 0, 1024)
            if ($read -lt 512 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) { return $result }

            $peOffset = [BitConverter]::ToInt32($header, 0x3C)
            if ($peOffset -le 0 -or ($peOffset + 94) -ge $read) { return $result }
            if ([System.Text.Encoding]::ASCII.GetString($header, $peOffset, 4) -ne "PE`0`0") { return $result }

            $result.IsPe = $true
            $result.Machine = [BitConverter]::ToUInt16($header, $peOffset + 4)

            # Subsystem sits at optional header offset 68 in both PE32 and PE32+, and the optional
            # header starts 24 bytes after the PE signature.
            $result.Subsystem = [BitConverter]::ToUInt16($header, $peOffset + 92)
            $result.IsEfi = $result.Subsystem -ge 10 -and $result.Subsystem -le 13
        }
        finally { $stream.Dispose() }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not read the PE header of $Path : $($_.Exception.Message)"
    }

    return $result
}

function Get-EfiFallbackBootFileName {
    <#
    .SYNOPSIS
        The removable-media fallback loader name for this image's architecture.

    .DESCRIPTION
        Firmware that cannot find a boot entry falls back to \EFI\Boot\boot<arch>.efi. The name is
        architecture specific, and writing an x64 loader to the ARM64 name leaves the firmware
        refusing it just as firmly as if there were no loader at all.

        The architecture is read from the Machine field of the kernel's own PE header rather than
        from the rescue VM, which may be a different architecture than the disk attached to it, and
        rather than from the registry, which would need a hive mount for two bytes.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $kernel = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\ntoskrnl.exe'
    $machine = (Get-PeImageInfo -Path $kernel).Machine

    switch ($machine) {
        0xAA64 { return 'bootaa64.efi' }
        0x8664 { return 'bootx64.efi' }
        0x014C { return 'bootia32.efi' }
        default {
            # Machine 0 covers four different outcomes - the kernel is absent, too short to hold a
            # PE header, not a PE image at all, or could not be read - and none of them is evidence
            # of an architecture. This name becomes the Destination of a copy, so assuming x64 here
            # lets a failed read pick a write target: on an ARM64 guest it writes an ARM64 boot
            # manager to the x64 name, leaves the real bootaa64.efi unexamined, and reports the run
            # as repaired on a VM that still will not boot. The trigger is self-referential, since a
            # corrupt ntoskrnl.exe is one of the faults this script exists to report.
            #
            # An empty name is returned instead, and Get-EspFinding turns it into a non-repairable
            # ArchitectureUnknown finding.
            Add-OfflineRepairLog -Level Warning -Message ("The architecture could not be read from $kernel (PE machine 0x{0:X4}), so the EFI fallback loader name for this installation is unknown." -f $machine)
            return ''
        }
    }
}

function Get-SignatureState {
    <#
    .SYNOPSIS
        Verifies the digital signature of one boot chain file.

    .DESCRIPTION
        This is the check the firmware and the boot manager themselves perform, which is what makes
        it the right test for this scenario. A file whose signature no longer verifies is exactly a
        file the boot chain will refuse.

        It replaced a comparison against the copies in the component store, which cannot work: the
        files under System32 are hard links to their component store copy, so corrupting one
        corrupts the other and the two still agree. Measured on a Server 2022 disk with winload.efi
        deliberately corrupted, the store comparison reported it as matching a copy in the store
        while its signature had already stopped verifying.

        Verdicts:
          Valid                                 the file is intact and is the file Microsoft signed
          HashMismatch, NotSigned, UnknownError the bytes no longer match the signature, or the
                                                signature is gone with them - repairable
          NotTrusted                            the signature is well formed but its chain is not
                                                trusted HERE. That is a statement about the rescue
                                                VM, not about the guest, so it is reported and never
                                                repaired.
          Unreadable                            the signature could not be evaluated at all because
                                                the call threw. That is a statement about the read,
                                                not about the file, so it is reported and never
                                                repaired.

        UnknownError is a verdict the trust provider RETURNS, and it is repairable because a zeroed
        3 MB file produces exactly that. A call that THROWS is a different thing and must not be
        collapsed into it: an I/O error or a sharing violation is no evidence about the bytes, and
        treating it as such would let a failed read authorise overwriting a serviced boot manager.

        A zeroed 3 MB file reports UnknownError with "The form specified for the subject is not one
        supported or known by the specified trust provider"; a file with corrupted bytes over its
        header reports NotSigned. Both mean the same thing for this purpose.

        No network is needed. A second pass over the same thirteen files returned identical verdicts
        in 0.26s, so nothing here depends on reaching a revocation list.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $state = [PSCustomObject]@{
        Status  = 'Missing'
        Intact  = $false
        Verdict = 'Missing'
        Message = ''
    }

    if (-not (Test-OfflinePath $Path)) { return $state }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $state.Status = "$($signature.Status)"
        $state.Message = "$($signature.StatusMessage)"
    }
    catch {
        # A verdict the trust provider RETURNED is evidence about the file. A call that THREW is
        # not: a sharing violation or an I/O error says nothing about the bytes. Both used to land
        # on UnknownError, so a transient read failure became authority to overwrite a serviced
        # boot manager with the older staged copy - the exact rollback this script's .NOTES warns
        # can self-revoke a VM that currently boots. Unreadable is now its own verdict and is
        # reported, never repaired.
        $state.Status = 'ReadFailed'
        $state.Message = $_.Exception.Message
        $state.Verdict = 'Unreadable'
        return $state
    }

    switch ($state.Status) {
        'Valid' { $state.Intact = $true; $state.Verdict = 'Intact' }
        'NotTrusted' { $state.Verdict = 'Untrusted' }
        default { $state.Verdict = 'Broken' }
    }

    return $state
}
function Get-EspArtifactSpec {
    <#
    .SYNOPSIS
        The two EFI System Partition files this scenario is responsible for.

    .DESCRIPTION
        The Secure Boot SKU policy is deliberately not in this list. A healthy, currently booting
        Server 2022 Gen2 VM with Secure Boot enabled was measured with no SKUSiPolicy.p7b on its
        EFI System Partition at all, so its absence is a normal state and not a fault. The copy
        under Windows\System32\SecureBootUpdates is the servicing stack's source for that policy if
        it ever decides to apply one - it is not a statement that the EFI System Partition is
        supposed to have it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $fallbackName = Get-EfiFallbackBootFileName -WindowsDrive $WindowsDrive

    return @(
        @{
            Item        = 'bootmgfw'
            Label       = 'EFI boot manager'
            Destination = Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Microsoft\Boot\bootmgfw.efi'
        }
        @{
            Item        = 'fallback'
            Label       = if ($fallbackName) { "EFI fallback boot manager ($fallbackName)" } else { 'EFI fallback boot manager' }
            Destination = if ($fallbackName) { Join-OfflinePath -Root $BootDrive -ChildPath "EFI\Boot\$fallbackName" } else { '' }
            ArchitectureUnknown = (-not $fallbackName)
        }
    )
}

function Get-EspFinding {
    <#
    .SYNOPSIS
        Reports an EFI System Partition boot manager that is missing or not an executable.

    .DESCRIPTION
        Hash comparison only. Nothing here writes, so this is safe under -detectOnly.

        This deliberately does NOT report a boot manager that merely differs from the copy under
        Windows\Boot\EFI. On a healthy, currently booting Server 2022 VM the boot manager on the EFI
        System Partition was measured at version 10.0.28000.322 against an operating system of
        10.0.20348, matching no copy in the component store and differing from the staged copy in
        both size and hash. That is not staleness: Secure Boot servicing updates the boot manager on
        the EFI System Partition on its own schedule, ahead of the operating system, as part of the
        signing certificate and SBAT revocation work. The newer file is the correct one.

        Overwriting it with the older staged copy would roll back a security update, and where the
        firmware's SBAT level has already advanced past that older boot manager it would be
        self-revoked and refused - turning a VM that boots into one that does not. So a difference
        is reported for information and nothing is touched.

        What is left is the failure that can be proven offline: the file is gone, or its signature no
        longer verifies. That covers a deleted, truncated, zeroed or overwritten boot manager, which
        is what actually strands a Gen2 VM. The signature is the same evidence the firmware uses, and
        the boot manager Secure Boot servicing installs - signed by the Windows UEFI CA 2023 - was
        measured verifying as Valid on a Server 2022 rescue VM, so a newer signing chain does not
        produce a false positive here.
    #>
    param(
        [Parameter(Mandatory = $true)][array]$Specs,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $stagedBootManager = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Boot\EFI\bootmgfw.efi'
    $espBootManager = ($Specs | Where-Object { $_.Item -eq 'bootmgfw' } | Select-Object -First 1).Destination
    $espBootManagerOk = (Get-SignatureState -Path $espBootManager).Intact

    foreach ($spec in $Specs) {
        # Checked before anything reads or writes the destination, because on this path there is no
        # destination to speak of: the architecture that names the file could not be established.
        if ($spec.ArchitectureUnknown) {
            [void]$findings.Add((New-Finding -Cause 'ArchitectureUnknown' -Item $spec.Item -Repairable $false `
                        -Message "The EFI fallback boot manager was not checked because this installation's architecture could not be read from Windows\System32\ntoskrnl.exe, and the fallback loader is named after it (bootx64.efi, bootaa64.efi or bootia32.efi). Guessing the name would write a loader to a file the firmware never reads and report the run as repaired. Repair the kernel first - win-fix-code-integrity or win-sfc-sf-corruption - then run this again." `
                        -Data $spec))
            continue
        }

        $signature = Get-SignatureState -Path $spec.Destination

        if ($signature.Verdict -eq 'Intact') {
            $note = ''
            if ($spec.Item -eq 'bootmgfw') {
                $stagedHash = Get-FileHashValue -Path $stagedBootManager
                $espHash = Get-FileHashValue -Path $spec.Destination
                if ($stagedHash -and $espHash -and $stagedHash -ne $espHash) {
                    $note = ' It does not match the copy staged at ' + $stagedBootManager +
                    ', which is normal: Secure Boot servicing updates the EFI System Partition ahead of the operating system, so the file there is usually the newer of the two. It is left alone.'
                }
            }
            Add-OfflineRepairLog -Level Info -Message "The $($spec.Label) is present on the EFI System Partition and its signature verifies.$note"
            continue
        }

        if ($signature.Verdict -eq 'Untrusted') {
            [void]$findings.Add((New-Finding -Cause 'UntrustedEspArtifact' -Item $spec.Item -Repairable $false `
                        -Message "The $($spec.Label) at $($spec.Destination) carries a well formed signature that this rescue VM does not trust ($($signature.Status): $($signature.Message)). That is a statement about the rescue VM's certificate store, not proof that the guest's file is wrong, so nothing was changed. Check it against a VM of the same build before replacing it." `
                        -Data $spec))
            continue
        }

        if ($signature.Verdict -eq 'Unreadable') {
            [void]$findings.Add((New-Finding -Cause 'UnreadableEspArtifact' -Item $spec.Item -Repairable $false `
                        -Message "The signature of the $($spec.Label) at $($spec.Destination) could not be evaluated at all ($($signature.Message)). That is a failure to read the file, not evidence about its contents, so nothing was changed. Replacing it on this evidence could roll a serviced boot manager back to an older staged copy. Re-run once the file is readable." `
                        -Data $spec))
            continue
        }

        # Prefer the boot manager already on this EFI System Partition as the source for the
        # fallback: it is the one this VM has actually been booting, and on a serviced VM it is
        # newer than anything on the Windows partition.
        $source = $stagedBootManager
        $sourceNote = "the copy staged at $stagedBootManager. That copy can be older than the one Secure Boot servicing had put on the EFI System Partition, so if the VM still stops at a Secure Boot violation after this, the boot manager needs reapplying through Windows Update rather than replacing again."
        if ($spec.Item -eq 'fallback' -and $espBootManagerOk) {
            $source = $espBootManager
            $sourceNote = "the working boot manager already on the EFI System Partition, $espBootManager, which is the one this VM has been booting."
        }

        $spec.Source = $source

        if (-not (Get-SignatureState -Path $source).Intact) {
            [void]$findings.Add((New-Finding -Cause 'MissingSource' -Item $spec.Item -Repairable $false `
                        -Message "The $($spec.Label) is $(if ($signature.Status -eq 'Missing') { 'missing' } else { "present but its signature does not verify ($($signature.Status))" }) at $($spec.Destination), and it cannot be replaced because $source is missing or its signature does not verify either. Only this installation's own boot manager is safe to use, so nothing was changed. Recover the boot manager from matching media or reapply the servicing update, then run this again." `
                        -Data $spec))
            continue
        }

        if ($signature.Status -ne 'Missing') {
            [void]$findings.Add((New-Finding -Cause 'CorruptEspArtifact' -Item $spec.Item `
                        -Message "The $($spec.Label) at $($spec.Destination) is present but its signature does not verify ($($signature.Status)), so the firmware will refuse it. It will be replaced from $sourceNote" `
                        -Data $spec))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'MissingEspArtifact' -Item $spec.Item `
                        -Message "The $($spec.Label) is missing from the EFI System Partition at $($spec.Destination), so the firmware has nothing to run. It will be restored from $sourceNote" `
                        -Data $spec))
        }
    }

    return @($findings)
}

function Get-BootChainFinding {
    <#
    .SYNOPSIS
        Verifies the signature of every file in the boot chain.

    .DESCRIPTION
        Signature verification only. Nothing here writes, so this is safe under -detectOnly: offline
        sfc rewrites files even when asked merely to verify, so it can play no part in detection.

        A file whose signature verifies is intact. A file whose signature does not is not the file
        Microsoft signed, and is exactly what the boot chain refuses.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $intact = [System.Collections.Generic.List[string]]::new()

    foreach ($spec in $script:BootChainFile) {
        $path = Join-OfflinePath -Root $WindowsDrive -ChildPath $spec.RelativePath
        $signature = Get-SignatureState -Path $path

        if ($signature.Status -eq 'Missing') {
            if ($spec.Optional) {
                Add-OfflineRepairLog -Level Info -Message "$($spec.Label) is not present, which is normal on an installation that does not use it."
                continue
            }
            [void]$findings.Add((New-Finding -Cause 'MissingBootChainFile' -Item $spec.RelativePath `
                        -Message "The $($spec.Label) is missing from $path. The loader cannot continue without it. It will be restored from the component store." `
                        -Data $spec))
            continue
        }

        if ($signature.Verdict -eq 'Intact') {
            [void]$intact.Add($spec.Label)
            continue
        }

        if ($signature.Verdict -eq 'Untrusted') {
            [void]$findings.Add((New-Finding -Cause 'UntrustedBootChainFile' -Item $spec.RelativePath -Repairable $false `
                        -Message "The $($spec.Label) at $path carries a well formed signature that this rescue VM does not trust ($($signature.Status): $($signature.Message)). That describes the rescue VM's certificate store rather than the guest's file, so nothing was changed. Compare it with a VM of the same build before replacing it." `
                        -Data $spec))
            continue
        }

        if ($signature.Verdict -eq 'Unreadable') {
            [void]$findings.Add((New-Finding -Cause 'UnreadableBootChainFile' -Item $spec.RelativePath -Repairable $false `
                        -Message "The signature of the $($spec.Label) at $path could not be evaluated at all ($($signature.Message)). That is a failure to read the file, not evidence about its contents, so nothing was changed and no sfc repair was attempted. Re-run once the file is readable." `
                        -Data $spec))
            continue
        }

        [void]$findings.Add((New-Finding -Cause 'CorruptBootChainFile' -Item $spec.RelativePath `
                    -Message "The $($spec.Label) at $path is present but its signature does not verify ($($signature.Status)), so it is not the file Microsoft signed and the boot chain will refuse it. It will be repaired from the component store." `
                    -Data $spec))
    }

    # One line for the healthy files rather than one each. az vm repair keeps only the last 4 KB of
    # the log and discards the start, so a line per verified file evicts the findings above it from
    # everything the operator ever sees.
    if ($intact.Count -gt 0) {
        Add-OfflineRepairLog -Level Info -Message "$($intact.Count) boot chain file(s) signed and verified: $($intact -join ', ')."
    }

    return @($findings)
}

function Get-BackupPath {
    <#
    .SYNOPSIS
        A backup path beside the file, unique to this run.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $candidate = "$Path$script:BackupSuffix"
    $counter = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = "$Path$script:BackupSuffix-$counter"
        $counter++
    }
    return $candidate
}

function Backup-Artifact {
    <#
    .SYNOPSIS
        Copies a file aside before it is replaced, and records it so -revert can find it.

    .DESCRIPTION
        A file that does not exist yet is recorded as an empty marker file beside where it will go.
        Reverting then means deleting what this script created, which is what putting the disk back
        requires. The marker has to be on the disk because -revert is a later, separate run of this
        script and finds its work by looking at the disk, not by remembering it.

        Failing to write the marker is reported but does not stop the repair. A missing boot file is
        the more serious problem, and the only cost is that a later revert leaves the file in place.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        $markerPath = "$(Get-BackupPath -Path $Path)$script:AbsentMarkerSuffix"
        try {
            New-Item -Path $markerPath -ItemType File -Force -ErrorAction Stop | Out-Null
            [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = $markerPath; Existed = $false })
            Add-OfflineRepairLog -Level Info -Message "$Path is absent. Recorded $markerPath so a revert removes the file this script is about to create."
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not record that $Path was absent ($($_.Exception.Message)). A revert will leave the created file in place."
        }
        return $true
    }

    $backupPath = Get-BackupPath -Path $Path
    try {
        Copy-Item -LiteralPath $Path -Destination $backupPath -Force -ErrorAction Stop
        [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = $backupPath; Existed = $true })
        Add-OfflineRepairLog -Level Info -Message "Backed up $Path to $backupPath."
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not back up $Path : $($_.Exception.Message)"
        return $false
    }
}

function Invoke-OfflineSfcScanFile {
    <#
    .SYNOPSIS
        Repairs one file from the guest's own component store with a targeted sfc.

    .DESCRIPTION
        Only ever /SCANFILE, and only ever against a file detection has already found to be wrong.
        The store it sources from belongs to the guest, so the replacement is the right build by
        construction - which is why no rescue-host or cross-build source is offered anywhere here.

        sfc exits 0 whether or not it repaired anything and writes UTF-16 to the console, so neither
        is usable. /OFFLOGFILE is parsed instead. The log is written to the rescue VM rather than the
        guest, so a failed repair leaves nothing behind on the disk being repaired.

        What this reports is only ever used as detail for the caller's message. Whether the repair
        actually worked is decided by the caller re-reading the file's signature, because one sfc
        transaction can repair files beyond the one it was given and will then report no repair for
        a file that is already correct.

    .OUTPUTS
        PSCustomObject with Succeeded, Detail and LogLines.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $drive = $WindowsDrive.TrimEnd('\')
    $sfcLog = Join-Path $env:TEMP ("sfc-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $sfcArgs = @(
        "/SCANFILE=$Path"
        "/OFFBOOTDIR=$drive\"
        "/OFFWINDIR=$drive\Windows"
        "/OFFLOGFILE=$sfcLog"
    )

    Add-OfflineRepairLog -Level Info -Message "Running offline sfc /SCANFILE against $Path."
    try { $null = & sfc.exe @sfcArgs 2>&1 }
    catch {
        return [PSCustomObject]@{ Succeeded = $false; Detail = "sfc could not be started: $($_.Exception.Message)"; LogLines = @() }
    }

    $lines = @()
    if (Test-Path -LiteralPath $sfcLog) {
        $lines = @(Get-Content -LiteralPath $sfcLog -ErrorAction SilentlyContinue | Where-Object { $_ -match '\[SR\]' })
        Remove-Item -LiteralPath $sfcLog -Force -ErrorAction SilentlyContinue
    }

    if ($lines.Count -eq 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc produced no offline log, so nothing can be said about what it did.'; LogLines = @() }
    }

    $repaired = @($lines | Where-Object { $_ -match 'Repair complete|successfully repaired|Repairing file' })
    $unrepairable = @($lines | Where-Object { $_ -match 'Cannot repair member file' -and $_ -notmatch 'Repaired file' })

    # sfc's [SR] narration runs to a few hundred characters a line, and az vm repair keeps only the
    # last 4 KB of the log and discards the start. Dumping it on every success pushed the findings
    # out of the operator's view entirely, so it is written only when sfc did not do what it was
    # asked, which is the case where the detail earns the space. The full log always reaches the
    # caller through LogLines regardless.
    if ($repaired.Count -eq 0) {
        foreach ($line in ($lines | Select-Object -Last 6)) {
            Add-OfflineRepairLog -Level Info -Message "  sfc: $($line.Trim())"
        }
    }

    if ($repaired.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $true; Detail = 'sfc repaired the file from the component store.'; LogLines = $lines }
    }
    if ($unrepairable.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc found the file damaged but could not repair it, which means the component store copy is damaged too.'; LogLines = $lines }
    }

    return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc reported no repair.'; LogLines = $lines }
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    switch ($Finding.Cause) {
        { $_ -in @('MissingEspArtifact', 'CorruptEspArtifact') } {
            $spec = $Finding.Data
            $destinationDir = Split-Path -Path $spec.Destination -Parent
            if (-not (Test-Path -LiteralPath $destinationDir)) {
                try { $null = New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop }
                catch { return [PSCustomObject]@{ Repaired = $false; Detail = "Could not create $destinationDir : $($_.Exception.Message)" } }
            }

            if (-not (Backup-Artifact -Path $spec.Destination)) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "The existing $($spec.Label) could not be backed up, so it was left alone." }
            }

            $copy = Copy-OfflineProtectedFile -Source $spec.Source -Destination $spec.Destination
            if (-not $copy.Copied) {
                return [PSCustomObject]@{ Repaired = $false; Detail = $copy.Reason }
            }

            # Verified by re-reading, not by trusting the copy that was just made.
            $sourceHash = Get-FileHashValue -Path $spec.Source
            $destinationHash = Get-FileHashValue -Path $spec.Destination
            if (-not $destinationHash -or $destinationHash -ne $sourceHash) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "The $($spec.Label) was written but does not match its source afterwards." }
            }

            return [PSCustomObject]@{ Repaired = $true; Detail = "Copied $($spec.Source) to $($spec.Destination)." }
        }

        { $_ -in @('CorruptBootChainFile', 'MissingBootChainFile') } {
            $spec = $Finding.Data
            $path = Join-OfflinePath -Root $WindowsDrive -ChildPath $spec.RelativePath

            if (Test-Path -LiteralPath $path) {
                if (-not (Backup-Artifact -Path $path)) {
                    return [PSCustomObject]@{ Repaired = $false; Detail = "The $($spec.Label) could not be backed up, so it was left alone." }
                }
            }

            $sfc = Invoke-OfflineSfcScanFile -Path $path -WindowsDrive $WindowsDrive

            # The outcome decides whether this worked, not what sfc said it did. One sfc transaction
            # can repair more than the file it was pointed at - repairing ci.dll was measured also
            # restoring CodeIntegrity\driver.stl - so by the time a later file's own sfc runs it can
            # already be correct, and sfc then truthfully reports having repaired nothing. Treating
            # that as a failure reported an error on a disk that was in fact fully repaired.
            $after = Get-SignatureState -Path $path
            if ($after.Intact) {
                return [PSCustomObject]@{ Repaired = $true; Detail = "$path is present and its signature verifies." }
            }

            return [PSCustomObject]@{ Repaired = $false; Detail = "$($sfc.Detail) The signature of $path still does not verify ($($after.Status))." }
        }

        default {
            return [PSCustomObject]@{ Repaired = $false; Detail = "No repair is defined for $($Finding.Cause)." }
        }
    }
}

function Get-RevertCandidate {
    <#
    .SYNOPSIS
        Finds the backups a previous run of this script left behind.

    .DESCRIPTION
        The run timestamp is part of the suffix, so the newest set is chosen and the rest are left
        alone. Reverting the newest run is what an operator means by "put it back".

        A name ending in the absent marker is a file that was not there before the repair created it.
        It carries no content, and putting it back means deleting the file rather than copying over it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $roots = @(
        (Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Microsoft\Boot')
        (Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Boot')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\CodeIntegrity')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\SecureBootUpdates')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\drivers')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Boot\EFI')
    )

    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($root in $roots) {
        if (-not (Test-OfflinePath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter "*.$scriptName-backup-*" -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -notmatch "^(?<original>.+)\.$([regex]::Escape($scriptName))-backup-(?<stamp>\d{14})(-\d+)?(?<absent>$([regex]::Escape($script:AbsentMarkerSuffix)))?$") { continue }
            [void]$found.Add([PSCustomObject]@{
                    BackupPath   = $file.FullName
                    OriginalPath = Join-Path $root $Matches['original']
                    Stamp        = $Matches['stamp']
                    Existed      = [string]::IsNullOrEmpty($Matches['absent'])
                })
        }
    }

    if ($found.Count -eq 0) { return @() }

    $newestStamp = @($found | Sort-Object Stamp -Descending | Select-Object -First 1).Stamp
    return @($found | Where-Object { $_.Stamp -eq $newestStamp })
}

function Invoke-Revert {
    <#
    .SYNOPSIS
        Puts back the files the most recent run replaced, and removes the ones it created.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $candidates = @(Get-RevertCandidate -WindowsDrive $WindowsDrive -BootDrive $BootDrive)
    if ($candidates.Count -eq 0) {
        Log-Output 'No backups from a previous run of this script were found, so there is nothing to put back.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    Log-Output "Restoring $($candidates.Count) file(s) backed up by the run of $($candidates[0].Stamp)." | Tee-Object -FilePath $logFile -Append

    $restored = 0
    $removed = 0
    $failed = 0
    foreach ($candidate in $candidates) {
        if (-not $candidate.Existed) {
            $deletion = Invoke-OfflineProtectedFileRemoval -Path $candidate.OriginalPath
            if ($deletion.Removed -or $deletion.Absent) {
                $removed++
                Log-Output "  Removed $($candidate.OriginalPath), which this script had created." | Tee-Object -FilePath $logFile -Append
                Remove-Item -LiteralPath $candidate.BackupPath -Force -ErrorAction SilentlyContinue
            }
            else {
                $failed++
                Log-Warning "  Could not remove $($candidate.OriginalPath): $($deletion.Reason)" | Tee-Object -FilePath $logFile -Append
            }
            continue
        }

        $copy = Copy-OfflineProtectedFile -Source $candidate.BackupPath -Destination $candidate.OriginalPath
        if ($copy.Copied) {
            $restored++
            Log-Output "  Restored $($candidate.OriginalPath) from $($candidate.BackupPath)." | Tee-Object -FilePath $logFile -Append
            Remove-Item -LiteralPath $candidate.BackupPath -Force -ErrorAction SilentlyContinue
        }
        else {
            $failed++
            Log-Warning "  Could not restore $($candidate.OriginalPath): $($copy.Reason)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $summary = "Restored $restored file(s) and removed $removed file(s) that the repair had created"

    if ($failed -gt 0) {
        Log-Error "$summary, but $failed could not be put back." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "$summary. The disk is back in the state it was in before this script ran." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}

try {
    "$scriptStartTime" | Out-File -FilePath $logFile -Append
    Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

    $offline = if ($windowsDrive) { Get-OfflineWindowsDisk -WindowsDrive $windowsDrive } else { Get-OfflineWindowsDisk }
    Log-Output "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName))." | Tee-Object -FilePath $logFile -Append

    if ($offline.Generation -ne 2) {
        Log-Error 'This disk is Generation 1 (MBR/BIOS) and has no EFI System Partition, so there is no signed EFI boot chain to repair. A Gen1 boot failure is a boot sector, boot configuration or partition problem: use win-fix-boot-partition or win-fix-bcd.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    if (-not $offline.BootDrive) {
        Log-Error 'No EFI System Partition could be mounted on this disk. If it is missing or its file system is unreadable, use win-fix-boot-partition to rebuild it, then run this script again.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "EFI System Partition: $($offline.BootDrive)" | Tee-Object -FilePath $logFile -Append

    if ($isRevert) {
        return Invoke-Revert -WindowsDrive $offline.WindowsDrive -BootDrive $offline.BootDrive
    }

    # Context, not a verdict. Secure Boot being on or off is normal either way; it decides how
    # serious a stale policy file is, and it is stated plainly so the engineer can weigh the rest.
    $secureBoot = Get-OfflineSecureBootState -WindowsDrive $offline.WindowsDrive
    if ($secureBoot.Known) {
        Log-Info "Secure Boot was $(if ($secureBoot.Enabled) { 'enabled' } else { 'disabled' }) when the guest last booted, measured $($secureBoot.MeasuredUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC (source: $($secureBoot.Source))." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "The Secure Boot state could not be established offline ($($secureBoot.Source)). Windows keeps it in a volatile registry key that is never written to disk, so this is expected on a VM without a vTPM and is not itself a fault." | Tee-Object -FilePath $logFile -Append
    }

    $espSpecs = @(Get-EspArtifactSpec -WindowsDrive $offline.WindowsDrive -BootDrive $offline.BootDrive)

    $findings = @()
    $findings += @(Get-EspFinding -Specs $espSpecs -WindowsDrive $offline.WindowsDrive)
    $findings += @(Get-BootChainFinding -WindowsDrive $offline.WindowsDrive)

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($findings.Count -eq 0) {
        Log-Output 'The EFI boot chain on this disk is intact. The boot manager on the EFI System Partition is present and every boot chain file carries a signature that verifies, which is the same evidence the firmware and the loader use. No changes were made.' | Tee-Object -FilePath $logFile -Append
        if ($secureBoot.Known -and -not $secureBoot.Enabled) {
            Log-Output 'Secure Boot was disabled at the last boot, so a signature problem in the boot chain would not have stopped this VM in the first place. Look at win-fix-bcd for the boot configuration, or win-fix-inaccessible-boot-device if the failure is a 0x7B.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    foreach ($finding in $findings) {
        Log-Output "[$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "detectOnly was requested, so nothing was changed. $($repairable.Count) issue(s) can be repaired, $($unrepairable.Count) need a decision." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = @()
    foreach ($finding in $repairable) {
        $result = Repair-Finding -Finding $finding -WindowsDrive $offline.WindowsDrive
        if ($result.Repaired) {
            $finding.Repaired = $true
            $repairedCount++
            Log-Output "  Repaired [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
        else {
            $failed += $finding
            Log-Warning "  Repair failed [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Verified against freshly read state rather than by trusting the repairs above.
    $remaining = @()
    $remaining += @(Get-EspFinding -Specs $espSpecs -WindowsDrive $offline.WindowsDrive)
    $remaining += @(Get-BootChainFinding -WindowsDrive $offline.WindowsDrive)
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
        if ($secureBoot.Known -and -not $secureBoot.Enabled) {
            Log-Output 'Secure Boot was disabled at the last boot. If it was turned off to work around this failure, re-enable it once the VM boots, so the chain that has just been repaired is actually enforced.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
        Log-Output "If the VM still fails to start, run this script again with -revert true to put the original files back." | Tee-Object -FilePath $logFile -Append
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
