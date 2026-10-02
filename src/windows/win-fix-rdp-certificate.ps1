#########################################################################################################
#
# .SYNOPSIS
#   Restores the Remote Desktop listener certificate on an offline disk - the permissions on its
#   private key, and the store it is created in - so a VM whose RDP service is running and listening
#   but drops every connection can be reached again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM where everything about Remote Desktop looks right. TermService is running, the
#   listener is on 3389, a certificate is present in the Remote Desktop store and it has not expired -
#   and every client is disconnected the moment the TLS handshake starts. The certificate is fine. The
#   private key behind it cannot be read by the account that has to read it.
#
#   Three faults are covered, and they are three different points on the same path: the key the
#   handshake reads, the store the certificate lives in, and the certificate itself. Each is only
#   acted on with evidence that it is the one stopping the connection.
#
#   TermService runs as NETWORK SERVICE. The listener's private key lives in a container file under
#   ProgramData\Microsoft\Crypto\RSA\MachineKeys, and NETWORK SERVICE needs read access to it on every
#   handshake. Strip that one access control entry and the service still starts, still listens, and
#   still fails every connection.
#
#   What makes this a repair rather than a wait is that Windows never recovers from it on its own.
#   Measured on a live VM: delete the certificate and its key and Windows mints a brand new key
#   container with correct permissions within seconds of the services restarting, so a MISSING
#   certificate is not a fault and is deliberately not repaired here. But leave a valid certificate in
#   place and break the permissions on its key, and nothing ever triggers regeneration - the
#   certificate has not expired, so there is nothing for Windows to renew. The VM stays unreachable
#   indefinitely.
#
#   The usual cause is a hardening pass over MachineKeys. Removing "Everyone" from that folder, or
#   replacing permissions on child objects, is a common and well-intentioned change; it takes
#   NETWORK SERVICE off the existing key containers with it. The damage often surfaces months later,
#   when the six-month self-signed certificate is renewed and the new key inherits the hardened
#   permissions.
#
#   "Prepare a Windows VHD or VHDX to upload to Azure"
#   (https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image) does not
#   describe these permissions, so there is no documented target to restore. The target used here was
#   measured instead, on healthy marketplace images of every supported build - Server 2012 R2 (9600),
#   2016 (14393), 2019 (17763), 2022 (20348), 2025 (26100) and Windows 11 (26100):
#
#     - The MachineKeys folder carries O:SYG:SYD:PAI(A;;0x12019f;;;WD)(A;;FA;;;BA) on all six.
#     - The key container is owned by SYSTEM, which holds FullControl, and NETWORK SERVICE holds Read
#       on all six.
#     - The third entry differs by build, and it SWAPS rather than accumulates. Up to and including
#       2016 it is BUILTIN\Administrators with Read. From 17763 onward that entry is gone and
#       NT SERVICE\SessionEnv holds FullControl instead. Writing one build's permissions onto the
#       other would be a change to a machine that had nothing wrong with it, so the build number is
#       read from the offline installation and the matching set is used.
#
#   The trigger and the target are deliberately not the same thing, exactly as in
#   win-fix-rdp-connectivity:
#
#     - The TRIGGER is the one condition that was proven to prevent RDP: NETWORK SERVICE cannot read
#       an RDP key container, because its access control entry is missing or is denied. A healthy VM
#       produces no findings and this script writes nothing at all.
#     - The TARGET, once that is found, is the full measured set for the build. A container that is
#       being repaired anyway is put back to the state its build ships with.
#
#   The MachineKeys folder permissions are repaired only alongside a broken container, never on their
#   own. That is a measured decision rather than a cautious one: a folder hardened to SYSTEM and
#   Administrators, with the key containers left correct, was tested and RDP kept working - Windows
#   even renewed the certificate successfully through it. Reporting that folder as a fault would fire
#   on a machine that is perfectly reachable. But the same hardened folder shaped the container
#   Windows created next, which came out without the SessionEnv entry, so a folder left hardened is
#   how a repaired VM breaks again at the next renewal. When a container has already proven the
#   certificate path is broken, the folder is put back with it.
#
#   The certificate store is the second point on the path. The Remote Desktop store is a REGISTRY
#   store - HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop, with one subkey per
#   certificate under Certificates - and "Cert:\LocalMachine\Remote Desktop" is only a provider view
#   over it. That is why it can be read and repaired here at all: an online mitigation reaches it
#   through the provider, and this one reaches the same keys through the mounted SOFTWARE hive.
#
#   A Deny entry for SYSTEM on that key stops the self-signed certificate being created in the first
#   place. It is the registry half of the two cases in this script where an access control entry is
#   REMOVED rather than added, and that is deliberate: SYSTEM is the account that creates the
#   listener certificate, so a deny against it on the store it is created in has no legitimate
#   purpose. Only Deny entries for SYSTEM are removed, only on that key, and the descriptor that was
#   there is written to the log. Everything else in it, including entries someone added on purpose,
#   is left exactly as found. The other case is on the file system, where granting an account access
#   to a key container also drops the deny entries standing in the way of that same account. Every
#   deny for an account being granted is removed, whatever rights it denied, because any of them can
#   defeat the grant; a deliberately narrow deny against one of those accounts goes with the rest,
#   and the descriptor that was there is written to the log first.
#
#   The two certificate store keys are judged on Deny entries for SYSTEM. An explicit deny is
#   removed; an inherited one is reported and left alone, because it belongs to a parent key this
#   script does not own. A key that merely stops granting SYSTEM - a protected DACL listing only
#   Administrators, say - blocks certificate creation just as effectively but is NOT reported,
#   because on a healthy image these keys inherit their access rather than granting it explicitly,
#   so requiring an explicit grant would fire on every machine. If RDP still fails after this script
#   reports the store healthy, compare that key's descriptor against a known-good VM by hand.
#
#   The certificate itself is the third. Two states leave the listener with nothing usable and are
#   repaired by removing the store entry, which is what makes Windows mint a fresh one:
#
#     - EXPIRED. Windows renews a certificate that has expired, so on a healthy machine this state
#       does not last. One that is still expired on a disk being repaired is one where renewal has
#       been failing, and the stale entry is what the next attempt trips over.
#     - ORPHANED - a certificate in the store with no key container behind it in MachineKeys. The
#       private key is half the certificate; without it the entry cannot be used and cannot be
#       renewed either. This is the state behind TerminalServices-RemoteConnectionManager event 1057
#       and 1058 "failed to create a new self-signed certificate ... the relevant status code was
#       Object already exists": Windows will not create one while the old entry is in its way.
#       Judged only for a certificate whose key would be in that folder at all. The provider
#       recorded against each entry is read, and only a legacy CSP keeps its containers there - a
#       CNG key lives under Crypto\Keys, so for that certificate an empty MachineKeys folder is the
#       expected state rather than a missing key. A provider that cannot be read counts as unknown.
#       Neither is treated as orphaned, because deleting on either would destroy a working
#       certificate for having looked in the wrong place.
#
#   Removing the entry is the same measurement the rest of this script rests on - with no certificate
#   present Windows generates one, and a key container with correct permissions with it, within
#   seconds of the Remote Desktop services starting. A certificate that is present, in date and
#   backed by a key container is never touched: there is nothing wrong with it.
#
#   An orphaned entry is reported rather than removed when SSLCertificateSHA1Hash pins the listener
#   to a different certificate, because then the store entry is not what the listener is using and
#   removing it would be a change to something that was not the fault.
#
#   Three things this script will not do, because the monolithic script it replaces did them and each
#   one is worse than the fault:
#
#     - It does not generate a certificate. The old script built one on the rescue VM, wrote the PFX
#       and its password in clear text into C:\temp on the target, and hijacked the target's first
#       boot with SetupType and CmdLine to import it. Windows generates its own certificate correctly
#       and unprompted once the permissions allow it.
#     - It does not run takeown and icacls recursively across MachineKeys. That grants NETWORK SERVICE
#       read on every private key on the machine - IIS, SQL, EFS, anything else stored there - and
#       reassigns ownership of all of them. Only container files belonging to the RDP listener are
#       touched here.
#     - It does not open a firewall rule. The old script enabled FPS-SMB-In-TCP as a side effect of
#       copying the PFX across. Nothing here needs SMB.
#
#   If the permissions are repaired and RDP still fails, the remaining option is to create a
#   certificate by hand and pin it to the listener with SSLCertificateSHA1Hash. That is an operator's
#   decision, it is temporary by nature, and it is the thing win-fix-rdp-connectivity removes - so it
#   is named here rather than done.
#
#   On the file system, an existing descriptor is never replaced wholesale: entries are added to it,
#   so permissions someone added deliberately survive the repair, and the original SDDL of anything
#   changed is written to the log so it can be put back by hand. Two kinds of entry are removed, and
#   only these two: a deny for one of the accounts being granted, because a deny beats an allow
#   whatever the order and leaving it would make the grant do nothing; and the SYSTEM deny on the
#   certificate store key described above. A deny for any other account is left exactly as it is.
#
# .RESOLVES
#   A VM that boots, whose Remote Desktop service is running and listening on 3389, and which
#   disconnects every client immediately; an RDP client reporting an internal error before the logon
#   screen; RDP lost after a security hardening baseline was applied to the machine's private key
#   store; RDP that failed months after such a baseline, when the listener certificate was renewed;
#   a listener certificate that has expired and is not being replaced; and Schannel event 36870 with
#   0x8009030D or TerminalServices-RemoteConnectionManager events 1057 and 1058 reporting that a new
#   self-signed certificate could not be created because access was denied or the object already
#   exists.
#
# .PARAMETER detectOnly
#   "true" to report what is wrong with the listener key container, the machine key store, the
#   certificate store keys, the certificates in them and the services behind them, and repair
#   nothing. No configuration is changed. It is not a pure read: an object whose descriptor refuses
#   this rescue VM has to have that descriptor borrowed before it can be read at all, and each one
#   is handed back as soon as that read is done. The hand-back is replayed from the binary
#   descriptor and verified, and one that cannot be put back is reported as a finding rather than
#   passed over in silence. Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-certificate --run-on-repair --parameters detectOnly=true
#
#   Reports the state of the listener's private key permissions, the Remote Desktop certificate
#   store and the certificates in it, and changes nothing.
#
# .EXAMPLE
#   az vm repair run -g MyRg -n MyVm --run-id win-fix-rdp-certificate --run-on-repair
#
#   Restores NETWORK SERVICE's access to the listener key container, removes an explicit Deny for
#   SYSTEM on the Remote Desktop store, and deletes an expired or key-less listener certificate so
#   Windows mints a fresh one on the next start.
#
# .NOTES
#   A VM that refuses RDP because remote connections are turned off, because the listener values are
#   out of range, or because a certificate is pinned to the listener, is win-fix-rdp-connectivity's
#   fault to fix. Run that one first. It removes SSLCertificateSHA1Hash so Windows generates a fresh
#   certificate - and that regeneration depends on the permissions this script repairs, so on a
#   machine where both are wrong, connectivity first and this one second.
#
#   TermService, SessionEnv and UmRdpService are reported when disabled but are never written here,
#   because win-fix-rdp-connectivity owns them.
#
#   A machine key store that is absent is not a fault, and neither is a Remote Desktop certificate
#   store that is absent, nor a store with no certificate in it: Windows recreates the store, the
#   folder, the certificate and the key, and was measured doing all four.
#
# .VERSION
#   v1.0: Initial version.
#   v1.1: Repair the certificate store as well as the key behind it - remove a SYSTEM deny on the
#         Remote Desktop store key, and remove an expired or orphaned listener certificate so
#         Windows generates a fresh one on the next start.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Add-OfflinePathAce uses $Ace inside the $apply script block, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')

$script:MachineKeysSubPath = 'ProgramData\Microsoft\Crypto\RSA\MachineKeys'
$script:DocUrl = 'https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image'

# The Remote Desktop certificate store, in the mounted SOFTWARE hive. A LocalMachine store is a
# registry store: one subkey per certificate under Certificates, named for its SHA1 thumbprint, each
# holding the certificate and its properties in a single Blob value.
$script:CertStoreKey = 'HKLM:\BROKENSOFTWARE\Microsoft\SystemCertificates\Remote Desktop'
$script:CertStoreCertificatesKey = "$script:CertStoreKey\Certificates"

# The listener pin, in the mounted SYSTEM hive. Read only to decide whether the store entry is the
# certificate the listener actually uses; this script never writes it - win-fix-rdp-connectivity owns it.
$script:RdpTcpSubPath = 'Control\Terminal Server\WinStations\RDP-Tcp'

# Every Remote Desktop listener key container measured on 9600, 14393, 17763, 20348 and 26100 began
# with this prefix. It is the machine-independent hash of the container name the Terminal Server CSP
# asks for, so it identifies the listener's own keys without needing the certificate store parsed.
# Anything else in MachineKeys belongs to another component and is not touched.
$script:RdpContainerPrefix = 'f686aace'

# The container NAME the Terminal Server CSP records against the listener certificate, measured as
# PROV_RSA_FULL / TSSecKeySet1. It pairs with the file prefix above: the folder stores file names,
# the certificate stores this, and the mapping between them is a hash this script does not
# reproduce. Only this one pair is measured on both sides, so only this one is tested.
$script:RdpContainerName = 'TSSecKeySet1'

# Stands in for "the listener pin could not be read". Not a possible thumbprint - those are 40 hex
# characters - so it can never collide with a real pin, and it reads plainly in a log line.
$script:PinUnreadable = 'UNREADABLE'

# Offline objects whose borrowed descriptor could not be handed back, keyed by path. Populated by
# Register-UnrestoredPath and turned into non-repairable findings, so a run that leaves a customer
# object taken cannot also report that it found nothing wrong.
$script:UnrestoredPaths = @{}

# Thumbprints of store entries this run deliberately did not judge against the machine key store,
# reset on every detection pass. The affirmative healthy line is narrowed when this is non-empty,
# so a certificate that was never examined is not covered by a statement that it is healthy.
$script:UnjudgedCertificates = @()

# NT SERVICE\SessionEnv. Service SIDs are derived from the service name rather than issued per
# machine, so this value is the same on every Windows installation and is safe to write offline.
$script:SessionEnvSid = 'S-1-5-80-4022436659-1090538466-1613889075-870485073-3428993833'

$script:SidSystem = 'S-1-5-18'
$script:SidNetworkService = 'S-1-5-20'
$script:SidAdministrators = 'S-1-5-32-544'
$script:SidEveryone = 'S-1-1-0'

# Access masks as they appear in the measured descriptors.
$script:MaskFullControl = 0x1F01FF
$script:MaskReadSync = 0x120089   # FILE_GENERIC_READ, shown as "Read, Synchronize"
$script:MaskFolderEveryone = 0x12019F   # read plus the write that lets a new container be created

# Registry rights, which are a different set from the file rights above. The certificate is written
# as a value in a subkey SYSTEM has to create, so these two are what a deny has to block to stop it.
$script:MaskKeyCreate = 0x0006   # KEY_SET_VALUE | KEY_CREATE_SUB_KEY
$script:MaskKeyFullControl = 0xF003F

# The two masks are deliberately different sizes, and which one is used where matters:
#
#   - MaskKeyCreate is the DETECTION mask. Only a deny that actually blocks writing the certificate
#     is evidence of this fault. A deny on some unrelated right is somebody's hardening decision,
#     not a reason to rewrite a descriptor, so it raises nothing.
#   - MaskKeyFullControl is the REPAIR and VERIFY mask, because the repair removes every explicit
#     deny for the account rather than only the bits it tested, and a healthy image grants the
#     account full control on this key.
#
# Verify is therefore strictly wider than detect: anything detect can find, verify also refuses to
# call repaired. The asymmetry cannot produce a false success, only a stricter final check.

# CERT_CERT_PROP_ID. A store blob is a run of (propId, encoding, cbData, data) records; this is the
# one whose data is the DER encoded certificate itself.
$script:CertPropIdCertificate = 32

# CERT_KEY_PROV_INFO_PROP_ID. Its data is a serialised CRYPT_KEY_PROV_INFO, which names the key
# container behind this certificate and the provider that holds it. Layout measured on a live
# machine store rather than assumed: the first three DWORDs are the offset of the container name,
# the offset of the provider name, and dwProvType.
$script:CertPropIdKeyProvInfo = 2

# dwProvType. A legacy CSP reports a non-zero provider type - the Remote Desktop listener
# certificate measured as 1, PROV_RSA_FULL, holding container TSSecKeySet1 - and its key container
# is a file under ProgramData\Microsoft\Crypto\RSA\MachineKeys, which is what this script reads.
# CNG reports 0, and its keys live under Crypto\Keys instead, where this script does not look. That
# distinction decides whether an empty MachineKeys folder is evidence of anything at all.
$script:ProvTypeCng = 0

# The build at which the third entry on the container swaps from Administrators to SessionEnv.
$script:SessionEnvBuild = 17763

# Certificate services. Start=2 is Automatic and Start=3 is Manual; both were measured identical on
# all six builds. Only Start=4 (Disabled) is treated as evidence, so a service someone deliberately
# left demand-started is never "corrected". Owner names the script that repairs it, so that two
# scripts never write the same value.
$script:ServiceSpec = @(
    [PSCustomObject]@{ Name = 'CryptSvc'; Start = 2; Owner = $null; Purpose = 'Cryptographic Services - stores and serves the machine certificates' }
    [PSCustomObject]@{ Name = 'KeyIso'; Start = 3; Owner = $null; Purpose = 'CNG Key Isolation - performs the private key operations for the handshake' }
    [PSCustomObject]@{ Name = 'CertPropSvc'; Start = 3; Owner = $null; Purpose = 'Certificate Propagation' }
    [PSCustomObject]@{ Name = 'SessionEnv'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'Remote Desktop Configuration - generates the listener certificate' }
    [PSCustomObject]@{ Name = 'TermService'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'Remote Desktop Services - the listener itself' }
    [PSCustomObject]@{ Name = 'UmRdpService'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'RD User Mode Port Redirector' }
)

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'SOFTWARE', 'FILE')][string]$Hive,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Hive       = $Hive
        Repairable = $Repairable
        Data       = $Data
    }
}

function Get-RequiredContainerAce {
    <#
    .SYNOPSIS
        The access control entries a listener key container carries on this build.

    .DESCRIPTION
        Measured on healthy images rather than assumed. The third entry swaps at 17763 - it is
        Administrators with Read up to 2016 and SessionEnv with FullControl from 2019 - so returning
        both would write an entry the build does not ship with.
    #>
    param([Parameter(Mandatory = $true)][int]$BuildNumber)

    $required = @(
        [PSCustomObject]@{ Sid = $script:SidSystem; Mask = $script:MaskFullControl; Rights = 'FullControl'; Who = 'NT AUTHORITY\SYSTEM'; Critical = $false }
        [PSCustomObject]@{ Sid = $script:SidNetworkService; Mask = $script:MaskReadSync; Rights = 'Read'; Who = 'NT AUTHORITY\NETWORK SERVICE'; Critical = $true }
    )

    if ($BuildNumber -ge $script:SessionEnvBuild) {
        $required += [PSCustomObject]@{ Sid = $script:SessionEnvSid; Mask = $script:MaskFullControl; Rights = 'FullControl'; Who = 'NT SERVICE\SessionEnv'; Critical = $false }
    }
    else {
        $required += [PSCustomObject]@{ Sid = $script:SidAdministrators; Mask = $script:MaskReadSync; Rights = 'Read'; Who = 'BUILTIN\Administrators'; Critical = $false }
    }

    return @($required)
}

function Test-SddlGrant {
    <#
    .SYNOPSIS
        Whether a captured SDDL grants one SID at least the given access, and whether it denies it.

    .DESCRIPTION
        The descriptor is parsed rather than resolved through Get-Acl's identity references, because
        an offline installation carries SIDs this rescue VM cannot translate to names - a domain
        account, or a service SID for a service that is not installed here - and a translation
        failure must never be read as "the entry is missing".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$Mask
    )

    $granted = $false
    $denied = $false
    # Accumulated across entries, not judged one at a time. Windows is free to express the same
    # access as one ACE or several - 0x20089 and 0x100000 for the same SID is the same grant as a
    # single 0x120089 - and requiring one entry to carry the whole mask read a healthy split grant
    # as missing, which would make the script write on a VM that has nothing wrong with it.
    $allowUnion = 0

    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -ne $raw.DiscretionaryAcl) {
        foreach ($ace in $raw.DiscretionaryAcl) {
            if ($ace.SecurityIdentifier.Value -ne $Sid) { continue }
            $type = $ace.AceType.ToString()

            # Deny is matched on the whole family - AccessDenied, AccessDeniedObject and the
            # callback (conditional) forms - the same way every other deny test in this file does.
            # Matching only the plain type left an object or conditional deny looking like neither a
            # grant nor a deny, so the entry was classed as Missing and the repair added an allow
            # underneath a deny that still wins. That reports a successful repair on a VM that is
            # still refusing connections.
            if ($type -like '*Denied*' -and ($ace.AccessMask -band $Mask)) { $denied = $true }

            # Grant stays strict on purpose. A conditional allow only applies when its condition
            # holds, which cannot be evaluated here, so it is not counted as access already present.
            # The cost of being wrong is one redundant explicit allow; the cost of the opposite is
            # leaving the account without access.
            if ($type -eq 'AccessAllowed') { $allowUnion = $allowUnion -bor [int]$ace.AccessMask }
        }
    }

    if (($allowUnion -band $Mask) -eq $Mask) { $granted = $true }

    return [PSCustomObject]@{ Granted = $granted; Denied = $denied }
}

function Register-UnrestoredPath {
    <#
    .SYNOPSIS
        Recording an offline object whose borrowed descriptor could not be handed back.

    .DESCRIPTION
        A borrow that cannot be returned leaves the object owned by this rescue VM with an extra
        FullControl entry on it - on a customer's private key store. That is a worse state than the
        one the run started in, so it is never allowed to pass silently: each one becomes a
        non-repairable finding naming the path and the descriptor to put back, which also stops the
        run reporting that nothing was wrong.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$Sddl,
        [Parameter(Mandatory = $false)][ValidateSet('File', 'Registry')][string]$Kind = 'File'
    )

    if ($script:UnrestoredPaths.Keys -contains $Path) { return }
    $script:UnrestoredPaths[$Path] = [PSCustomObject]@{ Sddl = $Sddl; Kind = $Kind }
}

function ConvertTo-ReportablePath {
    <#
    .SYNOPSIS
        Rendering an offline path as somewhere the operator can actually go and look.

    .DESCRIPTION
        The mounted hive names - BROKENSYSTEM, BROKENSOFTWARE - exist only while this run holds the
        hive loaded. Naming one in a finding gives the operator a path that is gone by the time they
        read it, so the transient mount is rendered back to the location the key really occupies on
        the attached disk. A file path needs no translation and is returned unchanged.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $rendered = $Path -replace '^HKLM:\\BROKENSOFTWARE\\', 'HKLM\SOFTWARE\' -replace '^HKLM:\\BROKENSYSTEM\\', 'HKLM\SYSTEM\'
    if ($rendered -ne $Path) { return "$rendered (on the attached disk)" }
    return $Path
}

function Restore-BorrowedPath {
    <#
    .SYNOPSIS
        Handing back a descriptor borrowed only to read something, and noticing when that fails.

    .DESCRIPTION
        The binary descriptor is replayed in preference to the SDDL because it round-trips
        losslessly: an SDDL string re-resolves machine-relative aliases (LA, DA, DU, DC) against
        the machine parsing it, so a domain-joined customer disk can fail to restore, or restore to
        the wrong account, on a workgroup rescue VM. The helper verifies a binary restore by reading
        it back, and that answer is recorded rather than discarded.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $false)][byte[]]$Binary
    )

    $restored = $false
    try { $restored = Restore-OfflinePathSecurity -Path $Path -Sddl $Sddl -BinaryDescriptor $Binary }
    catch { $restored = $false }
    if (-not $restored) { Register-UnrestoredPath -Path $Path -Sddl $Sddl }
    return $restored
}

function Test-FolderEveryoneAccess {
    <#
    .SYNOPSIS
        Whether the MachineKeys folder really gives Everyone the access the store needs.

    .DESCRIPTION
        Both halves of Test-SddlGrant have to be consumed. Reading only .Granted made a folder that
        allows Everyone and then explicitly denies Everyone look healthy, because the allow was
        found and the deny was thrown away - and a deny wins regardless of order. That is the exact
        shape a hardening baseline produces when it "removes Everyone" by adding a deny rather than
        stripping the allow, which is one of the configurations this script exists to repair.
    #>
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $check = Test-SddlGrant -Sddl $Sddl -Sid $script:SidEveryone -Mask $script:MaskFolderEveryone
    return ($check.Granted -and -not $check.Denied)
}

function Get-PathSddl {
    <#
    .SYNOPSIS
        The security descriptor of a file or folder, read even when its parent denies a listing.

    .DESCRIPTION
        Get-OfflinePathSecurity goes through Get-Acl, and the PowerShell provider resolves even a
        literal path in a way that needs access to the parent directory. A key container sitting in
        a hardened MachineKeys folder therefore comes back "unreadable" when its own descriptor is
        perfectly readable - and that is the exact shape this script exists to repair, so reporting
        it as unreadable would abandon the machine at the first hurdle. Measured: with the store
        hardened, Get-Acl on a container inside it fails with "Access is denied" while the .NET call
        below succeeds, because that one needs only the traverse right every account already has.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][switch]$IsDirectory
    )

    $sddl = Get-OfflinePathSecurity -Path $Path
    if ($sddl) { return $sddl }

    # Both shapes, because the method moved. GetAccessControl is an instance method on
    # DirectoryInfo/FileInfo under Windows PowerShell 5.1, but under PowerShell 7 it is an extension
    # method on System.IO.FileSystemAclExtensions and the instance call throws "does not contain a
    # method named 'GetAccessControl'" - measured on both hosts. Production is the 5.1 host that
    # az vm run-command starts, so the instance call is tried first and the whole fallback was dead
    # rather than wrong; but a fallback that silently never runs off-box is not one to rely on.
    # Constructed inside the guard, not above it. This function documents itself as returning $null
    # on failure and every caller tests for that, so an ArgumentException or PathTooLongException
    # from the constructor escaping instead would break the contract at the one call site least able
    # to cope with it.
    try {
        $info = if ($IsDirectory) { [System.IO.DirectoryInfo]::new($Path) } else { [System.IO.FileInfo]::new($Path) }
        return $info.GetAccessControl('Owner,Group,Access').GetSecurityDescriptorSddlForm('Owner,Group,Access')
    }
    catch { }
    try {
        $info = if ($IsDirectory) { [System.IO.DirectoryInfo]::new($Path) } else { [System.IO.FileInfo]::new($Path) }
        return [System.IO.FileSystemAclExtensions]::GetAccessControl($info, 'Owner,Group,Access').GetSecurityDescriptorSddlForm('Owner,Group,Access')
    }
    catch { return $null }
}

function Get-KeyStoreState {
    <#
    .SYNOPSIS
        Reads the MachineKeys folder and every Remote Desktop listener key container on the disk.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$VolumeRoot,
        [Parameter(Mandatory = $true)][int]$BuildNumber
    )

    $folder = Join-Path $VolumeRoot $script:MachineKeysSubPath
    $folderExists = Test-Path -LiteralPath $folder

    # Test-Path answers $false both for a folder that is not there and for one whose PARENT refuses
    # this account traverse or list - and a hardened Crypto\RSA is the same shape of damage this
    # script exists to repair. The difference matters because absence is used as a premise: the run
    # states "absent - not a fault, Windows recreates it on the next start" and records every
    # certificate as unjudged for that reason. Making a positive claim on an unverified read is the
    # one answer that must not be given, so a refused parent is treated as present-but-unreadable
    # and reaches the MachineKeysFolderUnreadable finding instead. The same argument Get-RegistryKeyProbe
    # makes for registry keys, applied to the folder the whole detection rests on.
    $folderRefused = $false
    if (-not $folderExists) {
        $parent = Split-Path -Path $folder -Parent
        if ($parent) {
            try { [void]@(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop) }
            catch [System.UnauthorizedAccessException] { $folderRefused = $true }
            catch { $folderRefused = $false }
        }
        if ($folderRefused) {
            Add-OfflineRepairLog -Level Info -Message "The machine key store folder did not answer as present, and its parent $parent refused to be listed, so whether the folder exists is unknown. It is treated as present and unreadable rather than absent."
            $folderExists = $true
        }
    }

    $folderSddl = $null
    $folderOk = $true
    # Kept apart from $folderOk so an unreadable descriptor cannot be reported as a healthy one.
    # $folderOk starts true for the folder that does not exist; "exists but refused its descriptor"
    # is a different answer and gets its own finding.
    $folderSddlKnown = $true

    if ($folderExists) {
        $folderSddl = Get-PathSddl -Path $folder -IsDirectory
        if ($folderSddl) {
            $folderOk = (Test-FolderEveryoneAccess -Sddl $folderSddl)
        }
        else {
            $folderSddlKnown = $false
        }
    }

    $required = Get-RequiredContainerAce -BuildNumber $BuildNumber
    $containers = @()
    $folderListed = $true
    # How many files the folder holds in total, listener or not. Deliberately a COUNT and not a list
    # of names: these are file names of the form <hash>_<machine GUID>, and a certificate records a
    # container NAME instead, so the two can never be compared. Keeping the names here invited
    # exactly that comparison, which is false for every certificate and turned "orphaned" into
    # "judgeable". The count is only ever reported, never used to decide anything.
    $allContainerCount = 0

    if ($folderExists) {
        $filter = { $_.Name -like "$($script:RdpContainerPrefix)*" }
        $allFiles = @()
        $files = @()
        try {
            $allFiles = @(Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop)
        }
        catch {
            # A store hardened hard enough to refuse this account a listing must never be read as
            # "no key container is present" - that would report a broken machine as healthy, and a
            # hardened store is precisely the case this script exists for. It is borrowed for the
            # length of the listing and handed straight back.
            $capturedBinary = $null
            $captured = $null
            try {
                $captured = Grant-OfflinePathAccess -Path $folder -CapturedBinary ([ref]$capturedBinary)
            }
            catch {
                # Grant-OfflinePathAccess writes the owner first and the DACL second, so a throw
                # between the two leaves the customer's key store owned by this rescue VM. Letting
                # that exception escape would end the run without ever registering the residue -
                # the one outcome the borrow bookkeeping exists to prevent. The owner is re-read
                # rather than assumed, so a throw that happened BEFORE the owner write does not
                # raise a false report.
                $ownerNow = Get-OfflineSddlOwner -Sddl (Get-PathSddl -Path $folder -IsDirectory)
                if ($ownerNow -and $ownerNow -eq (Get-OfflineCurrentUserSid).Value) {
                    Register-UnrestoredPath -Path $folder -Sddl $folderSddl
                    Add-OfflineRepairLog -Level Warning -Message "Taking $folder to list it failed part way through and it is still owned by this rescue VM. Restore it from the descriptor recorded in this log."
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "$folder could not be taken to list it, and it was left as it was found. $($_.Exception.Message)"
                }
                $captured = $null
            }
            if ($captured) {
                if (-not $folderSddl) {
                    $folderSddl = $captured
                    $folderSddlKnown = $true
                    $folderOk = (Test-FolderEveryoneAccess -Sddl $captured)
                }
                try { $allFiles = @(Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop) }
                catch { $folderListed = $false }
                [void](Restore-BorrowedPath -Path $folder -Sddl $captured -Binary $capturedBinary)
            }
            else { $folderListed = $false }
        }

        if ($folderListed) {
            $allContainerCount = @($allFiles).Count
            $files = @($allFiles | Where-Object $filter)
        }

        foreach ($file in $files) {
            # No ownership escalation here, deliberately. Grant-OfflinePathAccess captures the
            # descriptor through Get-OfflinePathSecurity before it takes anything, and returns $null
            # when that read fails - which is the state Get-PathSddl has already reached by the time
            # it returns $null, because Get-OfflinePathSecurity is the first thing Get-PathSddl
            # tries. Escalating here could only repeat the read that just failed, so a container
            # whose descriptor cannot be read is reported rather than made to look like it was tried.
            $sddl = Get-PathSddl -Path $file.FullName

            $missing = @()
            $blocked = @()
            $readable = $true

            if (-not $sddl) { $readable = $false }
            else {
                foreach ($ace in $required) {
                    $check = Test-SddlGrant -Sddl $sddl -Sid $ace.Sid -Mask $ace.Mask
                    if ($check.Denied) { $blocked += $ace }
                    elseif (-not $check.Granted) { $missing += $ace }
                }
            }

            # Only NETWORK SERVICE was proven to stop RDP, so only NETWORK SERVICE fires a finding.
            $nsBroken = @(@($missing) + @($blocked) | Where-Object { $_.Sid -eq $script:SidNetworkService }).Count -gt 0

            $containers += [PSCustomObject]@{
                Path     = $file.FullName
                Name     = $file.Name
                Sddl     = $sddl
                Readable = $readable
                Missing  = @($missing)
                Blocked  = @($blocked)
                NsBroken = $nsBroken
            }
        }
    }

    return [PSCustomObject]@{
        FolderPath          = $folder
        FolderExists        = $folderExists
        # Whether FolderExists is a verified answer. It is false only when Test-Path said the folder
        # was not there AND the parent refused a listing, so presence was inferred rather than read.
        # Without this the caller cannot tell "present but unreadable" from "presence unknown", and
        # a context line that guesses between them names the wrong directory as the one at fault.
        FolderPresenceKnown = (-not $folderRefused)
        FolderSddl          = $folderSddl
        FolderOk            = $folderOk
        FolderSddlKnown     = $folderSddlKnown
        FolderListed        = $folderListed
        Required            = @($required)
        Containers          = @($containers)
        AllContainerCount   = $allContainerCount
    }
}

function ConvertTo-CertificateBlobByte {
    <#
    .SYNOPSIS
        A registry Blob value as byte[], whatever shape the read handed back.

    .DESCRIPTION
        A REG_BINARY read through a helper that returns it out of a scriptblock arrives as Object[]
        of boxed bytes, because PowerShell unrolls an array as it leaves. Returns $null for
        anything that is not a run of bytes, so a value of the wrong type is reported rather than
        half-converted into a certificate that was never there.
    #>
    param([Parameter(Mandatory = $false)]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return $Value }

    $items = @($Value)
    if ($items.Count -eq 0) { return $null }

    $bytes = [byte[]]::new($items.Count)
    for ($i = 0; $i -lt $items.Count; $i++) {
        if ($items[$i] -isnot [byte]) { return $null }
        $bytes[$i] = [byte]$items[$i]
    }
    return $bytes
}

function Get-StoreCertificate {
    <#
    .SYNOPSIS
        The certificate inside one Remote Desktop store entry, or $null when it cannot be read.

    .DESCRIPTION
        A store entry's Blob value is a run of property records - propId, encoding, length, data -
        of which one, CERT_CERT_PROP_ID, carries the DER encoded certificate. The others are
        properties such as the key provider info and the friendly name.

        The blob is walked rather than scanned for something that looks like a certificate, because
        a length taken from the wrong place is how a parser reports a valid certificate as corrupt.
        Anything that does not parse returns $null and is reported, never guessed at: deleting a
        certificate this script could not read would be deleting it on no evidence.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Blob)

    $offset = 0
    while ($offset + 12 -le $Blob.Length) {
        $propId = [System.BitConverter]::ToUInt32($Blob, $offset)
        $length = [System.BitConverter]::ToUInt32($Blob, $offset + 8)
        $dataAt = $offset + 12

        if ($length -gt [int]::MaxValue -or ($dataAt + $length) -gt $Blob.Length) { return $null }

        if ($propId -eq $script:CertPropIdCertificate -and $length -gt 0) {
            # Cast to int before the copy: a UInt32 length makes the Array.Copy overload ambiguous,
            # and the bounds test above has already proved the value fits.
            $size = [int]$length
            try {
                $der = [byte[]]::new($size)
                [System.Array]::Copy($Blob, $dataAt, $der, 0, $size)
                return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
            }
            catch { return $null }
        }

        $offset = $dataAt + $length
    }

    return $null
}

function Get-StoreKeyProvInfo {
    <#
    .SYNOPSIS
        The key provider recorded against one store entry, or $null when it cannot be read.

    .DESCRIPTION
        Returns the provider type and container name from the entry's CERT_KEY_PROV_INFO property,
        which is what says WHERE this certificate's private key is kept.

        That matters because this script looks for key containers in exactly one place -
        ProgramData\Microsoft\Crypto\RSA\MachineKeys - and only a legacy CSP keeps them there. A
        certificate whose key is held by CNG has no container in that folder by design, so an empty
        folder is not evidence that its key is missing. Without this, "I looked in the only place I
        know and found nothing" becomes "this certificate has no key", and a working certificate
        gets deleted on the strength of having looked in the wrong place.

        The layout was measured on a live machine store rather than taken from a header: the data
        begins with the container name offset, the provider name offset and dwProvType, each a
        DWORD, with the two names stored as null terminated UTF-16 at those offsets.

        Anything that does not parse returns $null, which the caller treats as "unknown" and
        therefore as a reason not to delete.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Blob)

    $offset = 0
    while ($offset + 12 -le $Blob.Length) {
        $propId = [System.BitConverter]::ToUInt32($Blob, $offset)
        $length = [System.BitConverter]::ToUInt32($Blob, $offset + 8)
        $dataAt = $offset + 12

        if ($length -gt [int]::MaxValue -or ($dataAt + $length) -gt $Blob.Length) { return $null }

        if ($propId -eq $script:CertPropIdKeyProvInfo -and $length -ge 12) {
            try {
                $size = [int]$length
                $data = [byte[]]::new($size)
                [System.Array]::Copy($Blob, $dataAt, $data, 0, $size)

                $containerAt = [int][System.BitConverter]::ToUInt32($data, 0)
                $provType = [System.BitConverter]::ToUInt32($data, 8)

                # The layout is measured, not documented, and it gates a deletion - so every field
                # read out of it is range-checked before it is believed. A record that does not look
                # like a CRYPT_KEY_PROV_INFO returns $null, which the caller treats as unknown and
                # therefore as a reason not to judge the certificate at all. Guessing in either
                # direction is a fault: too low and a CNG certificate is called legacy, too high and
                # a legacy one is never examined.
                #
                # dwProvType is a small enumeration (PROV_RSA_FULL is 1, the defined values stop in
                # the twenties); anything larger means this is not the layout assumed here.
                if ($provType -gt 64) { return $null }

                # The container name is a UTF-16 string inside the same record. A zero offset is the
                # legitimate "no container name recorded" case; any other value has to land inside
                # the record, clear the three DWORDs read above, and be even-aligned. A non-zero
                # offset that does not is proof the layout is not the one assumed here, so the whole
                # record is discarded rather than half-believed - dwProvType was read on the same
                # assumption and cannot be trusted either.
                $container = $null
                if ($containerAt -ne 0) {
                    if ($containerAt -lt 12 -or $containerAt -ge $data.Length -or ($containerAt % 2) -ne 0) { return $null }

                    $text = [System.Text.Encoding]::Unicode.GetString($data, $containerAt, $data.Length - $containerAt)
                    $end = $text.IndexOf([char]0)
                    $container = $(if ($end -ge 0) { $text.Substring(0, $end) } else { $text })

                    # A decoded name that is empty or holds control characters is a mis-parse, not a
                    # container this script should test a file name against.
                    if ([string]::IsNullOrWhiteSpace($container) -or $container -match '[\x00-\x1F]') { return $null }
                }

                return [PSCustomObject]@{ ProvType = $provType; Container = $container }
            }
            catch { return $null }
        }

        $offset = $dataAt + $length
    }

    return $null
}

function Get-RegistryKeyProbe {
    <#
    .SYNOPSIS
        Whether an offline hive key exists, and its descriptor, told apart from "access refused".

    .DESCRIPTION
        Test-Path answers $false for a key that exists but refuses this account, which on this path
        is the one answer that must never be given: a store key denied to SYSTEM would be reported
        as "no store, and that is not a fault" - the exact opposite of the truth.

        OpenSubKey separates the two. It returns null only for a key that is not there and throws
        for one that is there and refused, so an absent store and a locked one are never confused.

        The owner of a key always keeps READ_CONTROL and WRITE_DAC whatever the DACL says, so a key
        denied to SYSTEM is usually still readable here. When it is not, Exists is still true and
        Sddl is $null, and the caller reports that rather than guessing.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
    if (-not $subKey) { return [PSCustomObject]@{ Exists = $false; Sddl = $null; Refused = $false } }

    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if (-not $key) { return [PSCustomObject]@{ Exists = $false; Sddl = $null; Refused = $false } }

        $binary = $key.GetAccessControl($script:OfflineSecuritySections).GetSecurityDescriptorBinaryForm()
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($binary, 0)
        return [PSCustomObject]@{ Exists = $true; Sddl = $raw.GetSddlForm('All'); Refused = $false }
    }
    catch {
        # Thrown, not null: the key is there and this account may not open it for READ_CONTROL.
        return [PSCustomObject]@{ Exists = $true; Sddl = $null; Refused = $true }
    }
    finally { if ($key) { $key.Close() } }
}

function Get-SddlDeny {
    <#
    .SYNOPSIS
        Whether a SID is denied an access, and whether that deny is written on the key itself.

    .DESCRIPTION
        The distinction decides what can be repaired. An explicit entry on the key is this script's
        to remove. An INHERITED one is a copy of an entry on a key above the certificate store -
        HKLM\SOFTWARE\Microsoft\SystemCertificates, which every machine certificate store on the VM
        lives under, or higher still. Removing the copy would leave the original in place to be
        re-propagated, and reaching up to the original would change the permissions of every other
        store on the machine to fix one. So an inherited deny is named and left to an operator.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$Mask
    )

    $any = $false
    $explicit = $false
    $inheritedFlag = [int][System.Security.AccessControl.AceFlags]::Inherited

    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -ne $raw.DiscretionaryAcl) {
        foreach ($ace in $raw.DiscretionaryAcl) {
            if ($ace.SecurityIdentifier.Value -ne $Sid) { continue }
            if ($ace.AceType.ToString() -notlike '*Denied*') { continue }
            if (-not ($ace.AccessMask -band $Mask)) { continue }
            $any = $true
            if (-not ([int]$ace.AceFlags -band $inheritedFlag)) { $explicit = $true }
        }
    }

    return [PSCustomObject]@{ Denied = $any; Explicit = $explicit }
}

function Get-CertificateStoreState {
    <#
    .SYNOPSIS
        Reads the Remote Desktop certificate store: who may write to it, and what is in it.

    .DESCRIPTION
        Must be called inside Invoke-WithHive -Hive 'SOFTWARE'.

        BOTH keys are judged, because they are not the same key and a deny on either one is enough.
        "Remote Desktop" is the store; "Remote Desktop\Certificates" is where the certificate is
        actually written, as a subkey named for its thumbprint. Creating a certificate means
        creating a subkey under Certificates and setting a value in it, so that is the key the write
        lands on - while a deny on the store above it stops the path being opened at all. A check
        that covered only one of the two would pass a machine that is still broken.

        A store that is absent, or present and empty, is not a fault and is reported as such by the
        caller: Windows creates both, and was measured doing it.
    #>
    param()

    $keys = @()
    foreach ($spec in @(
            [PSCustomObject]@{ Path = $script:CertStoreKey; Label = 'Remote Desktop' },
            [PSCustomObject]@{ Path = $script:CertStoreCertificatesKey; Label = 'Remote Desktop\Certificates' })) {

        $probe = Get-RegistryKeyProbe -Path $spec.Path
        $deny = if ($probe.Sddl) { Get-SddlDeny -Sddl $probe.Sddl -Sid $script:SidSystem -Mask $script:MaskKeyCreate } else { $null }

        $keys += [PSCustomObject]@{
            Path     = $spec.Path
            Label    = $spec.Label
            Exists   = $probe.Exists
            Sddl     = $probe.Sddl
            Refused  = $probe.Refused
            Denied   = [bool]($deny -and $deny.Denied)
            Explicit = [bool]($deny -and $deny.Explicit)
        }
    }

    $certificatesKey = @($keys | Where-Object { $_.Path -eq $script:CertStoreCertificatesKey })[0]
    $certificates = @()
    $certificatesKnown = $true

    if ($certificatesKey.Exists) {
        $entries = @()
        $captured = [System.Collections.Generic.List[object]]::new()
        try {
            try { $entries = @(Get-ChildItem -LiteralPath $script:CertStoreCertificatesKey -ErrorAction Stop) }
            catch {
                # Borrowed and handed straight back, the same way a hardened MachineKeys folder is.
                # A store locked hard enough to refuse a listing must never be read as "no
                # certificate is present" - that reports a broken machine as healthy, and a locked
                # store is precisely the case this is here for.
                # -NoRecurse because only this key is opened. Listing it needs
                # KEY_ENUMERATE_SUB_KEYS on the key itself; the thumbprint subkeys below it are
                # never opened for their security, and each Blob read escalates its own key on
                # demand. Without it the helper would take ownership of, and add a FullControl entry
                # for this account to, every certificate in the store - in detect-only as well,
                # where it would be the widest unrequested change the script makes.
                #
                # The trade-off, recorded deliberately: a Blob read that escalates a thumbprint
                # subkey borrows through Get-OfflineProtectedRegistryValue, which restores in its own
                # finally and reports a failed restore only as a log Warning. Those child keys
                # therefore do not reach $script:UnrestoredPaths and are not counted in the summary.
                # That is a helper-boundary limitation shared by every caller in the library, and it
                # is the better side of the trade: taking one key and possibly failing to account for
                # a child beats taking every key in the store on every run.
                [void](Grant-OfflineRegistryKeyAccess -Path $script:CertStoreCertificatesKey -CapturedInto $captured -NoRecurse)
                $entries = @(Get-ChildItem -LiteralPath $script:CertStoreCertificatesKey -ErrorAction Stop)
            }

            foreach ($entry in $entries) {
                $path = Join-Path $script:CertStoreCertificatesKey $entry.PSChildName
                $found = $false
                $blob = Get-OfflineProtectedRegistryValue -Path $path -Name 'Blob' -Found ([ref]$found)

                # Get-OfflineProtectedRegistryValue returns its value out of a scriptblock, and
                # PowerShell unrolls an array on the way out, so a REG_BINARY arrives here as
                # Object[] of boxed bytes rather than byte[]. Measured, not assumed: a healthy
                # 2019 listener certificate was reported unreadable by a plain -is [byte[]] test.
                # Reporting a valid certificate as unparsable is the worst answer this script can
                # give, so the bytes are rebuilt rather than type-tested.
                $bytes = ConvertTo-CertificateBlobByte -Value $blob
                $certificate = $null
                $provInfo = $null
                if ($found -and $bytes -and $bytes.Length -gt 0) {
                    $certificate = Get-StoreCertificate -Blob $bytes
                    $provInfo = Get-StoreKeyProvInfo -Blob $bytes
                }

                $certificates += [PSCustomObject]@{
                    Thumbprint = $entry.PSChildName
                    Path       = $path
                    Parsed     = ($null -ne $certificate)
                    Subject    = $(if ($certificate) { $certificate.Subject } else { $null })
                    NotAfter   = $(if ($certificate) { $certificate.NotAfter } else { $null })
                    Expired    = $(if ($certificate) { $certificate.NotAfter -lt (Get-Date) } else { $false })

                    # Whether this certificate's private key would live in the folder this script
                    # reads. $null means the property could not be read, which is treated as
                    # unknown rather than as a legacy CSP.
                    KeyInMachineKeys = $(if ($provInfo) { $provInfo.ProvType -ne $script:ProvTypeCng } else { $null })
                    KeyContainer     = $(if ($provInfo) { $provInfo.Container } else { $null })
                }

                if ($certificate) { $certificate.Dispose() }
            }
        }
        catch {
            $certificatesKnown = $false
            Add-OfflineRepairLog -Level Info -Message "The Remote Desktop certificate store could not be listed ($($_.Exception.Message)), so what is in it is unknown."
        }
        finally {
            # Gated on the capture list, not on a flag set after the call returned. The helper
            # appends to $captured as it takes each key, so if it throws part way through it has
            # already borrowed something; a flag set on the line below the call would still be
            # false and the restore would be skipped, leaving those descriptors taken. The
            # file-system borrow a few lines up guards itself the same way.
            if ($captured.Count -gt 0) {
                # The keys that failed are named individually rather than reported as a count
                # against the parent. The parent may be intact while a child is not, and an
                # operator sent to the wrong key cannot put anything back. The helper skips
                # captured keys that no longer exist, so a key missing from the restored set is
                # only sound evidence because nothing in this read path deletes a key; a future
                # change that does must compare the captured path against what it removed.
                $capturedKeys = @($captured.ToArray())
                $replayed = Restore-OfflineRegistrySecurity -Captured $capturedKeys
                if ($replayed -lt $capturedKeys.Count) {
                    foreach ($key in $capturedKeys) {
                        if (-not $key.Path) { continue }
                        # Rendered from the captured descriptor so the finding carries something the
                        # operator can actually set back. Grant-OfflineRegistryKeyAccess captures in
                        # BINARY - it skips any key whose descriptor it could not read, so Descriptor
                        # is always a populated [byte[]] here - and a byte array has no GetSddlForm.
                        # Calling it directly threw MethodNotFound on every iteration and the catch
                        # swallowed it, leaving the message with nothing to put back. The bytes have
                        # to be wrapped first, which is the same idiom the ownership hand-back uses.
                        $keySddl = $null
                        try { if ($key.Descriptor) { $keySddl = [System.Security.AccessControl.RawSecurityDescriptor]::new($key.Descriptor, 0).GetSddlForm('All') } }
                        catch { $keySddl = $null }
                        Register-UnrestoredPath -Path $key.Path -Sddl $keySddl -Kind 'Registry'
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        Keys              = @($keys)
        StoreExists       = @($keys | Where-Object { $_.Path -eq $script:CertStoreKey })[0].Exists
        Certificates      = @($certificates)
        CertificatesKnown = $certificatesKnown
    }
}

function Get-ListenerPinnedThumbprint {
    <#
    .SYNOPSIS
        The certificate the listener is pinned to, $null when it is not pinned to one, or the
        unreadable sentinel when the pin itself could not be read.

    .DESCRIPTION
        Must be called inside Invoke-WithHive -Hive 'SYSTEM'. Read only: an orphaned store entry is
        reported rather than removed when the listener is pinned elsewhere, because then the entry
        is not what the handshake uses and removing it would be a change to something that was not
        the fault. A zero length pin is the same as no pin - it names no certificate.

        Three-state rather than two, because this gates a deletion. Get-OfflineProtectedRegistryValue
        returns the default on an access denial as well as on a missing value, so without -Denied a
        pin that could not be read is indistinguishable from no pin at all, and the guard fails open:
        if the unreadable pin named the certificate being judged, the run would delete it and leave
        SSLCertificateSHA1Hash pointing at a thumbprint that no longer exists - a worse state than
        the one it found, and one this script cannot undo. Unknown is therefore treated as pinned.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $found = $false
    $denied = $false
    $value = Get-OfflineProtectedRegistryValue -Path (Join-Path $SystemRoot $script:RdpTcpSubPath) -Name 'SSLCertificateSHA1Hash' -Found ([ref]$found) -Denied ([ref]$denied)

    if ($denied) { return $script:PinUnreadable }

    # Rebuilt rather than type-tested, for the same measured reason as the certificate blob above:
    # the value arrives from the helper's scriptblock as Object[] of boxed bytes, so a plain
    # -is [byte[]] test fails on every pin that exists. Testing the type here instead of converting
    # made this function return $null unconditionally, which silently disarmed the guard below - a
    # pinned certificate would have been deleted as though nothing pointed at it.
    $bytes = ConvertTo-CertificateBlobByte -Value $value
    if (-not $found -or -not $bytes -or $bytes.Length -eq 0) { return $null }

    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
}

function Get-CertificateServiceState {
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $services = foreach ($spec in $script:ServiceSpec) {
        $path = Join-Path $SystemRoot "Services\$($spec.Name)"
        $exists = Test-Path -LiteralPath $path
        $start = $null
        $denied = $false
        $found = $false
        $malformed = $false

        if ($exists) {
            $value = Get-OfflineProtectedRegistryValue -Path $path -Name 'Start' -Found ([ref]$found) -Denied ([ref]$denied)
            # TryParse, not [int]: a bare cast throws on a value of an unexpected type, and that
            # throw happens inside the hive scriptblock and takes the whole run to STATUS_ERROR.
            if ($found) {
                $parsed = 0
                if ([int]::TryParse("$value", [ref]$parsed)) { $start = $parsed }
                # Read, but not a number. That is a broken service configuration in its own right,
                # and it must not share the "(Start not set)" wording with a value that is simply
                # absent - one of those is a healthy default and the other is not.
                else { $malformed = $true }
            }
        }

        [PSCustomObject]@{
            Name     = $spec.Name
            Spec     = $spec
            Path     = $path
            Exists   = $exists
            Start    = $start
            Denied   = $denied
            Found    = $found
            # Denied is raised on the first refusal, before the helper takes the key and retries,
            # and is not lowered when that retry succeeds. Only a read that was refused AND never
            # recovered is genuinely unreadable.
            Unreadable = ($exists -and $denied -and -not $found)
            Malformed  = $malformed
            Disabled = ($exists -and $start -eq 4)
        }
    }

    return @($services)
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turns the state that was read into the list of things actually preventing the handshake.
    #>
    param(
        [Parameter(Mandatory = $true)]$KeyStore,
        [Parameter(Mandatory = $true)]$Services,
        [Parameter(Mandatory = $false)]$CertStore,
        [Parameter(Mandatory = $false)][string]$PinnedThumbprint
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # Reset per call, because this function runs again to verify the repair and a stale entry would
    # qualify the healthy line on a disk that no longer has anything unjudged on it.
    $script:UnjudgedCertificates = @()

    # Raised first, because it describes damage this run itself is responsible for. A borrowed
    # descriptor that could not be handed back leaves a customer object owned by the rescue VM with
    # an extra FullControl entry on it, which is worse than the state the run started in and must
    # never be reported as a clean result.
    foreach ($taken in @($script:UnrestoredPaths.Keys)) {
        $record = $script:UnrestoredPaths[$taken]
        $shown = ConvertTo-ReportablePath -Path $taken
        # The remediation has to match what was taken. icacls does not address a registry key, and
        # offering it for one sends the operator to a tool that cannot help them.
        $how = if (-not $record.Sddl) { '' }
        elseif ($record.Kind -eq 'Registry') {
            " Its original descriptor was $($record.Sddl); set it back with Set-Acl, or with regini, once the disk is attached somewhere it can be reached."
        }
        else {
            " Its original descriptor was $($record.Sddl) and can be replayed with: icacls `"$shown`" /restore, or set directly with icacls."
        }
        [void]$findings.Add((New-Finding -Cause 'OfflineSecurityNotRestored' -Item $shown -Hive $(if ($record.Kind -eq 'Registry') { 'SOFTWARE' } else { 'FILE' }) -Repairable $false `
                    -Message "The security descriptor of $shown was borrowed to read it and could not be put back, so it is still owned by this rescue VM and carries an entry this repair added.$how"))
    }

    # --- The key containers -----------------------------------------------------------------------
    # A missing MachineKeys folder is deliberately not a fault. Measured on a live VM: renaming the
    # folder away and deleting the certificate produced a new folder, a new key container and a
    # working listener within seconds of the services restarting. Reporting it would fire on a
    # machine that Windows repairs by itself.
    if ($KeyStore.FolderExists) {
        if (-not $KeyStore.FolderListed) {
            [void]$findings.Add((New-Finding -Cause 'MachineKeysFolderUnreadable' -Item 'MachineKeys' -Hive 'FILE' -Repairable $false `
                        -Message "$($KeyStore.FolderPath) could not be listed even after taking ownership of it, so whether the listener's key container is intact is unknown. Nothing was changed. Inspect it by hand before concluding the certificate is not the problem."))
        }
        # An unreadable descriptor is not a healthy one. FolderOk defaults to true, so without this
        # a folder that refused its own descriptor was reported as correctly permissioned - the
        # mirror image of the mistake the container reads are careful to avoid.
        if (-not $KeyStore.FolderSddlKnown) {
            [void]$findings.Add((New-Finding -Cause 'MachineKeysFolderSecurityUnreadable' -Item 'MachineKeys' -Hive 'FILE' -Repairable $false `
                        -Message "The security descriptor of $($KeyStore.FolderPath) could not be read, so whether the store still grants Everyone the access every measured build ships with is unknown. It was left alone rather than rewritten from an assumption."))
        }
        foreach ($container in @($KeyStore.Containers)) {
            if (-not $container.Readable) {
                [void]$findings.Add((New-Finding -Cause 'ContainerSecurityUnreadable' -Item $container.Name -Hive 'FILE' -Repairable $false `
                            -Message "The security descriptor of $($container.Path) could not be read, so its permissions were left alone rather than replaced with something that was never compared against."))
                continue
            }
            if (-not $container.NsBroken) { continue }

            $blockedNs = @(@($container.Blocked) | Where-Object { $_.Sid -eq $script:SidNetworkService }).Count -gt 0
            $how = if ($blockedNs) { 'is explicitly denied' } else { 'has no entry' }
            $alsoMissing = @(@($container.Missing) | Where-Object { $_.Sid -ne $script:SidNetworkService } | ForEach-Object { $_.Who })

            $message = "NT AUTHORITY\NETWORK SERVICE $how on the listener key container $($container.Name). TermService runs as NETWORK SERVICE and reads this key on every handshake, so the service starts, the port listens and every connection is dropped. Windows will not repair this by itself, because the certificate is still valid and there is nothing for it to renew."
            if ($alsoMissing.Count -gt 0) { $message += " $($alsoMissing -join ' and ') is also missing and will be restored with it." }
            $message += " Current: $($container.Sddl)"

            [void]$findings.Add((New-Finding -Cause 'ContainerKeyUnreadable' -Item $container.Name -Hive 'FILE' -Data $container -Message $message))
        }

        # Only alongside a broken container - see the header. On its own a hardened folder was
        # measured NOT to prevent RDP, so it must not fire on a machine that is reachable.
        $broken = @(@($KeyStore.Containers) | Where-Object { $_.NsBroken })
        if ($broken.Count -gt 0 -and -not $KeyStore.FolderOk) {
            [void]$findings.Add((New-Finding -Cause 'MachineKeysFolderHardened' -Item 'MachineKeys' -Hive 'FILE' -Data $KeyStore `
                        -Message "The machine key store at $($KeyStore.FolderPath) no longer grants Everyone the read and write access that every measured build ships with. This does not block RDP on its own and would not have been touched by itself, but it is the folder the listener's next key container is created in - one created under these permissions came out incomplete when tested - so it is restored alongside the container. Current: $($KeyStore.FolderSddl)"))
        }
    }

    # --- Services ---------------------------------------------------------------------------------
    foreach ($service in @($Services)) {
        if (-not $service.Exists) {
            if (-not $service.Spec.Owner) {
                [void]$findings.Add((New-Finding -Cause 'CertificateServiceMissing' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "The $($service.Name) service key is missing ($($service.Spec.Purpose)). That is a damaged installation rather than a configuration fault, and this script will not create one."))
            }
            continue
        }
        # An unreadable Start is not a running service. Without this a genuinely disabled service
        # whose key refuses to be read was reported as healthy, because Disabled is false either way.
        if ($service.Unreadable) {
            [void]$findings.Add((New-Finding -Cause 'CertificateServiceStartUnreadable' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "The Start value of $($service.Name) could not be read even after taking the key ($($service.Spec.Purpose)), so whether it is disabled is unknown. It was left alone rather than overwritten with a documented default."))
            continue
        }
        # Read, but not a number Windows can use. Reported rather than repaired: the value that was
        # there is evidence of how the machine got into this state, and replacing it with a
        # documented default would destroy that without being asked to.
        if ($service.Malformed) {
            [void]$findings.Add((New-Finding -Cause 'CertificateServiceStartMalformed' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "The Start value of $($service.Name) is present but is not a number ($($service.Spec.Purpose)), so Windows cannot read a start type from it. It was left as found; correct it by hand to the measured $($service.Spec.Start)."))
            continue
        }
        if (-not $service.Disabled) { continue }

        if ($service.Spec.Owner) {
            [void]$findings.Add((New-Finding -Cause 'DependencyServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). The listener certificate cannot be used while it is, but $($service.Spec.Owner) owns this service and will restore it to Start=$($service.Spec.Start). It was not changed here."))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'CertificateServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Data $service `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). Without it the private key operations behind the handshake cannot run. It will be set to Start=$($service.Spec.Start), the value measured on every supported build."))
        }
    }

    # --- The certificate store --------------------------------------------------------------------
    # A store that is absent, or present with nothing in it, is not a fault for the same measured
    # reason a missing MachineKeys folder is not: Windows creates it. What is a fault is a store
    # SYSTEM cannot write into, and a certificate in it that cannot be used.
    if ($CertStore) {
        foreach ($key in @($CertStore.Keys)) {
            if (-not $key.Exists) { continue }

            if (-not $key.Sddl) {
                [void]$findings.Add((New-Finding -Cause 'CertificateStoreUnreadable' -Item $key.Label -Hive 'SOFTWARE' -Repairable $false `
                            -Message "$($key.Label) under HKLM\SOFTWARE\Microsoft\SystemCertificates exists but its security descriptor could not be read, so whether Windows can create a listener certificate there is unknown. Nothing was changed on it."))
                continue
            }

            if (-not $key.Denied) { continue }

            if (-not $key.Explicit) {
                [void]$findings.Add((New-Finding -Cause 'CertificateStoreAccessDeniedInherited' -Item $key.Label -Hive 'SOFTWARE' -Repairable $false `
                            -Message "NT AUTHORITY\SYSTEM is denied write access on $($key.Label), but the deny is INHERITED from a key above the Remote Desktop store rather than written on it. Removing the copy here would leave the original to be propagated again, and the key it comes from - HKLM\SOFTWARE\Microsoft\SystemCertificates or higher - is shared by every machine certificate store on the VM, so changing it to fix one store is an operator's decision. Find the deny on the parent key and remove it there. Current: $($key.Sddl)"))
                continue
            }

            [void]$findings.Add((New-Finding -Cause 'CertificateStoreAccessDenied' -Item $key.Label -Hive 'SOFTWARE' -Data $key `
                        -Message "NT AUTHORITY\SYSTEM is explicitly denied write access on $($key.Label). SYSTEM is the account that creates the listener certificate, and the certificate is written as a subkey of Remote Desktop\Certificates, so a deny on either key leaves the handshake with nothing to present - the client reports an internal error and Schannel logs 36870. The deny entries for SYSTEM will be removed from this key; every other entry in the descriptor is left as found. Current: $($key.Sddl)"))
        }

        if (-not $CertStore.CertificatesKnown) {
            [void]$findings.Add((New-Finding -Cause 'CertificateStoreUnreadable' -Item 'Certificates' -Hive 'SOFTWARE' -Repairable $false `
                        -Message "The certificates in the Remote Desktop store could not be listed even after taking ownership, so whether the listener has a usable certificate is unknown. Nothing in the store was changed."))
        }

        foreach ($certificate in @($CertStore.Certificates)) {
            # An unreadable pin counts as pinned for every certificate. It gates a deletion, and the
            # one thing not known is whether the pin names this entry, so the safe reading is that
            # it might.
            $pinUnknown = ($PinnedThumbprint -eq $script:PinUnreadable)
            $isPinned = $pinUnknown -or ($PinnedThumbprint -and ($certificate.Thumbprint -eq $PinnedThumbprint))

            if (-not $certificate.Parsed) {
                [void]$findings.Add((New-Finding -Cause 'ListenerCertificateUnreadable' -Item $certificate.Thumbprint -Hive 'SOFTWARE' -Repairable $false `
                            -Message "The store entry $($certificate.Thumbprint) does not contain a certificate this script could parse. It was left alone rather than deleted on the strength of a read that failed."))
                continue
            }

            # Orphaned: a certificate with no key container behind it. The private key is half the
            # certificate - without it the entry cannot be used and cannot be renewed, and Windows
            # will not create a replacement while it is in the way. That refusal is event 1057/1058
            # "Object already exists". Judged only when the key store was actually listed: a folder
            # that refused a listing tells us nothing about what is in it, and reading that silence
            # as "no container" would delete a perfectly good certificate.
            #
            # It is also judged only for a certificate whose key WOULD be in that folder. This
            # script reads ProgramData\Microsoft\Crypto\RSA\MachineKeys, where a legacy CSP keeps
            # its containers; a CNG key is kept under Crypto\Keys instead. For a CNG certificate an
            # empty MachineKeys folder is the expected state, not evidence of a missing key, so
            # treating it as orphaned would delete a certificate whose key is present and working -
            # typically the custom certificate an administrator bound to the listener deliberately.
            # A provider property that could not be read is unknown, and unknown does not authorise
            # a deletion either.
            #
            # The verdict is taken only for the listener's own container, and only against the file
            # name prefix measured for it. The two names are in different namespaces and cannot be
            # compared directly: KeyContainer is the CryptoAPI container NAME the certificate
            # records, while the MachineKeys folder holds FILE names of the form <hash>_<machine
            # GUID>. Testing one against the other is false for every certificate that names a
            # container at all, which makes "orphaned" collapse into "judgeable" and deletes the
            # store entry of a certificate whose key is present and healthy.
            #
            # The hash is deliberately not reproduced here. MD5 of the container name in ASCII,
            # UTF-8 and UTF-16, with and without a terminator, matches none of the observed file
            # names, so any name-to-file mapping written here would be a guess, and a guess is not
            # something to authorise a deletion with. What IS measured is the pair: the listener
            # records container TSSecKeySet1, and its container file begins f686aace on 9600, 14393,
            # 17763, 20348 and 26100. A constant file prefix across five builds and a constant
            # container name are the same fact seen from both sides, so that one pair is safe.
            #
            # A certificate naming any other container is left unjudged rather than guessed at. An
            # administrator's own certificate keeps its key under its own container name, and this
            # script cannot locate that file by name; reporting it is correct, deleting it is not.
            $keyWouldBeHere = ($certificate.KeyInMachineKeys -eq $true)
            $containerNamed = -not [string]::IsNullOrWhiteSpace($certificate.KeyContainer)
            $isListenerContainer = $containerNamed -and ($certificate.KeyContainer -eq $script:RdpContainerName)
            $containerPresent = $isListenerContainer -and (@($KeyStore.Containers).Count -gt 0)
            $judgeable = $keyWouldBeHere -and $isListenerContainer -and $KeyStore.FolderExists -and $KeyStore.FolderListed
            $orphaned = $judgeable -and -not $containerPresent

            # Printed for every parsed entry so a lab log shows which branch was taken and on what
            # evidence, rather than the decision resting on a comment.
            Add-OfflineRepairLog -Level Info -Message "Store entry $($certificate.Thumbprint): provider type $(if ($null -eq $certificate.KeyInMachineKeys) { 'unreadable' } elseif ($keyWouldBeHere) { 'legacy CSP' } else { 'CNG' }), container $(if ($containerNamed) { $certificate.KeyContainer } else { '(none recorded)' }), machine key store holds $($KeyStore.AllContainerCount) file(s) of which $(@($KeyStore.Containers).Count) are listener containers, judged: $judgeable."

            # Stated rather than left silent: without this line, a certificate that was spared only
            # because its key is kept somewhere this script does not read, because it names no
            # container to look for, or because the machine key store could not be examined at all,
            # looks identical in the log to one examined and found healthy.
            if (-not $judgeable) {
                # The per-certificate reasons come first, and the store-wide ones after, so each
                # certificate is given the reason that actually applies to it. Ordered the other way
                # round, a CNG certificate on a disk with no MachineKeys folder was reported as
                # spared because that folder is absent - which is not why. Its key was never going
                # to be in there.
                $where = if ($null -eq $certificate.KeyInMachineKeys) {
                    'the key provider recorded against it could not be read'
                }
                elseif (-not $keyWouldBeHere) {
                    "its private key is held by CNG, in Crypto\Keys rather than the RSA\MachineKeys folder this script reads$(if ($certificate.KeyContainer) { " (container $($certificate.KeyContainer))" })"
                }
                elseif (-not $containerNamed) {
                    'it records no key container name, so there is nothing to look for in the machine key store'
                }
                elseif (-not $KeyStore.FolderExists) {
                    'the machine key store folder is not present on this disk, so there is nothing to compare its key container against'
                }
                elseif (-not $KeyStore.FolderListed) {
                    'the machine key store folder could not be listed, so which key containers exist on this disk is unknown'
                }
                else {
                    "it keeps its key in container $($certificate.KeyContainer), and the machine key store names its files by a hash of the container name that this script does not reproduce, so the file behind that name cannot be located"
                }
                Add-OfflineRepairLog -Level Info -Message "Store entry $($certificate.Thumbprint) was not judged against the machine key store because $where. An empty or unreadable MachineKeys folder is not evidence about this certificate, so it is not deleted on that evidence."
                # Recorded, not just logged. The affirmative healthy line states that every
                # certificate in the store has its private key, and that is a claim this run cannot
                # make about a certificate it declined to judge. A missing MachineKeys folder is the
                # case that makes this matter most: it is the state behind the "Object already
                # exists" deadlock, and without this the run would report a clean bill of health.
                $script:UnjudgedCertificates += $certificate.Thumbprint
            }

            if ($certificate.Expired -or $orphaned) {
                $why = if ($certificate.Expired -and $orphaned) {
                    "expired on $($certificate.NotAfter.ToString('yyyy-MM-dd')) and has no private key container behind it in the machine key store"
                }
                elseif ($certificate.Expired) {
                    "expired on $($certificate.NotAfter.ToString('yyyy-MM-dd')) and has not been replaced, which means renewal has been failing rather than that the certificate simply aged out"
                }
                else {
                    "has no private key container behind it in the machine key store, so it cannot be used for a handshake and cannot be renewed either"
                }

                if ($isPinned) {
                    $pinText = if ($pinUnknown) {
                        "SSLCertificateSHA1Hash could not be read, so whether the listener is pinned to this exact certificate is unknown - deleting it could leave the listener pointed at nothing. Check the permissions on the RDP-Tcp key from the rescue VM, then run this script again"
                    }
                    else {
                        'SSLCertificateSHA1Hash pins the listener to this exact certificate - deleting it would leave the listener pointed at nothing. Run win-fix-rdp-connectivity to remove the pin first, then run this script again'
                    }
                    [void]$findings.Add((New-Finding -Cause 'ListenerCertificateUnusable' -Item $certificate.Thumbprint -Hive 'SOFTWARE' -Repairable $false `
                                -Message "The listener certificate $($certificate.Thumbprint) $why. It was NOT removed, because $pinText."))
                    continue
                }

                # Expiry on its own is not evidence that this certificate is the listener's. The
                # orphan verdict above is narrowed to the listener's own container precisely so that
                # an administrator's certificate is never removed for not being the listener's, and
                # deleting it for having expired instead would walk straight around that narrowing.
                # An entry this run cannot tie to the listener is reported for a decision. Nothing
                # is lost by declining: the primary case, a self-signed listener certificate that
                # aged out, records the listener's own container and so is still repaired below.
                if (-not $isListenerContainer) {
                    [void]$findings.Add((New-Finding -Cause 'StoreCertificateUnusable' -Item $certificate.Thumbprint -Hive 'SOFTWARE' -Repairable $false `
                                -Message "The certificate $($certificate.Thumbprint) in the Remote Desktop store $why. It was NOT removed: it does not name the listener's own key container, so this run cannot show that it belongs to the listener rather than having been put there deliberately. Remove it by hand if it is not wanted."))
                    continue
                }

                [void]$findings.Add((New-Finding -Cause 'ListenerCertificateUnusable' -Item $certificate.Thumbprint -Hive 'SOFTWARE' -Data $certificate `
                            -Message "The listener certificate $($certificate.Thumbprint) $why. The store entry will be removed so that Windows generates a fresh certificate, and the key container to go with it, when the Remote Desktop services next start."))
            }
        }
    }

    return $findings.ToArray()
}

function Add-OfflinePathAce {
    <#
    .SYNOPSIS
        Adds access control entries to a file or folder, taking ownership only if refused.

    .DESCRIPTION
        Entries are added to the descriptor that is already there; it is never replaced. Anything an
        administrator added deliberately survives, and a denied entry for the same SID is removed
        first because a deny beats an allow no matter which order they appear in.

        Ownership is only taken when the plain write is actually refused, and the original owner is
        put back afterwards, so a container that is repaired does not come away owned by the rescue
        VM's administrator.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Ace,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $false)][switch]$IsDirectory
    )

    # Told rather than probed. Get-Item on a path inside a hardened folder fails for the same
    # provider reason Get-Acl does, and the caller always knows which of the two it is holding.
    $isDirectory = [bool]$IsDirectory

    # First, before anything is read or written. This is the only privileged mutation in the script
    # that could otherwise land without the gate: Grant-OfflinePathAccess and
    # Restore-OfflinePathSecurity both assert, but Save-OfflinePathSecurity does not, and the
    # unescalated write below reaches it directly on any disk where the rescue VM already has
    # rights - which is most of them. The gate is what stops a privileged write landing on the
    # rescue VM's own disk if an upstream precondition degrades.
    [void](Assert-OfflineTarget -Path $Path -Action 'change the permissions of')

    $original = Get-PathSddl -Path $Path -IsDirectory:$isDirectory
    if (-not $original) {
        Add-OfflineRepairLog -Level Warning -Message "Could not read the security descriptor of $Path, so it was left alone."
        return $false
    }

    # The descriptor to build from is passed in rather than re-read. On the retry path below the
    # object has already been borrowed, which adds a FullControl entry for this account; rebuilding
    # from a fresh read would write that borrowed entry into the customer's descriptor permanently.
    # Building from the original capture is what keeps it out, the same reasoning the registry
    # counterpart records.
    $apply = {
        param([string]$SourceSddl)

        $current = $SourceSddl
        if (-not $current) { throw "The security descriptor of $Path could not be read." }

        # Worked at the raw level rather than through FileSecurity.AddAccessRule. .NET refuses to
        # modify a list whose entries are out of canonical order - a deny sitting after an allow,
        # which hardening scripts and hand written tools both produce - and an already damaged
        # descriptor is exactly the one that needs repairing. Rebuilding it restores the order
        # Windows expects while keeping every flag, including which entries were inherited.
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($current)
        $revision = 2
        $existing = @()
        if ($null -ne $raw.DiscretionaryAcl) {
            $revision = $raw.DiscretionaryAcl.Revision
            for ($i = 0; $i -lt $raw.DiscretionaryAcl.Count; $i++) { $existing += $raw.DiscretionaryAcl[$i] }
        }

        # A deny beats an allow whatever the order, so a deny for one of the accounts being granted
        # would survive the repair and keep the access shut. Those entries - and only those - are
        # dropped. Every other entry, including a deny for any other account, is carried through.
        $targets = @(@($Ace) | ForEach-Object { $_.Sid })
        $existing = @($existing | Where-Object { -not ($_.AceType.ToString() -like '*Denied*' -and $targets -contains $_.SecurityIdentifier.Value) })

        foreach ($entry in @($Ace)) {
            # The measured mask, not the friendly name: [FileSystemRights]::Read is 0x20089, while
            # every build ships 0x120089 - the same rights plus Synchronize.
            $existing += [System.Security.AccessControl.CommonAce]::new(
                'None', 'AccessAllowed', [int]$entry.Mask,
                [System.Security.Principal.SecurityIdentifier]::new($entry.Sid), $false, $null)
        }

        # Canonical order: explicit deny, explicit allow, inherited deny, inherited allow.
        $inheritedFlag = [int][System.Security.AccessControl.AceFlags]::Inherited
        $ordered = @(
            @($existing | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($existing | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
            @($existing | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($existing | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
        )

        $newAcl = [System.Security.AccessControl.RawAcl]::new($revision, $ordered.Count)
        for ($i = 0; $i -lt $ordered.Count; $i++) { $newAcl.InsertAce($i, $ordered[$i]) }
        $raw.DiscretionaryAcl = $newAcl

        $sd = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
        $sd.SetSecurityDescriptorSddlForm($raw.GetSddlForm('Access'), 'Access')
        Save-OfflinePathSecurity -Path $Path -Security $sd -IsDirectory:$isDirectory
    }

    try {
        & $apply $original
        Add-OfflineRepairLog -Message "$Description Original descriptor was $original"
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "$Path refused the permission change ($($_.Exception.Message)); taking ownership and retrying."
    }

    $captured = $null
    $capturedBinary = $null
    try { $captured = Grant-OfflinePathAccess -Path $Path -CapturedBinary ([ref]$capturedBinary) }
    catch { Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be taken ($($_.Exception.Message))." }
    if (-not $captured) {
        Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be taken, so its permissions were left alone."
        return $false
    }

    try {
        # Built from the descriptor captured before the borrow, so the FullControl entry the borrow
        # just added for this account is not carried into what gets written.
        & $apply $captured

        # Hand the object back. The DACL just written is kept; only the owner is replayed, and only
        # when taking it actually changed the owner.
        $ownerNow = Get-OfflineSddlOwner -Sddl (Get-PathSddl -Path $Path -IsDirectory:$isDirectory)
        $ownerWas = Get-OfflineSddlOwner -Sddl $captured
        if ($ownerWas -and $ownerNow -ne $ownerWas) {
            $ownerOnly = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
            $ownerOnly.SetOwner([System.Security.Principal.SecurityIdentifier]::new($ownerWas))
            try { Save-OfflinePathSecurity -Path $Path -Security $ownerOnly -IsDirectory:$isDirectory }
            catch {
                # Registered, not merely logged. Leaving a customer's key container owned by the
                # rescue VM is residue of exactly the kind the borrow bookkeeping exists to surface,
                # and without this the run could still finish "Repaired N of N" and report success.
                Register-UnrestoredPath -Path $Path -Sddl $captured
                Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be handed back to $ownerWas. Restore it with: icacls `"$Path`" /setowner `"*$ownerWas`""
            }
        }

        Add-OfflineRepairLog -Message "$Description Ownership was taken to do it. Original descriptor was $original"
        return $true
    }
    catch {
        # The binary descriptor is replayed in preference to the SDDL: an SDDL string re-resolves
        # machine-relative aliases against the rescue VM, so a domain-joined disk's DA/DU/DC entries
        # either fail to parse or resolve to the wrong account. A restore that does not read back
        # identically returns $false, and that answer is acted on rather than discarded - leaving a
        # customer's key container owned by the rescue VM is not something to report as success.
        $restored = Restore-BorrowedPath -Path $Path -Sddl $captured -Binary $capturedBinary
        if (-not $restored) {
            # Restore-BorrowedPath already registers on a false return, and Register-UnrestoredPath
            # is idempotent, so this is deliberate belt and braces rather than a missing case - kept
            # so the guarantee is visible at the call site that depends on it, and stated here so a
            # later reader does not conclude that Restore-BorrowedPath does not register.
            Register-UnrestoredPath -Path $Path -Sddl $captured
            Add-OfflineRepairLog -Level Warning -Message "$Path could not be repaired ($($_.Exception.Message)), and its original permissions could not be put back either."
        }
        else {
            Add-OfflineRepairLog -Level Warning -Message "$Path could not be repaired ($($_.Exception.Message)); its original permissions were put back."
        }
        return $false
    }
}

function Repair-FileFinding {
    <#
    .SYNOPSIS
        Repairs one finding that lives on the file system rather than in a hive.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch -Regex ($Finding.Cause) {

        '^ContainerKeyUnreadable$' {
            $container = $Finding.Data
            $restore = @(@($container.Missing) + @($container.Blocked))
            if ($restore.Count -eq 0) { return $false }
            $who = @($restore | ForEach-Object { "$($_.Who) ($($_.Rights))" }) -join ', '
            return (Add-OfflinePathAce -Path $container.Path -Ace $restore `
                    -Description "$($container.Name): restored $who on the listener key container, so the Remote Desktop service can read its private key again.")
        }

        '^MachineKeysFolderHardened$' {
            $ace = [PSCustomObject]@{ Sid = $script:SidEveryone; Mask = $script:MaskFolderEveryone; Rights = 'Read, Write, Synchronize'; Who = 'Everyone' }
            return (Add-OfflinePathAce -Path $Finding.Data.FolderPath -Ace $ace -IsDirectory `
                    -Description 'MachineKeys: restored the read and write access every measured build grants on the machine key store, so the next listener key container is created complete.')
        }

        default { return $false }
    }
}

function Repair-RegistryFinding {
    <#
    .SYNOPSIS
        Repairs one finding that lives in the SYSTEM hive.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch -Regex ($Finding.Cause) {

        '^CertificateServiceDisabled$' {
            $service = $Finding.Data
            $outcome = Invoke-OfflineProtectedRegistryWrite -Path $service.Path -Description "$($service.Name) Start" -Action {
                Set-ItemProperty -Path $service.Path -Name 'Start' -Value ([uint32]$service.Spec.Start) -Type DWord -Force -ErrorAction Stop
            }
            if ($outcome.Written) {
                Add-OfflineRepairLog -Message "$($service.Name): Start 4 (Disabled) -> $($service.Spec.Start), the value measured on every supported build."
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "$($service.Name) Start could not be written: $($outcome.Reason)"
            return $false
        }

        default { return $false }
    }
}

function Remove-OfflineRegistryKeyDeny {
    <#
    .SYNOPSIS
        Removes the Deny entries for one SID from an offline hive key, leaving the rest as found.

    .DESCRIPTION
        This is the registry half of the two places in this script where an access control entry is
        taken away rather than added, so it is deliberately narrow: only entries of type Deny, only
        for the SID it is given, only those written on the key itself, only on the key it is given.
        Inherited entries are left alone - they belong to a key above this one and are removed by
        repairing that key, not by stamping a copy of the parent's list here. Every other entry,
        including anything an administrator added on purpose, is carried across untouched.

        The new descriptor is built from the ORIGINAL capture, not from whatever is on the key after
        ownership has been taken. That matters: Grant-OfflineRegistryKeyAccess adds a FullControl
        entry for this account so the write can happen at all, and building from the original is what
        keeps that borrowed entry out of the result. It also means Restore-OfflineRegistrySecurity
        must NOT be called against this key afterwards - replaying the capture would put the deny
        straight back. The owner is handed back by hand instead.

        An allow entry is added only when removing the deny leaves the SID without the access, so a
        key that already grants it explicitly comes away with nothing added.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$GrantMask,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $original = Get-OfflineRegistryKeySecurity -Path $Path
    if (-not $original) {
        Add-OfflineRepairLog -Level Warning -Message "Could not read the security descriptor of $Path, so it was left alone."
        return $false
    }

    $target = [System.Security.Principal.SecurityIdentifier]::new($Sid)

    # Built once, from the original, and reused by both the plain attempt and the retry.
    $desired = {
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($original, 0)
        $acl = $raw.DiscretionaryAcl
        $inheritedFlag = [int][System.Security.AccessControl.AceFlags]::Inherited
        $kept = @()
        if ($null -ne $acl) {
            $kept = @($acl | Where-Object {
                    -not ($_.SecurityIdentifier -eq $target -and
                        $_.AceType.ToString() -like '*Denied*' -and
                        -not ([int]$_.AceFlags -band $inheritedFlag))
                })
        }

        # The union across every allow ACE for this SID, not a search for one ACE carrying the whole
        # mask. Test-SddlGrant takes the same view, and for the same reason: a healthy key can split
        # the rights across two entries, and reading that as "not granted" would add a redundant
        # explicit allow to a key that has nothing wrong with it.
        $allowUnion = 0
        foreach ($ace in @($kept | Where-Object { $_.SecurityIdentifier -eq $target -and $_.AceType -eq 'AccessAllowed' })) {
            $allowUnion = $allowUnion -bor [int]$ace.AccessMask
        }
        $granted = (($allowUnion -band $GrantMask) -eq $GrantMask)

        if (-not $granted) {
            $kept += [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                $GrantMask, $target, $false, $null)
        }

        # Canonical order: explicit deny, explicit allow, inherited deny, inherited allow. .NET
        # refuses to work with a list that is out of order, and a hardening tool is exactly what
        # produces one.
        $ordered = @(
            @($kept | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($kept | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
            @($kept | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($kept | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
        )

        $revision = if ($null -ne $acl) { $acl.Revision } else { 2 }
        $newAcl = [System.Security.AccessControl.RawAcl]::new($revision, $ordered.Count)
        for ($i = 0; $i -lt $ordered.Count; $i++) { $newAcl.InsertAce($i, $ordered[$i]) }
        $raw.DiscretionaryAcl = $newAcl

        $bytes = [byte[]]::new($raw.BinaryLength)
        $raw.GetBinaryForm($bytes, 0)

        $sd = [System.Security.AccessControl.RegistrySecurity]::new()
        # The Access section alone, so the owner is not rewritten by a repair that is about the DACL.
        $sd.SetSecurityDescriptorBinaryForm($bytes, [System.Security.AccessControl.AccessControlSections]::Access)
        return $sd
    }

    $write = {
        [void](Assert-OfflineTarget -Path $Path -Action 'change the permissions of')
        $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
        if (-not $subKey) { throw "$Path is not a key in a mounted offline hive." }

        $key = $null
        try {
            $rights = [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
            [System.Security.AccessControl.RegistryRights]::ChangePermissions
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
            if (-not $key) { throw "$subKey could not be opened to change its permissions." }
            $key.SetAccessControl((& $desired))
        }
        finally { if ($key) { $key.Close() } }
    }

    $verify = {
        $probe = Get-RegistryKeyProbe -Path $Path
        if (-not $probe.Sddl) { return $false }
        return -not (Get-SddlDeny -Sddl $probe.Sddl -Sid $Sid -Mask $GrantMask).Explicit
    }

    try {
        & $write
        if (& $verify) {
            Add-OfflineRepairLog -Message "$Description Original descriptor was $((([System.Security.AccessControl.RawSecurityDescriptor]::new($original, 0)).GetSddlForm('All')))"
            return $true
        }
        Add-OfflineRepairLog -Level Info -Message "$Path still denies the account after the permission change; taking ownership and retrying."
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "$Path refused the permission change ($($_.Exception.Message)); taking ownership and retrying."
    }

    # The capture is taken only so the owner can be handed back. The DACL is deliberately NOT
    # restored from it - that is the deny this whole function exists to remove.
    $captured = [System.Collections.Generic.List[object]]::new()
    try { [void](Grant-OfflineRegistryKeyAccess -Path $Path -NoRecurse -CapturedInto $captured) }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be taken ($($_.Exception.Message)), so its permissions were left alone."
        return $false
    }

    try {
        & $write
        if (-not (& $verify)) { throw 'the deny entry was still present after the write.' }
    }
    catch {
        [void](Restore-OfflineRegistrySecurity -Captured $captured.ToArray())
        Add-OfflineRepairLog -Level Warning -Message "$Path could not be repaired ($($_.Exception.Message)); its original permissions were put back."
        return $false
    }

    # Hand the key back. Only the owner is replayed; the DACL just written is what must survive.
    $rawOriginal = [System.Security.AccessControl.RawSecurityDescriptor]::new($original, 0)
    if ($rawOriginal.Owner) {
        $key = $null
        try {
            $subKey = ConvertTo-OfflineNativeSubKey -Path $Path
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($key) {
                $ownerOnly = [System.Security.AccessControl.RegistrySecurity]::new()
                $ownerOnly.SetOwner($rawOriginal.Owner)
                $key.SetAccessControl($ownerOnly)
            }
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be handed back to $($rawOriginal.Owner). Restore it by hand while the hive is mounted: [Security.AccessControl.RegistrySecurity] owner set to $($rawOriginal.Owner) on `"$(ConvertTo-OfflineNativeSubKey -Path $Path)`". (subinacl is not suggested here - Microsoft retired it and no longer distributes it.)"
        }
        # Closed in a finally, not on the success path. An open RegistryKey holds the mounted hive
        # open, so a throw inside SetAccessControl used to leave a handle behind and the unload at
        # the end of the run would fail - turning a cosmetic owner-handback failure into a disk that
        # still has a hive mounted on it.
        finally { if ($key) { $key.Close() } }
    }

    Add-OfflineRepairLog -Message "$Description Ownership was taken to do it. Original descriptor was $($rawOriginal.GetSddlForm('All'))"
    return $true
}

function Repair-SoftwareFinding {
    <#
    .SYNOPSIS
        Repairs one finding that lives in the SOFTWARE hive - the certificate store and its contents.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch -Regex ($Finding.Cause) {

        '^CertificateStoreAccessDenied$' {
            return (Remove-OfflineRegistryKeyDeny -Path $Finding.Data.Path -Sid $script:SidSystem -GrantMask $script:MaskKeyFullControl `
                    -Description "$($Finding.Data.Label): removed the entries denying NT AUTHORITY\SYSTEM, so Windows can create the listener certificate again.")
        }

        '^ListenerCertificateUnusable$' {
            $certificate = $Finding.Data
            $outcome = Invoke-OfflineProtectedKeyRemoval -Path $certificate.Path -Label "listener certificate $($certificate.Thumbprint)"
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "Removed the unusable listener certificate $($certificate.Thumbprint) (subject $($certificate.Subject), expiry $($certificate.NotAfter)) from the Remote Desktop store, so Windows generates a fresh one on the next start. $($outcome.Reason)"
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The listener certificate $($certificate.Thumbprint) could not be removed: $($outcome.Reason)"
            return $false
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

# The status is held rather than returned from inside the try. The status token is an ordinary
# string on the output stream, so returning it early puts it ahead of whatever the finally flushes -
# and Run Command keeps only the tail of a 4096-character log, so a long flush can push the token
# out of the retained window and leave 'az vm repair run' with no status at all. The caller contract
# in common\helpers\README.md asks for exactly this shape: cleanup and logging first, status last.
# The labelled block gives the early exits somewhere to go that is still inside the try.
$status = $STATUS_ERROR
try {
    :main do {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $buildNumber = 0
    [void][int]::TryParse("$($offline.BuildNumber)", [ref]$buildNumber)
    $volumeRoot = Split-Path -Path $offline.WindowsPath -Parent

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "Listener certificate permissions are not covered by $($script:DocUrl); the target below was measured on healthy images of 9600, 14393, 17763, 20348 and 26100." | Tee-Object -FilePath $logFile -Append

    if ($buildNumber -le 0) {
        Log-Warning 'The build number of the offline installation could not be read. The pre-17763 permission set is assumed, which grants Administrators read rather than SessionEnv full control.' | Tee-Object -FilePath $logFile -Append
    }

    $keyStore = Get-KeyStoreState -VolumeRoot $volumeRoot -BuildNumber $buildNumber
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # The certificate store is read before the SYSTEM hive rather than inside it, because the two
    # live in different hives and only one can be mounted under a given name at a time.
    $certStore = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-CertificateStoreState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath -Strict:(-not $isDetectOnly)
        $services = Get-CertificateServiceState -SystemRoot $systemRoot
        $pinned = Get-ListenerPinnedThumbprint -SystemRoot $systemRoot

        return [PSCustomObject]@{
            ControlSet = (Split-Path -Path $systemRoot -Leaf)
            Services   = @($services)
            Pinned     = $pinned
            Findings   = @(Get-AllFinding -KeyStore $keyStore -Services $services -CertStore $certStore -PinnedThumbprint $pinned)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet)." | Tee-Object -FilePath $logFile -Append
    # Four states, not three. FolderExists is forced true for a folder whose parent would not be
    # listed, so "present" would be a positive claim on a read that never succeeded. But a folder
    # that Test-Path confirmed and then would not list is a different answer again, and by far the
    # likelier one - a hardened MachineKeys is the scenario this script exists for. Naming the
    # parent in that case sends the operator up one directory from the object actually at fault.
    $folderShown = if (-not $keyStore.FolderExists) { 'absent - not a fault, Windows recreates it and the key with it on the next start' }
    elseif ($keyStore.FolderListed) { 'present' }
    elseif (-not $keyStore.FolderPresenceKnown) { 'could not be determined - the folder above it refused a listing, so it is treated as present and unreadable' }
    else { 'present, but its contents could not be listed even after taking ownership' }
    Log-Info "Machine key store: $($keyStore.FolderPath) $folderShown." | Tee-Object -FilePath $logFile -Append
    if ($keyStore.FolderExists) {
        Log-Info "  Folder descriptor: $(if ($keyStore.FolderSddlKnown) { $keyStore.FolderSddl } else { '<descriptor refused>' })" | Tee-Object -FilePath $logFile -Append
    }

    Log-Info "Expected on build $($offline.BuildNumber): $(@($keyStore.Required | ForEach-Object { "$($_.Who)=$($_.Rights)" }) -join ', ')." | Tee-Object -FilePath $logFile -Append

    if (@($keyStore.Containers).Count -eq 0 -and $keyStore.FolderExists -and $keyStore.FolderListed) {
        # Measured: with no container present Windows generates a new one, with correct permissions,
        # within seconds of the Remote Desktop services starting. Stated so nobody reads it as a fault.
        # Gated on FolderListed as well as FolderExists, because an empty Containers list means three
        # different things - genuinely empty, listing refused, or folder absent behind a refused
        # parent - and only the first supports the claim. The other two already raise their own
        # findings, and this line would contradict them in the part of the log most likely to be read.
        Log-Info 'No Remote Desktop listener key container is present. That is not a fault: Windows generates one on the next start, and it was measured doing so.' | Tee-Object -FilePath $logFile -Append
    }
    foreach ($container in @($keyStore.Containers)) {
        Log-Info "  $($container.Name): $(if ($container.NsBroken) { 'NETWORK SERVICE cannot read it' } else { 'NETWORK SERVICE can read it' })." | Tee-Object -FilePath $logFile -Append
    }

    foreach ($service in @($context.Services)) {
        $shown = if (-not $service.Exists) { 'no service key' } elseif ($service.Unreadable) { '(unreadable)' } elseif ($service.Malformed) { '(Start is not a number)' } elseif ($null -eq $service.Start) { '(Start not set)' } else { "Start=$($service.Start)" }
        Log-Info "  $($service.Name): $shown - $($service.Spec.Purpose)." | Tee-Object -FilePath $logFile -Append
    }

    $storeShown = if ($certStore.StoreExists) { 'present' } else { 'absent - not a fault, Windows recreates it with the certificate' }
    Log-Info "Remote Desktop certificate store: HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop $storeShown." | Tee-Object -FilePath $logFile -Append
    foreach ($key in @($certStore.Keys)) {
        if (-not $key.Exists) { Log-Info "  $($key.Label): absent." | Tee-Object -FilePath $logFile -Append; continue }
        Log-Info "  $($key.Label): $(if ($key.Sddl) { $key.Sddl } else { '<descriptor refused>' })" | Tee-Object -FilePath $logFile -Append
    }
    if (@($certStore.Certificates).Count -eq 0 -and $certStore.CertificatesKnown) {
        # Same measurement as the missing key container above. Stated so nobody reads it as a fault.
        Log-Info '  No certificate is in the store. That is not a fault: Windows generates one on the next start, and it was measured doing so.' | Tee-Object -FilePath $logFile -Append
    }
    foreach ($certificate in @($certStore.Certificates)) {
        $shown = if (-not $certificate.Parsed) { 'could not be parsed' } else { "$($certificate.Subject), expires $($certificate.NotAfter.ToString('yyyy-MM-dd HH:mm'))$(if ($certificate.Expired) { ' - EXPIRED' })" }
        Log-Info "  $($certificate.Thumbprint): $shown." | Tee-Object -FilePath $logFile -Append
    }
    if ($context.Pinned -eq $script:PinUnreadable) {
        # Not "pinned to certificate UNREADABLE". The sentinel says the read was refused, and
        # rendering it as a thumbprint would make a positive claim - that the listener IS pinned,
        # and to a value that does not exist - on precisely the read that failed, and would send the
        # operator to remove a pin that may not be there. The detection side already treats this as
        # "might be pinned to anything"; the log has to say the same thing.
        Log-Info "SSLCertificateSHA1Hash could not be read, so whether the listener is pinned to a specific certificate is unknown. No certificate was removed on that basis." | Tee-Object -FilePath $logFile -Append
    }
    elseif ($context.Pinned) {
        Log-Info "The listener is pinned to certificate $($context.Pinned) by SSLCertificateSHA1Hash. Removing a pin is win-fix-rdp-connectivity's job, not this script's." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    # Ahead of the detect gate on purpose, so one affirmative line serves both modes. A healthy disk
    # and one this script cannot help must not produce the same silence.
    if ($findings.Count -eq 0) {
        # The borrow clause is built from what actually happened rather than asserted. A run that
        # has just raised OfflineSecurityNotRestored must not also state that everything borrowed
        # was put back, and the detect-only summary below prints the same sentence.
        $borrowNote = if (@($script:UnrestoredPaths.Keys).Count -gt 0) {
            "$(@($script:UnrestoredPaths.Keys).Count) object(s) whose descriptor was borrowed could not be handed back and are listed above"
        }
        else {
            'where a descriptor had to be borrowed to read a locked object it was put back'
        }

        # The claim about private keys is narrowed when a certificate was deliberately not judged -
        # a CNG key, a provider that could not be read, or a container this script cannot locate by
        # name. Saying "any certificate in it has its private key" in that case is an affirmative
        # statement about a certificate this run explicitly declined to examine, which is the one
        # thing the detection rules forbid. The count is reported without attributing a cause,
        # because the three reasons are different and the per-certificate reason is already logged.
        $keyClaim = if (@($script:UnjudgedCertificates).Count -gt 0) {
            "every certificate this script could judge is in date and has its private key - $(@($script:UnjudgedCertificates).Count) certificate(s) were not judged against the machine key store, for the reasons given above, and were left alone"
        }
        else {
            'any certificate in it is in date and has its private key'
        }
        Log-Output "No listener certificate fault was found. The Remote Desktop service account can read the listener private key, the certificate store grants SYSTEM the access it needs to create a certificate, $keyClaim, and the services behind them are not disabled. No configuration was changed; $borrowNote." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses. The unjudged count is
        # carried here for the same reason it narrows the healthy line: the per-certificate reasons
        # live in the detail log, and this is the only line a truncated detect run is sure to keep.
        $unjudgedNote = if (@($script:UnjudgedCertificates).Count -gt 0) {
            " $(@($script:UnjudgedCertificates).Count) certificate(s) were not judged against the machine key store, for the reasons given above, and were left alone."
        }
        else { '' }
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No configuration was changed; $(if (@($script:UnrestoredPaths.Keys).Count -gt 0) { "$(@($script:UnrestoredPaths.Keys).Count) object(s) whose descriptor was borrowed could not be handed back and are listed above" } else { 'where a descriptor had to be borrowed to read a locked object it was put back' }).$unjudgedNote" | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_SUCCESS
        break main
    }

    $repairedCount = 0
    $failed = [System.Collections.Generic.List[string]]::new()

    # --- File system repairs, outside any hive ----------------------------------------------------
    foreach ($finding in @($repairable | Where-Object { $_.Hive -eq 'FILE' })) {
        try {
            if (Repair-FileFinding -Finding $finding) {
                $repairedCount++
            }
            else {
                # Add-OfflinePathAce returns false rather than throwing when a descriptor cannot be
                # read, ownership cannot be taken, or the retry apply fails. With no else branch
                # that silent false was neither counted nor recorded, and for a finding the verify
                # pass cannot re-raise - MachineKeysFolderHardened is gated on a broken container
                # that the same run just repaired - the script reported success for a repair that
                # did not happen.
                [void]$failed.Add("$($finding.Item): the repair reported that it changed nothing.")
                Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
            }
        }
        catch {
            [void]$failed.Add("$($finding.Item): $($_.Exception.Message)")
            Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # --- Certificate store repairs, in the SOFTWARE hive ------------------------------------------
    $softwareFindings = @($repairable | Where-Object { $_.Hive -eq 'SOFTWARE' })
    # Built from every SOFTWARE finding detection produced, not just the repairable ones. Keyed on
    # the repairable subset, an unrepairable finding detection had already reported would be absent
    # here, so the re-detection below would re-emit it, log it as newly found and count it a second
    # time in "issue(s) need a decision".
    $softwareSeen = @($findings | Where-Object { $_.Hive -eq 'SOFTWARE' } | ForEach-Object { "$($_.Cause)|$($_.Item)" })
    if ($softwareFindings.Count -gt 0) {
        $softwareBackup = Backup-OfflineHiveFile -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append

        $softwareOutcome = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()
            $revealed = [System.Collections.Generic.List[object]]::new()

            # The store's own permissions first: a certificate cannot be deleted out of a key that
            # still refuses to be written to.
            $ordered = @(@($softwareFindings | Where-Object { $_.Cause -eq 'CertificateStoreAccessDenied' }) +
                @($softwareFindings | Where-Object { $_.Cause -ne 'CertificateStoreAccessDenied' }))
            $denyRepaired = $false
            foreach ($finding in $ordered) {
                try {
                    if (Repair-SoftwareFinding -Finding $finding) {
                        $done++
                        if ($finding.Cause -eq 'CertificateStoreAccessDenied') { $denyRepaired = $true }
                    }
                    else {
                        [void]$errors.Add("$($finding.Item): the repair reported that it changed nothing.")
                        Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
                    }
                }
                catch {
                    [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                    Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
                }
            }

            # A store that refused to be listed hid whatever was in it, so removing the deny can
            # expose a certificate detection never saw. Left to the verification pass it would be
            # reported as an issue that is "still present" - which would be a repair this script
            # declined to make, called a failure. It is detected and repaired here instead, in the
            # same hive session, and reported as what it is: found only once the store opened.
            if ($denyRepaired) {
                $seen = $softwareSeen
                $fresh = Get-CertificateStoreState
                $new = @(Get-AllFinding -KeyStore $keyStore -Services @() -CertStore $fresh -PinnedThumbprint $context.Pinned |
                        Where-Object { $_.Hive -eq 'SOFTWARE' -and "$($_.Cause)|$($_.Item)" -notin $seen })

                foreach ($finding in $new) {
                    [void]$revealed.Add($finding)
                    Add-OfflineRepairLog -Message "Found once the certificate store opened: [$($finding.Cause)] $($finding.Message)"
                    if (-not $finding.Repairable) { continue }
                    try {
                        if (Repair-SoftwareFinding -Finding $finding) {
                            $done++
                        }
                        else {
                            [void]$errors.Add("$($finding.Item): the repair reported that it changed nothing.")
                            Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
                        }
                    }
                    catch {
                        [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                        Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
                    }
                }
            }

            return [PSCustomObject]@{ Repaired = $done; Errors = @($errors); Revealed = @($revealed) }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        foreach ($finding in @($softwareOutcome.Revealed)) {
            Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
            $findings += $finding
            if ($finding.Repairable) { $repairable += $finding } else { $unrepairable += $finding }
        }

        $repairedCount += $softwareOutcome.Repaired
        foreach ($failure in @($softwareOutcome.Errors)) { [void]$failed.Add($failure) }
    }

    # --- Registry repairs -------------------------------------------------------------------------
    $registryFindings = @($repairable | Where-Object { $_.Hive -eq 'SYSTEM' })
    if ($registryFindings.Count -gt 0) {
        $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            if ((Get-OfflineControlSetName -Strict) -ne $context.ControlSet) {
                throw 'Select\Current changed since detection; refusing to write the previously captured registry paths.'
            }
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($finding in $registryFindings) {
                try {
                    if (Repair-RegistryFinding -Finding $finding) {
                        $done++
                    }
                    else {
                        [void]$errors.Add("$($finding.Item): the repair reported that it changed nothing.")
                        Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair reported no change."
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

        $repairedCount += $repairOutcome.Repaired
        foreach ($failure in @($repairOutcome.Errors)) { [void]$failed.Add($failure) }
    }

    # Verify against freshly read state rather than trusting the writes above. Guarded the same way
    # the repair passes are: if nothing was repairable then nothing was backed up and nothing was
    # written, so re-reading can only restate what detection already found. Mounting SOFTWARE and
    # SYSTEM again for that is exposure without benefit - Invoke-WithHive throws if a hive will not
    # unload, which would turn an accurate "nothing here I can fix" into a reported failure on a run
    # that only ever read the disk. An all-non-repairable run is an ordinary outcome here: an
    # unjudged certificate and an inherited deny are both reported rather than repaired.
    $remaining = @()
    if ($repairable.Count -gt 0) {
        $verifyKeyStore = Get-KeyStoreState -VolumeRoot $volumeRoot -BuildNumber $buildNumber
        $verifyCertStore = Invoke-WithHive -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            return (Get-CertificateStoreState)
        }
        $remaining = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath -Strict
            return @(Get-AllFinding -KeyStore $verifyKeyStore -Services (Get-CertificateServiceState -SystemRoot $systemRoot) `
                    -CertStore $verifyCertStore -PinnedThumbprint (Get-ListenerPinnedThumbprint -SystemRoot $systemRoot))
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Piping $null sends one $null down the pipeline, and $null.Repairable is falsy, so an empty
    # verification pass would otherwise be reported as a finding with no cause and no message.
    $remaining = @($remaining | Where-Object { $null -ne $_ })

    # Computed before either loop so both can tell a finding that survived the repair from one the
    # repair itself created. The distinction matters to whoever reads the log: "still present" says
    # a repair did not take, "found after repair" says the run made something new.
    $alreadyReported = @($findings | ForEach-Object { "$($_.Cause)|$($_.Item)" })

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        $label = if ("$($finding.Cause)|$($finding.Item)" -in $alreadyReported) { 'STILL PRESENT' } else { 'FOUND AFTER REPAIR' }
        Log-Warning "$label [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # A non-repairable finding that appears for the first time in this pass was created by the
    # repair, not found by detection, and without this it would reach neither the summary nor the
    # [MANUAL] list below - which iterates the detection-time set. OfflineSecurityNotRestored is the
    # one that matters: a borrow taken during the repair pass and not handed back leaves a customer
    # object still owned by this rescue VM, and that cannot be allowed to end in a silent success.
    foreach ($finding in @($remaining | Where-Object { -not $_.Repairable -and "$($_.Cause)|$($_.Item)" -notin $alreadyReported })) {
        Log-Warning "FOUND AFTER REPAIR [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        $unrepairable += $finding
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported." }
    # Stated in the summary itself, because Run Command keeps only the tail of the log: a run that
    # still holds a customer object must not read as an unqualified success. It is not made a
    # failure - the repairs really were applied, and the disk should still be swapped back - but the
    # operator is told plainly what is still taken and where to look.
    if ($script:UnrestoredPaths.Count -gt 0) {
        $summary += " WARNING: $($script:UnrestoredPaths.Count) object(s) borrowed for this repair could not be handed back and are still owned by this rescue VM - see the detail log for each path."
    }
    # Carried here for the same reason the detect-only line carries it, and the same reason it
    # narrows the healthy line: Run Command keeps only the tail, so this is the line most likely to
    # survive. The count is the verification pass's where one ran, and detection's otherwise, so it
    # describes the disk as this run leaves it either way.
    if (@($script:UnjudgedCertificates).Count -gt 0) {
        $summary += " $(@($script:UnjudgedCertificates).Count) certificate(s) were left unjudged against the machine key store, for the reasons given above, and were not touched."
    }

    # Ahead of the failure gate on purpose, so both exits carry it. Behind it, a run that repaired
    # some findings and failed others printed only the count of the ones needing a decision, and
    # never said which - on exactly the run an engineer reads most carefully.
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($failed.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($failed.Count) repair(s) failed and $($stillRepairable.Count) issue(s) are still present." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        $status = $STATUS_ERROR
        break main
    }

    if ($repairedCount -gt 0) {
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM. If RDP still fails once it boots, the remaining option is to create a certificate by hand and pin it to the listener with SSLCertificateSHA1Hash, which is a temporary measure and an operator's decision." | Tee-Object -FilePath $logFile -Append
    }
    # The summary is printed after the [MANUAL] list and the restore advice, not before them, for
    # the same reason the detect summary comes last: az vm run-command keeps only the last 4096
    # characters of the output stream. A [MANUAL] message here can run several hundred characters -
    # a full SDDL, or an icacls hint - so a summary printed first is what a long run loses, and the
    # summary is the line carrying the warning about objects still owned by this rescue VM.
    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    $status = $STATUS_SUCCESS
    } while ($false)
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    $status = $STATUS_ERROR
}
finally {
    # The caller contract in common\helpers\README.md. On a throw the buffered helper entries are
    # the ones that say WHY - which hive refused to unload, which file was missing - and without
    # this they were discarded and only the exception survived. A dependency may have failed to
    # load before either function existed, hence the guards.
    if (Get-Command Clear-OfflineDriveLetter -ErrorAction SilentlyContinue) {
        Clear-OfflineDriveLetter
    }
    if (Get-Command Write-OfflineRepairLog -ErrorAction SilentlyContinue) {
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }
}

# Last, so it survives the tail-truncated log the extension keeps.
return $status
