# Fixture tests for win-detect-mana-readiness.ps1.
# Run from the repository root (works in Windows PowerShell 5.1 and PowerShell 7):
#   pwsh -NoProfile -File ./tests/test-win-detect-mana-readiness.ps1
#
# The detector's functions are extracted with the PowerShell parser and exercised against a temporary
# driver store and an in-memory stand-in for the offreg reader. Creating real hive files needs
# SeBackupPrivilege, and the reader itself is covered by OfflineRepairCommon's own consumers.

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$sourceScript = Join-Path $repositoryRoot 'src/windows/win-detect-mana-readiness.ps1'
$sourceText = Get-Content -LiteralPath $sourceScript -Raw

function Assert-True {
    Param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal {
    Param($Expected, $Actual, [string]$Message)
    if ("$Expected" -ne "$Actual") { throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')" }
}

$helperPath = Join-Path $repositoryRoot 'src/windows/common/helpers/ManaReadiness.ps1'
$helperText = Get-Content -LiteralPath $helperPath -Raw
ForEach ($path in $sourceScript, $helperPath) {
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) "$path must parse cleanly: $($parseErrors | Out-String)"
}
. $helperPath
ForEach ($name in 'Get-InfDriverFact', 'Get-OfflineDriverPackage', 'Resolve-ManaServiceBinaryPath', 'Get-OfflineServiceState', 'Get-ManaDriveAssessment', 'Get-OverallVerdict', 'Get-ManaOfflineAssessment') {
    Assert-True ([bool](Get-Command $name -ErrorAction SilentlyContinue)) "ManaReadiness.ps1 must define $name."
}
# The helper is also dot-sourced by win-fix-mana-driver next to Use-OfflineRegistryHive.ps1; a shared name would
# silently replace one of the two definitions.
$registryHelperText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/windows/common/helpers/Use-OfflineRegistryHive.ps1') -Raw
ForEach ($fn in [regex]::Matches($helperText, '(?m)^function ([\w-]+)')) {
    Assert-True ($registryHelperText -notmatch "(?m)^function $([regex]::Escape($fn.Groups[1].Value))\b") "ManaReadiness.ps1 must not redefine $($fn.Groups[1].Value)."
}
# --- INF parsing --------------------------------------------------------------------------------
# Synthetic INF: exercises the syntax the parser must survive, not a copy of a real MANA INF.
$inf = @(
    '; a comment line',
    '[Version]',
    'Signature   = "$WINDOWS NT$"',
    'DriverVer   = 01/02/2026,2.0.18.52 ; trailing comment',
    'Class       = Net',
    '[Example.Services]',
    'AddService = %ServiceName%, 0x00000002, Example_Service_Inst',
    '[MSFT.NTamd64]',
    '%Desc% = Example.ndi, PCI\VEN_1414&DEV_00BA',
    '%Desc2%=Other.ndi, mana_bus\VEN_1414&ROLE_004c, %CompatId%',
    'AddService = , 0x00000002   ; null service installs nothing',
    'addservice = "quoted;svc", 2, Other_Inst',
    '[Example_Service_Inst]',
    'ServiceBinary = %13%\example.sys',
    '[Strings]',
    'ServiceName = "examplesvc"',
    'CompatId = "mana_bus\VEN_1414&ROLE_004c_d"'
)
$facts = Get-InfDriverFact -Lines $inf
Assert-Equal '01/02/2026,2.0.18.52' $facts.driverVer 'DriverVer must be read from [Version] with the comment stripped.'
Assert-Equal 'examplesvc,quoted;svc' ($facts.services -join ',') 'AddService names must expand [Strings] tokens, keep quoted semicolons, and skip the null service.'
Assert-Equal 'example.sys' ($facts.serviceBinaries -join ',') 'ServiceBinary must resolve to the binary file name.'
Assert-Equal 'Net' $facts.class 'The setup class is read from [Version].'
Assert-Equal 'PCI\VEN_1414&DEV_00BA,MANA_BUS\VEN_1414&ROLE_004C,MANA_BUS\VEN_1414&ROLE_004C_D' ($facts.hardwareIds -join ',') 'Model lines yield upper-cased hardware and compatible IDs, with [Strings] tokens expanded.'
$hwPkg = @([pscustomobject]@{ hardwareIds = $facts.hardwareIds })
Assert-True (Test-ManaDeviceDriverStaged -DevicePath 'PCI\VEN_1414&DEV_00BA&SUBSYS_00B91414&REV_00\5&a&0&0' -Packages $hwPkg) 'A less specific INF ID matches a more specific device ID at an & boundary.'
Assert-True (-not (Test-ManaDeviceDriverStaged -DevicePath 'PCI\VEN_1414&DEV_00BAX\1' -Packages $hwPkg)) 'An INF ID must not match across an ID boundary.'
Assert-True (-not (Test-ManaDeviceDriverStaged -DevicePath 'MANA_BUS\VEN_1414&ROLE_0003\1' -Packages $hwPkg)) 'A device no package lists has no staged driver.'
Assert-Equal 0 @((Get-InfDriverFact -Lines @()).services).Count 'An empty INF must yield no services.'
Write-Host 'PASS: INF parsing (DriverVer, AddService with [Strings] expansion, null service, quoted semicolons, ServiceBinary).'

# --- Driver store discovery ---------------------------------------------------------------------
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mana-win-fixture-" + [guid]::NewGuid().ToString('N'))
try {
    $windowsRoot = Join-Path $fixtureRoot 'Windows'
    $store = Join-Path $windowsRoot 'System32\DriverStore\FileRepository'
    $manaPkg = Join-Path $store 'manavf.inf_amd64_0123456789abcdef'
    $mlxPkg = Join-Path $store 'mlx5.inf_amd64_fedcba9876543210'
    $emptyPkg = Join-Path $store 'mana_bus_vf.inf_amd64_00000000'
    $otherPkg = Join-Path $store 'netvsc.inf_amd64_11111111'
    $drivers = Join-Path $windowsRoot 'System32\drivers'
    ForEach ($dir in $manaPkg, $mlxPkg, $emptyPkg, $otherPkg, $drivers) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath (Join-Path $manaPkg 'manavf.inf') -Value $inf
    Set-Content -LiteralPath (Join-Path $mlxPkg 'mlx5.inf') -Value @('[Version]', 'DriverVer = 01/01/2024,1.0.0.0', '[S]', 'AddService = mlxsvc, 2, I')
    Set-Content -LiteralPath (Join-Path $otherPkg 'netvsc.inf') -Value @('[S]', 'AddService = netvsc, 2, I')
    Set-Content -LiteralPath (Join-Path $drivers 'netvsc.sys') -Value 'x'

    $mana = Get-OfflineDriverPackage -WindowsRoot $windowsRoot -InfPrefix 'mana'
    Assert-True $mana.repositoryFound 'The driver store must be found.'
    Assert-Equal 'manavf.inf_amd64_0123456789abcdef' (@($mana.packages).package -join ',') 'Only MANA packages with an INF present are returned; a directory without its INF is skipped.'
    Assert-Equal 'examplesvc,quoted;svc' (@($mana.packages)[0].services -join ',') 'Package services come from the INF.'
    Assert-Equal 'mlx5.inf_amd64_fedcba9876543210' (@((Get-OfflineDriverPackage -WindowsRoot $windowsRoot -InfPrefix 'mlx').packages).package -join ',') 'Mellanox packages are found with their own prefix.'

    $missingStore = Get-OfflineDriverPackage -WindowsRoot (Join-Path $fixtureRoot 'NoWindows') -InfPrefix 'mana'
    Assert-True (-not $missingStore.repositoryFound) 'A missing driver store must be reported as not found, not as no packages.'
    Write-Host 'PASS: driver store discovery (MANA, Mellanox, INF-less directory, missing store).'

    # --- ImagePath mapping --------------------------------------------------------------------------
    Assert-Equal "$windowsRoot\System32\drivers\netvsc.sys" (Resolve-ManaServiceBinaryPath -WindowsRoot $windowsRoot -ServiceName 'netvsc' -ImagePath '\SystemRoot\System32\drivers\netvsc.sys') '\SystemRoot must map to the attached disk.'
    Assert-Equal "$windowsRoot\System32\drivers\a.sys" (Resolve-ManaServiceBinaryPath -WindowsRoot $windowsRoot -ServiceName 'a' -ImagePath 'System32\drivers\a.sys') 'A System32-relative path must map to the attached disk.'
    Assert-Equal "$windowsRoot\System32\drivers\b.sys" (Resolve-ManaServiceBinaryPath -WindowsRoot $windowsRoot -ServiceName 'b' -ImagePath '\??\C:\Windows\System32\drivers\b.sys') 'An absolute C:\Windows path must map to the attached disk, never the repair VM.'
    Assert-Equal "$windowsRoot\System32\drivers\c.sys" (Resolve-ManaServiceBinaryPath -WindowsRoot $windowsRoot -ServiceName 'c' -ImagePath $null) 'A missing ImagePath defaults to System32\drivers\<service>.sys.'
    Assert-Equal '' "$(Resolve-ManaServiceBinaryPath -WindowsRoot $windowsRoot -ServiceName 'd' -ImagePath 'D:\Vendor\d.sys')" 'An unmappable path must not be guessed.'
    Write-Host 'PASS: ImagePath mapping never resolves to the repair VM.'

    # --- Service state through an offreg stand-in ---------------------------------------------------
    function New-FakeReader {
        Param([hashtable]$Values)
        $reader = [pscustomobject]@{ Values = $Values }
        $read = {
            Param($key, $name)
            $id = "$key|$name"
            if (-not $this.Values.ContainsKey($id)) { return $null }
            $value = $this.Values[$id]
            if ($value -is [System.Exception]) { throw $value }
            return $value
        }
        $reader | Add-Member -MemberType ScriptMethod -Name ReadDword -Value $read
        $reader | Add-Member -MemberType ScriptMethod -Name ReadString -Value $read
        return $reader
    }
    $reader = New-FakeReader @{
        'ControlSet001\Services\netvsc|Start'      = [uint32]3
        'ControlSet001\Services\netvsc|Type'       = [uint32]1
        'ControlSet001\Services\netvsc|ImagePath'  = '\SystemRoot\System32\drivers\netvsc.sys'
        'ControlSet001\Services\gone|Start'        = [uint32]3
        'ControlSet001\Services\gone|ImagePath'    = 'System32\drivers\gone.sys'
        'ControlSet001\Services\corrupt|Start'     = [System.IO.InvalidDataException]::new('not a registry DWORD')
        'ControlSet001\Services\nostart|Type'      = [uint32]1
        'ControlSet001\Services\nostart|ImagePath' = '\SystemRoot\System32\drivers\netvsc.sys'
        'ControlSet001\Services\badstart|Start'    = [uint32]7
    }
    $netvsc = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'netvsc' -WindowsRoot $windowsRoot
    Assert-True ($netvsc.present -and $netvsc.start -eq 3 -and $netvsc.binaryPresent) 'A healthy service must be present with its binary.'
    $gone = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'gone' -WindowsRoot $windowsRoot
    Assert-True ($gone.present -and $gone.binaryPresent -eq $false) 'A service whose binary is missing must say so.'
    $absent = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'absent' -WindowsRoot $windowsRoot
    Assert-True ($absent.present -eq $false -and $null -eq $absent.binaryPresent) 'An absent service key must be reported as not present.'
    $corrupt = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'corrupt' -WindowsRoot $windowsRoot
    Assert-True ($corrupt.readError -and $null -eq $corrupt.present) 'A read failure must be unknown, never absent.'
    $noStart = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'nostart' -WindowsRoot $windowsRoot
    Assert-True ($noStart.readError -match 'Start') 'An existing service without a Start value must be unknown, even with a healthy binary.'
    $badStart = Get-OfflineServiceState -Reader $reader -ControlSet 'ControlSet001' -ServiceName 'badstart' -WindowsRoot $windowsRoot
    Assert-True ($badStart.readError -match 'Start') 'A Start value outside 0..4 must be unknown.'
    Assert-Equal 'UNKNOWN' (Get-ManaDriveAssessment -Finding ([ordered]@{ netvsc = $noStart; driverStoreFound = $true; manaPackages = @([pscustomobject]@{ class = 'System'; hardwareIds = @('PCI\VEN_1414&DEV_00BA') }, [pscustomobject]@{ class = 'Net'; hardwareIds = @('MANA_BUS\VEN_1414&ROLE_004C') }); manaServices = @() })).verdict 'A netvsc service without Start makes the verdict unknown.'
    Write-Host 'PASS: service state (healthy, missing binary, absent key, read failure, missing or invalid Start).'

    # --- An unreadable driver package is unknown, not fatal -----------------------------------------
    function Open-OfflineRegistryReader { Param($Path) throw 'hive not available in this test' }
    function Get-Content { throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') }
    try { $unreadable = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot }
    finally { Remove-Item -Path Function:\Get-Content, Function:\Open-OfflineRegistryReader }
    Assert-True (-not $unreadable.driverStoreFound -and @($unreadable.manaPackages).Count -eq 0) 'A driver package that cannot be read must not be reported as a readable store.'
    Assert-True (@($unreadable.unknowns) -contains 'driver-store-unreadable') 'An unreadable driver store must be an unknown.'
    Assert-True (@($unreadable.readWarnings | Where-Object { $_ -match 'MANA driver packages' }).Count -eq 1) 'The read failure must be returned as a warning for the caller to log.'
    Write-Host 'PASS: an unreadable driver package makes the assessment UNKNOWN instead of stopping the run.'
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Verdicts -------------------------------------------------------------------------------------
$busPkg = [pscustomobject]@{ package = 'mana_bus_vf.inf_x'; class = 'System'; services = @('mana_bus'); hardwareIds = @('PCI\VEN_1414&DEV_00BA') }
$netPkg = [pscustomobject]@{ package = 'manavf.inf_x'; class = 'Net'; services = @('Mana'); hardwareIds = @('MANA_BUS\VEN_1414&ROLE_004C') }
$rdmaPkg = [pscustomobject]@{ package = 'mana_ib_vf.inf_x'; class = 'RDMA'; services = @('mana_ib'); hardwareIds = @('MANA_BUS\VEN_1414&ROLE_0003') }
function New-Finding {
    Param($Netvsc, [bool]$StoreFound = $true, [object[]]$Packages = @($busPkg, $netPkg), [object[]]$Services = @())
    [ordered]@{ netvsc = $Netvsc; driverStoreFound = $StoreFound; manaPackages = $Packages; manaServices = $Services }
}
$okNetvsc = @{ present = $true; start = 3; binaryPresent = $true; readError = $null }

$cases = @(
    @{ Name = 'ready'; Finding = (New-Finding $okNetvsc); Verdict = 'READY'; Problems = '' },
    @{ Name = 'MANA service not installed yet'; Finding = (New-Finding $okNetvsc -Services @(@{ name = 'm'; present = $false })); Verdict = 'READY'; Problems = '' },
    @{ Name = 'netvsc disabled'; Finding = (New-Finding @{ present = $true; start = 4; binaryPresent = $true }); Verdict = 'NOT_READY'; Problems = 'synthetic-nic-driver-disabled' },
    @{ Name = 'netvsc missing'; Finding = (New-Finding @{ present = $false }); Verdict = 'NOT_READY'; Problems = 'synthetic-nic-driver-missing' },
    @{ Name = 'netvsc binary missing'; Finding = (New-Finding @{ present = $true; start = 3; binaryPresent = $false }); Verdict = 'NOT_READY'; Problems = 'synthetic-nic-driver-binary-missing' },
    @{ Name = 'MANA package missing'; Finding = (New-Finding $okNetvsc -Packages @()); Verdict = 'NOT_READY'; Problems = 'mana-driver-missing' },
    @{ Name = 'MANA service disabled'; Finding = (New-Finding $okNetvsc -Services @(@{ name = 'm'; present = $true; start = 4; binaryPresent = $true })); Verdict = 'NOT_READY'; Problems = 'mana-driver-disabled:m' },
    @{ Name = 'SYSTEM hive unreadable'; Finding = (New-Finding $null); Verdict = 'UNKNOWN'; Problems = '' },
    @{ Name = 'driver store unreadable'; Finding = (New-Finding $okNetvsc -StoreFound $false -Packages @()); Verdict = 'UNKNOWN'; Problems = '' },
    @{ Name = 'MANA service read failure'; Finding = (New-Finding $okNetvsc -Services @(@{ name = 'm'; readError = 'x' })); Verdict = 'UNKNOWN'; Problems = '' },
    @{ Name = 'MANA service binary not resolvable'; Finding = (New-Finding $okNetvsc -Services @(@{ name = 'm'; present = $true; start = 3; binaryPresent = $null })); Verdict = 'UNKNOWN'; Problems = '' },
    @{ Name = 'only the RDMA package staged'; Finding = (New-Finding $okNetvsc -Packages @($rdmaPkg)); Verdict = 'NOT_READY'; Problems = 'mana-bus-driver-missing;mana-ethernet-driver-missing' },
    @{ Name = 'only the bus package staged'; Finding = (New-Finding $okNetvsc -Packages @($busPkg)); Verdict = 'NOT_READY'; Problems = 'mana-ethernet-driver-missing' },
    @{ Name = 'Ethernet ID listed by a non-Net package'; Finding = (New-Finding $okNetvsc -Packages @($busPkg, [pscustomobject]@{ package = 'x'; class = 'System'; hardwareIds = @('MANA_BUS\VEN_1414&ROLE_004C') })); Verdict = 'NOT_READY'; Problems = 'mana-ethernet-driver-missing' },
    @{ Name = 'only the Ethernet package staged'; Finding = (New-Finding $okNetvsc -Packages @($netPkg)); Verdict = 'NOT_READY'; Problems = 'mana-bus-driver-missing' }
)
ForEach ($case in $cases) {
    $result = Get-ManaDriveAssessment -Finding $case.Finding
    Assert-Equal $case.Verdict $result.verdict "Verdict for '$($case.Name)'."
    Assert-Equal $case.Problems ($result.problems -join ';') "Problems for '$($case.Name)'."
}
Assert-Equal 'NOT_READY' (Get-OverallVerdict -Verdicts @('READY', 'UNKNOWN', 'NOT_READY')) 'Any NOT_READY installation makes the disk NOT_READY.'
Assert-Equal 'UNKNOWN' (Get-OverallVerdict -Verdicts @('READY', 'UNKNOWN')) 'An unknown installation blocks a READY claim.'
Assert-Equal 'READY' (Get-OverallVerdict -Verdicts @('READY', 'READY')) 'All ready is READY.'
Assert-Equal 'UNKNOWN' (Get-OverallVerdict -Verdicts @()) 'No installations inspected is UNKNOWN.'
Write-Host "PASS: $($cases.Count) verdict cases and the overall verdict precedence."

# --- MANA device instances (live finding: a seen device is never reinstalled for a driver staged later) --------
$pkgs = @($busPkg, [pscustomobject]@{ package = 'manavf.inf_x'; class = 'Net'; services = @('Mana'); hardwareIds = @('MANA_BUS\VEN_1414&ROLE_004C', 'MANA_BUS\R') })
$deviceCases = @(
    @{ Name = 'seen device without driver'; D = @(@{ path = 'PCI\VEN_1414&DEV_00BA\1'; service = $null; configFlags = 0 }); S = @(); Verdict = 'NOT_READY'; Problems = 'mana-device-not-bound:PCI\VEN_1414&DEV_00BA\1' },
    @{ Name = 'seen device flagged for reinstall'; D = @(@{ path = 'PCI\VEN_1414&DEV_00BA\1'; service = $null; configFlags = 0x20 }); S = @(); Verdict = 'READY'; Problems = '' },
    @{ Name = 'bound device'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Mana'; configFlags = 0 }); S = @(@{ name = 'Mana'; present = $true; start = 3; binaryPresent = $true }); Verdict = 'READY'; Problems = '' },
    @{ Name = 'binary missing, bound device not flagged'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Mana'; configFlags = 0 }); S = @(@{ name = 'Mana'; present = $true; start = 3; binaryPresent = $false }); Verdict = 'NOT_READY'; Problems = 'mana-driver-binary-missing:Mana' },
    @{ Name = 'binary missing, staged and bound device flagged'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Mana'; configFlags = 0x20 }); S = @(@{ name = 'Mana'; present = $true; start = 3; binaryPresent = $false }); Verdict = 'READY'; Problems = '' },
    @{ Name = 'child of an unknown role with no driver'; D = @(@{ path = 'MANA_BUS\X\1'; service = $null; configFlags = 0x20 }); S = @(); Verdict = 'UNKNOWN'; Problems = '' },
    @{ Name = 'device bound to a deleted service'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Mana'; configFlags = 0 }); S = @(@{ name = 'Mana'; present = $false }); Verdict = 'NOT_READY'; Problems = 'mana-driver-service-missing:Mana' },
    @{ Name = 'deleted service, staged, device flagged'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Mana'; configFlags = 0x20 }); S = @(@{ name = 'Mana'; present = $false }); Verdict = 'READY'; Problems = '' },
    @{ Name = 'deleted service not staged'; D = @(@{ path = 'MANA_BUS\R\1'; service = 'Gone'; configFlags = 0x20 }); S = @(@{ name = 'Gone'; present = $false }); Verdict = 'NOT_READY'; Problems = 'mana-driver-service-missing:Gone' },
    @{ Name = 'binary missing, staged, no device yet'; D = @(); S = @(@{ name = 'Mana'; present = $true; start = 3; binaryPresent = $false }); Verdict = 'READY'; Problems = '' }
)
ForEach ($case in $deviceCases) {
    $finding = New-Finding $okNetvsc -Packages $pkgs -Services $case.S
    $finding.manaDevices = @($case.D | ForEach-Object { [pscustomobject]$_ })
    $finding.manaDevicesRead = $true
    $result = Get-ManaDriveAssessment -Finding $finding
    Assert-Equal $case.Verdict $result.verdict "Verdict for '$($case.Name)'."
    Assert-Equal $case.Problems ($result.problems -join ';') "Problems for '$($case.Name)'."
}
$netPkgs = @($busPkg, $netPkg)
$finding = New-Finding $okNetvsc -Packages $netPkgs
$finding.manaDevices = @([pscustomobject]@{ path = 'MANA_BUS\VEN_1414&ROLE_004C\1'; service = 'Mana'; configFlags = 0 }, [pscustomobject]@{ path = 'MANA_BUS\VEN_1414&ROLE_0003\1'; service = $null; configFlags = 0x40 })
$finding.manaDevicesRead = $true
$result = Get-ManaDriveAssessment -Finding $finding
Assert-Equal 'READY' $result.verdict 'With the Ethernet function covered, a MANA_BUS child without a driver (RDMA) does not block READY.'
Assert-Equal 'MANA_BUS\VEN_1414&ROLE_0003\1' ($result.optionalDevicesWithoutDriver -join ',') 'The uncovered non-Ethernet child is reported as optional.'
$finding.manaDevices = @([pscustomobject]@{ path = 'PCI\VEN_1414&DEV_00BA\1'; service = $null; configFlags = 0 })
$finding.manaPackages = @($netPkg)
Assert-Equal 'mana-bus-driver-missing;mana-device-no-driver:PCI\VEN_1414&DEV_00BA\1' ((Get-ManaDriveAssessment -Finding $finding).problems -join ';') 'The VF is never optional: without its bus driver there is no MANA networking.'
# A Net package that does not list the Ethernet child's ID does not make that child optional.
$finding = New-Finding $okNetvsc -Packages @($busPkg, [pscustomobject]@{ package = 'old.inf_x'; class = 'Net'; hardwareIds = @('MANA_BUS\VEN_1414&ROLE_0042') })
$finding.manaDevices = @([pscustomobject]@{ path = 'MANA_BUS\VEN_1414&ROLE_004C\1'; service = $null; configFlags = 0 })
$finding.manaDevicesRead = $true
$result = Get-ManaDriveAssessment -Finding $finding
Assert-True (@($result.problems) -contains 'mana-device-no-driver:MANA_BUS\VEN_1414&ROLE_004C\1') 'An uncovered Ethernet child is a problem, never optional.'
Assert-Equal 0 @($result.optionalDevicesWithoutDriver).Count 'The Ethernet child is not reported as optional.'
$finding = New-Finding $okNetvsc -Packages $pkgs; $finding.manaDevicesRead = $false
Assert-Equal 'UNKNOWN' (Get-ManaDriveAssessment -Finding $finding).verdict 'Unreadable device instances block a READY claim.'

function New-FakeHive {
    Param([hashtable]$Values)
    $r = [pscustomobject]@{ Values = $Values }
    $r | Add-Member ScriptMethod ReadDword { Param($key, $name) $this.Values["$key|$name"] }
    $r | Add-Member ScriptMethod ReadString { Param($key, $name) $this.Values["$key|$name"] }
    $r | Add-Member ScriptMethod GetSubKeyNames { Param($key) $null }
    $r | Add-Member ScriptMethod Dispose { }
    return $r
}
$enumReader = [pscustomobject]@{
    Keys   = @{
        'ControlSet001\Enum\PCI'                                   = @('VEN_1414&DEV_00BA&SUBSYS_1&REV_00', 'VEN_8086&DEV_7111')
        'ControlSet001\Enum\PCI\VEN_1414&DEV_00BA&SUBSYS_1&REV_00'  = @('5&a&0&0')
        'ControlSet001\Enum\MANA_BUS'                              = @('VEN_1414&ROLE_004C')
        'ControlSet001\Enum\MANA_BUS\VEN_1414&ROLE_004C'           = @('6&b&0&1')
    }
    Values = @{ 'ControlSet001\Enum\MANA_BUS\VEN_1414&ROLE_004C\6&b&0&1|Service' = 'Mana'; 'ControlSet001\Enum\MANA_BUS\VEN_1414&ROLE_004C\6&b&0&1|ConfigFlags' = [uint32]0x20 }
}
$enumReader | Add-Member ScriptMethod GetSubKeyNames { Param($key) if ($this.Keys.ContainsKey($key)) { , $this.Keys[$key] } else { $null } }
$enumReader | Add-Member ScriptMethod ReadString { Param($key, $name) $this.Values["$key|$name"] }
$enumReader | Add-Member ScriptMethod ReadDword { Param($key, $name) $this.Values["$key|$name"] }
$devices = @(Get-OfflineManaDevice -Reader $enumReader -ControlSet 'ControlSet001')
Assert-Equal 'PCI\VEN_1414&DEV_00BA&SUBSYS_1&REV_00\5&a&0&0|0|,MANA_BUS\VEN_1414&ROLE_004C\6&b&0&1|32|Mana' (@($devices | ForEach-Object { "$($_.path)|$($_.configFlags)|$($_.service)" }) -join ',') 'Only the MANA VF and MANA_BUS children are collected, with a missing ConfigFlags read as 0.'
Write-Host "PASS: $($deviceCases.Count + 2) MANA device-instance cases and offline device enumeration."

# --- A SYSTEM reader that fails to close invalidates what it read ----------------------------------
$assessRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mana-win-dispose-" + [guid]::NewGuid().ToString('N'))
try {
    function Get-OfflineDriverPackage { Param($WindowsRoot, $InfPrefix) [pscustomobject]@{ repositoryFound = $true; packages = $(if ($InfPrefix -eq 'mana') { @($busPkg, $netPkg) } else { @() }) } }
    function Open-OfflineRegistryReader {
        Param($Path)
        $r = New-FakeHive @{ 'Select|Current' = [uint32]1; 'ControlSet001\Services\netvsc|Start' = [uint32]3; 'ControlSet001\Services\mana_bus|Start' = [uint32]3; 'ControlSet001\Services\Mana|Start' = [uint32]3 }
        if ($Path -like '*SYSTEM') { $r | Add-Member -Force ScriptMethod Dispose { throw 'ORCloseHive failed' } }
        return $r
    }
    function Resolve-ManaServiceBinaryPath { Param($WindowsRoot, $ServiceName, $ImagePath) $null }
    $result = Get-ManaOfflineAssessment -WindowsRoot $assessRoot
    Assert-True (-not $result.systemHiveRead) 'A reader that failed to close must not count as read.'
    Assert-Equal 'UNKNOWN' $result.verdict 'Facts from a reader that failed to close cannot make the installation READY.'
    Assert-True (@($result.unknowns) -contains 'system-hive-unreadable') 'The close failure is reported as an unknown.'
    Write-Host 'PASS: a SYSTEM reader close failure makes the assessment UNKNOWN.'
}
finally {
    Remove-Item Function:\Get-OfflineDriverPackage, Function:\Open-OfflineRegistryReader, Function:\Resolve-ManaServiceBinaryPath -ErrorAction SilentlyContinue
    . $helperPath
}

# --- Read-only contract against the script text ---------------------------------------------------
ForEach ($forbidden in 'reg(\.exe)?\s+(load|unload|add|delete|import|restore|save)', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Disk', 'bcdedit', 'Remove-Item') {
    Assert-True ($sourceText -notmatch $forbidden) "The detector must not contain a write primitive matching '$forbidden'."
    Assert-True ($helperText -notmatch $forbidden) "ManaReadiness.ps1 must not contain a write primitive matching '$forbidden'."
}
Assert-True ($sourceText -match 'Get-Windows-OsDrives-v3 -ReadOnly') 'Discovery must bring an offline disk online read-only.'
Assert-True ($sourceText -match '(?s)finally \{.*Restore-Disk-Partitions-v3') 'Disks must be returned to their attached state in a finally block.'
Assert-True ($helperText -match 'Open-OfflineRegistryReader') 'Hives must be read with the in-memory offreg reader.'
Assert-True ($sourceText -match '\[MANA-EVIDENCE-JSON\]') 'The detector must emit the shared MANA evidence marker.'
Assert-True ($sourceText -match "scenario\s*=\s*'mana-readiness'") 'The scenario must match linux-detect-mana-readiness.'
Assert-True ($sourceText -match '(?m)^\s*unknowns\s*=\s*\(\(\$unknowns') 'The evidence must carry top-level unknowns, as linux-detect-mana-readiness does.'
Assert-True ($helperText -match '(?s)\.Dispose\(\).*\.Dispose\(\)') 'Each reader must be disposed.'
Write-Host 'PASS: read-only contract (no hive mounts, registry writes or disk changes) and the evidence contract.'
