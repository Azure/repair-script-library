#########################################################################################################
#
# .SYNOPSIS
#   Read-only detection for SCSI-to-NVMe disk controller migration boot failures. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. Reports whether the
#   guest is ready to boot from an NVMe disk controller, and collects an evidence bundle. Makes NO
#   changes to the attached OS disk: the SYSTEM hive is mounted, read, and unmounted.
#
#   Emits one machine-readable JSON line prefixed with [NVME-EVIDENCE-JSON] so a caller (diagnostics,
#   SelfHelp, or a test harness) can extract structured evidence from the free-text run-command output.
#
# .RESOLVES
#   Nothing. Detection only. Use the results to decide whether an NVMe boot-driver repair is warranted.
#
# .NOTES
#   Requires the --run-on-repair option: the source VM's OS disk must be attached to a repair VM as a
#   data disk. Uses Get-Disk-Partitions-v3, which locates attached disks by BusType and therefore works
#   on both SCSI and NVMe repair VMs.
#
# .PARAMETER OsDriveLetter
#   [Optional] Restrict inspection to one drive letter (e.g. F). Default: inspect every Windows
#   installation found on attached data disks.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n problemVM --run-id win-detect-nvme-readiness --run-on-repair --verbose
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n problemVM --run-id win-detect-nvme-readiness --run-on-repair --parameters OsDriveLetter=F
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][string]$OsDriveLetter = ''
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v3.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = 'win-detect-nvme-readiness'
$logFile = "$env:PUBLIC\Desktop\$scriptName.log"
$evidenceRoot = "$env:PUBLIC\Desktop\nvme-evidence-$scriptStartTime"
$hiveMountName = 'NVMEDETECT'

# NVMe controllers present themselves as PCI class 01 / subclass 08 (NVM) / prog-if 02 (NVMe I/O).
$CddbKeys = @('pci#cc_010802', 'pci#cc_0108')

Log-Output "START: Running script $scriptName (read-only)" | Tee-Object -FilePath $logFile -Append

function Dismount-RegistryHive {
    # A reg unload issued straight after a registry read fails with "Access is denied": the PowerShell
    # provider still holds keys open. The hive then stays mounted and locks the attached disk for every
    # later run, which is worse than the fault being diagnosed. Collect, retry, and report on failure.
    Param(
        [string]$MountName,
        [int]$MaxAttempts = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if (-not (Test-Path -LiteralPath "HKLM:\$MountName")) { return }
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 500
        & reg.exe unload "HKLM\$MountName" *>$null
    }

    if (Test-Path -LiteralPath "HKLM:\$MountName") {
        Log-Error "Failed to unload registry hive HKLM\$MountName after $MaxAttempts attempts. The attached disk may stay locked for subsequent runs. Unload it manually with: reg unload HKLM\$MountName" | Tee-Object -FilePath $logFile -Append
    }
}

$findings = @()
$overallStatus = $STATUS_SUCCESS

try {
    New-Item -Path $evidenceRoot -ItemType Directory -Force | Out-Null
    Log-Output "Evidence directory: $evidenceRoot" | Tee-Object -FilePath $logFile -Append

    # Bus type of the attached disks is itself evidence: it tells us how this repair VM was created.
    $attachedDisks = Get-Disk -ErrorAction SilentlyContinue | Where-Object { -not $_.IsBoot -and -not $_.IsSystem }
    $attachedBusTypes = @($attachedDisks | Select-Object -ExpandProperty BusType -Unique | ForEach-Object { $_.ToString() })
    Log-Output "Attached data disk bus types: $($attachedBusTypes -join ', ')" | Tee-Object -FilePath $logFile -Append

    Get-Disk | Format-List * | Out-File -FilePath (Join-Path $evidenceRoot 'get-disk.txt') -Encoding Ascii
    Get-Partition | Format-List * | Out-File -FilePath (Join-Path $evidenceRoot 'get-partition.txt') -Encoding Ascii

    if ($OsDriveLetter) {
        $osDrives = @($OsDriveLetter.TrimEnd(':'))
    }
    else {
        $osDrives = Get-Windows-OsDrives-v3
    }

    if (-not $osDrives -or $osDrives.Count -eq 0) {
        Log-Error "No Windows installation found on any attached data disk. Confirm the source OS disk is attached with 'Get-Disk | Select Number,BusType,IsBoot,IsSystem'." | Tee-Object -FilePath $logFile -Append
        throw "No attached Windows OS disk found."
    }

    ForEach ($drive in $osDrives) {
        Log-Output "--- Inspecting ${drive}: ---" | Tee-Object -FilePath $logFile -Append

        $systemHivePath = "${drive}:\Windows\System32\config\SYSTEM"
        $driverPath = "${drive}:\Windows\System32\drivers\stornvme.sys"

        $finding = [ordered]@{
            osDrive               = $drive
            systemHiveFound       = (Test-Path -LiteralPath $systemHivePath)
            stornvmeDriverPresent = (Test-Path -LiteralPath $driverPath)
            controlSet            = $null
            stornvmeStart         = $null
            stornvmeType          = $null
            stornvmeErrorControl  = $null
            stornvmeGroup         = $null
            stornvmeImagePath     = $null
            storahciStart         = $null
            cddbNvmeEntries       = @()
            bootReadyForNvme      = $false
            problems              = @()
        }

        if (-not $finding.systemHiveFound) {
            $finding.problems += 'SYSTEM hive not found'
            $findings += $finding
            continue
        }
        if (-not $finding.stornvmeDriverPresent) {
            # Without the driver binary, enabling the service would produce an unbootable configuration.
            $finding.problems += 'stornvme.sys missing from System32\drivers'
        }

        Dismount-RegistryHive -MountName $hiveMountName
        & reg.exe load "HKLM\$hiveMountName" "$systemHivePath" *>$null
        if ($LASTEXITCODE -ne 0) {
            $finding.problems += "Failed to load SYSTEM hive (reg load exit $LASTEXITCODE)"
            $findings += $finding
            continue
        }

        try {
            $current = (Get-ItemProperty -Path "HKLM:\$hiveMountName\Select" -Name Current -ErrorAction Stop).Current
            $controlSet = 'ControlSet{0:D3}' -f $current
            $finding.controlSet = $controlSet
            Log-Output "Active control set: $controlSet" | Tee-Object -FilePath $logFile -Append

            $stornvmeKey = "HKLM:\$hiveMountName\$controlSet\Services\stornvme"
            if (Test-Path -LiteralPath $stornvmeKey) {
                $svc = Get-ItemProperty -Path $stornvmeKey -ErrorAction SilentlyContinue
                $finding.stornvmeStart = $svc.Start
                $finding.stornvmeType = $svc.Type
                $finding.stornvmeErrorControl = $svc.ErrorControl
                $finding.stornvmeGroup = $svc.Group
                $finding.stornvmeImagePath = $svc.ImagePath

                # 0 = SERVICE_BOOT_START. Anything else means the driver is not on the boot path.
                if ($svc.Start -ne 0) {
                    $finding.problems += "stornvme Start=$($svc.Start) (expected 0 = boot-start)"
                }
            }
            else {
                $finding.problems += 'stornvme service key missing'
            }

            $storahciKey = "HKLM:\$hiveMountName\$controlSet\Services\storahci"
            if (Test-Path -LiteralPath $storahciKey) {
                $finding.storahciStart = (Get-ItemProperty -Path $storahciKey -ErrorAction SilentlyContinue).Start
            }

            ForEach ($cddb in $CddbKeys) {
                $cddbPath = "HKLM:\$hiveMountName\$controlSet\Control\CriticalDeviceDatabase\$cddb"
                if (Test-Path -LiteralPath $cddbPath) {
                    $entry = Get-ItemProperty -Path $cddbPath -ErrorAction SilentlyContinue
                    $finding.cddbNvmeEntries += [ordered]@{ key = $cddb; service = $entry.Service; classGuid = $entry.ClassGUID }
                }
            }
            if ($finding.cddbNvmeEntries.Count -eq 0) {
                $finding.problems += 'No NVMe CriticalDeviceDatabase entries'
            }

            $finding.bootReadyForNvme = ($finding.stornvmeStart -eq 0) -and $finding.stornvmeDriverPresent

            # Preserve the exact pre-change state so any later repair can be audited against it.
            & reg.exe export "HKLM\$hiveMountName\$controlSet\Services\stornvme" (Join-Path $evidenceRoot "$drive-stornvme.reg") /y *>$null
            & reg.exe export "HKLM\$hiveMountName\$controlSet\Control\CriticalDeviceDatabase" (Join-Path $evidenceRoot "$drive-cddb.reg") /y *>$null
            & reg.exe export "HKLM\$hiveMountName\Select" (Join-Path $evidenceRoot "$drive-select.reg") /y *>$null
        }
        finally {
            Dismount-RegistryHive -MountName $hiveMountName
        }

        if ($finding.bootReadyForNvme) {
            Log-Output "${drive}: appears READY to boot on NVMe (stornvme Start=0, driver present)." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "${drive}: NOT ready to boot on NVMe. Problems: $($finding.problems -join '; ')" | Tee-Object -FilePath $logFile -Append
        }

        $findings += $finding
    }

    $anyNotReady = @($findings | Where-Object { -not $_.bootReadyForNvme }).Count -gt 0

    # Guest evidence alone is not enough to declare the scenario: the caller must combine it with the
    # control-plane fact that the VM is actually on (or moving to) the NVMe controller.
    $confidence = 'low'
    if ($anyNotReady -and ($attachedBusTypes -contains 'NVMe')) { $confidence = 'high' }
    elseif ($anyNotReady) { $confidence = 'medium' }

    $evidence = [ordered]@{
        schemaVersion    = '1.0'
        scenario         = 'scsi-to-nvme-migration'
        producedBy       = $scriptName
        producedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
        confidence       = $confidence
        os               = [ordered]@{ family = 'windows' }
        repairVm         = [ordered]@{ attachedDiskBusTypes = $attachedBusTypes }
        controlPlane     = $null   # filled in by the caller; not visible from inside the guest
        guest            = $findings
        evidencePath     = $evidenceRoot
    }

    $json = $evidence | ConvertTo-Json -Depth 8 -Compress
    $json | Out-File -FilePath (Join-Path $evidenceRoot 'evidence.json') -Encoding Ascii
    Log-Output "[NVME-EVIDENCE-JSON]$json" | Tee-Object -FilePath $logFile -Append

    Log-Output "END: Detection complete. Evidence at $evidenceRoot" | Tee-Object -FilePath $logFile -Append
}
catch {
    $overallStatus = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    Dismount-RegistryHive -MountName $hiveMountName
}

return $overallStatus
