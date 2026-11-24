#########################################################################################################
#
# .SYNOPSIS
#   Read-only check of whether a Windows OS disk is ready for MANA (Microsoft Azure Network Adapter) hosts. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. Reports whether the
#   guest has what it needs to keep networking when its host moves from Mellanox to MANA hardware:
#
#     - the synthetic network driver (netvsc), which carries traffic whenever no accelerated VF is
#       usable. If it is missing or disabled the VM has no network at all.
#     - a MANA driver package in the driver store, so Plug and Play can bind the MANA VF when it
#       appears, and no MANA service disabled in the active control set.
#
#   Makes NO changes to the attached OS disk. Hives are read with the Offline Registry Library
#   (offreg.dll) in memory: nothing is mounted under HKLM, no hive or log is written, and reg.exe is
#   never used. A disk that is offline is brought online read-only and returned to offline and writable
#   when the check ends, so a later repair script finds it exactly as attached. A disk that is offline
#   because its disk ID collides with the repair VM's own disk is left untouched and reported. A disk
#   that Windows had already onlined writable before this script ran is reported in riskIndicators,
#   not changed.
#
#   A missing MANA driver loses accelerated networking but, as long as netvsc is healthy, the VM still
#   reaches the network through the synthetic adapter. problems tells the two cases apart.
#
#   Emits one machine-readable JSON line prefixed with [MANA-EVIDENCE-JSON], with the same verdict
#   vocabulary as linux-detect-mana-readiness: READY, NOT_READY or UNKNOWN. A fact that could not be
#   established is reported as unknown, never as missing.
#
# .RESOLVES
#   Nothing. Detection only.
#
# .NOTES
#   Requires the --run-on-repair option. Driver service names are read from the AddService directives
#   of the MANA packages found in the driver store, not from a hard-coded list.
#
# .PARAMETER OsDriveLetter
#   [Optional] Restrict inspection to one drive letter (e.g. F). Default: inspect every Windows
#   installation found on attached data disks.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n problemVM --run-id win-detect-mana-readiness --run-on-repair --verbose
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][string]$OsDriveLetter = ''
)

# Initialize script
. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\Get-Disk-Partitions-v3.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\ManaReadiness.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = 'win-detect-mana-readiness'
$logFile = "$env:PUBLIC\Desktop\$scriptName.log"
$evidenceRoot = "$env:PUBLIC\Desktop\mana-evidence-$scriptStartTime"

$overallStatus = $STATUS_SUCCESS
$findings = @()

try {
    Log-Output "START: Running script $scriptName (read-only)" | Tee-Object -FilePath $logFile -Append
    New-Item -Path $evidenceRoot -ItemType Directory -Force | Out-Null
    Log-Output "Evidence directory: $evidenceRoot" | Tee-Object -FilePath $logFile -Append

    if ($OsDriveLetter) {
        $osDrives = @($OsDriveLetter.TrimEnd(':'))
    }
    else {
        $osDrives = @(Get-Windows-OsDrives-v3 -ReadOnly)
    }

    if ($osDrives.Count -eq 0) {
        $collided = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsOffline -and "$($_.OfflineReason)" -eq 'Collision' })
        if ($collided.Count) {
            throw "Disk $(($collided | ForEach-Object { $_.Number }) -join ', ') is offline because its disk ID matches another disk on this repair VM, so it cannot be read without rewriting its disk ID. Recreate the repair VM from a different image (az vm repair create chooses one to avoid this) and run the check again."
        }
        throw "No Windows installation found on any attached data disk. Confirm the source OS disk is attached with 'Get-Disk | Select Number,BusType,IsBoot,IsSystem,IsOffline,IsReadOnly'."
    }

    ForEach ($drive in $osDrives) {
        Log-Output "--- Inspecting ${drive}: ---" | Tee-Object -FilePath $logFile -Append
        $windowsRoot = "${drive}:\Windows"

        $diskReadOnly = $null
        $partition = Get-Partition -DriveLetter $drive -ErrorAction SilentlyContinue
        if ($partition) {
            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
            if ($disk) { $diskReadOnly = [bool]$disk.IsReadOnly }
        }

        $finding = [ordered]@{ osDrive = $drive; diskReadOnly = $diskReadOnly }
        $assessment = Get-ManaOfflineAssessment -WindowsRoot $windowsRoot
        ForEach ($key in $assessment.Keys) { $finding[$key] = $assessment[$key] }
        ForEach ($warning in $finding.readWarnings) {
            Log-Warning "${drive}: $warning" | Tee-Object -FilePath $logFile -Append
        }
        if ($finding.productName) {
            Log-Output "${drive}: $($finding.productName) build $($finding.currentBuild) $($finding.displayVersion)" | Tee-Object -FilePath $logFile -Append
        }
        ForEach ($pkg in $finding.manaPackages) {
            Log-Output "${drive}: MANA package $($pkg.package) DriverVer=$($pkg.driverVer) services=$($pkg.services -join ',')" | Tee-Object -FilePath $logFile -Append
        }

        if ($finding.verdict -eq 'READY') {
            Log-Output "${drive}: READY for MANA hosts." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "${drive}: $($finding.verdict). Problems: $($finding.problems -join '; '). Unknown: $($finding.unknowns -join '; ')" | Tee-Object -FilePath $logFile -Append
        }
        $findings += $finding
    }

    $verdict = Get-OverallVerdict -Verdicts @($findings | ForEach-Object { $_.verdict })
    $problems = @($findings | ForEach-Object { $_.problems } | Select-Object -Unique)
    $riskIndicators = @()
    if (@($findings | Where-Object { $_.diskReadOnly -eq $false }).Count) { $riskIndicators += 'disk-already-online-writable' }
    if (@($findings | Where-Object { @($_.mellanoxPackages).Count -and -not @($_.manaPackages).Count }).Count) { $riskIndicators += 'mellanox-driver-only' }

    $evidence = [ordered]@{
        schemaVersion  = '1.0'
        scenario       = 'mana-readiness'
        producedBy     = $scriptName
        producedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
        verdict        = $verdict
        problems       = (($problems | ForEach-Object { "$_;" }) -join '')
        riskIndicators = (($riskIndicators | ForEach-Object { "$_;" }) -join '')
        os             = [ordered]@{ family = 'windows' }
        guest          = $findings
        evidencePath   = $evidenceRoot
    }

    $json = $evidence | ConvertTo-Json -Depth 8 -Compress
    $json | Out-File -FilePath (Join-Path $evidenceRoot 'evidence.json') -Encoding Ascii
    Log-Output "[MANA-EVIDENCE-JSON]$json" | Tee-Object -FilePath $logFile -Append
    Log-Output "END: verdict $verdict. Evidence at $evidenceRoot" | Tee-Object -FilePath $logFile -Append
}
catch {
    $overallStatus = $STATUS_ERROR
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
}
finally {
    # Leave every disk exactly as attached, so a later repair script can bring it online writable.
    $notRestored = @(Restore-Disk-Partitions-v3)
    if ($notRestored.Count) {
        $overallStatus = $STATUS_ERROR
        Log-Error "Disk $($notRestored -join ', ') could not be returned to offline and writable. Before running a repair script, run diskpart: select disk <n>, offline disk, attributes disk clear readonly." | Tee-Object -FilePath $logFile -Append
    }
}

return $overallStatus
