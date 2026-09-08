#########################################################################################################
#
# .SYNOPSIS
#   NVMe-aware disk discovery for attached OS disks. v3.0.0
#
# .DESCRIPTION
#   Returns the partitions of every OS/data disk attached to this repair VM, bringing each disk online
#   and read-write first. Selects disks by BusType, so it works whether the repair VM was created with
#   the SCSI or the NVMe disk controller.
#
#   Get-Disk-Partitions.ps1 (v1) and Get-Disk-Partitions-v2.ps1 select with:
#       get-wmiobject Win32_diskdrive | Where-Object {$_.model -like 'Microsoft Virtual Disk'}
#   That model string is only reported for disks attached through the SCSI controller. When the repair VM
#   runs on a size that uses the NVMe disk controller, the copied OS disk is enumerated as an NVMe
#   namespace, the filter matches nothing, $partitionlist comes back empty, and the calling script
#   completes without repairing anything while still returning [STATUS]::SUCCESS.
#
#   This helper also excludes the Azure resource (temporary) disk, which v1/v2 do not.
#
# .NOTES
#   Additive. v1 and v2 are intentionally left untouched: ten production scripts depend on them,
#   including the CrowdStrike bootloop scripts referenced by support runbooks. Callers are migrated to v3
#   one at a time, each with its own verification on both a SCSI and an NVMe repair VM.
#
#   Requires init.ps1 to have been dot-sourced first (for the Log-* functions), which is the standard
#   pattern for every script in this repo. A no-op fallback is defined if it was not, so the helper can
#   be dot-sourced standalone for testing.
#
#   Logger.ps1's Log-* functions write to the success stream. Both functions here return data, so a
#   direct Log-* call would make every log line part of the returned collection - a caller iterating
#   Get-Windows-OsDrives-v3 would treat '[Info ...]found Windows installation on F:' as a drive letter.
#   All logging therefore goes through Write-V3Log, which sends the formatted line to the host instead.
#
# .EXAMPLE
#   . .\src\windows\common\setup\init.ps1
#   . .\src\windows\common\helpers\Get-Disk-Partitions-v3.ps1
#
#   $partitionlist = Get-Disk-Partitions-v3
#   $fixedDrives   = ($partitionlist | Group-Object DiskNumber).Group | Select-Object -ExpandProperty DriveLetter
#
#   # Or, when only Windows installations are of interest:
#   $osDrives = Get-Windows-OsDrives-v3
#
#########################################################################################################

# Volume label Azure gives the ephemeral resource disk; never a repair target.
# Global rather than script-scoped: $script: binds to the scope of whatever script is running when the
# function is called, not to this file, so a dot-source into a child scope would leave it unresolved.
$global:AzureTempDiskLabel = 'Temporary Storage'

# Allows the helper to be dot-sourced on its own (e.g. Pester) without init.ps1. The shims write to the
# verbose and warning streams, so standalone runs need -Verbose to see Log-Info output.
# Defined via the function: drive so the repo's Log-* naming convention does not trip PSScriptAnalyzer here.
if (-not (Get-Command -Name 'Log-Info' -ErrorAction SilentlyContinue)) {
    Set-Item -Path 'function:global:Log-Info' -Value { Param([PSObject[]]$message) Write-Verbose "$message" }
}
if (-not (Get-Command -Name 'Log-Warning' -ErrorAction SilentlyContinue)) {
    Set-Item -Path 'function:global:Log-Warning' -Value { Param([PSObject[]]$message) Write-Warning "$message" }
}

function Write-V3Log {
    <#
      Log-* write to the success stream, so calling them directly from a function that returns data
      would append the log lines to that return value. Emitting to the host keeps the pipeline clean
      while preserving Logger.ps1's exact format. The standalone shims above return nothing, so under
      Pester the line goes to the verbose or warning stream instead and nothing is printed here.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][ValidateSet('Info', 'Warning')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $formatted = if ($Level -eq 'Warning') { Log-Warning $Message } else { Log-Info $Message }
    if ($formatted) { Write-Host ($formatted -join [Environment]::NewLine) }
}

function Get-Disk-Partitions-v3 {
    <#
      Returns Get-Partition objects for every non-boot, non-system, non-resource disk attached to this VM.
      Return shape matches Get-Disk-Partitions, so callers can be migrated without changing how they
      consume the result.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Any', 'SCSI', 'NVMe')]
        [string]$BusTypeFilter = 'Any',

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 300)]
        [int]$DriveLetterTimeoutSeconds = 60
    )

    $busTypes = switch ($BusTypeFilter) {
        'SCSI' { @('SCSI', 'SAS', 'RAID') }
        'NVMe' { @('NVMe') }
        default { @('SCSI', 'SAS', 'RAID', 'NVMe') }
    }

    $partitionList = @()

    # IsBoot and IsSystem both report $false while a disk is offline, so an offline attached OS disk is
    # correctly kept here while the repair VM's own live disk is excluded.
    $disks = Get-Disk -ErrorAction Stop | Where-Object {
        $busTypes -contains $_.BusType -and -not $_.IsBoot -and -not $_.IsSystem
    }

    if (-not $disks) {
        Write-V3Log -Level Warning -Message "Get-Disk-Partitions-v3: no attached data disks found for BusType filter '$BusTypeFilter'. Run 'Get-Disk | Select Number,BusType,IsBoot,IsSystem' to confirm what this VM can see."
        return $partitionList
    }

    ForEach ($disk in $disks) {
        Write-V3Log -Level Info -Message "Get-Disk-Partitions-v3: evaluating disk $($disk.Number) (BusType=$($disk.BusType), Model='$($disk.Model)', Offline=$($disk.IsOffline))"

        $wasOffline = [bool]$disk.IsOffline

        if ($disk.IsOffline) {
            $disk | Set-Disk -IsOffline $false -ErrorAction SilentlyContinue
        }
        if ($disk.IsReadOnly) {
            $disk | Set-Disk -IsReadOnly $false -ErrorAction SilentlyContinue
        }

        # Read the state back. Without this a disk that stayed offline is skipped further down as
        # "exposes no partitions", which is the silent-success failure this helper exists to remove.
        $diskState = Get-Disk -Number $disk.Number -ErrorAction SilentlyContinue
        if (-not $diskState) {
            Write-V3Log -Level Warning -Message "Get-Disk-Partitions-v3: disk $($disk.Number) could not be re-read after being brought online, skipping."
            continue
        }
        if ($diskState.IsOffline -or $diskState.IsReadOnly) {
            Write-V3Log -Level Warning -Message "Get-Disk-Partitions-v3: disk $($disk.Number) is still Offline=$($diskState.IsOffline) ReadOnly=$($diskState.IsReadOnly) after Set-Disk, so it cannot be repaired. Skipping."
            continue
        }

        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue

        # Windows assigns drive letters asynchronously after a disk is brought online, so a disk that
        # was offline on entry returns partitions with no letters for the first few seconds. Callers key
        # off DriveLetter, so returning too early looks identical to an empty disk - the silent success
        # this helper exists to remove. Only wait when this call did the onlining.
        if ($wasOffline) {
            $deadline = (Get-Date).AddSeconds($DriveLetterTimeoutSeconds)
            while ((Get-Date) -lt $deadline -and -not (@($partitions | Where-Object { $_.DriveLetter }).Count)) {
                Start-Sleep -Seconds 2
                $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
            }
            if (-not (@($partitions | Where-Object { $_.DriveLetter }).Count)) {
                Write-V3Log -Level Warning -Message "Get-Disk-Partitions-v3: disk $($disk.Number) came online but no partition was assigned a drive letter within $DriveLetterTimeoutSeconds seconds. Partitions are still returned, but callers that need a path will find none."
            }
        }

        if (-not $partitions) {
            Write-V3Log -Level Info -Message "Get-Disk-Partitions-v3: disk $($disk.Number) exposes no partitions, skipping."
            continue
        }

        # The Azure resource disk is attached like any other data disk; excluding it stops scripts
        # treating ephemeral scratch space as a repair target. The label alone is not enough: a broken
        # OS disk may carry a data partition with the same label, so the disk must also look like the
        # resource disk - always SCSI-attached, and a single volume.
        $labelledTemp = @($partitions | ForEach-Object {
                Get-Volume -Partition $_ -ErrorAction SilentlyContinue
            } | Where-Object { $_ -and $_.FileSystemLabel -eq $global:AzureTempDiskLabel })

        if ($labelledTemp.Count -gt 0) {
            if ($diskState.BusType -eq 'SCSI' -and $partitions.Count -eq 1) {
                Write-V3Log -Level Info -Message "Get-Disk-Partitions-v3: disk $($disk.Number) is the Azure resource disk, skipping."
                continue
            }

            Write-V3Log -Level Warning -Message "Get-Disk-Partitions-v3: disk $($disk.Number) has a volume labelled '$($global:AzureTempDiskLabel)' but is BusType=$($diskState.BusType) with $($partitions.Count) partition(s), so it is not the resource disk and is being treated as a repair target."
        }

        $partitionList += $partitions
    }

    return $partitionList
}

function Get-Windows-OsDrives-v3 {
    <#
      Narrows Get-Disk-Partitions-v3 to partitions that contain a Windows installation, i.e. those with
      \Windows\System32\config\SYSTEM. Returns drive letters (e.g. 'F').

      More than one hit is legitimate (multi-boot, restored images). Callers that modify the guest must
      refuse to guess rather than picking the first result.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Any', 'SCSI', 'NVMe')]
        [string]$BusTypeFilter = 'Any',

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 300)]
        [int]$DriveLetterTimeoutSeconds = 60
    )

    $osDrives = @()

    ForEach ($partition in (Get-Disk-Partitions-v3 -BusTypeFilter $BusTypeFilter -DriveLetterTimeoutSeconds $DriveLetterTimeoutSeconds)) {
        if ([string]::IsNullOrWhiteSpace($partition.DriveLetter)) { continue }
        if ($partition.DriveLetter -eq "`0") { continue }

        $driveLetter = $partition.DriveLetter.ToString()

        # Composed as a string rather than with Join-Path: a temporary letter can be unmounted between
        # enumeration and use, and Join-Path throws DriveNotFoundException when the drive is gone.
        $systemHive = "${driveLetter}:\Windows\System32\config\SYSTEM"

        if (Test-Path -LiteralPath $systemHive) {
            Write-V3Log -Level Info -Message "Get-Windows-OsDrives-v3: found Windows installation on ${driveLetter}:"
            $osDrives += $driveLetter
        }
    }

    return $osDrives
}
