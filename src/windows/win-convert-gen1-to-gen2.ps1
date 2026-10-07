#########################################################################################################
#
# .SYNOPSIS
#   Validate or convert the running Windows source VM OS disk from MBR/BIOS to GPT/UEFI. v1.0.0
#
# .DESCRIPTION
#   Runs inside the healthy source VM. Report mode is the read-only default. Convert mode requires
#   explicit confirmation of a recoverable full VM backup, confirmation of Trusted Launch
#   prerequisites, and an exact conversion acknowledgement.
#
#   Invoke this run-id without --run-on-repair. After successful conversion, do not reboot the VM
#   while it is still Generation 1. Deallocate it and update it to Trusted Launch through Azure.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('Report', 'Convert')][string]$Mode = 'Report',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$BackupConfirmed = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$TrustedLaunchPrerequisitesConfirmed = 'false',
    [Parameter(Mandatory = $false)][string]$ConversionAcknowledgement = ''
)

. .\src\windows\common\setup\init.ps1

$status = $STATUS_ERROR
$resultEmitted = $false
$result = [ordered]@{
    mode       = $Mode
    signature  = 'UNSUPPORTED_CONFIGURATION'
    diskNumber = $null
    logPath    = $null
    message    = ''
}

function Write-CurrentConversionResult {
    Log-Output "[GEN1-GEN2-RESULT] $($result | ConvertTo-Json -Compress)"
    $script:resultEmitted = $true
}

function Write-ConversionResult {
    Param(
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $result.signature = $Signature
    $result.message = $Message
    Write-CurrentConversionResult
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemDisk {
    $systemDrive = $env:SystemDrive.TrimEnd(':', '\')
    if ($systemDrive -notmatch '^[A-Za-z]$') {
        throw "SystemDrive '$env:SystemDrive' is not a valid Windows drive letter."
    }

    $partition = Get-Partition -DriveLetter $systemDrive -ErrorAction Stop
    return Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
}

function Assert-OsVolumeNotEncrypted {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw 'Get-BitLockerVolume is unavailable, so OS-volume encryption state cannot be verified.'
    }

    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($volume.VolumeStatus -ne 'FullyDecrypted' -or $volume.ProtectionStatus -ne 'Off') {
        Write-ConversionResult -Signature 'VOLUME_ENCRYPTED' -Message "The OS volume must be fully decrypted with protection off. VolumeStatus=$($volume.VolumeStatus); ProtectionStatus=$($volume.ProtectionStatus)."
        throw 'The OS volume is encrypted or BitLocker protection is active.'
    }
}

function Invoke-Mbr2Gpt {
    Param(
        [Parameter(Mandatory = $true)][ValidateSet('validate', 'convert')][string]$Operation,
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][string]$Logs
    )

    $mbr2gptPath = Join-Path $env:SystemRoot 'System32\MBR2GPT.exe'
    if (-not (Test-Path -LiteralPath $mbr2gptPath -PathType Leaf)) {
        $result.signature = 'MBR2GPT_UNAVAILABLE'
        $result.message = "MBR2GPT.exe was not found at '$mbr2gptPath'."
        throw 'MBR2GPT.exe is unavailable.'
    }

    $arguments = @("/$Operation", "/disk:$DiskNumber", '/allowFullOS', "/logs:$Logs")
    $output = & $mbr2gptPath @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output | Set-Content -LiteralPath (Join-Path $Logs "mbr2gpt-$Operation.console.log") -Encoding Utf8
    return [PSCustomObject]@{ ExitCode = $exitCode; Output = @($output) }
}

function Wait-DriveRootReady {
    Param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]$')][string]$DriveLetter,
        [Parameter(Mandatory = $false)][ValidateSet('Present', 'Absent')][string]$State = 'Present',
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 10
    )

    $mountRoot = "$DriveLetter`:\"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $exists = Test-Path -LiteralPath $mountRoot
        if (($State -eq 'Present' -and $exists) -or ($State -eq 'Absent' -and -not $exists)) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    }

    $exists = Test-Path -LiteralPath $mountRoot
    return ($State -eq 'Present' -and $exists) -or ($State -eq 'Absent' -and -not $exists)
}

function Add-EfiDriveLetter {
    Param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]$')][string]$DriveLetter
    )

    $diskpartScript = @"
select disk $DiskNumber
select partition $PartitionNumber
assign letter=$DriveLetter
exit
"@
    $output = $diskpartScript | diskpart.exe 2>&1
    $exitCode = $LASTEXITCODE
    if (-not (Wait-DriveRootReady -DriveLetter $DriveLetter)) {
        throw "Could not mount the EFI system partition at $DriveLetter`: (diskpart exit $exitCode): $(($output | Out-String).Trim())"
    }
}

function Remove-EfiDriveLetter {
    Param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]$')][string]$DriveLetter
    )

    $diskpartScript = @"
select disk $DiskNumber
select partition $PartitionNumber
remove letter=$DriveLetter
exit
"@
    $output = $diskpartScript | diskpart.exe 2>&1
    $exitCode = $LASTEXITCODE
    if (-not (Wait-DriveRootReady -DriveLetter $DriveLetter -State Absent)) {
        throw "Could not remove temporary EFI drive letter $DriveLetter`: (diskpart exit $exitCode): $(($output | Out-String).Trim())"
    }
}

function Test-ConvertedBootLayout {
    Param([Parameter(Mandatory = $true)][int]$DiskNumber)

    Update-HostStorageCache
    $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
    if ($disk.PartitionStyle -ne 'GPT') {
        throw "Disk $DiskNumber remains '$($disk.PartitionStyle)' instead of GPT."
    }

    $espGuid = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $esp = @(Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop | Where-Object {
        ([string]$_.GptType).Equals($espGuid, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($esp.Count -ne 1) {
        throw "Expected exactly one EFI system partition on disk $DiskNumber; found $($esp.Count)."
    }

    $usedDriveLetters = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter })
    $driveLetter = @('Z', 'Y', 'X', 'W', 'V') | Where-Object { $_ -notin $usedDriveLetters } | Select-Object -First 1
    if (-not $driveLetter) {
        throw 'No temporary drive letter is available to verify the EFI BCD store.'
    }

    $mountRoot = "$driveLetter`:\"
    $assignmentAttempted = $false
    try {
        $assignmentAttempted = $true
        Add-EfiDriveLetter -DiskNumber $DiskNumber -PartitionNumber $esp[0].PartitionNumber -DriveLetter $driveLetter
        $bcdPath = Join-Path $mountRoot 'EFI\Microsoft\Boot\BCD'
        if (-not (Test-Path -LiteralPath $bcdPath -PathType Leaf)) {
            throw "The EFI BCD store was not found at '$bcdPath'."
        }
    }
    finally {
        if ($assignmentAttempted) {
            Remove-EfiDriveLetter -DiskNumber $DiskNumber -PartitionNumber $esp[0].PartitionNumber -DriveLetter $driveLetter
        }
    }
}

try {
    :workflow do {
        if (-not (Test-Administrator)) {
            throw 'This script must run elevated inside the source Windows VM.'
        }

        $disk = Get-SystemDisk
        $result.diskNumber = $disk.Number

        if ($disk.PartitionStyle -eq 'GPT') {
            try {
                Test-ConvertedBootLayout -DiskNumber $disk.Number
            }
            catch {
                Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "OS disk $($disk.Number) is already GPT, but ESP/BCD verification failed: $($_.Exception.Message) Do not reboot or change the VM security type. Preserve the full VM backup and recover from it if required."
                break workflow
            }

            $firmwareType = [string](Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue).BiosFirmwareType
            if ($firmwareType -eq 'Legacy') {
                Write-ConversionResult -Signature 'NO_CHANGE_NEEDED' -Message "OS disk $($disk.Number) is already GPT with a verified EFI boot layout while the VM is using legacy BIOS firmware. Do not reboot. Deallocate the VM and update it to Trusted Launch."
            }
            else {
                Write-ConversionResult -Signature 'NO_CHANGE_NEEDED' -Message "OS disk $($disk.Number) is already GPT with one EFI system partition and an EFI BCD store. No conversion was attempted."
            }
            $status = $STATUS_SUCCESS
            break workflow
        }
        if ($disk.PartitionStyle -ne 'MBR') {
            throw "OS disk $($disk.Number) uses unsupported partition style '$($disk.PartitionStyle)'."
        }

        $partitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)
        if ($partitions.Count -gt 3) {
            Write-ConversionResult -Signature 'TOO_MANY_PRIMARY_PARTITIONS' -Message "OS disk $($disk.Number) has $($partitions.Count) partitions; MBR2GPT supports at most three MBR primary partitions."
            break workflow
        }

        Assert-OsVolumeNotEncrypted
        $logDirectory = Join-Path $env:ProgramData "VmRepair\Gen1ToGen2\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $result.logPath = $logDirectory
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null

        $validation = Invoke-Mbr2Gpt -Operation validate -DiskNumber $disk.Number -Logs $logDirectory
        if ($validation.ExitCode -ne 0) {
            Write-ConversionResult -Signature 'UNSUPPORTED_CONFIGURATION' -Message "MBR2GPT validation failed with exit code $($validation.ExitCode). Review '$logDirectory'. No conversion was attempted."
            break workflow
        }

        if ($Mode -eq 'Report') {
            Write-ConversionResult -Signature 'GEN2_CONVERSION_APPLICABLE' -Message "OS disk $($disk.Number) passed MBR2GPT validation. Verify a full VM backup and Trusted Launch prerequisites before Convert mode."
            $status = $STATUS_SUCCESS
            break workflow
        }

        if ($BackupConfirmed -ne 'true') {
            throw 'Convert mode requires BackupConfirmed=true. There is no in-place Generation 1 rollback.'
        }
        if ($TrustedLaunchPrerequisitesConfirmed -ne 'true') {
            throw 'Convert mode requires TrustedLaunchPrerequisitesConfirmed=true.'
        }
        if ($ConversionAcknowledgement -cne 'CONVERT_TO_GEN2_TRUSTED_LAUNCH') {
            throw 'Convert mode requires ConversionAcknowledgement=CONVERT_TO_GEN2_TRUSTED_LAUNCH.'
        }

        $conversion = Invoke-Mbr2Gpt -Operation convert -DiskNumber $disk.Number -Logs $logDirectory
        if ($conversion.ExitCode -ne 0) {
            Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "MBR2GPT conversion returned exit code $($conversion.ExitCode). Do not reboot or change the VM security type. Preserve '$logDirectory' and recover from backup if required."
            break workflow
        }

        try {
            Test-ConvertedBootLayout -DiskNumber $disk.Number
        }
        catch {
            Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "MBR2GPT returned success, but GPT/ESP/BCD verification failed: $($_.Exception.Message) Do not reboot or change the VM security type."
            break workflow
        }

        Write-ConversionResult -Signature 'GEN2_CONVERSION_COMPLETED' -Message "OS disk $($disk.Number) is GPT with one EFI system partition and an EFI BCD store. Do not reboot. Deallocate the VM and update it to Trusted Launch."
        $status = $STATUS_SUCCESS
    } while ($false)
}
catch {
    if ([string]::IsNullOrWhiteSpace($result.message)) {
        Write-ConversionResult -Signature 'UNSUPPORTED_CONFIGURATION' -Message $_.Exception.Message
    }
    elseif (-not $resultEmitted) {
        Write-CurrentConversionResult
    }
    Log-Error $_.Exception.Message
}

return $status