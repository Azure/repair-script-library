#########################################################################################################
#
# .SYNOPSIS
#   Validate or convert the running Windows source VM OS disk from MBR/BIOS to GPT/UEFI. v1.0.2
#
# .DESCRIPTION
#   Runs inside the healthy source VM. Report mode is the read-only default. Convert mode requires
#   explicit confirmation of a recoverable full VM backup, confirmation of Trusted Launch
#   prerequisites, and an exact conversion acknowledgement.
#
#   Invoke this run-id without --run-on-repair. After successful conversion, do not reboot the VM
#   while it is still Generation 1. Deallocate it and update it to Trusted Launch through Azure.
#
# .PARAMETER Mode
#   "Report" (default) validates eligibility and changes nothing. "Convert" runs MBR2GPT.
#
# .PARAMETER BackupConfirmed
#   "true" confirms a recoverable full VM backup exists. Required for Convert. Defaults to "false".
#
# .PARAMETER TrustedLaunchPrerequisitesConfirmed
#   "true" confirms the Trusted Launch prerequisites were reviewed. Required for Convert.
#   Defaults to "false".
#
# .PARAMETER ConversionAcknowledgement
#   Must equal CONVERT_TO_GEN2_TRUSTED_LAUNCH, exactly, for Convert.
#
# .EXAMPLE
#   az vm repair run -g MyRG -n MyWinVM --run-id win-convert-gen1-to-gen2 --verbose
#   Report mode. Read-only; returns GEN2_CONVERSION_APPLICABLE when the disk can be converted.
#
# .EXAMPLE
#   az vm repair run -g MyRG -n MyWinVM --run-id win-convert-gen1-to-gen2 --verbose --parameters Mode=Convert BackupConfirmed=true TrustedLaunchPrerequisitesConfirmed=true ConversionAcknowledgement=CONVERT_TO_GEN2_TRUSTED_LAUNCH
#   Convert mode. Irreversible in place; restore from the full VM backup to roll back.
#
# .NOTES
#   Output contract:
#     [GEN1-GEN2-RESULT]    One JSON line with the signature and message. Unchanged and authoritative.
#     [GEN1-GEN2-TELEMETRY] JSON lines for diagnostics only: runId, stage, elapsedMs, decisions, and
#                           every caught error. The runId is also the suffix of the log directory
#                           under ProgramData\VmRepair\Gen1ToGen2. Never contains credentials.
#   The final output is the repair-library status token. Run directly on the source VM.
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

$script:ScriptVersion = '1.0.2'
$script:RunId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Diagnostics only. Emitted through Log-Info/Log-Error so it reaches the same pipeline as every other
# message. Never call this from a function whose output is captured as a return value.
# Fail-safe: a telemetry failure must never stop the run, because that would drop the structured result,
# the status token, and the no-reboot guidance after an irreversible conversion.
function Write-ConversionTelemetry {
    Param(
        [Parameter(Mandatory = $true)][ValidateSet('Start', 'Decision', 'Operation', 'Result', 'Error')][string]$Event,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][hashtable]$Properties = @{}
    )

    try {
        $payload = [ordered]@{
            event         = $Event
            message       = $Message
            runId         = $script:RunId
            scriptVersion = $script:ScriptVersion
            mode          = $Mode
            elapsedMs     = $script:Stopwatch.ElapsedMilliseconds
            properties    = $Properties
        }
        $line = "[GEN1-GEN2-TELEMETRY] $($payload | ConvertTo-Json -Compress -Depth 5)"
        if ($Event -eq 'Error') { Log-Error $line } else { Log-Info $line }
    }
    catch {
        # Plain text only: the JSON path is what just failed.
        Log-Warning "[GEN1-GEN2-TELEMETRY] A '$Event' telemetry event could not be emitted. The conversion result is unaffected."
    }
}

function Write-ConversionCatchTelemetry {
    Param(
        [Parameter(Mandatory = $true)][string]$CatchName,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    try {
        Write-ConversionTelemetry -Event Error -Message "Catch block: $CatchName" -Properties @{
            catchName     = $CatchName
            stage         = $Stage
            exceptionType = $ErrorRecord.Exception.GetType().FullName
            error         = $ErrorRecord.Exception.Message
        }
    }
    catch {
        Log-Warning "[GEN1-GEN2-TELEMETRY] Error details for catch '$CatchName' could not be recorded. The conversion result is unaffected."
    }
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

function Get-DosDeviceTarget {
    Param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]:$')][string]$Name)

    if (-not ('VmRepairGen1ToGen2.NativeDosDevice' -as [type])) {
        Add-Type -Namespace VmRepairGen1ToGen2 -Name NativeDosDevice -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint QueryDosDeviceW(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -ErrorAction Stop
    }

    $buffer = New-Object System.Text.StringBuilder 1024
    $length = [VmRepairGen1ToGen2.NativeDosDevice]::QueryDosDeviceW($Name, $buffer, $buffer.Capacity)
    if ($length -eq 0) { return '' }
    return $buffer.ToString()
}

function Test-DriveLetterInUse {
    Param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]$')][string]$DriveLetter)

    if (-not [string]::IsNullOrWhiteSpace((Get-DosDeviceTarget -Name "$DriveLetter`:"))) { return $true }
    if (Test-Path -LiteralPath "$DriveLetter`:\") { return $true }
    if (Get-PSDrive -Name $DriveLetter -PSProvider FileSystem -ErrorAction SilentlyContinue) { return $true }
    if (Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Invoke-BcdStoreEnumeration {
    Param([Parameter(Mandatory = $true)][string]$BcdPath)

    $bcdEditPath = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not (Test-Path -LiteralPath $bcdEditPath -PathType Leaf)) {
        throw "bcdedit.exe was not found at '$bcdEditPath'."
    }

    $null = & $bcdEditPath /store $BcdPath /enum all 2>&1
    return $LASTEXITCODE
}

function Assert-EfiBcdStoreReadable {
    Param([Parameter(Mandatory = $true)][string]$BcdPath)

    if (-not (Test-Path -LiteralPath $BcdPath -PathType Leaf)) {
        throw "The EFI BCD store was not found at '$BcdPath'."
    }
    if ((Invoke-BcdStoreEnumeration -BcdPath $BcdPath) -ne 0) {
        throw "The EFI BCD store at '$BcdPath' could not be enumerated by bcdedit.exe."
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

    $driveLetter = @('Z', 'Y', 'X', 'W', 'V') | Where-Object { -not (Test-DriveLetterInUse -DriveLetter $_) } | Select-Object -First 1
    if (-not $driveLetter) {
        throw 'No temporary drive letter is available to verify the EFI BCD store.'
    }

    $mountRoot = "$driveLetter`:\"
    $assignmentAttempted = $false
    $verified = $false
    try {
        $assignmentAttempted = $true
        Add-EfiDriveLetter -DiskNumber $DiskNumber -PartitionNumber $esp[0].PartitionNumber -DriveLetter $driveLetter
        $bcdPath = Join-Path $mountRoot 'EFI\Microsoft\Boot\BCD'
        Assert-EfiBcdStoreReadable -BcdPath $bcdPath
        $verified = $true
    }
    finally {
        if ($assignmentAttempted) {
            try {
                Remove-EfiDriveLetter -DiskNumber $DiskNumber -PartitionNumber $esp[0].PartitionNumber -DriveLetter $driveLetter
            }
            catch {
                # After a successful verification a leftover drive letter must still fail the run. After a
                # failed verification, throwing here would replace the real cause, so record it and keep it.
                if ($verified) { throw }
                Write-ConversionCatchTelemetry -CatchName 'EfiCleanupAfterVerificationFailure' -Stage 'VerifyBootLayout' -ErrorRecord $_
            }
        }
    }
}

try {
    :workflow do {
        $stage = 'Initialize'
        Write-ConversionTelemetry -Event Start -Message 'Gen1 to Gen2 conversion script started' -Properties @{
            backupConfirmed                     = ($BackupConfirmed -eq 'true')
            trustedLaunchPrerequisitesConfirmed = ($TrustedLaunchPrerequisitesConfirmed -eq 'true')
            acknowledgementProvided             = (-not [string]::IsNullOrEmpty($ConversionAcknowledgement))
        }
        if (-not (Test-Administrator)) {
            throw 'This script must run elevated inside the source Windows VM.'
        }

        $stage = 'DetectSystemDisk'
        $disk = Get-SystemDisk
        $result.diskNumber = $disk.Number
        Write-ConversionTelemetry -Event Decision -Message 'System disk detected' -Properties @{
            diskNumber     = $disk.Number
            partitionStyle = [string]$disk.PartitionStyle
        }

        if ($disk.PartitionStyle -eq 'GPT') {
            $stage = 'AlreadyGptVerification'
            try {
                Test-ConvertedBootLayout -DiskNumber $disk.Number
            }
            catch {
                Write-ConversionCatchTelemetry -CatchName 'AlreadyGptVerification' -Stage $stage -ErrorRecord $_
                Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "OS disk $($disk.Number) is already GPT, but ESP/BCD verification failed: $($_.Exception.Message) Do not reboot or change the VM security type. Preserve the full VM backup and recover from it if required."
                break workflow
            }

            $firmwareType = [string](Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue).BiosFirmwareType
            Write-ConversionTelemetry -Event Decision -Message 'Disk is already GPT and its boot layout verified' -Properties @{ firmwareType = $firmwareType }
            if ($firmwareType -eq 'Bios') {
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

        $stage = 'CheckPartitionCount'
        $partitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)
        if ($partitions.Count -gt 3) {
            Write-ConversionTelemetry -Event Decision -Message 'Refused: too many MBR partitions' -Properties @{ partitionCount = $partitions.Count }
            Write-ConversionResult -Signature 'TOO_MANY_PRIMARY_PARTITIONS' -Message "OS disk $($disk.Number) has $($partitions.Count) partitions; MBR2GPT supports at most three MBR primary partitions."
            break workflow
        }

        $stage = 'CheckEncryption'
        Assert-OsVolumeNotEncrypted
        $logDirectory = Join-Path $env:ProgramData "VmRepair\Gen1ToGen2\$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($script:RunId)"
        $result.logPath = $logDirectory
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null

        $stage = 'Mbr2GptValidate'
        $operationTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $validation = Invoke-Mbr2Gpt -Operation validate -DiskNumber $disk.Number -Logs $logDirectory
        Write-ConversionTelemetry -Event Operation -Message 'MBR2GPT validate finished' -Properties @{
            exitCode   = $validation.ExitCode
            durationMs = $operationTimer.ElapsedMilliseconds
        }
        if ($validation.ExitCode -ne 0) {
            Write-ConversionResult -Signature 'UNSUPPORTED_CONFIGURATION' -Message "MBR2GPT validation failed with exit code $($validation.ExitCode). Review '$logDirectory'. No conversion was attempted."
            break workflow
        }

        if ($Mode -eq 'Report') {
            Write-ConversionResult -Signature 'GEN2_CONVERSION_APPLICABLE' -Message "OS disk $($disk.Number) passed MBR2GPT validation. Verify a full VM backup and Trusted Launch prerequisites before Convert mode."
            $status = $STATUS_SUCCESS
            break workflow
        }

        $stage = 'ConvertGuards'
        if ($BackupConfirmed -ne 'true') {
            throw 'Convert mode requires BackupConfirmed=true. There is no in-place Generation 1 rollback.'
        }
        if ($TrustedLaunchPrerequisitesConfirmed -ne 'true') {
            throw 'Convert mode requires TrustedLaunchPrerequisitesConfirmed=true.'
        }
        if ($ConversionAcknowledgement -cne 'CONVERT_TO_GEN2_TRUSTED_LAUNCH') {
            throw 'Convert mode requires ConversionAcknowledgement=CONVERT_TO_GEN2_TRUSTED_LAUNCH.'
        }

        $stage = 'Mbr2GptConvert'
        Write-ConversionTelemetry -Event Decision -Message 'All Convert gates passed; starting irreversible MBR2GPT conversion'
        $operationTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $conversion = Invoke-Mbr2Gpt -Operation convert -DiskNumber $disk.Number -Logs $logDirectory
        Write-ConversionTelemetry -Event Operation -Message 'MBR2GPT convert finished' -Properties @{
            exitCode   = $conversion.ExitCode
            durationMs = $operationTimer.ElapsedMilliseconds
        }
        if ($conversion.ExitCode -ne 0) {
            Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "MBR2GPT conversion returned exit code $($conversion.ExitCode). Do not reboot or change the VM security type. Preserve '$logDirectory' and recover from backup if required."
            break workflow
        }

        $stage = 'VerifyBootLayout'
        try {
            Test-ConvertedBootLayout -DiskNumber $disk.Number
        }
        catch {
            Write-ConversionCatchTelemetry -CatchName 'ConvertedBootLayoutVerification' -Stage $stage -ErrorRecord $_
            Write-ConversionResult -Signature 'CONVERSION_VERIFICATION_FAILED' -Message "MBR2GPT returned success, but GPT/ESP/BCD verification failed: $($_.Exception.Message) Do not reboot or change the VM security type."
            break workflow
        }

        Write-ConversionResult -Signature 'GEN2_CONVERSION_COMPLETED' -Message "OS disk $($disk.Number) is GPT with one EFI system partition and an EFI BCD store. Do not reboot. Deallocate the VM and update it to Trusted Launch."
        $status = $STATUS_SUCCESS
    } while ($false)
}
catch {
    Write-ConversionCatchTelemetry -CatchName 'WorkflowFailure' -Stage $stage -ErrorRecord $_
    if ([string]::IsNullOrWhiteSpace($result.message)) {
        Write-ConversionResult -Signature 'UNSUPPORTED_CONFIGURATION' -Message $_.Exception.Message
    }
    elseif (-not $resultEmitted) {
        Write-CurrentConversionResult
    }
    Log-Error $_.Exception.Message
}

Write-ConversionTelemetry -Event Result -Message 'Gen1 to Gen2 conversion script finished' -Properties @{
    signature  = $result.signature
    succeeded  = ($status -eq $STATUS_SUCCESS)
    diskNumber = $result.diskNumber
    stage      = $stage
    durationMs = $script:Stopwatch.ElapsedMilliseconds
}

return $status