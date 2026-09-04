<#
.SYNOPSIS
    Helper functions that locate and prepare the offline Windows installation on a
    broken OS disk attached to a rescue VM.

.DESCRIPTION
    'az vm repair create' attaches the broken OS disk to a rescue VM as a data disk.
    Before any offline repair can run, the disk must be brought online, every partition
    that matters must be reachable through a drive letter, and the correct Windows
    installation must be selected when the disk carries more than one.

    This helper does all of that. Unlike Get-Disk-Partitions.ps1 it also assigns
    temporary drive letters to partitions that have none (EFI System and Recovery
    partitions), which offline boot repairs need.

    Exposed functions:
      Get-OfflineWindowsDisk        Main entry point. Returns the resolved offline install.
      Set-OfflineDisksOnline        Bring attached virtual data disks online and writable.
      Add-PartitionDriveLetter      Assign a free drive letter to a partition via diskpart.
      Get-FreeDriveLetter           Return the next unused drive letter.
      Stop-NestedRepairVm           Stop a nested Hyper-V repair VM holding the disk.

    Get-OfflineWindowsDisk sets $script:OfflineWindowsDrive, which the offline registry
    hive helper (Use-OfflineRegistryHive.ps1) uses as its default Windows path.

.NOTES
    Name:   Get-OfflineWindowsDisk.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    These functions return values, so they buffer their messages with Add-OfflineRepairLog
    instead of calling Log-* directly. Call Write-OfflineRepairLog at script level to flush.
    The rescue VM's own system disk is always excluded from the search.

.VERSION
    v1.0: Initial version.
#>

if (-not (Get-Command Add-OfflineRepairLog -ErrorAction SilentlyContinue)) {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
}

# QueryDosDevice reads the NT object namespace, which is the only place a drive letter
# that diskpart assigned to a hidden EFI System or Recovery partition can be observed.
# mountvol and Get-Partition both report the mount manager database instead, and neither
# lists those letters, so without this the helper cannot tell that a partition already
# has one and hands out a new letter on every run until the alphabet is exhausted.
if (-not ('RslOffline.NativeDosDevice' -as [type])) {
    try {
        Add-Type -Namespace RslOffline -Name NativeDosDevice -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint QueryDosDeviceW(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -ErrorAction Stop
    }
    catch {
        # Falls back to the mountvol lookup, which is weaker but needs no compiler.
        Add-OfflineRepairLog -Level Info -Message "QueryDosDevice is unavailable, so drive letter reuse falls back to mountvol: $($_.Exception.Message)"
    }
}

function Get-DosDeviceTarget {
    <#
    .SYNOPSIS
        Returns the device a DOS device name points at, or an empty string.

    .PARAMETER Name
        A DOS device name without the \\?\ prefix, such as 'K:' or 'Volume{guid}'.

    .OUTPUTS
        A device name such as \Device\HarddiskVolume5, or '' when the name is undefined.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not ('RslOffline.NativeDosDevice' -as [type])) { return '' }

    $buffer = New-Object System.Text.StringBuilder 1024
    $length = [RslOffline.NativeDosDevice]::QueryDosDeviceW($Name, $buffer, $buffer.Capacity)
    if ($length -eq 0) { return '' }

    return $buffer.ToString()
}

function Test-DriveLetterInUse {
    <#
    .SYNOPSIS
        Returns $true when a drive letter is already taken.

    .DESCRIPTION
        Get-Volume and Get-Partition do not report drive letters that were assigned to
        hidden System or Recovery partitions, so the object namespace is consulted and
        the root path is probed directly as well. A letter that is defined but not
        reachable still counts as taken, because assigning over it would fail.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DriveLetter
    )

    $letter = $DriveLetter.TrimEnd(':', '\')
    if (-not [string]::IsNullOrWhiteSpace((Get-DosDeviceTarget -Name "${letter}:"))) { return $true }
    if (Test-OfflinePath "${letter}:\") { return $true }
    if (Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction SilentlyContinue) { return $true }
    if (Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Get-FreeDriveLetter {
    <#
    .SYNOPSIS
        Returns the next unused drive letter, searching from Z: downwards.
    #>
    param(
        [Parameter(Mandatory = $false)][string[]]$Exclude = @()
    )

    $excluded = @($Exclude | ForEach-Object { $_.TrimEnd(':', '\').ToUpperInvariant() })

    # Z down to E. A-D are reserved for the rescue VM's own system and temporary disks.
    foreach ($letter in ([char[]](90..69))) {
        if ($excluded -contains "$letter") { continue }
        if (-not (Test-DriveLetterInUse -DriveLetter "$letter")) { return "$letter" }
    }

    throw 'No free drive letter is available on the rescue VM. Remove unused mount points with "mountvol <letter>: /d" and run the script again.'
}

function Get-VolumeDriveLetterMap {
    <#
    .SYNOPSIS
        Maps each volume GUID path to the drive letters currently mounted on it.

    .DESCRIPTION
        Fallback used only when QueryDosDevice is unavailable. mountvol reports the
        mount manager database, which does not contain letters that diskpart created
        directly in the object namespace, so this is the weaker of the two sources.

    .OUTPUTS
        Hashtable keyed by volume GUID path (no trailing backslash) whose values are
        drive letter arrays in the form 'K:'.
    #>
    $map = @{}
    $currentVolume = $null

    foreach ($line in @(mountvol.exe 2>$null)) {
        $text = "$line".Trim()

        if ($text -match '^\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\?$') {
            $currentVolume = $text.TrimEnd('\')
            if (-not $map.ContainsKey($currentVolume)) { $map[$currentVolume] = @() }
            continue
        }

        if (-not $currentVolume) { continue }
        if ($text -match '^([A-Za-z]):\\?$') { $map[$currentVolume] += "$($Matches[1].ToUpperInvariant()):" }
    }

    return $map
}

function Get-DriveLetterDeviceMap {
    <#
    .SYNOPSIS
        Maps every defined drive letter to the device it points at.

    .OUTPUTS
        Hashtable keyed by drive letter in the form 'K:' whose values are device
        names such as \Device\HarddiskVolume5.
    #>
    $map = @{}

    foreach ($letter in ([char[]](67..90))) {
        $target = Get-DosDeviceTarget -Name "${letter}:"
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        $map["${letter}:"] = $target
    }

    return $map
}

function Get-PartitionExistingRoot {
    <#
    .SYNOPSIS
        Returns the drive letters already usable for a partition, or an empty array.

    .DESCRIPTION
        Reported access paths are confirmed before they are trusted, because a
        partition can advertise a letter whose drive is no longer mounted.

        Hidden EFI System and Recovery partitions never report a drive letter at all,
        so the partition's volume device is resolved instead and matched against the
        device every defined drive letter points at. That recovers a letter assigned
        by an earlier run, which is what stops each run from leaking two more letters
        until the alphabet is exhausted.
    #>
    param(
        [Parameter(Mandatory = $true)]$Partition,
        [Parameter(Mandatory = $false)][hashtable]$LetterDeviceMap = @{},
        [Parameter(Mandatory = $false)][hashtable]$VolumeMap = @{}
    )

    $existing = @($Partition.AccessPaths |
        Where-Object { $_ -and $_ -match '^[A-Za-z]:' } |
        ForEach-Object { $_.TrimEnd('\').ToUpperInvariant() } |
        Where-Object { Test-OfflinePath "$_\" })

    if ($existing.Count -gt 0) { return @($existing | Select-Object -Unique) }

    $volumePaths = @($Partition.AccessPaths | Where-Object { $_ -and $_ -match '^\\\\\?\\Volume\{' })

    # Preferred source: the object namespace, which holds letters mountvol cannot see.
    foreach ($volumePath in $volumePaths) {
        $device = Get-DosDeviceTarget -Name (($volumePath.TrimEnd('\')) -replace '^\\\\\?\\', '')
        if ([string]::IsNullOrWhiteSpace($device)) { continue }

        # Sorted so repeated runs settle on the same letter for the same partition.
        foreach ($letter in @($LetterDeviceMap.Keys | Sort-Object)) {
            if ($LetterDeviceMap[$letter] -ne $device) { continue }
            if (-not (Test-OfflinePath "$letter\")) { continue }
            return @($letter)
        }
    }

    foreach ($volumePath in $volumePaths) {
        $key = $volumePath.TrimEnd('\')
        if (-not $VolumeMap.ContainsKey($key)) { continue }

        # All letters on one volume address the same file system, so the first
        # usable one is enough and keeps later path building deterministic.
        $recovered = @($VolumeMap[$key] | Where-Object { Test-OfflinePath "$_\" } | Select-Object -First 1)
        if ($recovered.Count -gt 0) { return @($recovered) }
    }

    return @()
}

function Stop-NestedRepairVm {
    <#
    .SYNOPSIS
        Stops a running nested Hyper-V VM so its VHD can be mounted offline.

    .DESCRIPTION
        Only relevant when the repair VM was created with 'az vm repair create --enable-nested'.
        Returns the names of the VMs that were stopped. Silently does nothing when the
        Hyper-V role is not installed.
    #>
    $stopped = @()

    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $stopped }

    try {
        $running = @(Get-VM -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' })
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Hyper-V is present but VMs could not be enumerated: $($_.Exception.Message)"
        return $stopped
    }

    foreach ($vm in $running) {
        Add-OfflineRepairLog -Level Info -Message "Stopping nested Hyper-V VM '$($vm.Name)' so its disk can be mounted offline."
        Stop-VM -Name $vm.Name -TurnOff -Force -ErrorAction SilentlyContinue
        $stopped += $vm.Name
    }

    if ($stopped.Count -gt 0) { Start-Sleep -Seconds 3 }
    return $stopped
}

function Set-OfflineDisksOnline {
    <#
    .SYNOPSIS
        Brings every attached virtual data disk online and clears the read-only flag.

    .DESCRIPTION
        The rescue VM's own system disk is never touched. Returns the disk numbers
        that were processed.
    #>
    param(
        [Parameter(Mandatory = $false)][int[]]$ExcludeDiskNumber = @()
    )

    $processed = @()
    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -like '*Virtual Disk*' -and $_.Number -notin $ExcludeDiskNumber
        })

    foreach ($disk in $disks) {
        # diskpart is used rather than Set-Disk because it succeeds on disks whose
        # partition table is damaged, which is common on the disks we are repairing.
        $script = @"
select disk $($disk.Number)
attributes disk clear readonly noerr
online disk noerr
"@
        $null = $script | diskpart.exe 2>&1
        $processed += $disk.Number
    }

    if ($processed.Count -gt 0) {
        Add-OfflineRepairLog -Level Info -Message "Brought attached virtual disk(s) online: $($processed -join ', ')"
    }
    else {
        Add-OfflineRepairLog -Level Warning -Message 'No attached virtual data disk was found on the rescue VM.'
    }

    # Give the volume stack a moment to surface the new volumes.
    Start-Sleep -Seconds 2
    return $processed
}

function Add-PartitionDriveLetter {
    <#
    .SYNOPSIS
        Assigns a free drive letter to a partition that does not have one.

    .DESCRIPTION
        Set-Partition -NewDriveLetter fails on EFI System and Recovery partitions, so
        diskpart is used, with Add-PartitionAccessPath as a fallback.

        Success is verified by probing the drive root rather than by re-reading
        Get-Partition, because the partition object never reports a drive letter for
        hidden System and Recovery partitions even after one has been assigned.

    .OUTPUTS
        The assigned drive letter (without a colon), or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $false)][string]$DriveLetter
    )

    if ([string]::IsNullOrWhiteSpace($DriveLetter)) { $DriveLetter = Get-FreeDriveLetter }
    $DriveLetter = $DriveLetter.TrimEnd(':', '\').ToUpperInvariant()

    $diskpartScript = @"
select disk $DiskNumber
select partition $PartitionNumber
assign letter=$DriveLetter
exit
"@
    $null = $diskpartScript | diskpart.exe 2>&1
    Start-Sleep -Milliseconds 500

    if (Test-OfflinePath "${DriveLetter}:\") {
        Add-OfflineRepairLog -Level Info -Message "Assigned drive letter ${DriveLetter}: to disk $DiskNumber partition $PartitionNumber."
        return $DriveLetter
    }

    # Fallback for partitions diskpart refuses to address, such as the MSR partition.
    try {
        Add-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -AccessPath "${DriveLetter}:" -ErrorAction Stop
        if (Test-OfflinePath "${DriveLetter}:\") {
            Add-OfflineRepairLog -Level Info -Message "Assigned drive letter ${DriveLetter}: to disk $DiskNumber partition $PartitionNumber (access path)."
            return $DriveLetter
        }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not add an access path for disk $DiskNumber partition ${PartitionNumber}: $($_.Exception.Message)"
    }

    Add-OfflineRepairLog -Level Warning -Message "Could not assign a drive letter to disk $DiskNumber partition $PartitionNumber."
    return $null
}

function Get-OfflineWindowsInstallCandidate {
    <#
    .SYNOPSIS
        Builds a scored candidate object for one offline Windows installation.

    .DESCRIPTION
        Scoring prefers an installation that has both core hives, the boot loader
        binary expected for the disk's firmware generation, and the highest build
        number, and penalises an installation that is mid-setup.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AccessPath,
        [Parameter(Mandatory = $true)]$PartitionInfo,
        [Parameter(Mandatory = $true)][int]$Generation
    )

    $normalizedPath = if ($AccessPath -match '\\$') { $AccessPath } else { "$AccessPath\" }
    $windowsRoot = Join-OfflinePath -Root $normalizedPath -ChildPath 'Windows'
    $systemHivePath = Join-OfflinePath -Root $windowsRoot -ChildPath 'System32\Config\SYSTEM'
    $softwareHivePath = Join-OfflinePath -Root $windowsRoot -ChildPath 'System32\Config\SOFTWARE'
    $winloadName = if ($Generation -eq 2) { 'System32\winload.efi' } else { 'System32\winload.exe' }
    $expectedWinload = Join-OfflinePath -Root $windowsRoot -ChildPath $winloadName

    $candidate = [ordered]@{
        AccessPath          = $normalizedPath
        Drive               = $normalizedPath.TrimEnd('\').ToUpperInvariant()
        DiskNumber          = $PartitionInfo.DiskNumber
        PartitionNumber     = $PartitionInfo.PartitionNumber
        PartitionType       = "$($PartitionInfo.Type)"
        IsActive            = [bool]$PartitionInfo.IsActive
        WindowsRoot         = $windowsRoot
        SystemHivePresent   = Test-OfflinePath $systemHivePath
        SoftwareHivePresent = Test-OfflinePath $softwareHivePath
        HasExpectedWinload  = Test-OfflinePath $expectedWinload
        ProductName         = ''
        CurrentBuildNumber  = ''
        GuestComputerName   = ''
        SetupInProgress     = $false
        Score               = 0
        Selected            = $false
    }

    if ($candidate.SystemHivePresent -and $candidate.SoftwareHivePresent) {
        # Load under a unique temporary key so this probe never collides with the
        # BROKEN<HIVE> mounts used by the repair itself.
        $tempBase = 'RSLPROBE_{0}' -f ([guid]::NewGuid().ToString('N'))
        $softwareKey = "${tempBase}_SOFTWARE"
        $systemKey = "${tempBase}_SYSTEM"
        $loadedKeys = [System.Collections.Generic.List[string]]::new()

        try {
            $null = reg.exe load "HKLM\$softwareKey" "$softwareHivePath" 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                [void]$loadedKeys.Add($softwareKey)
                $cv = Get-ItemProperty "HKLM:\$softwareKey\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
                if ($cv) {
                    $candidate.ProductName = [string]$cv.ProductName
                    $candidate.CurrentBuildNumber = [string]$cv.CurrentBuildNumber
                }
            }

            $null = reg.exe load "HKLM\$systemKey" "$systemHivePath" 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                [void]$loadedKeys.Add($systemKey)
                $currentSet = (Get-ItemProperty "HKLM:\$systemKey\Select" -ErrorAction SilentlyContinue).Current
                $controlSetName = if ($currentSet) { 'ControlSet{0:d3}' -f $currentSet } else { 'ControlSet001' }
                $candidate.GuestComputerName = [string]((Get-ItemProperty "HKLM:\$systemKey\$controlSetName\Control\ComputerName\ComputerName" -ErrorAction SilentlyContinue).ComputerName)

                $setup = Get-ItemProperty "HKLM:\$systemKey\Setup" -ErrorAction SilentlyContinue
                if ($setup -and (($null -ne $setup.SetupType -and "$($setup.SetupType)" -ne '0') -or -not [string]::IsNullOrWhiteSpace($setup.CmdLine))) {
                    $candidate.SetupInProgress = $true
                }
            }
        }
        finally {
            $Error.Clear()
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            for ($i = $loadedKeys.Count - 1; $i -ge 0; $i--) {
                $null = reg.exe unload "HKLM\$($loadedKeys[$i])" 2>&1
            }
        }
    }

    if (Test-OfflinePath (Join-OfflinePath -Root $normalizedPath -ChildPath '$WINDOWS.~BT')) { $candidate.SetupInProgress = $true }

    $score = 0
    if ($candidate.SystemHivePresent) { $score += 10 }
    if ($candidate.SoftwareHivePresent) { $score += 10 }
    if ($candidate.HasExpectedWinload) { $score += 30 } else { $score -= 25 }
    if ($candidate.ProductName) { $score += 10 }

    $buildInt = 0
    if ([int]::TryParse($candidate.CurrentBuildNumber, [ref]$buildInt)) {
        $score += [Math]::Min([int]($buildInt / 1000), 30)
    }
    if ($candidate.SetupInProgress) { $score -= 20 }

    $candidate.Score = $score
    return [PSCustomObject]$candidate
}

function Get-OfflineWindowsDisk {
    <#
    .SYNOPSIS
        Locates the offline Windows installation on the attached broken OS disk.

    .DESCRIPTION
        Stops a nested repair VM if one is running, brings the attached virtual disks
        online, assigns drive letters to partitions that have none, then selects the
        best Windows installation and its matching boot partition.

        Sets $script:OfflineWindowsDrive for the offline registry hive helper.

    .PARAMETER DiskNumber
        Restrict the search to a specific disk number.

    .PARAMETER WindowsDrive
        Skip discovery and use this drive letter as the offline Windows volume.

    .OUTPUTS
        PSCustomObject with DiskNumber, Generation, WindowsDrive, WindowsPath,
        BootDrive, BcdStorePath, ProductName, GuestComputerName and Candidates.

    .EXAMPLE
        $offline = Get-OfflineWindowsDisk
        Invoke-WithHive 'SYSTEM' { Get-ItemProperty "$(Get-OfflineSystemRootPath)\Services\disk" }
    #>
    param(
        [Parameter(Mandatory = $false)][int]$DiskNumber = -1,
        [Parameter(Mandatory = $false)][string]$WindowsDrive
    )

    $systemDiskNumber = -1
    try {
        $systemDiskNumber = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop).DiskNumber
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not determine the rescue VM system disk number: $($_.Exception.Message)"
    }

    $null = Stop-NestedRepairVm
    $null = Set-OfflineDisksOnline -ExcludeDiskNumber @($systemDiskNumber | Where-Object { $_ -ge 0 })

    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -like '*Virtual Disk*' -and $_.Number -ne $systemDiskNumber -and
            ($DiskNumber -lt 0 -or $_.Number -eq $DiskNumber)
        })

    if ($disks.Count -eq 0) {
        throw 'No attached broken OS disk was found. Create the rescue VM with "az vm repair create" first.'
    }

    # Give every partition a drive letter. EFI System and Recovery partitions have none
    # by default, and offline boot repairs cannot reach them without one.
    # Get-Partition never reports a letter for those partitions even after assignment,
    # so the letters are tracked here and used for all later path building.
    $partitionRoots = @{}
    $volumeMap = Get-VolumeDriveLetterMap
    $letterDeviceMap = Get-DriveLetterDeviceMap
    foreach ($disk in $disks) {
        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            $key = "$($disk.Number)-$($part.PartitionNumber)"

            $existing = @(Get-PartitionExistingRoot -Partition $part -LetterDeviceMap $letterDeviceMap -VolumeMap $volumeMap)
            if ($existing.Count -gt 0) {
                $partitionRoots[$key] = @($existing)
                continue
            }

            # The Microsoft Reserved partition holds no file system and cannot be mounted.
            if ("$($part.Type)" -eq 'Reserved') { continue }
            if ($part.Size -lt 1MB) { continue }

            $letter = Add-PartitionDriveLetter -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
            if ($letter) {
                $partitionRoots[$key] = @("${letter}:")

                # Keep the map current so a partition that shares this volume is not
                # handed a second letter later in the same pass.
                $newDevice = Get-DosDeviceTarget -Name "${letter}:"
                if (-not [string]::IsNullOrWhiteSpace($newDevice)) { $letterDeviceMap["${letter}:"] = $newDevice }
            }
        }
    }

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($disk in $disks) {
        $generation = if ($disk.PartitionStyle -eq 'GPT') { 2 } elseif ($disk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            foreach ($accessPath in @($partitionRoots["$($disk.Number)-$($part.PartitionNumber)"])) {
                if (-not $accessPath) { continue }
                if (-not (Test-OfflinePath (Join-OfflinePath -Root $accessPath -ChildPath 'Windows\System32\ntdll.dll'))) { continue }

                $normalized = if ($accessPath -match '\\$') { $accessPath } else { "$accessPath\" }
                if ($candidates | Where-Object { $_.AccessPath -eq $normalized } | Select-Object -First 1) { continue }

                [void]$candidates.Add((Get-OfflineWindowsInstallCandidate -AccessPath $normalized -PartitionInfo $part -Generation $generation))
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($WindowsDrive)) {
        $wanted = $WindowsDrive.TrimEnd(':', '\').ToUpperInvariant() + ':'
        $forced = @($candidates | Where-Object { $_.Drive -eq $wanted })
        if ($forced.Count -eq 0) {
            throw "No offline Windows installation was found on drive $wanted."
        }
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        $forced | ForEach-Object { [void]$candidates.Add($_) }
    }

    if ($candidates.Count -eq 0) {
        throw 'No offline Windows installation was found on the attached disk(s).'
    }

    $sorted = @($candidates | Sort-Object @{ Expression = 'Score'; Descending = $true },
        @{ Expression = { [int]($_.CurrentBuildNumber -as [int]) }; Descending = $true }, PartitionNumber)
    $selected = $sorted[0]
    foreach ($candidate in $sorted) { $candidate.Selected = ($candidate.Drive -eq $selected.Drive) }

    if ($sorted.Count -gt 1) {
        Add-OfflineRepairLog -Level Warning -Message "$($sorted.Count) Windows installations found on the attached disk(s). Selected $($selected.Drive) (score $($selected.Score))."
    }

    $selectedDisk = Get-Disk -Number $selected.DiskNumber -ErrorAction SilentlyContinue
    $generation = if ($selectedDisk.PartitionStyle -eq 'GPT') { 2 } elseif ($selectedDisk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

    # Locate the boot partition and its BCD store on the same disk.
    $bootDrive = $null
    $bcdStorePath = $null
    foreach ($part in (Get-Partition -DiskNumber $selected.DiskNumber -ErrorAction SilentlyContinue)) {
        foreach ($accessPath in @($partitionRoots["$($selected.DiskNumber)-$($part.PartitionNumber)"])) {
            if (-not $accessPath) { continue }
            $efiBcd = Join-OfflinePath -Root $accessPath -ChildPath 'EFI\Microsoft\Boot\BCD'
            $biosBcd = Join-OfflinePath -Root $accessPath -ChildPath 'Boot\BCD'

            if ($generation -eq 2 -and (Test-OfflinePath $efiBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $efiBcd; break
            }
            if ($generation -ne 2 -and (Test-OfflinePath $biosBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $biosBcd; break
            }
        }
        if ($bootDrive) { break }
    }

    if (-not $bootDrive) {
        # The BCD file may be missing while the system partition itself is intact.
        foreach ($part in (Get-Partition -DiskNumber $selected.DiskNumber -ErrorAction SilentlyContinue)) {
            $isBootPartition = ("$($part.Type)" -eq 'System') -or ($generation -ne 2 -and $part.IsActive)
            if (-not $isBootPartition) { continue }
            $root = @($partitionRoots["$($selected.DiskNumber)-$($part.PartitionNumber)"]) | Select-Object -First 1
            if ($root) {
                $bootDrive = $root.TrimEnd('\')
                $bcdStorePath = if ($generation -eq 2) { Join-OfflinePath -Root $bootDrive -ChildPath 'EFI\Microsoft\Boot\BCD' } else { Join-OfflinePath -Root $bootDrive -ChildPath 'Boot\BCD' }
                Add-OfflineRepairLog -Level Warning -Message "No BCD store was found at $bcdStorePath, but the boot partition is present at $bootDrive."
                break
            }
        }
    }

    if (-not $bootDrive) {
        Add-OfflineRepairLog -Level Warning -Message 'No boot partition was found on the attached disk. Boot configuration repairs will not be available.'
    }

    $script:OfflineWindowsDrive = $selected.Drive

    $result = [PSCustomObject]@{
        DiskNumber        = $selected.DiskNumber
        PartitionStyle    = "$($selectedDisk.PartitionStyle)"
        Generation        = $generation
        WindowsDrive      = $selected.Drive
        WindowsPath       = $selected.WindowsRoot
        PartitionNumber   = $selected.PartitionNumber
        BootDrive         = $bootDrive
        BcdStorePath      = $bcdStorePath
        ProductName       = $selected.ProductName
        BuildNumber       = $selected.CurrentBuildNumber
        GuestComputerName = $selected.GuestComputerName
        SetupInProgress   = $selected.SetupInProgress
        PartitionRoots    = $partitionRoots
        Candidates        = $sorted
    }

    Add-OfflineRepairLog -Level Info -Message "Offline Windows: $($result.WindowsPath) (disk $($result.DiskNumber), Gen$($result.Generation), $($result.ProductName) build $($result.BuildNumber))"
    if ($result.GuestComputerName) { Add-OfflineRepairLog -Level Info -Message "Guest computer name: $($result.GuestComputerName)" }
    if ($result.BootDrive) { Add-OfflineRepairLog -Level Info -Message "Boot partition: $($result.BootDrive) (BCD: $($result.BcdStorePath))" }

    return $result
}
