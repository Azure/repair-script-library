# Windows Shared Helper Scripts

Each helper script and description should be listed here.

| Helper | Description |
|---|---|
| `Logger.ps1` | `Log-Output` / `Log-Info` / `Log-Warning` / `Log-Error` / `Log-Debug`. Imported automatically by `common/setup/init.ps1`. |
| `Get-Disk-Partitions.ps1` | Returns partitions of attached disks whose `Win32_diskdrive` model is `Microsoft Virtual Disk`, bringing them online with `diskpart`. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v2.ps1` | As v1, with `$partitionlist` initialised to an array so a single result is not unrolled. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v3.ps1` | `Get-Disk-Partitions-v3` selects attached disks by **BusType** (SCSI/SAS/RAID/NVMe) instead of the SCSI-only model string, so it also works when the repair VM uses the NVMe disk controller. Excludes the Azure resource disk. `Get-Windows-OsDrives-v3` narrows the result to drive letters that contain a Windows installation. |
| `OfflineRepairCommon.ps1` | Shared primitives for offline repair: buffered logging, path joining and validation, Authenticode/catalog signature inspection, a read-only `offreg.dll` hive reader, and the offline-target gate (`Set-OfflineRepairRoot` / `Assert-OfflineTarget`) that binds every other offline helper to the attached disk. |
| `Get-OfflineWindowsDisk.ps1` | Finds the offline Windows installation on the attached disk, verifies its disks are online and writable, and manages temporary drive letters for hidden EFI System and Recovery partitions. Selects by **BusType**, excludes resource disks by label or warning-file marker, and refuses the rescue VM's own boot/system disk. Reads hive metadata without registry mounts and binds the offline root for `Assert-OfflineTarget`. |
| `Use-OfflineRegistryHive.ps1` | Mounts writable hives from the attached disk, runs a scriptblock, and verifies their unload even after a partial mount failure. Its separate `Test-OfflineHiveFile` validation uses the shared in-memory reader without mounting or copying hives. |
| `Use-OfflineProtectedResource.ps1` | Takes ownership of, reads and restores files and registry keys on the attached disk that `SYSTEM` cannot otherwise open, restoring every security descriptor it changed and verifying the restore rather than counting it. |
| `Use-OfflinePrivilegedRegistry.ps1` | The privileged registry operations from `Use-OfflineProtectedResource.ps1`: enabling `SeTakeOwnershipPrivilege`/`SeRestorePrivilege` and removing or rewriting keys that deny access to `SYSTEM`. |
| `Get-OfflineBcdStore.ps1` | Locates the BCD store on the attached disk and runs `bcdedit.exe` against it directly, without a shell. Distinguishes an empty boot inventory from a failed enumeration, and refuses to operate on the rescue VM's own store. |
| `Use-OfflineFileRemoval.ps1` | Removes files from the attached disk with a backup, a verified rollback, and post-removal checks. Refuses to remove a registry hive or any of its side files, refuses to follow reparse points, and refuses any path outside the bound offline root. |
| `Use-NestedRepairVm.ps1` | Boots the offline Windows installation as a nested Hyper-V guest on the rescue VM for repairs that only the running OS can perform. Restores the offline state of every disk it took, on every exit path. |

**Which one to use:** new scripts that need the *Windows installation* — to mount its hives, edit its
BCD, or repair files on it — should use `Get-OfflineWindowsDisk.ps1`, which also binds the offline root
for `Assert-OfflineTarget`. Use **`Get-Disk-Partitions-v3`** when you only need the attached partitions
or drive letters. v1 and v2 are retained because existing scripts depend on them; they return nothing on
a repair VM created with the NVMe disk controller. v1/v2 are not extended — port to v3 when you touch them.

## Required caller contract

Helpers throw on unsafe targets and failed preconditions. A `map.json` script must catch those
exceptions, log through the library logger, and return `$STATUS_ERROR` rather than exposing a raw
exception through `az vm repair run`. Always release temporary drive letters and flush helper logs
in `finally`, including when discovery fails partway through.

```powershell
. .\src\windows\common\setup\init.ps1

$status = $STATUS_ERROR
try {
    . .\src\windows\common\helpers\OfflineRepairCommon.ps1
    . .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1

    $offline = Get-OfflineWindowsDisk
    # Inspect and repair only the selected offline installation using guarded helpers.
    # Set success only after the scenario's own verification succeeds.
    $status = $STATUS_SUCCESS
}
catch {
    Log-Error $_.Exception.Message
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
return $status
```

Keep `Write-OfflineRepairLog` at script level: the logger writes to the output stream, so flushing
inside a value-returning helper contaminates its result. Return the final status after cleanup and
logging so it remains at the end of the output.

## Read-only hive access

Discovery and `Test-OfflineHiveFile` share `Open-OfflineRegistryReader` in `OfflineRepairCommon.ps1`.
It uses the Windows Offline Registry Library (`System32\offreg.dll`), keeps recovery in memory, and
never invokes `reg.exe`, mounts an HKLM key, saves a hive, or copies credential-bearing hives to TEMP.
Keep matching recovery logs beside dirty hives. Reader handles must be disposed in `finally`; close
failures throw instead of letting a repair proceed with uncertain cleanup.

Discovery records unreadable metadata in `ProbeStatus` and logs a warning because damaged hives are
a valid repair target. Hive validation instead throws when the reader itself is unavailable; that
environment failure must not trigger a corruption repair. `IsValid` means offreg can open the hive,
not that the guest will boot or that a separate structural check is unnecessary.

`Invoke-WithHive` and the protected-registry helpers still expose writable HKLM paths. The in-memory
reader does not replace that contract; callers requiring those paths must keep using the guarded
mount/unmount helpers.
