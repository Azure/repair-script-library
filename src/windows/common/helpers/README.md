# Windows Shared Helper Scripts

Each helper script and description should be listed here.

| Helper | Description |
|---|---|
| `Logger.ps1` | `Log-Output` / `Log-Info` / `Log-Warning` / `Log-Error` / `Log-Debug`. Imported automatically by `common/setup/init.ps1`. |
| `Get-Disk-Partitions.ps1` | Returns partitions of attached disks whose `Win32_diskdrive` model is `Microsoft Virtual Disk`, bringing them online with `diskpart`. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v2.ps1` | As v1, with `$partitionlist` initialised to an array so a single result is not unrolled. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v3.ps1` | `Get-Disk-Partitions-v3` selects attached disks by **BusType** (SCSI/SAS/RAID/NVMe) instead of the SCSI-only model string, so it also works when the repair VM uses the NVMe disk controller. Excludes the Azure resource disk. `Get-Windows-OsDrives-v3` narrows the result to drive letters that contain a Windows installation. |
| `OfflineRepairCommon.ps1` | Shared primitives for offline repair: buffered logging, drive-safe paths, signature inspection, a read-only `offreg.dll` reader, shared hive/default-drive state, the offline-target gate, and cross-process nested-VM lifecycle coordination. |
| `Get-OfflineWindowsDisk.ps1` | Finds the offline Windows installation, verifies its disks are online and writable, and manages temporary drive letters. Selects by **BusType**, excludes resource disks and the rescue VM's own disks, reads hive metadata without mounts, and publishes the shared offline target. Active helper-managed or unrelated guests block discovery before disk preparation. |
| `Use-OfflineRegistryHive.ps1` | Mounts writable hives, runs reentrant callbacks, and verifies unload with language-independent key-state checks. Provides strict control-set selection for writers. Its separate `Test-OfflineHiveFile` uses the shared in-memory reader without mounting or copying hives. |
| `Use-OfflineProtectedResource.ps1` | Takes ownership of, reads and restores files and registry keys on the attached disk that `SYSTEM` cannot otherwise open, restoring every security descriptor it changed and verifying the restore rather than counting it. |
| `Use-OfflinePrivilegedRegistry.ps1` | The privileged registry operations from `Use-OfflineProtectedResource.ps1`: enabling `SeTakeOwnershipPrivilege`/`SeRestorePrivilege` and removing or rewriting keys that deny access to `SYSTEM`. |
| `Get-OfflineBcdStore.ps1` | Locates the BCD store on the attached disk and runs `bcdedit.exe` against it directly, without a shell. Distinguishes an empty boot inventory from a failed enumeration, and refuses to operate on the rescue VM's own store. |
| `Use-OfflineFileRemoval.ps1` | Removes approved files with hash-verified backups and rollback. Unknown or insufficient native volume capacity refuses removal. Retains original hashes and recorded metadata for later restores, refuses hive side files and reparse points, and enforces the bound offline target. |
| `Use-NestedRepairVm.ps1` | Hands named disks to an existing nested guest and records ownership in Notes so discovery cannot interrupt it. A failed start restores only disks that call took offline. Reports whether an explicit shutdown actually completed before the caller takes the disk back. |

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

Discovery and `Test-OfflineHiveFile` use the shared offreg reader in `OfflineRepairCommon.ps1`.
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

## Writable hives and control-set selection

Mounted-key state is `Present`, `Absent`, or `Unknown`, determined through registry APIs rather
than localized `reg.exe` messages. Access denial is not absence, and a file-sharing check is not
used as proof of which registry key owns a hive.

Writers must use `Get-OfflineSystemRootPath -Strict`, `Get-OfflineControlSetName -Strict`, or
`Get-OfflineReferencedControlSetName -Strict`. Strict selection rejects an unreadable, wrongly typed,
out-of-range or missing current control set instead of guessing `ControlSet001`. The non-strict
fallback remains for tolerant reads, not for deriving a write target.

`Invoke-WithHive` shares its depth and file bindings across dot-source scopes. An inner callback
cannot unload an outer caller's hive or switch that active hive to another file. Discovery sets
the default through `Set-OfflineWindowsDrive`; manual selection must use that setter too, rather
than assigning a scope-private `$script:OfflineWindowsDrive`.

## Removal and later rollback

Persist `Invoke-OfflineRemovalPlan`'s `BackupRecord` with the backup location. Pass those records as
`Restore-OfflineFileSet -FileRecord` on a later revert; reconstructing just names and attributes
discards the verified original hashes and security descriptors.

A restore checks the backup and restored contents against the recorded hash, reapplies the recorded
security, then restores and verifies exact attributes. Attributes come last because an NTFS security
change can set Archive. Treat `Succeeded = $false` as a failed or incomplete restore and retain the
undo manifest, even when some files were restored.

Legacy records without a Hash field remain supported with an explicit warning: the check proves the
copy against the current backup, not against a recorded historical original. An explicitly empty
Hash field is an unavailable verification result and is refused.

## Nested-guest hand-offs

Automatic discovery shutdown is limited to the unmanaged Azure-created `ProblemVM`, or an exact
custom guest selected with `Get-OfflineWindowsDisk -NestedVmId`. Other active guests are never
implicitly turned off.

`Start-NestedRepairVm` marks a started or adopted guest with a separate
`repair-script-library:nested-repair:v1` Notes line, preserving existing notes. A fresh discovery
process recognizes it and refuses to proceed while it is active. Skipping the guest and onlining
its disk would not be safe.

Sequence offline editing, `Start-NestedRepairVm`, boot/result observation,
`Stop-NestedRepairVmGraceful`, and rediscovery. **Confirm `Stopped` before taking the disk back.**
A timeout power-off is reported as non-graceful and requires rechecking the disk. The shared host
mutex serializes lifecycle transitions, not an entire repair session; it does not replace this
caller sequencing.
