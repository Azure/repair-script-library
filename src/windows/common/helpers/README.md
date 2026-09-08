# Windows Shared Helper Scripts

Each helper script and description should be listed here.

| Helper | Description |
|---|---|
| `Logger.ps1` | `Log-Output` / `Log-Info` / `Log-Warning` / `Log-Error` / `Log-Debug`. Imported automatically by `common/setup/init.ps1`. |
| `Get-Disk-Partitions.ps1` | Returns partitions of attached disks whose `Win32_diskdrive` model is `Microsoft Virtual Disk`, bringing them online with `diskpart`. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v2.ps1` | As v1, with `$partitionlist` initialised to an array so a single result is not unrolled. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v3.ps1` | `Get-Disk-Partitions-v3` selects attached disks by **BusType** (SCSI/SAS/RAID/NVMe) instead of the SCSI-only model string, so it also works when the repair VM uses the NVMe disk controller. Excludes the Azure resource disk. `Get-Windows-OsDrives-v3` narrows the result to drive letters that contain a Windows installation. |
| `OfflineRepairCommon.ps1` | Shared primitives for offline repair: buffered logging, path joining and validation, Authenticode/catalog signature inspection, and the offline-target gate (`Set-OfflineRepairRoot` / `Assert-OfflineTarget`) that binds every other offline helper to the attached disk. |
| `Get-OfflineWindowsDisk.ps1` | Finds the offline Windows installation on the attached disk, brings its disks online, assigns and tracks temporary drive letters for hidden EFI System and Recovery partitions, and releases them again. Selects by **BusType**, excludes the resource disk, and refuses to return the rescue VM's own boot/system disk. Binds the offline root for `Assert-OfflineTarget`. |
| `Use-OfflineRegistryHive.ps1` | Loads a registry hive from the attached disk, runs a scriptblock against it, and unloads it again — verifying the unload rather than assuming it, and dismounting even when the mount loop itself fails. |
| `Use-OfflineProtectedResource.ps1` | Takes ownership of, reads and restores files and registry keys on the attached disk that `SYSTEM` cannot otherwise open, restoring every security descriptor it changed and verifying the restore rather than counting it. |
| `Use-OfflinePrivilegedRegistry.ps1` | The privileged registry operations from `Use-OfflineProtectedResource.ps1`: enabling `SeTakeOwnershipPrivilege`/`SeRestorePrivilege` and removing or rewriting keys that deny access to `SYSTEM`. |
| `Get-OfflineBcdStore.ps1` | Locates the BCD store on the attached disk and runs `bcdedit.exe` against it directly, without a shell. Distinguishes an empty boot inventory from a failed enumeration, and refuses to operate on the rescue VM's own store. |
| `Use-OfflineFileRemoval.ps1` | Removes files from the attached disk with a backup, a verified rollback, and post-removal checks. Refuses to remove a registry hive or any of its side files, refuses to follow reparse points, and refuses any path outside the bound offline root. |
| `Use-NestedRepairVm.ps1` | Boots the offline Windows installation as a nested Hyper-V guest on the rescue VM for repairs that only the running OS can perform. Restores the offline state of every disk it took, on every exit path. |

The last six helpers in that table are added by the two companion pull requests:
`Use-OfflineRegistryHive.ps1`, `Use-OfflineProtectedResource.ps1` and
`Use-OfflinePrivilegedRegistry.ps1` by #146, and `Get-OfflineBcdStore.ps1`,
`Use-OfflineFileRemoval.ps1` and `Use-NestedRepairVm.ps1` by #147. They are listed here so this
file stays the single index the repository asks for, and so the three pull requests do not all
edit the same ten-line table and conflict with one another.

**Which one to use:** new scripts should use **v3**. v1 and v2 are retained because existing scripts depend
on them; they return nothing on a repair VM created with the NVMe disk controller.

`Get-OfflineWindowsDisk.ps1` solves a different problem from the `Get-Disk-Partitions` family: it
identifies the *Windows installation* to repair and binds it as the offline root, rather than
returning every attached partition. It selects disks by `BusType` for the same reason **v3** does.
