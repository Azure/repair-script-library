# Windows Shared Helper Scripts

Each helper script and description should be listed here.

| Helper | Description |
|---|---|
| `Logger.ps1` | `Log-Output` / `Log-Info` / `Log-Warning` / `Log-Error` / `Log-Debug`. Imported automatically by `common/setup/init.ps1`. |
| `Get-Disk-Partitions.ps1` | Returns partitions of attached disks whose `Win32_diskdrive` model is `Microsoft Virtual Disk`, bringing them online with `diskpart`. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v2.ps1` | As v1, with `$partitionlist` initialised to an array so a single result is not unrolled. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v3.ps1` | `Get-Disk-Partitions-v3` selects attached disks by **BusType** (SCSI/SAS/RAID/NVMe) instead of the SCSI-only model string, so it also works when the repair VM uses the NVMe disk controller. Excludes the Azure resource disk. `Get-Windows-OsDrives-v3` narrows the result to drive letters that contain a Windows installation. |

**Which one to use:** new scripts should use **v3**. v1 and v2 are retained because existing scripts depend
on them; they return nothing on a repair VM created with the NVMe disk controller.
