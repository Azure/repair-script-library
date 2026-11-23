# Tests

The repository does not currently run these PowerShell tests in CI. Until automation is added, run
the relevant tests locally and record the commands and results in the pull request.

## NVMe merge gates

Changes to `map.json`, either NVMe readiness detector, `win-enable-nvme-boot-driver.ps1`, or their
shared helpers must pass all three tests from the repository root:

```powershell
pwsh -NoProfile -File ./tests/test-map-catalog.ps1
pwsh -NoProfile -File ./tests/test-win-detect-nvme-readiness-generation.ps1
pwsh -NoProfile -File ./tests/test-win-enable-nvme-boot-driver.ps1
```

Do not merge an affected change when any gate fails or when the pull request does not include the
results. These tests are static and fixture-based; they do not replace the live validation required
for changes that modify a repair script's write behavior.

## MANA readiness merge gates

Changes to `linux-detect-mana-readiness.sh` or its `map.json` entry must pass both tests from the
repository root. The second test needs root on Linux or WSL because it builds disk images and
attaches them as loop devices; it also verifies that the detector writes nothing to the disk and
leaves no mount, snapshot, or loop device behind. Install `xfsprogs` first (it provides `mkfs.xfs`
and `xfs_io`); without it, the XFS and crash-consistent cases are skipped. One case temporarily writes
`/usr/lib/modprobe.d/zz-mana-detector-fixture.conf` on the test machine, to prove the detector never reads the
repair VM's own modprobe configuration, and removes it afterwards.

```powershell
pwsh -NoProfile -File ./tests/test-map-catalog.ps1
```

```bash
sudo bash ./tests/test-linux-detect-mana-readiness.sh .
```

Changes to `win-detect-mana-readiness.ps1`, its `map.json` entry, or the `-ReadOnly` mode of
`Get-Disk-Partitions-v3.ps1` must pass these tests from the repository root. The detector test uses
a temporary driver store and an in-memory stand-in for the offreg reader, so it needs no elevation;
run it in Windows PowerShell 5.1 as well, because that is what runs on the repair VM.

```powershell
pwsh -NoProfile -File ./tests/test-map-catalog.ps1
pwsh -NoProfile -File ./tests/test-get-disk-partitions-v3.ps1
pwsh -NoProfile -File ./tests/test-win-detect-mana-readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File ./tests/test-win-detect-mana-readiness.ps1
```

## Generation 1 to Generation 2 conversion merge gates

Changes to `win-convert-gen1-to-gen2.ps1` or its `map.json` entry must pass both tests from the
repository root:

```powershell
pwsh -NoProfile -File ./tests/test-win-convert-gen1-to-gen2.ps1
pwsh -NoProfile -File ./tests/test-map-catalog.ps1
```

Before merge, use the pull request branch through `--preview` and verify that Report returns
`GEN2_CONVERSION_APPLICABLE`, Convert returns `GEN2_CONVERSION_COMPLETED`, the VM upgrades to
Trusted Launch and boots with Secure Boot and vTPM, and a pre-conversion full backup restores a
bootable Generation 1 VM. Do not use `--run-on-repair` for this source-VM script.
