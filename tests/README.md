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
