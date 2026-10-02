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
