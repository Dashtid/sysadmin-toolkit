# Backlog

Tactical work queue for the toolkit. Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Items are sized S (under an hour), M (1-3 hours), L (half-day or more) and ordered by priority.

## Active

| # | Item | Notes | Size |
|---|------|-------|------|
| 1 | Setup scripts: use CommonFunctions logging | `fresh-windows-setup.ps1`, `install-from-exported-packages.ps1`, `export-current-packages.ps1`, `remote-development-setup.ps1` each redefine `Write-Info`/`Write-Success`/`Write-Warning`/`Write-Error`. The last two shadow built-in PowerShell cmdlets (`PSAvoidOverwritingBuiltInCmdlets`). Import `Windows/lib/CommonFunctions.psm1` and drop the wrappers. | M |
| 2 | Refresh `docs/ROADMAP.md` | Add `Install-SystemUpdatesTask.ps1` to completed Tier 5 list. Update "Last Updated" stamp. Reassess "Linux Parity: Achieved" claim against actual file counts (14 Linux vs 26 Windows scripts). | S |
| 3 | Singular-noun renames in `install-from-exported-packages.ps1` | `Install-WingetPackages` -> `Install-WingetPackage`, `Install-ChocolateyPackages` -> `Install-ChocolateyPackage`, `Refresh-Environment` -> `Update-Environment` (unapproved verb). PSScriptAnalyzer flags all three. Touch the call sites too. | S |
| 4 | Behavioral tests for setup scripts | Current `FirstTimeSetup.Tests.ps1` is structural only (file exists, syntax valid, param declared). Add Pester tests with mocks for the actual install/export flows. These are the highest-risk scripts (admin-required, system-wide changes). | L |
| 5 | Replace `Invoke-Expression` in Chocolatey bootstrap | `install-from-exported-packages.ps1:73` uses the standard `iex (DownloadString ...)` pattern. The toolkit's own `Maintenance.Comprehensive.Tests.ps1:223` flags this as insecure. Download script to temp, optionally verify, then run. | M |
## Linux coverage gaps (deferred; potential future work)

Drop-the-parity-claim is done in `docs/ROADMAP.md`. The real gaps below are not committed to but kept here for visibility. Linux scope is headless server (q-lab) so several Windows categories are intentionally out of scope.

| Gap | Linux script needed | Effort |
|-----|---------------------|--------|
| Reporting | `system-report.sh` - hardware/network/services summary mirroring `Get-SystemReport.ps1` | M |
| Troubleshooting | `repair-common-issues.sh` - DNS/network/apt-broken-state recovery | M |
| Network | `test-network-health.sh` - connectivity/DNS/port testing for q-lab | S |
| Monitoring | Expand `service-health-monitor.sh` coverage or add equivalent of `Watch-ServiceHealth.ps1` | M |

## Deferred (Tier 4 - explicitly low priority)

| Item | Effort | Notes |
|------|--------|-------|
| Azure resource management | 4-5 hr | From ROADMAP.md |
| AWS resource management | 4-5 hr | From ROADMAP.md |
| OneDrive sync automation | 2-3 hr | From ROADMAP.md |
| System change log tracker | 4-5 hr | From ROADMAP.md |
| Configuration drift detection | 3-4 hr | From ROADMAP.md |
| Compliance reporting | 3-4 hr | From ROADMAP.md |

## Recently closed

- 2026-05-27: `docs: refresh ROADMAP, drop Linux parity claim, document coverage honestly` (this commit)
- 2026-05-25: `feat: add Install-SystemUpdatesTask.ps1` (commit a42ed8e)
- 2026-05-25: `chore: remove dotfiles/claude-config + Windows/ssh, add CmdletBinding to 4 setup scripts` (commit 02a7709)

---
**Last Updated**: 2026-05-27
