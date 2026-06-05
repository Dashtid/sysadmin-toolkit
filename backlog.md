# Backlog

Tactical work queue for the toolkit. Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Items are sized S (under an hour), M (1-3 hours), L (half-day or more) and ordered by priority.

## Active

| # | Item | Notes | Size |
|---|------|-------|------|
| 1 | Behavioral tests for setup scripts | Current `FirstTimeSetup.Tests.ps1` is structural only. Add Pester tests with mocks for the actual install/export flows (winget/choco/Invoke-WebRequest/etc.) covering `fresh-windows-setup.ps1`, `install-from-exported-packages.ps1`, `export-current-packages.ps1`, `remote-development-setup.ps1`. Highest-risk scripts (admin-required, system-wide changes). | L |
| 2 | Behavioral tests for `Restore-DeveloperEnvironment.ps1` | Backup side has full Pester coverage. Restore side has none. Asymmetric coverage where data-loss bugs hide. | M |
| 3 | Polish pass | README version bump, CHANGELOG.md bootstrap, optional PR template, unify `tests/run-tests.ps1` to invoke BATS when available. | M |

## Linux coverage gaps (deferred; potential future work)

The "parity achieved" claim was dropped in `docs/ROADMAP.md` on 2026-05-27. The real gaps below are not committed to but kept here for visibility. Linux scope is headless server (q-lab) so several Windows categories are intentionally out of scope.

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

- 2026-05-27: `refactor(setup): approved verbs + lock down iex regression` (commit 20affe7) - Renamed 6 functions in remote-development-setup.ps1 to use PowerShell-approved verbs; added FirstTimeSetup test to prevent iex-with-URL regression.
- 2026-05-27: `refactor(setup): use CommonFunctions for logging instead of local wrappers` (commit 42a1dbd) - CommonFunctions v1.2.0 (Set-LogFile/Tee-Log/Write-Section); 4 setup scripts deduplicated.
- 2026-05-27: `refactor(setup): singular-noun renames + drop Invoke-Expression` (commit 28607cd)
- 2026-05-27: `docs: refresh ROADMAP, drop Linux parity claim, document coverage honestly` (commit 6a963db)
- 2026-05-25: `feat: add Install-SystemUpdatesTask.ps1` (commit a42ed8e)
- 2026-05-25: `chore: remove dotfiles/claude-config + Windows/ssh, add CmdletBinding to 4 setup scripts` (commit 02a7709)

---
**Last Updated**: 2026-05-27
