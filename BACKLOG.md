# BACKLOG

Tactical work queue for the toolkit, organized into discrete sprints so the road ahead is visible.
Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Sizing: **S** under an hour, **M** 1-3 hours, **L** half-day or more.

---

## Current state (2026-06-09)

- **Windows behavioral coverage**: 20.94% overall (was 6.68% at session start, +14.26 pp).
- **Pester tests**: 1038 passing, 0 failing.
- **Production bugs found and fixed via testing**: 5 (see Sprint 1 closeouts).
- **Setup, restore, monitoring core, and Docker/WSL all behaviorally covered.**

The current bottleneck is **read-only reporting/audit scripts** and a smaller cluster of **system-mutation scripts** (backup, network, updates, repair).
After that, two scripts (Get-SystemPerformance, Test-DevEnvironment) need substantial refactor before they can be tested cleanly.

---

## Sprint plan

| Sprint | Theme | Scripts | Effort | Coverage gain |
|--------|-------|---------|--------|---------------|
| 1 | High-ROI monitoring + dev-tooling | 5 scripts | ~16 hrs | +14.26 pp (DONE) |
| 2 | Read-only reporting & audit | 4 scripts | ~20 hrs | est. +8-10 pp |
| 3 | Mutating system & network | 4 scripts | ~18 hrs | est. +6-8 pp |
| 4 | Backup & state | 5 scripts | ~24 hrs | est. +8-10 pp |
| 5 | Excluded hard scripts | 2 scripts | ~24 hrs | est. +5-7 pp |
| 6 | Test runner + repo hygiene | 3 small items | ~3 hrs | -- |
| 7 | Linux coverage gaps | 4 sh scripts | ~10 hrs | -- |

Cumulative target after Sprint 5: **~55-60% overall coverage**, all Windows scripts behaviorally tested.

---

## Sprint 2 — Read-only reporting & audit (next)

Low-risk because nothing mutates state, but mocking surface is wide (WMI/CIM/registry/HKLM/HKCU).
Each follows the established pattern: wrap main in `Invoke-X`, add dot-source guard, refactor helpers that read script-scope to take explicit params, then write behavioral tests.

| # | Script | Lines | Size | Notes |
|---|--------|-------|------|-------|
| 2.1 | `Windows/reporting/Get-SystemReport.ps1` | 1074 | L | Was rank-5 in the original survey. Main function already present, 7 helpers, 28 try/catch blocks. Single blocker is auto-execution. 21 WMI/CIM cmdlets to mock. |
| 2.2 | `Windows/monitoring/Get-ApplicationHealth.ps1` | 796 | M | Application health check — read-only by design. |
| 2.3 | `Windows/first-time-setup/Compare-SoftwareInventory.ps1` | 749 | M | Diffs installed packages against a baseline. Reads winget/choco/registry. |
| 2.4 | `Windows/security/Get-UserAccountAudit.ps1` | 632 | M | Local account audit. Reads SAM/security registry. |

---

## Sprint 3 — Mutating system & network

Higher risk because these write to system state. Tests must mock at the boundary so they never actually call `wsl --shutdown`, `netsh`, `Windows Update`, etc.

| # | Script | Lines | Size | Notes |
|---|--------|-------|------|-------|
| 3.1 | `Windows/maintenance/system-updates.ps1` | 831 | L | Installs Windows updates. Mock PSWindowsUpdate cmdlets. |
| 3.2 | `Windows/network/Set-StaticIP.ps1` | 276 | M | Small but mutates network config. |
| 3.3 | `Windows/network/Manage-VPN.ps1` | 915 | L | Adds/removes VPN connections via `Add-VpnConnection` etc. |
| 3.4 | `Windows/troubleshooting/Repair-CommonIssues.ps1` | 671 | M | Runs sfc/dism/network resets. Test the dispatch logic, not the repair calls. |

---

## Sprint 4 — Backup & state

Highest mutation risk in the entire backlog (file copies, registry exports, restore paths).
Every test must be sandboxed in `$TestDrive`; nothing touches the real user profile.

| # | Script | Lines | Size | Notes |
|---|--------|-------|------|-------|
| 4.1 | `Windows/backup/Backup-DeveloperEnvironment.ps1` | 248 | S | Already small; smallest entry point into this category. |
| 4.2 | `Windows/backup/Backup-UserData.ps1` | 996 | L | User-profile backup. Robocopy boundary. |
| 4.3 | `Windows/backup/Backup-BrowserProfiles.ps1` | 1078 | L | Browser profile backup + restore round-trip. File-mutation hazards. |
| 4.4 | `Windows/backup/Export-SystemState.ps1` | 895 | L | Registry/service export. |
| 4.5 | `Windows/backup/Test-BackupIntegrity.ps1` | 869 | L | Backup verifier — read-only but checksums real archives. |

---

## Sprint 5 — Excluded hard scripts

Both were explicitly excluded from the original survey ranking because they need substantial restructuring before behavioral tests can land. Treat the refactor as the deliverable; tests come after.

| # | Script | Lines | Size | Notes |
|---|--------|-------|------|-------|
| 5.1 | `Windows/monitoring/Get-SystemPerformance.ps1` | 1457 | L+ | No Main function, 70-line straight-line script body, destructive AutoCleanup option. Refactor first: extract `Invoke-SystemPerformance`, factor out the script body, add testability guard. |
| 5.2 | `Windows/development/Test-DevEnvironment.ps1` | 1213 | L+ | 17 external tools to stub (git, node, npm, python, pip, docker, kubectl, az, gh, code, etc.). Most expensive mocking surface in the repo. |

---

## Sprint 6 — Test runner + repo hygiene

Small items carried over from the prior backlog.

| # | Item | Size | Notes |
|---|------|------|-------|
| 6.1 | Unify `tests/run-tests.ps1` to invoke BATS when available | S | Currently runs Pester (Windows) only. Linux BATS tests are invoked by CI separately. Single-command local test runner would be a quality-of-life win. |
| 6.2 | `.github/PULL_REQUEST_TEMPLATE.md` (optional) | S | Toolkit has no PR template. Decide whether one would actually help (single-author repo, mostly direct commits) before adding. |
| 6.3 | Add `Restore-VsCodeExtension` retry/backoff | M | When a vscode-marketplace install times out, retry once with backoff. Low priority -- current behavior just logs and continues. |

---

## Sprint 7 — Linux coverage gaps (deferred)

The "parity achieved" claim was dropped in `docs/ROADMAP.md` on 2026-05-27.
Linux scope is headless server (q-lab) so several Windows categories are intentionally out of scope.
Not committed to yet; kept here for visibility.

| Gap | Linux script needed | Size |
|-----|---------------------|------|
| Reporting | `system-report.sh` - hardware/network/services summary mirroring `Get-SystemReport.ps1` | M |
| Troubleshooting | `repair-common-issues.sh` - DNS/network/apt-broken-state recovery | M |
| Network | `test-network-health.sh` - connectivity/DNS/port testing for q-lab | S |
| Monitoring | Expand `service-health-monitor.sh` coverage or add equivalent of `Watch-ServiceHealth.ps1` | M |

---

## Deferred (Tier 4 - explicitly low priority)

Carried from ROADMAP.md. Not in the sprint plan above because nothing in this list is actually load-bearing today.

| Item | Effort | Notes |
|------|--------|-------|
| Azure resource management | 4-5 hr | From ROADMAP.md |
| AWS resource management | 4-5 hr | From ROADMAP.md |
| OneDrive sync automation | 2-3 hr | From ROADMAP.md |
| System change log tracker | 4-5 hr | From ROADMAP.md |
| Configuration drift detection | 3-4 hr | From ROADMAP.md |
| Compliance reporting | 3-4 hr | From ROADMAP.md |

---

## Sprint 1 closeouts (recent)

The current behavioral-testing push started 2026-06-05. Coverage went from 6.68% to 20.94% across 138 new tests; 5 real production bugs were fixed along the way.

- 2026-06-09: `test(development): behavioral coverage for Manage-WSL` (commit 88bb415) - 32 new tests, +2.86 pp (18.08% -> 20.94%). Refactor: `Main` -> `Invoke-WslManager`, testability guard, `-ConfigPath` param on `Set-WslConfiguration` so `~/.wslconfig` is not clobbered during tests. Highest-risk script (risk=5: distro export/import, `--unregister` can permanently delete user data) now covered. No bugs found.
- 2026-06-09: `test(development): behavioral coverage for Manage-Docker` (commit 9205a31) - 29 new tests, +2.17 pp (15.91% -> 18.08%). Refactor: `Main` -> `Invoke-DockerManager`, testability guard, `-Path` param on Docker Desktop helpers, `Pull-DockerImage` -> `Invoke-DockerImagePull` (approved verb), `$args` -> `$dockerArgs` to stop shadowing the automatic variable. No bugs found.
- 2026-06-07: `test(monitoring): behavioral coverage for Get-EventLogAnalysis` (commit 53bb062) - 27 new tests, +3.96 pp (11.95% -> 15.91%). **Fixed two production bugs**: Summary counters returned the matched hashtable's key count instead of 1 (single-match unwrap trap); `Get-SystemIssues` / `Get-ApplicationIssues` / `Get-SecurityAnalysis` / `Get-FailedLogonDetails` `[Mandatory][array]$Events` rejected empty collections, crashing the script for non-admins who only specified the Security log.
- 2026-06-07: `test(monitoring): behavioral coverage for Test-NetworkHealth` (commit e080cac) - 27 new tests, +3.37 pp (8.58% -> 11.95%). **Fixed three production bugs**: `$host` (automatic variable for the host object) used in place of `$targetHost` in four alert messages; empty-string `$DNSServer` not defaulting to 'System Default' because `??` only triggers on null; AAAA records lost because `IPAddresses` was a single string not an array (`+=` did string concat).
- 2026-06-06: `test(monitoring): behavioral coverage for Watch-ServiceHealth` (commit 9f0e941) - 23 new tests; +1.9 pp (6.68% -> 8.58%). Established the "wrap main in `Invoke-X` + testability guard + explicit params" pattern that the rest of the cycle reuses.

## Earlier closeouts (pre-2026-06-05)

- 2026-06-05: `test(backup): behavioral coverage for Restore-DeveloperEnvironment` (commit 7d9b2aa) - 20 new tests after factoring straight-line script into four functions.
- 2026-06-05: `test(setup): behavioral coverage for remote-development-setup` (commit b7cd047) - 17 tests; final setup script covered.
- 2026-06-05: `test(setup): behavioral coverage for fresh-windows-setup` (commit 616643a) - 23 tests; Work/Home profile branching covered.
- 2026-06-05: `test(setup): behavioral coverage for install-from-exported-packages` (commit 4948960) - 26 tests; iex-free Chocolatey bootstrap covered.
- 2026-06-05: `test(setup): behavioral coverage for export-current-packages + empty-Message fix` (commit 08b9022) - 19 tests; uncovered a real production bug (CommonFunctions Mandatory rejecting empty strings).
- 2026-06-05: `test(setup): make setup scripts testable via dot-source` (commit 0612b7e) - removed `#Requires -RunAsAdministrator` from 3 scripts (replaced by runtime `Assert-Administrator`).
- 2026-05-27: `refactor(setup): approved verbs + lock down iex regression` (commit 20affe7)
- 2026-05-27: `refactor(setup): use CommonFunctions for logging instead of local wrappers` (commit 42a1dbd)
- 2026-05-27: `refactor(setup): singular-noun renames + drop Invoke-Expression` (commit 28607cd)
- 2026-05-27: `docs: refresh ROADMAP, drop Linux parity claim` (commit 6a963db)
- 2026-05-25: `feat: add Install-SystemUpdatesTask.ps1` (commit a42ed8e)
- 2026-05-25: `chore: remove dotfiles/claude-config + Windows/ssh, add CmdletBinding to 4 setup scripts` (commit 02a7709)

---
**Last Updated**: 2026-06-09
