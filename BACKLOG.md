# BACKLOG

Tactical work queue for the toolkit, organized into discrete sprints so the road ahead is visible.
Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Sizing: **S** under an hour, **M** 1-3 hours, **L** half-day or more.

---

## Current state (2026-06-10)

- **Windows behavioral coverage**: 31.24% overall (was 6.68% at session start, +24.56 pp).
- **Pester tests**: 1161 passing, 0 failing.
- **Production bugs found and fixed via testing**: 6 (5 from Sprint 1, 1 from Sprint 3.3).
- **Sprints 1, 2, and 3 all complete.** Setup, restore, monitoring, Docker/WSL, read-only reporting/audit, system updates, and network/repair tooling all behaviorally covered.

Next bottleneck is **backup & state** (Sprint 4: 5 scripts, est. +8-10 pp).
After that, two scripts (Get-SystemPerformance, Test-DevEnvironment) need substantial refactor before they can be tested cleanly.

---

## Sprint plan

| Sprint | Theme | Scripts | Effort | Coverage gain |
|--------|-------|---------|--------|---------------|
| 1 | High-ROI monitoring + dev-tooling | 5 scripts | ~16 hrs | +14.26 pp (DONE) |
| 2 | Read-only reporting & audit | 4 scripts | ~12 hrs | +7.15 pp (DONE) |
| 3 | Mutating system & network | 4 scripts | ~10 hrs | +3.15 pp (DONE) |
| 4 | Backup & state | 5 scripts | ~24 hrs | est. +8-10 pp (NEXT) |
| 5 | Excluded hard scripts | 2 scripts | ~24 hrs | est. +5-7 pp |
| 6 | Test runner + repo hygiene | 3 small items | ~3 hrs | -- |
| 7 | Linux coverage gaps | 4 sh scripts | ~10 hrs | -- |

Cumulative target after Sprint 5: **~55-60% overall coverage**, all Windows scripts behaviorally tested.

---

## Sprint 4 — Backup & state (next)

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

## Sprint 3 closeouts (mutating system & network)

Coverage 28.09% -> 31.24% across 57 new tests. **One real production bug fixed.**

- 2026-06-10: `test(troubleshooting): behavioral coverage for Repair-CommonIssues` (commit 8af368b, Sprint 3.4) - 11 tests. Removed `#Requires -RunAsAdministrator` for dot-source testability; added testability guard. Test strategy: mock Invoke-CommandWithLogging (the orchestrator) and assert on `$Description` so each Repair-X function is a dispatch check rather than a coupling-to-cmdlet check.
- 2026-06-10: `test(network): behavioral coverage for Manage-VPN` (commit 48d04e8, Sprint 3.3) - 19 tests. **Fixed one production bug**: `Remove-VpnProfile` did not discard `Disconnect-VpnProfile`'s return value, so when called on a Connected profile it emitted `@($true, $true)` to the pipeline instead of `$true`. Any caller using `if ($success = Remove-VpnProfile ...)` saw an array-truthy result in either success or partial-failure cases. Wrapped the call in `$null = Disconnect-VpnProfile`.
- 2026-06-10: `test(network): behavioral coverage for Set-StaticIP` (commit ff4c6a5, Sprint 3.2) - 8 tests. Wrapped the straight-line main flow in Invoke-SetStaticIP with a testability guard; replaced inner `exit` with `return`.
- 2026-06-10: `test(maintenance): behavioral coverage for system-updates` (commit a9275ec, Sprint 3.1) - 19 tests. Wrapped top-level try/catch/finally in Invoke-SystemUpdates; removed `#Requires -RunAsAdministrator`. Added `[CmdletBinding(SupportsShouldProcess=$true)]` to Disable-FastStartup, New-SystemRestorePoint, Update-Winget, Update-Chocolatey, Update-Windows so `$PSCmdlet.ShouldProcess` resolves correctly when the helpers are tested in isolation (was null-ref otherwise).

## Sprint 2 closeouts (read-only reporting & audit)

Coverage 20.94% -> 28.09% across 75 new tests; no production bugs found (all four scripts were already well-shaped read-only data collectors).

- 2026-06-10: `test(security): behavioral coverage for Get-UserAccountAudit` (commit 15d0eca, Sprint 2.4) - 17 tests. All seven branches of Get-UserSecurityIssues exercised (PasswordNeverExpires, PasswordNotRequired, IsInactive, old password, CRITICAL admin escalation, built-in Administrator, Guest); Get-UserAccountDetails IsAdmin tagging and disabled-account skipping; Get-AuditSummary aggregation including CRITICAL substring detection. Coverage 23.86% -> 28.09% (+4.23 pp).
- 2026-06-10: `test(setup): behavioral coverage for Compare-SoftwareInventory` (commit 2cf55da, Sprint 2.3) - 18 tests. Wrapped top-level try/catch in Invoke-SoftwareInventoryComparison with a testability guard. Tests cover Winget JSON / Chocolatey XML parsing, all four Compare-PackageLists buckets, Import-Inventory file vs directory dispatch, and Export-MissingPackagesScript output. Coverage delta included in Sprint 2.4 closeout.
- 2026-06-10: `test(monitoring): behavioral coverage for Get-ApplicationHealth` (commit cc40e2e, Sprint 2.2) - 18 tests. Registry app enumeration with x86/x64 tagging from WOW6432Node path, dedup, Windows Store apps, winget upgrade parser, choco outdated parser, Application Error / Hang / WER event mapping, process top-10 filtering, Update-Application package-manager routing.
- 2026-06-10: `test(reporting): behavioral coverage for Get-SystemReport` (commit ef928e1, Sprint 2.1) - 13 tests. Hardware/Software/Network/Security/Performance helpers exercised by mocking each CIM/registry call independently; CPU Architecture switch (9 -> x64), SMBIOSMemoryType switch (26 -> DDR4), UAC ConsentPromptBehaviorAdmin switch, fDenyTSConnections inversion, Get-Counter + Win32_OperatingSystem memory branch. Coverage 20.94% -> 23.86% (+2.92 pp).

## Sprint 1 closeouts (high-ROI monitoring + dev-tooling)

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
**Last Updated**: 2026-06-10
