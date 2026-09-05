# BACKLOG

Tactical work queue for the toolkit. Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md).

Sizing: **S** under an hour, **M** 1-3 hours, **L** half-day or more.

---

## Current state (2026-06-14, post-cull)

The 2026-06-14 ghost-code audit (driven by web research + git archaeology) cut ~13 KLOC of production scripts and ~8 KLOC of tests defending behavior with no operational consumer.

- **What survived**: 4 first-time-setup scripts, `system-updates.ps1` + `Install-SystemUpdatesTask.ps1`, `Backup-DeveloperEnvironment.ps1`, `Manage-Docker.ps1`, `remote-development-setup.ps1`, `Set-StaticIP.ps1`, `Repair-CommonIssues.ps1`. Linux: `nvidia-gpu-exporter.sh`, `disk-cleanup.sh`, `headless-server-setup.sh`.
- **What was killed**: all 5 `Windows/monitoring/*`, `Windows/reporting/Get-SystemReport.ps1`, `Windows/security/Get-UserAccountAudit.ps1`, `Windows/network/Manage-VPN.ps1`, `Windows/development/Test-DevEnvironment.ps1`, `Windows/development/Manage-WSL.ps1`, 5 of 6 `Windows/backup/*` (only Backup-DeveloperEnvironment survives), `Linux/docker/docker-cleanup.sh`, `Linux/kubernetes/pod-health-monitor.sh`, `Linux/monitoring/service-health-monitor.sh`, `Linux/security/security-hardening.sh`, `Linux/maintenance/{log-cleanup,system-update,restore-previous-state}.sh`.
- **Why**: web research showed these duplicated native tools (Task Manager, Event Viewer, `wsl.exe`, `netsh`, OneDrive, Settings app) or the lab-server stack (Prometheus/Grafana/Velero/k9s). Git history showed 174 commits over 14 months, only ~3 looked like "ran it, broke, fixed". The rest was test backfill and refactor churn — the classic over-engineered-personal-toolkit shape.

**Policy going forward**: any script that goes 6 months without a `fix:` commit triggered by real failure is a candidate for archival. No more "behavioral coverage" sprints — favor smoke tests for the surviving setup scripts; do not mock-pad scripts you do not invoke.

---

## Active work

**Nothing planned.** This is intentional, not a gap.

The toolkit is in maintenance mode. What survives the cull either has a real consumer (the scheduled `system-updates.ps1` task, the lab-server Prometheus scrape of `nvidia-gpu-exporter.sh`) or sits dormant for occasional lifecycle events (fresh-machine re-image, dev-environment snapshot before a rebuild). Marginal maintenance cost is approximately zero unless something actually breaks.

The temptation to add to this list — "shrink X", "refactor Y", "add tests for Z" — is the exact ghost-code pattern that drove the 2026-06-14 cull. Resist it.

### What WOULD legitimately add work here

- A `fix:` commit triggered by a real failure (something broke in actual use). Land the fix, document it, move on.
- A repeated manual workaround that's worth scripting (the "I keep typing this command" signal).
- An external dependency change that forces a real edit (Windows API change, choco package rename, etc.).
- A genuinely new external trigger (new scheduled job, new alert).

### What WOULD NOT

- "It would be cleaner if..." → keep as-is.
- "I should add a test for..." → not without a failure to anchor the test.
- "I could rewrite this in fewer lines" → see [[feedback_no_speculative_test_coverage]] and the cull rationale below.

---

## Cancelled

| Item | Reason |
|------|--------|
| Shrinks: `system-updates.ps1` 873→150, `Manage-Docker.ps1` 1198→100, `Repair-CommonIssues.ps1` 677→200, `Set-StaticIP.ps1` 298→30 | These were tentatively planned in the cull PR but cancelled the same day on reflection. The scripts work. The LOC targets are aesthetic, not functional. Days of work for a personal-use script with no consumer asking for the cleanup. If one of these scripts genuinely needs a fix from real failure later, shrink as part of that fix — not as a standalone sprint. |
| Replace `fresh-windows-setup.ps1` with `winget configure` YAML | Modern alternative is real, but the current bespoke script works and the trigger (re-imaging) happens every 1-3 years. Migration cost ≈ next-rebuild's setup-from-scratch cost. Defer until the next rebuild forces the choice. |
| `.github/PULL_REQUEST_TEMPLATE.md` | Single-author repo, mostly direct commits. Adding ceremony for solo work doesn't help. |
| Sprint 7 — Linux coverage gaps (`system-report.sh`, `repair-common-issues.sh`, `test-network-health.sh`, additional service-health monitor) | All would have been more ghost code. the lab server's existing Prometheus/k9s/journalctl/apt stack covers each gap. |
| Tier 4 (Azure/AWS/OneDrive/change-log/drift-detection/compliance) | Carried from old ROADMAP; nothing in this list is load-bearing today and most fall into the same "duplicates a SaaS" pattern that drove the cull. |

---

## Project history

This section preserves the closeouts from the pre-cull "behavioral coverage" sprints. Most of the code described below was deleted in the 2026-06-14 cull — entries are kept as a record of work done, not as a description of the current codebase.

## Sprint 6 closeouts (test runner + repo hygiene)

- 2026-06-14: `feat(backup): retry once with 5 s backoff on vscode-extension install` (Sprint 6.3) — added 2-attempt retry loop to `Restore-VsCodeExtension`. **This file was subsequently deleted in the 2026-06-14 cull** (the entire Restore-DeveloperEnvironment.ps1 was removed). Entry retained for historical context only.
- 2026-06-14: `chore(tests): unify run-tests.ps1 to also invoke BATS (Sprint 6.1)` (commit 2b1c504) — Added `-Linux` switch to `tests/run-tests.ps1` plus auto-detect when no flags are given. BATS files invoked with `bats --tap`. Survives the cull (general test infrastructure).

## Sprint 5 closeouts (excluded hard scripts, DONE)

- 2026-06-13: `refactor(development): wrap Test-DevEnvironment main in Invoke-DevEnvironmentTest` (Sprint 5.2, refactor-only) — **Test-DevEnvironment.ps1 deleted in cull**. Entry retained for historical context.
- 2026-06-11: `test(monitoring): behavioral coverage for Get-SystemPerformance` (Sprint 5.1) — **Get-SystemPerformance.ps1 deleted in cull**. Found and fixed one production bug at the time (disconnected `-IncludeDiskAnalysis` wire-up). Bug fix lost with the file.

## Sprint 4 closeouts (backup & state, DONE)

132 tests added at the time, +13.96 pp coverage gain. **All 5 of these scripts (Backup-UserData, Backup-BrowserProfiles, Export-SystemState, Test-BackupIntegrity, plus the pair partner Restore-DeveloperEnvironment) were deleted in the cull.** Backup-DeveloperEnvironment (Sprint 4.1) survives. The Sprint 4.2 production bug (`-CompressionLevel SmallestSize` enum/string mismatch) was a real find at the time; the fix lives in the dropped code.

## Sprint 3 closeouts (mutating system & network)

Coverage 28.09% -> 31.24% at the time. **One real production bug fixed.** `Repair-CommonIssues` and `Set-StaticIP` survive; `Manage-VPN`, `system-updates.ps1` survive (system-updates was Sprint 3.1).

- 2026-06-10: `test(network): behavioral coverage for Manage-VPN` (commit 48d04e8, Sprint 3.3) — **Manage-VPN.ps1 deleted in cull**. The pipeline-emission bug fix is lost with the file.

## Sprint 2 closeouts (read-only reporting & audit)

Coverage 20.94% -> 28.09% at the time across 75 new tests. **All 4 scripts (Get-SystemReport, Compare-SoftwareInventory, Get-ApplicationHealth, Get-UserAccountAudit) had their tests deleted in the cull; Compare-SoftwareInventory script survives, the other 3 scripts were deleted.**

## Sprint 1 closeouts (high-ROI monitoring + dev-tooling)

138 tests at the time; 5 real production bugs fixed. **Manage-Docker survives; Manage-WSL, Get-EventLogAnalysis, Test-NetworkHealth, Watch-ServiceHealth were deleted in the cull.** The 5 production bugs (`$host` shadowing, AAAA-record array bug, summary unwrap, Mandatory empty-collection rejection) lived in scripts that are now gone.

## Earlier closeouts (pre-2026-06-05)

- 2026-06-05: `test(backup): behavioral coverage for Restore-DeveloperEnvironment` (commit 7d9b2aa) — file deleted in cull.
- 2026-06-05: setup script test coverage (3 commits) — all setup scripts and their tests survive.
- 2026-05-27: `refactor(setup): approved verbs + lock down iex regression` (commit 20affe7) — survives.
- 2026-05-27: `refactor(setup): use CommonFunctions for logging instead of local wrappers` (commit 42a1dbd) — survives.
- 2026-05-27: `docs: refresh ROADMAP, drop Linux parity claim` (commit 6a963db) — ROADMAP rewritten again in the 2026-06-14 cull.
- 2026-05-25: `feat: add Install-SystemUpdatesTask.ps1` (commit a42ed8e) — survives.

---
**Last Updated**: 2026-06-14
