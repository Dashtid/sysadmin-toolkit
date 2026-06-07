# Backlog

Tactical work queue for the toolkit. Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Items are sized S (under an hour), M (1-3 hours), L (half-day or more) and ordered by priority.

## Active

| # | Item | Notes | Size |
|---|------|-------|------|
| 1 | Unify `tests/run-tests.ps1` to invoke BATS when available | Currently runs Pester (Windows) only. Linux BATS tests are invoked by CI separately. Single-command local test runner would be a quality-of-life win. | S |
| 2 | `.github/PULL_REQUEST_TEMPLATE.md` (optional) | Toolkit has no PR template. Decide whether one would actually help (single-author repo, mostly direct commits) before adding. | S |
| 3 | Add `Restore-VsCodeExtension` retry/backoff | When a vscode-marketplace install times out, retry once with backoff. Low priority -- current behavior just logs and continues. | M |

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

- 2026-06-07: `test(monitoring): behavioral coverage for Get-EventLogAnalysis` - 27 new tests, +3.96 pp overall coverage (11.95% -> 15.91%). Fixed two pre-existing bugs: Summary counters (`Critical`, `Error`, `Warning`, `Information`) returned the matched hashtable's key count instead of 1 when Where-Object returned exactly one event (the classic single-match unwrap trap); and `Get-SystemIssues` / `Get-ApplicationIssues` / `Get-SecurityAnalysis` / `Get-FailedLogonDetails` `[Parameter(Mandatory)][array]$Events` rejected empty collections, crashing the script for non-admins who only specified the Security log.
- 2026-06-07: `test(monitoring): behavioral coverage for Test-NetworkHealth` (commit e080cac) - 27 new tests, +3.37 pp overall coverage (8.58% -> 11.95%). Fixed three pre-existing bugs uncovered by the tests: `$host` automatic-variable in alert messages (used in place of `$targetHost`); empty-string `$DNSServer` not defaulting to 'System Default' due to `??` only triggering on null; and AAAA records lost because `IPAddresses` was a single string not an array (`+=` did string concat). Test refactor pattern matches Watch-ServiceHealth proof.
- 2026-06-06: `test(monitoring): behavioral coverage for Watch-ServiceHealth` (commit 9f0e941) - 23 new tests; Watch-ServiceHealth.ps1 0% -> 41.9%; overall coverage 6.68% -> 8.58%. Established the "wrap main in Invoke-X + testability guard + explicit params" pattern for monitoring scripts.
- 2026-06-05: `test(backup): behavioral coverage for Restore-DeveloperEnvironment` (commit 7d9b2aa) - closed Item 2 from the prior list. Refactored straight-line script into four functions; 20 new behavioral tests.
- 2026-06-05: `test(setup): behavioral coverage for remote-development-setup` (commit b7cd047) - closed Item 1 from the prior list (final setup script). 17 tests.
- 2026-06-05: `test(setup): behavioral coverage for fresh-windows-setup` (commit 616643a) - 23 tests; Work/Home profile branching covered.
- 2026-06-05: `test(setup): behavioral coverage for install-from-exported-packages` (commit 4948960) - 26 tests including the iex-free Chocolatey bootstrap.
- 2026-06-05: `test(setup): behavioral coverage for export-current-packages + empty-Message fix` (commit 08b9022) - 19 tests + uncovered a real production bug (CommonFunctions Mandatory rejecting empty strings).
- 2026-06-05: `test(setup): make setup scripts testable via dot-source` (commit 0612b7e) - testability infrastructure; removed #Requires -RunAsAdministrator from 3 scripts (replaced by runtime Assert-Administrator).
- 2026-05-27: `refactor(setup): approved verbs + lock down iex regression` (commit 20affe7)
- 2026-05-27: `refactor(setup): use CommonFunctions for logging instead of local wrappers` (commit 42a1dbd)
- 2026-05-27: `refactor(setup): singular-noun renames + drop Invoke-Expression` (commit 28607cd)
- 2026-05-27: `docs: refresh ROADMAP, drop Linux parity claim` (commit 6a963db)
- 2026-05-25: `feat: add Install-SystemUpdatesTask.ps1` (commit a42ed8e)
- 2026-05-25: `chore: remove dotfiles/claude-config + Windows/ssh, add CmdletBinding to 4 setup scripts` (commit 02a7709)

---
**Last Updated**: 2026-06-07
