# BACKLOG

Tactical work queue for the toolkit, organized into discrete sprints so the road ahead is visible.
Strategic direction lives in [docs/ROADMAP.md](docs/ROADMAP.md); this file is the "what's next" punch list.

Sizing: **S** under an hour, **M** 1-3 hours, **L** half-day or more.

---

## Current state (2026-06-11)

- **Windows behavioral coverage**: 46.76% overall (was 6.68% at session start, +40.08 pp cumulative).
- **Pester tests**: 1316 passing, 0 failing.
- **Production bugs found and fixed via testing**: 8 (5 from Sprint 1, 1 from Sprint 3.3, 1 from Sprint 4.2, 1 from Sprint 5.1).
- **Sprints 1, 2, 3, 4, and 5 complete (5.2 shipped as refactor-only).**

Next: Sprint 6.1 (unify `tests/run-tests.ps1` to invoke BATS when available).

---

## Sprint plan

| Sprint | Theme | Scripts | Effort | Coverage gain |
|--------|-------|---------|--------|---------------|
| 1 | High-ROI monitoring + dev-tooling | 5 scripts | ~16 hrs | +14.26 pp (DONE) |
| 2 | Read-only reporting & audit | 4 scripts | ~12 hrs | +7.15 pp (DONE) |
| 3 | Mutating system & network | 4 scripts | ~10 hrs | +3.15 pp (DONE) |
| 4 | Backup & state | 5 scripts | ~24 hrs | +13.96 pp (DONE - above +8-10 est) |
| 5 | Excluded hard scripts | 2 scripts | ~24 hrs | +2.64 pp (DONE - 5.2 refactor-only) |
| 6 | Test runner + repo hygiene | 3 small items | ~3 hrs | -- |
| 7 | Linux coverage gaps | 4 sh scripts | ~10 hrs | -- |

Cumulative target after Sprint 5: **~55-60% overall coverage**, all Windows scripts behaviorally tested.

---

## Sprint 4 — Backup & state (DONE)

Highest mutation risk in the entire backlog (file copies, registry exports, restore paths).
Every test must be sandboxed in `$TestDrive`; nothing touches the real user profile.

| # | Script | Lines | Size | Status | Notes |
|---|--------|-------|------|--------|-------|
| 4.1 | `Windows/backup/Backup-DeveloperEnvironment.ps1` | 252 | S | DONE | 16 tests, +0.47 pp. |
| 4.2 | `Windows/backup/Backup-UserData.ps1` | ~1050 | L | DONE | 37 tests, +2.91 pp, 1 bug. |
| 4.3 | `Windows/backup/Backup-BrowserProfiles.ps1` | ~1130 | L | DONE | 34 tests, +3.73 pp. |
| 4.4 | `Windows/backup/Export-SystemState.ps1` | ~920 | L | DONE | 18 tests, +3.56 pp. |
| 4.5 | `Windows/backup/Test-BackupIntegrity.ps1` | ~895 | L | DONE | 27 tests, +3.29 pp. |

---

## Sprint 5 — Excluded hard scripts (DONE)

Both were explicitly excluded from the original survey ranking because they need substantial restructuring before behavioral tests can land. Treat the refactor as the deliverable; tests come after.

| # | Script | Lines | Size | Status | Notes |
|---|--------|-------|------|--------|-------|
| 5.1 | `Windows/monitoring/Get-SystemPerformance.ps1` | ~1500 | L+ | DONE | 23 tests, +2.64 pp, 1 bug. |
| 5.2 | `Windows/development/Test-DevEnvironment.ps1` | 1213 | L+ | DONE (refactor-only) | Refactored Main -> `Invoke-DevEnvironmentTest` with mirrored params + testability guard; `exit N` -> `return N`. Behavioral tests deferred -- 17 CLI stubs (`ssh`, `code`, `gh` ...) collide with Pester discovery; exit-4-empty-output signature couldn't be diagnosed in reasonable time. Refactor still pays for itself: same Main->Invoke pattern that uncovered Bug #8 in 5.1. |

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

## Sprint 5 closeouts (excluded hard scripts, DONE)

- 2026-06-13: `refactor(development): wrap Test-DevEnvironment main in Invoke-DevEnvironmentTest` (Sprint 5.2, refactor-only) - Renamed `Main` to `Invoke-DevEnvironmentTest` with a mirrored param() block (Profile, RequirementsFile, AutoInstall, CheckSSH, CheckExtensions, OutputFormat, OutputPath). Replaced inner `exit 1` and final `exit $exitCode` with `return` so the function returns an exit code cleanly. Added testability guard at the bottom of the file that splats script params into Invoke-DevEnvironmentTest only when not dot-sourced. Behavioral tests **deferred**: this script depends on 17 external CLI tools (git, node, npm, yarn, pnpm, python, pip, docker, kubectl, winget, choco, scoop, ssh, code, gh, az, terraform). Initial attempt to stub them all in a BeforeAll block caused `Invoke-Pester` to fail with exit code 4 and zero output across multiple runs; the SSH probe (`ssh -T git@github.com`) hung past the function stub on a separate attempt. Root cause not pinned down -- likely CLI stub names colliding with native exe resolution and/or the script's `$Profile` parameter shadowing PowerShell's automatic variable when dot-sourced. BACKLOG flagged this script as "most expensive mocking surface in the repo" up front; debugging further has poor expected ROI. Refactor still pays for itself: the same Main->Invoke pattern uncovered Bug #8 in Sprint 5.1. Coverage: 46.76% (unchanged).

- 2026-06-11: `test(monitoring): behavioral coverage for Get-SystemPerformance` (Sprint 5.1) - 23 tests across 9 helpers + Invoke-SystemPerformance top-level. Refactored the straight-line main try/catch into Invoke-SystemPerformance with a mirrored param() block (same Sprint 4.x pattern). Replaced inner `exit 1` with `return 1`; testability guard forwards script params. **Fixed one production bug**: 4 script-level switches/ints carried from a "merged from Watch-DiskSpace.ps1" comment (`-IncludeDiskAnalysis`, `-AutoCleanup`, `-TopFilesCount`, `-TopFoldersCount`) were declared but never actually invoked in main. The `Get-DiskAnalysis` helper existed and was complete, just never called. Reconnected the wire-up: when `-IncludeDiskAnalysis` is set in single-run mode, main now calls `Get-DiskAnalysis -DiskVolumes $metrics.DiskVolumes -EnableAutoCleanup:$AutoCleanup` after metrics collection. Tests cover Get-ThresholdAlerts (Critical/Warning bands, multi-alert combinations, no-alert path), Get-TopProcesses (sort+top-N, PID 0 filter, Get-Process throw), Get-SystemInfo CIM aggregation, Get-LargestFiles >100MB filter, Get-CleanupSuggestions Temp/Windows-Update branches, Invoke-DiskAutoCleanup with Remove-Item / Clear-RecycleBin destructive operations blocked, Get-DiskAnalysis dispatcher (Warning threshold gate, EnableAutoCleanup+Critical-only auto-clean trigger), Export-JSONReport / Export-CSVReport file output, Invoke-SystemPerformance happy path + fatal-error + AlertOnly + IncludeDiskAnalysis wire-up verification. Coverage 44.12% -> 46.76% (+2.64 pp).

## Sprint 4 closeouts (backup & state, DONE)

Total: 132 tests added, +13.96 pp coverage gain (30.16% -> 44.12%), 1 production bug fixed. Above the +8-10 pp estimate. Same wrap-main-in-Invoke-X + mirrored param block pattern across all five scripts; Sprint 4.2 documented why this pattern is necessary (Pester 5 isolates dot-sourced script vars).

- 2026-06-11: `test(backup): behavioral coverage for Test-BackupIntegrity` (Sprint 4.5) - 27 tests across 10 helpers + Invoke-BackupIntegrityTest top-level. Same wrap-main-in-Invoke-BackupIntegrityTest pattern as 4.2-4.4. Tests build a real ZIP archive in $TestDrive with a SHA256 metadata file so the archive helpers can run end-to-end against real bytes. Coverage: Format-FileSize boundaries, Get-BackupInfo archive/folder/corrupt-archive paths, Test-ArchiveStructure valid/corrupt, Get-BackupMetadata archive/folder/missing, Expand-BackupToTemp success+failure, Test-FileHashes skipped/matched/mismatched, Test-FileExtraction readable/corrupt, Restore-ToTarget archive+folder paths and failure, Remove-TempFolder existing+missing, Export-HTMLReport / Export-JSONReport file writing, Invoke-BackupIntegrityTest Restore-without-target returns 1, Quick happy path returns 0, fatal-error returns 1. Coverage 40.83% -> 44.12% (+3.29 pp).
- 2026-06-11: `test(backup): behavioral coverage for Export-SystemState` (Sprint 4.4) - 18 tests across 12 helper functions + Invoke-SystemStateExport top-level. Same wrap-and-mirror refactor pattern as 4.2/4.3: top-level try/catch wrapped in Invoke-SystemStateExport with explicit params, inner `exit N` replaced with `return N`, testability guard forwards script params. Tests cover Get-ExportComponents (All vs explicit), New-ExportFolder timestamp+subdirs, Export-Drivers (Get-PnpDevice + Get-PnpDeviceProperty success and throw), Export-Services, Export-WindowsFeatures, Export-NetworkConfig (adapters/ip-config/dns/routes/firewall), Export-ScheduledTasks (Microsoft\* filter exclusion verified), Export-EventLogs, New-ExportManifest, Compress-ExportFolder (zip+remove and failure fallback), Export-HTMLReport, Export-JSONReport, Invoke-SystemStateExport DryRun returns 0, fatal-error returns 1, dispatcher only invokes listed components. Coverage 37.27% -> 40.83% (+3.56 pp, crossed the 40% threshold).
- 2026-06-11: `test(backup): behavioral coverage for Backup-BrowserProfiles` (Sprint 4.3) - 34 tests across 11 helpers + Invoke-BrowserProfileBackup top-level. Renamed `Main` to `Invoke-BrowserProfileBackup` with a mirrored param() block so the testability guard forwards all script params explicitly (same pattern as Sprint 4.2). Replaced inner `exit N` with `return N`. Added explicit `-Path` to Get-BackupDirectory and `-BackupDir` to Get-BackupList so they are independently testable. **New Pester gotcha documented**: Get-Content's `-Path` and `-LiteralPath` are separate parameters; a ParameterFilter on `$Path` does not see `-LiteralPath` values, so when tests verify written files via `Get-Content -LiteralPath`, the mock's filter still fires and returns the mocked content instead of the real file. Workaround: read verification files via `[System.IO.File]::ReadAllText()` to bypass Pester's mock entirely. Coverage 33.54% -> 37.27% (+3.73 pp).
- 2026-06-11: `test(backup): behavioral coverage for Backup-UserData` (Sprint 4.2) - 37 tests across 11 helper functions + Invoke-UserDataBackup top-level. Wrapped 160-line main try/catch in Invoke-UserDataBackup function; replaced inner `exit 1` with `return 1` so the main flow returns an exit code cleanly. **Pester scope discovery**: helpers in the original script read `$VerifyBackup`, `$CompressionLevel`, `$RetentionCount`, `$RetentionDays`, `$DryRun`, etc. via dynamic scope from the script's param block. Pester 5 isolates the dot-sourced script's variables in a scope NOT reachable by `$script:` or `$global:` from the It block, so the test cannot override them after the fact. Solution was to refactor the helpers to take explicit parameters (`Copy-BackupFiles -ComputeHash`, `Compress-BackupFolder -Level`, `Remove-OldBackups -KeepCount/-KeepDays`) and add a full mirrored `param()` block to Invoke-UserDataBackup with the testability guard forwarding all script params. The refactor improves the production code too — explicit beats implicit dynamic scope reads. **Fixed one production bug**: the script accepts `-CompressionLevel SmallestSize` (mapped to `[System.IO.Compression.CompressionLevel]::SmallestSize` enum) but `Compress-Archive`'s `-CompressionLevel` parameter is `[string]` with ValidateSet limited to `Optimal`/`Fastest`/`NoCompression` — so any user picking SmallestSize hit the silent catch path and got "Compression failed". Removed SmallestSize from the script's and helper's ValidateSets and switched the Compress-Archive call to pass the string name. Coverage 30.63% -> 33.54% (+2.91 pp).
- 2026-06-10: `test(backup): behavioral coverage for Backup-DeveloperEnvironment` (Sprint 4.1) - 16 tests. Wrapped straight-line body in `Invoke-DeveloperEnvironmentBackup` with `[CmdletBinding(SupportsShouldProcess=$true)]`; replaced inner `exit 1` with `return $null`; added testability guard. **Pester quirk discovered**: in PS7, `Out-File`'s `-Encoding` parameter has an `ArgumentTransformationAttribute` that converts strings like `"UTF8"` to encoding objects; Pester's `Mock Out-File` replicates the parameter type but NOT the transformer, so mocking `Out-File` breaks the script's `-Encoding UTF8` call with a binding error. Workaround: tests that need the manifest/extensions code paths leave `Out-File` and `New-Item` unmocked so real cmdlets write into `$TestDrive`. Documented inline at the top of the test file. Coverage 30.16% -> 30.63% (+0.47 pp).

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
