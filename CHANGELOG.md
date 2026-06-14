# Changelog

All notable changes to this project. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project does
not strictly adhere to semantic versioning (it is a personal toolkit, not a
published library) but minor bumps signal new public surface and patch bumps
signal bug fixes only.

## [3.0.0] - 2026-06-14

### Removed (ghost-code cull)

Driven by a 2026-06-14 audit (web research + git archaeology) that found ~13 KLOC of production scripts and ~8 KLOC of tests defending behavior with no operational consumer on a single-user laptop. Most categories duplicated either native Windows tools (Task Manager, Event Viewer, `wsl.exe`, Settings) or the lab-server stack on q-lab (Prometheus/Grafana for monitoring, Velero for backup, k9s for Kubernetes). See [BACKLOG.md](BACKLOG.md) for the full rationale.

- **Windows monitoring (entire category):** `Get-ApplicationHealth.ps1`, `Get-EventLogAnalysis.ps1`, `Get-SystemPerformance.ps1`, `Test-NetworkHealth.ps1`, `Watch-ServiceHealth.ps1` + corresponding tests + dir README.
- **Windows backup (5 of 6):** `Backup-BrowserProfiles.ps1`, `Backup-UserData.ps1`, `Export-SystemState.ps1`, `Restore-DeveloperEnvironment.ps1`, `Test-BackupIntegrity.ps1` + corresponding tests. `Backup-DeveloperEnvironment.ps1` survives (snapshot before rebuild).
- **Windows development (2 of 4):** `Test-DevEnvironment.ps1`, `Manage-WSL.ps1` + corresponding tests. `Manage-Docker.ps1` and `remote-development-setup.ps1` survive.
- **Windows reporting:** `Get-SystemReport.ps1` + test + dir README.
- **Windows security:** `Get-UserAccountAudit.ps1` + test + dir README.
- **Windows network (1 of 2):** `Manage-VPN.ps1` + test. `Set-StaticIP.ps1` survives.
- **Linux maintenance (3 of 4):** `log-cleanup.sh`, `restore-previous-state.sh`, `system-update.sh` + tests. `disk-cleanup.sh` survives.
- **Linux monitoring:** `service-health-monitor.sh` + test + dir README (Grafana dashboards in this folder kept as reference).
- **Linux docker:** `docker-cleanup.sh` + tests + dir README.
- **Linux kubernetes:** `pod-health-monitor.sh` + tests + dir README.
- **Linux security:** `security-hardening.sh` + test + dir README (security work lives in `defensive-toolkit`).
- **Umbrella Pester tests:** `Backup.Tests.ps1`, `Monitoring.Tests.ps1`, `Tier2Scripts.Tests.ps1`, `Tier3Scripts.Tests.ps1`, `DeveloperEnvironment.Tests.ps1`. These pre-dated the per-script `*.Behavioral.Tests.ps1` files and were now redundant or referenced deleted scripts.

### Changed

- `README.md`, `QUICKSTART.md`, `BACKLOG.md`, `docs/ROADMAP.md` rewritten to reflect the post-cull scope.
- Subdirectory READMEs (`Windows/backup`, `Windows/network`, `Windows/development`, `Linux/maintenance`, `Linux/monitoring`) updated with scope notes and surviving-script tables.
- `tests/Linux/maintenance.bats` trimmed to cover only `disk-cleanup.sh` (was covering 4 scripts, 3 now deleted).

### Policy

- Cancelled Sprint 7 (Linux coverage gaps) — would have produced more ghost code.
- New rule: any script that goes 6 months without a `fix:` commit triggered by real failure is a candidate for archival, not for additional test scaffolding.

## [2.3.3] - 2026-06-11

### Fixed

- `ci.yml`: repoint `EnricoMi/publish-unit-test-result-action` pin from
  the broken SHA `170bf24d...c0f46f5bb5800e9ce` (commented as v2.18.0
  but never an actual git object - first 23 chars matched, then
  diverged; the real v2.18.0 SHA ends in `403b73ed297e6645b`) to the
  current v2.23.0 SHA `c950f6fb...8838901040` (Feb 2026). Surfaced
  via private-toolkit's post-session audit on 2026-06-11 - the broken
  pin had made CI fail on every push since it was added, including
  v2.3.2's kubernetes-cli exclude commit. Updates two call sites:
  Windows Pester job and Linux Pester job.

## [2.3.2] - 2026-06-10

### Changed

- `system-updates.ps1` `Update-Chocolatey`: split the `--except` list into
  two named variables (`$wingetOwned`, `$versionPinned`) so each exclusion
  carries the reason it exists in the source. Added `kubernetes-cli` to
  `$versionPinned` - it's now pinned to v1.34.x to stay within the
  supported +/-1 minor skew of the K3s v1.33.5 server on q-lab.
  Previously the weekly choco sweep would have bumped kubectl to v1.36.x
  and reopened the skew gap. Bump manually when q-lab K3s upgrades.

## [2.3.1] - 2026-06-09

### Fixed

- `system-updates.ps1`: a pending reboot no longer silently turns the whole
  scheduled run into a no-op. Previously, when a reboot was pending and
  `AutoReboot` was off (the default), the script logged a warning and
  `exit 0`ed *before* running winget/Chocolatey/Windows Update -- yet the
  scheduled task still reported success. On a daily-driver laptop this stalled
  all updates indefinitely. The early `exit 0` is now gated behind `AutoReboot`;
  with `AutoReboot` off the run warns and continues.
- `Test-PendingReboot`: `PendingFileRenameOperations` is no longer a blocking
  signal. It is populated near-constantly by routine app updates (Office, Edge,
  OneDrive, etc.) and on its own does not mean updates must be deferred; it is
  now logged informationally. `Component Based Servicing\RebootPending` and
  `WindowsUpdate\Auto Update\RebootRequired` remain the blocking signals.
- `system-updates.ps1` now disables Windows Fast Startup (`HiberbootEnabled = 0`)
  on every run via the new `Disable-FastStartup` helper. Fast Startup's hybrid
  shutdown hibernates the kernel session instead of fully booting, so a plain
  "Shut down" never runs the boot-time pass that processes
  `PendingFileRenameOperations` / finalizes servicing -- only "Restart" does
  (Microsoft KB 4011287). On a machine that is shut down rather than restarted,
  this stranded in-use updates (e.g. PowerShell) indefinitely. The value is
  re-applied each run because feature updates can silently reset it; hibernation
  is unaffected.
- `system-updates.ps1` now excludes winget-owned packages (PowerShell, Azure CLI,
  Notepad++, Pandoc) from `choco upgrade all` via `--except`, so the two package
  managers no longer both upgrade the same app. Chocolatey continues to own
  everything else (kubectl, the .NET SDKs, python/uv, grype/syft, etc.).
- `fresh-windows-setup.ps1`: Pandoc is now installed via winget for both profiles
  (`$CommonWinget`) and removed from the hardcoded Chocolatey list, so a fresh
  Work-profile setup no longer installs it through both managers.
  `chocolatey-packages.config` no longer lists powershell-core / azure-cli /
  notepadplusplus(.install) / pandoc.
- Added four regression tests in `tests/Windows/SystemUpdates.Tests.ps1` covering
  the continue-on-pending-reboot, informational-file-rename, Fast-Startup-disable,
  and choco-excludes-winget-owned behaviors.

## [2.3.0] - 2026-06-05

### Added

- Behavioral Pester coverage for the four first-time-setup scripts and for
  `Restore-DeveloperEnvironment.ps1` -- 101 new tests across five new files,
  most of which exercise real control flow with mocked external commands
  (winget, choco, code, ssh-keygen, registry, etc.) rather than just
  asserting on file contents.
- `CommonFunctions.psm1` v1.2.0:
  - `Set-LogFile` / `Clear-LogFile` / `Get-LogFile` -- mirror Write-Log
    output (and derivatives) to a file. Lets caller scripts share a
    single logging stack instead of redefining wrappers locally.
  - `Write-Section` -- banner-style section header.
- `Install-SystemUpdatesTask.ps1` -- registers `system-updates.ps1` as a
  Windows scheduled task with laptop-friendly defaults
  (current user with Highest, weekly Sunday 10:00, StartWhenAvailable,
  battery-tolerant, 3h cap). `-SystemAccount` opts into SYSTEM for
  headless scenarios.
- `Restore-DeveloperEnvironment.ps1` v1.1.0: refactored straight-line
  body into `Read-RestoreManifest` / `Restore-ManifestItem` /
  `Restore-VsCodeExtension` / `Invoke-Restore`. `exit 1` paths replaced
  with `throw` so callers can catch failures.
- `backlog.md` -- tactical work queue separate from `docs/ROADMAP.md`.

### Changed

- `CommonFunctions.psm1` v1.2.1: `Write-Log` / `Write-Section` /
  `Write-Success` / `Write-InfoMessage` / `Write-WarningMessage` /
  `Write-ErrorMessage` now accept an empty `Message` string via
  `[AllowEmptyString()]`. Caller scripts use blank `Write-* ""` calls
  for visual spacing; v1.2.0 erroneously threw
  `ParameterBindingValidationException` on those.
- The four setup scripts (`fresh-windows-setup.ps1`,
  `install-from-exported-packages.ps1`, `export-current-packages.ps1`,
  `remote-development-setup.ps1`) now use `CommonFunctions` for
  logging instead of redefining local `Write-Info` /
  `Write-Warning` / `Write-Error` wrappers (the latter two shadowed
  built-in PowerShell cmdlets and tripped `PSAvoidOverwritingBuiltInCmdlets`).
  ~120 lines of duplicated wrapper code retired.
- The same four setup scripts had `#Requires -RunAsAdministrator`
  replaced with a runtime `Assert-Administrator` call at the top of
  `Main()`. Same real-world safety; enables behavioral testing in a
  non-elevated session.
- `install-from-exported-packages.ps1`: replaced
  `Invoke-Expression $((New-Object Net.WebClient).DownloadString(...))`
  in the Chocolatey bootstrap with a download-to-temp + dot-source
  pattern, cleaned up in a `finally` block. Aligns with the
  anti-pattern check the toolkit already enforces against
  maintenance scripts.
- `install-from-exported-packages.ps1`: function renames
  `Install-WingetPackages` -> `Install-WingetPackage`,
  `Install-ChocolateyPackages` -> `Install-ChocolateyPackage`,
  `Refresh-Environment` -> `Update-Environment` (the prior name used
  an unapproved verb).
- `remote-development-setup.ps1`: function renames
  `Setup-SSHClient` -> `Initialize-SSHClient` and equivalents for
  `Setup-VSCodeRemote` / `Setup-PortForwarding` /
  `Setup-DevelopmentWorkspace` / `Configure-WindowsTerminal`. Also
  `Install-RemoteDevTools` -> `Install-RemoteDevTool` (singular noun).
- `docs/ROADMAP.md`: dropped the unfounded "Linux Parity: Achieved"
  claim. New `Linux Coverage` table compares categories side-by-side
  and marks real gaps, Windows-only-by-design, and
  Linux-only-by-design entries.
- `Windows/backup/Backup-DeveloperEnvironment.ps1`: fixed a real bug
  where `Split-Path -Extension` was used (no such parameter exists);
  now uses `[System.IO.Path]::GetExtension()`.

### Removed

- `dotfiles/claude-config/` -- out of scope for a sysadmin toolkit.
- `Windows/ssh/` -- the underlying SSH scripts had been pruned earlier;
  only docs remained, and they were already de-listed from the top-level
  README.

### Tests

- 896 Windows Pester tests passing (was 784 at the start of the cycle).
  Of the +112: 85 are new behavioral tests for setup/restore scripts,
  ~20 are CommonFunctions coverage for the new public functions plus
  the empty-string regression, and a handful update existing structural
  tests for renames.

[2.3.0]: https://github.com/Dashtid/sysadmin-toolkit/compare/v2.2.0...v2.3.0
