# Changelog

All notable changes to this project. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project does
not strictly adhere to semantic versioning (it is a personal toolkit, not a
published library) but minor bumps signal new public surface and patch bumps
signal bug fixes only.

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
