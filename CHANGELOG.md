# Changelog

All notable changes to this project. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project does
not strictly adhere to semantic versioning (it is a personal toolkit, not a
published library) but minor bumps signal new public surface and patch bumps
signal bug fixes only.

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
