# Windows 11 First-Time Setup

Automated package export and installation for fresh Windows 11 machines.

## Scripts

| Script | Purpose |
|--------|---------|
| [export-current-packages.ps1](export-current-packages.ps1) | Export Winget/Chocolatey packages to JSON/XML |
| [install-from-exported-packages.ps1](install-from-exported-packages.ps1) | Install from exported package lists |
| [fresh-windows-setup.ps1](fresh-windows-setup.ps1) | Complete setup: the Home profile, or the exported package lists |

## Package Lists

| File | Count | Format |
|------|-------|--------|
| [chocolatey-packages.config](chocolatey-packages.config) | 52 | XML |

## Quick Start

```powershell
# On current machine: export packages
.\export-current-packages.ps1

# On new machine: install everything
.\install-from-exported-packages.ps1 -UseLatestVersions

# Or full setup with the Home profile
.\fresh-windows-setup.ps1 -SetupProfile Home
```

## Script Parameters

### export-current-packages.ps1

```powershell
.\export-current-packages.ps1 -OutputDir "C:\Backups"
```

### install-from-exported-packages.ps1

| Parameter | Description |
|-----------|-------------|
| `-UseLatestVersions` | Install latest versions (recommended) |
| `-SkipWinget` | Skip Winget packages |
| `-SkipChocolatey` | Skip Chocolatey packages |
| `-PackageDir` | Custom package directory |

### fresh-windows-setup.ps1

| Parameter | Description |
|-----------|-------------|
| `-SetupProfile Home` | Home profile (includes gaming); omit it to install the exported package lists |
| `-SkipGaming` | Leave out gaming packages (Home profile) |
| `-SkipWSL` | Skip WSL2 setup (exported-package runs only) |
| `-SkipPackageInstall` | Configuration only |
| `-Minimal` | Essential packages only |

## Prerequisites

- Windows 11 with latest updates
- PowerShell 7+ (`winget install Microsoft.PowerShell`)
- Administrator privileges
- Internet connection

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Winget not found | Install "App Installer" from Microsoft Store |
| Chocolatey not found | Script installs automatically, or see [chocolatey.org/install](https://chocolatey.org/install) |
| Package fails | Check logs: `$env:USERPROFILE\.setup-logs\` |
| Access denied | Run PowerShell as Administrator |

## Maintenance

```powershell
# Update all packages
winget upgrade --all
choco upgrade all -y

# Re-export after installing new software
.\export-current-packages.ps1
```

---
**Last Updated**: 2026-09-26
