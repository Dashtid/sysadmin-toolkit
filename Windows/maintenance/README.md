# Windows Maintenance Scripts

Automated update scripts for Chocolatey, Winget, and Windows Update with restore point support.

## Scripts

| Script | Purpose |
|--------|---------|
| [system-updates.ps1](system-updates.ps1) | Full update automation with state export |
| [Install-SystemUpdatesTask.ps1](Install-SystemUpdatesTask.ps1) | Register system-updates.ps1 as a recurring scheduled task |

## Quick Start

```powershell
# Copy config template
Copy-Item config.example.json config.json

# Dry-run first
.\system-updates.ps1 -WhatIf

# Run updates
.\system-updates.ps1
```

## Usage

### system-updates.ps1

```powershell
.\system-updates.ps1                       # Update everything
.\system-updates.ps1 -SkipWinget           # Skip Winget packages
.\system-updates.ps1 -SkipChocolatey       # Skip Chocolatey packages
.\system-updates.ps1 -SkipWindowsUpdate    # Skip Windows Update
.\system-updates.ps1 -SkipRestorePoint     # Skip restore point creation
.\system-updates.ps1 -AutoReboot           # Reboot after updates
.\system-updates.ps1 -WhatIf               # Dry-run mode
.\system-updates.ps1 -ConfigFile "C:\path\to\config.json"
```

## Configuration

Create `config.json` from template:

```powershell
Copy-Item config.example.json config.json
```

| Option | Default | Description |
|--------|---------|-------------|
| AutoReboot | false | Reboot after updates |
| LogRetentionDays | 30 | Days to keep logs |
| SkipWindowsUpdate | false | Skip Windows Update |
| SkipChocolatey | false | Skip Chocolatey packages |
| SkipWinget | false | Skip Winget packages |
| SkipRestorePoint | false | Skip restore point creation |

## Scheduled Updates

### Recommended: Install-SystemUpdatesTask.ps1

```powershell
# From an elevated pwsh, in this directory:
.\Install-SystemUpdatesTask.ps1                                       # Sunday 10:00, current user, no auto-reboot
.\Install-SystemUpdatesTask.ps1 -DayOfWeek Saturday -Time 06:30 -Force # Replace existing task with new schedule
.\Install-SystemUpdatesTask.ps1 -AutoReboot -Force                    # Reboot when updates require it
.\Install-SystemUpdatesTask.ps1 -SystemAccount -Force                 # Run as SYSTEM (see note below)
```

The installer registers a task with laptop-friendly defaults: runs as the current user with `RunLevel=Highest`
(no UAC prompt), weekly on the chosen day/time, `StartWhenAvailable` so a missed window catches up, and
allows starting/continuing on battery.

### Why not SYSTEM?

`winget upgrade --all` running under the SYSTEM account misses user-scope packages -- a documented limitation
of winget. For a dev environment toolkit, the current user with elevated rights is the right default. Use
`-SystemAccount` only for headless server scenarios where no user is interactively logged in.

### Alternative: XML import

For GUI-based installs, see [examples/weekly-updates-task.xml](examples/weekly-updates-task.xml) and
[examples/README.md](examples/README.md). The XML requires manual placeholder replacement before import.

## Log Files

```text
<toolkit-root>/logs/
├── system-updates_YYYY-MM-DD.log           # Main log
├── transcript_system-updates_*.log         # Detailed transcript
└── pre-update-state_*.json                 # Package snapshots
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Chocolatey not installed | See [chocolatey.org/install](https://chocolatey.org/install) |
| Winget not in PATH | Install App Installer from Microsoft Store |
| PSWindowsUpdate fails | `Install-Module -Name PSWindowsUpdate -Force` |
| Permission denied | Run PowerShell 7+ as Administrator |

Use `Get-Help .\system-updates.ps1 -Full` for detailed parameter info.

## Prerequisites

- PowerShell 7.0+
- Administrator privileges
- Chocolatey and/or Winget (optional)

---
**Last Updated**: 2026-05-15
