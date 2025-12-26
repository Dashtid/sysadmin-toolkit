# Windows Maintenance Scripts

Automated update scripts for Chocolatey, Winget, and Windows Update with restore point support.

## Scripts

| Script | Purpose |
|--------|---------|
| [system-updates.ps1](system-updates.ps1) | Full update automation with state export |
| [Restore-PreviousState.ps1](Restore-PreviousState.ps1) | Rollback to pre-update package state |
| [startup_script.ps1](startup_script.ps1) | Simplified updates and cleanup |
| [setup-scheduled-tasks.ps1](setup-scheduled-tasks.ps1) | Create scheduled update tasks |

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

### Restore-PreviousState.ps1

```powershell
.\Restore-PreviousState.ps1 -List          # List available backups
.\Restore-PreviousState.ps1 -Latest -ShowDiff  # Preview changes
.\Restore-PreviousState.ps1 -Latest        # Restore from latest
.\Restore-PreviousState.ps1 -Latest -WhatIf    # Dry-run restore
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

```powershell
# Weekly Sunday 3 AM
$action = New-ScheduledTaskAction -Execute "pwsh.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\system-updates.ps1`" -AutoReboot"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Weekly System Updates" -Action $action -Trigger $trigger -Principal $principal
```

## Log Files

```
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
**Last Updated**: 2025-12-26
