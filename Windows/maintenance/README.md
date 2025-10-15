# Windows Maintenance Scripts

Automated update and maintenance scripts for Windows systems with support for Chocolatey, Winget, and Windows Update.

## [*] Available Scripts

### system-updates.ps1 (Recommended)
**Version:** 2.0.0
**Purpose:** Comprehensive automated update script with advanced features

**Features:**
- Updates Chocolatey packages
- Updates Winget packages
- Installs Windows Updates (via PSWindowsUpdate module)
- Creates system restore points before updates
- Exports pre-update state for rollback capability
- Configuration file support
- WhatIf mode for dry-run testing
- Update summary with duration tracking
- Progress indicators for long operations
- Automatic reboot handling
- Log retention management

**Usage:**
```powershell
# Basic usage - updates everything
.\system-updates.ps1

# Skip specific update types
.\system-updates.ps1 -SkipWinget
.\system-updates.ps1 -SkipChocolatey
.\system-updates.ps1 -SkipWindowsUpdate

# Dry-run mode (shows what would be updated without doing it)
.\system-updates.ps1 -WhatIf

# Automatic reboot after updates
.\system-updates.ps1 -AutoReboot

# Use custom configuration file
.\system-updates.ps1 -ConfigFile "C:\path\to\config.json"

# Skip system restore point creation
.\system-updates.ps1 -SkipRestorePoint

# Combine options
.\system-updates.ps1 -SkipWinget -AutoReboot -WhatIf
```

**Configuration File:**
Create `config.json` in this directory (or use a custom path with `-ConfigFile`):
```json
{
  "AutoReboot": false,
  "LogRetentionDays": 30,
  "SkipWindowsUpdate": false,
  "SkipChocolatey": false,
  "SkipWinget": false,
  "SkipRestorePoint": false,
  "UpdateTypes": ["Security", "Critical", "Important"]
}
```

See [config.example.json](config.example.json) for a template with detailed comments.

---

### startup_script.ps1
**Version:** 2.0.0
**Purpose:** Simplified update and maintenance script for basic automation

**Features:**
- Updates Chocolatey packages
- Installs Windows Updates
- System cleanup (temp files, Windows Update cache)
- Log file maintenance

**Usage:**
```powershell
.\startup_script.ps1
```

**When to use:**
- Simple scheduled task scenarios
- No need for Winget updates
- No need for restore points or advanced features
- Prefer system-updates.ps1 for production systems

---

### Restore-PreviousState.ps1
**Version:** 1.0.0
**Purpose:** Rollback tool to restore system to pre-update state

**Features:**
- Lists available backup states
- Compares current vs. backup package versions
- Downgrades upgraded packages (Chocolatey/Winget)
- Reinstalls removed packages
- WhatIf mode for safe preview
- Detailed difference reporting

**Usage:**
```powershell
# List all available backups
.\Restore-PreviousState.ps1 -List

# Show differences from latest backup (no changes)
.\Restore-PreviousState.ps1 -Latest -ShowDiff

# Restore from latest backup
.\Restore-PreviousState.ps1 -Latest

# Restore from specific backup file
.\Restore-PreviousState.ps1 -BackupFile "C:\logs\pre-update-state_2025-10-15_10-30-00.json"

# Preview what would be restored (dry-run)
.\Restore-PreviousState.ps1 -Latest -WhatIf
```

**When to use:**
- After problematic updates that break functionality
- To revert packages to known-good versions
- To diagnose update-related issues
- Before attempting manual fixes

**Limitations:**
- Windows updates cannot be rolled back (use System Restore instead)
- Some package downgrades may fail if dependencies conflict
- Rollback does NOT undo system configuration changes

---

### Other Maintenance Scripts

#### setup-scheduled-tasks.ps1
Creates Windows Task Scheduler entries for automated updates.

```powershell
.\setup-scheduled-tasks.ps1
```

#### cleanup-disk.ps1
Performs disk cleanup operations.

#### update-defender.ps1
Updates Windows Defender signatures and definitions.

#### system-integrity-check.ps1
Runs system integrity checks (SFC, DISM).

---

## [!] Prerequisites

### Required Software
- **PowerShell 7.0+** - [Download](https://github.com/PowerShell/PowerShell/releases)
- **Administrator privileges** - All scripts require elevation

### Optional Software
- **Chocolatey** - [Installation Guide](https://chocolatey.org/install)
- **Winget** - Included with Windows 11 and Windows 10 1809+

### PowerShell Modules (Auto-installed)
- **PSWindowsUpdate** - Installed automatically when needed

---

## [+] Quick Start

### First-Time Setup

1. **Install PowerShell 7+** (if not already installed):
   ```powershell
   winget install Microsoft.PowerShell
   ```

2. **Copy configuration template**:
   ```powershell
   Copy-Item config.example.json config.json
   ```

3. **Edit configuration** (optional):
   ```powershell
   notepad config.json
   ```

4. **Run your first update** (dry-run):
   ```powershell
   .\system-updates.ps1 -WhatIf
   ```

5. **Run actual updates**:
   ```powershell
   .\system-updates.ps1
   ```

### Scheduled Task Setup

Run updates automatically every week:

```powershell
# Create a scheduled task using Task Scheduler
$action = New-ScheduledTaskAction -Execute "pwsh.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\system-updates.ps1`" -AutoReboot"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Weekly System Updates" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Automated system updates with Chocolatey, Winget, and Windows Update"
```

---

## [i] Update Summary Example

After running `system-updates.ps1`, you'll see a summary like this:

```
=== Update Summary ===
[+] Chocolatey: 5 packages updated
[+] Winget: 3 packages updated
[+] Windows Updates: 8 updates installed
[+] Restore Point: Created - Before Automated Updates - 2025-10-15 10:30
[!] Reboot Required: YES
[i] Total Runtime: 00:15:23
=====================
```

---

## [*] Logging

### Log Location
All scripts now use a centralized log directory:
```
<toolkit-root>/logs/
```

Example log files:
- `system-updates_2025-10-15.log` - Main log file
- `transcript_system-updates_2025-10-15_10-30-45.log` - Detailed transcript
- `pre-update-state_2025-10-15_10-30-00.json` - Package state before updates

### Log Retention
- Default: 30 days
- Configurable via `LogRetentionDays` parameter or config file
- Automatic cleanup on each run

---

## [!] Safety Features

### System Restore Points
`system-updates.ps1` creates a restore point before updates by default.

**To restore from a restore point:**
```powershell
# List available restore points
Get-ComputerRestorePoint

# Restore to a specific point
Restore-Computer -RestorePoint <RestorePoint>

# Or use System Restore GUI
rstrui.exe
```

### Pre-Update State Export
Each update run exports current package versions to:
```
logs/pre-update-state_<timestamp>.json
```

Use this for rollback if updates cause issues.

### WhatIf Mode
Test updates without making changes:
```powershell
.\system-updates.ps1 -WhatIf
```

---

## [!] Troubleshooting

### Common Issues

#### "Chocolatey is not installed"
Install Chocolatey:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

#### "Winget is not available in PATH"
Winget should be included with Windows 10 1809+ and Windows 11. If missing:
```powershell
# Install App Installer from Microsoft Store (includes Winget)
# Or use winget-cli from GitHub
```

#### "PSWindowsUpdate module fails to install"
Ensure PowerShell Gallery is accessible:
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSWindowsUpdate -Force -AllowClobber
```

#### "Permission denied even as admin"
Ensure you're running in an elevated PowerShell 7+ session:
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check administrator status
[Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
```

#### "Updates fail with no error message"
Check the detailed transcript log:
```powershell
Get-Content "logs\transcript_system-updates_*.log" -Tail 50
```

### Getting Help
```powershell
# View script help
Get-Help .\system-updates.ps1 -Full

# View examples
Get-Help .\system-updates.ps1 -Examples
```

For more troubleshooting tips, see [docs/TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md)

---

## [*] Best Practices

### For Production Systems
1. **Test first** - Use `-WhatIf` mode before actual updates
2. **Use config files** - Avoid command-line parameters for scheduled tasks
3. **Enable restore points** - Don't skip this safety feature
4. **Monitor logs** - Check logs after automated runs
5. **Schedule during maintenance windows** - Update during low-activity periods
6. **Keep backups** - System restore points are NOT a replacement for backups

### For Hyper-V Guests
1. **Snapshot before updates** - Create VM snapshots before major updates
2. **Disable AutoReboot** - Manually reboot VMs on your schedule
3. **Stagger updates** - Don't update all VMs simultaneously
4. **Test on dev VMs first** - Validate updates on non-production VMs

### For Development Workstations
1. **Skip Winget for package managers** - If using scoop, chocolatey-only updates may be preferable
2. **Monitor for breaking changes** - Some updates may break dev tools
3. **Use WhatIf regularly** - Check what will be updated before committing

---

## [v] Version History

### 2.0.0 (2025-10-15)
- Refactored scripts to use CommonFunctions module
- Added system restore point creation
- Added pre-update state export
- Added WhatIf support
- Added update summary with duration tracking
- Centralized log directory management
- Removed redundant security-updates.ps1 (merged into system-updates.ps1)
- Improved error handling and progress reporting

### 1.0.0
- Initial release of system-updates.ps1 and startup_script.ps1
- Basic Chocolatey, Winget, and Windows Update support

---

## [i] Related Documentation

- [Script Templates](../../docs/SCRIPT_TEMPLATE.md) - Guidelines for creating new scripts
- [Security Best Practices](../../docs/SECURITY.md) - Security guidelines
- [Troubleshooting Guide](../../docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Functionality Roadmap](../../docs/ROADMAP.md) - Planned features and enhancements

---

**Last Updated:** 2025-10-15
**Maintainer:** Windows & Linux Sysadmin Toolkit
