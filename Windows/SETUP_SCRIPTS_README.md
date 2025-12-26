# Setup & Maintenance Scripts

Documentation for setup and maintenance scripts (2025-10-12).

## Directory Structure

```
Windows/
├── first-time-setup/
│   └── package-cleanup.ps1          # Remove redundant packages after initial install
├── security/
│   └── Get-UserAccountAudit.ps1     # User account security audit
└── maintenance/
    └── setup-scheduled-tasks.ps1    # Create automated maintenance tasks
    # Note: cleanup-disk.ps1 and system-integrity-check.ps1 are auto-generated
    # by setup-scheduled-tasks.ps1 to C:\Code\ at runtime
```

---

## First-Time Setup Scripts

### package-cleanup.ps1

**Purpose**: Remove redundant packages after OS/package installation
**Location**: `Windows/first-time-setup/`
**Requires**: Administrator

**What it removes:**
- Redundant Python versions (keeps latest only)
- Old Git credential managers
- OEM bloatware (HP Support Assistant, etc.)
- Optional: Java/Maven if not needed

**Usage:**
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\first-time-setup
.\package-cleanup.ps1
```

**Expected Results:**
- 1-2 GB disk space freed
- 200+ MB RAM freed (from removed background processes)
- Cleaner PATH environment variable

---

## Maintenance Scripts

### setup-scheduled-tasks.ps1

**Purpose**: Create automated maintenance scheduled tasks
**Location**: `Windows/maintenance/`
**Requires**: Administrator

**Creates 5 tasks:**

1. **SystemMaintenance-WeeklyUpdates**
   - Schedule: Sunday 3AM
   - Action: Runs system-updates.ps1
   - Updates: Chocolatey, Winget, Windows

2. **SystemMaintenance-DefenderFullScan**
   - Schedule: Saturday 2AM
   - Action: Full system malware scan
   - Command: `MpCmdRun.exe -Scan -ScanType 2`

3. **SystemMaintenance-DefenderDefinitions**
   - Schedule: Daily 1AM
   - Action: Update virus definitions
   - Command: `MpCmdRun.exe -SignatureUpdate`

4. **SystemMaintenance-DiskCleanup**
   - Schedule: Every 4 weeks, 4AM
   - Action: Runs cleanup-disk.ps1
   - Removes: Temp files, old updates

5. **SystemMaintenance-IntegrityCheck**
   - Schedule: Every 4 weeks, 5AM
   - Action: Runs system-integrity-check.ps1
   - Checks: DISM + SFC system file integrity

**Usage:**
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\maintenance
.\setup-scheduled-tasks.ps1
```

**Task Settings:**
- Run as SYSTEM account
- Run whether user is logged on or not
- Start when available if missed
- Allow start on battery power
- Don't stop if going on battery

**View Tasks:**
```powershell
# GUI
taskschd.msc

# PowerShell
Get-ScheduledTask | Where-Object {$_.TaskName -like 'SystemMaintenance-*'}
```

---

### Auto-Generated Scripts (by setup-scheduled-tasks.ps1)

The following scripts are auto-generated to `C:\Code\` when `setup-scheduled-tasks.ps1` runs:

#### cleanup-disk.ps1

**Purpose**: Automated disk cleanup (runs Windows Disk Cleanup utility)

#### system-integrity-check.ps1

**Purpose**: System file integrity verification (DISM + SFC)
**Duration**: Can take 15-30 minutes depending on system health

---

## Recommended Workflow

### Fresh Windows 11 Installation

1. **Initial Setup**
   ```powershell
   # Run package installers
   cd Windows/first-time-setup
   .\fresh-windows-setup.ps1 -Profile Work

   # Or install from exported packages
   .\install-from-exported-packages.ps1

   # Remove redundancies
   .\package-cleanup.ps1
   ```

2. **Setup Automation**
   ```powershell
   cd Windows/maintenance
   .\setup-scheduled-tasks.ps1
   ```

3. **Restart System**

### Monthly Maintenance

Even with automation, periodic manual checks are recommended:

```powershell
# Force update check
cd Windows/maintenance
.\system-updates.ps1

# Verify scheduled tasks ran
Get-ScheduledTask | Where-Object {$_.TaskName -like 'SystemMaintenance-*'} | Get-ScheduledTaskInfo
```

---

## Logs and Troubleshooting

### Log Locations

- **Scheduled Tasks**: `Windows/maintenance/logs/`
- **Security Hardening**: `Windows/security/backups/`
- **PowerShell Transcripts**: `C:\PSTranscripts\`

### Common Issues

**Issue**: Scheduled tasks not running
**Solution**: Check Task Scheduler for errors; ensure SYSTEM account has permissions

**Issue**: Package installation failures
**Solution**: Check network connectivity and try running with `-Verbose` flag

---

## Security Considerations

**These scripts:**
- ✓ Create System Restore Points before changes
- ✓ Log all actions
- ✓ Can be rolled back
- ✓ Don't modify user data
- ✓ Don't disable critical services

**These scripts do NOT:**
- ✗ Send data over network
- ✗ Modify credentials
- ✗ Disable Windows security features
- ✗ Install third-party software

---

## Version History

**2025-10-12**: Initial creation
- Added 8 new scripts for workstation setup
- Integrated with existing hardening and maintenance structure
- Tested on Windows 11 Professional (24H2)

---

## Contributing

When adding new scripts:
1. Place in appropriate directory (first-time-setup, security, maintenance, utilities)
2. Update this README
3. Follow naming convention: `verb-noun.ps1`
4. Include help header with `.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`
5. Use consistent logging functions (Write-Success, Write-Info, Write-Error)
6. Test on clean Windows 11 install

---

**Maintained by**: David Dashti
**Repository**: windows-linux-sysadmin-toolkit
**Last Updated**: 2025-12-25
