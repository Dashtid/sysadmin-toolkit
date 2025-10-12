# New Setup & Maintenance Scripts

Documentation for scripts added during initial workstation setup (2025-10-12).

## Directory Structure

```
Windows/
├── first-time-setup/
│   └── package-cleanup.ps1          # Remove redundant packages after initial install
├── security/
│   ├── complete-system-setup.ps1    # Post-hardening fixes (OpenVPN removal, NetBIOS, etc.)
│   ├── fix-netbios.ps1              # Disable NetBIOS via registry method
│   └── system-health-check.ps1      # Comprehensive system verification
└── maintenance/
    ├── setup-scheduled-tasks.ps1    # Create automated maintenance tasks
    ├── fix-monthly-tasks.ps1        # Alternative monthly task creation
    ├── cleanup-disk.ps1             # Disk cleanup script (auto-generated)
    └── system-integrity-check.ps1   # DISM + SFC integrity check (auto-generated)
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

## Security Scripts

### complete-system-setup.ps1

**Purpose**: Post-hardening cleanup and fixes
**Location**: `Windows/security/`
**Requires**: Administrator

**What it does:**
1. Removes OpenVPN client (if you only need VPN server access)
2. Disables NetBIOS over TCP/IP (via WMI method)
3. Enables Exploit Protection (DEP, ASLR, SEHOP)
4. Disables Print Spooler service (if no printer)

**Usage:**
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\security
.\complete-system-setup.ps1
```

**Use Case**: Run after `harden-level1-safe.ps1` to complete security setup

---

### fix-netbios.ps1

**Purpose**: Disable NetBIOS using registry method
**Location**: `Windows/security/`
**Requires**: Administrator

**Why it exists**: The WMI method in hardening scripts may fail with PowerShell 7. This script uses the registry method which is more reliable across PS versions.

**Usage:**
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\security
.\fix-netbios.ps1
```

**What it does:**
- Iterates through all network adapters in NetBT registry
- Sets NetbiosOptions to 2 (Disable)
- Takes effect immediately

**Security Benefit**: Prevents NetBIOS name poisoning attacks on local network

---

### system-health-check.ps1

**Purpose**: Comprehensive system verification after setup/hardening
**Location**: `Windows/security/`
**Requires**: Administrator

**What it checks:**

1. **Security Settings** (6 tests)
   - Windows Defender real-time protection
   - Windows Firewall status
   - UAC enabled
   - SMBv1 disabled
   - Guest account disabled
   - Print Spooler disabled

2. **Scheduled Tasks** (5 tests)
   - Verifies all maintenance tasks exist and are enabled

3. **Network Connectivity** (3 tests)
   - Internet connectivity
   - DNS resolution
   - NetBIOS disabled confirmation

4. **Development Tools** (4 tests)
   - Git installed and configured
   - GitHub CLI authenticated
   - Python installed
   - PowerShell 7 installed

5. **Cleanup Verification** (4 tests)
   - OpenVPN removed
   - Redundant Python versions removed
   - Old credential managers removed
   - OEM bloatware removed

6. **System Resources**
   - Free memory report
   - Free disk space report

**Usage:**
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\security
.\system-health-check.ps1
```

**Output**: Health score percentage and detailed pass/fail report

**Recommended**: Run after major system changes or monthly

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

### fix-monthly-tasks.ps1

**Purpose**: Alternative method to create monthly tasks
**Location**: `Windows/maintenance/`
**Requires**: Administrator

**Why it exists**: Some PowerShell versions don't support `-Monthly` parameter. This uses `-Weekly -WeeksInterval 4` as a workaround.

**Creates:**
- SystemMaintenance-DiskCleanup (every 4 weeks)
- SystemMaintenance-IntegrityCheck (every 4 weeks)

**Usage:** Only needed if `setup-scheduled-tasks.ps1` fails on monthly tasks

---

### cleanup-disk.ps1

**Purpose**: Automated disk cleanup
**Location**: `Windows/maintenance/`
**Auto-generated**: Yes (by setup-scheduled-tasks.ps1)

**What it does:**
- Runs Windows Disk Cleanup utility
- Removes temporary files
- Removes old Windows updates
- Empties Recycle Bin

**Usage:** Typically called by scheduled task, can run manually:
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\maintenance
.\cleanup-disk.ps1
```

---

### system-integrity-check.ps1

**Purpose**: System file integrity verification
**Location**: `Windows/maintenance/`
**Auto-generated**: Yes (by setup-scheduled-tasks.ps1)

**What it does:**
1. Runs DISM `/Online /Cleanup-Image /RestoreHealth`
   - Repairs Windows image corruption
2. Runs SFC `/scannow`
   - Repairs system file corruption

**Usage:** Typically called by scheduled task, can run manually:
```powershell
cd C:\Code\windows-linux-sysadmin-toolkit\Windows\maintenance
.\system-integrity-check.ps1
```

**Duration**: Can take 15-30 minutes depending on system health

---

## Recommended Workflow

### Fresh Windows 11 Installation

1. **Initial Setup**
   ```powershell
   # Run package installers
   cd Windows/first-time-setup
   .\install-packages.ps1

   # Remove redundancies
   .\package-cleanup.ps1
   ```

2. **Security Hardening**
   ```powershell
   cd Windows/security
   .\harden-level1-safe.ps1

   # Fix any failures
   .\complete-system-setup.ps1
   .\fix-netbios.ps1
   ```

3. **Setup Automation**
   ```powershell
   cd Windows/maintenance
   .\setup-scheduled-tasks.ps1

   # If monthly tasks fail
   .\fix-monthly-tasks.ps1
   ```

4. **Verify Everything**
   ```powershell
   cd Windows/security
   .\system-health-check.ps1
   ```

5. **Restart System**

### Monthly Maintenance

Even with automation, periodic manual checks are recommended:

```powershell
# Health check
cd Windows/security
.\system-health-check.ps1

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

**Issue**: NetBIOS disable fails in hardening script
**Solution**: Run `fix-netbios.ps1` separately

**Issue**: Monthly scheduled tasks show as "WARN"
**Solution**: Run `fix-monthly-tasks.ps1`

**Issue**: Health check shows < 90%
**Solution**: Review failed tests, may need manual intervention

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
**Last Updated**: 2025-10-12
