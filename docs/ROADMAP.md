# Functionality Expansion Roadmap

This document outlines potential future enhancements for the Windows & Linux Sysadmin Toolkit based on industry best practices and common sysadmin needs identified in 2025.

**Status**: Active Development - Tier 1, Tier 2, Tier 3, & Quick Wins Complete
**Last Updated**: 2025-12-25

## Current Coverage Analysis

### Strengths (Implemented)
- [+] SSH agent setup and tunnel management
- [+] First-time Windows setup and package management
- [+] Security hardening (3-tier approach with audit/backup/restore)
- [+] Windows Update automation (security and system updates)
- [+] Basic Linux server and desktop setup
- [+] Development environment configuration
- [+] Scheduled task management

### Gaps Identified

- [+] System performance monitoring and alerting (COMPLETED - Get-SystemPerformance.ps1)
- [+] Automated backup and disaster recovery (COMPLETED - Backup-UserData.ps1)
- [+] Network diagnostics and management (COMPLETED - Test-NetworkHealth.ps1)
- [+] User and permission auditing (PARTIAL - Get-UserAccountAudit.ps1)
- [+] Event log analysis and security monitoring (COMPLETED - Get-EventLogAnalysis.ps1)
- [+] Application health monitoring (COMPLETED - Get-ApplicationHealth.ps1)
- [-] Cloud integration (Azure/AWS/OneDrive)
- [+] Comprehensive troubleshooting toolkit (COMPLETED - Repair-CommonIssues.ps1)

---

## Category 1: Monitoring & Alerting

**Priority**: CRITICAL
**Current Status**: COMPLETE

### 1.1 System Performance Monitor [COMPLETED]

**Effort**: 2-3 hours
**Impact**: High - Proactive issue detection

**Features**:
- Monitor CPU, RAM, Disk I/O, Network usage
- Configurable threshold alerts
- Performance trend tracking over time
- Generate HTML/JSON reports
- Export metrics for external tools

**Implementation Notes**:
```powershell
# Use Get-Counter for performance metrics
# Store historical data in JSON/CSV
# Alert via email or Windows notifications
# Integration with Windows Performance Monitor
```

### 1.2 Service Health Monitor [COMPLETED]

**Effort**: 2-3 hours
**Impact**: High - System reliability

**Features**:
- Monitor critical Windows services (configurable list)
- Auto-restart failed services with retry logic
- Email/notification on service failures
- Service dependency checking
- Service startup history tracking

**Implementation Notes**:
```powershell
# Use Get-Service and Get-CimInstance
# Scheduled task for continuous monitoring
# Log service state changes
# Integration with Event Log
```

### 1.3 Disk Space Monitor & Alert
**Effort**: 1-2 hours
**Impact**: Medium - Prevent disk full issues

**Features**:
- Monitor all drives for low space (threshold-based)
- Identify top 20 largest files/folders
- Safe cleanup suggestions (temp files, logs)
- Generate space usage reports
- Automatic cleanup of temp files when threshold reached

**Implementation Notes**:
```powershell
# Now integrated into Get-SystemPerformance.ps1
# Use -IncludeDiskAnalysis for detailed analysis
# Use -AutoCleanup for automatic cleanup
```

### 1.4 Event Log Analyzer [COMPLETED]

**Effort**: 3-4 hours
**Impact**: High - Security & troubleshooting

**Features**:
- Parse Windows Event Logs (Application, Security, System)
- Filter critical errors and warnings
- Generate security incident reports
- Track failed logon attempts
- Detect privilege escalation attempts
- Export to HTML/CSV for analysis

**Implementation Notes**:
```powershell
# Use Get-WinEvent with FilterHashtable
# Categorize events by severity
# Pattern detection for common issues
# Integration with security auditing
```

---

## Category 2: Backup & Disaster Recovery

**Priority**: CRITICAL
**Current Status**: COMPLETE (user backup, system state, and validation)

### 2.1 Automated User Backup Script [COMPLETED]

**Effort**: 3-4 hours
**Impact**: Critical - Data protection

**Features**:
- Backup user documents, desktop, downloads
- Support for custom folder selection
- Scheduled backups (daily/weekly)
- Incremental backup support
- Backup to local/network/cloud destinations
- Compression and encryption options
- Backup verification and integrity checks
- Rotation policy (keep last N backups)

**Implementation Notes**:
```powershell
# Use Robocopy for efficient file copying
# 7-Zip for compression
# Hash verification for integrity
# Integration with OneDrive/network shares
```

### 2.2 Complete System State Snapshot [COMPLETED]

**Effort**: 1-2 hours
**Impact**: Medium - Faster recovery

**Features**:
- Expand existing backup functionality
- Export installed applications list (Winget + Chocolatey)
- Export all registry hives
- Driver list and versions
- Network configuration (IP, DNS, routes)
- Scheduled tasks export
- Windows features and optional features
- PowerShell profile and scripts

**Implementation Notes**:
```powershell
# Windows/backup/Export-SystemState.ps1
# Exports drivers, registry, network, tasks, features, services, packages
# Supports -Compress for ZIP archive, -IncludeEventLogs for event logs
# Multiple output formats: Console, HTML, JSON, All
```

### 2.3 Backup Validation & Recovery Testing [COMPLETED]

**Effort**: 2-3 hours
**Impact**: High - Confidence in disaster recovery

**Features**:
- Verify backup files are not corrupted
- Test restore procedures (dry run)
- Validate backup integrity (checksums)
- Generate recovery test reports
- Automated recovery testing on schedule

**Implementation Notes**:
```powershell
# Windows/backup/Test-BackupIntegrity.ps1
# TestType: Quick (sample hashes), Full (extract all), Restore (actual restore)
# SHA256 hash verification against backup_metadata.json
# Multiple output formats: Console, HTML, JSON, All
```

---

## Category 3: Network Management

**Priority**: HIGH
**Current Status**: Partial (diagnostics complete, VPN and firewall pending)

### 3.1 Network Diagnostics Suite [COMPLETED]

**Effort**: 1-2 hours
**Impact**: High - Troubleshooting

**Features**:
- Test connectivity to configured hosts
- DNS resolution validation
- Port availability testing (common ports)
- Network speed test (iperf/speedtest-cli)
- Traceroute to key destinations
- Generate network health reports
- Detect proxy/DNS issues

**Implementation Notes**:
```powershell
# Use Test-Connection, Test-NetConnection
# Resolve-DnsName for DNS checks
# Generate HTML report with results
# Color-coded pass/fail indicators
```

### 3.2 VPN Management Helper [COMPLETED]

**Effort**: 2-3 hours
**Impact**: Medium - Remote work reliability

**Features**:
- Auto-connect VPN on startup
- VPN connection health monitoring
- Switch between VPN profiles
- Troubleshoot common VPN issues
- VPN reconnect on disconnect
- Log VPN connection events

**Implementation Notes**:
```powershell
# Use rasdial or VPN cmdlets
# Extend gitea-tunnel-manager approach
# Support multiple VPN types
```

### 3.3 Firewall Rule Management
**Effort**: 2-3 hours
**Impact**: Medium - Security & connectivity

**Features**:
- List all active firewall rules
- Add/remove rules programmatically
- Export/import rule sets
- Audit suspicious or unused rules
- Backup and restore firewall configuration
- Block/allow by port, IP, or application

**Implementation Notes**:
```powershell
# Use Get-NetFirewallRule
# Integration with security hardening
# Rule validation and conflict detection
```

---

## Category 4: User & Permission Management

**Priority**: MEDIUM
**Current Status**: Partial (user audit complete, permission reporter pending)

### 4.1 User Account Audit Script [COMPLETED]

**Effort**: 1-2 hours
**Impact**: High - Security compliance

**Features**:
- List all local user accounts
- Check administrator group membership
- Identify inactive/dormant accounts
- Password expiration tracking
- Last logon time for all users
- Detect accounts with no password
- Generate compliance reports (HTML/CSV)

**Implementation Notes**:
```powershell
# Use Get-LocalUser, Get-LocalGroupMember
# Active Directory integration (if applicable)
# Report generation with recommendations
```

### 4.2 Permission Reporter & Auditor
**Effort**: 2-3 hours
**Impact**: Medium - Security & access control

**Features**:
- Scan folder permissions recursively
- Identify overly permissive shares
- Detect "Everyone" or "Authenticated Users" access
- Generate access control reports
- Suggest permission fixes
- Export to CSV for review

**Implementation Notes**:
```powershell
# Use Get-Acl for NTFS permissions
# Get-SmbShare for network shares
# Highlight security risks
```

---

## Category 5: Application Management

**Priority**: MEDIUM
**Current Status**: COMPLETE (health monitoring, inventory comparison, browser backup)

### 5.1 Application Health Monitor [COMPLETED]

**Effort**: 2-3 hours
**Impact**: Medium - Application availability

**Features**:
- Check if critical applications are installed
- Verify application versions (detect outdated)
- Detect application crashes (Event Log)
- Auto-update apps via Winget/Chocolatey
- Monitor application resource usage
- Generate application status report

**Implementation Notes**:
```powershell
# Query installed programs registry
# Use Winget list and choco list
# Event log parsing for app crashes
```

### 5.2 Software Inventory & Comparison [COMPLETED]

**Effort**: 1-2 hours
**Impact**: Low - Asset management

**Features**:
- Generate complete installed software list
- Compare installed software across machines
- License compliance checking
- Detect bloatware/unwanted software
- Export inventory to CSV/JSON
- Track software changes over time

**Implementation Notes**:
```powershell
# Windows/first-time-setup/Compare-SoftwareInventory.ps1
# Compare baseline to file or live system
# Sources: Winget, Chocolatey, Registry, All
# Detects: Added, Removed, VersionChanged packages
# -ExportMissing generates install script for missing packages
```

### 5.3 Browser Profile Backup & Restore [COMPLETED]

**Effort**: 2-3 hours
**Impact**: Medium - User convenience

**Features**:
- Backup browser bookmarks and settings
- Support Chrome, Edge, Firefox
- Restore bookmarks to new machine
- Scheduled bookmark backups
- Extension list export
- History and password notes (not actual passwords)

**Implementation Notes**:
```powershell
# Locate browser profile directories
# Copy specific files (bookmarks, preferences)
# Cross-browser restore capability
```

---

## Category 6: Development Environment

**Priority**: LOW
**Current Status**: COMPLETE

### 6.1 Development Environment Validator [COMPLETED]

**Effort**: 1-2 hours
**Impact**: Medium - Dev setup reliability

**Features**:
- Verify Git, Node.js, Python, etc. are installed
- Check for correct versions
- Test PATH configuration
- Validate SSH keys setup
- Check IDE installations (VSCode, Visual Studio)
- Install missing development tools
- Generate development environment report

**Implementation Notes**:
```powershell
# Extend remote-development-setup.ps1
# Version checking with Get-Command
# Automated tool installation
```

### 6.2 Docker Management Suite (Windows) [COMPLETED]

**Effort**: 2-3 hours
**Impact**: Low - Docker workflow

**Features**:
- Start/stop Docker containers
- Clean up unused images/volumes
- Health check running containers
- Resource usage monitoring
- Container logs viewer
- Quick container restart

**Implementation Notes**:
```powershell
# Use docker CLI via PowerShell
# Docker Desktop integration
# Container orchestration helpers
```

### 6.3 WSL2 Setup & Management [COMPLETED]

**Effort**: 3-4 hours
**Impact**: Medium - Linux dev on Windows

**Features**:
- Install and configure WSL2
- Backup WSL2 distributions (export)
- Restore WSL2 distributions (import)
- Resource limit management (wslconfig)
- Cross-platform file synchronization
- WSL2 network troubleshooting

**Implementation Notes**:
```powershell
# Use wsl.exe commands
# Integration with Windows Terminal
# Automated Ubuntu/Debian setup
```

---

## Category 7: Reporting & Documentation

**Priority**: LOW
**Current Status**: Partial (system reporter complete, change tracker pending)

### 7.1 System Information Reporter [COMPLETED]

**Effort**: 2-3 hours
**Impact**: Medium - Documentation

**Features**:
- Generate comprehensive system report
- Hardware inventory (CPU, RAM, GPU, storage)
- Software inventory (OS, apps, updates)
- Network configuration
- Security settings audit
- Export to HTML, PDF, or JSON
- Compare reports across machines

**Implementation Notes**:
```powershell
# Use Get-ComputerInfo, Get-CimInstance
# HTML template with CSS styling
# Include charts/graphs for visual appeal
```

### 7.2 System Change Log Tracker
**Effort**: 4-5 hours
**Impact**: Low - Change management

**Features**:
- Track system changes over time
- Compare before/after system states
- Identify unauthorized changes
- Configuration drift detection
- Compliance reporting
- Integration with backup/audit scripts

**Implementation Notes**:
```powershell
# Daily snapshot of system state
# Diff comparison between snapshots
# Alert on significant changes
# Integration with Git for versioning
```

---

## Category 8: Cloud Integration

**Priority**: LOW
**Current Status**: Missing

### 8.1 Azure/AWS Resource Manager
**Effort**: 4-5 hours
**Impact**: Low - Cloud management

**Features**:
- List cloud resources (VMs, storage, etc.)
- Start/stop VMs to save costs
- Monitor cloud spending
- Backup cloud configurations
- Automated resource provisioning
- Cloud cost optimization suggestions

**Implementation Notes**:
```powershell
# Use Az PowerShell module for Azure
# AWS Tools for PowerShell for AWS
# Cloud-agnostic abstraction layer
```

### 8.2 OneDrive/SharePoint Sync Manager
**Effort**: 2-3 hours
**Impact**: Medium - File sync reliability

**Features**:
- Monitor OneDrive sync status
- Fix common sync issues
- Manage selective sync folders
- Report sync errors with solutions
- Force sync of specific folders
- Sync health dashboard

**Implementation Notes**:
```powershell
# Query OneDrive sync client status
# Registry-based sync configuration
# Event log parsing for errors
```

---

## Category 9: Troubleshooting & Repair

**Priority**: MEDIUM
**Current Status**: COMPLETE

### 9.1 Common Issue Auto-Fixer [COMPLETED]

**Effort**: 3-4 hours
**Impact**: High - Self-service troubleshooting

**Features**:
- Fix DNS resolution issues (flush DNS, reset)
- Reset network adapter configuration
- Repair Windows Update issues
- Fix corrupted user profiles
- Clear problematic caches (temp, browser, etc.)
- Reset Windows Store cache
- Fix audio/video issues
- Repair printer connections

**Implementation Notes**:
```powershell
# ipconfig /flushdns, netsh commands
# Windows Update reset scripts
# SFC and DISM integration
# User-friendly menu interface
```

### 9.2 System Repair Toolkit
**Effort**: 2-3 hours
**Impact**: Medium - System stability

**Features**:
- Run SFC /scannow (System File Checker)
- DISM repair operations
- Check disk integrity (chkdsk)
- Fix boot configuration (bcdedit)
- Registry backup and repair
- Component store cleanup
- Windows image health check

**Implementation Notes**:
```powershell
# Use Repair-CommonIssues.ps1 -Fix SystemFiles
# Elevated privilege requirements
# Progress reporting for long operations
# Pre-check to determine needed repairs
```

---

## Implementation Priorities

### Tier 1: Critical (Immediate Value) [COMPLETED]

1. [x] System Performance Monitor - Windows/monitoring/Get-SystemPerformance.ps1
2. [x] Service Health Monitor - Windows/monitoring/Watch-ServiceHealth.ps1
3. [x] Automated User Backup Script - Windows/backup/Backup-UserData.ps1
4. [x] Network Diagnostics Suite - Windows/monitoring/Test-NetworkHealth.ps1
5. [x] Event Log Analyzer - Windows/monitoring/Get-EventLogAnalysis.ps1

**Total Effort**: ~13-16 hours
**Status**: COMPLETE (2025-11-30)
**Impact**: Critical infrastructure monitoring and data protection

### Tier 2: High Value (Next Phase) [COMPLETED]

6. [x] User Account Audit - Windows/security/Get-UserAccountAudit.ps1
7. [x] Common Issue Auto-Fixer - Windows/troubleshooting/Repair-CommonIssues.ps1
8. [x] Disk Space Monitor - Merged into Get-SystemPerformance.ps1 (-IncludeDiskAnalysis)
9. [x] Application Health Monitor - Windows/monitoring/Get-ApplicationHealth.ps1
10. [x] System Information Reporter - Windows/reporting/Get-SystemReport.ps1

**Total Effort**: ~11-14 hours
**Status**: COMPLETE (2025-11-30)
**Impact**: Security compliance and troubleshooting efficiency

### Tier 3: Nice to Have (Future) [COMPLETED]

11. [x] Browser Profile Backup - Windows/backup/Backup-BrowserProfiles.ps1
12. [x] VPN Management Helper - Windows/network/Manage-VPN.ps1
13. [x] WSL2 Setup & Management - Windows/development/Manage-WSL.ps1
14. [x] Docker Management Suite - Windows/development/Manage-Docker.ps1
15. [x] Development Environment Validator - Windows/development/Test-DevEnvironment.ps1

**Total Effort**: ~11-14 hours
**Status**: COMPLETE (2025-11-30)
**Impact**: User convenience and development workflows

### Tier 4: Advanced (Long-term)
16. Cloud Integration (Azure/AWS)
17. System Change Log Tracker
18. Permission Reporter
19. OneDrive Sync Manager
20. Firewall Rule Management

**Total Effort**: ~15-20 hours
**Impact**: Enterprise-level features and compliance

---

## Quick Wins (1-2 hours each) [COMPLETED]

These can be implemented quickly with high value:

- [x] Disk Space Monitor expansion (extend existing cleanup script)
- [x] User Account Audit script
- [x] Software Inventory expansion - Compare-SoftwareInventory.ps1 (NEW 2025-12-25)
- [x] Network Diagnostics Suite (basic version)
- [x] Development Environment Validator
- [x] System State Export - Export-SystemState.ps1 (NEW 2025-12-25)
- [x] Backup Validation - Test-BackupIntegrity.ps1 (NEW 2025-12-25)

**Total Effort**: ~5-10 hours
**Status**: COMPLETE (2025-12-25)
**Value**: Immediate improvement to toolkit completeness

---

## Integration Points

### With Existing Scripts

- **Performance Monitor** → Includes disk cleanup via -AutoCleanup parameter
- **Event Log Analyzer** → Integrate with Get-UserAccountAudit.ps1
- **Backup Script** → Backup-UserData.ps1 handles user data and settings
- **Service Monitor** → Extend startup_script.ps1 capabilities
- **Network Diagnostics** → Use in gitea-tunnel-manager.ps1 health checks

### With CommonFunctions Module:
- All new scripts should use CommonFunctions.psm1 for:
  - Logging (Write-Success, Write-InfoMessage, etc.)
  - Admin privilege checking (Test-IsAdministrator)
  - PowerShell 7 detection
  - Consistent color scheme

---

## Testing Strategy

For each new script category:

1. **Unit Tests** (Pester)
   - Function-level tests
   - Parameter validation
   - Error handling

2. **Integration Tests**
   - Cross-script interactions
   - Module dependencies
   - System integration

3. **Manual Testing**
   - Real-world scenarios
   - Edge cases
   - Performance validation

4. **Documentation**
   - Comment-based help
   - Usage examples
   - Known limitations

---

## Success Metrics

Track implementation progress:

- [x] Monitoring category (4/4 scripts) - COMPLETE
  - Get-SystemPerformance.ps1
  - Watch-ServiceHealth.ps1
  - Get-EventLogAnalysis.ps1
  - Disk Space Monitor (integrated into Get-SystemPerformance.ps1)
- [x] Backup category (4/3 scripts - exceeds target)
  - Backup-UserData.ps1 (includes security settings backup)
  - Backup-BrowserProfiles.ps1
  - Export-SystemState.ps1 (NEW 2025-12-25)
  - Test-BackupIntegrity.ps1 (NEW 2025-12-25)
- [x] Network category (2/3 scripts)
  - Test-NetworkHealth.ps1 (NEW)
  - Manage-VPN.ps1 (NEW)
- [x] User management (1/2 scripts) - Get-UserAccountAudit.ps1 (NEW)
- [x] Application management (3/3 scripts - COMPLETE)
  - Get-ApplicationHealth.ps1 (NEW)
  - Backup-BrowserProfiles.ps1 (NEW)
  - Compare-SoftwareInventory.ps1 (NEW 2025-12-25)
- [x] Development tools (4/3 scripts - exceeds target)
  - remote-development-setup.ps1 (existing)
  - Manage-WSL.ps1 (NEW)
  - Manage-Docker.ps1 (NEW)
  - Test-DevEnvironment.ps1 (NEW)
- [x] Reporting (1/2 scripts) - Get-SystemReport.ps1 (NEW)
- [ ] Cloud integration (0/2 scripts)
- [x] Troubleshooting (1/2 scripts)
  - Repair-CommonIssues.ps1 (includes SFC/DISM via -Fix SystemFiles)

**Windows Completion**: ~85% of identified functionality
**Tier 1 Status**: COMPLETE (2025-11-30)
**Tier 2 Status**: COMPLETE (2025-11-30)
**Tier 3 Status**: COMPLETE (2025-11-30)
**Quick Wins Status**: COMPLETE (2025-12-25)
**Target Phase 4**: 95% completion (Tier 4 advanced features)

---

## Linux Parity Initiative (2025-12-25)

Closing the gap between Windows and Linux script coverage.

### Completed Linux Scripts

- [x] **Security Hardening** - Linux/security/security-hardening.sh (NEW)
  - SSH hardening (key-only auth, disable root login, secure ciphers)
  - Firewall configuration (UFW with sensible defaults)
  - Kernel hardening (sysctl security parameters)
  - File permission auditing (sensitive files, SUID/SGID)
  - User security (password policies, inactive accounts)
  - Service hardening (disable risky services)
  - Automatic security updates
  - Audit mode + apply mode with backups

- [x] **Service Health Monitor** - Linux/monitoring/service-health-monitor.sh (NEW)
  - Monitor critical services (configurable list)
  - Auto-restart failed services with retry logic
  - Multiple alert methods (log, email, Slack)
  - Prometheus metrics export
  - Daemon mode with configurable interval
  - JSON config file support

### Linux Test Coverage

- [x] CommonFunctions.bats - 60+ tests for bash library
- [x] maintenance.bats - Maintenance script tests
- [x] SystemHealthCheck.bats - NEW: 40+ tests
- [x] SecurityHardening.bats - NEW: 60+ tests
- [x] ServiceHealthMonitor.bats - NEW: 50+ tests

**Linux Test Total**: 5 BATS test files, 200+ test assertions

### CI/CD Improvements

- [x] Strict shellcheck (removed || true, proper exclusions)
- [x] All BATS tests run in CI
- [x] Severity threshold: warning level

---

## Notes

- This roadmap is based on industry best practices and common sysadmin needs identified in 2025
- Effort estimates assume familiarity with PowerShell and system administration
- Priorities may shift based on specific use cases and requirements
- Some scripts may be combined for efficiency (e.g., monitoring suite)
- Consider creating subcategories of "monitoring" or "backup" directories as scripts grow

**Last Analysis Date**: 2025-10-12
**Tier 1 Completed**: 2025-11-30
**Tier 2 Completed**: 2025-11-30
**Tier 3 Completed**: 2025-11-30
**Quick Wins Completed**: 2025-12-25 (Export-SystemState, Test-BackupIntegrity, Compare-SoftwareInventory)
**Linux Parity**: 2025-12-25 (security-hardening.sh, service-health-monitor.sh)
**Next Review**: When ready to implement Tier 4 features
