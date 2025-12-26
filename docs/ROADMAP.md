# Roadmap

Future enhancements for Windows & Linux Sysadmin Toolkit.

## Status Summary

| Tier | Focus | Status | Completed |
|------|-------|--------|-----------|
| 1 | Core Monitoring | Complete | 2025-11-30 |
| 2 | Backup & Recovery | Complete | 2025-11-30 |
| 3 | Network & Troubleshooting | Complete | 2025-11-30 |
| 4 | Cloud & Advanced | Pending | - |
| 5 | Observability & DevEx | Complete | 2025-12-26 |

**Windows Completion**: ~90% | **Linux Parity**: Achieved

---

## Completed Features

### Monitoring (Tier 1)
- Get-SystemPerformance.ps1 - CPU, RAM, disk, network with Prometheus export
- Watch-ServiceHealth.ps1 - Auto-restart failed services
- Get-EventLogAnalysis.ps1 - Security and error log analysis
- Get-ApplicationHealth.ps1 - Crash detection, version tracking

### Backup & Recovery (Tier 2)
- Backup-UserData.ps1 - Documents, desktop, downloads
- Backup-BrowserProfiles.ps1 - Chrome, Firefox, Edge, Brave
- Export-SystemState.ps1 - Drivers, registry, network, services
- Test-BackupIntegrity.ps1 - Validation and test restore
- Backup-DeveloperEnvironment.ps1 - VSCode, Terminal, Git, SSH
- Restore-DeveloperEnvironment.ps1 - Manifest-based restore

### Network & Troubleshooting (Tier 3)
- Test-NetworkHealth.ps1 - Connectivity, DNS, port testing
- Manage-VPN.ps1 - VPN connection management
- Repair-CommonIssues.ps1 - DNS, network, Windows Update fixes

### Observability (Tier 5)
- Export-PrometheusMetrics - CommonFunctions.psm1 function
- Prometheus output format in Get-SystemPerformance.ps1

### Linux Scripts
- security-hardening.sh - SSH, firewall, kernel hardening
- service-health-monitor.sh - Service monitoring with Prometheus
- docker-cleanup.sh - Image cleanup with retention
- nvidia-gpu-exporter.sh - GPU metrics for Prometheus

---

## Pending Features (Tier 4)

### Cloud Integration
| Feature | Effort | Priority |
|---------|--------|----------|
| Azure resource management | 4-5 hours | Low |
| AWS resource management | 4-5 hours | Low |
| OneDrive sync automation | 2-3 hours | Low |

### Advanced Reporting
| Feature | Effort | Priority |
|---------|--------|----------|
| System change log tracker | 4-5 hours | Low |
| Configuration drift detection | 3-4 hours | Low |
| Compliance reporting | 3-4 hours | Low |

---

## Integration Points

New scripts should integrate with:
- **CommonFunctions.psm1** - Logging, admin checks, Prometheus export
- **ErrorHandling.psm1** - Contextual errors, retry logic
- **common-functions.sh** - Bash logging, validation, metrics

---

## Test Coverage

| Platform | Files | Assertions |
|----------|-------|------------|
| Windows (Pester) | 8 | 1,100+ |
| Linux (BATS) | 5 | 200+ |

---
**Last Updated**: 2025-12-26
