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

**Windows Completion**: ~90% | **Linux Scope**: Server-focused subset (see [Linux Coverage](#linux-coverage) below)

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

### Maintenance
- Install-SystemUpdatesTask.ps1 - Register system-updates.ps1 as a scheduled task

### Linux Scripts
- security-hardening.sh - SSH, firewall, kernel hardening
- service-health-monitor.sh - Service monitoring with Prometheus
- docker-cleanup.sh - Image cleanup with retention
- nvidia-gpu-exporter.sh - GPU metrics for Prometheus

---

## Linux Coverage

The Linux side is intentionally narrower than Windows: it targets headless server use (q-lab), not desktop workstations. Windows-only categories below are out of scope unless explicitly added to the backlog.

| Category | Windows | Linux | Status |
|----------|---------|-------|--------|
| Monitoring | 5 scripts | 1 script (service-health) | Partial - K8s/GPU exporters cover specific needs |
| Maintenance | 2 scripts | 3 scripts (system-update, log-cleanup, restore) | At parity |
| Backup | 5 scripts | 0 scripts | Windows-only by design (browser, dev env) |
| Development | 3 scripts | 0 scripts | Windows-only by design |
| Reporting | 1 script | 0 scripts | Gap - candidate for backlog |
| Troubleshooting | 1 script | 0 scripts | Gap - candidate for backlog |
| Network | 2 scripts | 0 scripts | Gap - candidate for backlog |
| Security | 1 script | 1 script (security-hardening) | At parity |
| First-time-setup | 4 scripts | 1 script (headless-server-setup) | At parity for server scope |
| Docker | (via Manage-Docker) | docker-cleanup | At parity |
| Kubernetes | (none) | 2 scripts (pod-health, pvc) | Linux-only by design |
| GPU | (none) | nvidia-gpu-exporter | Linux-only by design |

**Realistic gaps**: Linux-side reporting, troubleshooting, and network scripts. Tracked in `backlog.md` under "Linux coverage gaps".

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

| Platform | Files | Tests |
|----------|-------|-------|
| Windows (Pester) | 9 | 800+ |
| Linux (BATS) | 5 | 200+ |

---
**Last Updated**: 2026-05-27
