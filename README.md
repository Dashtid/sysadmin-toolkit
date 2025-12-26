# Windows & Linux Sysadmin Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![CI Tests](https://github.com/Dashtid/sysadmin-toolkit/workflows/CI%20-%20Automated%20Testing/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/ci.yml)
[![Security Scan](https://github.com/Dashtid/sysadmin-toolkit/workflows/Security%20Scanning/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/security-scan.yml)

Personal system administration scripts for Windows and Linux. SSH configuration, monitoring, backup, and maintenance automation.

> **Note**: Security hardening scripts are in [defensive-toolkit](https://github.com/Dashtid/defensive-toolkit).

## Quick Start

```bash
git clone https://github.com/Dashtid/sysadmin-toolkit.git
cd sysadmin-toolkit
cp .env.example .env.local  # Configure your values
```

## Windows Scripts

| Category | Script | Purpose |
|----------|--------|---------|
| **Monitoring** | [Get-SystemPerformance.ps1](Windows/monitoring/) | CPU, RAM, disk, network metrics with Prometheus export |
| | [Watch-ServiceHealth.ps1](Windows/monitoring/) | Service monitoring with auto-restart |
| | [Test-NetworkHealth.ps1](Windows/monitoring/) | Connectivity, DNS, port testing |
| | [Get-EventLogAnalysis.ps1](Windows/monitoring/) | Security and error log analysis |
| | [Get-ApplicationHealth.ps1](Windows/monitoring/) | Application crash and version monitoring |
| **Backup** | [Backup-UserData.ps1](Windows/backup/) | User documents with compression |
| | [Backup-BrowserProfiles.ps1](Windows/backup/) | Browser bookmarks and settings |
| | [Backup-DeveloperEnvironment.ps1](Windows/backup/) | VSCode, Terminal, Git, SSH configs |
| | [Export-SystemState.ps1](Windows/backup/) | Drivers, registry, network, services |
| | [Test-BackupIntegrity.ps1](Windows/backup/) | Backup validation and restore testing |
| **SSH** | [setup-ssh-agent-access.ps1](Windows/ssh/) | Windows SSH agent for Git Bash |
| | [gitea-tunnel-manager.ps1](Windows/ssh/) | Persistent SSH tunnels |
| **Setup** | [fresh-windows-setup.ps1](Windows/first-time-setup/) | Automated Windows 11 setup |
| | [export-current-packages.ps1](Windows/first-time-setup/) | Export Winget/Chocolatey packages |
| **Development** | [Test-DevEnvironment.ps1](Windows/development/) | Validate dev tool installation |
| | [Manage-Docker.ps1](Windows/development/) | Docker Desktop management |
| | [Manage-WSL.ps1](Windows/development/) | WSL2 backup and configuration |
| **Maintenance** | [system-updates.ps1](Windows/maintenance/) | Windows Update automation |
| | [Restore-PreviousState.ps1](Windows/maintenance/) | System restore from backup |
| **Troubleshooting** | [Repair-CommonIssues.ps1](Windows/troubleshooting/) | Fix DNS, network, update issues |
| **Security** | [Get-UserAccountAudit.ps1](Windows/security/) | User and admin account audit |
| **Network** | [Manage-VPN.ps1](Windows/network/) | VPN connection management |
| **Reporting** | [Get-SystemReport.ps1](Windows/reporting/) | Comprehensive system report |

## Linux Scripts

| Category | Script | Purpose |
|----------|--------|---------|
| **Monitoring** | [pod-health-monitor.sh](Linux/kubernetes/) | Kubernetes pod health and restart detection |
| | [pvc-monitor.sh](Linux/kubernetes/) | PVC usage monitoring |
| | [service-health-monitor.sh](Linux/monitoring/) | Service monitoring with alerts |
| **Maintenance** | [system-updates.sh](Linux/maintenance/) | APT/Snap updates with rollback |
| | [log-cleanup.sh](Linux/maintenance/) | Log rotation and cleanup |
| | [restore-previous-state.sh](Linux/maintenance/) | System state restoration |
| **Docker** | [docker-cleanup.sh](Linux/docker/) | Image cleanup with retention policy |
| **GPU** | [nvidia-gpu-exporter.sh](Linux/gpu/) | NVIDIA GPU metrics for Prometheus |
| **Security** | [security-hardening.sh](Linux/security/) | SSH, firewall, kernel hardening |
| **Server** | [headless-server-setup.sh](Linux/server/) | Ubuntu server provisioning |

## Shared Modules

| Platform | Module | Purpose |
|----------|--------|---------|
| Windows | [CommonFunctions.psm1](Windows/lib/) | Logging, admin checks, Prometheus export |
| Windows | [ErrorHandling.psm1](Windows/lib/) | Contextual errors, retry logic |
| Linux | [common-functions.sh](Linux/lib/) | Logging, validation, Prometheus export |

## Documentation

| Document | Purpose |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute setup guide |
| [SECURITY.md](SECURITY.md) | Security policy and best practices |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Coding standards and PR process |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Feature roadmap and progress |
| [docs/SSH-TUNNEL-SETUP.md](docs/SSH-TUNNEL-SETUP.md) | SSH tunnel configuration |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## Prerequisites

| Platform | Requirements |
|----------|--------------|
| Windows | PowerShell 7+, OpenSSH Client enabled |
| Linux | Bash 4.0+, sudo access |

## License

MIT License - See [LICENSE](LICENSE)

---
**Author**: David Dashti | **Version**: 2.1.0 | **Updated**: 2025-12-26
