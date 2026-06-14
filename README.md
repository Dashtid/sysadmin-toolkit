# Windows & Linux Sysadmin Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![CI Tests](https://github.com/Dashtid/sysadmin-toolkit/workflows/CI%20-%20Automated%20Testing/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/ci.yml)

Personal system administration scripts for Windows and Linux. Narrow scope: fresh-machine setup, weekly update automation, a Docker convenience wrapper, and a GPU exporter for the lab server.

> **Note:** Security hardening lives in [defensive-toolkit](https://github.com/Dashtid/defensive-toolkit). Monitoring and backup happen on the lab server via Prometheus/Grafana and Velero, not here.

> **2026-06-14:** the toolkit was deliberately culled. Monitoring/reporting/security/most-backup/VPN/WSL/Test-DevEnvironment scripts were removed because they duplicated native tools (Task Manager, Event Viewer, `wsl.exe`, Settings) or the lab-server stack. See [BACKLOG.md](BACKLOG.md) for the new scope and rationale.

## Windows Scripts

| Category | Script | Purpose |
|----------|--------|---------|
| **Setup** | [fresh-windows-setup.ps1](Windows/first-time-setup/) | Automated Windows 11 setup (Winget + Chocolatey) |
| | [export-current-packages.ps1](Windows/first-time-setup/) | Export installed Winget/Choco packages to a list |
| | [install-from-exported-packages.ps1](Windows/first-time-setup/) | Restore an exported package list on a fresh box |
| | [Compare-SoftwareInventory.ps1](Windows/first-time-setup/) | Diff two package inventories |
| **Maintenance** | [system-updates.ps1](Windows/maintenance/) | Weekly Winget/Choco/Windows Update automation |
| | [Install-SystemUpdatesTask.ps1](Windows/maintenance/) | Register `system-updates.ps1` as a scheduled task |
| **Backup** | [Backup-DeveloperEnvironment.ps1](Windows/backup/) | Snapshot VSCode, Terminal, Git, SSH configs before a rebuild |
| **Development** | [Manage-Docker.ps1](Windows/development/) | Docker Desktop start/stop/cleanup helper |
| | [remote-development-setup.ps1](Windows/development/) | Configure SSH client for remote development |
| **Network** | [Set-StaticIP.ps1](Windows/network/) | One-shot static IP/DNS/gateway helper |
| **Troubleshooting** | [Repair-CommonIssues.ps1](Windows/troubleshooting/) | DNS, network, and Windows Update fix-it routines |

## Linux Scripts

Scope is narrow on purpose: the lab server (q-lab) covers most operational needs via Prometheus/Grafana/Velero/k9s; the survivors here are the bits those tools don't cover.

| Category | Script | Purpose |
|----------|--------|---------|
| **GPU** | [nvidia-gpu-exporter.sh](Linux/gpu/) | NVIDIA GPU metrics for Prometheus (scraped by Grafana) |
| **Maintenance** | [disk-cleanup.sh](Linux/maintenance/) | APT cache + journal + Docker leftover cleanup |
| **Server** | [headless-server-setup.sh](Linux/server/) | Ubuntu server provisioning for a fresh q-lab-style box |

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
| [BACKLOG.md](BACKLOG.md) | Tactical work queue and post-cull scope |
| [SECURITY.md](SECURITY.md) | Security policy and best practices |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Coding standards and PR process |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Strategic direction (post-cull) |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## Prerequisites

| Platform | Requirements |
|----------|--------------|
| Windows | PowerShell 7+, OpenSSH Client enabled |
| Linux | Bash 4.0+, sudo access |

## License

MIT License - See [LICENSE](LICENSE)

---
**Author**: David Dashti | **Version**: 3.0.0 | **Updated**: 2026-06-14
