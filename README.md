# Windows & Linux Sysadmin Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![CI Tests](https://github.com/Dashtid/sysadmin-toolkit/workflows/CI%20-%20Automated%20Testing/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/ci.yml)
[![Security Scan](https://github.com/Dashtid/sysadmin-toolkit/workflows/Security%20Scanning/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/security-scan.yml)

Personal collection of system administration scripts for Windows and Linux. Scripts for SSH configuration, system maintenance, security hardening, and remote development workflows.

**Note**: This is a personal toolkit - use at your own risk, customize for your environment.

## [i] Target Environments

This toolkit is designed for multi-environment setups:

- **Windows 11 Workstation**: Development and administration workstation
- **Ubuntu Server**: Headless lab/production environment
- **Cross-platform workflows**: Remote development and SSH-based management

## [*] Repository Structure

```
windows-linux-sysadmin-toolkit/
├── .vscode/                    # VSCode workspace settings
│   └── settings.json           # Hides chat sidebar, formatting rules
├── Windows/
│   ├── lib/                    # Shared modules and functions
│   │   ├── CommonFunctions.psm1  # Logging, admin checks, utilities
│   │   └── CommonFunctions.psd1  # Module manifest
│   ├── ssh/                    # SSH configuration and tunnel management
│   │   ├── setup-ssh-agent-access.ps1
│   │   └── gitea-tunnel-manager.ps1
│   ├── first-time-setup/       # Windows 11 desktop setup automation
│   │   ├── export-current-packages.ps1
│   │   ├── install-from-exported-packages.ps1
│   │   ├── fresh-windows-setup.ps1
│   │   ├── work-laptop-setup.ps1
│   │   ├── winget-packages.json     # Exported package lists
│   │   └── chocolatey-packages.config
│   ├── maintenance/            # System maintenance scripts
│   │   ├── security-updates.ps1
│   │   ├── system-updates.ps1
│   │   ├── update-defender.ps1
│   │   └── startup_script.ps1
│   ├── security/               # Security hardening (audit, backup, restore, harden)
│   │   ├── audit-security-posture.ps1
│   │   ├── backup-security-settings.ps1
│   │   ├── restore-security-settings.ps1
│   │   ├── harden-level1-safe.ps1
│   │   ├── harden-level2-balanced.ps1
│   │   └── harden-level3-maximum.ps1
│   ├── development/            # Development environment setup
│   │   └── remote-development-setup.ps1
│   └── utilities/              # Helper utilities
│       ├── add-winget-to-path.ps1
│       └── Manage-ScheduledTask.ps1
├── Linux/
│   ├── server/                 # Ubuntu server scripts
│   ├── desktop/                # Desktop environment scripts
│   ├── maintenance/            # System maintenance (updates, log cleanup, rollback)
│   ├── monitoring/             # System monitoring tools
│   ├── kubernetes/             # Kubernetes pod/PVC monitoring
│   ├── docker/                 # Docker image cleanup and management
│   └── gpu/                    # NVIDIA GPU metrics export
├── docs/                       # Documentation
│   ├── SSH-TUNNEL-SETUP.md    # SSH tunnel configuration guide
│   ├── SECURITY.md            # Security best practices
│   └── SCRIPT_TEMPLATE.md     # Script templates
├── tests/                      # Automated test suite (650+ tests)
│   ├── TestHelpers.psm1       # Shared test utilities
│   ├── Windows/               # Windows script tests
│   └── Linux/                 # Linux script tests
├── examples/                   # Script templates and examples
├── .gitignore                  # Comprehensive secret protection
├── .env.example                # Configuration template
└── README.md                   # This file
```

## [+] Quick Start

### Windows: SSH Agent Setup for Claude Code & Git Bash

This script configures Windows OpenSSH agent for passphrase-free Git operations:

```powershell
# Basic setup (SSH agent configuration only)
.\Windows\ssh\setup-ssh-agent-access.ps1

# With server configuration
.\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.10" -ServerUser "myuser"
```

**What it does:**
- Configures Windows SSH agent for automatic startup
- Creates Git Bash SSH wrapper for Claude Code compatibility
- Sets up PowerShell profile for SSH_AUTH_SOCK
- Optionally configures server shortcuts in Git Bash

### Windows: Gitea SSH Tunnel Manager

Maintains persistent SSH tunnels for Gitea or other SSH-based services:

```powershell
# Check tunnel status
.\Windows\ssh\gitea-tunnel-manager.ps1 -Status

# Install as scheduled task (runs at login)
.\Windows\ssh\gitea-tunnel-manager.ps1 -Install

# Stop tunnel
.\Windows\ssh\gitea-tunnel-manager.ps1 -Stop

# Uninstall scheduled task
.\Windows\ssh\gitea-tunnel-manager.ps1 -Uninstall
```

**Configuration** (edit script before use):
```powershell
$LOCAL_PORT = 2222                              # Local port
$REMOTE_HOST = "youruser@gitea.example.com"     # SSH server
$REMOTE_PORT = 2222                             # Remote port
$VPN_CHECK_HOST = "gitea.example.com"           # Network check host
```

### Windows: First-Time Desktop Setup

Automate Windows 11 desktop setup by capturing and reinstalling packages:

```powershell
# Export current Winget and Chocolatey packages
.\Windows\first-time-setup\export-current-packages.ps1

# Install from exported package lists (with latest versions)
.\Windows\first-time-setup\install-from-exported-packages.ps1 -UseLatestVersions

# Full setup orchestration (packages + configuration)
.\Windows\first-time-setup\fresh-windows-setup.ps1
```

**What it does:**
- Exports current Winget and Chocolatey packages to JSON/XML
- Reinstalls packages on fresh Windows installs
- Gets you back to "tip-top shape" quickly
- Supports selective installation (skip Winget or Chocolatey)

### Windows: Security Hardening Framework

Comprehensive security hardening based on CIS Benchmark v4.0.0, DISA STIG V2R2, and MS Security Baseline v25H2:

```powershell
# 1. Audit current security posture (18 checks)
.\Windows\security\audit-security-posture.ps1

# 2. Create backup before hardening
.\Windows\security\backup-security-settings.ps1

# 3. Preview changes without applying (RECOMMENDED)
.\Windows\security\harden-level1-safe.ps1 -WhatIf

# 4. Apply Level 1 hardening (20 safe, non-breaking controls)
.\Windows\security\harden-level1-safe.ps1

# 5. Apply Level 2 hardening (18 moderate-impact controls)
.\Windows\security\harden-level2-balanced.ps1

# 6. Apply Level 3 hardening (18 high-impact controls - TEST FIRST!)
.\Windows\security\harden-level3-maximum.ps1

# 7. Rollback if needed
.\Windows\security\restore-security-settings.ps1 -BackupPath ".\backups\20250112_143000"
```

**Hardening Levels:**
- **Level 1 (Safe)**: Developer-friendly, non-breaking changes (SMBv1 disable, Defender, Firewall, UAC, PowerShell logging)
- **Level 2 (Balanced)**: Moderate security with potential app impact (Credential Guard, HVCI, ASR rules, TLS 1.2+)
- **Level 3 (Maximum)**: High-security environments only (AppLocker, Constrained Language Mode, NTLM blocking, all ASR rules)

**Features:**
- Automatic backups with System Restore Points
- WhatIf preview mode for all scripts
- Rollback capability for all changes
- Detailed impact warnings and compatibility notes
- Change tracking with success/failure reporting

### Linux: Server Maintenance & Monitoring

Comprehensive automation scripts for Ubuntu server administration with Prometheus integration:

```bash
# Kubernetes pod health monitoring
./Linux/kubernetes/pod-health-monitor.sh --namespace docker-services

# PVC usage monitoring
./Linux/kubernetes/pvc-monitor.sh

# GPU metrics export (every 5 minutes via cron)
./Linux/gpu/nvidia-gpu-exporter.sh

# Docker cleanup (daily via cron)
./Linux/docker/docker-cleanup.sh --keep-versions 2

# Log cleanup (weekly via cron)
./Linux/maintenance/log-cleanup.sh

# System updates with state management
./Linux/maintenance/system-updates.sh --whatif
./Linux/maintenance/restore-previous-state.sh --list
```

**Prometheus Metrics Export:**
- All monitoring scripts export metrics to `/var/lib/prometheus/node-exporter`
- Metrics automatically collected by Prometheus node-exporter textfile collector
- Available for Grafana dashboards and alerting

**Key Features:**
- **Pod Health Monitoring**: Detects CrashLoopBackOff, OOMKilled, ImagePullBackOff
- **Docker Cleanup**: Automated image cleanup with version retention policies
- **GPU Monitoring**: NVIDIA GPU metrics (utilization, memory, temperature, power)
- **Log Management**: Automated compression and cleanup (journald + syslog)
- **System Updates**: APT/Snap updates with pre/post state capture for rollback

## [*] Key Features

### Shared Module System

All Windows PowerShell scripts can leverage the **CommonFunctions** module for:
- **Consistent logging** with ASCII markers (`[+]`, `[-]`, `[!]`, `[i]`)
- **Admin privilege checking** with `Test-IsAdministrator` and `Assert-Administrator`
- **PowerShell 7 detection** with `Test-PowerShell7` and `Get-PowerShell7Path`
- **Color-coded output** with standardized color scheme

**Usage example:**
```powershell
Import-Module "$PSScriptRoot\..\lib\CommonFunctions.psm1"

# Use consistent logging
Write-InfoMessage "Starting operation..."
Write-Success "Operation completed successfully"
Write-WarningMessage "Proceeding with caution"
Write-ErrorMessage "Operation failed"

# Check admin privileges
if (Test-IsAdministrator) {
    Write-Success "Running with admin privileges"
}
```

### Cross-Platform Development Support

- **SSH agent integration** for Windows (works with Claude Code and Git Bash)
- **Persistent SSH tunnels** with automatic health monitoring
- **Passphrase-free Git operations** after initial key unlock
- **Remote development** setup for SSH access to servers

### Security & Best Practices

- **No hardcoded credentials** - all scripts use parameters or environment variables
- **Comprehensive .gitignore** - prevents accidental secret commits
- **Example configurations** - uses RFC 5737 example IPs (192.0.2.x)
- **Secure SSH key storage** - keys encrypted on disk, unlocked in memory
- **Tiered security hardening** - 3 levels from safe to maximum security
- **Automatic backups** - System Restore Points before any hardening
- **Rollback capability** - Restore from backups if issues occur

### Automation & Monitoring

- **Scheduled task support** for background operations
- **Health monitoring** with auto-restart capabilities
- **VPN/network awareness** for tunnel management
- **Detailed logging** for troubleshooting

## [!] Prerequisites

### Windows Systems

- Windows 10/11 with latest updates
- PowerShell 7+ installed (recommended)
- OpenSSH Client enabled
- Administrator privileges for some operations

**Enable OpenSSH Client:**
```powershell
# Check if installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

# Install if needed
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

### Linux Systems

- Ubuntu 20.04 LTS or newer
- Sudo access for system modifications
- Bash 4.0+

## [*] Usage Examples

### Setting Up SSH for Claude Code on Windows

1. **Configure SSH Agent:**
   ```powershell
   .\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "203.0.113.50" -ServerUser "admin"
   ```

2. **Load your SSH key (one time per session):**
   ```powershell
   ssh-add C:\Users\YourName\.ssh\id_ed25519
   ```

3. **Configure Git to use Windows SSH:**
   ```bash
   git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
   ```

4. **Test from Git Bash:**
   ```bash
   ssh_server 'hostname'
   ```

### Setting Up Persistent Gitea Tunnel

1. **Edit tunnel configuration in script:**
   ```powershell
   # Edit Windows\ssh\gitea-tunnel-manager.ps1
   $REMOTE_HOST = "myuser@gitea.mycompany.com"
   $REMOTE_PORT = 2222
   ```

2. **Install as scheduled task:**
   ```powershell
   .\Windows\ssh\gitea-tunnel-manager.ps1 -Install
   ```

3. **Configure Git remote:**
   ```bash
   git remote add origin ssh://git@localhost:2222/username/repo.git
   ```

4. **Verify tunnel health:**
   ```powershell
   .\Windows\ssh\gitea-tunnel-manager.ps1 -Status
   ```

## [!] Security Considerations

### What This Repository NEVER Contains

- [X] Passwords, API keys, tokens, or credentials
- [X] SSH private keys or certificates
- [X] Private IP addresses (uses RFC 5737 examples)
- [X] Company-specific or personal information
- [X] Database connection strings with credentials

### Best Practices Implemented

- [+] Environment variables for configuration
- [+] `.env.example` with placeholders (no real values)
- [+] Comprehensive `.gitignore` patterns
- [+] Parameter-based scripts (no hardcoded values)
- [+] Clear documentation about customization needs

### Before Using These Scripts

1. **Review the code** - Understand what each script does
2. **Customize configuration** - Replace example values with your own
3. **Test in non-production** - Verify behavior before production use
4. **Protect your secrets** - Never commit real credentials to Git
5. **Use `.env.local`** - For local overrides (gitignored automatically)

## [*] Prometheus Integration

The Linux monitoring scripts export metrics in Prometheus format for centralized monitoring and alerting.

### Exported Metrics

**Kubernetes Pod Health:**
```
k8s_unhealthy_pods_total{cluster="k3s-lab"} 0
k8s_crashloop_pods_total{cluster="k3s-lab"} 0
k8s_oomkilled_pods_total{cluster="k3s-lab"} 0
k8s_pending_pods_total{cluster="k3s-lab"} 0
```

**GPU Metrics:**
```
nvidia_gpu_utilization_percent{gpu="0",name="Quadro_RTX_5000"} 15
nvidia_gpu_memory_used_bytes{gpu="0",name="Quadro_RTX_5000"} 6442450944
nvidia_gpu_temperature_celsius{gpu="0",name="Quadro_RTX_5000"} 45
```

**Docker Cleanup:**
```
docker_cleanup_images_removed_total 18
docker_cleanup_space_reclaimed_bytes 13958643712
docker_cleanup_execution_time_seconds 12.5
```

### Example PromQL Queries

```promql
# Pods with high restart counts
k8s_pod_restarts{restart_count > "10"}

# GPU temperature over time
nvidia_gpu_temperature_celsius{gpu="0"}

# Docker cleanup effectiveness (GB reclaimed per run)
rate(docker_cleanup_space_reclaimed_bytes[1d]) / 1024 / 1024 / 1024

# System log growth rate
rate(log_cleanup_logs_compressed_total[1h])
```

### Grafana Dashboard Setup

1. Add Prometheus as data source in Grafana
2. Import dashboards or create custom panels with queries above
3. Set up alerts for critical metrics (pod crashes, high GPU temp, disk space)

## [i] Documentation

Comprehensive guides available in the [`docs/`](docs/) directory:

- **[SSH Tunnel Setup Guide](docs/SSH-TUNNEL-SETUP.md)**: Detailed Gitea tunnel configuration
- **[Security Best Practices](docs/SECURITY.md)**: Guidelines for secure script usage
- **[Script Template](docs/SCRIPT_TEMPLATE.md)**: PowerShell and Bash script templates with best practices
- **[Functionality Roadmap](docs/ROADMAP.md)**: Future enhancements and expansion opportunities (20+ planned features)
- **[Contributing Guidelines](CONTRIBUTING.md)**: Coding standards and contribution process

Additional documentation:
- **[First-Time Setup](Windows/first-time-setup/README.md)**: Windows 11 desktop setup automation
- **[Example Scripts](examples/README.md)**: Reference implementations and templates
- **[Test Suite](tests/README.md)**: Automated testing framework (650+ tests)

## [!] Troubleshooting

### Common Issues and Solutions

#### Windows SSH Agent Issues

**Problem**: SSH keys not persisting after reboot
```powershell
# Solution: Ensure SSH agent is set to automatic startup
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

**Problem**: "Bad owner or permissions" error
```powershell
# Solution: Fix SSH directory permissions
icacls "$env:USERPROFILE\.ssh" /inheritance:r
icacls "$env:USERPROFILE\.ssh" /grant:r "$($env:USERNAME):(OI)(CI)F"
```

**Problem**: Claude Code cannot access SSH keys
```bash
# Solution: Verify SSH_AUTH_SOCK environment variable
echo $SSH_AUTH_SOCK
# Should output: \\.\pipe\openssh-ssh-agent

# If not set, run setup script again
./Windows/ssh/setup-ssh-agent-access.ps1
```

#### PowerShell Script Issues

**Problem**: "Execution policy" error when running scripts
```powershell
# Solution: Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Or permanently for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Problem**: "Cannot load module CommonFunctions.psm1"
```powershell
# Solution: Verify module path is correct
Test-Path "$PSScriptRoot\..\lib\CommonFunctions.psm1"

# If false, check your current directory and adjust path
```

**Problem**: PSScriptAnalyzer warnings or errors
```powershell
# Solution: Install and run PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path .\Windows -Recurse -Fix
```

#### Linux Script Issues

**Problem**: "Permission denied" when running scripts
```bash
# Solution: Make script executable
chmod +x script-name.sh

# Or run with bash explicitly
bash script-name.sh
```

**Problem**: "common-functions.sh: No such file or directory"
```bash
# Solution: Verify library path
ls -la Linux/lib/bash/common-functions.sh

# Check script is sourcing from correct relative path
# Should be: source "$SCRIPT_DIR/../lib/bash/common-functions.sh"
```

**Problem**: Docker daemon connection refused
```bash
# Solution: Start Docker service and add user to docker group
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker  # Or logout/login for group to take effect
```

**Problem**: nvidia-smi command not found
```bash
# Solution: Install NVIDIA drivers and verify installation
nvidia-smi --version

# If not installed, install NVIDIA drivers for your GPU
# Ubuntu: sudo apt install nvidia-driver-535
```

#### Configuration Issues

**Problem**: Script cannot find config.json
```bash
# Solution: Copy example config and customize
cp config.example.json config.json
nano config.json  # Edit with your settings
```

**Problem**: Prometheus metrics not appearing
```bash
# Solution: Verify node-exporter textfile collector is configured
ls -la /var/lib/prometheus/node-exporter/

# Ensure node-exporter has --collector.textfile.directory flag
systemctl status prometheus-node-exporter
```

#### Git and Version Control Issues

**Problem**: Git operations prompt for passphrase repeatedly
```powershell
# Windows Solution: Ensure SSH agent is running with key loaded
Get-Service ssh-agent
ssh-add -l  # Should list your key

# If key not listed, add it
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

```bash
# Linux Solution: Start ssh-agent and add key
eval $(ssh-agent)
ssh-add ~/.ssh/id_ed25519
```

**Problem**: "Permission denied (publickey)" when pushing to GitHub
```bash
# Solution: Test SSH connection and ensure key is added to GitHub
ssh -T git@github.com

# Add your public key to GitHub: Settings > SSH and GPG keys
cat ~/.ssh/id_ed25519.pub
```

### Getting Help

If you encounter an issue not covered here:

1. **Check script logs**: Most scripts write detailed logs to `/var/log/` (Linux) or script directory (Windows)
2. **Run with debug mode**: Use `--debug` flag (Bash) or `-Verbose` (PowerShell) for detailed output
3. **Review documentation**: Check `docs/` directory for specific guides
4. **Search existing issues**: [GitHub Issues](https://github.com/Dashtid/sysadmin-toolkit/issues)
5. **Create new issue**: Provide:
   - OS and version
   - Script name and version
   - Full error message
   - Steps to reproduce
   - Relevant log output

### Validation and Testing

Before reporting an issue, verify your environment:

```powershell
# Windows validation
Get-Host | Select-Object Version  # PowerShell version
Get-Service ssh-agent              # SSH agent status
$PSVersionTable.PSVersion          # Detailed PS version

# Run test suite
.\tests\run-tests.ps1
```

```bash
# Linux validation
bash --version                     # Bash version
docker --version                   # Docker version
shellcheck --version               # shellcheck availability

# Test script syntax
shellcheck script-name.sh
```

## [!] Important Notes

- **Personal toolkit** - No support or warranty provided
- **Test everything first** - These scripts can make system changes
- **Review before running** - Understand what each script does
- **Customize for your environment** - Examples use placeholder values
- **Backup before hardening** - Security scripts can break applications

## License

MIT License - Use at your own risk. See [LICENSE](LICENSE) file.

---

**Author**: David Dashti
**Purpose**: Personal sysadmin automation scripts
**Version**: 2.0.0
**Last Updated**: 2025-10-18
