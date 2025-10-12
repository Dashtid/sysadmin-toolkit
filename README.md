# System Administration & Development Toolkit

[![Syntax Check](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/syntax-check.yml/badge.svg)](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/syntax-check.yml)
[![Test Scripts](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/test-scripts.yml/badge.svg)](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/test-scripts.yml)
[![Secret Scan](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/actions/workflows/secret-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Dashtid/windows-linux-sysadmin-toolkit/graphs/commit-activity)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)

A comprehensive collection of system administration scripts and tools for Windows and Linux environments. This repository provides ready-to-use scripts for SSH configuration, system maintenance, security hardening, and remote development workflows.

**Public Repository**: [https://github.com/dashtid/windows-linux-sysadmin-toolkit](https://github.com/dashtid/windows-linux-sysadmin-toolkit)

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
│   ├── ssh/                    # SSH configuration and tunnel management
│   │   ├── setup-ssh-agent-access.ps1
│   │   └── gitea-tunnel-manager.ps1
│   ├── first-time-setup/       # Windows 11 desktop setup automation
│   │   ├── export-current-packages.ps1
│   │   ├── install-from-exported-packages.ps1
│   │   ├── fresh-windows-setup.ps1
│   │   └── work-laptop-setup.ps1
│   ├── maintenance/            # System maintenance scripts
│   ├── security/               # Security hardening (audit, backup, restore, harden)
│   │   ├── audit-security-posture.ps1
│   │   ├── backup-security-settings.ps1
│   │   ├── restore-security-settings.ps1
│   │   ├── harden-level1-safe.ps1
│   │   ├── harden-level2-balanced.ps1
│   │   └── harden-level3-maximum.ps1
│   └── utilities/              # Helper utilities
├── Linux/
│   ├── server/                 # Ubuntu server scripts
│   ├── maintenance/            # System maintenance
│   ├── monitoring/             # System monitoring tools
│   └── security/               # Security hardening
├── docs/                       # Documentation
│   ├── SSH-TUNNEL-SETUP.md    # SSH tunnel configuration guide
│   └── SECURITY.md            # Security best practices
├── tests/                      # Test scripts
│   ├── Windows/
│   └── Linux/
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

### Linux: Server Maintenance

Scripts for Ubuntu server administration:
- System updates and cleanup
- Monitoring and health checks
- Security hardening
- Backup automation

## [*] Key Features

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

## [i] Documentation

Comprehensive guides available in the [`docs/`](docs/) directory:

- **[SSH Tunnel Setup Guide](docs/SSH-TUNNEL-SETUP.md)**: Detailed Gitea tunnel configuration
- **[Security Best Practices](docs/SECURITY.md)**: Guidelines for secure script usage

Additional documentation in script directories:
- **[First-Time Setup README](Windows/first-time-setup/README.md)**: Windows 11 desktop setup guide
- **[First-Time Setup QUICKSTART](Windows/first-time-setup/QUICKSTART.md)**: TL;DR setup guide

## [*] Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-script`)
3. Follow existing code style and conventions
4. Test thoroughly in appropriate environments
5. Ensure no secrets in commits
6. Submit a pull request

### Script Conventions

- **PowerShell**: Require PowerShell 7+, proper error handling
- **Bash**: Use `#!/usr/bin/env bash` shebang, POSIX-compatible when possible
- **Documentation**: Clear comments and usage instructions
- **Security**: No hardcoded credentials, use parameters/environment variables
- **Logging**: Consistent format with timestamps using [+] [-] [i] [!] markers

## [!] Important Notes

- **Test scripts** in safe environments first
- **Review before execution** to understand what they do
- **Backup important data** before system modifications
- **Check prerequisites** before running any script
- **Run with appropriate privileges** (sudo for Linux, Administrator for Windows)
- **Customize configuration** - example values won't work as-is

## [*] License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## [+] Acknowledgments

- Designed for multi-environment development workflows
- Optimized for Windows 11 and Ubuntu 20.04+ compatibility
- Built with security and best practices as top priorities
- Created to solve real Windows + SSH + Git integration challenges

---

**Author**: David Dashti
**GitHub**: [@dashtid](https://github.com/dashtid)
**Purpose**: Making system administration easier and more secure

_For questions, suggestions, or issues, please open a GitHub issue._

---

**Last Updated**: 2025-10-12
**Version**: 2.1 (Added first-time setup automation and security hardening framework)
