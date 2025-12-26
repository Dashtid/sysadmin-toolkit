# SSH Configuration Scripts

SSH agent setup and persistent tunnel management for Windows.

## Scripts

| Script | Purpose |
|--------|---------|
| [setup-ssh-agent-access.ps1](setup-ssh-agent-access.ps1) | Configure Windows SSH agent for Git Bash and Claude Code |
| [gitea-tunnel-manager.ps1](gitea-tunnel-manager.ps1) | Persistent SSH tunnel with auto-reconnect |
| [SETUP-SSH-SERVER.md](SETUP-SSH-SERVER.md) | Windows OpenSSH server setup guide |

## Prerequisites

```powershell
# 1. Verify OpenSSH client installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

# 2. Start SSH agent
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent

# 3. Add your key (prompts for passphrase once)
ssh-add $env:USERPROFILE\.ssh\id_ed25519

# 4. Configure Git to use Windows SSH
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

## SSH Agent Setup

```powershell
# Basic setup
.\setup-ssh-agent-access.ps1

# With server configuration
.\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.10" -ServerUser "admin"
```

Creates Git Bash wrapper for Claude Code compatibility and configures PowerShell profile for SSH_AUTH_SOCK.

## SSH Tunnel Manager

### Configuration

Edit `gitea-tunnel-manager.ps1` before use:

```powershell
$LOCAL_PORT = 2222                           # Local tunnel port
$REMOTE_HOST = "user@gitea.example.com"      # SSH server
$REMOTE_PORT = 2222                          # Remote port
$VPN_CHECK_HOST = "gitea.example.com"        # Network check host
```

### Installation

```powershell
# Install as scheduled task (runs at login)
.\gitea-tunnel-manager.ps1 -Install

# Check status
.\gitea-tunnel-manager.ps1 -Status

# Stop tunnel
.\gitea-tunnel-manager.ps1 -Stop

# Uninstall
.\gitea-tunnel-manager.ps1 -Uninstall
```

### Git Remote Configuration

```bash
# New repository
git remote add origin ssh://git@localhost:2222/username/repo.git

# Existing repository
git remote set-url origin ssh://git@localhost:2222/username/repo.git
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Passphrase prompts | `git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"` |
| Key not in agent | `ssh-add $env:USERPROFILE\.ssh\id_ed25519` |
| Connection refused | `.\gitea-tunnel-manager.ps1 -Status` then `-Install` if not running |
| Network disconnected | Connect VPN, verify `$VPN_CHECK_HOST` in script |
| View logs | `Get-Content $env:TEMP\gitea-tunnel.log -Tail 50` |

## How It Works

```
localhost:2222  →  SSH Tunnel (encrypted)  →  Gitea:2222
```

- Windows SSH agent provides key authentication (no passphrase prompts)
- Tunnel auto-restarts on failure
- VPN/network awareness with health monitoring

---
**Last Updated**: 2025-12-26
