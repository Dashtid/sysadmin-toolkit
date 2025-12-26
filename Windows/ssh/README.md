# SSH Configuration Scripts

SSH agent setup and tunnel management for Windows.

## Scripts

| Script | Purpose |
|--------|---------|
| [setup-ssh-agent-access.ps1](setup-ssh-agent-access.ps1) | Configure Windows SSH agent for Git Bash and Claude Code |
| [gitea-tunnel-manager.ps1](gitea-tunnel-manager.ps1) | Persistent SSH tunnel with auto-reconnect |

## Documentation

| Document | Purpose |
|----------|---------|
| [SETUP-SSH-SERVER.md](SETUP-SSH-SERVER.md) | Windows OpenSSH server setup guide |

## Quick Examples

```powershell
# Setup SSH agent
.\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.10" -ServerUser "admin"

# Install tunnel as scheduled task
.\gitea-tunnel-manager.ps1 -Install

# Check tunnel status
.\gitea-tunnel-manager.ps1 -Status
```

---
**Last Updated**: 2025-12-26
