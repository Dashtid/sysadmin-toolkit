# SSH Configuration

Windows OpenSSH setup and configuration guides.

## Documentation

| File | Purpose |
|------|---------|
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

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Passphrase prompts | `git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"` |
| Key not in agent | `ssh-add $env:USERPROFILE\.ssh\id_ed25519` |
| Agent not running | `Start-Service ssh-agent` |

---
**Last Updated**: 2025-12-26
