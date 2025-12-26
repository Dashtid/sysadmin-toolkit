# Quick Start

Get started in 5 minutes.

## 1. Clone & Configure

```bash
git clone https://github.com/Dashtid/sysadmin-toolkit.git
cd sysadmin-toolkit
cp .env.example .env.local
```

Edit `.env.local` with your values:
```bash
SERVER_IP=192.0.2.50
SERVER_USER=admin
SSH_KEY_PATH=~/.ssh/id_ed25519
```

## 2. Run Your First Script

### Windows: SSH Agent

```powershell
.\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.50" -ServerUser "admin"
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

### Windows: System Monitoring

```powershell
.\Windows\monitoring\Get-SystemPerformance.ps1 -OutputFormat HTML
.\Windows\monitoring\Test-NetworkHealth.ps1
```

### Linux: Maintenance

```bash
./Linux/maintenance/system-updates.sh --whatif
./Linux/docker/docker-cleanup.sh --keep-versions 2
```

## 3. Common Commands

| Task | Command |
|------|---------|
| Backup user data | `.\Windows\backup\Backup-UserData.ps1 -Destination "D:\Backups"` |
| Check dev environment | `.\Windows\development\Test-DevEnvironment.ps1` |
| Fix common issues | `.\Windows\troubleshooting\Repair-CommonIssues.ps1 -Diagnose` |
| Run tests | `.\tests\run-tests.ps1` |

## 4. Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Full script listing |
| [SECURITY.md](SECURITY.md) | Security best practices |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Coding standards |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues |

## Important

- Never commit secrets - use `.env.local` (gitignored)
- Use RFC 5737 IPs in examples: `192.0.2.x`, `198.51.100.x`
- Test scripts before production use
- Review code before running

---
**Author**: David Dashti | [GitHub Issues](https://github.com/Dashtid/sysadmin-toolkit/issues)
