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

### Windows: Schedule weekly updates

```powershell
# From an elevated pwsh
.\Windows\maintenance\Install-SystemUpdatesTask.ps1
# Optional: trigger a one-shot smoke test
Start-ScheduledTask -TaskName SystemUpdates
```

### Windows: Snapshot the dev environment before a rebuild

```powershell
.\Windows\backup\Backup-DeveloperEnvironment.ps1 -BackupPath "D:\DevBackups"
```

### Windows: Provision a fresh machine

```powershell
.\Windows\first-time-setup\fresh-windows-setup.ps1
# Then restore your previously-exported package list:
.\Windows\first-time-setup\install-from-exported-packages.ps1 -Manifest .\Windows\package-lists\my-packages.json
```

### Linux: Maintenance on q-lab

```bash
./Linux/maintenance/disk-cleanup.sh --whatif
./Linux/server/headless-server-setup.sh
```

## 3. Common Commands

| Task | Command |
|------|---------|
| Run all tests | `.\tests\run-tests.ps1` |
| Snapshot dev env | `.\Windows\backup\Backup-DeveloperEnvironment.ps1` |
| Schedule weekly updates | `.\Windows\maintenance\Install-SystemUpdatesTask.ps1` |
| Repair DNS/network | `.\Windows\troubleshooting\Repair-CommonIssues.ps1` |
| Clean Docker images | `.\Windows\development\Manage-Docker.ps1 -Cleanup` |

## 4. Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Full script listing |
| [BACKLOG.md](BACKLOG.md) | What's planned, what was killed |
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
