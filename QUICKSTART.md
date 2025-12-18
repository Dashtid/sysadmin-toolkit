# Quick Start Guide

Get started with the System Administration Toolkit in 5 minutes.

## [1] Clone the Repository

```bash
git clone https://github.com/Dashtid/sysadmin-toolkit.git
cd windows-linux-sysadmin-toolkit
```

## [2] Install Development Tools (Optional)

For contributors who want pre-commit checks:

```bash
# Simple bash-based hooks
./.githooks/install-hooks.sh

# Or use pre-commit framework for advanced scanning
pip install pre-commit
pre-commit install
```

## [3] Configure Your Environment

```bash
# Copy template
cp .env.example .env.local

# Edit with your values (uses your preferred editor)
nano .env.local
```

Example configuration:
```bash
SERVER_IP=10.0.0.50
SERVER_USER=admin
SSH_KEY_PATH=~/.ssh/id_ed25519
```

## [4] Run Your First Script

### Windows: Setup SSH Agent

```powershell
# Configure SSH agent for Claude Code and Git Bash
.\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "10.0.0.50" -ServerUser "admin"

# Load your SSH key (will prompt for passphrase once)
ssh-add C:\Users\YourName\.ssh\id_ed25519

# Test connection from Git Bash
ssh_server 'hostname'
```

### Windows: Setup Gitea Tunnel

```powershell
# Edit configuration in the script first
notepad .\Windows\ssh\gitea-tunnel-manager.ps1
# Change: $REMOTE_HOST, $REMOTE_PORT, $VPN_CHECK_HOST

# Check status
.\Windows\ssh\gitea-tunnel-manager.ps1 -Status

# Install as background service
.\Windows\ssh\gitea-tunnel-manager.ps1 -Install

# Configure Git to use tunnel
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
git remote add origin ssh://git@localhost:2222/username/repo.git
```

## [5] Read the Documentation

- **[README.md](README.md)** - Full feature overview
- **[SECURITY.md](SECURITY.md)** - Security best practices
- **[docs/SSH-TUNNEL-SETUP.md](docs/SSH-TUNNEL-SETUP.md)** - Detailed SSH tunnel guide
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - For contributors

## [i] Common Tasks

### Check for Secrets Before Committing

```bash
# Run pre-commit checks manually
./.githooks/pre-commit

# Or with pre-commit framework
pre-commit run --all-files
```

### Test a Script

```powershell
# PowerShell (dry run)
.\Windows\ssh\setup-ssh-agent-access.ps1 -WhatIf

# PowerShell (full run with test values)
.\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.10" -ServerUser "testuser"
```

```bash
# Bash (syntax check)
bash -n Linux/server/script.sh

# Bash (dry run if supported)
./Linux/server/script.sh --dry-run
```

### Verify No Secrets

```bash
# Check for common patterns
git diff | grep -iE "(password|secret|key|token)"

# Check for private IPs
git diff | grep -E "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

## [!] Important Reminders

- **Never commit secrets** - Use .env.local (gitignored)
- **Use RFC 5737 IPs in examples** - 192.0.2.x, 198.51.100.x, 203.0.113.x
- **Test in safe environment first** - Don't run in production without testing
- **Review scripts before running** - Understand what they do
- **Keep SSH keys secure** - Use passphrases, store safely

## [+] Next Steps

1. **Customize scripts** for your environment
2. **Star the repository** if you find it useful
3. **Open issues** for bugs or feature requests
4. **Contribute** improvements (see [CONTRIBUTING.md](CONTRIBUTING.md))
5. **Share** with colleagues who might benefit

## [?] Need Help?

- **Issues**: [GitHub Issues](https://github.com/Dashtid/sysadmin-toolkit/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Questions**: Open a discussion or issue

---

**Happy automating!**

**Author**: David Dashti | **GitHub**: [@dashtid](https://github.com/dashtid)
