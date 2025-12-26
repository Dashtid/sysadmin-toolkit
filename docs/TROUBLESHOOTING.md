# Troubleshooting

Common issues and solutions.

## Windows SSH

| Issue | Solution |
|-------|----------|
| Keys not persisting after reboot | `Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent; ssh-add ~/.ssh/id_ed25519` |
| "Bad owner or permissions" | `icacls "$env:USERPROFILE\.ssh" /inheritance:r; icacls "$env:USERPROFILE\.ssh" /grant:r "$($env:USERNAME):(OI)(CI)F"` |
| Claude Code can't access keys | Verify `$SSH_AUTH_SOCK` is `\\.\pipe\openssh-ssh-agent` |
| Passphrase prompt every time | `ssh-add -l` to check, then `ssh-add ~/.ssh/id_ed25519` |

## PowerShell

| Issue | Solution |
|-------|----------|
| "Running scripts is disabled" | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| "Requires PowerShell 7" | `winget install Microsoft.PowerShell` |
| "Must run as Administrator" | Right-click PowerShell → Run as Administrator |
| "Cannot load CommonFunctions.psm1" | `Test-Path "$PSScriptRoot\..\lib\CommonFunctions.psm1"` |

## Linux

| Issue | Solution |
|-------|----------|
| "Permission denied" | `chmod +x script.sh` |
| "common-functions.sh not found" | Check relative path: `source "$SCRIPT_DIR/../lib/bash/common-functions.sh"` |
| Docker connection refused | `sudo systemctl start docker; sudo usermod -aG docker $USER` |
| nvidia-smi not found | `sudo apt install nvidia-driver-535` |

## Package Managers

| Issue | Solution |
|-------|----------|
| Chocolatey not found | Install from [chocolatey.org/install](https://chocolatey.org/install) |
| Winget not in PATH | `$env:PATH += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"` |
| PSWindowsUpdate fails | `Set-PSRepository -Name PSGallery -InstallationPolicy Trusted` |
| Winget "no upgrade found" | `winget source reset --force` |

## Network

| Issue | Solution |
|-------|----------|
| "Unable to resolve package source" | Check proxy: `choco config set proxy http://proxy:8080` |
| SSH tunnel disconnects | Add to `~/.ssh/config`: `ServerAliveInterval 60` |
| "Permission denied (publickey)" | `ssh-add -l` then `ssh -T git@github.com` |

## Debugging

```powershell
# Verbose output
.\script.ps1 -Verbose

# Dry run
.\script.ps1 -WhatIf

# Check transcript logs
Get-ChildItem logs\ -Filter "transcript_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Verify module
Import-Module "Windows\lib\CommonFunctions.psm1" -Force -Verbose
```

```bash
# Bash syntax check
bash -n script.sh

# Debug mode
bash -x script.sh

# Check shellcheck
shellcheck script.sh
```

## Still Stuck?

1. Check [GitHub Issues](https://github.com/Dashtid/sysadmin-toolkit/issues)
2. Run with `-Verbose` or `--debug`
3. Review logs in `logs/` directory
4. Open a new issue with: OS version, script name, full error, steps to reproduce

---
**Last Updated**: 2025-12-26
