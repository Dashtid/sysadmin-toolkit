# Development Environment Scripts

Setup and management for development tools on Windows.

## Scripts

| Script | Purpose |
|--------|---------|
| [Test-DevEnvironment.ps1](Test-DevEnvironment.ps1) | Validate installed dev tools (Git, Node, Python, VSCode) |
| [Manage-Docker.ps1](Manage-Docker.ps1) | Docker Desktop management and cleanup |
| [Manage-WSL.ps1](Manage-WSL.ps1) | WSL2 distribution backup, restore, and configuration |
| [remote-development-setup.ps1](remote-development-setup.ps1) | Configure SSH for remote development |

## Quick Examples

```powershell
# Check dev environment
.\Test-DevEnvironment.ps1

# Clean Docker images
.\Manage-Docker.ps1 -Cleanup -KeepVersions 2

# Backup WSL distribution
.\Manage-WSL.ps1 -Export -Distribution Ubuntu -Path "D:\Backups"
```

---
**Last Updated**: 2025-12-26
