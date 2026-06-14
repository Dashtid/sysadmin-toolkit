# Development Environment Scripts

> **Scope note (2026-06-14):** `Test-DevEnvironment.ps1` and `Manage-WSL.ps1` were removed in the ghost-code cull — `wsl.exe` covers WSL operations natively and the dev-env checker had no clear trigger.

## Scripts

| Script | Purpose |
|--------|---------|
| [Manage-Docker.ps1](Manage-Docker.ps1) | Docker Desktop start/stop/cleanup helper |
| [remote-development-setup.ps1](remote-development-setup.ps1) | Configure SSH client for remote development |

## Quick Example

```powershell
# Cleanup Docker images
.\Manage-Docker.ps1 -Cleanup -KeepVersions 2
```

---
**Last Updated**: 2026-06-14
