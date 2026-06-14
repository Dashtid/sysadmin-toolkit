# Windows Backup Scripts

Snapshot the developer environment (VSCode, Terminal, Git, SSH) before a machine rebuild.

> **Scope note (2026-06-14):** the broader backup tier (`Backup-UserData`, `Backup-BrowserProfiles`, `Export-SystemState`, `Test-BackupIntegrity`, `Restore-DeveloperEnvironment`) was removed in the ghost-code cull. User data is covered by OneDrive sync; browser bookmarks/extensions sync natively; lab-server backups live on q-backup via Velero. See [BACKLOG.md](../../BACKLOG.md) for rationale.

## Scripts

| Script | Purpose |
|--------|---------|
| [Backup-DeveloperEnvironment.ps1](Backup-DeveloperEnvironment.ps1) | Snapshot VSCode settings, Windows Terminal config, Git config, SSH keys |

## Quick Example

```powershell
# Snapshot before a rebuild
.\Backup-DeveloperEnvironment.ps1 -BackupPath "D:\DevBackups"
```

The script writes a manifest alongside the archive so the contents are self-describing.

---

**Last Updated**: 2026-06-14
