# Windows Backup Scripts

Backup, export, and validation utilities for Windows systems.

## Scripts

| Script | Purpose |
|--------|---------|
| [Backup-UserData.ps1](Backup-UserData.ps1) | Backup user documents, desktop, downloads with compression |
| [Backup-BrowserProfiles.ps1](Backup-BrowserProfiles.ps1) | Backup browser bookmarks, extensions, settings |
| [Export-SystemState.ps1](Export-SystemState.ps1) | Export drivers, registry, network, tasks, services |
| [Test-BackupIntegrity.ps1](Test-BackupIntegrity.ps1) | Validate backup archives and test restores |

## Quick Examples

```powershell
# Backup user data
.\Backup-UserData.ps1 -Destination "D:\Backups" -Compress

# Export system configuration
.\Export-SystemState.ps1 -Destination "D:\SystemState" -Include All -Compress

# Validate a backup
.\Test-BackupIntegrity.ps1 -BackupPath "D:\Backups\backup.zip" -TestType Full

# Test restore to temp location
.\Test-BackupIntegrity.ps1 -BackupPath "D:\Backups" -TestType Restore -RestoreTarget "C:\Temp\TestRestore" -CleanupAfterTest
```

## Output Formats

All scripts support `-OutputFormat Console|HTML|JSON|All`.

---

**Last Updated**: 2025-12-25
