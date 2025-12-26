# Troubleshooting Scripts

Automated diagnosis and repair for common Windows issues.

## Scripts

| Script | Purpose |
|--------|---------|
| [Repair-CommonIssues.ps1](Repair-CommonIssues.ps1) | Fix DNS, network, Windows Update, audio, printer issues |

## Quick Examples

```powershell
# Diagnose all issues
.\Repair-CommonIssues.ps1 -Diagnose

# Fix specific category
.\Repair-CommonIssues.ps1 -Fix Network
.\Repair-CommonIssues.ps1 -Fix DNS
.\Repair-CommonIssues.ps1 -Fix WindowsUpdate

# Run system file checker
.\Repair-CommonIssues.ps1 -Fix SystemFiles
```

---
**Last Updated**: 2025-12-26
