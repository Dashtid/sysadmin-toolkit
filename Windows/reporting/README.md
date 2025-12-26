# Reporting Scripts

System information and reporting utilities.

## Scripts

| Script | Purpose |
|--------|---------|
| [Get-SystemReport.ps1](Get-SystemReport.ps1) | Generate comprehensive system report (hardware, software, network) |

## Quick Examples

```powershell
# Generate HTML report
.\Get-SystemReport.ps1 -OutputFormat HTML -OutputPath "C:\Reports"

# JSON export for automation
.\Get-SystemReport.ps1 -OutputFormat JSON

# Full report with all sections
.\Get-SystemReport.ps1 -Include All -OutputFormat All
```

---
**Last Updated**: 2025-12-26
