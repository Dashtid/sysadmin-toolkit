# Security Scripts

Security auditing and compliance checking.

## Scripts

| Script | Purpose |
|--------|---------|
| [Get-UserAccountAudit.ps1](Get-UserAccountAudit.ps1) | Audit local users, admins, inactive accounts, password status |

## Quick Examples

```powershell
# Run security audit
.\Get-UserAccountAudit.ps1

# Export to HTML
.\Get-UserAccountAudit.ps1 -OutputFormat HTML -OutputPath "C:\Audits"

# Check specific concerns
.\Get-UserAccountAudit.ps1 -CheckInactiveAccounts -InactiveDays 90
```

## Related

Security hardening scripts are in [defensive-toolkit](https://github.com/Dashtid/defensive-toolkit).

---
**Last Updated**: 2025-12-26
