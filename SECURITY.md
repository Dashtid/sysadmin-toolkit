# Security Policy

## Reporting Vulnerabilities

**Do not** create public GitHub issues for security vulnerabilities.

**Report via email** to maintainer (available on GitHub profile):
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline**:

| Severity | Response | Fix |
|----------|----------|-----|
| Critical | 48 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 7 days | 30 days |
| Low | 7 days | Next release |

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main) | Yes |
| < 2.0 | No |

## Security Scanning

This repository uses:
- GitHub Secret Scanning
- Pre-commit hooks for local validation
- GitHub Actions for CI security checks

## Never Commit

| Type | Examples |
|------|----------|
| Credentials | Passwords, API keys, tokens |
| Keys | SSH private keys, certificates (.pem, .pfx, .key) |
| Connection strings | Database URLs with credentials |
| Real IPs | Use RFC 5737: 192.0.2.x, 198.51.100.x, 203.0.113.x |
| Personal data | Names, emails, company information |

## Best Practices

| Practice | Implementation |
|----------|----------------|
| Parameters | No hardcoded values in scripts |
| Templates | Use `.example` files for configs |
| Environment | Use `.env.local` (gitignored) |
| Validation | Sanitize all user input |
| Review | Check `git diff` before commit |

## If Secrets Are Exposed

1. **Immediately rotate/revoke** the credential
2. **Remove from Git history**:
   ```bash
   git filter-repo --path path/to/secret --invert-paths
   git push origin --force --all
   ```
3. **Notify collaborators** to re-clone (not pull)

## Security Tools

- [git-secrets](https://github.com/awslabs/git-secrets)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [detect-secrets](https://github.com/Yelp/detect-secrets)

## Resources

- [GitHub: Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [RFC 5737: Documentation IPs](https://tools.ietf.org/html/rfc5737)

---
**Last Updated**: 2025-12-26 | **Contact**: [@dashtid](https://github.com/dashtid)
