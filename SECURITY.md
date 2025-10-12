# Security Policy

## Reporting a Vulnerability

The security of this project is taken seriously. If you discover a security vulnerability, please report it responsibly.

**DO NOT** create a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email**: Send details to the maintainer's email (available on GitHub profile)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: In next release
- **Disclosure**: After fix is released, with credit if desired

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 2.0   | :x:                |

Scripts are maintained on a rolling-release basis. Always use the latest version from the main branch.

## Security Best Practices

For detailed security guidelines, see:
- [Security Best Practices Documentation](docs/SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

### Quick Reference

**Never commit:**
- Passwords, API keys, tokens
- SSH private keys
- Database credentials
- Real IP addresses or hostnames
- Personal or company-specific information

**Always:**
- Use parameters for configuration
- Provide `.example` template files
- Review diffs before committing
- Use environment variables for secrets
- Test scripts in safe environments first

## Security Scanning

This repository uses:
- **GitHub Secret Scanning**: Automatic detection of known secret patterns
- **Custom Pre-commit Hooks**: Local validation before commits
- **GitHub Actions**: Continuous security checks on all PRs

## Known Limitations

These scripts require privileged access for system administration tasks. Review and understand scripts before running with administrator/sudo privileges.

## Attribution

Security researchers who responsibly disclose vulnerabilities will be credited in:
- Release notes
- CHANGELOG.md
- Security advisories (if published)

## Questions?

For non-security questions, open a regular GitHub issue or discussion.

---

**Last Updated**: 2025-10-12
**Contact**: [@dashtid](https://github.com/dashtid)
