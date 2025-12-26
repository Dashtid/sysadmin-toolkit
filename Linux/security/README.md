# Security Hardening Scripts

Linux security hardening and auditing.

## Scripts

| Script | Purpose |
|--------|---------|
| [security-hardening.sh](security-hardening.sh) | SSH, firewall, kernel, and service hardening |

## Quick Examples

```bash
# Audit mode (no changes)
./security-hardening.sh --audit

# Apply hardening
sudo ./security-hardening.sh --apply

# Specific category
./security-hardening.sh --audit --category ssh
./security-hardening.sh --apply --category firewall
```

## Categories

- **ssh**: Key-only auth, disable root, secure ciphers
- **firewall**: UFW with sensible defaults
- **kernel**: sysctl security parameters
- **permissions**: Sensitive file permissions, SUID/SGID audit
- **users**: Password policies, inactive accounts
- **services**: Disable risky services

---
**Last Updated**: 2025-12-26
