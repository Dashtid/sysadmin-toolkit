# Linux Maintenance Scripts

> **Scope note (2026-06-14):** `system-update.sh`, `log-cleanup.sh`, and `restore-previous-state.sh` were removed in the ghost-code cull. `apt`/`apt-get` and `journalctl --vacuum-time` cover those needs natively, and the rollback script was speculative (never used in a real restore).

## Scripts

| Script | Purpose |
|--------|---------|
| [disk-cleanup.sh](disk-cleanup.sh) | APT cache + journal + Docker leftover cleanup with `--whatif` and confirmation guards |

## Quick Example

```bash
# Dry-run first
sudo ./disk-cleanup.sh --whatif

# Run for real
sudo ./disk-cleanup.sh
```

## Prerequisites

- Bash 4.0+
- Root/sudo privileges

---
**Last Updated**: 2026-06-14
