# Linux Maintenance Scripts

Automated update and maintenance scripts for Debian/Ubuntu systems with APT/Snap support.

## Scripts

| Script | Purpose |
|--------|---------|
| [system-updates.sh](system-updates.sh) | APT/Snap updates with state export and Prometheus metrics |
| [restore-previous-state.sh](restore-previous-state.sh) | Rollback to pre-update package state |

## Quick Start

```bash
# Make executable
chmod +x system-updates.sh restore-previous-state.sh

# Install dependencies
sudo apt install -y jq

# Dry-run first
sudo ./system-updates.sh --whatif

# Run updates
sudo ./system-updates.sh
```

## Usage

### system-updates.sh

```bash
sudo ./system-updates.sh                    # Update everything
sudo ./system-updates.sh --skip-apt         # Skip APT packages
sudo ./system-updates.sh --skip-snap        # Skip Snap packages
sudo ./system-updates.sh --whatif           # Dry-run mode
sudo ./system-updates.sh --auto-reboot      # Reboot after updates
sudo ./system-updates.sh --config /path/to/config.json
```

### restore-previous-state.sh

```bash
sudo ./restore-previous-state.sh --list              # List backups
sudo ./restore-previous-state.sh --latest --show-diff # Preview changes
sudo ./restore-previous-state.sh --latest            # Restore latest
sudo ./restore-previous-state.sh --latest --whatif   # Dry-run restore
```

## Configuration

Create `config.json` from template:
```bash
cp config.example.json config.json
```

| Option | Default | Description |
|--------|---------|-------------|
| AutoReboot | false | Reboot after updates |
| LogRetentionDays | 30 | Days to keep logs |
| SkipAPT | false | Skip APT updates |
| SkipSnap | false | Skip Snap updates |
| ExportMetrics | true | Export Prometheus metrics |

## Scheduled Updates

### Cron (Simple)
```bash
sudo crontab -e
# Weekly Sunday 3 AM:
0 3 * * 0 /path/to/system-updates.sh --auto-reboot
```

### Systemd Timer (Robust)
```bash
# See /etc/systemd/system/system-updates.{service,timer}
sudo systemctl enable --now system-updates.timer
```

## Log Files

```
/var/log/system-updates/
├── system-updates_YYYY-MM-DD.log    # Main log
├── states/pre-update-state_*.json   # Package snapshots
└── metrics/system_updates.prom      # Prometheus metrics
```

## Prometheus Metrics

Exported to `/var/log/system-updates/metrics/system_updates.prom`:

| Metric | Description |
|--------|-------------|
| system_updates_apt_packages_updated | APT packages updated |
| system_updates_snap_packages_updated | Snap packages updated |
| system_updates_reboot_required | Reboot needed (0/1) |
| system_updates_duration_seconds | Update duration |
| system_updates_last_run_timestamp | Last run epoch |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| jq not found | `sudo apt install -y jq` |
| Permission denied | `chmod +x *.sh` and use `sudo` |
| APT downgrade fails | Check `apt-cache policy <pkg>` for versions |
| Snap not updating | `sudo systemctl status snapd` |

## Prerequisites

- Bash 4.0+
- Root/sudo privileges
- jq (for JSON parsing)

---
**Last Updated**: 2025-12-26
