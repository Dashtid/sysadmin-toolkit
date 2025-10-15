# Linux Maintenance Scripts

Automated update and maintenance scripts for Debian/Ubuntu Linux systems with support for APT and Snap packages.

## [*] Available Scripts

### system-updates.sh (Recommended)
**Version:** 1.0.0
**Purpose:** Comprehensive automated update script with advanced features

**Features:**
- Updates APT packages (apt update && apt upgrade)
- Updates Snap packages
- Exports pre-update state for rollback capability
- Prometheus metrics export for monitoring
- Configuration file support
- WhatIf mode for dry-run testing
- Update summary with duration tracking
- Automatic reboot handling
- Log retention management

**Usage:**
```bash
# Basic usage - updates everything
sudo ./system-updates.sh

# Skip specific update types
sudo ./system-updates.sh --skip-apt
sudo ./system-updates.sh --skip-snap

# Dry-run mode (shows what would be updated without doing it)
sudo ./system-updates.sh --whatif

# Automatic reboot after updates
sudo ./system-updates.sh --auto-reboot

# Use custom configuration file
sudo ./system-updates.sh --config /etc/system-updates.json

# Combine options
sudo ./system-updates.sh --skip-snap --auto-reboot
```

**Configuration File:**
Create `config.json` in this directory (or use a custom path with `--config`):
```json
{
  "AutoReboot": false,
  "LogRetentionDays": 30,
  "SkipAPT": false,
  "SkipSnap": false,
  "ExportMetrics": true
}
```

See [config.example.json](config.example.json) for a template with detailed comments.

---

### restore-previous-state.sh
**Version:** 1.0.0
**Purpose:** Rollback tool to restore system to pre-update state

**Features:**
- Lists available backup states
- Compares current vs. backup package versions
- Downgrades upgraded packages (APT)
- Reinstalls removed packages
- WhatIf mode for safe preview

**Usage:**
```bash
# List all available backups
sudo ./restore-previous-state.sh --list

# Show differences from latest backup (no changes)
sudo ./restore-previous-state.sh --latest --show-diff

# Restore from latest backup
sudo ./restore-previous-state.sh --latest

# Restore from specific backup file
sudo ./restore-previous-state.sh --backup-file /var/log/system-updates/states/pre-update-state_2025-10-15_10-30-00.json

# Preview what would be restored (dry-run)
sudo ./restore-previous-state.sh --latest --whatif
```

---

## [!] Prerequisites

### Required Software
- **Bash 4.0+** - Should be standard on Ubuntu 20.04+
- **Root/sudo privileges** - All scripts require elevation
- **jq** - JSON parser for configuration files

### Install Dependencies
```bash
sudo apt update
sudo apt install -y jq
```

### Optional Software
- **snap** - Pre-installed on Ubuntu, but updates can be skipped if not used

---

## [+] Quick Start

### First-Time Setup

1. **Make scripts executable**:
   ```bash
   chmod +x system-updates.sh restore-previous-state.sh
   ```

2. **Install dependencies**:
   ```bash
   sudo apt install -y jq
   ```

3. **Copy configuration template**:
   ```bash
   cp config.example.json config.json
   ```

4. **Edit configuration** (optional):
   ```bash
   nano config.json
   ```

5. **Run your first update** (dry-run):
   ```bash
   sudo ./system-updates.sh --whatif
   ```

6. **Run actual updates**:
   ```bash
   sudo ./system-updates.sh
   ```

### Scheduled Task Setup (Cron)

Run updates automatically every Sunday at 3 AM:

```bash
# Edit root's crontab
sudo crontab -e

# Add this line:
0 3 * * 0 /path/to/sysadmin-toolkit/Linux/maintenance/system-updates.sh --auto-reboot
```

### Scheduled Task Setup (Systemd Timer)

Create a more robust scheduled task using systemd:

1. **Create service file** (`/etc/systemd/system/system-updates.service`):
   ```ini
   [Unit]
   Description=Automated System Updates
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=oneshot
   ExecStart=/path/to/sysadmin-toolkit/Linux/maintenance/system-updates.sh
   StandardOutput=journal
   StandardError=journal
   ```

2. **Create timer file** (`/etc/systemd/system/system-updates.timer`):
   ```ini
   [Unit]
   Description=Run system updates weekly

   [Timer]
   OnCalendar=Sun *-*-* 03:00:00
   Persistent=true

   [Install]
   WantedBy=timers.target
   ```

3. **Enable and start the timer**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable system-updates.timer
   sudo systemctl start system-updates.timer

   # Check timer status
   sudo systemctl list-timers system-updates.timer
   ```

---

## [i] Update Summary Example

After running `system-updates.sh`, you'll see a summary like this:

```
=== Update Summary ===
[+] APT: 12 packages updated
[+] Snap: 3 packages updated
[+] Reboot Required: NO
[+] State File: /var/log/system-updates/states/pre-update-state_2025-10-15_10-30-00.json
[i] Total Runtime: 00:08:45
=====================
```

---

## [*] Logging

### Log Location
All scripts use `/var/log/system-updates/`:
```
/var/log/system-updates/
├── system-updates_2025-10-15.log         # Main log file
├── states/
│   └── pre-update-state_*.json           # Package state before updates
└── metrics/
    └── system_updates.prom               # Prometheus metrics
```

### Log Retention
- Default: 30 days
- Configurable via `LogRetentionDays` parameter or config file
- Automatic cleanup on each run

---

## [*] Prometheus Integration

### Metrics Export

`system-updates.sh` automatically exports metrics to:
```
/var/log/system-updates/metrics/system_updates.prom
```

**Exported Metrics:**
```prometheus
system_updates_apt_packages_updated{hostname="server1"} 12
system_updates_apt_packages_failed{hostname="server1"} 0
system_updates_snap_packages_updated{hostname="server1"} 3
system_updates_snap_packages_failed{hostname="server1"} 0
system_updates_reboot_required{hostname="server1"} 0
system_updates_duration_seconds{hostname="server1"} 525
system_updates_last_run_timestamp{hostname="server1"} 1729075345
```

### Prometheus Node Exporter Setup

Configure Prometheus node_exporter to scrape these metrics:

1. **Install node_exporter** (if not already installed):
   ```bash
   sudo apt install prometheus-node-exporter
   ```

2. **Configure textfile collector**:
   Edit `/etc/default/prometheus-node-exporter`:
   ```bash
   ARGS="--collector.textfile.directory=/var/log/system-updates/metrics"
   ```

3. **Restart node_exporter**:
   ```bash
   sudo systemctl restart prometheus-node-exporter
   ```

4. **Verify metrics** (from Prometheus server):
   ```promql
   system_updates_apt_packages_updated
   ```

### Grafana Dashboard

Create alerts and dashboards in Grafana using these metrics:

**Example PromQL Queries:**
```promql
# Packages updated in last 24 hours
sum(system_updates_apt_packages_updated)

# Systems requiring reboot
system_updates_reboot_required == 1

# Failed updates
sum(system_updates_apt_packages_failed + system_updates_snap_packages_failed) > 0

# Last update time
time() - system_updates_last_run_timestamp{hostname="server1"}
```

---

## [!] Safety Features

### Pre-Update State Export
Each update run exports current package versions to:
```
/var/log/system-updates/states/pre-update-state_<timestamp>.json
```

Use `restore-previous-state.sh` to rollback if updates cause issues.

### WhatIf Mode
Test updates without making changes:
```bash
sudo ./system-updates.sh --whatif
```

### Show Differences Before Restore
Preview what will be restored:
```bash
sudo ./restore-previous-state.sh --latest --show-diff
```

---

## [!] Troubleshooting

### Common Issues

#### "jq: command not found"
Install jq JSON parser:
```bash
sudo apt install -y jq
```

#### "Permission denied" when running scripts
Ensure scripts are executable:
```bash
chmod +x system-updates.sh restore-previous-state.sh
```

#### "This script must be run as root"
Always use sudo:
```bash
sudo ./system-updates.sh
```

#### APT package downgrade fails
Some packages cannot be downgraded if dependencies conflict. In such cases:
```bash
# Check available versions
apt-cache policy <package-name>

# Force downgrade with dependencies
sudo apt install <package-name>=<version> --allow-downgrades
```

#### Snap packages don't update
Check snap daemon status:
```bash
sudo systemctl status snapd
sudo snap refresh --list
```

#### Updates appear to hang
Check for interactive prompts in the log:
```bash
tail -f /var/log/system-updates/system-updates_$(date +%Y-%m-%d).log
```

The script uses `DEBIAN_FRONTEND=noninteractive` to avoid prompts, but some packages may still cause issues.

### Getting Help
```bash
# View script help
./system-updates.sh --help
./restore-previous-state.sh --help

# Check logs
sudo tail -f /var/log/system-updates/system-updates_$(date +%Y-%m-%d).log
```

For more troubleshooting tips, see [docs/TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md)

---

## [*] Best Practices

### For Production Servers
1. **Test first** - Use `--whatif` mode before actual updates
2. **Use config files** - Avoid command-line parameters for scheduled tasks
3. **Monitor logs** - Check logs after automated runs
4. **Schedule during maintenance windows** - Update during low-activity periods
5. **Keep backups** - State exports are NOT a replacement for full system backups
6. **Export metrics** - Monitor update status with Prometheus/Grafana

### For Kubernetes Nodes
1. **Drain nodes before updates** - Use `kubectl drain` before updating
2. **Update one node at a time** - Don't update all nodes simultaneously
3. **Skip AutoReboot** - Manually reboot nodes on your schedule
4. **Test on dev clusters first** - Validate updates on non-production clusters
5. **Monitor pod disruption** - Watch for pod evictions during updates

### For Containers/VMs
1. **Snapshot before updates** - Create VM snapshots before major updates
2. **Disable AutoReboot** - Manually reboot on your schedule
3. **Stagger updates** - Don't update all instances simultaneously
4. **Use version pinning** - Pin critical packages to specific versions

---

## [!] Limitations

### Package Rollback
- **APT downgrades** - Work for most packages, but may fail if dependencies conflict
- **Snap downgrades** - Use `snap revert` or channel switching (not fully implemented yet)
- **Kernel updates** - Should NOT be downgraded (use system restore instead)

### Reboot Detection
- Checks `/var/run/reboot-required` file
- Some updates may require reboot but not set this flag
- Manual reboot may still be needed in edge cases

### Distribution Support
- Tested on Ubuntu 24.04 LTS
- Should work on Ubuntu 20.04+ and Debian 11+
- Other distributions may need adjustments (different package managers)

---

## [v] Version History

### 1.0.0 (2025-10-15)
- Initial release of system-updates.sh
- APT and Snap package update automation
- Pre-update state export with JSON format
- Prometheus metrics export for monitoring integration
- restore-previous-state.sh for package rollback
- Configuration file support
- WhatIf mode for dry-run testing
- Log retention management

---

## [i] Related Documentation

- [Windows Maintenance Scripts](../../Windows/maintenance/README.md) - Windows equivalent
- [Troubleshooting Guide](../../docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Functionality Roadmap](../../docs/ROADMAP.md) - Planned features and enhancements

---

**Last Updated:** 2025-10-15
**Maintainer:** Windows & Linux Sysadmin Toolkit
