# Docker Management Scripts

Automated Docker maintenance and cleanup tools for Linux servers.

## [*] Available Scripts

| Script | Purpose | Features |
|--------|---------|----------|
| [docker-cleanup.sh](docker-cleanup.sh) | Automated Docker cleanup | Image pruning, container cleanup, volume management |

---

## [+] Quick Start

```bash
# Preview what would be cleaned (dry-run)
./docker-cleanup.sh --whatif

# Run cleanup with defaults
./docker-cleanup.sh

# Keep only 2 versions per image, prune volumes
./docker-cleanup.sh --keep-versions 2 --prune-volumes

# Remove containers stopped more than 30 days ago
./docker-cleanup.sh --container-age-days 30
```

---

## [*] docker-cleanup.sh

Automated Docker cleanup to reclaim disk space while preserving important images.

**Features:**
- Remove dangling images (`<none>:<none>`)
- Keep only N latest versions per image repository
- Prune stopped containers older than X days
- Remove unused volumes (optional)
- Prometheus metrics export (disk space reclaimed)
- Dry-run mode for safe testing
- Configuration file support

**Parameters:**
| Option | Description | Default |
|--------|-------------|---------|
| `--keep-versions N` | Keep N most recent versions per image | 3 |
| `--container-age-days N` | Remove containers stopped > N days | 7 |
| `--prune-volumes` | Also prune unused volumes | false |
| `--whatif` | Dry-run mode | false |
| `--config FILE` | Configuration file path | config.json |
| `--debug` | Enable debug logging | false |

**Examples:**

```bash
# Safe preview before cleanup
./docker-cleanup.sh --whatif

# Aggressive cleanup (keep 1 version, prune volumes)
./docker-cleanup.sh --keep-versions 1 --prune-volumes

# With custom config file
./docker-cleanup.sh --config /etc/docker-cleanup/config.json
```

---

## [i] Configuration File

Create `config.json` for persistent settings:

```json
{
  "keep_versions": 3,
  "container_age_days": 7,
  "prune_volumes": false,
  "protected_images": [
    "postgres:15",
    "redis:7-alpine"
  ],
  "output_dir": "/var/log/docker-cleanup",
  "metrics_enabled": true
}
```

---

## [*] Prometheus Integration

The script exports metrics to `/var/lib/prometheus/node-exporter/docker_cleanup.prom`:

```prometheus
# HELP docker_cleanup_disk_reclaimed_bytes Disk space reclaimed by cleanup
# TYPE docker_cleanup_disk_reclaimed_bytes gauge
docker_cleanup_disk_reclaimed_bytes 1073741824

# HELP docker_cleanup_images_removed Number of images removed
# TYPE docker_cleanup_images_removed gauge
docker_cleanup_images_removed 15

# HELP docker_cleanup_containers_removed Number of containers removed
# TYPE docker_cleanup_containers_removed gauge
docker_cleanup_containers_removed 8

# HELP docker_cleanup_last_run_timestamp Unix timestamp of last run
# TYPE docker_cleanup_last_run_timestamp gauge
docker_cleanup_last_run_timestamp 1703520000
```

---

## [+] Automated Cleanup via Cron

Add to crontab for scheduled cleanup:

```bash
# Edit crontab
crontab -e

# Add weekly cleanup (Sunday 3 AM)
0 3 * * 0 /opt/sysadmin-toolkit/Linux/docker/docker-cleanup.sh --prune-volumes >> /var/log/docker-cleanup/cron.log 2>&1
```

---

## [!] Prerequisites

- **Docker** installed and running
- **jq** for JSON parsing (`apt install jq`)
- User in `docker` group or root access
- Common functions library (`../lib/bash/common-functions.sh`)

---

## [*] What Gets Cleaned

| Category | Cleaned | Preserved |
|----------|---------|-----------|
| **Dangling Images** | All `<none>:<none>` | - |
| **Tagged Images** | Older versions beyond `--keep-versions` | N latest per repository |
| **Containers** | Stopped > `--container-age-days` | Running, recently stopped |
| **Volumes** | Unused (if `--prune-volumes`) | In-use volumes |
| **Build Cache** | Unused layers | Recent cache |

---

## [!] Safety Features

- **Dry-run mode** (`--whatif`) - Always preview before cleanup
- **Protected images** - Configure images that should never be removed
- **Running container protection** - Never removes running containers
- **Logging** - All actions logged to `/var/log/docker-cleanup/`

---

## [*] Related Documentation

- [Kubernetes Monitoring](../kubernetes/README.md)
- [System Health Check](../monitoring/README.md)

---

**Last Updated**: 2025-12-25
**Version**: 2.0.0
