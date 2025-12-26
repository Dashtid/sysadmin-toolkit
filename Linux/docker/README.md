# Docker Management Scripts

Automated Docker maintenance and cleanup for Linux servers.

## Scripts

| Script | Purpose |
|--------|---------|
| [docker-cleanup.sh](docker-cleanup.sh) | Image pruning, container cleanup, volume management |

## Quick Start

```bash
# Preview cleanup (dry-run)
./docker-cleanup.sh --whatif

# Run with defaults
./docker-cleanup.sh

# Keep 2 versions, prune volumes
./docker-cleanup.sh --keep-versions 2 --prune-volumes

# Remove old containers
./docker-cleanup.sh --container-age-days 30
```

## Parameters

| Option | Description | Default |
|--------|-------------|---------|
| `--keep-versions N` | Keep N latest versions per image | 3 |
| `--container-age-days N` | Remove containers stopped > N days | 7 |
| `--prune-volumes` | Also prune unused volumes | false |
| `--whatif` | Dry-run mode | false |
| `--config FILE` | Configuration file path | config.json |

## Configuration

Create `config.json`:
```json
{
  "keep_versions": 3,
  "container_age_days": 7,
  "prune_volumes": false,
  "protected_images": ["postgres:15", "redis:7-alpine"],
  "metrics_enabled": true
}
```

## What Gets Cleaned

| Category | Cleaned | Preserved |
|----------|---------|-----------|
| Dangling images | All `<none>:<none>` | - |
| Tagged images | Beyond keep-versions | N latest per repo |
| Containers | Stopped > age-days | Running, recent |
| Volumes | Unused (if enabled) | In-use |

## Prometheus Metrics

Exported to `/var/lib/prometheus/node-exporter/docker_cleanup.prom`:

| Metric | Description |
|--------|-------------|
| docker_cleanup_disk_reclaimed_bytes | Space freed |
| docker_cleanup_images_removed | Images removed |
| docker_cleanup_containers_removed | Containers removed |

## Cron Setup

```bash
# Weekly Sunday 3 AM
0 3 * * 0 /path/to/docker-cleanup.sh --prune-volumes >> /var/log/docker-cleanup/cron.log 2>&1
```

## Prerequisites

- Docker installed and running
- jq (`apt install jq`)
- User in docker group or root

---
**Last Updated**: 2025-12-26
