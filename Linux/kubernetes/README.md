# Kubernetes Monitoring Scripts

Health monitoring and metrics collection for Kubernetes clusters.

## Scripts

| Script | Purpose |
|--------|---------|
| [pod-health-monitor.sh](pod-health-monitor.sh) | Pod health and restart detection |
| [pvc-monitor.sh](pvc-monitor.sh) | PVC capacity and binding status |

## Quick Start

```bash
# Monitor all pods
./pod-health-monitor.sh

# Monitor specific namespace
./pod-health-monitor.sh --namespace docker-services

# Check PVC status
./pvc-monitor.sh --namespace default

# Dry-run mode
./pod-health-monitor.sh --whatif
```

## Usage

### pod-health-monitor.sh

| Option | Description | Default |
|--------|-------------|---------|
| `--namespace NS` | Monitor specific namespace | all |
| `--kubeconfig PATH` | Path to kubeconfig | default |
| `--restart-threshold N` | Alert if restarts > N | 5 |
| `--output-dir DIR` | Log directory | /var/log/k8s-monitor |
| `--whatif` | Dry-run mode | false |

**Detected Issues**: CrashLoopBackOff, OOMKilled, ImagePullBackOff, Pending, High Restarts

### pvc-monitor.sh

| Option | Description | Default |
|--------|-------------|---------|
| `--namespace NS` | Monitor specific namespace | all |
| `--threshold N` | Alert if usage > N% | 85 |
| `--output-dir DIR` | Log directory | /var/log/k8s-monitor |

## Prometheus Metrics

Exported to `/var/lib/prometheus/node-exporter/`:

| Metric | Description |
|--------|-------------|
| k8s_pod_unhealthy | Unhealthy pods by reason |
| k8s_pod_restarts_total | Total pod restarts |
| k8s_pvc_usage_percent | PVC usage percentage |
| k8s_pvc_pending | Pending PVCs |

## Cron Setup

```bash
# Every 5 minutes
*/5 * * * * /path/to/pod-health-monitor.sh >> /var/log/k8s-monitor/cron.log 2>&1

# Hourly PVC check
0 * * * * /path/to/pvc-monitor.sh --threshold 80 >> /var/log/k8s-monitor/pvc.log 2>&1
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No pods found | Check `kubectl config current-context` |
| Permission denied | `kubectl auth can-i get pods --all-namespaces` |
| Metrics missing | Verify scripts running via cron |

## Prerequisites

- kubectl configured
- jq for JSON parsing
- Read access to Kubernetes cluster

---
**Last Updated**: 2025-12-26
