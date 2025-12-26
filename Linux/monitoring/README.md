# Grafana Dashboards

Pre-configured Grafana dashboards for lab server monitoring.

## Dashboards

| Dashboard | Purpose | Source Script |
|-----------|---------|---------------|
| [grafana-dashboard-gpu.json](grafana-dashboard-gpu.json) | NVIDIA GPU metrics | nvidia-gpu-exporter.sh |
| [grafana-dashboard-kubernetes.json](grafana-dashboard-kubernetes.json) | K8s pod health | pod-health-monitor.sh |
| [grafana-dashboard-maintenance.json](grafana-dashboard-maintenance.json) | Docker/log cleanup | docker-cleanup.sh |

## Import Dashboards

### Grafana UI
1. Open Grafana → **Dashboards** → **Import**
2. Upload JSON file
3. Select Prometheus data source
4. Click **Import**

### API Import
```bash
GRAFANA_URL="http://your-grafana:3000"
API_KEY="your-api-key"

curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard-gpu.json
```

## Key Metrics

### GPU Metrics
| Metric | Description |
|--------|-------------|
| nvidia_gpu_utilization_percent | GPU usage % |
| nvidia_gpu_temperature_celsius | Temperature |
| nvidia_gpu_memory_used_bytes | Memory used |
| nvidia_gpu_power_watts | Power draw |

### Kubernetes Metrics
| Metric | Description |
|--------|-------------|
| k8s_unhealthy_pods_total | Unhealthy pods |
| k8s_crashloop_pods_total | CrashLoopBackOff pods |
| k8s_oomkilled_pods_total | OOM killed pods |
| k8s_pending_pods_total | Pending pods |

### Maintenance Metrics
| Metric | Description |
|--------|-------------|
| docker_cleanup_images_removed_total | Images removed |
| docker_cleanup_space_reclaimed_bytes | Space freed |
| log_cleanup_logs_deleted_total | Logs deleted |

## Prometheus Setup

```yaml
scrape_configs:
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['10.143.31.18:9100']
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No data | Verify Prometheus data source connection |
| Metrics missing | Check scripts are running: `crontab -l` |
| Stale data | Check script logs in /var/log/ |

### Verify Metrics
```bash
# Check node-exporter
curl http://10.143.31.18:9100/metrics | grep nvidia_gpu

# Check Prometheus targets
curl http://prometheus:9090/api/v1/targets
```

## Prerequisites

- Grafana with Prometheus data source
- Prometheus scraping node-exporter
- Monitoring scripts running via cron

---
**Last Updated**: 2025-12-26
