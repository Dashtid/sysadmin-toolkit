# Grafana Dashboards

Pre-configured Grafana dashboards for the lab server.

> **Scope note (2026-06-14):** the `service-health-monitor.sh` script was removed in the ghost-code cull — Prometheus + node-exporter + Grafana already covers service health on the lab server. The dashboards below are kept because they remain useful for the GPU exporter (and as references for Kubernetes/Docker views populated by other tooling on the lab server).

## Dashboards

| Dashboard | Purpose | Data source |
|-----------|---------|-------------|
| [grafana-dashboard-gpu.json](grafana-dashboard-gpu.json) | NVIDIA GPU metrics | `Linux/gpu/nvidia-gpu-exporter.sh` (scraped via node-exporter textfile collector) |
| [grafana-dashboard-kubernetes.json](grafana-dashboard-kubernetes.json) | K8s pod health (reference) | kube-state-metrics on the lab server |
| [grafana-dashboard-maintenance.json](grafana-dashboard-maintenance.json) | Docker/log cleanup (reference) | Existing lab-server exporters |

## Import a Dashboard

### Grafana UI
1. Open Grafana -> **Dashboards** -> **Import**
2. Upload the JSON file
3. Select your Prometheus data source
4. Click **Import**

### API

```bash
GRAFANA_URL="http://your-grafana:3000"
API_KEY="your-api-key"

curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard-gpu.json
```

## Key GPU Metrics

| Metric | Description |
|--------|-------------|
| nvidia_gpu_utilization_percent | GPU usage % |
| nvidia_gpu_temperature_celsius | Temperature |
| nvidia_gpu_memory_used_bytes | Memory used |
| nvidia_gpu_power_watts | Power draw |

## Verify

```bash
curl http://<lab-server>:9100/metrics | grep nvidia_gpu
```

---
**Last Updated**: 2026-06-14
