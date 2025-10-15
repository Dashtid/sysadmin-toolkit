# Grafana Dashboards for Lab Server Monitoring

This directory contains pre-configured Grafana dashboards for monitoring the lab server metrics exported by the sysadmin-toolkit scripts.

## Available Dashboards

### 1. GPU Monitoring (`grafana-dashboard-gpu.json`)
Monitors NVIDIA GPU metrics exported by `nvidia-gpu-exporter.sh`.

**Panels:**
- GPU Utilization (%) - Real-time GPU usage
- GPU Temperature (°C) - Temperature with thresholds (70°C yellow, 85°C red)
- GPU Memory Usage (%) - Memory utilization percentage
- GPU Power Draw (W) - Current power consumption
- Memory Stats (GB) - Used vs Total memory
- Current Temperature - Single stat with color thresholds

**Metrics Used:**
- `nvidia_gpu_utilization_percent`
- `nvidia_gpu_temperature_celsius`
- `nvidia_gpu_memory_used_bytes`
- `nvidia_gpu_memory_total_bytes`
- `nvidia_gpu_power_watts`

### 2. Kubernetes Pod Health (`grafana-dashboard-kubernetes.json`)
Monitors Kubernetes pod health exported by `pod-health-monitor.sh`.

**Panels:**
- Unhealthy Pods - Total unhealthy pods (0=green, 1+=yellow, 5+=red)
- CrashLoopBackOff Pods - Pods stuck in crash loop (0=green, 1+=red)
- OOMKilled Pods - Pods killed due to out-of-memory (0=green, 1+=red)
- Pending Pods - Pods waiting to be scheduled (0=green, 1+=yellow, 3+=red)
- Pod Health Over Time - Time series showing all pod states
- Image Pull Errors - Pods with image pull failures
- Last Monitor Check - Time since last monitoring run

**Metrics Used:**
- `k8s_unhealthy_pods_total`
- `k8s_crashloop_pods_total`
- `k8s_oomkilled_pods_total`
- `k8s_pending_pods_total`
- `k8s_image_pull_error_pods_total`
- `k8s_monitor_timestamp`

### 3. Maintenance & Cleanup (`grafana-dashboard-maintenance.json`)
Tracks Docker and log cleanup operations.

**Panels:**
- Docker Images Removed - Images removed in last cleanup run
- Space Reclaimed - Disk space freed (GB)
- Execution Time - Time taken for cleanup
- Last Docker Cleanup - Time since last run
- Space Reclaimed Over Time - Trend of space recovery
- Logs Compressed - Number of log files compressed
- Logs Deleted - Number of log files deleted
- Log Space Reclaimed - Space freed by log cleanup (MB)
- Last Log Cleanup - Time since last log cleanup

**Metrics Used:**
- `docker_cleanup_images_removed_total`
- `docker_cleanup_space_reclaimed_bytes`
- `docker_cleanup_execution_time_seconds`
- `docker_cleanup_timestamp`
- `log_cleanup_logs_compressed_total`
- `log_cleanup_logs_deleted_total`
- `log_cleanup_space_reclaimed_bytes`
- `log_cleanup_timestamp`

## Import Instructions

### Method 1: Grafana UI Import

1. Open Grafana web interface (http://your-grafana-host:3000)
2. Navigate to: **Dashboards** → **Import**
3. Click **Upload JSON file**
4. Select one of the dashboard JSON files
5. Choose your Prometheus data source
6. Click **Import**

### Method 2: API Import (Automated)

```bash
# Set your Grafana URL and API key
GRAFANA_URL="http://10.143.31.115"
API_KEY="your-api-key-here"

# Import GPU dashboard
curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard-gpu.json

# Import Kubernetes dashboard
curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard-kubernetes.json

# Import Maintenance dashboard
curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard-maintenance.json
```

### Method 3: ConfigMap in Kubernetes

If running Grafana in Kubernetes, create a ConfigMap with dashboard definitions:

```bash
kubectl create configmap grafana-dashboards \
  --from-file=grafana-dashboard-gpu.json \
  --from-file=grafana-dashboard-kubernetes.json \
  --from-file=grafana-dashboard-maintenance.json \
  -n monitoring
```

Then mount the ConfigMap in your Grafana deployment at `/etc/grafana/provisioning/dashboards/`.

## Prerequisites

### Prometheus Configuration

Ensure Prometheus is scraping the node-exporter endpoint where metrics are exported:

```yaml
scrape_configs:
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['10.143.31.18:9100']
        labels:
          instance: 'lab-server'
```

### Metrics Validation

Before importing dashboards, verify metrics are available in Prometheus:

```bash
# Check if GPU metrics are available
curl -s http://your-prometheus:9090/api/v1/query?query=nvidia_gpu_utilization_percent

# Check Kubernetes metrics
curl -s http://your-prometheus:9090/api/v1/query?query=k8s_unhealthy_pods_total

# Check Docker cleanup metrics
curl -s http://your-prometheus:9090/api/v1/query?query=docker_cleanup_space_reclaimed_bytes
```

## Alert Configuration

### Recommended Prometheus Alerting Rules

Create these alerts in your Prometheus configuration:

```yaml
groups:
  - name: lab_server_alerts
    interval: 1m
    rules:
      # GPU Alerts
      - alert: GPUTemperatureHigh
        expr: nvidia_gpu_temperature_celsius > 85
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "GPU temperature critically high"
          description: "GPU {{ $labels.gpu }} temperature is {{ $value }}°C"

      - alert: GPUMemoryHigh
        expr: (nvidia_gpu_memory_used_bytes / nvidia_gpu_memory_total_bytes * 100) > 90
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "GPU memory usage high"
          description: "GPU {{ $labels.gpu }} memory usage is {{ $value }}%"

      # Kubernetes Alerts
      - alert: PodsCrashLooping
        expr: k8s_crashloop_pods_total > 0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Pods in CrashLoopBackOff state"
          description: "{{ $value }} pods are crash looping"

      - alert: PodsOOMKilled
        expr: k8s_oomkilled_pods_total > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pods killed due to OOM"
          description: "{{ $value }} pods were OOM killed"

      # Maintenance Alerts
      - alert: DockerCleanupNotRunning
        expr: time() - docker_cleanup_timestamp > 172800
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Docker cleanup hasn't run in 48 hours"
          description: "Last run: {{ $value | humanizeDuration }}"

      - alert: LowDiskSpaceReclaimed
        expr: docker_cleanup_space_reclaimed_bytes < 1073741824
        for: 1d
        labels:
          severity: info
        annotations:
          summary: "Docker cleanup reclaimed less than 1GB"
          description: "Only {{ $value | humanize1024 }}B reclaimed"
```

## Dashboard Customization

### Modifying Refresh Rates

Edit the dashboard JSON and change the `refresh` field:

```json
"refresh": "30s",  // Change to: "1m", "5m", "10m", etc.
```

### Adjusting Thresholds

Modify threshold values in panel fieldConfig:

```json
"thresholds": {
  "steps": [
    {"value": 0, "color": "green"},
    {"value": 70, "color": "yellow"},  // Change these values
    {"value": 85, "color": "red"}
  ]
}
```

### Adding Custom Queries

Add new panels by copying existing panel definitions and modifying the `expr` field:

```json
{
  "expr": "your_custom_promql_query",
  "legendFormat": "Your Legend {{label}}"
}
```

## Troubleshooting

### Dashboard Shows "No Data"

1. **Check Prometheus connection:**
   - Verify Prometheus data source is configured in Grafana
   - Test connection: Settings → Data Sources → Prometheus → Test

2. **Verify metrics are being collected:**
   ```bash
   # Check node-exporter is serving metrics
   curl http://10.143.31.18:9100/metrics | grep nvidia_gpu

   # Check Prometheus is scraping
   curl http://your-prometheus:9090/api/v1/targets
   ```

3. **Ensure scripts are running:**
   ```bash
   # Check cron jobs
   crontab -l

   # Manually run scripts to generate metrics
   sudo /path/to/nvidia-gpu-exporter.sh
   sudo /path/to/pod-health-monitor.sh
   ```

### Metrics Not Updating

1. **Check script execution logs:**
   ```bash
   tail -f /var/log/gpu-monitor/cron.log
   tail -f /var/log/docker-cleanup/cron.log
   ```

2. **Verify metrics file permissions:**
   ```bash
   ls -la /var/lib/prometheus/node-exporter/
   # Files should be readable by prometheus user
   ```

3. **Check Prometheus scrape interval:**
   - Default is usually 15s-1m
   - Adjust dashboard time range if needed

## Dashboard Maintenance

### Backup Dashboards

Export dashboards regularly:

```bash
# Via API
curl -H "Authorization: Bearer $API_KEY" \
  "$GRAFANA_URL/api/dashboards/uid/$DASHBOARD_UID" > backup.json
```

### Version Control

These dashboard JSONs are version-controlled in this repository. After making changes in Grafana UI:

1. Export the updated dashboard (JSON model)
2. Update the corresponding JSON file in this directory
3. Commit changes to Git

## Additional Resources

- [Grafana Dashboard Documentation](https://grafana.com/docs/grafana/latest/dashboards/)
- [PromQL Basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Grafana Alerting](https://grafana.com/docs/grafana/latest/alerting/)

---

**Last Updated**: 2025-10-15
