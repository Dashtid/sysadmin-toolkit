# Kubernetes Monitoring Scripts

Health monitoring and metrics collection tools for Kubernetes clusters.

## [*] Available Scripts

| Script | Purpose | Metrics |
|--------|---------|---------|
| [pod-health-monitor.sh](pod-health-monitor.sh) | Pod health and restart detection | CrashLoopBackOff, OOMKilled, ImagePullBackOff |
| [pvc-monitor.sh](pvc-monitor.sh) | Persistent Volume Claim monitoring | Capacity, usage, binding status |

---

## [+] Quick Start

```bash
# Monitor all pods across namespaces
./pod-health-monitor.sh

# Monitor specific namespace
./pod-health-monitor.sh --namespace docker-services

# Check PVC status
./pvc-monitor.sh --namespace default

# Dry-run to see what would be reported
./pod-health-monitor.sh --whatif
```

---

## [*] pod-health-monitor.sh

Detects unhealthy Kubernetes pods and exports Prometheus metrics.

**Detected Issues:**
- **CrashLoopBackOff** - Container repeatedly crashing
- **OOMKilled** - Container killed due to memory limits
- **ImagePullBackOff** - Failed to pull container image
- **Pending** - Pod stuck waiting for resources
- **High Restart Count** - Pods exceeding restart threshold

**Parameters:**
| Option | Description | Default |
|--------|-------------|---------|
| `--namespace NS` | Monitor specific namespace | all |
| `--kubeconfig PATH` | Path to kubeconfig file | default |
| `--output-dir DIR` | Directory for logs and metrics | /var/log/k8s-monitor |
| `--restart-threshold N` | Alert if restarts > N | 5 |
| `--whatif` | Dry-run mode | false |

**Examples:**

```bash
# Monitor all namespaces with custom threshold
./pod-health-monitor.sh --restart-threshold 10

# Use custom kubeconfig
./pod-health-monitor.sh --kubeconfig ~/.kube/config-lab

# Monitor docker-services namespace only
./pod-health-monitor.sh --namespace docker-services
```

---

## [*] pvc-monitor.sh

Monitors Persistent Volume Claims for capacity and health issues.

**Detected Issues:**
- **Pending** - PVC waiting for volume binding
- **High Usage** - Volume approaching capacity limits
- **Lost** - PVC lost connection to underlying volume

**Parameters:**
| Option | Description | Default |
|--------|-------------|---------|
| `--namespace NS` | Monitor specific namespace | all |
| `--threshold N` | Alert if usage > N% | 85 |
| `--output-dir DIR` | Directory for logs | /var/log/k8s-monitor |

---

## [i] Prometheus Integration

Scripts export metrics to `/var/lib/prometheus/node-exporter/`:

**Pod Health Metrics:**
```prometheus
# HELP k8s_pod_unhealthy Number of unhealthy pods
# TYPE k8s_pod_unhealthy gauge
k8s_pod_unhealthy{namespace="docker-services",reason="CrashLoopBackOff"} 2

# HELP k8s_pod_restarts_total Total pod restarts
# TYPE k8s_pod_restarts_total counter
k8s_pod_restarts_total{namespace="docker-services",pod="web-app-abc123"} 15

# HELP k8s_monitor_last_run_timestamp Unix timestamp of last run
# TYPE k8s_monitor_last_run_timestamp gauge
k8s_monitor_last_run_timestamp 1703520000
```

**PVC Metrics:**
```prometheus
# HELP k8s_pvc_usage_percent PVC usage percentage
# TYPE k8s_pvc_usage_percent gauge
k8s_pvc_usage_percent{namespace="default",pvc="data-postgres-0"} 72

# HELP k8s_pvc_pending Number of pending PVCs
# TYPE k8s_pvc_pending gauge
k8s_pvc_pending{namespace="default"} 0
```

---

## [+] Automated Monitoring via Cron

Add to crontab for scheduled checks:

```bash
# Edit crontab
crontab -e

# Check pod health every 5 minutes
*/5 * * * * /opt/sysadmin-toolkit/Linux/kubernetes/pod-health-monitor.sh >> /var/log/k8s-monitor/cron.log 2>&1

# Check PVC usage hourly
0 * * * * /opt/sysadmin-toolkit/Linux/kubernetes/pvc-monitor.sh --threshold 80 >> /var/log/k8s-monitor/pvc-cron.log 2>&1
```

---

## [!] Prerequisites

- **kubectl** configured and accessible
- **jq** for JSON parsing
- Read access to Kubernetes cluster
- Common functions library (`../lib/bash/common-functions.sh`)

**Verify access:**
```bash
# Check kubectl access
kubectl cluster-info

# List pods (should work)
kubectl get pods --all-namespaces
```

---

## [*] Alerting Examples

**Grafana Alert Rule (from Prometheus metrics):**
```yaml
groups:
  - name: kubernetes-alerts
    rules:
      - alert: PodCrashLooping
        expr: k8s_pod_unhealthy{reason="CrashLoopBackOff"} > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Pod {{ $labels.pod }} is crash looping"

      - alert: PVCNearlyFull
        expr: k8s_pvc_usage_percent > 90
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "PVC {{ $labels.pvc }} is {{ $value }}% full"
```

---

## [*] Troubleshooting

**No pods found:**
```bash
# Check kubeconfig
echo $KUBECONFIG
kubectl config current-context

# Verify namespace exists
kubectl get namespaces
```

**Permission denied:**
```bash
# Check RBAC permissions
kubectl auth can-i get pods --all-namespaces
kubectl auth can-i get pvc --all-namespaces
```

---

## [*] Related Documentation

- [Docker Cleanup](../docker/README.md)
- [System Health Check](../monitoring/README.md)
- [Troubleshooting Guide](../../docs/TROUBLESHOOTING.md)

---

**Last Updated**: 2025-12-25
**Version**: 1.0.0
