#!/usr/bin/env bash
# PVC Usage Monitor - Monitors Kubernetes PersistentVolumeClaim usage
# Version: 1.0.0

set -euo pipefail

NAMESPACE="${NAMESPACE:-}"
OUTPUT_DIR="/var/log/k8s-monitor"
METRICS_DIR="/var/lib/prometheus/node-exporter"
ALERT_THRESHOLD=80

mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

log_info() { echo "[i] $1"; }
log_warning() { echo "[!] $1" >&2; }

# Get PVC usage
kubectl get pvc ${NAMESPACE:+--namespace=$NAMESPACE} ${NAMESPACE:---all-namespaces} -o json | \
jq -r '.items[] | "\(.metadata.namespace)|\(.metadata.name)|\(.spec.resources.requests.storage)|\(.status.capacity.storage // "N/A")"' | \
while IFS='|' read -r ns pvc_name requested capacity; do
    log_info "PVC: $ns/$pvc_name - Requested: $requested, Capacity: $capacity"
done

# Export metrics
cat > "${METRICS_DIR}/k8s_pvc_monitor.prom" <<EOF
# HELP k8s_pvc_monitored_total Total PVCs monitored
# TYPE k8s_pvc_monitored_total gauge
k8s_pvc_monitored_total{cluster="$(kubectl config current-context)"} $(kubectl get pvc -A --no-headers 2>/dev/null | wc -l)

# HELP k8s_pvc_monitor_timestamp Timestamp of last check
# TYPE k8s_pvc_monitor_timestamp gauge
k8s_pvc_monitor_timestamp{cluster="$(kubectl config current-context)"} $(date +%s)
EOF

log_info "Metrics exported to: ${METRICS_DIR}/k8s_pvc_monitor.prom"
