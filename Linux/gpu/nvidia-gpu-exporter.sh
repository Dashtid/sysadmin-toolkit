#!/usr/bin/env bash
# NVIDIA GPU Metrics Exporter for Prometheus
# Version: 1.0.0

set -euo pipefail

OUTPUT_DIR="/var/log/gpu-monitor"
METRICS_DIR="/var/lib/prometheus/node-exporter"

mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

log_info() { echo "[i] $1"; }

# Check nvidia-smi availability
if ! command -v nvidia-smi &>/dev/null; then
    echo "[-] nvidia-smi not found"
    exit 1
fi

log_info "Collecting GPU metrics..."

# Get GPU metrics
gpu_data=$(nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.total,memory.used,memory.free,temperature.gpu,power.draw --format=csv,noheader,nounits)

# Export to Prometheus format
metrics_file="${METRICS_DIR}/nvidia_gpu.prom"
cat > "$metrics_file" <<EOF
# HELP nvidia_gpu_utilization_percent GPU utilization percentage
# TYPE nvidia_gpu_utilization_percent gauge
# HELP nvidia_gpu_memory_utilization_percent GPU memory utilization percentage
# TYPE nvidia_gpu_memory_utilization_percent gauge
# HELP nvidia_gpu_memory_total_bytes Total GPU memory in bytes
# TYPE nvidia_gpu_memory_total_bytes gauge
# HELP nvidia_gpu_memory_used_bytes Used GPU memory in bytes
# TYPE nvidia_gpu_memory_used_bytes gauge
# HELP nvidia_gpu_temperature_celsius GPU temperature in Celsius
# TYPE nvidia_gpu_temperature_celsius gauge
# HELP nvidia_gpu_power_watts GPU power draw in watts
# TYPE nvidia_gpu_power_watts gauge
EOF

echo "$gpu_data" | while IFS=',' read -r idx name util_gpu util_mem mem_total mem_used mem_free temp power; do
    # Clean values
    util_gpu=$(echo "$util_gpu" | tr -d ' ')
    util_mem=$(echo "$util_mem" | tr -d ' ')
    mem_total=$(echo "$mem_total" | tr -d ' ')
    mem_used=$(echo "$mem_used" | tr -d ' ')
    temp=$(echo "$temp" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    name_clean=$(echo "$name" | tr ' ' '_')
    
    # Convert MiB to bytes
    mem_total_bytes=$((mem_total * 1048576))
    mem_used_bytes=$((mem_used * 1048576))
    
    cat >> "$metrics_file" <<EOFMETRIC
nvidia_gpu_utilization_percent{gpu="$idx",name="$name_clean"} $util_gpu
nvidia_gpu_memory_utilization_percent{gpu="$idx",name="$name_clean"} $util_mem
nvidia_gpu_memory_total_bytes{gpu="$idx",name="$name_clean"} $mem_total_bytes
nvidia_gpu_memory_used_bytes{gpu="$idx",name="$name_clean"} $mem_used_bytes
nvidia_gpu_temperature_celsius{gpu="$idx",name="$name_clean"} $temp
nvidia_gpu_power_watts{gpu="$idx",name="$name_clean"} $power
EOFMETRIC
done

log_info "GPU metrics exported to: $metrics_file"
