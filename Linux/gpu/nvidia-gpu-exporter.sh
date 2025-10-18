#!/usr/bin/env bash
# ============================================================================
# NVIDIA GPU Metrics Exporter for Prometheus
# ============================================================================
# Description: Exports NVIDIA GPU metrics in Prometheus format
# Author: David Dashti
# Version: 2.0.0
# Last Updated: 2025-10-18
#
# Usage:
#   ./nvidia-gpu-exporter.sh [--config /path/to/config.json]
#   ./nvidia-gpu-exporter.sh --debug
#
# Configuration:
#   Uses config.json if present, otherwise uses defaults
#   See config.example.json for all available options
# ============================================================================

set -euo pipefail

# Script configuration
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions library
if [[ -f "$SCRIPT_DIR/../lib/bash/common-functions.sh" ]]; then
    source "$SCRIPT_DIR/../lib/bash/common-functions.sh"
else
    echo "[-] ERROR: Cannot find common-functions.sh library" >&2
    exit 1
fi

# Default configuration
CONFIG_FILE="${SCRIPT_DIR}/config.json"
OUTPUT_DIR="${OUTPUT_DIR:-/var/log/gpu-monitor}"
METRICS_DIR="${METRICS_DIR:-/var/lib/prometheus/node-exporter}"
CLUSTER_NAME="${CLUSTER_NAME:-homelab}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --debug)
            DEBUG=1
            shift
            ;;
        --help)
            echo "Usage: $0 [--config FILE] [--debug]"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load configuration if available
if [[ -f "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE"
    OUTPUT_DIR=$(get_config "output.log_dir" "$OUTPUT_DIR")
    METRICS_DIR=$(get_config "output.metrics_dir" "$METRICS_DIR")
    CLUSTER_NAME=$(get_config "monitoring.cluster_name" "$CLUSTER_NAME")
fi

# Create directories
ensure_dir "$OUTPUT_DIR"
ensure_dir "$METRICS_DIR"

# Set up logging
LOG_FILE="$OUTPUT_DIR/nvidia-gpu-exporter.log"
log_info "NVIDIA GPU Metrics Exporter v2.0.0"
log_debug "Configuration: OUTPUT_DIR=$OUTPUT_DIR, METRICS_DIR=$METRICS_DIR"

# Check nvidia-smi availability
check_command nvidia-smi

log_info "Collecting GPU metrics..."

# Get GPU metrics with error handling
if ! gpu_data=$(nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.total,memory.used,memory.free,temperature.gpu,power.draw --format=csv,noheader,nounits 2>&1); then
    log_error "Failed to query nvidia-smi: $gpu_data"
    die "nvidia-smi query failed" 1
fi

# Validate output is not empty
if [[ -z "$gpu_data" ]]; then
    log_error "nvidia-smi returned no data"
    die "No GPU data available" 1
fi

log_debug "Raw GPU data: $gpu_data"

# Export to Prometheus format
metrics_file="${METRICS_DIR}/nvidia_gpu.prom"
init_prometheus_metrics "$metrics_file"

# Write metric headers
if ! cat >> "$metrics_file" <<EOF
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
then
    die "Failed to write metrics file headers" 1
fi

# Process GPU data and write metrics
gpu_count=0
while IFS=',' read -r idx name util_gpu util_mem mem_total mem_used mem_free temp power; do
    # Clean values (remove whitespace)
    util_gpu=$(echo "$util_gpu" | tr -d ' ')
    util_mem=$(echo "$util_mem" | tr -d ' ')
    mem_total=$(echo "$mem_total" | tr -d ' ')
    mem_used=$(echo "$mem_used" | tr -d ' ')
    temp=$(echo "$temp" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    name_clean=$(echo "$name" | tr ' ' '_')

    # Validate numeric values
    if ! validate_number "$util_gpu" || ! validate_number "$util_mem" || ! validate_number "$mem_total" || ! validate_number "$mem_used"; then
        log_warning "Invalid numeric values for GPU $idx, skipping"
        continue
    fi

    log_debug "Processing GPU $idx: $name_clean (Util: ${util_gpu}%, Temp: ${temp}C)"

    # Convert MiB to bytes
    mem_total_bytes=$((mem_total * 1048576))
    mem_used_bytes=$((mem_used * 1048576))

    # Write metrics with error handling
    if ! cat >> "$metrics_file" <<EOFMETRIC
nvidia_gpu_utilization_percent{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $util_gpu
nvidia_gpu_memory_utilization_percent{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $util_mem
nvidia_gpu_memory_total_bytes{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $mem_total_bytes
nvidia_gpu_memory_used_bytes{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $mem_used_bytes
nvidia_gpu_temperature_celsius{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $temp
nvidia_gpu_power_watts{gpu="$idx",name="$name_clean",cluster="$CLUSTER_NAME"} $power
EOFMETRIC
    then
        log_error "Failed to write metrics for GPU $idx"
        die "Failed to write metrics file" 1
    fi

    ((gpu_count++))
done <<< "$gpu_data"

log_success "Exported metrics for $gpu_count GPU(s) to: $metrics_file"
log_debug "Metrics file size: $(wc -c < "$metrics_file") bytes"

exit 0
