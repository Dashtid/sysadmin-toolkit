# GPU Monitoring Scripts

NVIDIA GPU metrics export for Prometheus.

## Scripts

| Script | Purpose |
|--------|---------|
| [nvidia-gpu-exporter.sh](nvidia-gpu-exporter.sh) | Export GPU metrics (utilization, memory, temp, power) |

## Configuration

| File | Purpose |
|------|---------|
| [config.example.json](config.example.json) | Example configuration template |

## Quick Examples

```bash
# Run once
./nvidia-gpu-exporter.sh

# Install as cron job (every 5 minutes)
./nvidia-gpu-exporter.sh --install-cron

# Metrics exported to /var/lib/prometheus/node-exporter/
```

## Metrics

```
nvidia_gpu_utilization_percent{gpu="0",name="RTX_5000"} 15
nvidia_gpu_memory_used_bytes{gpu="0"} 6442450944
nvidia_gpu_temperature_celsius{gpu="0"} 45
nvidia_gpu_power_draw_watts{gpu="0"} 75
```

---
**Last Updated**: 2025-12-26
