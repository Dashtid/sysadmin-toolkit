#!/usr/bin/env bats
# BATS tests for NVIDIA GPU exporter script
# Run: bats tests/Linux/GPUExporter.bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/gpu/nvidia-gpu-exporter.sh"
    LIB_PATH="${PROJECT_ROOT}/Linux/lib/bash/common-functions.sh"
}

# ============================================================================
# BASIC VALIDATION
# ============================================================================

@test "nvidia-gpu-exporter.sh exists" {
    [ -f "$SCRIPT_PATH" ]
}

@test "nvidia-gpu-exporter.sh is executable" {
    [ -x "$SCRIPT_PATH" ]
}

@test "nvidia-gpu-exporter.sh has valid bash syntax" {
    bash -n "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has bash shebang" {
    head -1 "$SCRIPT_PATH" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# SECURITY COMPLIANCE
# ============================================================================

@test "nvidia-gpu-exporter.sh contains no emojis" {
    ! grep -P '\xE2\x9C|\xF0\x9F' "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh contains no hardcoded passwords" {
    ! grep -iE "password\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh contains no API keys" {
    ! grep -iE "api[_-]?key\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

# ============================================================================
# ERROR HANDLING
# ============================================================================

@test "nvidia-gpu-exporter.sh has strict error handling" {
    grep -q "set -euo pipefail" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh sources common-functions.sh" {
    grep -q "source.*common-functions.sh" "$SCRIPT_PATH"
}

# ============================================================================
# COMMAND LINE OPTIONS
# ============================================================================

@test "nvidia-gpu-exporter.sh has --help flag" {
    grep -q "\-\-help" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has --config option" {
    grep -q "\-\-config" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has --debug option" {
    grep -q "\-\-debug" "$SCRIPT_PATH"
}

# ============================================================================
# NVIDIA-SMI INTEGRATION
# ============================================================================

@test "nvidia-gpu-exporter.sh checks nvidia-smi command" {
    grep -q "check_command nvidia-smi\|command -v nvidia-smi" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh queries nvidia-smi" {
    grep -q "nvidia-smi.*--query-gpu" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh handles nvidia-smi failure" {
    grep -q "Failed to query nvidia-smi\|nvidia-smi.*failed" "$SCRIPT_PATH"
}

# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

@test "nvidia-gpu-exporter.sh exports to .prom file" {
    grep -q "\.prom" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has HELP comments for metrics" {
    grep -q "# HELP" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has TYPE comments for metrics" {
    grep -q "# TYPE" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh exports GPU utilization metric" {
    grep -q "nvidia_gpu_utilization" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh exports GPU memory metric" {
    grep -q "nvidia_gpu_memory" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh exports GPU temperature metric" {
    grep -q "nvidia_gpu_temperature" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh exports GPU power metric" {
    grep -q "nvidia_gpu_power" "$SCRIPT_PATH"
}

# ============================================================================
# DATA VALIDATION
# ============================================================================

@test "nvidia-gpu-exporter.sh validates numeric values" {
    grep -q "validate_number" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh handles empty GPU data" {
    grep -q "No GPU data\|empty" "$SCRIPT_PATH"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

@test "nvidia-gpu-exporter.sh has CONFIG_FILE variable" {
    grep -q "CONFIG_FILE" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has METRICS_DIR variable" {
    grep -q "METRICS_DIR" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has CLUSTER_NAME variable" {
    grep -q "CLUSTER_NAME" "$SCRIPT_PATH"
}

# ============================================================================
# DOCUMENTATION
# ============================================================================

@test "nvidia-gpu-exporter.sh has version information" {
    grep -q "Version:" "$SCRIPT_PATH"
}

@test "nvidia-gpu-exporter.sh has description" {
    grep -q "Description:" "$SCRIPT_PATH"
}
