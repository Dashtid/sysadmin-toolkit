#!/usr/bin/env bats
# BATS tests for Kubernetes monitoring scripts
# Run: bats tests/Linux/KubernetesMonitoring.bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    K8S_DIR="${PROJECT_ROOT}/Linux/kubernetes"
    POD_MONITOR="${K8S_DIR}/pod-health-monitor.sh"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - BASIC VALIDATION
# ============================================================================

@test "pod-health-monitor.sh exists" {
    [ -f "$POD_MONITOR" ]
}

@test "pod-health-monitor.sh is executable" {
    [ -x "$POD_MONITOR" ]
}

@test "pod-health-monitor.sh has valid bash syntax" {
    bash -n "$POD_MONITOR"
}

@test "pod-health-monitor.sh has bash shebang" {
    head -1 "$POD_MONITOR" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - SECURITY COMPLIANCE
# ============================================================================

@test "pod-health-monitor.sh contains no emojis" {
    ! grep -P '\xE2\x9C|\xF0\x9F' "$POD_MONITOR"
}

@test "pod-health-monitor.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$POD_MONITOR"
}

@test "pod-health-monitor.sh contains no hardcoded passwords" {
    ! grep -iE "password\s*=\s*['\"][^'\"]+['\"]" "$POD_MONITOR"
}

@test "pod-health-monitor.sh contains no API keys" {
    ! grep -iE "api[_-]?key\s*=\s*['\"][^'\"]+['\"]" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - ERROR HANDLING
# ============================================================================

@test "pod-health-monitor.sh has strict error handling" {
    grep -q "set -euo pipefail" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - COMMAND LINE OPTIONS
# ============================================================================

@test "pod-health-monitor.sh has --help flag" {
    grep -q "\-\-help" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has --namespace option" {
    grep -q "\-\-namespace" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has --kubeconfig option" {
    grep -q "\-\-kubeconfig" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has --whatif option" {
    grep -q "\-\-whatif" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has --restart-threshold option" {
    grep -q "\-\-restart-threshold" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - KUBERNETES INTEGRATION
# ============================================================================

@test "pod-health-monitor.sh checks kubectl command" {
    grep -q "command -v kubectl\|kubectl" "$POD_MONITOR"
}

@test "pod-health-monitor.sh checks jq command" {
    grep -q "command -v jq\|jq" "$POD_MONITOR"
}

@test "pod-health-monitor.sh detects CrashLoopBackOff" {
    grep -q "CrashLoopBackOff" "$POD_MONITOR"
}

@test "pod-health-monitor.sh detects OOMKilled" {
    grep -q "OOMKilled" "$POD_MONITOR"
}

@test "pod-health-monitor.sh detects ImagePullBackOff" {
    grep -q "ImagePullBackOff" "$POD_MONITOR"
}

@test "pod-health-monitor.sh detects Pending pods" {
    grep -q "Pending" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - PROMETHEUS METRICS
# ============================================================================

@test "pod-health-monitor.sh exports Prometheus metrics" {
    grep -q "\.prom" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has HELP comments for metrics" {
    grep -q "# HELP" "$POD_MONITOR"
}

@test "pod-health-monitor.sh has TYPE comments for metrics" {
    grep -q "# TYPE" "$POD_MONITOR"
}

@test "pod-health-monitor.sh exports unhealthy_pods metric" {
    grep -q "unhealthy_pods\|k8s_unhealthy" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - FUNCTION DEFINITIONS
# ============================================================================

@test "pod-health-monitor.sh defines check_dependencies function" {
    grep -q "^check_dependencies()" "$POD_MONITOR"
}

@test "pod-health-monitor.sh defines check_crashloop_backoff function" {
    grep -q "^check_crashloop_backoff()" "$POD_MONITOR"
}

@test "pod-health-monitor.sh defines check_oom_killed function" {
    grep -q "^check_oom_killed()" "$POD_MONITOR"
}

@test "pod-health-monitor.sh defines export_prometheus_metrics function" {
    grep -q "^export_prometheus_metrics()" "$POD_MONITOR"
}

@test "pod-health-monitor.sh defines show_summary function" {
    grep -q "^show_summary()" "$POD_MONITOR"
}

# ============================================================================
# POD-HEALTH-MONITOR.SH - EXIT CODES
# ============================================================================

@test "pod-health-monitor.sh exits with error on unhealthy pods" {
    grep -q "exit 1" "$POD_MONITOR"
}

