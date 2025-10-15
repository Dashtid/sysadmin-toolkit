#!/usr/bin/env bash

# ==============================================================================
# Kubernetes Pod Health Monitor with Prometheus Integration
# ==============================================================================
#
# DESCRIPTION:
#   Monitors Kubernetes pod health and exports metrics to Prometheus.
#   Detects common pod issues: CrashLoopBackOff, OOMKilled, ImagePullBackOff.
#
# FEATURES:
#   - Detects unhealthy pods across all namespaces
#   - Identifies pod restart loops and memory issues
#   - Exports Prometheus metrics for alerting
#   - Logs pod events and container logs for troubleshooting
#   - Supports custom KUBECONFIG path
#   - Optional namespace filtering
#
# USAGE:
#   ./pod-health-monitor.sh [OPTIONS]
#
# OPTIONS:
#   --namespace NS          Monitor specific namespace (default: all)
#   --kubeconfig PATH       Path to kubeconfig file
#   --output-dir DIR        Directory for logs and metrics (default: /var/log/k8s-monitor)
#   --restart-threshold N   Alert if pod restarts > N times (default: 5)
#   --whatif                Dry-run mode
#   --help                  Show this help message
#
# EXAMPLES:
#   ./pod-health-monitor.sh
#   ./pod-health-monitor.sh --namespace docker-services
#   ./pod-health-monitor.sh --kubeconfig ~/.kube/config-lab
#   ./pod-health-monitor.sh --restart-threshold 10
#
# REQUIREMENTS:
#   - kubectl configured and accessible
#   - Read access to Kubernetes cluster
#   - jq for JSON parsing
#
# AUTHOR:
#   Windows & Linux Sysadmin Toolkit
#
# VERSION:
#   1.0.0
#
# CHANGELOG:
#   1.0.0 - 2025-10-15
#       - Initial release
#       - Pod health detection (CrashLoopBackOff, OOMKilled, etc.)
#       - Prometheus metrics export
#       - Event and log collection
#
# ==============================================================================

set -euo pipefail

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# Configuration
NAMESPACE="${NAMESPACE:-}"
KUBECONFIG_PATH="${KUBECONFIG:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/var/log/k8s-monitor}"
METRICS_DIR="${METRICS_DIR:-/var/lib/prometheus/node-exporter}"
LOGS_DIR="${OUTPUT_DIR}/pod-logs"
RESTART_THRESHOLD="${RESTART_THRESHOLD:-5}"
WHATIF_MODE=false

# Runtime variables
START_TIME=$(date +%s)
UNHEALTHY_POD_COUNT=0
CRASHLOOP_POD_COUNT=0
OOM_KILLED_POD_COUNT=0
PENDING_POD_COUNT=0
IMAGE_PULL_ERROR_COUNT=0

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log_info() {
    echo "[i] $1"
}

log_success() {
    echo "[+] $1"
}

log_warning() {
    echo "[!] $1" >&2
}

log_error() {
    echo "[-] $1" >&2
}

check_dependencies() {
    local missing_deps=()

    if ! command -v kubectl &>/dev/null; then
        missing_deps+=("kubectl")
    fi

    if ! command -v jq &>/dev/null; then
        missing_deps+=("jq")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Install with: sudo apt install kubectl jq"
        exit 1
    fi
}

init_directories() {
    mkdir -p "$OUTPUT_DIR" "$METRICS_DIR" "$LOGS_DIR"
    log_info "Initialized directories: $OUTPUT_DIR, $METRICS_DIR, $LOGS_DIR"
}

setup_kubeconfig() {
    if [[ -n "$KUBECONFIG_PATH" ]]; then
        export KUBECONFIG="$KUBECONFIG_PATH"
        log_info "Using KUBECONFIG: $KUBECONFIG_PATH"
    fi

    # Test kubectl access
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        log_info "Check your kubeconfig or use --kubeconfig option"
        exit 1
    fi

    log_success "Connected to Kubernetes cluster: $(kubectl cluster-info | head -n 1 | awk '{print $NF}')"
}

# ==============================================================================
# POD HEALTH CHECK FUNCTIONS
# ==============================================================================

get_all_pods() {
    local namespace_arg=""
    if [[ -n "$NAMESPACE" ]]; then
        namespace_arg="--namespace=$NAMESPACE"
    else
        namespace_arg="--all-namespaces"
    fi

    kubectl get pods $namespace_arg -o json
}

check_crashloop_backoff() {
    log_info "Checking for CrashLoopBackOff pods..."

    local pods_json="$1"
    local crashloop_pods
    crashloop_pods=$(echo "$pods_json" | jq -r '
        .items[] |
        select(.status.containerStatuses != null) |
        select(.status.containerStatuses[].state.waiting.reason == "CrashLoopBackOff") |
        "\(.metadata.namespace)|\(.metadata.name)|\(.status.containerStatuses[].restartCount)"
    ')

    if [[ -z "$crashloop_pods" ]]; then
        log_success "No CrashLoopBackOff pods found"
        return
    fi

    while IFS='|' read -r ns pod_name restart_count; do
        ((CRASHLOOP_POD_COUNT++))
        ((UNHEALTHY_POD_COUNT++))

        log_warning "CrashLoopBackOff detected: $ns/$pod_name (Restarts: $restart_count)"

        # Collect logs
        local log_file="${LOGS_DIR}/${ns}_${pod_name}_$(date +%Y%m%d_%H%M%S).log"
        if [[ "$WHATIF_MODE" == false ]]; then
            kubectl logs -n "$ns" "$pod_name" --tail=100 > "$log_file" 2>&1 || true
            kubectl describe pod -n "$ns" "$pod_name" >> "$log_file" 2>&1 || true
            log_info "Logs saved to: $log_file"
        else
            log_info "[WHATIF] Would save logs to: $log_file"
        fi
    done <<< "$crashloop_pods"
}

check_oom_killed() {
    log_info "Checking for OOMKilled pods..."

    local pods_json="$1"
    local oom_pods
    oom_pods=$(echo "$pods_json" | jq -r '
        .items[] |
        select(.status.containerStatuses != null) |
        select(.status.containerStatuses[].lastState.terminated.reason == "OOMKilled") |
        "\(.metadata.namespace)|\(.metadata.name)|\(.status.containerStatuses[].restartCount)"
    ')

    if [[ -z "$oom_pods" ]]; then
        log_success "No OOMKilled pods found"
        return
    fi

    while IFS='|' read -r ns pod_name restart_count; do
        ((OOM_KILLED_POD_COUNT++))
        ((UNHEALTHY_POD_COUNT++))

        log_warning "OOMKilled detected: $ns/$pod_name (Restarts: $restart_count)"

        # Get memory limits
        local memory_limit
        memory_limit=$(kubectl get pod -n "$ns" "$pod_name" -o json | jq -r '.spec.containers[0].resources.limits.memory // "not set"')
        log_info "Memory limit: $memory_limit"

        # Collect events
        local event_file="${LOGS_DIR}/${ns}_${pod_name}_events_$(date +%Y%m%d_%H%M%S).log"
        if [[ "$WHATIF_MODE" == false ]]; then
            kubectl get events -n "$ns" --field-selector involvedObject.name="$pod_name" > "$event_file" 2>&1 || true
            log_info "Events saved to: $event_file"
        fi
    done <<< "$oom_pods"
}

check_pending_pods() {
    log_info "Checking for Pending pods..."

    local pods_json="$1"
    local pending_pods
    pending_pods=$(echo "$pods_json" | jq -r '
        .items[] |
        select(.status.phase == "Pending") |
        "\(.metadata.namespace)|\(.metadata.name)|\(.status.conditions[].reason // "Unknown")"
    ')

    if [[ -z "$pending_pods" ]]; then
        log_success "No Pending pods found"
        return
    fi

    while IFS='|' read -r ns pod_name reason; do
        ((PENDING_POD_COUNT++))
        ((UNHEALTHY_POD_COUNT++))

        log_warning "Pending pod detected: $ns/$pod_name (Reason: $reason)"
    done <<< "$pending_pods"
}

check_image_pull_errors() {
    log_info "Checking for ImagePullBackOff/ErrImagePull..."

    local pods_json="$1"
    local image_error_pods
    image_error_pods=$(echo "$pods_json" | jq -r '
        .items[] |
        select(.status.containerStatuses != null) |
        select(
            .status.containerStatuses[].state.waiting.reason == "ImagePullBackOff" or
            .status.containerStatuses[].state.waiting.reason == "ErrImagePull"
        ) |
        "\(.metadata.namespace)|\(.metadata.name)|\(.status.containerStatuses[].state.waiting.reason)"
    ')

    if [[ -z "$image_error_pods" ]]; then
        log_success "No image pull errors found"
        return
    fi

    while IFS='|' read -r ns pod_name reason; do
        ((IMAGE_PULL_ERROR_COUNT++))
        ((UNHEALTHY_POD_COUNT++))

        log_warning "Image pull error: $ns/$pod_name ($reason)"

        # Get image name
        local image
        image=$(kubectl get pod -n "$ns" "$pod_name" -o json | jq -r '.spec.containers[0].image')
        log_info "Image: $image"
    done <<< "$image_error_pods"
}

check_restart_loops() {
    log_info "Checking for pods with high restart counts (threshold: $RESTART_THRESHOLD)..."

    local pods_json="$1"
    local high_restart_pods
    high_restart_pods=$(echo "$pods_json" | jq -r --argjson threshold "$RESTART_THRESHOLD" '
        .items[] |
        select(.status.containerStatuses != null) |
        select(.status.containerStatuses[].restartCount > $threshold) |
        "\(.metadata.namespace)|\(.metadata.name)|\(.status.containerStatuses[].restartCount)"
    ')

    if [[ -z "$high_restart_pods" ]]; then
        log_success "No pods with high restart counts"
        return
    fi

    while IFS='|' read -r ns pod_name restart_count; do
        log_warning "High restart count: $ns/$pod_name (Restarts: $restart_count)"
    done <<< "$high_restart_pods"
}

# ==============================================================================
# PROMETHEUS METRICS
# ==============================================================================

export_prometheus_metrics() {
    local metrics_file="${METRICS_DIR}/k8s_pod_health.prom"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would export Prometheus metrics to: $metrics_file"
        return
    fi

    log_info "Exporting Prometheus metrics..."

    local cluster_name
    cluster_name=$(kubectl config current-context)

    cat > "$metrics_file" <<EOF
# HELP k8s_unhealthy_pods_total Total number of unhealthy pods detected
# TYPE k8s_unhealthy_pods_total gauge
k8s_unhealthy_pods_total{cluster="$cluster_name"} $UNHEALTHY_POD_COUNT

# HELP k8s_crashloop_pods_total Number of pods in CrashLoopBackOff state
# TYPE k8s_crashloop_pods_total gauge
k8s_crashloop_pods_total{cluster="$cluster_name"} $CRASHLOOP_POD_COUNT

# HELP k8s_oomkilled_pods_total Number of pods killed by OOM
# TYPE k8s_oomkilled_pods_total gauge
k8s_oomkilled_pods_total{cluster="$cluster_name"} $OOM_KILLED_POD_COUNT

# HELP k8s_pending_pods_total Number of pods in Pending state
# TYPE k8s_pending_pods_total gauge
k8s_pending_pods_total{cluster="$cluster_name"} $PENDING_POD_COUNT

# HELP k8s_image_pull_error_pods_total Number of pods with image pull errors
# TYPE k8s_image_pull_error_pods_total gauge
k8s_image_pull_error_pods_total{cluster="$cluster_name"} $IMAGE_PULL_ERROR_COUNT

# HELP k8s_pod_health_check_duration_seconds Duration of health check in seconds
# TYPE k8s_pod_health_check_duration_seconds gauge
k8s_pod_health_check_duration_seconds{cluster="$cluster_name"} $duration

# HELP k8s_pod_health_check_timestamp Unix timestamp of last health check
# TYPE k8s_pod_health_check_timestamp gauge
k8s_pod_health_check_timestamp{cluster="$cluster_name"} $end_time
EOF

    log_success "Prometheus metrics exported to: $metrics_file"
}

# ==============================================================================
# SUMMARY
# ==============================================================================

show_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    echo ""
    echo "=== Pod Health Check Summary ==="
    echo "[i] Cluster: $(kubectl config current-context)"
    echo "[i] Namespace: $([ -n "$NAMESPACE" ] && echo "$NAMESPACE" || echo "all")"
    echo ""

    if [[ $UNHEALTHY_POD_COUNT -eq 0 ]]; then
        log_success "All pods healthy"
    else
        log_warning "Unhealthy pods: $UNHEALTHY_POD_COUNT"
        echo "  - CrashLoopBackOff: $CRASHLOOP_POD_COUNT"
        echo "  - OOMKilled: $OOM_KILLED_POD_COUNT"
        echo "  - Pending: $PENDING_POD_COUNT"
        echo "  - Image pull errors: $IMAGE_PULL_ERROR_COUNT"
    fi

    echo ""
    echo "[i] Check duration: ${duration}s"
    echo "[i] Logs directory: $LOGS_DIR"
    echo "[i] Metrics file: ${METRICS_DIR}/k8s_pod_health.prom"
    echo "==============================="
    echo ""
}

# ==============================================================================
# HELP
# ==============================================================================

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Monitors Kubernetes pod health and exports metrics to Prometheus.

OPTIONS:
    --namespace NS          Monitor specific namespace (default: all)
    --kubeconfig PATH       Path to kubeconfig file
    --output-dir DIR        Directory for logs and metrics (default: /var/log/k8s-monitor)
    --restart-threshold N   Alert if pod restarts > N times (default: 5)
    --whatif                Dry-run mode
    --help                  Show this help message

EXAMPLES:
    $SCRIPT_NAME
    $SCRIPT_NAME --namespace docker-services
    $SCRIPT_NAME --kubeconfig ~/.kube/config-lab
    $SCRIPT_NAME --restart-threshold 10

PROMETHEUS METRICS:
    Metrics are exported to: $METRICS_DIR/k8s_pod_health.prom
    Configure node_exporter textfile collector to scrape this directory.

VERSION:
    $SCRIPT_VERSION

EOF
}

# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --kubeconfig)
                KUBECONFIG_PATH="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                LOGS_DIR="${OUTPUT_DIR}/pod-logs"
                shift 2
                ;;
            --restart-threshold)
                RESTART_THRESHOLD="$2"
                shift 2
                ;;
            --whatif)
                WHATIF_MODE=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main() {
    parse_arguments "$@"

    log_info "=== Kubernetes Pod Health Monitor Started ==="
    log_info "Version: $SCRIPT_VERSION"
    log_info "Date: $(date)"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_warning "Running in WHATIF mode - no logs will be saved"
    fi

    check_dependencies
    init_directories
    setup_kubeconfig

    # Get all pods
    log_info "Fetching pod information..."
    local pods_json
    pods_json=$(get_all_pods)

    # Run health checks
    check_crashloop_backoff "$pods_json"
    check_oom_killed "$pods_json"
    check_pending_pods "$pods_json"
    check_image_pull_errors "$pods_json"
    check_restart_loops "$pods_json"

    # Export metrics
    export_prometheus_metrics

    # Show summary
    show_summary

    log_success "=== Kubernetes Pod Health Monitor Completed ==="

    # Exit with error code if unhealthy pods found
    if [[ $UNHEALTHY_POD_COUNT -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
