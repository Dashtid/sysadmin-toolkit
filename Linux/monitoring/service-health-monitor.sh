#!/usr/bin/env bash
# ============================================================================
# Service Health Monitor for Linux
# Monitors critical services, auto-restarts failed services, sends alerts
# ============================================================================
#
# Usage:
#   ./service-health-monitor.sh [OPTIONS]
#
# Options:
#   --services <list>     Comma-separated list of services to monitor
#   --config <file>       Load services from JSON config file
#   --auto-restart        Automatically restart failed services
#   --max-restarts <n>    Maximum restart attempts per service [default: 3]
#   --interval <seconds>  Check interval for daemon mode [default: 60]
#   --daemon              Run in continuous monitoring mode
#   --alert <method>      Alert method: log, email, slack, prometheus
#   --prometheus <file>   Export metrics to Prometheus file
#   --verbose             Enable verbose output
#   --help                Show this help message
#
# Examples:
#   # Check specific services
#   ./service-health-monitor.sh --services docker,nginx,sshd
#
#   # Run as daemon with auto-restart
#   ./service-health-monitor.sh --daemon --auto-restart --services docker,k3s
#
#   # Use config file with Prometheus export
#   ./service-health-monitor.sh --config services.json --prometheus /var/lib/node_exporter/services.prom
#
# ============================================================================

set -euo pipefail

# Script metadata
SCRIPT_NAME="service-health-monitor"
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
COMMON_FUNCTIONS="${SCRIPT_DIR}/../lib/bash/common-functions.sh"
if [[ -f "$COMMON_FUNCTIONS" ]]; then
    # shellcheck source=../lib/bash/common-functions.sh
    source "$COMMON_FUNCTIONS"
else
    echo "[-] Common functions library not found: $COMMON_FUNCTIONS"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default services to monitor (can be overridden)
DEFAULT_SERVICES=("sshd" "docker" "cron")

# User-provided services
declare -a SERVICES=()

# Settings
AUTO_RESTART=false
MAX_RESTARTS=3
CHECK_INTERVAL=60
DAEMON_MODE=false
ALERT_METHOD="log"
PROMETHEUS_FILE=""
CONFIG_FILE=""
VERBOSE=false

# Tracking restart attempts
declare -A RESTART_COUNTS

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

show_help() {
    head -35 "$0" | tail -30 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --services)
                IFS=',' read -ra SERVICES <<< "$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --auto-restart)
                AUTO_RESTART=true
                shift
                ;;
            --max-restarts)
                MAX_RESTARTS="$2"
                shift 2
                ;;
            --interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            --daemon)
                DAEMON_MODE=true
                shift
                ;;
            --alert)
                ALERT_METHOD="$2"
                shift 2
                ;;
            --prometheus)
                PROMETHEUS_FILE="$2"
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                DEBUG=1
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

load_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log_error "Config file not found: $config_file"
        exit 1
    fi

    check_command jq

    # Load services from JSON array
    if jq -e '.services' "$config_file" &>/dev/null; then
        while IFS= read -r service; do
            SERVICES+=("$service")
        done < <(jq -r '.services[]' "$config_file")
        log_info "Loaded ${#SERVICES[@]} services from config"
    fi

    # Load other settings if present
    if jq -e '.auto_restart' "$config_file" &>/dev/null; then
        AUTO_RESTART=$(jq -r '.auto_restart' "$config_file")
    fi
    if jq -e '.max_restarts' "$config_file" &>/dev/null; then
        MAX_RESTARTS=$(jq -r '.max_restarts' "$config_file")
    fi
    if jq -e '.interval' "$config_file" &>/dev/null; then
        CHECK_INTERVAL=$(jq -r '.interval' "$config_file")
    fi
}

# ============================================================================
# SERVICE MONITORING FUNCTIONS
# ============================================================================

check_service_status() {
    local service="$1"
    local status=""
    local active=false
    local enabled=false
    local memory_mb=0
    local uptime_seconds=0

    # Check if service exists
    if ! systemctl list-unit-files "${service}.service" &>/dev/null && \
       ! systemctl list-unit-files "${service}" &>/dev/null; then
        # Try common service name variations
        if systemctl list-unit-files "${service}d.service" &>/dev/null; then
            service="${service}d"
        fi
    fi

    # Get service status
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        active=true
        status="running"
    elif systemctl is-failed --quiet "$service" 2>/dev/null; then
        status="failed"
    else
        status="stopped"
    fi

    # Check if enabled
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        enabled=true
    fi

    # Get memory usage if active
    if [[ "$active" == true ]]; then
        memory_mb=$(systemctl show "$service" --property=MemoryCurrent 2>/dev/null | \
            cut -d= -f2 | awk '{print int($1/1024/1024)}') || memory_mb=0

        # Get uptime (time since last start)
        local active_since
        active_since=$(systemctl show "$service" --property=ActiveEnterTimestamp 2>/dev/null | \
            cut -d= -f2)
        if [[ -n "$active_since" && "$active_since" != "" ]]; then
            local start_epoch
            start_epoch=$(date -d "$active_since" +%s 2>/dev/null || echo 0)
            local now_epoch
            now_epoch=$(date +%s)
            uptime_seconds=$((now_epoch - start_epoch))
        fi
    fi

    # Output as JSON-like format for parsing
    echo "{\"service\":\"$service\",\"active\":$active,\"status\":\"$status\",\"enabled\":$enabled,\"memory_mb\":$memory_mb,\"uptime_seconds\":$uptime_seconds}"
}

format_uptime() {
    local seconds="$1"
    local days=$((seconds / 86400))
    local hours=$(((seconds % 86400) / 3600))
    local minutes=$(((seconds % 3600) / 60))

    if [[ $days -gt 0 ]]; then
        echo "${days}d ${hours}h ${minutes}m"
    elif [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m"
    else
        echo "${minutes}m"
    fi
}

restart_service() {
    local service="$1"
    local count="${RESTART_COUNTS[$service]:-0}"

    if [[ $count -ge $MAX_RESTARTS ]]; then
        log_error "Service $service has exceeded max restart attempts ($MAX_RESTARTS)"
        send_alert "CRITICAL" "$service has failed $count times and will not be restarted automatically"
        return 1
    fi

    log_warning "Attempting to restart $service (attempt $((count + 1))/$MAX_RESTARTS)"

    if systemctl restart "$service" 2>/dev/null; then
        RESTART_COUNTS[$service]=$((count + 1))
        sleep 2  # Wait for service to stabilize

        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_success "Service $service restarted successfully"
            send_alert "INFO" "$service was restarted successfully"
            return 0
        else
            log_error "Service $service failed to start after restart"
            return 1
        fi
    else
        log_error "Failed to restart $service"
        RESTART_COUNTS[$service]=$((count + 1))
        return 1
    fi
}

# ============================================================================
# ALERTING FUNCTIONS
# ============================================================================

send_alert() {
    local severity="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$ALERT_METHOD" in
        log)
            log_warning "[$severity] $message"
            ;;
        email)
            # Requires mail command configured
            if command -v mail &>/dev/null; then
                echo "[$timestamp] [$severity] $message" | mail -s "Service Monitor Alert: $severity" root
            fi
            ;;
        slack)
            # Requires SLACK_WEBHOOK_URL environment variable
            if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
                curl -s -X POST -H 'Content-type: application/json' \
                    --data "{\"text\":\"[$severity] Service Monitor: $message\"}" \
                    "$SLACK_WEBHOOK_URL" &>/dev/null || true
            fi
            ;;
        prometheus)
            # Alerts handled via Prometheus metrics
            ;;
    esac
}

# ============================================================================
# PROMETHEUS EXPORT
# ============================================================================

export_prometheus_metrics() {
    local services_data=("$@")

    if [[ -z "$PROMETHEUS_FILE" ]]; then
        return
    fi

    local temp_file="${PROMETHEUS_FILE}.tmp"
    local metrics_dir
    metrics_dir=$(dirname "$PROMETHEUS_FILE")
    mkdir -p "$metrics_dir"

    {
        echo "# HELP service_up Service status (1=running, 0=not running)"
        echo "# TYPE service_up gauge"
        echo "# HELP service_enabled Service enabled status (1=enabled, 0=disabled)"
        echo "# TYPE service_enabled gauge"
        echo "# HELP service_memory_bytes Service memory usage in bytes"
        echo "# TYPE service_memory_bytes gauge"
        echo "# HELP service_uptime_seconds Service uptime in seconds"
        echo "# TYPE service_uptime_seconds gauge"
        echo "# HELP service_restart_count Number of automatic restarts"
        echo "# TYPE service_restart_count counter"

        for data in "${services_data[@]}"; do
            local service active enabled memory_mb uptime_seconds
            service=$(echo "$data" | jq -r '.service')
            active=$(echo "$data" | jq -r '.active')
            enabled=$(echo "$data" | jq -r '.enabled')
            memory_mb=$(echo "$data" | jq -r '.memory_mb')
            uptime_seconds=$(echo "$data" | jq -r '.uptime_seconds')

            local up_value=0
            [[ "$active" == "true" ]] && up_value=1

            local enabled_value=0
            [[ "$enabled" == "true" ]] && enabled_value=1

            echo "service_up{service=\"$service\"} $up_value"
            echo "service_enabled{service=\"$service\"} $enabled_value"
            echo "service_memory_bytes{service=\"$service\"} $((memory_mb * 1024 * 1024))"
            echo "service_uptime_seconds{service=\"$service\"} $uptime_seconds"
            echo "service_restart_count{service=\"$service\"} ${RESTART_COUNTS[$service]:-0}"
        done
    } > "$temp_file"

    mv "$temp_file" "$PROMETHEUS_FILE"
    log_debug "Prometheus metrics exported to $PROMETHEUS_FILE"
}

# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo "=============================================="
    echo "        Service Health Monitor"
    echo "=============================================="
    echo ""
    log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Hostname: $(hostname)"
    log_info "Services: ${#SERVICES[@]}"
    if [[ "$AUTO_RESTART" == true ]]; then
        log_info "Auto-restart: enabled (max $MAX_RESTARTS attempts)"
    fi
    echo ""
}

print_service_table() {
    local services_data=("$@")

    printf "%-20s %-10s %-10s %-12s %-15s\n" "SERVICE" "STATUS" "ENABLED" "MEMORY" "UPTIME"
    printf "%-20s %-10s %-10s %-12s %-15s\n" "-------" "------" "-------" "------" "------"

    local failed_count=0
    local running_count=0

    for data in "${services_data[@]}"; do
        local service status enabled memory_mb uptime_seconds active
        service=$(echo "$data" | jq -r '.service')
        status=$(echo "$data" | jq -r '.status')
        enabled=$(echo "$data" | jq -r '.enabled')
        memory_mb=$(echo "$data" | jq -r '.memory_mb')
        uptime_seconds=$(echo "$data" | jq -r '.uptime_seconds')
        active=$(echo "$data" | jq -r '.active')

        local enabled_str="no"
        [[ "$enabled" == "true" ]] && enabled_str="yes"

        local memory_str="-"
        [[ "$memory_mb" -gt 0 ]] && memory_str="${memory_mb} MB"

        local uptime_str="-"
        [[ "$uptime_seconds" -gt 0 ]] && uptime_str=$(format_uptime "$uptime_seconds")

        local status_color=""
        local status_reset=""
        if [[ "$status" == "running" ]]; then
            status_color="${COLOR_GREEN}"
            status_reset="${COLOR_RESET}"
            ((running_count++))
        elif [[ "$status" == "failed" ]]; then
            status_color="${COLOR_RED}"
            status_reset="${COLOR_RESET}"
            ((failed_count++))
        else
            status_color="${COLOR_YELLOW}"
            status_reset="${COLOR_RESET}"
            ((failed_count++))
        fi

        printf "%-20s ${status_color}%-10s${status_reset} %-10s %-12s %-15s\n" \
            "$service" "$status" "$enabled_str" "$memory_str" "$uptime_str"
    done

    echo ""
    log_info "Summary: $running_count running, $failed_count not running"
}

# ============================================================================
# MAIN MONITORING LOOP
# ============================================================================

check_all_services() {
    local services_data=()

    for service in "${SERVICES[@]}"; do
        local data
        data=$(check_service_status "$service")
        services_data+=("$data")

        # Check if failed and handle auto-restart
        local status
        status=$(echo "$data" | jq -r '.status')
        if [[ "$status" != "running" && "$AUTO_RESTART" == true ]]; then
            restart_service "$service"
        elif [[ "$status" != "running" ]]; then
            send_alert "WARNING" "Service $service is $status"
        fi
    done

    # Display results
    print_header
    print_service_table "${services_data[@]}"

    # Export metrics if configured
    if [[ -n "$PROMETHEUS_FILE" ]]; then
        export_prometheus_metrics "${services_data[@]}"
    fi
}

main() {
    parse_args "$@"

    # Load services from config if specified
    if [[ -n "$CONFIG_FILE" ]]; then
        load_config "$CONFIG_FILE"
    fi

    # Use default services if none specified
    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        SERVICES=("${DEFAULT_SERVICES[@]}")
        log_info "Using default services: ${SERVICES[*]}"
    fi

    # Verify jq is available for JSON parsing
    check_command jq

    if [[ "$DAEMON_MODE" == true ]]; then
        log_info "Starting daemon mode (interval: ${CHECK_INTERVAL}s)"
        log_info "Press Ctrl+C to stop"

        trap 'log_info "Stopping service monitor..."; exit 0' SIGINT SIGTERM

        while true; do
            check_all_services
            sleep "$CHECK_INTERVAL"
        done
    else
        check_all_services
    fi
}

main "$@"
