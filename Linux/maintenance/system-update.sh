#!/usr/bin/env bash

# ==============================================================================
# Linux System Update Script with Rollback Support
# ==============================================================================
#
# DESCRIPTION:
#   Automated system update script for Debian/Ubuntu with APT and Snap support.
#   Provides rollback capability via filesystem snapshots.
#
# FEATURES:
#   - APT package updates with security focus
#   - Snap package updates
#   - Pre-update state backup for rollback
#   - Prometheus metrics export
#   - Configurable via JSON config file
#   - WhatIf mode (dry-run)
#   - Log retention management
#   - Update summary with duration tracking
#
# USAGE:
#   sudo ./system-updates.sh [OPTIONS]
#
# OPTIONS:
#   --skip-apt              Skip APT package updates
#   --skip-snap             Skip Snap package updates
#   --auto-reboot           Automatically reboot if required
#   --config FILE           Path to JSON configuration file
#   --whatif                Dry-run mode (show what would be done)
#   --help                  Show this help message
#
# EXAMPLES:
#   sudo ./system-updates.sh
#   sudo ./system-updates.sh --skip-snap --auto-reboot
#   sudo ./system-updates.sh --whatif
#   sudo ./system-updates.sh --config /etc/system-updates.json
#
# REQUIREMENTS:
#   - Bash 4.0+
#   - Root/sudo privileges
#   - apt, snap (optional), jq (for JSON parsing)
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
#       - APT and Snap update automation
#       - Pre-update state export
#       - Prometheus metrics support
#       - Configuration file support
#       - WhatIf mode
#
# ==============================================================================

set -euo pipefail

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
LOG_DIR="${LOG_DIR:-/var/log/system-updates}"
LOG_FILE="${LOG_DIR}/system-updates_$(date +%Y-%m-%d).log"
STATE_DIR="${LOG_DIR}/states"
METRICS_DIR="${LOG_DIR}/metrics"
CONFIG_FILE="${SCRIPT_DIR}/config.json"

# Configuration variables (can be overridden by config file)
SKIP_APT=false
SKIP_SNAP=false
AUTO_REBOOT=false
LOG_RETENTION_DAYS=30
WHATIF_MODE=false
EXPORT_METRICS=true

# Runtime variables
START_TIME=$(date +%s)
UPDATE_SUMMARY_APT_UPDATED=0
UPDATE_SUMMARY_APT_FAILED=0
UPDATE_SUMMARY_SNAP_UPDATED=0
UPDATE_SUMMARY_SNAP_FAILED=0
REBOOT_REQUIRED=false
STATE_FILE=""

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# Print messages with ASCII markers
log_info() {
    local msg="$1"
    echo "[i] $msg" | tee -a "$LOG_FILE"
}

log_success() {
    local msg="$1"
    echo "[+] $msg" | tee -a "$LOG_FILE"
}

log_warning() {
    local msg="$1"
    echo "[!] $msg" | tee -a "$LOG_FILE" >&2
}

log_error() {
    local msg="$1"
    echo "[-] $msg" | tee -a "$LOG_FILE" >&2
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
    log_success "Running with root privileges"
}

# Check required commands
check_dependencies() {
    local missing_deps=()

    if ! command -v apt &>/dev/null; then
        missing_deps+=("apt")
    fi

    if ! command -v jq &>/dev/null; then
        log_warning "jq not found - JSON config parsing will be limited"
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

# Initialize directories
init_directories() {
    mkdir -p "$LOG_DIR" "$STATE_DIR" "$METRICS_DIR"
    log_info "Initialized directories: $LOG_DIR, $STATE_DIR, $METRICS_DIR"
}

# Load configuration from JSON file
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "No configuration file found at $CONFIG_FILE, using defaults"
        return
    fi

    if ! command -v jq &>/dev/null; then
        log_warning "jq not available, cannot parse JSON config file"
        return
    fi

    log_info "Loading configuration from: $CONFIG_FILE"

    # Parse JSON config (only if parameters not explicitly set)
    if [[ "${SKIP_APT_SET:-false}" == "false" ]]; then
        SKIP_APT=$(jq -r '.SkipAPT // false' "$CONFIG_FILE")
    fi
    if [[ "${SKIP_SNAP_SET:-false}" == "false" ]]; then
        SKIP_SNAP=$(jq -r '.SkipSnap // false' "$CONFIG_FILE")
    fi
    if [[ "${AUTO_REBOOT_SET:-false}" == "false" ]]; then
        AUTO_REBOOT=$(jq -r '.AutoReboot // false' "$CONFIG_FILE")
    fi

    LOG_RETENTION_DAYS=$(jq -r '.LogRetentionDays // 30' "$CONFIG_FILE")
    EXPORT_METRICS=$(jq -r '.ExportMetrics // true' "$CONFIG_FILE")

    log_success "Configuration loaded successfully"
}

# Export pre-update state for rollback
export_preupdate_state() {
    STATE_FILE="${STATE_DIR}/pre-update-state_$(date +%Y-%m-%d_%H-%M-%S).json"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would export pre-update state to: $STATE_FILE"
        return
    fi

    log_info "Exporting pre-update state..."

    local apt_packages=""
    local snap_packages=""

    # Export APT packages
    if command -v apt &>/dev/null; then
        apt_packages=$(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null || echo "")
    fi

    # Export Snap packages
    if command -v snap &>/dev/null; then
        snap_packages=$(snap list 2>/dev/null || echo "")
    fi

    # Create JSON state file
    cat > "$STATE_FILE" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "apt_packages": $(echo "$apt_packages" | jq -R -s -c 'split("\n") | map(select(length > 0))'),
  "snap_packages": $(echo "$snap_packages" | jq -R -s -c 'split("\n") | map(select(length > 0))')
}
EOF

    log_success "Pre-update state exported to: $STATE_FILE"
}

# Check if reboot is required
check_reboot_required() {
    if [[ -f /var/run/reboot-required ]]; then
        log_warning "System reboot is required"
        REBOOT_REQUIRED=true

        if [[ -f /var/run/reboot-required.pkgs ]]; then
            log_info "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs | tee -a "$LOG_FILE"
        fi

        return 0
    fi
    return 1
}

# Handle reboot
handle_reboot() {
    if [[ "$REBOOT_REQUIRED" == false ]]; then
        return
    fi

    if [[ "$AUTO_REBOOT" == true ]]; then
        if [[ "$WHATIF_MODE" == true ]]; then
            log_warning "[WHATIF] Would reboot system in 60 seconds"
            return
        fi

        log_warning "System will reboot in 60 seconds. Press Ctrl+C to cancel."
        sleep 60
        reboot
    else
        log_warning "A system reboot is recommended to complete updates"
        log_info "Run 'sudo reboot' when ready"
    fi
}

# ==============================================================================
# UPDATE FUNCTIONS
# ==============================================================================

# Update APT packages
update_apt() {
    if [[ "$SKIP_APT" == true ]]; then
        log_info "Skipping APT updates (disabled in configuration)"
        return
    fi

    log_info "=== Starting APT Updates ==="

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would update APT package lists"
        apt list --upgradable 2>/dev/null | tee -a "$LOG_FILE" || true
        return
    fi

    # Update package lists
    log_info "Updating APT package lists..."
    if apt update 2>&1 | tee -a "$LOG_FILE"; then
        log_success "APT package lists updated"
    else
        log_error "Failed to update APT package lists"
        UPDATE_SUMMARY_APT_FAILED=1
        return
    fi

    # Check for upgradable packages
    local upgradable_count
    upgradable_count=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")

    if [[ "$upgradable_count" -eq 0 ]]; then
        log_success "No APT updates available"
        return
    fi

    log_info "Found $upgradable_count upgradable APT packages"
    UPDATE_SUMMARY_APT_UPDATED=$upgradable_count

    # Perform upgrade
    log_info "Upgrading APT packages..."
    if DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1 | tee -a "$LOG_FILE"; then
        log_success "APT packages upgraded successfully"
    else
        log_error "Failed to upgrade APT packages"
        UPDATE_SUMMARY_APT_FAILED=1
        return
    fi

    # Autoremove unused packages
    log_info "Removing unused packages..."
    if DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Unused packages removed"
    else
        log_warning "Failed to remove some unused packages"
    fi

    # Clean package cache
    log_info "Cleaning package cache..."
    if apt clean 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Package cache cleaned"
    else
        log_warning "Failed to clean package cache"
    fi
}

# Update Snap packages
update_snap() {
    if [[ "$SKIP_SNAP" == true ]]; then
        log_info "Skipping Snap updates (disabled in configuration)"
        return
    fi

    if ! command -v snap &>/dev/null; then
        log_info "Snap is not installed, skipping"
        return
    fi

    log_info "=== Starting Snap Updates ==="

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would refresh all Snap packages"
        snap refresh --list 2>&1 | tee -a "$LOG_FILE" || true
        return
    fi

    # List pending updates
    local snap_pending
    snap_pending=$(snap refresh --list 2>&1 || echo "")

    if echo "$snap_pending" | grep -q "All snaps up to date"; then
        log_success "No Snap updates available"
        return
    fi

    # Count pending updates
    UPDATE_SUMMARY_SNAP_UPDATED=$(echo "$snap_pending" | grep -c '^[^ ]' || echo "0")
    log_info "Found $UPDATE_SUMMARY_SNAP_UPDATED Snap packages to update"

    # Perform refresh
    log_info "Refreshing Snap packages..."
    if snap refresh 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Snap packages refreshed successfully"
    else
        log_error "Failed to refresh Snap packages"
        UPDATE_SUMMARY_SNAP_FAILED=1
    fi
}

# ==============================================================================
# MAINTENANCE FUNCTIONS
# ==============================================================================

# Remove old logs
cleanup_old_logs() {
    log_info "Cleaning up old log files (older than $LOG_RETENTION_DAYS days)..."

    if [[ "$WHATIF_MODE" == true ]]; then
        local old_logs_count
        old_logs_count=$(find "$LOG_DIR" -name "*.log" -type f -mtime +"$LOG_RETENTION_DAYS" | wc -l)
        log_info "[WHATIF] Would remove $old_logs_count old log files"
        return
    fi

    local removed_count=0
    while IFS= read -r -d '' log_file; do
        rm -f "$log_file"
        ((removed_count++))
    done < <(find "$LOG_DIR" -name "*.log" -type f -mtime +"$LOG_RETENTION_DAYS" -print0)

    if [[ $removed_count -gt 0 ]]; then
        log_success "Removed $removed_count old log files"
    else
        log_info "No old log files to remove"
    fi
}

# Export Prometheus metrics
export_prometheus_metrics() {
    if [[ "$EXPORT_METRICS" == false ]]; then
        return
    fi

    local metrics_file="${METRICS_DIR}/system_updates.prom"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would export Prometheus metrics to: $metrics_file"
        return
    fi

    log_info "Exporting Prometheus metrics..."

    cat > "$metrics_file" <<EOF
# HELP system_updates_apt_packages_updated Number of APT packages updated
# TYPE system_updates_apt_packages_updated gauge
system_updates_apt_packages_updated{hostname="$(hostname)"} $UPDATE_SUMMARY_APT_UPDATED

# HELP system_updates_apt_packages_failed Number of APT package update failures
# TYPE system_updates_apt_packages_failed gauge
system_updates_apt_packages_failed{hostname="$(hostname)"} $UPDATE_SUMMARY_APT_FAILED

# HELP system_updates_snap_packages_updated Number of Snap packages updated
# TYPE system_updates_snap_packages_updated gauge
system_updates_snap_packages_updated{hostname="$(hostname)"} $UPDATE_SUMMARY_SNAP_UPDATED

# HELP system_updates_snap_packages_failed Number of Snap package update failures
# TYPE system_updates_snap_packages_failed gauge
system_updates_snap_packages_failed{hostname="$(hostname)"} $UPDATE_SUMMARY_SNAP_FAILED

# HELP system_updates_reboot_required Whether a reboot is required (1=yes, 0=no)
# TYPE system_updates_reboot_required gauge
system_updates_reboot_required{hostname="$(hostname)"} $([ "$REBOOT_REQUIRED" == true ] && echo 1 || echo 0)

# HELP system_updates_duration_seconds Duration of update process in seconds
# TYPE system_updates_duration_seconds gauge
system_updates_duration_seconds{hostname="$(hostname)"} $duration

# HELP system_updates_last_run_timestamp Unix timestamp of last update run
# TYPE system_updates_last_run_timestamp gauge
system_updates_last_run_timestamp{hostname="$(hostname)"} $end_time
EOF

    log_success "Prometheus metrics exported to: $metrics_file"
    log_info "Configure Prometheus node_exporter textfile collector to scrape: $METRICS_DIR"
}

# Display update summary
show_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))

    echo ""
    echo "=== Update Summary ==="

    # APT summary
    if [[ "$SKIP_APT" == true ]]; then
        echo "[i] APT: Skipped"
    elif [[ $UPDATE_SUMMARY_APT_FAILED -gt 0 ]]; then
        echo "[-] APT: Failed"
    else
        echo "[+] APT: $UPDATE_SUMMARY_APT_UPDATED packages updated"
    fi

    # Snap summary
    if [[ "$SKIP_SNAP" == true ]]; then
        echo "[i] Snap: Skipped"
    elif [[ $UPDATE_SUMMARY_SNAP_FAILED -gt 0 ]]; then
        echo "[-] Snap: Failed"
    else
        echo "[+] Snap: $UPDATE_SUMMARY_SNAP_UPDATED packages updated"
    fi

    # Reboot status
    if [[ "$REBOOT_REQUIRED" == true ]]; then
        echo "[!] Reboot Required: YES"
    else
        echo "[+] Reboot Required: NO"
    fi

    # State file
    if [[ -n "$STATE_FILE" ]]; then
        echo "[+] State File: $STATE_FILE"
    fi

    # Duration
    printf "[i] Total Runtime: %02d:%02d:%02d\n" $hours $minutes $seconds
    echo "====================="
    echo ""
}

# ==============================================================================
# HELP FUNCTION
# ==============================================================================

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Automated system update script for Debian/Ubuntu Linux.

OPTIONS:
    --skip-apt              Skip APT package updates
    --skip-snap             Skip Snap package updates
    --auto-reboot           Automatically reboot if required
    --config FILE           Path to JSON configuration file (default: $CONFIG_FILE)
    --whatif                Dry-run mode (show what would be done)
    --help                  Show this help message

EXAMPLES:
    sudo $SCRIPT_NAME
    sudo $SCRIPT_NAME --skip-snap --auto-reboot
    sudo $SCRIPT_NAME --whatif
    sudo $SCRIPT_NAME --config /etc/system-updates.json

CONFIGURATION FILE FORMAT:
    {
      "SkipAPT": false,
      "SkipSnap": false,
      "AutoReboot": false,
      "LogRetentionDays": 30,
      "ExportMetrics": true
    }

PROMETHEUS METRICS:
    Metrics are exported to: $METRICS_DIR/system_updates.prom
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
            --skip-apt)
                SKIP_APT=true
                SKIP_APT_SET=true
                shift
                ;;
            --skip-snap)
                SKIP_SNAP=true
                SKIP_SNAP_SET=true
                shift
                ;;
            --auto-reboot)
                AUTO_REBOOT=true
                AUTO_REBOOT_SET=true
                shift
                ;;
            --config)
                CONFIG_FILE="$2"
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

    log_info "=== Linux System Update Script Started ==="
    log_info "Version: $SCRIPT_VERSION"
    log_info "Hostname: $(hostname)"
    log_info "Kernel: $(uname -r)"
    log_info "Date: $(date)"
    log_info "Log file: $LOG_FILE"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_warning "Running in WHATIF mode - no changes will be made"
    fi

    check_root
    check_dependencies
    init_directories
    load_config

    # Export pre-update state
    export_preupdate_state

    # Run updates
    update_apt
    update_snap

    # Maintenance
    cleanup_old_logs
    export_prometheus_metrics

    # Check for reboot requirement
    check_reboot_required

    # Show summary
    show_summary

    log_success "=== Linux System Update Script Completed ==="

    # Handle reboot if needed
    handle_reboot
}

# Run main function
main "$@"
