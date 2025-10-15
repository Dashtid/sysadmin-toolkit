#!/usr/bin/env bash

# ==============================================================================
# Linux Log Cleanup and Rotation Script
# ==============================================================================
#
# DESCRIPTION:
#   Automated log file cleanup to reclaim disk space.
#   Compresses old logs, removes aged rotated logs, and vacuums journald.
#
# FEATURES:
#   - Compress logs older than N days
#   - Delete rotated logs older than N days
#   - Vacuum journald logs to specified size/time
#   - Target specific log directories or all common locations
#   - Prometheus metrics export (space reclaimed)
#   - Dry-run mode for safe testing
#
# USAGE:
#   sudo ./log-cleanup.sh [OPTIONS]
#
# OPTIONS:
#   --compress-age-days N     Compress logs older than N days (default: 7)
#   --delete-age-days N       Delete rotated logs older than N days (default: 30)
#   --journal-max-size SIZE   Max journald size (e.g., 500M, 2G) (default: 500M)
#   --log-dir DIR             Additional log directory to clean (repeatable)
#   --whatif                  Dry-run mode
#   --help                    Show this help message
#
# EXAMPLES:
#   sudo ./log-cleanup.sh --whatif
#   sudo ./log-cleanup.sh --compress-age-days 3 --delete-age-days 14
#   sudo ./log-cleanup.sh --journal-max-size 1G
#   sudo ./log-cleanup.sh --log-dir /var/log/myapp
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - gzip for compression
#   - journalctl for systemd journal management
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
#       - Log compression and deletion
#       - Journald vacuum support
#       - Prometheus metrics export
#
# ==============================================================================

set -euo pipefail

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# Configuration
COMPRESS_AGE_DAYS="${COMPRESS_AGE_DAYS:-7}"
DELETE_AGE_DAYS="${DELETE_AGE_DAYS:-30}"
JOURNAL_MAX_SIZE="${JOURNAL_MAX_SIZE:-500M}"
WHATIF_MODE=false
OUTPUT_DIR="${OUTPUT_DIR:-/var/log/log-cleanup}"
METRICS_DIR="${METRICS_DIR:-/var/lib/prometheus/node-exporter}"

# Additional log directories to clean
CUSTOM_LOG_DIRS=()

# Common log directories to clean
DEFAULT_LOG_DIRS=(
    "/var/log"
    "/var/log/sysstat"
)

# Runtime variables
START_TIME=$(date +%s)
COMPRESSED_FILES_COUNT=0
DELETED_FILES_COUNT=0
SPACE_RECLAIMED_BYTES=0

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

check_dependencies() {
    local missing_deps=()

    if ! command -v gzip &>/dev/null; then
        missing_deps+=("gzip")
    fi

    if ! command -v journalctl &>/dev/null; then
        log_warning "journalctl not found - journald cleanup will be skipped"
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

init_directories() {
    mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"
}

bytes_to_human() {
    local bytes=$1
    if [[ $bytes -lt 1024 ]]; then
        echo "${bytes}B"
    elif [[ $bytes -lt 1048576 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1024}")KB"
    elif [[ $bytes -lt 1073741824 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1048576}")MB"
    else
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1073741824}")GB"
    fi
}

get_file_size() {
    local file="$1"
    if [[ -f "$file" ]]; then
        stat -f "%z" "$file" 2>/dev/null || stat -c "%s" "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# ==============================================================================
# CLEANUP FUNCTIONS
# ==============================================================================

compress_old_logs() {
    local log_dir="$1"
    log_info "Compressing logs in $log_dir older than $COMPRESS_AGE_DAYS days..."

    if [[ ! -d "$log_dir" ]]; then
        log_warning "Directory not found: $log_dir"
        return
    fi

    # Find uncompressed log files older than threshold
    # Exclude already compressed files (.gz, .bz2, .xz)
    local old_logs
    old_logs=$(find "$log_dir" -type f \
        -name "*.log" -o -name "*.log.[0-9]*" \
        ! -name "*.gz" ! -name "*.bz2" ! -name "*.xz" \
        -mtime +$COMPRESS_AGE_DAYS 2>/dev/null || true)

    if [[ -z "$old_logs" ]]; then
        log_success "No old logs to compress in $log_dir"
        return
    fi

    local count=0
    local space_saved=0

    while IFS= read -r log_file; do
        [[ -z "$log_file" ]] && continue

        # Skip empty files
        local file_size
        file_size=$(get_file_size "$log_file")
        [[ $file_size -eq 0 ]] && continue

        if [[ "$WHATIF_MODE" == true ]]; then
            log_info "[WHATIF] Would compress: $log_file"
            ((count++))
            continue
        fi

        # Compress the file
        if gzip "$log_file" 2>/dev/null; then
            local compressed_size
            compressed_size=$(get_file_size "${log_file}.gz")
            space_saved=$((space_saved + file_size - compressed_size))
            ((count++))
        fi
    done <<< "$old_logs"

    if [[ $count -gt 0 ]]; then
        COMPRESSED_FILES_COUNT=$((COMPRESSED_FILES_COUNT + count))
        SPACE_RECLAIMED_BYTES=$((SPACE_RECLAIMED_BYTES + space_saved))
        log_success "Compressed $count log files in $log_dir ($(bytes_to_human $space_saved) saved)"
    fi
}

delete_old_rotated_logs() {
    local log_dir="$1"
    log_info "Deleting rotated logs in $log_dir older than $DELETE_AGE_DAYS days..."

    if [[ ! -d "$log_dir" ]]; then
        log_warning "Directory not found: $log_dir"
        return
    fi

    # Find rotated log files (with numbers or .gz extension)
    local old_rotated_logs
    old_rotated_logs=$(find "$log_dir" -type f \
        \( -name "*.log.[0-9]*.gz" -o -name "*.log.old" -o -name "*.log-[0-9]*" \) \
        -mtime +$DELETE_AGE_DAYS 2>/dev/null || true)

    if [[ -z "$old_rotated_logs" ]]; then
        log_success "No old rotated logs to delete in $log_dir"
        return
    fi

    local count=0
    local space_freed=0

    while IFS= read -r log_file; do
        [[ -z "$log_file" ]] && continue

        local file_size
        file_size=$(get_file_size "$log_file")

        if [[ "$WHATIF_MODE" == true ]]; then
            log_info "[WHATIF] Would delete: $log_file ($(bytes_to_human $file_size))"
            ((count++))
            space_freed=$((space_freed + file_size))
            continue
        fi

        if rm -f "$log_file" 2>/dev/null; then
            space_freed=$((space_freed + file_size))
            ((count++))
        fi
    done <<< "$old_rotated_logs"

    if [[ $count -gt 0 ]]; then
        DELETED_FILES_COUNT=$((DELETED_FILES_COUNT + count))
        SPACE_RECLAIMED_BYTES=$((SPACE_RECLAIMED_BYTES + space_freed))
        log_success "Deleted $count old rotated logs in $log_dir ($(bytes_to_human $space_freed) freed)"
    fi
}

vacuum_journald() {
    if ! command -v journalctl &>/dev/null; then
        log_warning "journalctl not available, skipping journald vacuum"
        return
    fi

    log_info "Vacuuming journald logs (max size: $JOURNAL_MAX_SIZE)..."

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would vacuum journald to max size: $JOURNAL_MAX_SIZE"
        local journal_size
        journal_size=$(journalctl --disk-usage 2>/dev/null | awk '{print $NF}' || echo "unknown")
        log_info "[WHATIF] Current journal size: $journal_size"
        return
    fi

    # Get journal size before vacuum
    local size_before
    size_before=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+(\.\d+)?[KMG]' | head -n 1 || echo "0")

    # Vacuum by size
    journalctl --vacuum-size="$JOURNAL_MAX_SIZE" &>/dev/null || log_warning "Failed to vacuum journald"

    # Get journal size after vacuum
    local size_after
    size_after=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+(\.\d+)?[KMG]' | head -n 1 || echo "0")

    log_success "Journald vacuum completed (was: $size_before, now: $size_after)"
}

clean_specific_large_logs() {
    log_info "Checking for specific large log files..."

    # NVIDIA logs
    if [[ -f "/var/log/nv-hostengine.log" ]]; then
        local nvidia_size
        nvidia_size=$(get_file_size "/var/log/nv-hostengine.log")
        if [[ $nvidia_size -gt 10485760 ]]; then  # > 10MB
            log_info "Large NVIDIA log detected: $(bytes_to_human $nvidia_size)"
            if [[ "$WHATIF_MODE" == false ]]; then
                # Truncate to last 1000 lines
                tail -n 1000 /var/log/nv-hostengine.log > /tmp/nv-hostengine.log.tmp
                mv /tmp/nv-hostengine.log.tmp /var/log/nv-hostengine.log
                log_success "Truncated NVIDIA log to last 1000 lines"
            else
                log_info "[WHATIF] Would truncate NVIDIA log"
            fi
        fi
    fi

    # UFW logs
    if [[ -f "/var/log/ufw.log" ]]; then
        local ufw_size
        ufw_size=$(get_file_size "/var/log/ufw.log")
        if [[ $ufw_size -gt 5242880 ]]; then  # > 5MB
            log_info "Large UFW log detected: $(bytes_to_human $ufw_size)"
            # Let logrotate handle this
        fi
    fi
}

# ==============================================================================
# PROMETHEUS METRICS
# ==============================================================================

export_prometheus_metrics() {
    local metrics_file="${METRICS_DIR}/log_cleanup.prom"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would export Prometheus metrics to: $metrics_file"
        return
    fi

    log_info "Exporting Prometheus metrics..."

    local hostname_var
    hostname_var=$(hostname)

    cat > "$metrics_file" <<EOF
# HELP log_cleanup_compressed_files_total Number of log files compressed
# TYPE log_cleanup_compressed_files_total gauge
log_cleanup_compressed_files_total{hostname="$hostname_var"} $COMPRESSED_FILES_COUNT

# HELP log_cleanup_deleted_files_total Number of log files deleted
# TYPE log_cleanup_deleted_files_total gauge
log_cleanup_deleted_files_total{hostname="$hostname_var"} $DELETED_FILES_COUNT

# HELP log_cleanup_space_reclaimed_bytes Disk space reclaimed in bytes
# TYPE log_cleanup_space_reclaimed_bytes gauge
log_cleanup_space_reclaimed_bytes{hostname="$hostname_var"} $SPACE_RECLAIMED_BYTES

# HELP log_cleanup_duration_seconds Duration of cleanup in seconds
# TYPE log_cleanup_duration_seconds gauge
log_cleanup_duration_seconds{hostname="$hostname_var"} $duration

# HELP log_cleanup_last_run_timestamp Unix timestamp of last cleanup run
# TYPE log_cleanup_last_run_timestamp gauge
log_cleanup_last_run_timestamp{hostname="$hostname_var"} $end_time
EOF

    log_success "Prometheus metrics exported to: $metrics_file"
}

# ==============================================================================
# SUMMARY
# ==============================================================================

show_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local space_human
    space_human=$(bytes_to_human "$SPACE_RECLAIMED_BYTES")

    echo ""
    echo "=== Log Cleanup Summary ==="
    echo "[+] Files compressed: $COMPRESSED_FILES_COUNT"
    echo "[+] Files deleted: $DELETED_FILES_COUNT"
    echo "[+] Space reclaimed: $space_human"
    echo "[i] Cleanup duration: ${duration}s"
    echo "==========================="
    echo ""

    # Show current /var/log disk usage
    log_info "Current /var/log disk usage:"
    du -sh /var/log 2>/dev/null || true
    echo ""
    log_info "Largest log files:"
    du -sh /var/log/* 2>/dev/null | sort -hr | head -n 10 || true
}

# ==============================================================================
# HELP
# ==============================================================================

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Automated log file cleanup to reclaim disk space.

OPTIONS:
    --compress-age-days N     Compress logs older than N days (default: 7)
    --delete-age-days N       Delete rotated logs older than N days (default: 30)
    --journal-max-size SIZE   Max journald size (e.g., 500M, 2G) (default: 500M)
    --log-dir DIR             Additional log directory to clean (repeatable)
    --whatif                  Dry-run mode
    --help                    Show this help message

EXAMPLES:
    sudo $SCRIPT_NAME --whatif
    sudo $SCRIPT_NAME --compress-age-days 3 --delete-age-days 14
    sudo $SCRIPT_NAME --journal-max-size 1G
    sudo $SCRIPT_NAME --log-dir /var/log/myapp

WHAT GETS CLEANED:
    - Uncompressed logs older than N days -> compressed with gzip
    - Rotated logs older than N days -> deleted
    - Journald logs -> vacuumed to specified size
    - Large specific logs (NVIDIA, etc.) -> truncated if > threshold

PROMETHEUS METRICS:
    Metrics are exported to: $METRICS_DIR/log_cleanup.prom
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
            --compress-age-days)
                COMPRESS_AGE_DAYS="$2"
                shift 2
                ;;
            --delete-age-days)
                DELETE_AGE_DAYS="$2"
                shift 2
                ;;
            --journal-max-size)
                JOURNAL_MAX_SIZE="$2"
                shift 2
                ;;
            --log-dir)
                CUSTOM_LOG_DIRS+=("$2")
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

    log_info "=== Log Cleanup Script Started ==="
    log_info "Version: $SCRIPT_VERSION"
    log_info "Date: $(date)"
    log_info "Configuration:"
    log_info "  - Compress age: $COMPRESS_AGE_DAYS days"
    log_info "  - Delete age: $DELETE_AGE_DAYS days"
    log_info "  - Journal max size: $JOURNAL_MAX_SIZE"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_warning "Running in WHATIF mode - no changes will be made"
    fi

    check_root
    check_dependencies
    init_directories

    # Combine default and custom log directories
    local all_log_dirs=("${DEFAULT_LOG_DIRS[@]}" "${CUSTOM_LOG_DIRS[@]}")

    # Clean each log directory
    for log_dir in "${all_log_dirs[@]}"; do
        compress_old_logs "$log_dir"
        delete_old_rotated_logs "$log_dir"
    done

    # Clean specific large logs
    clean_specific_large_logs

    # Vacuum journald
    vacuum_journald

    # Export metrics and show summary
    export_prometheus_metrics
    show_summary

    log_success "=== Log Cleanup Script Completed ==="
}

# Run main function
main "$@"
