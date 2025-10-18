#!/usr/bin/env bash
# ============================================================================
# Docker Image and Container Cleanup Script
# ============================================================================
# Description: Automated Docker cleanup to reclaim disk space
# Author: David Dashti
# Version: 2.0.0
# Last Updated: 2025-10-18
#
# Usage:
#   ./docker-cleanup.sh [OPTIONS]
#
# Options:
#   --keep-versions N       Keep N most recent versions per image (default: 3)
#   --container-age-days N  Remove containers stopped > N days ago (default: 7)
#   --prune-volumes         Also prune unused volumes (default: false)
#   --whatif                Dry-run mode (show what would be removed)
#   --config FILE           Use configuration file (default: config.json)
#   --debug                 Enable debug logging
#   --help                  Show this help message
#
# Examples:
#   ./docker-cleanup.sh --whatif
#   ./docker-cleanup.sh --keep-versions 2
#   ./docker-cleanup.sh --container-age-days 30 --prune-volumes
#   ./docker-cleanup.sh --config /etc/docker-cleanup/config.json
#
# Features:
#   - Remove dangling images (<none>:<none>)
#   - Keep only N latest versions per image repository
#   - Prune stopped containers older than X days
#   - Remove unused volumes
#   - Prometheus metrics export (disk space reclaimed)
#   - Dry-run mode for safe testing
#   - Configuration file support
# ============================================================================

set -euo pipefail

# Script configuration
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_VERSION="2.0.0"

# Source common functions library
if [[ -f "$SCRIPT_DIR/../lib/bash/common-functions.sh" ]]; then
    source "$SCRIPT_DIR/../lib/bash/common-functions.sh"
else
    echo "[-] ERROR: Cannot find common-functions.sh library" >&2
    exit 1
fi

# Configuration defaults
CONFIG_FILE="${SCRIPT_DIR}/config.json"
KEEP_VERSIONS="${KEEP_VERSIONS:-3}"
CONTAINER_AGE_DAYS="${CONTAINER_AGE_DAYS:-7}"
PRUNE_VOLUMES=false
WHATIF_MODE=false
OUTPUT_DIR="${OUTPUT_DIR:-/var/log/docker-cleanup}"
METRICS_DIR="${METRICS_DIR:-/var/lib/prometheus/node-exporter}"
CLUSTER_NAME="${CLUSTER_NAME:-homelab}"

# Runtime variables
START_TIME=$(get_timestamp)
REMOVED_IMAGES_COUNT=0
REMOVED_CONTAINERS_COUNT=0
REMOVED_VOLUMES_COUNT=0
SPACE_RECLAIMED_BYTES=0

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

check_dependencies() {
    check_command docker

    # Test docker daemon access with retry
    log_info "Verifying Docker daemon access..."
    if ! retry_command 3 2 docker info >/dev/null 2>&1; then
        die "Cannot access Docker daemon. Check Docker service status or user permissions." 1
    fi

    log_debug "Docker daemon accessible"
}

init_directories() {
    ensure_dir "$OUTPUT_DIR"
    ensure_dir "$METRICS_DIR"
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

# ==============================================================================
# CLEANUP FUNCTIONS
# ==============================================================================

get_disk_usage_before() {
    log_info "Calculating current Docker disk usage..."
    docker system df --format "{{.Type}}\t{{.TotalCount}}\t{{.Size}}" || true
}

remove_dangling_images() {
    log_info "Checking for dangling images (<none>:<none>)..."

    local dangling_images
    dangling_images=$(docker images --filter "dangling=true" -q)

    if [[ -z "$dangling_images" ]]; then
        log_success "No dangling images found"
        return
    fi

    local count
    count=$(echo "$dangling_images" | wc -l)
    log_info "Found $count dangling images"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would remove $count dangling images"
        return
    fi

    # Calculate space before removal
    local space_before
    space_before=$(docker images --filter "dangling=true" --format "{{.Size}}" | \
        sed 's/MB/*1000000/;s/GB/*1000000000/' | \
        awk '{sum += $1} END {print sum}' | bc 2>/dev/null || echo "0")

    log_info "Removing dangling images..."
    docker rmi $dangling_images 2>&1 | grep -v "No such image" || true

    REMOVED_IMAGES_COUNT=$((REMOVED_IMAGES_COUNT + count))
    SPACE_RECLAIMED_BYTES=$((SPACE_RECLAIMED_BYTES + space_before))

    log_success "Removed $count dangling images"
}

remove_old_image_versions() {
    log_info "Checking for old image versions (keeping $KEEP_VERSIONS latest per repository)..."

    # Get all unique repositories
    local repositories
    repositories=$(docker images --format "{{.Repository}}" | grep -v "<none>" | sort -u)

    if [[ -z "$repositories" ]]; then
        log_info "No repositories with multiple versions found"
        return
    fi

    local total_removed=0

    while IFS= read -r repo; do
        # Skip if repo is empty
        [[ -z "$repo" ]] && continue

        # Get all image IDs for this repository, sorted by creation date (newest first)
        local all_images
        all_images=$(docker images "$repo" --format "{{.ID}}|{{.CreatedAt}}" | sort -t'|' -k2 -r)

        local image_count
        image_count=$(echo "$all_images" | wc -l)

        # Skip if we have fewer images than the keep threshold
        if [[ $image_count -le $KEEP_VERSIONS ]]; then
            continue
        fi

        # Get images to remove (skip the first N)
        local images_to_remove
        images_to_remove=$(echo "$all_images" | tail -n +$((KEEP_VERSIONS + 1)) | cut -d'|' -f1)

        if [[ -z "$images_to_remove" ]]; then
            continue
        fi

        local remove_count
        remove_count=$(echo "$images_to_remove" | wc -l)

        log_info "Repository: $repo - keeping $KEEP_VERSIONS, removing $remove_count old versions"

        if [[ "$WHATIF_MODE" == true ]]; then
            log_info "[WHATIF] Would remove $remove_count old versions of $repo"
            continue
        fi

        # Remove old images with error logging
        while IFS= read -r image_id; do
            if docker rmi "$image_id" 2>&1 | grep -q "Deleted"; then
                ((total_removed++))
                ((REMOVED_IMAGES_COUNT++))
                log_debug "Removed image: $image_id"
            else
                log_warning "Failed to remove image: $image_id (may be in use)"
            fi
        done <<< "$images_to_remove"

    done <<< "$repositories"

    if [[ $total_removed -gt 0 ]]; then
        log_success "Removed $total_removed old image versions"
    else
        log_success "No old image versions to remove"
    fi
}

prune_old_containers() {
    log_info "Checking for stopped containers older than $CONTAINER_AGE_DAYS days..."

    # Get stopped containers
    local stopped_containers
    stopped_containers=$(docker ps -a --filter "status=exited" --format "{{.ID}}|{{.CreatedAt}}")

    if [[ -z "$stopped_containers" ]]; then
        log_success "No stopped containers found"
        return
    fi

    local cutoff_date
    cutoff_date=$(date -d "$CONTAINER_AGE_DAYS days ago" +%s)

    local old_containers=()
    while IFS='|' read -r container_id created_at; do
        local container_date
        container_date=$(date -d "$created_at" +%s 2>/dev/null || echo "0")

        if [[ $container_date -lt $cutoff_date ]]; then
            old_containers+=("$container_id")
        fi
    done <<< "$stopped_containers"

    if [[ ${#old_containers[@]} -eq 0 ]]; then
        log_success "No old containers to remove"
        return
    fi

    log_info "Found ${#old_containers[@]} old containers to remove"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would remove ${#old_containers[@]} old containers"
        return
    fi

    log_info "Removing old containers..."
    for container_id in "${old_containers[@]}"; do
        if docker rm "$container_id" &>/dev/null; then
            ((REMOVED_CONTAINERS_COUNT++))
        fi
    done

    log_success "Removed ${#old_containers[@]} old containers"
}

prune_unused_volumes() {
    if [[ "$PRUNE_VOLUMES" == false ]]; then
        log_info "Skipping volume pruning (use --prune-volumes to enable)"
        return
    fi

    log_info "Checking for unused volumes..."

    if [[ "$WHATIF_MODE" == true ]]; then
        local unused_volumes
        unused_volumes=$(docker volume ls -q --filter "dangling=true")
        if [[ -n "$unused_volumes" ]]; then
            local count
            count=$(echo "$unused_volumes" | wc -l)
            log_info "[WHATIF] Would remove $count unused volumes"
        else
            log_success "No unused volumes found"
        fi
        return
    fi

    log_info "Pruning unused volumes..."
    local prune_output
    prune_output=$(docker volume prune -f 2>&1 || echo "")

    # Parse removed volume count
    if echo "$prune_output" | grep -q "Deleted Volumes:"; then
        REMOVED_VOLUMES_COUNT=$(echo "$prune_output" | grep -c "local" || echo "0")
        log_success "Removed $REMOVED_VOLUMES_COUNT unused volumes"
    else
        log_success "No unused volumes found"
    fi
}

run_docker_system_prune() {
    log_info "Running docker system prune (dangling build cache)..."

    if [[ "$WHATIF_MODE" == true ]]; then
        log_info "[WHATIF] Would run docker system prune"
        return
    fi

    local prune_output
    prune_output=$(docker system prune -f 2>&1 || echo "")

    # Parse space reclaimed
    if echo "$prune_output" | grep -q "Total reclaimed space:"; then
        local reclaimed
        reclaimed=$(echo "$prune_output" | grep "Total reclaimed space:" | awk '{print $4}')
        log_success "System prune reclaimed: $reclaimed"
    fi
}

# ==============================================================================
# PROMETHEUS METRICS
# ==============================================================================

export_prometheus_metrics() {
    local metrics_file="${METRICS_DIR}/docker_cleanup.prom"
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
# HELP docker_cleanup_images_removed_total Number of images removed
# TYPE docker_cleanup_images_removed_total gauge
docker_cleanup_images_removed_total{hostname="$hostname_var"} $REMOVED_IMAGES_COUNT

# HELP docker_cleanup_containers_removed_total Number of containers removed
# TYPE docker_cleanup_containers_removed_total gauge
docker_cleanup_containers_removed_total{hostname="$hostname_var"} $REMOVED_CONTAINERS_COUNT

# HELP docker_cleanup_volumes_removed_total Number of volumes removed
# TYPE docker_cleanup_volumes_removed_total gauge
docker_cleanup_volumes_removed_total{hostname="$hostname_var"} $REMOVED_VOLUMES_COUNT

# HELP docker_cleanup_space_reclaimed_bytes Disk space reclaimed in bytes
# TYPE docker_cleanup_space_reclaimed_bytes gauge
docker_cleanup_space_reclaimed_bytes{hostname="$hostname_var"} $SPACE_RECLAIMED_BYTES

# HELP docker_cleanup_duration_seconds Duration of cleanup in seconds
# TYPE docker_cleanup_duration_seconds gauge
docker_cleanup_duration_seconds{hostname="$hostname_var"} $duration

# HELP docker_cleanup_last_run_timestamp Unix timestamp of last cleanup run
# TYPE docker_cleanup_last_run_timestamp gauge
docker_cleanup_last_run_timestamp{hostname="$hostname_var"} $end_time
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
    echo "=== Docker Cleanup Summary ==="
    echo "[+] Images removed: $REMOVED_IMAGES_COUNT"
    echo "[+] Containers removed: $REMOVED_CONTAINERS_COUNT"
    echo "[+] Volumes removed: $REMOVED_VOLUMES_COUNT"
    echo "[+] Space reclaimed: $space_human"
    echo "[i] Cleanup duration: ${duration}s"
    echo "=============================="
    echo ""

    # Show current disk usage
    log_info "Current Docker disk usage:"
    docker system df
}

# ==============================================================================
# HELP
# ==============================================================================

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Automated Docker cleanup to reclaim disk space.

OPTIONS:
    --keep-versions N       Keep N most recent versions per image (default: 3)
    --container-age-days N  Remove containers stopped > N days ago (default: 7)
    --prune-volumes         Also prune unused volumes (default: false)
    --whatif                Dry-run mode (show what would be removed)
    --help                  Show this help message

EXAMPLES:
    $SCRIPT_NAME --whatif
    $SCRIPT_NAME --keep-versions 2
    $SCRIPT_NAME --container-age-days 30 --prune-volumes

WHAT GETS REMOVED:
    - Dangling images (<none>:<none>)
    - Image versions older than the N most recent per repository
    - Stopped containers older than N days
    - Unused volumes (if --prune-volumes specified)
    - Dangling build cache

PROMETHEUS METRICS:
    Metrics are exported to: $METRICS_DIR/docker_cleanup.prom
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
            --keep-versions)
                KEEP_VERSIONS="$2"
                shift 2
                ;;
            --container-age-days)
                CONTAINER_AGE_DAYS="$2"
                shift 2
                ;;
            --prune-volumes)
                PRUNE_VOLUMES=true
                shift
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

    log_info "=== Docker Cleanup Script Started ==="
    log_info "Version: $SCRIPT_VERSION"
    log_info "Date: $(date)"
    log_info "Configuration:"
    log_info "  - Keep versions per image: $KEEP_VERSIONS"
    log_info "  - Container age threshold: $CONTAINER_AGE_DAYS days"
    log_info "  - Prune volumes: $PRUNE_VOLUMES"

    if [[ "$WHATIF_MODE" == true ]]; then
        log_warning "Running in WHATIF mode - no changes will be made"
    fi

    check_dependencies
    init_directories

    # Show disk usage before cleanup
    get_disk_usage_before
    echo ""

    # Run cleanup operations
    remove_dangling_images
    remove_old_image_versions
    prune_old_containers
    prune_unused_volumes
    run_docker_system_prune

    # Export metrics and show summary
    export_prometheus_metrics
    show_summary

    log_success "=== Docker Cleanup Script Completed ==="
}

# Run main function
main "$@"
