#!/usr/bin/env bash

# ==============================================================================
# Linux Package State Restore Script
# ==============================================================================
#
# DESCRIPTION:
#   Restores system to a previous package state after failed updates.
#   Analyzes pre-update state JSON files created by system-updates.sh.
#
# FEATURES:
#   - List available backup states
#   - Show differences between current and backup state
#   - Downgrade packages to previous versions (APT and Snap)
#   - WhatIf mode for safe preview
#
# USAGE:
#   sudo ./restore-previous-state.sh [OPTIONS]
#
# OPTIONS:
#   --list                  List all available pre-update state backups
#   --latest                Use the most recent backup file
#   --backup-file FILE      Path to specific pre-update state JSON file
#   --show-diff             Only show differences (no changes made)
#   --whatif                Dry-run mode (show what would be done)
#   --help                  Show this help message
#
# EXAMPLES:
#   sudo ./restore-previous-state.sh --list
#   sudo ./restore-previous-state.sh --latest --show-diff
#   sudo ./restore-previous-state.sh --latest
#   sudo ./restore-previous-state.sh --backup-file /var/log/system-updates/states/pre-update-state_2025-10-15_10-30-00.json
#
# REQUIREMENTS:
#   - Bash 4.0+
#   - Root/sudo privileges
#   - jq (for JSON parsing)
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
#       - APT and Snap package restore
#       - State comparison and diff display
#
# NOTES:
#   - APT downgrades use apt install <package>=<version>
#   - Snap downgrades use snap revert or snap install --channel
#   - Some packages may not be easily reversible
#   - Kernel updates should not be downgraded
#
# ==============================================================================

set -euo pipefail

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default paths
LOG_DIR="${LOG_DIR:-/var/log/system-updates}"
STATE_DIR="${LOG_DIR}/states"

# Operation mode
LIST_MODE=false
LATEST_MODE=false
SHOW_DIFF_MODE=false
WHATIF_MODE=false
BACKUP_FILE=""

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# Print messages with ASCII markers
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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Check for jq dependency
check_dependencies() {
    if ! command -v jq &>/dev/null; then
        log_error "jq is required but not installed"
        log_info "Install with: sudo apt install jq"
        exit 1
    fi
}

# ==============================================================================
# BACKUP LISTING FUNCTIONS
# ==============================================================================

# List all available backup files
list_backup_files() {
    if [[ ! -d "$STATE_DIR" ]]; then
        log_warning "State directory not found: $STATE_DIR"
        return
    fi

    local backup_files
    backup_files=$(find "$STATE_DIR" -name "pre-update-state_*.json" -type f 2>/dev/null | sort -r)

    if [[ -z "$backup_files" ]]; then
        log_warning "No backup state files found in: $STATE_DIR"
        log_info "Backup files are created when running system-updates.sh"
        return
    fi

    log_info "Available backup states:"
    echo ""

    local index=1
    while IFS= read -r backup_file; do
        local filename
        filename=$(basename "$backup_file")

        local timestamp
        timestamp=$(jq -r '.timestamp' "$backup_file" 2>/dev/null || echo "Unknown")

        local hostname_backup
        hostname_backup=$(jq -r '.hostname' "$backup_file" 2>/dev/null || echo "Unknown")

        local apt_count
        apt_count=$(jq -r '.apt_packages | length' "$backup_file" 2>/dev/null || echo "0")

        echo "[$index] $filename"
        echo "    Created: $timestamp"
        echo "    Hostname: $hostname_backup"
        echo "    APT packages: $apt_count"
        echo "    Path: $backup_file"
        echo ""

        ((index++))
    done <<< "$backup_files"
}

# Get the latest backup file
get_latest_backup() {
    if [[ ! -d "$STATE_DIR" ]]; then
        log_error "State directory not found: $STATE_DIR"
        return 1
    fi

    local latest
    latest=$(find "$STATE_DIR" -name "pre-update-state_*.json" -type f 2>/dev/null | sort -r | head -n 1)

    if [[ -z "$latest" ]]; then
        log_error "No backup files found in: $STATE_DIR"
        return 1
    fi

    echo "$latest"
}

# ==============================================================================
# STATE COMPARISON FUNCTIONS
# ==============================================================================

# Get current package state
get_current_state() {
    local temp_file
    temp_file=$(mktemp)

    log_info "Gathering current package state..."

    # Get APT packages
    local apt_packages
    apt_packages=$(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null || echo "")

    # Get Snap packages (if available)
    local snap_packages=""
    if command -v snap &>/dev/null; then
        snap_packages=$(snap list 2>/dev/null || echo "")
    fi

    # Create JSON state file
    cat > "$temp_file" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "apt_packages": $(echo "$apt_packages" | jq -R -s -c 'split("\n") | map(select(length > 0))'),
  "snap_packages": $(echo "$snap_packages" | jq -R -s -c 'split("\n") | map(select(length > 0))')
}
EOF

    echo "$temp_file"
}

# Compare backup and current states
compare_states() {
    local backup_file="$1"
    local current_file="$2"

    log_info "Comparing package states..."

    # Parse backup APT packages
    local backup_apt
    backup_apt=$(jq -r '.apt_packages[]' "$backup_file" 2>/dev/null || echo "")

    # Parse current APT packages
    local current_apt
    current_apt=$(jq -r '.apt_packages[]' "$current_file" 2>/dev/null || echo "")

    # Create associative arrays for comparison
    declare -A backup_packages
    declare -A current_packages

    # Populate backup packages
    while IFS=$'\t' read -r pkg_name pkg_version; do
        if [[ -n "$pkg_name" ]]; then
            backup_packages["$pkg_name"]="$pkg_version"
        fi
    done <<< "$backup_apt"

    # Populate current packages
    while IFS=$'\t' read -r pkg_name pkg_version; do
        if [[ -n "$pkg_name" ]]; then
            current_packages["$pkg_name"]="$pkg_version"
        fi
    done <<< "$current_apt"

    # Find differences
    local upgraded_packages=()
    local downgraded_packages=()
    local added_packages=()
    local removed_packages=()

    # Check for upgraded/downgraded packages
    for pkg_name in "${!backup_packages[@]}"; do
        if [[ -n "${current_packages[$pkg_name]:-}" ]]; then
            local backup_ver="${backup_packages[$pkg_name]}"
            local current_ver="${current_packages[$pkg_name]}"

            if [[ "$backup_ver" != "$current_ver" ]]; then
                # Use dpkg --compare-versions for proper version comparison
                if dpkg --compare-versions "$current_ver" gt "$backup_ver" 2>/dev/null; then
                    upgraded_packages+=("$pkg_name|$backup_ver|$current_ver")
                else
                    downgraded_packages+=("$pkg_name|$backup_ver|$current_ver")
                fi
            fi
        else
            # Package in backup but not in current
            removed_packages+=("$pkg_name|${backup_packages[$pkg_name]}")
        fi
    done

    # Check for added packages
    for pkg_name in "${!current_packages[@]}"; do
        if [[ -z "${backup_packages[$pkg_name]:-}" ]]; then
            added_packages+=("$pkg_name|${current_packages[$pkg_name]}")
        fi
    done

    # Return differences as JSON
    local diff_file
    diff_file=$(mktemp)

    cat > "$diff_file" <<EOF
{
  "upgraded": $(printf '%s\n' "${upgraded_packages[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))'),
  "downgraded": $(printf '%s\n' "${downgraded_packages[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))'),
  "added": $(printf '%s\n' "${added_packages[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))'),
  "removed": $(printf '%s\n' "${removed_packages[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))')
}
EOF

    echo "$diff_file"
}

# Display package differences
show_differences() {
    local diff_file="$1"

    echo ""
    echo "=== Package State Differences ==="
    echo ""

    # Upgraded packages
    local upgraded_count
    upgraded_count=$(jq -r '.upgraded | length' "$diff_file")
    if [[ $upgraded_count -gt 0 ]]; then
        echo "[i] Upgraded Packages ($upgraded_count):"
        jq -r '.upgraded[]' "$diff_file" | while IFS='|' read -r pkg_name old_ver new_ver; do
            echo "    $pkg_name: $old_ver -> $new_ver"
        done
        echo ""
    fi

    # Downgraded packages
    local downgraded_count
    downgraded_count=$(jq -r '.downgraded | length' "$diff_file")
    if [[ $downgraded_count -gt 0 ]]; then
        echo "[!] Downgraded Packages ($downgraded_count):"
        jq -r '.downgraded[]' "$diff_file" | while IFS='|' read -r pkg_name old_ver new_ver; do
            echo "    $pkg_name: $old_ver -> $new_ver"
        done
        echo ""
    fi

    # Added packages
    local added_count
    added_count=$(jq -r '.added | length' "$diff_file")
    if [[ $added_count -gt 0 ]]; then
        echo "[+] Added Packages ($added_count):"
        jq -r '.added[]' "$diff_file" | while IFS='|' read -r pkg_name pkg_version; do
            echo "    $pkg_name v$pkg_version"
        done
        echo ""
    fi

    # Removed packages
    local removed_count
    removed_count=$(jq -r '.removed | length' "$diff_file")
    if [[ $removed_count -gt 0 ]]; then
        echo "[-] Removed Packages ($removed_count):"
        jq -r '.removed[]' "$diff_file" | while IFS='|' read -r pkg_name pkg_version; do
            echo "    $pkg_name v$pkg_version"
        done
        echo ""
    fi

    # Summary
    local total_changes=$((upgraded_count + downgraded_count + added_count + removed_count))
    if [[ $total_changes -eq 0 ]]; then
        log_success "No package changes detected"
    else
        log_info "Total changes: $total_changes packages"
    fi

    echo "================================"
    echo ""
}

# ==============================================================================
# RESTORE FUNCTIONS
# ==============================================================================

# Restore packages to backup state
restore_packages() {
    local diff_file="$1"

    log_info "Starting package restore process..."

    local restored_count=0
    local failed_count=0

    # Downgrade upgraded packages
    local upgraded_count
    upgraded_count=$(jq -r '.upgraded | length' "$diff_file")
    if [[ $upgraded_count -gt 0 ]]; then
        log_info "Downgrading $upgraded_count upgraded packages..."

        jq -r '.upgraded[]' "$diff_file" | while IFS='|' read -r pkg_name old_ver new_ver; do
            if [[ "$WHATIF_MODE" == true ]]; then
                log_info "[WHATIF] Would downgrade $pkg_name from $new_ver to $old_ver"
                continue
            fi

            log_info "Downgrading $pkg_name to version $old_ver..."
            if DEBIAN_FRONTEND=noninteractive apt install -y --allow-downgrades "${pkg_name}=${old_ver}" &>/dev/null; then
                log_success "Successfully downgraded $pkg_name"
                ((restored_count++))
            else
                log_error "Failed to downgrade $pkg_name"
                ((failed_count++))
            fi
        done
    fi

    # Reinstall removed packages
    local removed_count
    removed_count=$(jq -r '.removed | length' "$diff_file")
    if [[ $removed_count -gt 0 ]]; then
        log_info "Reinstalling $removed_count removed packages..."

        jq -r '.removed[]' "$diff_file" | while IFS='|' read -r pkg_name pkg_version; do
            if [[ "$WHATIF_MODE" == true ]]; then
                log_info "[WHATIF] Would install $pkg_name version $pkg_version"
                continue
            fi

            log_info "Installing $pkg_name version $pkg_version..."
            if DEBIAN_FRONTEND=noninteractive apt install -y "${pkg_name}=${pkg_version}" &>/dev/null; then
                log_success "Successfully installed $pkg_name"
                ((restored_count++))
            else
                log_error "Failed to install $pkg_name"
                ((failed_count++))
            fi
        done
    fi

    # Report summary
    echo ""
    echo "=== Restore Summary ==="
    log_success "Successfully restored: $restored_count"
    if [[ $failed_count -gt 0 ]]; then
        log_error "Failed to restore: $failed_count"
    fi
    echo "======================="
    echo ""
}

# ==============================================================================
# HELP FUNCTION
# ==============================================================================

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Restores system to a previous package state after failed updates.

OPTIONS:
    --list                  List all available pre-update state backups
    --latest                Use the most recent backup file
    --backup-file FILE      Path to specific pre-update state JSON file
    --show-diff             Only show differences (no changes made)
    --whatif                Dry-run mode (show what would be done)
    --help                  Show this help message

EXAMPLES:
    sudo $SCRIPT_NAME --list
    sudo $SCRIPT_NAME --latest --show-diff
    sudo $SCRIPT_NAME --latest
    sudo $SCRIPT_NAME --backup-file /var/log/system-updates/states/pre-update-state_2025-10-15_10-30-00.json

NOTES:
    - APT package downgrades use: apt install <package>=<version>
    - Snap downgrades use: snap revert or snap install --channel
    - Some packages may not be easily reversible
    - Kernel packages should not be downgraded

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
            --list)
                LIST_MODE=true
                shift
                ;;
            --latest)
                LATEST_MODE=true
                shift
                ;;
            --backup-file)
                BACKUP_FILE="$2"
                shift 2
                ;;
            --show-diff)
                SHOW_DIFF_MODE=true
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

    log_info "=== Package State Restore Tool ==="

    # Handle list mode
    if [[ "$LIST_MODE" == true ]]; then
        list_backup_files
        exit 0
    fi

    # Require root for restore operations
    check_root
    check_dependencies

    # Determine which backup file to use
    local backup_path=""

    if [[ "$LATEST_MODE" == true ]]; then
        backup_path=$(get_latest_backup)
        if [[ -z "$backup_path" ]]; then
            exit 1
        fi
        log_info "Using latest backup: $(basename "$backup_path")"
    elif [[ -n "$BACKUP_FILE" ]]; then
        backup_path="$BACKUP_FILE"
        if [[ ! -f "$backup_path" ]]; then
            log_error "Backup file not found: $backup_path"
            exit 1
        fi
    else
        log_error "Please specify --list, --latest, or --backup-file"
        log_info "Usage: $SCRIPT_NAME --latest --show-diff"
        exit 1
    fi

    # Load backup state
    log_info "Loading backup state from: $backup_path"

    # Get current state
    local current_state_file
    current_state_file=$(get_current_state)

    # Compare states
    local diff_file
    diff_file=$(compare_states "$backup_path" "$current_state_file")

    # Show differences
    show_differences "$diff_file"

    # Cleanup temp file
    rm -f "$current_state_file"

    # If show-diff only, exit here
    if [[ "$SHOW_DIFF_MODE" == true ]]; then
        log_info "Showing differences only (no changes made)"
        rm -f "$diff_file"
        exit 0
    fi

    # Check if restore is needed
    local total_changes
    total_changes=$(jq -r '[.upgraded, .removed] | map(length) | add' "$diff_file")

    if [[ $total_changes -eq 0 ]]; then
        log_success "No restore needed - system is already in backup state"
        rm -f "$diff_file"
        exit 0
    fi

    # Confirm restore
    if [[ "$WHATIF_MODE" == false ]]; then
        log_warning "This will attempt to restore $total_changes package(s) to their previous state"
        log_warning "Some operations may require internet connectivity and can take time"
        read -rp "Do you want to proceed? (yes/no): " confirm

        if [[ "$confirm" != "yes" ]]; then
            log_info "Restore cancelled by user"
            rm -f "$diff_file"
            exit 0
        fi
    fi

    # Perform restore
    restore_packages "$diff_file"

    # Cleanup
    rm -f "$diff_file"

    log_success "Restore process completed"
}

# Run main function
main "$@"
