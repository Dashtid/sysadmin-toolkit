#!/bin/bash
# ============================================================================
# Common Functions Library for Bash Scripts
# Provides standardized logging, error handling, validation, and utilities
# ============================================================================
#
# Usage:
#   source "$(dirname "$0")/../lib/bash/common-functions.sh"
#
# Functions:
#   Logging:
#     log_info <message>           - Log informational message
#     log_success <message>        - Log success message
#     log_warning <message>        - Log warning message
#     log_error <message>          - Log error message
#     log_debug <message>          - Log debug message (if DEBUG=1)
#
#   Error Handling:
#     die <message> [exit_code]    - Print error and exit
#     retry_command <max_attempts> <delay> <command> [args...]
#     check_command <command>      - Verify command exists
#     check_root                   - Verify running as root
#
#   Validation:
#     validate_file <path>         - Check file exists and readable
#     validate_dir <path>          - Check directory exists
#     validate_number <value>      - Check value is numeric
#     validate_ip <ip_address>     - Check valid IP address format
#     validate_hostname <hostname> - Check valid hostname format
#
#   Configuration:
#     load_config <config_file>    - Load JSON configuration
#     get_config <key> [default]   - Get config value with optional default
#
#   Prometheus:
#     init_prometheus_metrics <file> - Initialize metrics file with headers
#     export_prometheus_metric <name> <value> [labels] - Export metric
#
# ============================================================================

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

# Color codes for output
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'

# Log level markers (ASCII only - no emojis)
readonly MARKER_INFO="[i]"
readonly MARKER_SUCCESS="[+]"
readonly MARKER_WARNING="[!]"
readonly MARKER_ERROR="[-]"
readonly MARKER_DEBUG="[*]"

# Script metadata (set by sourcing script)
SCRIPT_NAME="${SCRIPT_NAME:-$(basename "$0")}"
LOG_FILE="${LOG_FILE:-}"
DEBUG="${DEBUG:-0}"

# Configuration storage (populated by load_config)
declare -A CONFIG_DATA

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

# Log informational message
# Usage: log_info "message"
log_info() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${COLOR_CYAN}${MARKER_INFO}${COLOR_RESET} ${message}"

    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [INFO] $message" >> "$LOG_FILE"
    fi
}

# Log success message
# Usage: log_success "message"
log_success() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${COLOR_GREEN}${MARKER_SUCCESS}${COLOR_RESET} ${message}"

    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [SUCCESS] $message" >> "$LOG_FILE"
    fi
}

# Log warning message
# Usage: log_warning "message"
log_warning() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${COLOR_YELLOW}${MARKER_WARNING}${COLOR_RESET} ${message}"

    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [WARNING] $message" >> "$LOG_FILE"
    fi
}

# Log error message
# Usage: log_error "message"
log_error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${COLOR_RED}${MARKER_ERROR}${COLOR_RESET} ${message}" >&2

    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [ERROR] $message" >> "$LOG_FILE"
    fi
}

# Log debug message (only if DEBUG=1)
# Usage: log_debug "message"
log_debug() {
    if [[ "$DEBUG" == "1" ]]; then
        local message="$1"
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo -e "${COLOR_BLUE}${MARKER_DEBUG}${COLOR_RESET} ${message}"

        if [[ -n "$LOG_FILE" ]]; then
            echo "[$timestamp] [DEBUG] $message" >> "$LOG_FILE"
        fi
    fi
}

# ============================================================================
# ERROR HANDLING FUNCTIONS
# ============================================================================

# Print error message and exit
# Usage: die "error message" [exit_code]
die() {
    local message="$1"
    local exit_code="${2:-1}"

    log_error "$message"
    exit "$exit_code"
}

# Retry command with exponential backoff
# Usage: retry_command <max_attempts> <delay> <command> [args...]
# Example: retry_command 3 2 curl -f https://example.com
retry_command() {
    local max_attempts="$1"
    local delay="$2"
    shift 2
    local command=("$@")

    local attempt=1
    local exit_code=0

    while [[ $attempt -le $max_attempts ]]; do
        log_debug "Attempt $attempt/$max_attempts: ${command[*]}"

        if "${command[@]}"; then
            log_debug "Command succeeded on attempt $attempt"
            return 0
        else
            exit_code=$?
            log_warning "Command failed (attempt $attempt/$max_attempts): ${command[*]}"

            if [[ $attempt -lt $max_attempts ]]; then
                local wait_time=$((delay * attempt))
                log_info "Waiting ${wait_time}s before retry..."
                sleep "$wait_time"
            fi
        fi

        ((attempt++))
    done

    log_error "Command failed after $max_attempts attempts: ${command[*]}"
    return "$exit_code"
}

# Check if command exists in PATH
# Usage: check_command <command>
check_command() {
    local cmd="$1"

    if ! command -v "$cmd" &>/dev/null; then
        die "Required command not found: $cmd"
    fi

    log_debug "Command found: $cmd"
    return 0
}

# Check if running as root
# Usage: check_root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi

    log_debug "Running with root privileges"
    return 0
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

# Validate file exists and is readable
# Usage: validate_file <path>
validate_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        log_error "File not readable: $file"
        return 1
    fi

    log_debug "File validated: $file"
    return 0
}

# Validate directory exists
# Usage: validate_dir <path>
validate_dir() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        log_error "Directory not found: $dir"
        return 1
    fi

    log_debug "Directory validated: $dir"
    return 0
}

# Validate value is numeric
# Usage: validate_number <value>
validate_number() {
    local value="$1"

    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        log_error "Invalid number: $value"
        return 1
    fi

    log_debug "Number validated: $value"
    return 0
}

# Validate IP address format (IPv4)
# Usage: validate_ip <ip_address>
validate_ip() {
    local ip="$1"
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if ! [[ "$ip" =~ $ip_regex ]]; then
        log_error "Invalid IP address format: $ip"
        return 1
    fi

    # Validate each octet is 0-255
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ $octet -gt 255 ]]; then
            log_error "Invalid IP address (octet > 255): $ip"
            return 1
        fi
    done

    log_debug "IP address validated: $ip"
    return 0
}

# Validate hostname format
# Usage: validate_hostname <hostname>
# Accepts: server01, web-server, server.example.com
# Rejects: -invalid, invalid-, empty strings
validate_hostname() {
    local hostname="$1"

    # Check for empty string
    if [[ -z "$hostname" ]]; then
        log_error "Empty hostname provided"
        return 1
    fi

    # RFC 1123: hostname can contain a-z, A-Z, 0-9, hyphen, and dots
    # Must not start or end with hyphen or dot
    local hostname_regex='^[a-zA-Z0-9]([a-zA-Z0-9\.-]*[a-zA-Z0-9])?$'

    if ! [[ "$hostname" =~ $hostname_regex ]]; then
        log_error "Invalid hostname format: $hostname"
        return 1
    fi

    # Check for consecutive dots
    if [[ "$hostname" == *".."* ]]; then
        log_error "Invalid hostname (consecutive dots): $hostname"
        return 1
    fi

    # Check individual labels don't start or end with hyphen
    IFS='.' read -r -a labels <<< "$hostname"
    for label in "${labels[@]}"; do
        if [[ "$label" == -* ]] || [[ "$label" == *- ]]; then
            log_error "Invalid hostname (label starts or ends with hyphen): $hostname"
            return 1
        fi
    done

    log_debug "Hostname validated: $hostname"
    return 0
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

# Load JSON configuration file
# Usage: load_config <config_file>
load_config() {
    local config_file="$1"

    check_command jq
    validate_file "$config_file" || die "Cannot load configuration file: $config_file"

    log_info "Loading configuration from: $config_file"

    # Parse JSON and store in associative array
    # This is a simplified approach - for complex configs, consider storing the JSON directly
    while IFS='=' read -r key value; do
        CONFIG_DATA["$key"]="$value"
        log_debug "Config: $key = $value"
    done < <(jq -r 'to_entries | .[] | "\(.key)=\(.value)"' "$config_file" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        die "Failed to parse JSON configuration file: $config_file"
    fi

    log_success "Configuration loaded successfully"
    return 0
}

# Get configuration value
# Usage: get_config <key> [default_value]
get_config() {
    local key="$1"
    local default="${2:-}"

    if [[ -n "${CONFIG_DATA[$key]:-}" ]]; then
        echo "${CONFIG_DATA[$key]}"
    else
        echo "$default"
    fi
}

# ============================================================================
# PROMETHEUS METRICS EXPORT
# ============================================================================

# Initialize Prometheus metrics file with headers
# Usage: init_prometheus_metrics <metrics_file>
init_prometheus_metrics() {
    local metrics_file="$1"
    local metrics_dir=$(dirname "$metrics_file")

    # Create directory if it doesn't exist
    if [[ ! -d "$metrics_dir" ]]; then
        mkdir -p "$metrics_dir" || die "Failed to create metrics directory: $metrics_dir"
    fi

    # Create/truncate metrics file
    : > "$metrics_file" || die "Failed to initialize metrics file: $metrics_file"

    log_debug "Initialized Prometheus metrics file: $metrics_file"
    return 0
}

# Export Prometheus metric
# Usage: export_prometheus_metric <metrics_file> <metric_name> <value> [labels]
# Example: export_prometheus_metric "/tmp/metrics.prom" "script_success" "1" "script=\"backup\",host=\"server1\""
export_prometheus_metric() {
    local metrics_file="$1"
    local metric_name="$2"
    local value="$3"
    local labels="${4:-}"

    # Validate metric name (alphanumeric and underscores only)
    if ! [[ "$metric_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
        log_error "Invalid Prometheus metric name: $metric_name"
        return 1
    fi

    # Build metric line
    local metric_line
    if [[ -n "$labels" ]]; then
        metric_line="${metric_name}{${labels}} ${value}"
    else
        metric_line="${metric_name} ${value}"
    fi

    # Append to metrics file
    if ! echo "$metric_line" >> "$metrics_file"; then
        log_error "Failed to write metric to file: $metrics_file"
        return 1
    fi

    log_debug "Exported metric: $metric_line"
    return 0
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Create directory if it doesn't exist
# Usage: ensure_dir <path>
ensure_dir() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        log_info "Creating directory: $dir"
        mkdir -p "$dir" || die "Failed to create directory: $dir"
    fi

    return 0
}

# Get script execution time
# Usage: START_TIME=$(get_timestamp); ... ; elapsed=$(get_elapsed_time $START_TIME)
get_timestamp() {
    date +%s
}

get_elapsed_time() {
    local start_time="$1"
    local end_time=$(date +%s)
    echo $((end_time - start_time))
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Set up error handling
set -o pipefail  # Propagate pipe failures

# Verify common required commands
for cmd in date basename dirname; do
    check_command "$cmd"
done

log_debug "Common functions library loaded: $SCRIPT_NAME"
