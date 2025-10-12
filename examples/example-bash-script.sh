#!/usr/bin/env bash
#
# Script Name: example-bash-script.sh
# Description: Example Bash script demonstrating best practices for this repository
# Author: David Dashti
# Created: 2025-10-12
# Last Modified: 2025-10-12
# Version: 1.0.0
#
# This script serves as a reference implementation showing:
#   - Proper header documentation
#   - Strict mode and error handling
#   - Parameter parsing and validation
#   - Consistent output formatting
#   - Logging capabilities
#   - Retry logic
#   - Clean function-based structure
#   - Dry-run support
#   - Prerequisite checking
#
# Prerequisites:
#   - Bash 4.0+
#   - curl (for network operations)
#   - jq (for JSON parsing)
#
# Usage:
#   ./example-bash-script.sh [OPTIONS]
#
# Options:
#   -h, --help              Show this help message and exit
#   -v, --verbose           Enable verbose output
#   -d, --dry-run           Preview changes without applying them
#   -s, --server HOST       Target server hostname or IP (required)
#   -p, --port PORT         Port number (default: 22)
#   -o, --operation TYPE    Operation type: check|connect|test|status (required)
#   -t, --timeout SECS      Timeout in seconds (default: 30)
#   -r, --retries NUM       Maximum retry attempts (default: 3)
#
# Examples:
#   ./example-bash-script.sh -s "192.0.2.10" -o check
#   ./example-bash-script.sh -s "web.example.com" -p 8080 -o test --dry-run
#   ./example-bash-script.sh -s "192.0.2.20" -o connect -t 60 -r 5 --verbose
#
# Exit Codes:
#   0 - Success
#   1 - General error
#   2 - Invalid arguments
#   3 - Prerequisites not met
#   4 - Operation failed
#
# Notes:
#   - Use RFC 5737 example IPs in documentation (192.0.2.x, 198.51.100.x, 203.0.113.x)
#   - All timestamps are in ISO 8601 format
#   - Logs are written to ./logs/ directory if it exists
#

# ============================================================================
# STRICT MODE AND ERROR HANDLING
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Set Internal Field Separator for safer word splitting

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

# Script metadata
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DATE="2025-10-12"

# Default values
DRY_RUN=false
VERBOSE=false
SERVER=""
PORT=22
OPERATION=""
TIMEOUT=30
MAX_RETRIES=3

# Log file
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d).log"

# Colors for output (disabled if not a terminal)
if [[ -t 1 ]]; then
    readonly COLOR_RED='\033[0;31m'
    readonly COLOR_GREEN='\033[0;32m'
    readonly COLOR_YELLOW='\033[1;33m'
    readonly COLOR_BLUE='\033[0;34m'
    readonly COLOR_GRAY='\033[0;90m'
    readonly COLOR_RESET='\033[0m'
else
    readonly COLOR_RED=''
    readonly COLOR_GREEN=''
    readonly COLOR_YELLOW=''
    readonly COLOR_BLUE=''
    readonly COLOR_GRAY=''
    readonly COLOR_RESET=''
fi

# Valid operations
readonly VALID_OPERATIONS=("check" "connect" "test" "status")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Print functions with consistent formatting
print_info() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[${timestamp}] [i] $*"
    echo -e "${COLOR_BLUE}${message}${COLOR_RESET}"
    [[ -d "${LOG_DIR}" ]] && echo "${message}" >> "${LOG_FILE}"
}

print_success() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[${timestamp}] [+] $*"
    echo -e "${COLOR_GREEN}${message}${COLOR_RESET}"
    [[ -d "${LOG_DIR}" ]] && echo "${message}" >> "${LOG_FILE}"
}

print_warning() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[${timestamp}] [!] $*"
    echo -e "${COLOR_YELLOW}${message}${COLOR_RESET}"
    [[ -d "${LOG_DIR}" ]] && echo "${message}" >> "${LOG_FILE}"
}

print_error() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[${timestamp}] [-] $*"
    echo -e "${COLOR_RED}${message}${COLOR_RESET}" >&2
    [[ -d "${LOG_DIR}" ]] && echo "${message}" >> "${LOG_FILE}"
}

print_debug() {
    if [[ "${VERBOSE}" == true ]]; then
        local timestamp
        timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
        local message="[${timestamp}] [DEBUG] $*"
        echo -e "${COLOR_GRAY}${message}${COLOR_RESET}"
        [[ -d "${LOG_DIR}" ]] && echo "${message}" >> "${LOG_FILE}"
    fi
}

# Usage information
show_usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Description:
    Example Bash script demonstrating best practices for system administration
    tasks. Shows proper structure, error handling, logging, and documentation.

Required Options:
    -s, --server HOST       Target server hostname or IP address
    -o, --operation TYPE    Operation to perform: check|connect|test|status

Optional Settings:
    -p, --port PORT         Port number (default: 22, range: 1-65535)
    -t, --timeout SECS      Timeout in seconds (default: 30, range: 5-300)
    -r, --retries NUM       Maximum retry attempts (default: 3, range: 1-10)

Control Options:
    -h, --help              Show this help message and exit
    -v, --verbose           Enable verbose/debug output
    -d, --dry-run           Preview changes without applying them

Examples:
    Check server connectivity:
        ${SCRIPT_NAME} -s "192.0.2.10" -o check

    Test with custom port and timeout:
        ${SCRIPT_NAME} -s "web.example.com" -p 8080 -o test -t 60

    Preview mode with verbose output:
        ${SCRIPT_NAME} -s "192.0.2.20" -o connect --dry-run --verbose

    Maximum retries:
        ${SCRIPT_NAME} -s "db.example.com" -o status -r 5

Exit Codes:
    0 - Success
    1 - General error
    2 - Invalid arguments
    3 - Prerequisites not met
    4 - Operation failed

Version: ${SCRIPT_VERSION} (${SCRIPT_DATE})
Author: David Dashti
Repository: https://github.com/Dashtid/windows-linux-sysadmin-toolkit
EOF
}

# Validate required commands exist
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check Bash version
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        print_error "Bash 4.0+ is required (current: ${BASH_VERSION})"
        return 3
    fi
    print_debug "Bash version: ${BASH_VERSION}"

    # Check required commands
    local required_commands=("curl" "jq" "nc")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "${cmd}" &> /dev/null; then
            missing_commands+=("${cmd}")
        else
            print_debug "Found command: ${cmd} at $(command -v "${cmd}")"
        fi
    done

    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        print_error "Missing required commands: ${missing_commands[*]}"
        print_info "Install with: sudo apt-get install ${missing_commands[*]}"
        return 3
    fi

    # Create log directory if it doesn't exist
    if [[ ! -d "${LOG_DIR}" ]]; then
        print_debug "Creating log directory: ${LOG_DIR}"
        mkdir -p "${LOG_DIR}" || {
            print_warning "Could not create log directory: ${LOG_DIR}"
        }
    fi

    print_success "All prerequisites met"
    return 0
}

# Validate IP address or hostname
validate_server() {
    local server="$1"

    # Check if it's an IP address
    if [[ "${server}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_debug "Server appears to be an IP address"
        return 0
    fi

    # Check if it's a valid hostname
    if [[ "${server}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_debug "Server appears to be a valid hostname"
        return 0
    fi

    print_error "Invalid server format: ${server}"
    return 2
}

# Validate operation type
validate_operation() {
    local op="$1"

    for valid_op in "${VALID_OPERATIONS[@]}"; do
        if [[ "${op}" == "${valid_op}" ]]; then
            print_debug "Operation '${op}' is valid"
            return 0
        fi
    done

    print_error "Invalid operation: ${op}"
    print_error "Valid operations: ${VALID_OPERATIONS[*]}"
    return 2
}

# Cleanup function (called on exit)
cleanup() {
    local exit_code=$?

    print_debug "Cleanup function called with exit code: ${exit_code}"

    # Perform cleanup tasks here
    # - Remove temporary files
    # - Close open connections
    # - Restore previous state

    if [[ ${exit_code} -eq 0 ]]; then
        print_success "========================================"
        print_success "Script completed successfully"
        print_success "========================================"
    else
        print_error "========================================"
        print_error "Script exited with error code: ${exit_code}"
        print_error "========================================"
    fi

    exit "${exit_code}"
}

# Error handler
error_handler() {
    local line_number=$1
    local command="$2"
    print_error "Error occurred at line ${line_number}: ${command}"
}

# ============================================================================
# MAIN LOGIC FUNCTIONS
# ============================================================================

# Test server connectivity
test_server_connection() {
    local server="$1"
    local port="$2"
    local timeout="$3"

    print_info "Testing connection to ${server}:${port} (timeout: ${timeout}s)"

    if command -v nc &> /dev/null; then
        if timeout "${timeout}" nc -z -w "${timeout}" "${server}" "${port}" 2>/dev/null; then
            print_success "Connection successful"
            return 0
        else
            print_warning "Connection failed or timed out"
            return 4
        fi
    else
        print_warning "nc not available, using curl for HTTP test"
        if timeout "${timeout}" curl -s --connect-timeout "${timeout}" "http://${server}:${port}" &> /dev/null; then
            print_success "HTTP connection successful"
            return 0
        else
            print_warning "HTTP connection failed"
            return 4
        fi
    fi
}

# Perform operation with retry logic
perform_operation_with_retry() {
    local server="$1"
    local port="$2"
    local operation="$3"
    local max_attempts="${MAX_RETRIES}"

    local attempt=1
    local success=false

    while [[ "${success}" == false ]] && [[ ${attempt} -le ${max_attempts} ]]; do
        print_debug "Attempt ${attempt} of ${max_attempts}"

        if perform_operation "${server}" "${port}" "${operation}"; then
            success=true
            return 0
        else
            if [[ ${attempt} -lt ${max_attempts} ]]; then
                print_warning "Attempt ${attempt} failed, retrying in 2 seconds..."
                sleep 2
                ((attempt++))
            else
                print_error "All ${max_attempts} attempts failed"
                return 4
            fi
        fi
    done
}

# Perform the requested operation
perform_operation() {
    local server="$1"
    local port="$2"
    local operation="$3"

    print_info "Performing '${operation}' operation on ${server}:${port}"

    # Dry run check
    if [[ "${DRY_RUN}" == true ]]; then
        print_warning "DRY RUN MODE - No actual changes will be made"
        print_info "Would perform: ${operation} on ${server}:${port}"
        return 0
    fi

    case "${operation}" in
        check)
            test_server_connection "${server}" "${port}" "${TIMEOUT}"
            return $?
            ;;

        connect)
            print_info "Initiating connection..."
            test_server_connection "${server}" "${port}" "${TIMEOUT}"
            if [[ $? -eq 0 ]]; then
                print_success "Connection established"
                # Add actual connection logic here
                return 0
            else
                print_error "Connection failed"
                return 4
            fi
            ;;

        test)
            print_info "Running tests..."
            test_server_connection "${server}" "${port}" "${TIMEOUT}"
            if [[ $? -eq 0 ]]; then
                print_success "Tests passed"
                # Add more test logic here
                return 0
            else
                print_warning "Tests failed"
                return 4
            fi
            ;;

        status)
            print_info "Checking status..."
            test_server_connection "${server}" "${port}" "${TIMEOUT}"
            if [[ $? -eq 0 ]]; then
                print_success "Status: Online"
                return 0
            else
                print_warning "Status: Offline or unreachable"
                return 4
            fi
            ;;

        *)
            print_error "Unknown operation: ${operation}"
            return 1
            ;;
    esac
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_arguments() {
    if [[ $# -eq 0 ]]; then
        print_error "No arguments provided"
        show_usage
        exit 2
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -s|--server)
                SERVER="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -o|--operation)
                OPERATION="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -r|--retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 2
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "${SERVER}" ]]; then
        print_error "Required parameter missing: -s/--server"
        show_usage
        exit 2
    fi

    if [[ -z "${OPERATION}" ]]; then
        print_error "Required parameter missing: -o/--operation"
        show_usage
        exit 2
    fi

    # Validate parameter values
    if ! validate_server "${SERVER}"; then
        exit 2
    fi

    if ! validate_operation "${OPERATION}"; then
        exit 2
    fi

    # Validate port range
    if [[ ${PORT} -lt 1 ]] || [[ ${PORT} -gt 65535 ]]; then
        print_error "Port must be between 1 and 65535 (got: ${PORT})"
        exit 2
    fi

    # Validate timeout range
    if [[ ${TIMEOUT} -lt 5 ]] || [[ ${TIMEOUT} -gt 300 ]]; then
        print_error "Timeout must be between 5 and 300 seconds (got: ${TIMEOUT})"
        exit 2
    fi

    # Validate retries range
    if [[ ${MAX_RETRIES} -lt 1 ]] || [[ ${MAX_RETRIES} -gt 10 ]]; then
        print_error "Retries must be between 1 and 10 (got: ${MAX_RETRIES})"
        exit 2
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Set up trap for cleanup and error handling
    trap cleanup EXIT
    trap 'error_handler ${LINENO} "${BASH_COMMAND}"' ERR

    print_info "========================================"
    print_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
    print_info "========================================"

    # Parse command line arguments
    parse_arguments "$@"

    # Display configuration
    print_info "Configuration:"
    print_info "  Server: ${SERVER}"
    print_info "  Port: ${PORT}"
    print_info "  Operation: ${OPERATION}"
    print_info "  Timeout: ${TIMEOUT}s"
    print_info "  Max Retries: ${MAX_RETRIES}"
    print_info "  Dry Run: ${DRY_RUN}"
    print_info "  Verbose: ${VERBOSE}"
    print_info "========================================"

    # Check prerequisites
    check_prerequisites || exit $?

    # Execute operation with retry logic
    if perform_operation_with_retry "${SERVER}" "${PORT}" "${OPERATION}"; then
        print_success "Operation completed successfully"
        exit 0
    else
        print_error "Operation failed"
        exit 4
    fi
}

# Execute main function with all arguments
main "$@"
