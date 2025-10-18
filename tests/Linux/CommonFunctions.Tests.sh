#!/usr/bin/env bash
# ============================================================================
# Bash Tests for common-functions.sh Library
# ============================================================================
# Description: Unit tests for the shared Bash library
# Author: David Dashti
# Version: 1.0.0
# Last Updated: 2025-10-18
#
# Usage:
#   ./tests/Linux/CommonFunctions.Tests.sh
#
# Requirements:
#   - Bash 4.0+
#   - common-functions.sh library
# ============================================================================

set -euo pipefail

# Test framework colors
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[0;33m'
COLOR_CYAN='\033[0;36m'
COLOR_RESET='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test file path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LIBRARY_PATH="$PROJECT_ROOT/Linux/lib/bash/common-functions.sh"

# ============================================================================
# TEST FRAMEWORK FUNCTIONS
# ============================================================================

assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Assertion failed}"

    ((TESTS_RUN++))

    if [[ "$expected" == "$actual" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $message"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $message"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_true() {
    local condition="$1"
    local message="${2:-Assertion failed: expected true}"

    ((TESTS_RUN++))

    if [[ "$condition" == "true" ]] || [[ "$condition" == "0" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $message"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $message"
        echo "  Condition was false"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_command_exists() {
    local cmd="$1"
    local message="${2:-Command exists: $cmd}"

    ((TESTS_RUN++))

    if command -v "$cmd" &>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $message"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $message"
        echo "  Command not found: $cmd"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_file_exists() {
    local file="$1"
    local message="${2:-File exists: $file}"

    ((TESTS_RUN++))

    if [[ -f "$file" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $message"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $message"
        echo "  File not found: $file"
        ((TESTS_FAILED++))
        return 1
    fi
}

print_test_header() {
    echo ""
    echo -e "${COLOR_CYAN}========================================${COLOR_RESET}"
    echo -e "${COLOR_CYAN}$1${COLOR_RESET}"
    echo -e "${COLOR_CYAN}========================================${COLOR_RESET}"
}

# ============================================================================
# LIBRARY EXISTENCE TESTS
# ============================================================================

test_library_existence() {
    print_test_header "Library Existence Tests"

    assert_file_exists "$LIBRARY_PATH" "common-functions.sh exists"

    # Check if library can be sourced
    ((TESTS_RUN++))
    if source "$LIBRARY_PATH" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} Library can be sourced"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} Library can be sourced"
        ((TESTS_FAILED++))
    fi
}

# ============================================================================
# LOGGING FUNCTIONS TESTS
# ============================================================================

test_logging_functions() {
    print_test_header "Logging Functions Tests"

    # Source library
    source "$LIBRARY_PATH"

    # Test log_info
    ((TESTS_RUN++))
    if log_info "Test message" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_info function works"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_info function works"
        ((TESTS_FAILED++))
    fi

    # Test log_success
    ((TESTS_RUN++))
    if log_success "Test message" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_success function works"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_success function works"
        ((TESTS_FAILED++))
    fi

    # Test log_warning
    ((TESTS_RUN++))
    if log_warning "Test message" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_warning function works"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_warning function works"
        ((TESTS_FAILED++))
    fi

    # Test log_error
    ((TESTS_RUN++))
    if log_error "Test message" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_error function works"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_error function works"
        ((TESTS_FAILED++))
    fi

    # Test log_debug (should be silent when DEBUG=0)
    DEBUG=0
    ((TESTS_RUN++))
    output=$(log_debug "Test message" 2>&1)
    if [[ -z "$output" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_debug is silent when DEBUG=0"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_debug is silent when DEBUG=0"
        ((TESTS_FAILED++))
    fi

    # Test log_debug (should output when DEBUG=1)
    DEBUG=1
    ((TESTS_RUN++))
    output=$(log_debug "Test message" 2>&1)
    if [[ -n "$output" ]] && [[ "$output" =~ "Test message" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} log_debug outputs when DEBUG=1"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} log_debug outputs when DEBUG=1"
        ((TESTS_FAILED++))
    fi
    DEBUG=0
}

# ============================================================================
# VALIDATION FUNCTIONS TESTS
# ============================================================================

test_validation_functions() {
    print_test_header "Validation Functions Tests"

    source "$LIBRARY_PATH"

    # Test validate_number - valid cases
    ((TESTS_RUN++))
    if validate_number "123" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_number accepts valid number"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_number accepts valid number"
        ((TESTS_FAILED++))
    fi

    # Test validate_number - invalid cases
    ((TESTS_RUN++))
    if ! validate_number "abc" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_number rejects invalid number"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_number rejects invalid number"
        ((TESTS_FAILED++))
    fi

    # Test validate_ip - valid IP
    ((TESTS_RUN++))
    if validate_ip "192.168.1.1" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_ip accepts valid IP"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_ip accepts valid IP"
        ((TESTS_FAILED++))
    fi

    # Test validate_ip - invalid IP
    ((TESTS_RUN++))
    if ! validate_ip "256.1.1.1" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_ip rejects invalid IP"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_ip rejects invalid IP"
        ((TESTS_FAILED++))
    fi

    # Test validate_ip - octets over 255
    ((TESTS_RUN++))
    if ! validate_ip "192.168.300.1" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_ip rejects octets > 255"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_ip rejects octets > 255"
        ((TESTS_FAILED++))
    fi

    # Create temp file for validate_file test
    local temp_file="/tmp/test-common-functions-$$"
    touch "$temp_file"

    ((TESTS_RUN++))
    if validate_file "$temp_file" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_file accepts existing file"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_file accepts existing file"
        ((TESTS_FAILED++))
    fi

    ((TESTS_RUN++))
    if ! validate_file "/nonexistent/file" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_file rejects nonexistent file"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_file rejects nonexistent file"
        ((TESTS_FAILED++))
    fi

    rm -f "$temp_file"

    # Test validate_dir
    ((TESTS_RUN++))
    if validate_dir "/tmp" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_dir accepts existing directory"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_dir accepts existing directory"
        ((TESTS_FAILED++))
    fi

    ((TESTS_RUN++))
    if ! validate_dir "/nonexistent/directory" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} validate_dir rejects nonexistent directory"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} validate_dir rejects nonexistent directory"
        ((TESTS_FAILED++))
    fi
}

# ============================================================================
# UTILITY FUNCTIONS TESTS
# ============================================================================

test_utility_functions() {
    print_test_header "Utility Functions Tests"

    source "$LIBRARY_PATH"

    # Test get_timestamp
    ((TESTS_RUN++))
    local ts=$(get_timestamp)
    if [[ "$ts" =~ ^[0-9]+$ ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} get_timestamp returns numeric timestamp"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} get_timestamp returns numeric timestamp"
        ((TESTS_FAILED++))
    fi

    # Test get_elapsed_time
    ((TESTS_RUN++))
    local start=$(get_timestamp)
    sleep 1
    local elapsed=$(get_elapsed_time "$start")
    if [[ "$elapsed" -ge 1 ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} get_elapsed_time calculates elapsed time"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} get_elapsed_time calculates elapsed time"
        echo "  Expected: >= 1, Got: $elapsed"
        ((TESTS_FAILED++))
    fi

    # Test ensure_dir
    local test_dir="/tmp/test-common-functions-dir-$$"
    ((TESTS_RUN++))
    if ensure_dir "$test_dir" 2>/dev/null && [[ -d "$test_dir" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} ensure_dir creates directory"
        ((TESTS_PASSED++))
        rm -rf "$test_dir"
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} ensure_dir creates directory"
        ((TESTS_FAILED++))
    fi
}

# ============================================================================
# PROMETHEUS METRICS TESTS
# ============================================================================

test_prometheus_functions() {
    print_test_header "Prometheus Metrics Functions Tests"

    source "$LIBRARY_PATH"

    local metrics_file="/tmp/test-metrics-$$.prom"

    # Test init_prometheus_metrics
    ((TESTS_RUN++))
    if init_prometheus_metrics "$metrics_file" 2>/dev/null && [[ -f "$metrics_file" ]]; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} init_prometheus_metrics creates file"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} init_prometheus_metrics creates file"
        ((TESTS_FAILED++))
    fi

    # Test export_prometheus_metric
    ((TESTS_RUN++))
    if export_prometheus_metric "$metrics_file" "test_metric" "42" 2>/dev/null; then
        if grep -q "test_metric 42" "$metrics_file"; then
            echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} export_prometheus_metric writes metric"
            ((TESTS_PASSED++))
        else
            echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} export_prometheus_metric writes metric"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} export_prometheus_metric writes metric"
        ((TESTS_FAILED++))
    fi

    # Test export_prometheus_metric with labels
    ((TESTS_RUN++))
    if export_prometheus_metric "$metrics_file" "test_metric_labeled" "100" 'instance="test",job="test-job"' 2>/dev/null; then
        if grep -q 'test_metric_labeled{instance="test",job="test-job"} 100' "$metrics_file"; then
            echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} export_prometheus_metric writes metric with labels"
            ((TESTS_PASSED++))
        else
            echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} export_prometheus_metric writes metric with labels"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} export_prometheus_metric writes metric with labels"
        ((TESTS_FAILED++))
    fi

    # Test invalid metric name
    ((TESTS_RUN++))
    if ! export_prometheus_metric "$metrics_file" "invalid-metric-name" "1" 2>/dev/null; then
        echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} export_prometheus_metric rejects invalid metric name"
        ((TESTS_PASSED++))
    else
        echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} export_prometheus_metric rejects invalid metric name"
        ((TESTS_FAILED++))
    fi

    rm -f "$metrics_file"
}

# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================

echo ""
echo "================================================================================"
echo "  Common Functions Library - Unit Tests"
echo "================================================================================"
echo ""
echo "Library: $LIBRARY_PATH"
echo ""

# Run all test suites
test_library_existence
test_logging_functions
test_validation_functions
test_utility_functions
test_prometheus_functions

# Print summary
print_test_header "Test Summary"
echo ""
echo "Total tests run:    $TESTS_RUN"
echo -e "${COLOR_GREEN}Tests passed:       $TESTS_PASSED${COLOR_RESET}"

if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${COLOR_RED}Tests failed:       $TESTS_FAILED${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}Tests failed:       $TESTS_FAILED${COLOR_RESET}"
fi

echo ""

# Exit with appropriate code
if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi
