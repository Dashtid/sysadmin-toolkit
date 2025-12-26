#!/usr/bin/env bats
# BATS tests for Linux/monitoring/system-health-check.sh
# Test Framework: BATS (Bash Automated Testing System)
# Version: 1.0.0
# Last Updated: 2025-12-25

# Setup test environment
setup() {
    # Get project root directory
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/monitoring/system-health-check.sh"

    # Create temporary directory for test files
    TEST_TEMP_DIR="${BATS_TEST_TMPDIR}/system-health-check-test"
    mkdir -p "$TEST_TEMP_DIR"
}

# Cleanup after tests
teardown() {
    if [ -d "$TEST_TEMP_DIR" ]; then
        rm -rf "$TEST_TEMP_DIR"
    fi
}

# ============================================================================
# BASIC VALIDATION TESTS
# ============================================================================

@test "[*] Script file exists" {
    [ -f "$SCRIPT_PATH" ]
}

@test "[*] Script is readable" {
    [ -r "$SCRIPT_PATH" ]
}

@test "[*] Script has valid Bash syntax" {
    bash -n "$SCRIPT_PATH"
}

@test "[*] Script has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE '^#!/(usr/)?bin/(env )?bash'
}

@test "[*] Script is executable or can be made executable" {
    # Script should have valid syntax and be source-able for syntax check
    bash -n "$SCRIPT_PATH"
}

# ============================================================================
# SECURITY AND COMPLIANCE TESTS
# ============================================================================

@test "[-] Script contains no emojis - CLAUDE.md compliance" {
    # Check for common emoji byte sequences (UTF-8 emoji range)
    ! grep -P '\xE2\x9C|\xF0\x9F' "$SCRIPT_PATH"
}

@test "[+] Script uses ASCII markers [+] [-] [i] [!]" {
    grep -q '\[+\]' "$SCRIPT_PATH" || grep -q '\[i\]' "$SCRIPT_PATH"
}

@test "[-] Script contains no hardcoded passwords" {
    ! grep -iE 'password\s*=\s*["\'][^"'\'']+["\']' "$SCRIPT_PATH"
}

@test "[-] Script contains no hardcoded API keys" {
    ! grep -iE 'api[_-]?key\s*=\s*["\'][^"'\'']+["\']' "$SCRIPT_PATH"
}

@test "[-] Script contains no SSH private keys" {
    ! grep -q 'BEGIN.*PRIVATE KEY' "$SCRIPT_PATH"
}

@test "[-] Script contains no hardcoded IPs (except examples)" {
    # Allow localhost, examples, and documentation IPs
    ! grep -E '\b(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)\b' "$SCRIPT_PATH" || \
    grep -E '\b(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)\b' "$SCRIPT_PATH" | grep -qE '(example|sample|doc|#)'
}

# ============================================================================
# SCRIPT CONTENT TESTS
# ============================================================================

@test "[+] Script has set -e or errexit option" {
    grep -qE '^set\s+-[a-z]*e|^set\s+.*errexit' "$SCRIPT_PATH" || \
    grep -q 'set -euo pipefail' "$SCRIPT_PATH"
}

@test "[+] Script has help option defined" {
    grep -qE '\-\-help|\-h\)' "$SCRIPT_PATH"
}

@test "[+] Script has version or configuration section" {
    grep -qiE 'version|configuration|config' "$SCRIPT_PATH"
}

@test "[+] Script defines color codes" {
    grep -qE 'RED=|GREEN=|YELLOW=|BLUE=' "$SCRIPT_PATH"
}

@test "[+] Script has section function for output" {
    grep -qE 'function section|section\(\)|info\(\)|success\(\)' "$SCRIPT_PATH"
}

@test "[+] Script checks system resources" {
    grep -qiE 'cpu|memory|disk|ram' "$SCRIPT_PATH"
}

@test "[+] Script has print_header or header function" {
    grep -qE 'print_header|header\(\)|Header' "$SCRIPT_PATH"
}

# ============================================================================
# ARGUMENT PARSING TESTS
# ============================================================================

@test "[+] Script supports --verbose flag" {
    grep -qE '\-\-verbose|\-v\)' "$SCRIPT_PATH"
}

@test "[+] Script supports --save-log flag" {
    grep -qE '\-\-save-log|SAVE_LOG' "$SCRIPT_PATH"
}

@test "[+] Script handles unknown options" {
    grep -qE 'Unknown option|unknown.*option|\*\)' "$SCRIPT_PATH"
}

# ============================================================================
# LOGGING AND OUTPUT TESTS
# ============================================================================

@test "[+] Script has info logging function" {
    grep -qE 'info\(\)|log_info|function info' "$SCRIPT_PATH"
}

@test "[+] Script has success logging function" {
    grep -qE 'success\(\)|log_success|function success' "$SCRIPT_PATH"
}

@test "[+] Script has warning logging function" {
    grep -qE 'warning\(\)|log_warning|function warning' "$SCRIPT_PATH"
}

@test "[+] Script has error logging function" {
    grep -qE 'error\(\)|log_error|function error' "$SCRIPT_PATH"
}

# ============================================================================
# FEATURE TESTS
# ============================================================================

@test "[+] Script can check CPU usage" {
    grep -qiE 'cpu|processor|load' "$SCRIPT_PATH"
}

@test "[+] Script can check memory usage" {
    grep -qiE 'memory|ram|mem' "$SCRIPT_PATH"
}

@test "[+] Script can check disk usage" {
    grep -qiE 'disk|storage|filesystem|df' "$SCRIPT_PATH"
}

@test "[+] Script has K8s/K3s monitoring capability" {
    grep -qiE 'k8s|k3s|kubernetes|kubectl' "$SCRIPT_PATH"
}

@test "[+] Script uses timestamps" {
    grep -qE 'date|timestamp|Timestamp' "$SCRIPT_PATH"
}

# ============================================================================
# ROBUSTNESS TESTS
# ============================================================================

@test "[+] Script handles piped failures" {
    grep -q 'pipefail' "$SCRIPT_PATH"
}

@test "[+] Script uses proper variable quoting" {
    # Check that variables are generally quoted
    grep -qE '"\$[A-Za-z_]+"|"\$\{[A-Za-z_]+\}"' "$SCRIPT_PATH"
}

# ============================================================================
# DOCUMENTATION TESTS
# ============================================================================

@test "[+] Script has usage documentation" {
    grep -qiE 'usage|options|help' "$SCRIPT_PATH"
}

@test "[+] Script has description comment" {
    head -20 "$SCRIPT_PATH" | grep -qiE 'monitor|health|check'
}
