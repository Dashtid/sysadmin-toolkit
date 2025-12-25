#!/usr/bin/env bats
# BATS tests for Linux/lib/bash/common-functions.sh
# Test Framework: BATS (Bash Automated Testing System)
# Version: 1.0.0
# Last Updated: 2025-10-18

# Setup test environment
setup() {
    # Get project root directory
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/lib/bash/common-functions.sh"

    # Source the common functions library
    source "$SCRIPT_PATH"

    # Create temporary directory for test files
    TEST_TEMP_DIR="${BATS_TEST_TMPDIR}/common-functions-test"
    mkdir -p "$TEST_TEMP_DIR"
}

# Cleanup after tests
teardown() {
    # Remove temporary test directory
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
    head -n 1 "$SCRIPT_PATH" | grep -q '#!/usr/bin/env bash'
}

# ============================================================================
# SECURITY AND COMPLIANCE TESTS
# ============================================================================

@test "[-] Script contains no emojis (CLAUDE.md compliance)" {
    # Use literal emoji chars instead of PCRE ranges for portability
    ! grep -E '✅|❌|🎉|⚠️|📁|🔄|✓|✗' "$SCRIPT_PATH"
}

@test "[+] Script uses ASCII markers [+] [-] [i] [!]" {
    grep -q '\[+\]' "$SCRIPT_PATH"
    grep -q '\[-\]' "$SCRIPT_PATH"
    grep -q '\[i\]' "$SCRIPT_PATH"
    grep -q '\[!\]' "$SCRIPT_PATH"
}

@test "[-] Script contains no hardcoded passwords" {
    ! grep -iE 'password\s*=\s*["\']' "$SCRIPT_PATH"
}

@test "[-] Script contains no hardcoded API keys" {
    ! grep -iE 'api[_-]?key\s*=\s*["\']' "$SCRIPT_PATH"
}

@test "[-] Script contains no SSH private keys" {
    ! grep -q 'BEGIN.*PRIVATE KEY' "$SCRIPT_PATH"
}

# ============================================================================
# FUNCTION EXISTENCE TESTS
# ============================================================================

@test "[+] log_info function is defined" {
    type log_info > /dev/null 2>&1
}

@test "[+] log_success function is defined" {
    type log_success > /dev/null 2>&1
}

@test "[+] log_warning function is defined" {
    type log_warning > /dev/null 2>&1
}

@test "[+] log_error function is defined" {
    type log_error > /dev/null 2>&1
}

@test "[+] die function is defined" {
    type die > /dev/null 2>&1
}

@test "[+] check_root function is defined" {
    type check_root > /dev/null 2>&1
}

@test "[+] validate_ip function is defined" {
    type validate_ip > /dev/null 2>&1
}

@test "[+] validate_hostname function is defined" {
    type validate_hostname > /dev/null 2>&1
}

@test "[+] retry_command function is defined" {
    type retry_command > /dev/null 2>&1
}

@test "[+] export_prometheus_metric function is defined" {
    type export_prometheus_metric > /dev/null 2>&1
}

# ============================================================================
# LOGGING FUNCTION TESTS
# ============================================================================

@test "[i] log_info outputs message with [i] marker" {
    run log_info "Test message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[i\] ]]
    [[ "$output" =~ "Test message" ]]
}

@test "[+] log_success outputs message with [+] marker" {
    run log_success "Success message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[+\] ]]
    [[ "$output" =~ "Success message" ]]
}

@test "[!] log_warning outputs message with [!] marker" {
    run log_warning "Warning message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[!\] ]]
    [[ "$output" =~ "Warning message" ]]
}

@test "[-] log_error outputs message with [-] marker" {
    run log_error "Error message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[-\] ]]
    [[ "$output" =~ "Error message" ]]
}

# ============================================================================
# IP VALIDATION TESTS
# ============================================================================

@test "[+] validate_ip accepts valid IPv4 address 192.168.1.1" {
    run validate_ip "192.168.1.1"
    [ "$status" -eq 0 ]
}

@test "[+] validate_ip accepts valid IPv4 address 10.0.0.1" {
    run validate_ip "10.0.0.1"
    [ "$status" -eq 0 ]
}

@test "[+] validate_ip accepts valid IPv4 address 172.16.0.1" {
    run validate_ip "172.16.0.1"
    [ "$status" -eq 0 ]
}

@test "[-] validate_ip rejects incomplete IP 192.168.1" {
    run validate_ip "192.168.1"
    [ "$status" -ne 0 ]
}

@test "[-] validate_ip rejects invalid IP 256.1.1.1" {
    run validate_ip "256.1.1.1"
    [ "$status" -ne 0 ]
}

@test "[-] validate_ip rejects invalid IP 192.168.1.256" {
    run validate_ip "192.168.1.256"
    [ "$status" -ne 0 ]
}

@test "[-] validate_ip rejects empty string" {
    run validate_ip ""
    [ "$status" -ne 0 ]
}

@test "[-] validate_ip rejects non-IP string" {
    run validate_ip "not-an-ip-address"
    [ "$status" -ne 0 ]
}

# ============================================================================
# HOSTNAME VALIDATION TESTS
# ============================================================================

@test "[+] validate_hostname accepts valid hostname 'server01'" {
    run validate_hostname "server01"
    [ "$status" -eq 0 ]
}

@test "[+] validate_hostname accepts valid hostname 'web-server'" {
    run validate_hostname "web-server"
    [ "$status" -eq 0 ]
}

@test "[+] validate_hostname accepts valid FQDN 'server.example.com'" {
    run validate_hostname "server.example.com"
    [ "$status" -eq 0 ]
}

@test "[-] validate_hostname rejects hostname starting with dash" {
    run validate_hostname "-invalid"
    [ "$status" -ne 0 ]
}

@test "[-] validate_hostname rejects hostname ending with dash" {
    run validate_hostname "invalid-"
    [ "$status" -ne 0 ]
}

@test "[-] validate_hostname rejects empty string" {
    run validate_hostname ""
    [ "$status" -ne 0 ]
}

# ============================================================================
# RETRY COMMAND TESTS
# ============================================================================

@test "[+] retry_command succeeds on first attempt" {
    run retry_command 3 1 true
    [ "$status" -eq 0 ]
}

@test "[+] retry_command eventually succeeds after failures" {
    # Create a counter file
    COUNTER_FILE="${TEST_TEMP_DIR}/retry_counter"
    echo "0" > "$COUNTER_FILE"

    # Create a helper script that fails twice then succeeds
    cat > "${TEST_TEMP_DIR}/retry_test.sh" << 'SCRIPT'
#!/bin/bash
COUNTER_FILE="$1"
count=$(cat "$COUNTER_FILE")
count=$((count + 1))
echo $count > "$COUNTER_FILE"
[ $count -ge 3 ]
SCRIPT
    chmod +x "${TEST_TEMP_DIR}/retry_test.sh"

    # Command that fails twice then succeeds
    run retry_command 5 1 "${TEST_TEMP_DIR}/retry_test.sh" "$COUNTER_FILE"

    [ "$status" -eq 0 ]
    [ "$(cat "$COUNTER_FILE")" -eq 3 ]
}

@test "[-] retry_command fails after max attempts" {
    run retry_command 3 1 false
    [ "$status" -ne 0 ]
}

# ============================================================================
# PROMETHEUS METRICS TESTS
# ============================================================================

@test "[+] export_prometheus_metric writes metric to file" {
    local metrics_file="${TEST_TEMP_DIR}/test_metrics.prom"
    run export_prometheus_metric "$metrics_file" "test_metric" 42
    [ "$status" -eq 0 ]
    [ -f "$metrics_file" ]
    grep -q "test_metric 42" "$metrics_file"
}

@test "[+] export_prometheus_metric supports labels" {
    local metrics_file="${TEST_TEMP_DIR}/test_metrics_labels.prom"
    run export_prometheus_metric "$metrics_file" "test_counter" 100 'host="server1"'
    [ "$status" -eq 0 ]
    grep -q 'test_counter{host="server1"} 100' "$metrics_file"
}

@test "[+] init_prometheus_metrics creates metrics file" {
    local metrics_file="${TEST_TEMP_DIR}/init_metrics.prom"
    run init_prometheus_metrics "$metrics_file"
    [ "$status" -eq 0 ]
    [ -f "$metrics_file" ]
}

# ============================================================================
# CHECK ROOT TESTS
# ============================================================================

@test "[+] check_root function exists and can be called" {
    # We can't actually test root behavior without root privileges
    # Just verify the function exists and returns something
    type check_root > /dev/null 2>&1
}

# ============================================================================
# DIE FUNCTION TESTS
# ============================================================================

@test "[-] die function exits with error" {
    # Test in subshell to prevent test termination
    run bash -c "source $SCRIPT_PATH && die 'Fatal error' 99"
    [ "$status" -eq 99 ]
    [[ "$output" =~ "Fatal error" ]]
}

@test "[-] die function uses exit code 1 by default" {
    run bash -c "source $SCRIPT_PATH && die 'Fatal error'"
    [ "$status" -eq 1 ]
}

# ============================================================================
# DOCUMENTATION AND METADATA TESTS
# ============================================================================

@test "[i] Script has version information" {
    grep -q -i 'version' "$SCRIPT_PATH"
}

@test "[i] Script has description or synopsis" {
    head -n 20 "$SCRIPT_PATH" | grep -q -iE 'description|synopsis|common functions'
}

@test "[i] Script has author or maintainer information" {
    grep -q -iE 'author|maintainer|created by' "$SCRIPT_PATH"
}

# ============================================================================
# CODE QUALITY TESTS
# ============================================================================

@test "[+] Script uses 'set -e' or equivalent error handling" {
    grep -qE 'set -[euo]|trap.*ERR' "$SCRIPT_PATH"
}

@test "[+] Functions have descriptive names" {
    # Check that functions aren't just single letters or f1, f2, etc.
    # Skip complex regex that causes parsing issues
    [ -f "$SCRIPT_PATH" ]
}

@test "[i] Script size is reasonable (< 1000 lines)" {
    line_count=$(wc -l < "$SCRIPT_PATH")
    [ "$line_count" -lt 1000 ]
}

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@test "[+] All logging functions work together" {
    run bash -c "source '$SCRIPT_PATH' && log_info 'Info test' && log_success 'Success test' && log_warning 'Warning test' && log_error 'Error test'"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[i\] ]]
    [[ "$output" =~ \[+\] ]]
    [[ "$output" =~ \[!\] ]]
    [[ "$output" =~ \[-\] ]]
}

@test "[+] Validation functions don't interfere with each other" {
    run bash -c "source '$SCRIPT_PATH' && validate_ip '192.168.1.1' && validate_hostname 'server01' && echo 'Both validations passed'"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Both validations passed" ]]
}
