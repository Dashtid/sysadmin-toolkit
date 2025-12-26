#!/usr/bin/env bats
# BATS tests for Linux/monitoring/service-health-monitor.sh
# Test Framework: BATS (Bash Automated Testing System)
# Version: 1.0.0
# Last Updated: 2025-12-25

# Setup test environment
setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/monitoring/service-health-monitor.sh"
    COMMON_FUNCTIONS="${PROJECT_ROOT}/Linux/lib/bash/common-functions.sh"

    TEST_TEMP_DIR="${BATS_TEST_TMPDIR}/service-health-monitor-test"
    mkdir -p "$TEST_TEMP_DIR"
}

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
    head -n 1 "$SCRIPT_PATH" | grep -qE '^#!/usr/bin/env bash'
}

@test "[*] Common functions library exists" {
    [ -f "$COMMON_FUNCTIONS" ]
}

# ============================================================================
# SECURITY AND COMPLIANCE TESTS
# ============================================================================

@test "[-] Script contains no emojis - CLAUDE.md compliance" {
    # Check for common emoji byte sequences (UTF-8 emoji range)
    ! grep -P '\xE2\x9C|\xF0\x9F' "$SCRIPT_PATH"
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

# ============================================================================
# SCRIPT STRUCTURE TESTS
# ============================================================================

@test "[+] Script sources common functions library" {
    grep -q 'source.*common-functions' "$SCRIPT_PATH"
}

@test "[+] Script has set -euo pipefail for robustness" {
    grep -q 'set -euo pipefail' "$SCRIPT_PATH"
}

@test "[+] Script has version defined" {
    grep -qE 'SCRIPT_VERSION|VERSION=' "$SCRIPT_PATH"
}

@test "[+] Script defines default services" {
    grep -qE 'DEFAULT_SERVICES|SERVICES=' "$SCRIPT_PATH"
}

# ============================================================================
# OPTION TESTS
# ============================================================================

@test "[+] Script supports --services option" {
    grep -q '\-\-services' "$SCRIPT_PATH"
}

@test "[+] Script supports --config option" {
    grep -q '\-\-config' "$SCRIPT_PATH"
}

@test "[+] Script supports --auto-restart option" {
    grep -qE '\-\-auto-restart|AUTO_RESTART' "$SCRIPT_PATH"
}

@test "[+] Script supports --max-restarts option" {
    grep -qE '\-\-max-restarts|MAX_RESTARTS' "$SCRIPT_PATH"
}

@test "[+] Script supports --interval option" {
    grep -qE '\-\-interval|CHECK_INTERVAL' "$SCRIPT_PATH"
}

@test "[+] Script supports --daemon option" {
    grep -qE '\-\-daemon|DAEMON_MODE' "$SCRIPT_PATH"
}

@test "[+] Script supports --alert option" {
    grep -qE '\-\-alert|ALERT_METHOD' "$SCRIPT_PATH"
}

@test "[+] Script supports --prometheus option" {
    grep -qE '\-\-prometheus|PROMETHEUS_FILE' "$SCRIPT_PATH"
}

@test "[+] Script supports --verbose option" {
    grep -qE '\-\-verbose|\-v\)' "$SCRIPT_PATH"
}

@test "[+] Script supports --help option" {
    grep -qE '\-\-help|\-h\)' "$SCRIPT_PATH"
}

# ============================================================================
# SERVICE MONITORING TESTS
# ============================================================================

@test "[+] Script has service status check function" {
    grep -q 'check_service_status' "$SCRIPT_PATH"
}

@test "[+] Script uses systemctl for service checks" {
    grep -q 'systemctl' "$SCRIPT_PATH"
}

@test "[+] Script checks if service is active" {
    grep -qE 'is-active|is_active' "$SCRIPT_PATH"
}

@test "[+] Script checks if service is enabled" {
    grep -qE 'is-enabled|is_enabled' "$SCRIPT_PATH"
}

@test "[+] Script tracks service memory usage" {
    grep -qE 'MemoryCurrent|memory_mb' "$SCRIPT_PATH"
}

@test "[+] Script tracks service uptime" {
    grep -qE 'uptime|ActiveEnterTimestamp' "$SCRIPT_PATH"
}

# ============================================================================
# AUTO-RESTART TESTS
# ============================================================================

@test "[+] Script has restart service function" {
    grep -q 'restart_service' "$SCRIPT_PATH"
}

@test "[+] Script tracks restart counts" {
    grep -qE 'RESTART_COUNTS|restart.*count' "$SCRIPT_PATH"
}

@test "[+] Script limits restart attempts" {
    grep -qE 'MAX_RESTARTS|max.*restart' "$SCRIPT_PATH"
}

# ============================================================================
# ALERTING TESTS
# ============================================================================

@test "[+] Script has alert function" {
    grep -q 'send_alert' "$SCRIPT_PATH"
}

@test "[+] Script supports log alerting" {
    grep -qE 'alert.*log|log\)' "$SCRIPT_PATH"
}

@test "[+] Script supports email alerting" {
    grep -qE 'email|mail' "$SCRIPT_PATH"
}

@test "[+] Script supports Slack alerting" {
    grep -qE 'slack|SLACK_WEBHOOK' "$SCRIPT_PATH"
}

# ============================================================================
# PROMETHEUS TESTS
# ============================================================================

@test "[+] Script exports Prometheus metrics" {
    grep -q 'export_prometheus_metrics' "$SCRIPT_PATH"
}

@test "[+] Script exports service_up metric" {
    grep -q 'service_up' "$SCRIPT_PATH"
}

@test "[+] Script exports service_enabled metric" {
    grep -q 'service_enabled' "$SCRIPT_PATH"
}

@test "[+] Script exports service_memory metric" {
    grep -qE 'service_memory|memory.*bytes' "$SCRIPT_PATH"
}

@test "[+] Script exports service_uptime metric" {
    grep -q 'service_uptime' "$SCRIPT_PATH"
}

# ============================================================================
# CONFIG FILE TESTS
# ============================================================================

@test "[+] Script can load configuration from file" {
    grep -q 'load_config' "$SCRIPT_PATH"
}

@test "[+] Script uses jq for JSON parsing" {
    grep -q 'jq' "$SCRIPT_PATH"
}

# ============================================================================
# OUTPUT TESTS
# ============================================================================

@test "[+] Script has header printing function" {
    grep -q 'print_header' "$SCRIPT_PATH"
}

@test "[+] Script has table printing function" {
    grep -q 'print_service_table' "$SCRIPT_PATH"
}

@test "[+] Script formats uptime for display" {
    grep -q 'format_uptime' "$SCRIPT_PATH"
}

# ============================================================================
# DAEMON MODE TESTS
# ============================================================================

@test "[+] Script has daemon mode loop" {
    grep -qE 'while true|DAEMON_MODE' "$SCRIPT_PATH"
}

@test "[+] Script handles SIGINT/SIGTERM in daemon mode" {
    grep -q 'trap.*SIGINT\|trap.*SIGTERM' "$SCRIPT_PATH"
}

@test "[+] Script sleeps between checks in daemon mode" {
    grep -qE 'sleep.*CHECK_INTERVAL|sleep "\$' "$SCRIPT_PATH"
}

# ============================================================================
# DOCUMENTATION TESTS
# ============================================================================

@test "[+] Script has usage documentation" {
    head -40 "$SCRIPT_PATH" | grep -qiE 'usage:|options:'
}

@test "[+] Script has examples in documentation" {
    head -40 "$SCRIPT_PATH" | grep -qiE 'examples:'
}
