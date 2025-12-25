#!/usr/bin/env bats
# BATS tests for Linux/security/security-hardening.sh
# Test Framework: BATS (Bash Automated Testing System)
# Version: 1.0.0
# Last Updated: 2025-12-25

# Setup test environment
setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/security/security-hardening.sh"
    COMMON_FUNCTIONS="${PROJECT_ROOT}/Linux/lib/bash/common-functions.sh"

    TEST_TEMP_DIR="${BATS_TEST_TMPDIR}/security-hardening-test"
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

@test "[-] Script contains no emojis (CLAUDE.md compliance)" {
    ! grep -P '[\x{1F300}-\x{1F9FF}]|✅|❌|🎉|⚠️|📁' "$SCRIPT_PATH"
}

@test "[+] Script uses ASCII markers [+] [-] [i] [!]" {
    grep -qE '\[+\]|\[-\]|\[i\]|\[!\]' "$SCRIPT_PATH" || \
    grep -qE 'MARKER_INFO|MARKER_SUCCESS|MARKER_WARNING|MARKER_ERROR' "$SCRIPT_PATH"
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

# ============================================================================
# MODE AND OPTION TESTS
# ============================================================================

@test "[+] Script supports --audit mode" {
    grep -qE '\-\-audit|MODE.*audit' "$SCRIPT_PATH"
}

@test "[+] Script supports --apply mode" {
    grep -qE '\-\-apply|MODE.*apply' "$SCRIPT_PATH"
}

@test "[+] Script supports --auto mode" {
    grep -qE '\-\-auto|MODE.*auto' "$SCRIPT_PATH"
}

@test "[+] Script supports hardening levels" {
    grep -qE '\-\-level|HARDENING_LEVEL' "$SCRIPT_PATH"
}

@test "[+] Script supports --skip-ssh option" {
    grep -q '\-\-skip-ssh' "$SCRIPT_PATH"
}

@test "[+] Script supports --skip-firewall option" {
    grep -q '\-\-skip-firewall' "$SCRIPT_PATH"
}

@test "[+] Script supports --skip-kernel option" {
    grep -q '\-\-skip-kernel' "$SCRIPT_PATH"
}

@test "[+] Script supports --report option" {
    grep -qE '\-\-report|REPORT_FILE' "$SCRIPT_PATH"
}

@test "[+] Script supports --verbose option" {
    grep -qE '\-\-verbose|\-v\)' "$SCRIPT_PATH"
}

@test "[+] Script supports --help option" {
    grep -qE '\-\-help|\-h\)' "$SCRIPT_PATH"
}

# ============================================================================
# SSH HARDENING TESTS
# ============================================================================

@test "[+] Script audits SSH configuration" {
    grep -q 'audit_ssh' "$SCRIPT_PATH"
}

@test "[+] Script hardens SSH configuration" {
    grep -q 'harden_ssh' "$SCRIPT_PATH"
}

@test "[+] Script checks PermitRootLogin" {
    grep -q 'PermitRootLogin' "$SCRIPT_PATH"
}

@test "[+] Script checks PasswordAuthentication" {
    grep -q 'PasswordAuthentication' "$SCRIPT_PATH"
}

@test "[+] Script configures secure ciphers" {
    grep -qE 'Ciphers|cipher' "$SCRIPT_PATH"
}

@test "[+] Script checks for MaxAuthTries" {
    grep -q 'MaxAuthTries' "$SCRIPT_PATH"
}

# ============================================================================
# FIREWALL TESTS
# ============================================================================

@test "[+] Script audits firewall configuration" {
    grep -q 'audit_firewall' "$SCRIPT_PATH"
}

@test "[+] Script can configure UFW" {
    grep -qE 'ufw|UFW' "$SCRIPT_PATH"
}

@test "[+] Script checks for open ports" {
    grep -qE 'open.*port|listening|LISTEN' "$SCRIPT_PATH"
}

# ============================================================================
# KERNEL HARDENING TESTS
# ============================================================================

@test "[+] Script audits kernel parameters" {
    grep -q 'audit_kernel' "$SCRIPT_PATH"
}

@test "[+] Script hardens kernel parameters" {
    grep -q 'harden_kernel' "$SCRIPT_PATH"
}

@test "[+] Script configures sysctl" {
    grep -qE 'sysctl|sysctl\.d' "$SCRIPT_PATH"
}

@test "[+] Script checks IP forwarding" {
    grep -q 'ip_forward' "$SCRIPT_PATH"
}

@test "[+] Script checks ASLR" {
    grep -q 'randomize_va_space' "$SCRIPT_PATH"
}

# ============================================================================
# FILE PERMISSIONS TESTS
# ============================================================================

@test "[+] Script audits file permissions" {
    grep -q 'audit_file_permissions' "$SCRIPT_PATH"
}

@test "[+] Script checks sensitive files" {
    grep -qE '/etc/passwd|/etc/shadow' "$SCRIPT_PATH"
}

@test "[+] Script audits SUID/SGID binaries" {
    grep -qE 'SUID|SGID|perm -4000' "$SCRIPT_PATH"
}

# ============================================================================
# USER SECURITY TESTS
# ============================================================================

@test "[+] Script audits user security" {
    grep -q 'audit_user_security' "$SCRIPT_PATH"
}

@test "[+] Script checks for UID 0 users" {
    grep -qE 'UID.*0|uid.*0|\$3 == 0' "$SCRIPT_PATH"
}

@test "[+] Script checks for empty passwords" {
    grep -qE 'empty.*password|without.*password|\$2 == ""' "$SCRIPT_PATH"
}

# ============================================================================
# SERVICE HARDENING TESTS
# ============================================================================

@test "[+] Script audits running services" {
    grep -q 'audit_services' "$SCRIPT_PATH"
}

@test "[+] Script checks for risky services" {
    grep -qE 'telnet|rsh|rlogin|tftp' "$SCRIPT_PATH"
}

@test "[+] Script configures automatic updates" {
    grep -q 'unattended-upgrades' "$SCRIPT_PATH"
}

# ============================================================================
# LOGGING TESTS
# ============================================================================

@test "[+] Script audits logging configuration" {
    grep -q 'audit_logging' "$SCRIPT_PATH"
}

@test "[+] Script checks for auditd" {
    grep -q 'auditd' "$SCRIPT_PATH"
}

@test "[+] Script checks for rsyslog" {
    grep -q 'rsyslog' "$SCRIPT_PATH"
}

# ============================================================================
# BACKUP TESTS
# ============================================================================

@test "[+] Script creates backups before changes" {
    grep -qE 'backup_file|BACKUP_DIR' "$SCRIPT_PATH"
}

# ============================================================================
# REPORTING TESTS
# ============================================================================

@test "[+] Script has summary report function" {
    grep -q 'print_summary' "$SCRIPT_PATH"
}

@test "[+] Script tracks issues found" {
    grep -qE 'ISSUES_FOUND|report_issue' "$SCRIPT_PATH"
}

@test "[+] Script tracks issues fixed" {
    grep -qE 'ISSUES_FIXED' "$SCRIPT_PATH"
}

# ============================================================================
# DOCUMENTATION TESTS
# ============================================================================

@test "[+] Script has usage documentation" {
    head -50 "$SCRIPT_PATH" | grep -qiE 'usage:|options:'
}

@test "[+] Script documents hardening categories" {
    head -50 "$SCRIPT_PATH" | grep -qiE 'ssh|firewall|kernel|user'
}
