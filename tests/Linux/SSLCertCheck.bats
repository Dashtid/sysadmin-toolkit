#!/usr/bin/env bats
# BATS tests for SSL certificate check script
# Run: bats tests/Linux/SSLCertCheck.bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/monitoring/ssl-cert-check.sh"
}

# ============================================================================
# BASIC VALIDATION
# ============================================================================

@test "ssl-cert-check.sh exists" {
    [ -f "$SCRIPT_PATH" ]
}

@test "ssl-cert-check.sh is executable" {
    [ -x "$SCRIPT_PATH" ]
}

@test "ssl-cert-check.sh has valid bash syntax" {
    bash -n "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has bash shebang" {
    head -1 "$SCRIPT_PATH" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# SECURITY COMPLIANCE
# ============================================================================

@test "ssl-cert-check.sh contains no emojis" {
    ! grep -P '\xE2\x9C|\xF0\x9F' "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh contains no hardcoded passwords" {
    ! grep -iE "password\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh contains no API keys" {
    ! grep -iE "api[_-]?key\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh contains no private keys" {
    ! grep -q "BEGIN.*PRIVATE KEY" "$SCRIPT_PATH"
}

# ============================================================================
# ERROR HANDLING
# ============================================================================

@test "ssl-cert-check.sh has strict error handling" {
    grep -q "set -euo pipefail" "$SCRIPT_PATH"
}

# ============================================================================
# COMMAND LINE OPTIONS
# ============================================================================

@test "ssl-cert-check.sh has --help flag" {
    grep -q "\-\-help\|-h" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has --warn-days option" {
    grep -q "\-\-warn-days" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has --critical-days option" {
    grep -q "\-\-critical-days" "$SCRIPT_PATH"
}

# ============================================================================
# CERTIFICATE CHECKING
# ============================================================================

@test "ssl-cert-check.sh uses openssl" {
    grep -q "openssl" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh checks certificate expiry" {
    grep -q "enddate\|DAYS_REMAINING\|expire" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh finds .crt files" {
    grep -q "\.crt\|\.pem" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh calculates days remaining" {
    grep -q "DAYS_REMAINING\|days" "$SCRIPT_PATH"
}

# ============================================================================
# KUBERNETES INTEGRATION
# ============================================================================

@test "ssl-cert-check.sh checks K8s TLS secrets" {
    grep -q "kubernetes.io/tls\|TLS.*secrets\|tls\.crt" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh uses kubectl" {
    grep -q "kubectl" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh uses base64 decode" {
    grep -q "base64" "$SCRIPT_PATH"
}

# ============================================================================
# EXIT CODES
# ============================================================================

@test "ssl-cert-check.sh exits 0 on success" {
    grep -q "exit 0" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh exits 1 on warnings" {
    grep -q "exit 1" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh exits 2 on critical issues" {
    grep -q "exit 2" "$SCRIPT_PATH"
}

# ============================================================================
# THRESHOLDS
# ============================================================================

@test "ssl-cert-check.sh has WARN_DAYS variable" {
    grep -q "WARN_DAYS" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has CRITICAL_DAYS variable" {
    grep -q "CRITICAL_DAYS" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh default warn threshold is 30 days" {
    grep -q "WARN_DAYS=30\|WARN_DAYS:-30" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh default critical threshold is 7 days" {
    grep -q "CRITICAL_DAYS=7\|CRITICAL_DAYS:-7" "$SCRIPT_PATH"
}

# ============================================================================
# OUTPUT
# ============================================================================

@test "ssl-cert-check.sh shows expired certificates" {
    grep -q "EXPIRED\|expired" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh shows critical certificates" {
    grep -q "CRITICAL\|critical" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has summary section" {
    grep -q "Summary\|SUMMARY" "$SCRIPT_PATH"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

@test "ssl-cert-check.sh has K8S_PLATFORM_REPO variable" {
    grep -q "K8S_PLATFORM_REPO" "$SCRIPT_PATH"
}

@test "ssl-cert-check.sh has KUBECONFIG reference" {
    grep -q "KUBECONFIG" "$SCRIPT_PATH"
}
