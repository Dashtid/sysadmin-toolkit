#!/usr/bin/env bats
# BATS tests for Docker cleanup script
# Run: bats tests/Linux/DockerCleanup.bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/docker/docker-cleanup.sh"
    LIB_PATH="${PROJECT_ROOT}/Linux/lib/bash/common-functions.sh"
}

# ============================================================================
# BASIC VALIDATION
# ============================================================================

@test "docker-cleanup.sh exists" {
    [ -f "$SCRIPT_PATH" ]
}

@test "docker-cleanup.sh is executable" {
    [ -x "$SCRIPT_PATH" ]
}

@test "docker-cleanup.sh has valid bash syntax" {
    bash -n "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has bash shebang" {
    head -1 "$SCRIPT_PATH" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# SECURITY COMPLIANCE
# ============================================================================

@test "docker-cleanup.sh contains no emojis" {
    ! grep -P '\xE2\x9C|\xF0\x9F' "$SCRIPT_PATH"
}

@test "docker-cleanup.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$SCRIPT_PATH"
}

@test "docker-cleanup.sh contains no hardcoded passwords" {
    ! grep -iE "password\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh contains no API keys" {
    ! grep -iE "api[_-]?key\s*=\s*['\"][^'\"]+['\"]" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh contains no private keys" {
    ! grep -q "BEGIN.*PRIVATE KEY" "$SCRIPT_PATH"
}

# ============================================================================
# ERROR HANDLING
# ============================================================================

@test "docker-cleanup.sh has strict error handling" {
    grep -q "set -euo pipefail" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh sources common-functions.sh" {
    grep -q "source.*common-functions.sh" "$SCRIPT_PATH"
}

# ============================================================================
# COMMAND LINE OPTIONS
# ============================================================================

@test "docker-cleanup.sh has --help flag" {
    grep -q "\-\-help" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has --whatif flag" {
    grep -q "\-\-whatif" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has --keep-versions option" {
    grep -q "\-\-keep-versions" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has --container-age-days option" {
    grep -q "\-\-container-age-days" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has --prune-volumes option" {
    grep -q "\-\-prune-volumes" "$SCRIPT_PATH"
}

# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

@test "docker-cleanup.sh exports Prometheus metrics" {
    grep -q "prometheus\|\.prom" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has HELP comments for metrics" {
    grep -q "# HELP" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has TYPE comments for metrics" {
    grep -q "# TYPE" "$SCRIPT_PATH"
}

# ============================================================================
# DOCKER OPERATIONS
# ============================================================================

@test "docker-cleanup.sh checks docker command" {
    grep -q "check_command docker\|command -v docker" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh removes dangling images" {
    grep -q "dangling" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh uses docker system prune" {
    grep -q "docker system prune" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh handles docker rmi" {
    grep -q "docker rmi" "$SCRIPT_PATH"
}

# ============================================================================
# FUNCTION DEFINITIONS
# ============================================================================

@test "docker-cleanup.sh defines check_dependencies function" {
    grep -q "^check_dependencies()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines remove_dangling_images function" {
    grep -q "^remove_dangling_images()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines prune_old_containers function" {
    grep -q "^prune_old_containers()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines export_prometheus_metrics function" {
    grep -q "^export_prometheus_metrics()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines show_summary function" {
    grep -q "^show_summary()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines show_help function" {
    grep -q "^show_help()" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh defines main function" {
    grep -q "^main()" "$SCRIPT_PATH"
}

# ============================================================================
# WHATIF MODE IMPLEMENTATION
# ============================================================================

@test "docker-cleanup.sh implements WHATIF_MODE variable" {
    grep -q "WHATIF_MODE" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh checks WHATIF_MODE before operations" {
    grep -q 'WHATIF_MODE.*==.*true' "$SCRIPT_PATH"
}

# ============================================================================
# DOCUMENTATION
# ============================================================================

@test "docker-cleanup.sh has version information" {
    grep -q "SCRIPT_VERSION\|Version:" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has usage documentation" {
    grep -q "Usage:" "$SCRIPT_PATH"
}

@test "docker-cleanup.sh has examples in documentation" {
    grep -q "Example" "$SCRIPT_PATH"
}
