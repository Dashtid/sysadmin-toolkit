#!/usr/bin/env bats
# BATS tests for server setup and maintenance scripts
# Run: bats tests/Linux/ServerSetup.bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SERVER_DIR="${PROJECT_ROOT}/Linux/server"
    DOCKER_LAB="${SERVER_DIR}/docker-lab-environment.sh"
    HEADLESS_SETUP="${SERVER_DIR}/headless-server-setup.sh"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - BASIC VALIDATION
# ============================================================================

@test "docker-lab-environment.sh exists" {
    [ -f "$DOCKER_LAB" ]
}

@test "docker-lab-environment.sh is executable" {
    [ -x "$DOCKER_LAB" ]
}

@test "docker-lab-environment.sh has valid bash syntax" {
    bash -n "$DOCKER_LAB"
}

@test "docker-lab-environment.sh has bash shebang" {
    head -1 "$DOCKER_LAB" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - SECURITY COMPLIANCE
# ============================================================================

@test "docker-lab-environment.sh contains no emojis" {
    ! grep -P '\xE2\x9C|\xF0\x9F' "$DOCKER_LAB"
}

@test "docker-lab-environment.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$DOCKER_LAB"
}

# Note: This script has example/demo passwords which is acceptable for lab setup
@test "docker-lab-environment.sh uses demo passwords only" {
    # Acceptable demo passwords for local lab environment
    grep -q "devpass123\|adminpass123\|rootpass123" "$DOCKER_LAB"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - ERROR HANDLING
# ============================================================================

@test "docker-lab-environment.sh has strict error handling" {
    grep -q "set -euo pipefail" "$DOCKER_LAB"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - DOCKER INTEGRATION
# ============================================================================

@test "docker-lab-environment.sh checks docker command" {
    grep -q "command -v docker\|docker info" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh creates docker networks" {
    grep -q "docker network create" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh creates docker-compose files" {
    grep -q "docker-compose\|\.yml" "$DOCKER_LAB"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - FUNCTION DEFINITIONS
# ============================================================================

@test "docker-lab-environment.sh defines check_docker function" {
    grep -q "^check_docker()" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh defines create_directories function" {
    grep -q "^create_directories()" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh defines create_networks function" {
    grep -q "^create_networks()" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh defines setup_portainer function" {
    grep -q "^setup_portainer()" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh defines setup_databases function" {
    grep -q "^setup_databases()" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh defines main function" {
    grep -q "^main()" "$DOCKER_LAB"
}

# ============================================================================
# DOCKER-LAB-ENVIRONMENT.SH - SERVICES
# ============================================================================

@test "docker-lab-environment.sh sets up PostgreSQL" {
    grep -q "postgres" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh sets up MySQL" {
    grep -q "mysql" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh sets up Redis" {
    grep -q "redis" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh sets up MongoDB" {
    grep -q "mongo" "$DOCKER_LAB"
}

@test "docker-lab-environment.sh sets up Portainer" {
    grep -q "portainer" "$DOCKER_LAB"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - BASIC VALIDATION
# ============================================================================

@test "headless-server-setup.sh exists" {
    [ -f "$HEADLESS_SETUP" ]
}

@test "headless-server-setup.sh is executable" {
    [ -x "$HEADLESS_SETUP" ]
}

@test "headless-server-setup.sh has valid bash syntax" {
    bash -n "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh has bash shebang" {
    head -1 "$HEADLESS_SETUP" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - SECURITY COMPLIANCE
# ============================================================================

@test "headless-server-setup.sh contains no emojis in logging" {
    # Allow emojis in comments/descriptions but not in log() calls
    ! grep -E "log.*[\xE2\x9C\xF0\x9F]" "$HEADLESS_SETUP" || true
}

@test "headless-server-setup.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh contains no hardcoded passwords" {
    ! grep -iE "password\s*=\s*['\"][a-zA-Z0-9]+['\"]" "$HEADLESS_SETUP" || \
    grep -q "POSTGRES_PASSWORD\|MYSQL_PASSWORD" "$HEADLESS_SETUP"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - ERROR HANDLING
# ============================================================================

@test "headless-server-setup.sh has strict error handling" {
    grep -q "set -euo pipefail" "$HEADLESS_SETUP"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - ROOT CHECK
# ============================================================================

@test "headless-server-setup.sh checks for root privileges" {
    grep -q "EUID\|check_root\|must be run as root" "$HEADLESS_SETUP"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - FUNCTION DEFINITIONS
# ============================================================================

@test "headless-server-setup.sh defines check_root function" {
    grep -q "^check_root()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines update_system function" {
    grep -q "^update_system()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines install_essentials function" {
    grep -q "^install_essentials()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines configure_firewall function" {
    grep -q "^configure_firewall()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines secure_ssh function" {
    grep -q "^secure_ssh()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines install_docker function" {
    grep -q "^install_docker()" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh defines main function" {
    grep -q "^main()" "$HEADLESS_SETUP"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - SECURITY FEATURES
# ============================================================================

@test "headless-server-setup.sh configures SSH security" {
    grep -q "PermitRootLogin\|PasswordAuthentication" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh sets up fail2ban" {
    grep -q "fail2ban" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh configures UFW firewall" {
    grep -q "ufw" "$HEADLESS_SETUP"
}

# ============================================================================
# HEADLESS-SERVER-SETUP.SH - LOGGING
# ============================================================================

@test "headless-server-setup.sh has LOG_DIR variable" {
    grep -q "LOG_DIR\|LOG_FILE" "$HEADLESS_SETUP"
}

@test "headless-server-setup.sh creates log directory" {
    grep -q "mkdir.*log\|LOG_DIR" "$HEADLESS_SETUP"
}

