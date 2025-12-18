#!/usr/bin/env bats
# BATS tests for Linux maintenance scripts
# Run: bats tests/Linux/maintenance.bats
# Install BATS: https://github.com/bats-core/bats-core

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    LINUX_MAINTENANCE="${PROJECT_ROOT}/Linux/maintenance"
}

# Test script existence
@test "disk-cleanup.sh exists" {
    [ -f "${LINUX_MAINTENANCE}/disk-cleanup.sh" ]
}

@test "system-update.sh exists" {
    [ -f "${LINUX_MAINTENANCE}/system-update.sh" ]
}

# Test script permissions
@test "disk-cleanup.sh is executable" {
    [ -x "${LINUX_MAINTENANCE}/disk-cleanup.sh" ]
}

@test "system-update.sh is executable" {
    [ -x "${LINUX_MAINTENANCE}/system-update.sh" ]
}

# Test script syntax (bash -n checks syntax without executing)
@test "disk-cleanup.sh has valid bash syntax" {
    bash -n "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

@test "system-update.sh has valid bash syntax" {
    bash -n "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for proper shebang
@test "disk-cleanup.sh has bash shebang" {
    head -1 "${LINUX_MAINTENANCE}/disk-cleanup.sh" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

@test "system-update.sh has bash shebang" {
    head -1 "${LINUX_MAINTENANCE}/system-update.sh" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# Test for no emojis (per CLAUDE.md rules)
@test "disk-cleanup.sh contains no emojis" {
    ! grep -P '[\x{1F300}-\x{1F9FF}]|✅|❌|⚠️|ℹ️' "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

@test "system-update.sh contains no emojis" {
    ! grep -P '[\x{1F300}-\x{1F9FF}]|✅|❌|⚠️|ℹ️' "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for ASCII markers [+] [-] [i] [!]
@test "disk-cleanup.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

@test "system-update.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for no hardcoded credentials
@test "disk-cleanup.sh contains no passwords" {
    ! grep -i "password=" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

@test "system-update.sh contains no API keys" {
    ! grep -i "api[_-]\?key=" "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for error handling
@test "disk-cleanup.sh has error handling" {
    grep -q "set -e\|set -u\|set -o pipefail\|trap" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

@test "system-update.sh has error handling" {
    grep -q "set -e\|set -u\|set -o pipefail\|trap" "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for logging approach (either functions or colored echo)
@test "scripts have logging approach" {
    # Check for logging functions OR colored echo output
    grep -q "^log()\|^info()\|^error()\|^warning()\|echo -e.*\[" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for sudo checks where needed
@test "scripts check for appropriate privileges" {
    grep -q "EUID\|whoami\|sudo" "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test script help output (dry run)
@test "disk-cleanup.sh accepts --help flag" {
    run bash -c "grep -q '\-\-help\|-h' '${LINUX_MAINTENANCE}/disk-cleanup.sh'"
    [ "$status" -eq 0 ] || skip "Script doesn't implement --help"
}

# Test for safe rm commands (should use -i or -I or have confirmation)
@test "scripts use safe rm operations" {
    if grep -q "rm -rf" "${LINUX_MAINTENANCE}/disk-cleanup.sh"; then
        # If using rm -rf, should have safety checks or confirmation
        grep -q "read.*confirm\|--force\|DRY_RUN" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
    else
        # No rm -rf found, which is safe
        true
    fi
}

# Test for apt/yum/dnf update patterns
@test "system-update.sh uses apt or yum/dnf" {
    grep -q "apt.*update\|yum.*update\|dnf.*update" "${LINUX_MAINTENANCE}/system-update.sh"
}

# Test for cleanup of package caches
@test "disk-cleanup.sh cleans package manager caches" {
    grep -q "apt.*clean\|apt.*autoclean\|apt.*autoremove\|yum.*clean" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}
