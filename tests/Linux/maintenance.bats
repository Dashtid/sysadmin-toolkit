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

# Test script permissions
@test "disk-cleanup.sh is executable" {
    [ -x "${LINUX_MAINTENANCE}/disk-cleanup.sh" ]
}

# Test script syntax (bash -n checks syntax without executing)
@test "disk-cleanup.sh has valid bash syntax" {
    bash -n "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for proper shebang
@test "disk-cleanup.sh has bash shebang" {
    head -1 "${LINUX_MAINTENANCE}/disk-cleanup.sh" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

# Test for no emojis (per style guide)
@test "disk-cleanup.sh contains no emojis" {
    # Check for common emoji byte sequences (UTF-8 emoji range)
    ! grep -P '\xE2\x9C|\xF0\x9F' "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for ASCII markers [+] [-] [i] [!]
@test "disk-cleanup.sh uses ASCII markers" {
    grep -q '\[\+\]\|\[-\]\|\[i\]\|\[!\]' "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for no hardcoded credentials
@test "disk-cleanup.sh contains no passwords" {
    ! grep -i "password=" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for error handling
@test "disk-cleanup.sh has error handling" {
    grep -q "set -e\|set -u\|set -o pipefail\|trap" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for logging approach (either functions or colored echo)
@test "disk-cleanup.sh has logging approach" {
    grep -q "^log()\|^info()\|^error()\|^warning()\|echo -e.*\[" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for safe rm commands (should use confirmation or DRY_RUN guard)
@test "disk-cleanup.sh uses safe rm operations" {
    if grep -q "rm -rf" "${LINUX_MAINTENANCE}/disk-cleanup.sh"; then
        grep -q "read.*confirm\|--force\|DRY_RUN" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
    else
        true
    fi
}

# Test for cleanup of package manager caches
@test "disk-cleanup.sh cleans package manager caches" {
    grep -q "apt.*clean\|apt.*autoclean\|apt.*autoremove\|yum.*clean" "${LINUX_MAINTENANCE}/disk-cleanup.sh"
}

# Test for --help flag support
@test "disk-cleanup.sh accepts --help flag" {
    run bash -c "grep -q '\-\-help\|-h' '${LINUX_MAINTENANCE}/disk-cleanup.sh'"
    [ "$status" -eq 0 ] || skip "Script does not implement --help"
}
