#!/usr/bin/env bash
# ============================================================================
# Linux Security Hardening Script
# Implements security best practices based on CIS Benchmarks and DISA STIG
# Supports Ubuntu 22.04+ and Debian 12+
# ============================================================================
#
# Usage:
#   sudo ./security-hardening.sh [OPTIONS]
#
# Options:
#   --audit          Audit mode - report issues without making changes
#   --apply          Apply recommended hardening (requires confirmation)
#   --auto           Apply hardening without prompts (use with caution)
#   --level <1|2>    Hardening level (1=basic, 2=strict) [default: 1]
#   --skip-ssh       Skip SSH hardening
#   --skip-firewall  Skip firewall configuration
#   --skip-kernel    Skip kernel hardening
#   --report <file>  Save audit report to file
#   --verbose        Enable verbose output
#   --help           Show this help message
#
# Hardening Categories:
#   - SSH Configuration (key-only auth, disable root login)
#   - Firewall Setup (UFW with sensible defaults)
#   - Kernel Hardening (sysctl security parameters)
#   - File Permissions (sensitive files, SUID/SGID audit)
#   - User Security (password policies, inactive accounts)
#   - Service Hardening (disable unnecessary services)
#   - Audit Logging (auditd configuration)
#   - Automatic Security Updates
#
# ============================================================================

set -euo pipefail

# Script metadata
SCRIPT_NAME="security-hardening"
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
COMMON_FUNCTIONS="${SCRIPT_DIR}/../lib/bash/common-functions.sh"
if [[ -f "$COMMON_FUNCTIONS" ]]; then
    # shellcheck source=../lib/bash/common-functions.sh
    source "$COMMON_FUNCTIONS"
else
    echo "[-] Common functions library not found: $COMMON_FUNCTIONS"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default settings
MODE="audit"              # audit, apply, or auto
HARDENING_LEVEL=1         # 1=basic, 2=strict
SKIP_SSH=false
SKIP_FIREWALL=false
SKIP_KERNEL=false
REPORT_FILE=""
VERBOSE=false

# Counters
ISSUES_FOUND=0
ISSUES_FIXED=0
WARNINGS=0

# Backup directory
BACKUP_DIR="/var/backup/security-hardening/$(date +%Y%m%d-%H%M%S)"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

show_help() {
    head -45 "$0" | tail -40 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -p "$file" "$BACKUP_DIR/$(basename "$file").bak"
        log_debug "Backed up: $file"
    fi
}

report_issue() {
    local category="$1"
    local description="$2"
    local severity="${3:-MEDIUM}"

    ((ISSUES_FOUND++))
    log_warning "[$severity] $category: $description"

    if [[ -n "$REPORT_FILE" ]]; then
        echo "[$severity] $category: $description" >> "$REPORT_FILE"
    fi
}

report_pass() {
    local category="$1"
    local description="$2"

    log_success "$category: $description"

    if [[ -n "$REPORT_FILE" ]]; then
        echo "[PASS] $category: $description" >> "$REPORT_FILE"
    fi
}

confirm_action() {
    local prompt="$1"
    if [[ "$MODE" == "auto" ]]; then
        return 0
    fi

    read -r -p "$prompt [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ============================================================================
# SSH HARDENING
# ============================================================================

audit_ssh() {
    log_info "Auditing SSH configuration..."
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_warning "SSH server not installed - skipping SSH audit"
        return 0
    fi

    # Check PermitRootLogin
    if grep -qE "^\s*PermitRootLogin\s+(yes|without-password)" "$sshd_config" 2>/dev/null; then
        report_issue "SSH" "Root login is permitted" "HIGH"
    elif grep -qE "^\s*PermitRootLogin\s+no" "$sshd_config" 2>/dev/null; then
        report_pass "SSH" "Root login disabled"
    else
        report_issue "SSH" "PermitRootLogin not explicitly set (defaults may allow)" "MEDIUM"
    fi

    # Check PasswordAuthentication
    if grep -qE "^\s*PasswordAuthentication\s+yes" "$sshd_config" 2>/dev/null; then
        report_issue "SSH" "Password authentication enabled (key-only recommended)" "MEDIUM"
    elif grep -qE "^\s*PasswordAuthentication\s+no" "$sshd_config" 2>/dev/null; then
        report_pass "SSH" "Password authentication disabled"
    fi

    # Check Protocol (for older systems)
    if grep -qE "^\s*Protocol\s+1" "$sshd_config" 2>/dev/null; then
        report_issue "SSH" "SSHv1 protocol enabled (insecure)" "CRITICAL"
    fi

    # Check for weak ciphers
    if grep -qE "^\s*Ciphers.*3des|arcfour|blowfish" "$sshd_config" 2>/dev/null; then
        report_issue "SSH" "Weak ciphers configured" "HIGH"
    fi

    # Check MaxAuthTries
    local max_auth
    max_auth=$(grep -E "^\s*MaxAuthTries" "$sshd_config" 2>/dev/null | awk '{print $2}')
    if [[ -n "$max_auth" && "$max_auth" -gt 4 ]]; then
        report_issue "SSH" "MaxAuthTries is too high ($max_auth, recommend 4)" "LOW"
    elif [[ -n "$max_auth" ]]; then
        report_pass "SSH" "MaxAuthTries set to $max_auth"
    fi

    # Check X11Forwarding
    if grep -qE "^\s*X11Forwarding\s+yes" "$sshd_config" 2>/dev/null; then
        if [[ $HARDENING_LEVEL -ge 2 ]]; then
            report_issue "SSH" "X11 forwarding enabled (disable for servers)" "LOW"
        fi
    fi

    # Check for empty passwords
    if grep -qE "^\s*PermitEmptyPasswords\s+yes" "$sshd_config" 2>/dev/null; then
        report_issue "SSH" "Empty passwords permitted" "CRITICAL"
    else
        report_pass "SSH" "Empty passwords not permitted"
    fi
}

harden_ssh() {
    log_info "Applying SSH hardening..."
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_warning "SSH server not installed - skipping"
        return 0
    fi

    backup_file "$sshd_config"

    # Create hardened config drop-in
    local hardened_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
    mkdir -p /etc/ssh/sshd_config.d

    cat > "$hardened_conf" << 'EOF'
# Security hardening configuration
# Generated by security-hardening.sh

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Limit authentication attempts
MaxAuthTries 4

# Set login grace time
LoginGraceTime 60

# Disable X11 forwarding (unless needed)
X11Forwarding no

# Disable TCP forwarding (uncomment if not needed)
# AllowTcpForwarding no

# Use only secure ciphers and MACs
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Logging
LogLevel VERBOSE

# Client alive settings (disconnect idle sessions)
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    log_success "SSH hardening configuration written to $hardened_conf"
    ((ISSUES_FIXED++))

    # Test and reload SSH
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        log_success "SSH configuration reloaded"
    else
        log_error "SSH configuration test failed - reverting"
        rm -f "$hardened_conf"
        return 1
    fi
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================

audit_firewall() {
    log_info "Auditing firewall configuration..."

    # Check if UFW is installed and active
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)

        if [[ "$ufw_status" == *"inactive"* ]]; then
            report_issue "Firewall" "UFW is installed but inactive" "HIGH"
        elif [[ "$ufw_status" == *"active"* ]]; then
            report_pass "Firewall" "UFW is active"

            # Check default policies
            if ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; then
                report_pass "Firewall" "Default incoming policy is deny"
            else
                report_issue "Firewall" "Default incoming policy should be deny" "MEDIUM"
            fi
        fi
    elif command -v iptables &>/dev/null; then
        # Check iptables rules
        local rule_count
        rule_count=$(iptables -L INPUT -n 2>/dev/null | wc -l)

        if [[ $rule_count -le 2 ]]; then
            report_issue "Firewall" "No iptables rules configured (open firewall)" "HIGH"
        else
            report_pass "Firewall" "iptables rules present ($((rule_count - 2)) rules)"
        fi
    else
        report_issue "Firewall" "No firewall software detected" "HIGH"
    fi

    # Check for open ports
    if command -v ss &>/dev/null; then
        local open_ports
        open_ports=$(ss -tulpn 2>/dev/null | grep LISTEN | wc -l)
        log_info "Found $open_ports listening services"

        # Check for potentially dangerous open ports
        if ss -tulpn 2>/dev/null | grep -qE ":23\s"; then
            report_issue "Firewall" "Telnet port (23) is open - use SSH instead" "HIGH"
        fi
        if ss -tulpn 2>/dev/null | grep -qE ":21\s"; then
            report_issue "Firewall" "FTP port (21) is open - use SFTP instead" "MEDIUM"
        fi
    fi
}

harden_firewall() {
    log_info "Configuring UFW firewall..."

    if ! command -v ufw &>/dev/null; then
        log_info "Installing UFW..."
        apt-get update -qq
        apt-get install -y -qq ufw
    fi

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH (critical - don't lock yourself out!)
    ufw allow ssh

    # Common services (uncomment as needed)
    # ufw allow http
    # ufw allow https

    # Enable firewall
    if confirm_action "Enable UFW firewall? (make sure SSH is allowed)"; then
        ufw --force enable
        log_success "UFW firewall enabled"
        ((ISSUES_FIXED++))
    else
        log_warning "UFW not enabled - manual configuration required"
    fi
}

# ============================================================================
# KERNEL HARDENING
# ============================================================================

audit_kernel() {
    log_info "Auditing kernel security parameters..."

    # Check key sysctl parameters
    declare -A kernel_params=(
        ["net.ipv4.ip_forward"]="0:IP forwarding should be disabled (unless router)"
        ["net.ipv4.conf.all.accept_redirects"]="0:ICMP redirects should be disabled"
        ["net.ipv4.conf.all.send_redirects"]="0:ICMP redirect sending should be disabled"
        ["net.ipv4.conf.all.accept_source_route"]="0:Source routing should be disabled"
        ["net.ipv4.conf.all.log_martians"]="1:Martian packet logging should be enabled"
        ["net.ipv4.tcp_syncookies"]="1:SYN cookies should be enabled"
        ["kernel.randomize_va_space"]="2:ASLR should be fully enabled"
        ["fs.protected_hardlinks"]="1:Hardlink protection should be enabled"
        ["fs.protected_symlinks"]="1:Symlink protection should be enabled"
    )

    for param in "${!kernel_params[@]}"; do
        IFS=':' read -r expected_value description <<< "${kernel_params[$param]}"
        local current_value
        current_value=$(sysctl -n "$param" 2>/dev/null || echo "N/A")

        if [[ "$current_value" == "$expected_value" ]]; then
            report_pass "Kernel" "$param = $current_value"
        elif [[ "$current_value" == "N/A" ]]; then
            log_debug "Kernel parameter not available: $param"
        else
            report_issue "Kernel" "$description (current: $current_value)" "MEDIUM"
        fi
    done

    # Check core dumps
    if [[ -f /proc/sys/kernel/core_pattern ]]; then
        local core_pattern
        core_pattern=$(cat /proc/sys/kernel/core_pattern)
        if [[ "$core_pattern" != "|/bin/false" && "$core_pattern" != "" ]]; then
            if [[ $HARDENING_LEVEL -ge 2 ]]; then
                report_issue "Kernel" "Core dumps enabled (security risk for sensitive data)" "LOW"
            fi
        fi
    fi
}

harden_kernel() {
    log_info "Applying kernel hardening..."

    local sysctl_conf="/etc/sysctl.d/99-security-hardening.conf"
    backup_file "$sysctl_conf"

    cat > "$sysctl_conf" << 'EOF'
# Security hardening sysctl configuration
# Generated by security-hardening.sh

# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 security (if not using IPv6, consider disabling)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

    # Apply immediately
    sysctl -p "$sysctl_conf" 2>/dev/null || true
    log_success "Kernel hardening parameters applied"
    ((ISSUES_FIXED++))
}

# ============================================================================
# FILE PERMISSION AUDIT
# ============================================================================

audit_file_permissions() {
    log_info "Auditing file permissions..."

    # Check sensitive file permissions
    declare -A sensitive_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
        ["/etc/ssh/sshd_config"]="600"
        ["/etc/crontab"]="600"
    )

    for file in "${!sensitive_files[@]}"; do
        if [[ -f "$file" ]]; then
            local expected="${sensitive_files[$file]}"
            local actual
            actual=$(stat -c "%a" "$file" 2>/dev/null)

            if [[ "$actual" == "$expected" ]] || [[ "$actual" -le "$expected" ]]; then
                report_pass "Permissions" "$file ($actual)"
            else
                report_issue "Permissions" "$file has permissions $actual (should be $expected or less)" "MEDIUM"
            fi
        fi
    done

    # Find world-writable files (excluding /tmp, /var/tmp, /dev)
    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        log_info "Scanning for world-writable files..."
        local ww_count
        ww_count=$(find / -xdev -type f -perm -0002 \
            -not -path "/proc/*" \
            -not -path "/sys/*" \
            -not -path "/tmp/*" \
            -not -path "/var/tmp/*" \
            2>/dev/null | wc -l)

        if [[ $ww_count -gt 0 ]]; then
            report_issue "Permissions" "Found $ww_count world-writable files" "MEDIUM"
        else
            report_pass "Permissions" "No world-writable files found (outside temp dirs)"
        fi
    fi

    # Find SUID/SGID binaries
    log_info "Auditing SUID/SGID binaries..."
    local suid_count
    suid_count=$(find /usr -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l)
    log_info "Found $suid_count SUID/SGID binaries in /usr"

    # Check for unusual SUID binaries
    while IFS= read -r suid_file; do
        case "$suid_file" in
            /usr/bin/sudo|/usr/bin/su|/usr/bin/passwd|/usr/bin/mount|/usr/bin/umount|/usr/bin/ping)
                # Expected SUID binaries
                ;;
            *)
                if [[ $HARDENING_LEVEL -ge 2 ]]; then
                    log_debug "SUID binary: $suid_file"
                fi
                ;;
        esac
    done < <(find /usr -xdev -perm -4000 -type f 2>/dev/null)
}

# ============================================================================
# USER SECURITY
# ============================================================================

audit_user_security() {
    log_info "Auditing user security..."

    # Check for users with UID 0 (should only be root)
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd)
    local uid0_count
    uid0_count=$(echo "$uid0_users" | wc -w)

    if [[ $uid0_count -eq 1 && "$uid0_users" == "root" ]]; then
        report_pass "Users" "Only root has UID 0"
    else
        report_issue "Users" "Multiple users with UID 0: $uid0_users" "CRITICAL"
    fi

    # Check for users without passwords
    if [[ -r /etc/shadow ]]; then
        local no_pass
        no_pass=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" { print $1 }' /etc/shadow | head -5)
        if [[ -n "$no_pass" ]]; then
            report_issue "Users" "Accounts without passwords: $no_pass" "HIGH"
        else
            report_pass "Users" "All accounts have passwords set"
        fi
    fi

    # Check root account status
    if passwd -S root 2>/dev/null | grep -q "L"; then
        report_pass "Users" "Root account is locked (use sudo)"
    else
        if [[ $HARDENING_LEVEL -ge 2 ]]; then
            report_issue "Users" "Root account is not locked (consider locking)" "LOW"
        fi
    fi

    # Check for inactive accounts (no login in 90 days)
    if command -v lastlog &>/dev/null; then
        local inactive_count
        inactive_count=$(lastlog -b 90 2>/dev/null | tail -n +2 | grep -v "Never logged in" | wc -l)
        log_info "Found $inactive_count accounts with recent activity (last 90 days)"
    fi

    # Check password aging
    if [[ -f /etc/login.defs ]]; then
        local pass_max_days
        pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [[ -n "$pass_max_days" && "$pass_max_days" -gt 90 ]]; then
            report_issue "Users" "Password max age is $pass_max_days days (recommend 90)" "LOW"
        elif [[ -n "$pass_max_days" ]]; then
            report_pass "Users" "Password max age: $pass_max_days days"
        fi
    fi
}

# ============================================================================
# SERVICE HARDENING
# ============================================================================

audit_services() {
    log_info "Auditing running services..."

    # Services that should typically be disabled on servers
    local risky_services=("telnet" "rsh" "rlogin" "rexec" "tftp" "talk" "ntalk" "xinetd")

    for service in "${risky_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            report_issue "Services" "$service is running (consider disabling)" "HIGH"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            report_issue "Services" "$service is enabled at boot" "MEDIUM"
        fi
    done

    # Check for unnecessary network services
    if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
        if [[ $HARDENING_LEVEL -ge 2 ]]; then
            report_issue "Services" "avahi-daemon running (mDNS, often not needed on servers)" "LOW"
        fi
    fi

    # Check automatic updates
    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        report_pass "Services" "Automatic security updates enabled"
    else
        report_issue "Services" "Automatic security updates not configured" "MEDIUM"
    fi
}

harden_services() {
    log_info "Configuring automatic security updates..."

    if ! dpkg -l unattended-upgrades &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq unattended-upgrades
    fi

    # Enable automatic security updates
    dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true

    # Configure unattended-upgrades
    local uu_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    if [[ -f "$uu_conf" ]]; then
        # Ensure security updates are enabled (usually already is)
        log_success "Unattended upgrades configured"
        ((ISSUES_FIXED++))
    fi
}

# ============================================================================
# AUDIT LOGGING
# ============================================================================

audit_logging() {
    log_info "Auditing system logging..."

    # Check if auditd is installed and running
    if command -v auditd &>/dev/null; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            report_pass "Logging" "auditd is running"
        else
            report_issue "Logging" "auditd is installed but not running" "MEDIUM"
        fi
    else
        if [[ $HARDENING_LEVEL -ge 2 ]]; then
            report_issue "Logging" "auditd not installed (recommended for compliance)" "MEDIUM"
        fi
    fi

    # Check rsyslog
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        report_pass "Logging" "rsyslog is running"
    else
        report_issue "Logging" "rsyslog is not running" "MEDIUM"
    fi

    # Check log rotation
    if [[ -f /etc/logrotate.conf ]]; then
        report_pass "Logging" "Log rotation configured"
    else
        report_issue "Logging" "Log rotation not configured" "LOW"
    fi

    # Check for auth.log
    if [[ -f /var/log/auth.log ]] || [[ -f /var/log/secure ]]; then
        report_pass "Logging" "Authentication logging enabled"
    else
        report_issue "Logging" "Authentication log not found" "MEDIUM"
    fi
}

# ============================================================================
# SUMMARY REPORT
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "          Security Audit Summary"
    echo "=============================================="
    echo ""

    if [[ $ISSUES_FOUND -eq 0 ]]; then
        log_success "No security issues found!"
    else
        log_warning "Issues found: $ISSUES_FOUND"
    fi

    if [[ $MODE != "audit" ]]; then
        log_info "Issues fixed: $ISSUES_FIXED"
    fi

    echo ""
    echo "Hardening level: $HARDENING_LEVEL"
    echo "Mode: $MODE"

    if [[ -n "$REPORT_FILE" ]]; then
        echo ""
        log_info "Full report saved to: $REPORT_FILE"
    fi

    if [[ -d "$BACKUP_DIR" ]]; then
        echo ""
        log_info "Configuration backups saved to: $BACKUP_DIR"
    fi

    echo ""
    if [[ $ISSUES_FOUND -gt 0 && $MODE == "audit" ]]; then
        log_info "Run with --apply to fix identified issues"
    fi
}

# ============================================================================
# MAIN
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --audit)
                MODE="audit"
                shift
                ;;
            --apply)
                MODE="apply"
                shift
                ;;
            --auto)
                MODE="auto"
                shift
                ;;
            --level)
                HARDENING_LEVEL="$2"
                shift 2
                ;;
            --skip-ssh)
                SKIP_SSH=true
                shift
                ;;
            --skip-firewall)
                SKIP_FIREWALL=true
                shift
                ;;
            --skip-kernel)
                SKIP_KERNEL=true
                shift
                ;;
            --report)
                REPORT_FILE="$2"
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                DEBUG=1
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    # Verify running as root for apply modes
    if [[ $MODE != "audit" ]]; then
        check_root
    fi

    echo ""
    echo "=============================================="
    echo "      Linux Security Hardening Script"
    echo "           Version: $SCRIPT_VERSION"
    echo "=============================================="
    echo ""
    log_info "Mode: $MODE"
    log_info "Hardening Level: $HARDENING_LEVEL"
    log_info "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Hostname: $(hostname)"
    echo ""

    # Initialize report file
    if [[ -n "$REPORT_FILE" ]]; then
        echo "Security Hardening Report - $(date)" > "$REPORT_FILE"
        echo "Hostname: $(hostname)" >> "$REPORT_FILE"
        echo "Mode: $MODE, Level: $HARDENING_LEVEL" >> "$REPORT_FILE"
        echo "========================================" >> "$REPORT_FILE"
    fi

    # Run audits
    if [[ $SKIP_SSH != true ]]; then
        audit_ssh
        [[ $MODE != "audit" ]] && harden_ssh
    fi

    if [[ $SKIP_FIREWALL != true ]]; then
        audit_firewall
        [[ $MODE != "audit" ]] && harden_firewall
    fi

    if [[ $SKIP_KERNEL != true ]]; then
        audit_kernel
        [[ $MODE != "audit" ]] && harden_kernel
    fi

    audit_file_permissions
    audit_user_security
    audit_services
    [[ $MODE != "audit" ]] && harden_services
    audit_logging

    # Print summary
    print_summary

    # Exit with appropriate code
    if [[ $ISSUES_FOUND -gt 0 && $MODE == "audit" ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
