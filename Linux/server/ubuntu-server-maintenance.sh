#!/usr/bin/env bash
# Ubuntu Server Maintenance Script
# Run as root or with sudo

set -euo pipefail

### --- Updates & Upgrades ---
update_system() {
    echo "[i] Updating system..."
    apt update && apt -y upgrade && apt -y dist-upgrade
    apt -y autoremove --purge
    apt -y autoclean
}

### --- Security Hardening ---
configure_firewall() {
    echo "[i] Configuring UFW firewall..."
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    # allow SSH (adjust if not default port)
    ufw allow 22/tcp
    ufw --force enable
}

secure_ssh() {
    echo "[+] Securing SSH..."
    # Backup sshd_config
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%F)"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

harden_fail2ban() {
    echo "[!] Configuring fail2ban..."
    apt install -y fail2ban
    systemctl enable --now fail2ban
    # Optional: create local jail config
    cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 5
EOF
    systemctl restart fail2ban
}

### --- Monitoring & Logs ---
setup_log_rotation() {
    echo "[i] Ensuring logrotate is enabled..."
    apt install -y logrotate
    systemctl enable logrotate.timer
    systemctl start logrotate.timer
}

install_htop_sysstat() {
    echo "[i] Installing monitoring tools..."
    apt install -y htop sysstat iotop vnstat
    systemctl enable --now sysstat
    systemctl enable --now vnstat
}

### --- Docker Maintenance ---
docker_cleanup() {
    echo "[i] Cleaning up Docker..."
    docker system prune -af --volumes
}

### --- Backup Hook ---
backup_reminder() {
    echo "[i] Reminder: set up backups!"
    echo "Suggested tool: restic, borgbackup, or rsync + cron"
}

# ----- Run all -----
main() {
    update_system
    configure_firewall
    secure_ssh
    harden_fail2ban
    setup_log_rotation
    install_htop_sysstat
    docker_cleanup
    backup_reminder
    echo "[+] All maintenance tasks complete!"
}

main