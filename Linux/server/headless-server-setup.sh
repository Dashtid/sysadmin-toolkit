#!/usr/bin/env bash
# Ubuntu Server Headless Setup Script
# Enhanced version for lab environment with Docker
# Run as root or with sudo

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging setup
LOG_DIR="/var/log/server-setup"
LOG_FILE="$LOG_DIR/setup-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        exit 1
    fi
}

# System updates and upgrades
update_system() {
    log "🔄 Updating system packages..."
    apt update && apt -y upgrade && apt -y dist-upgrade
    apt -y autoremove --purge
    apt -y autoclean
    log "✅ System update completed"
}

# Install essential packages
install_essentials() {
    log "📦 Installing essential packages..."
    apt install -y \
        curl \
        wget \
        git \
        vim \
        htop \
        tree \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        build-essential \
        python3 \
        python3-pip \
        nodejs \
        npm
    log "✅ Essential packages installed"
}

# Configure firewall
configure_firewall() {
    log "🛡️ Configuring UFW firewall..."
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (adjust port if needed)
    ufw allow 22/tcp
    
    # Allow common development ports
    ufw allow 3000/tcp  # Node.js dev server
    ufw allow 8000/tcp  # Python dev server
    ufw allow 8080/tcp  # Alternative HTTP
    
    # Docker ports (will be configured later)
    ufw allow 2376/tcp  # Docker daemon
    ufw allow 2377/tcp  # Docker swarm
    
    ufw --force enable
    log "✅ Firewall configured"
}

# Secure SSH configuration
secure_ssh() {
    log "🔒 Securing SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
    
    # Apply security settings
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config
    
    # Add additional security settings
    echo "" >> /etc/ssh/sshd_config
    echo "# Additional security settings" >> /etc/ssh/sshd_config
    echo "Protocol 2" >> /etc/ssh/sshd_config
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
    
    systemctl restart sshd
    log "✅ SSH secured"
}

# Install and configure fail2ban
setup_fail2ban() {
    log "🚨 Setting up fail2ban..."
    apt install -y fail2ban
    
    # Create local jail configuration
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = false

[nginx-limit-req]
enabled = false
EOF
    
    systemctl enable --now fail2ban
    log "✅ Fail2ban configured"
}

# Setup log rotation and monitoring
setup_logging() {
    log "📜 Configuring logging and rotation..."
    apt install -y logrotate rsyslog
    
    # Ensure logrotate is enabled
    systemctl enable logrotate.timer
    systemctl start logrotate.timer
    
    # Install monitoring tools
    apt install -y sysstat iotop vnstat ncdu
    systemctl enable --now sysstat
    systemctl enable --now vnstat
    
    log "✅ Logging and monitoring configured"
}

# Install Docker
install_docker() {
    log "🐋 Installing Docker..."
    
    # Remove old versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Start and enable Docker
    systemctl enable --now docker
    
    # Install Docker Compose (standalone)
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    log "✅ Docker installed"
}

# Configure Docker for development
configure_docker() {
    log "⚙️ Configuring Docker for development..."
    
    # Create docker group and add current user (if not root)
    groupadd -f docker
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG docker "$SUDO_USER"
        log "Added $SUDO_USER to docker group"
    fi
    
    # Configure Docker daemon for remote access (secure)
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2"
}
EOF
    
    systemctl restart docker
    log "✅ Docker configured for development"
}

# Setup development tools
setup_dev_tools() {
    log "🛠️ Setting up development tools..."
    
    # Install additional development packages
    apt install -y \
        jq \
        httpie \
        tmux \
        screen \
        zsh \
        fish \
        neofetch \
        bat \
        fd-find \
        ripgrep
    
    # Install modern alternatives
    if ! command -v exa &> /dev/null; then
        wget -qO- https://github.com/ogham/exa/releases/latest/download/exa-linux-x86_64-musl-*.zip | funzip > /usr/local/bin/exa
        chmod +x /usr/local/bin/exa
    fi
    
    log "✅ Development tools installed"
}

# Create useful aliases and functions
setup_aliases() {
    log "🔗 Setting up useful aliases..."
    
    cat > /etc/profile.d/server-aliases.sh << 'EOF'
# Server management aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# Docker aliases
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dex='docker exec -it'
alias dlog='docker logs -f'
alias dstop='docker stop $(docker ps -q)'
alias drm='docker rm $(docker ps -aq)'
alias drmi='docker rmi $(docker images -q)'

# System monitoring
alias ports='netstat -tulanp'
alias meminfo='free -m -l -t'
alias psmem='ps auxf | sort -nr -k 4'
alias pscpu='ps auxf | sort -nr -k 3'
alias cpuinfo='lscpu'
alias diskusage='df -H'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline'
EOF
    
    log "✅ Aliases configured"
}

# Setup automatic updates (security only)
setup_auto_updates() {
    log "🔄 Configuring automatic security updates..."
    
    apt install -y unattended-upgrades
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    systemctl enable --now unattended-upgrades
    log "✅ Automatic security updates configured"
}

# Final system optimization
optimize_system() {
    log "⚡ Optimizing system performance..."
    
    # Optimize swappiness for server workload
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    
    # Increase file descriptor limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
root soft nofile 65536
root hard nofile 65536
EOF
    
    # Apply sysctl changes
    sysctl -p
    
    log "✅ System optimized"
}

# Main execution function
main() {
    log "🚀 Starting Ubuntu Server Headless Setup..."
    
    check_root
    update_system
    install_essentials
    configure_firewall
    secure_ssh
    setup_fail2ban
    setup_logging
    install_docker
    configure_docker
    setup_dev_tools
    setup_aliases
    setup_auto_updates
    optimize_system
    
    log "✅ Ubuntu Server setup completed successfully!"
    log "📋 Setup log saved to: $LOG_FILE"
    
    info "🔄 Please reboot the system to ensure all changes take effect"
    info "🐋 After reboot, verify Docker: docker --version && docker-compose --version"
    info "🔒 SSH is now secured - ensure you have SSH keys configured"
    info "📊 Monitor system: htop, docker stats, vnstat -l"
}

# Run main function
main "$@"
