#!/usr/bin/env bash
# Ubuntu Desktop Fresh Installation Setup Script
# Sets up a new Ubuntu desktop for development and daily use
# Run as regular user (will prompt for sudo when needed)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging setup
LOG_DIR="$HOME/.setup-logs"
LOG_FILE="$LOG_DIR/desktop-setup-$(date +%Y%m%d-%H%M%S).log"
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

# Check if running as root (should not be)
check_user() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should NOT be run as root. Run as regular user."
        exit 1
    fi
    log "[+] Running as regular user: $USER"
}

# Update system packages
update_system() {
    log "[*] Updating system packages..."
    sudo apt update && sudo apt -y upgrade
    sudo apt -y autoremove --purge
    sudo apt -y autoclean
    log "[+] System updated"
}

# Install essential packages
install_essentials() {
    log "[*] Installing essential packages..."
    
    sudo apt install -y \
        curl \
        wget \
        git \
        vim \
        nano \
        htop \
        tree \
        unzip \
        zip \
        p7zip-full \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        libffi-dev \
        python3 \
        python3-pip \
        python3-venv \
        nodejs \
        npm \
        default-jdk \
        snapd \
        flatpak \
        gnome-software-plugin-flatpak
    
    log "[+] Essential packages installed"
}

# Install multimedia codecs and drivers
install_multimedia() {
    log "[*] Installing multimedia codecs and drivers..."
    
    # Enable partner repository for additional codecs
    sudo add-apt-repository -y "deb http://archive.canonical.com/ubuntu $(lsb_release -sc) partner"
    sudo apt update
    
    # Install multimedia codecs
    sudo apt install -y ubuntu-restricted-extras
    
    # Install additional media tools
    sudo apt install -y \
        vlc \
        gimp \
        audacity \
        ffmpeg \
        imagemagick \
        gstreamer1.0-plugins-bad \
        gstreamer1.0-plugins-ugly \
        gstreamer1.0-libav
    
    log "[+] Multimedia support installed"
}

# Setup Flatpak
setup_flatpak() {
    log "[*] Setting up Flatpak..."
    
    # Add Flathub repository
    sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
    
    log "[+] Flatpak configured with Flathub"
}

# Install development tools
install_dev_tools() {
    log "[*] Installing development tools..."
    
    # Install Visual Studio Code
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
    sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
    sudo apt update
    sudo apt install -y code
    
    # Install additional development tools
    sudo apt install -y \
        git-gui \
        gitk \
        meld \
        terminator \
        tilix \
        zsh \
        fish \
        tmux \
        screen \
        neofetch \
        bat \
        fd-find \
        ripgrep \
        jq \
        httpie \
        postman
    
    # Install modern alternatives
    if ! command -v exa &> /dev/null; then
        wget -qO exa.zip https://github.com/ogham/exa/releases/latest/download/exa-linux-x86_64-musl-v0.10.1.zip
        unzip exa.zip
        sudo mv bin/exa /usr/local/bin/
        rm -rf bin exa.zip
    fi
    
    log "[+] Development tools installed"
}

# Install Docker Desktop
install_docker() {
    log "[*] Installing Docker Desktop..."
    
    # Remove old versions
    sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Add user to docker group
    sudo usermod -aG docker "$USER"
    
    # Install Docker Compose (standalone)
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    
    # Download Docker Desktop (user will need to install manually)
    wget -O ~/Downloads/docker-desktop.deb "https://desktop.docker.com/linux/main/amd64/docker-desktop-4.25.0-amd64.deb"
    
    log "[+] Docker Engine installed, Docker Desktop downloaded to ~/Downloads/"
    warning "Install Docker Desktop manually: sudo dpkg -i ~/Downloads/docker-desktop.deb"
}

# Install browsers
install_browsers() {
    log "[*] Installing web browsers..."
    
    # Install Firefox (usually pre-installed)
    sudo apt install -y firefox
    
    # Install Google Chrome
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
    sudo apt update
    sudo apt install -y google-chrome-stable
    
    # Install Brave Browser
    curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
    sudo apt update
    sudo apt install -y brave-browser
    
    log "[+] Web browsers installed"
}

# Install communication tools
install_communication() {
    log "[*] Installing communication tools..."
    
    # Install via Snap
    sudo snap install discord
    sudo snap install slack --classic
    sudo snap install teams-for-linux
    sudo snap install zoom-client
    
    # Install Thunderbird email client
    sudo apt install -y thunderbird
    
    log "[+] Communication tools installed"
}

# Install productivity tools
install_productivity() {
    log "[*] Installing productivity tools..."
    
    # Install LibreOffice (usually pre-installed)
    sudo apt install -y libreoffice
    
    # Install additional productivity tools
    sudo apt install -y \
        gnome-tweaks \
        dconf-editor \
        synaptic \
        gparted \
        bleachbit \
        timeshift \
        remmina \
        filezilla \
        transmission-gtk
    
    # Install via Snap
    sudo snap install notion-snap
    sudo snap install obsidian --classic
    
    log "[+] Productivity tools installed"
}

# Setup programming languages
setup_programming_languages() {
    log "[*] Setting up programming languages..."
    
    # Python setup
    python3 -m pip install --user --upgrade pip
    python3 -m pip install --user virtualenv pipenv poetry
    
    # Node.js setup (install latest LTS via NodeSource)
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    # Install global npm packages
    sudo npm install -g yarn pnpm typescript ts-node nodemon create-react-app @vue/cli @angular/cli
    
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    # Install Go
    GO_VERSION="1.21.4"
    wget "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    log "[+] Programming languages configured"
}

# Configure Git
configure_git() {
    log "[*] Configuring Git..."
    
    # Check if Git is already configured
    if ! git config --global user.name &>/dev/null; then
        read -p "Enter your Git username: " git_username
        read -p "Enter your Git email: " git_email
        
        git config --global user.name "$git_username"
        git config --global user.email "$git_email"
        git config --global init.defaultBranch main
        git config --global pull.rebase false
        git config --global core.editor "code --wait"
        
        log "[+] Git configured for $git_username"
    else
        log "[+] Git already configured"
    fi
}

# Setup shell improvements
setup_shell() {
    log "[*] Setting up shell improvements..."
    
    # Install Oh My Zsh
    if [ ! -d "$HOME/.oh-my-zsh" ]; then
        sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
        
        # Install popular plugins
        git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
        git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
        
        # Update .zshrc with plugins
        sed -i 's/plugins=(git)/plugins=(git zsh-autosuggestions zsh-syntax-highlighting docker docker-compose npm node python)/' ~/.zshrc
    fi
    
    # Create useful aliases
    cat >> ~/.bashrc << 'EOF'

# Custom aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias bat='batcat'
alias fd='fdfind'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline'
alias gd='git diff'

# Docker aliases
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dex='docker exec -it'
alias dlog='docker logs -f'

# System aliases
alias update='sudo apt update && sudo apt upgrade'
alias install='sudo apt install'
alias search='apt search'
alias ports='netstat -tulanp'
alias meminfo='free -m -l -t'
alias diskusage='df -H'
EOF
    
    log "[+] Shell improvements configured"
}

# Configure firewall
configure_firewall() {
    log "[*] Configuring firewall..."
    
    sudo ufw enable
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow common development ports
    sudo ufw allow 3000/tcp  # React/Node dev server
    sudo ufw allow 8000/tcp  # Python dev server
    sudo ufw allow 8080/tcp  # Alternative HTTP
    sudo ufw allow 5000/tcp  # Flask default
    
    log "[+] Firewall configured"
}

# Setup development directories
setup_dev_directories() {
    log "[*] Setting up development directories..."
    
    mkdir -p ~/Development/{Projects,Learning,Tools,Scripts}
    mkdir -p ~/Development/Projects/{Web,Mobile,Desktop,Scripts}
    mkdir -p ~/Development/Learning/{Tutorials,Courses,Books}
    
    # Create a projects template
    cat > ~/Development/README.md << 'EOF'
# Development Directory Structure

## Projects/
- **Web/**: Web development projects
- **Mobile/**: Mobile app projects  
- **Desktop/**: Desktop application projects
- **Scripts/**: Utility scripts and automation

## Learning/
- **Tutorials/**: Tutorial projects and exercises
- **Courses/**: Course materials and projects
- **Books/**: Book examples and exercises

## Tools/
- Development tools and utilities

## Scripts/
- Personal automation scripts
EOF
    
    log "[+] Development directories created"
}

# Install VS Code extensions
install_vscode_extensions() {
    log "[*] Installing VS Code extensions..."
    
    # Wait for VS Code to be available
    sleep 2
    
    # Essential extensions
    code --install-extension ms-python.python
    code --install-extension ms-vscode.vscode-typescript-next
    code --install-extension bradlc.vscode-tailwindcss
    code --install-extension esbenp.prettier-vscode
    code --install-extension ms-vscode.vscode-eslint
    code --install-extension ms-vscode-remote.remote-ssh
    code --install-extension ms-vscode-remote.remote-containers
    code --install-extension ms-vscode.remote-explorer
    code --install-extension ms-vscode.vscode-docker
    code --install-extension GitLens.gitlens
    code --install-extension ms-vscode.vscode-git-graph
    code --install-extension formulahendry.auto-rename-tag
    code --install-extension ms-vscode.vscode-live-server
    code --install-extension ms-vscode.vscode-thunder-client
    code --install-extension ms-vscode.vscode-markdown-preview-enhanced
    
    log "[+] VS Code extensions installed"
}

# Final system optimization
optimize_system() {
    log "[*] Optimizing system..."
    
    # Enable firewall
    sudo systemctl enable ufw
    
    # Optimize swappiness for desktop use
    echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
    
    # Increase inotify limits for development
    echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf
    
    # Apply changes
    sudo sysctl -p
    
    log "[+] System optimized"
}

# Create desktop shortcuts
create_shortcuts() {
    log "[*] Creating desktop shortcuts..."
    
    # Create desktop directory if it doesn't exist
    mkdir -p ~/Desktop
    
    # VS Code shortcut
    cat > ~/Desktop/VSCode.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Visual Studio Code
Comment=Code Editing. Redefined.
Exec=/usr/bin/code
Icon=code
Terminal=false
Categories=Development;IDE;
EOF
    chmod +x ~/Desktop/VSCode.desktop
    
    # Terminal shortcut
    cat > ~/Desktop/Terminal.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal
Comment=Use the command line
Exec=gnome-terminal
Icon=terminal
Terminal=false
Categories=System;TerminalEmulator;
EOF
    chmod +x ~/Desktop/Terminal.desktop
    
    log "[+] Desktop shortcuts created"
}

# Main execution function
main() {
    log "[*] Starting Ubuntu Desktop Fresh Setup..."
    
    check_user
    update_system
    install_essentials
    install_multimedia
    setup_flatpak
    install_dev_tools
    install_docker
    install_browsers
    install_communication
    install_productivity
    setup_programming_languages
    configure_git
    setup_shell
    configure_firewall
    setup_dev_directories
    install_vscode_extensions
    optimize_system
    create_shortcuts
    
    log "[+] Ubuntu Desktop setup completed successfully!"
    log "[i] Setup log saved to: $LOG_FILE"
    
    info "[*] Please reboot the system to ensure all changes take effect"
    info "[*] After reboot, install Docker Desktop: sudo dpkg -i ~/Downloads/docker-desktop.deb"
    info "[*] Switch to Zsh: chsh -s $(which zsh)"
    info "[*] Setup SSH keys for Git: ssh-keygen -t ed25519 -C 'your_email@example.com'"
    info "[*] Development directory: ~/Development/"
    info "[*] VS Code is ready with essential extensions"
    
    warning "You may need to log out and back in for all group memberships to take effect"
}

# Run main function
main "$@"


