# System Administration & Development Scripts

A comprehensive collection of system administration and setup scripts for both Linux (Ubuntu) and Windows 11 environments. This repository is designed for developers and system administrators who need to quickly set up and maintain development environments across multiple platforms.

## 🎯 Target Environments

- **Windows 11 Work Laptop**: Development workstation with corporate-friendly tools
- **Ubuntu Server**: Headless lab environment with Docker for development and testing
- **Ubuntu Desktop**: Home coding station with full GUI development environment

## 📁 Repository Structure

```
Scripts/
├── Linux/
│   ├── server/                    # Ubuntu Server (Headless)
│   │   ├── headless-server-setup.sh
│   │   ├── docker-lab-environment.sh
│   │   └── ubuntu-server-maintenance.sh
│   ├── desktop/                   # Ubuntu Desktop (GUI)
│   │   └── fresh-desktop-setup.sh
│   ├── maintenance/               # System maintenance (ready for expansion)
│   ├── development/               # Development tools (ready for expansion)
│   └── utilities/                 # System utilities (ready for expansion)
├── Windows/
│   ├── first-time-setup/          # Initial system setup
│   │   └── work-laptop-setup.ps1
│   ├── maintenance/               # System maintenance
│   │   └── startup_script.ps1
│   ├── development/               # Development tools
│   │   └── remote-development-setup.ps1
│   ├── utilities/                 # System utilities
│   │   └── schedule_task.ps1
│   └── package-lists/             # Package definitions
│       ├── chocolatey-packages.txt
│       └── winget-packages.txt
└── logs/                          # Script execution logs
```

## 🚀 Quick Start

### Ubuntu Server (Headless Lab Environment)

```bash
# Initial server setup with Docker lab environment
sudo bash Linux/server/headless-server-setup.sh

# Setup comprehensive Docker development environment
bash Linux/server/docker-lab-environment.sh

# Regular maintenance
sudo bash Linux/server/ubuntu-server-maintenance.sh
```

### Ubuntu Desktop (Home Coding Station)

```bash
# Fresh desktop installation setup
bash Linux/desktop/fresh-desktop-setup.sh

# Additional coding station configuration (script ready for creation)
# bash Linux/desktop/coding-station-setup.sh
```

### Windows 11 (Work Laptop)

```powershell
# Run as Administrator in PowerShell 7+
# Comprehensive work laptop setup
.\Windows\first-time-setup\work-laptop-setup.ps1

# Regular maintenance (can be scheduled)
.\Windows\maintenance\startup_script.ps1
```

## 🔧 Key Features

### Cross-Platform Development Support

- **Consistent tooling** across Ubuntu and Windows environments
- **Remote development** setup for SSH access to Ubuntu server
- **Container-based** development with Docker
- **Multi-language** support (Python, Node.js, Go, Rust, etc.)

### Automated Environment Setup

- **First-time installation** scripts for fresh systems
- **Development environment** configuration
- **Security hardening** and best practices
- **Package management** via apt, Chocolatey, and Winget

### Maintenance & Monitoring

- **Automated updates** and system maintenance
- **Docker container** management and cleanup
- **System monitoring** and health checks
- **Backup solutions** and data protection

### Remote Development Workflow

- **SSH key management** across all systems
- **VS Code Remote Development** configuration
- **Port forwarding** for accessing services
- **Synchronized development** environments

## 📋 Prerequisites

### Ubuntu Systems

- Ubuntu 20.04 LTS or newer
- Sudo access for system modifications
- Internet connection for package downloads

### Windows 11 Systems

- Windows 11 with latest updates
- PowerShell 7+ installed
- Administrator privileges
- Internet connection for package downloads

## 🛠️ Script Categories

### First-Time Setup Scripts

Perfect for new system installations or major environment changes:

- Install essential development tools
- Configure security settings
- Set up development directories
- Install and configure package managers

### Maintenance Scripts

Regular system upkeep and optimization:

- System updates and cleanup
- Docker container management
- Log rotation and monitoring
- Performance optimization

### Development Scripts

Tools for setting up and managing development environments:

- Programming language installations
- IDE and editor configuration
- Version control setup
- Remote development tools

### Utility Scripts

Helper scripts for common administrative tasks:

- Network diagnostics
- System information gathering
- User and permission management
- Backup and restore operations

## 🔒 Security Features

- **SSH hardening** with key-based authentication
- **Firewall configuration** with development-friendly rules
- **Fail2ban setup** for intrusion prevention
- **Automatic security updates** configuration
- **No hardcoded credentials** - all scripts prompt for sensitive information

## 📊 Logging & Monitoring

All scripts include comprehensive logging:

- **Timestamped logs** for all operations
- **Color-coded output** for easy reading
- **Error handling** with rollback capabilities
- **Progress tracking** for long-running operations

## 🌐 Multi-Environment Workflow

This repository is designed for a specific multi-environment development workflow:

1. **Windows 11 Laptop**: Primary development machine with VS Code, remote SSH capabilities
2. **Ubuntu Server**: Headless lab environment running Docker containers for testing
3. **Ubuntu Desktop**: Home coding station with full GUI development environment

Scripts are optimized for this workflow, including:

- Remote development setup from Windows to Ubuntu server
- Consistent development environments across all platforms
- Easy synchronization of configurations and projects

## 📖 Usage Examples

### Setting up a new Ubuntu server for development:

```bash
# Run the comprehensive server setup
sudo bash Linux/server/headless-server-setup.sh

# Setup Docker lab environment
bash Linux/server/docker-lab-environment.sh

# Access the lab environment
lab-start  # Starts all development containers
```

### Configuring Windows 11 for remote development:

```powershell
# Install development tools and configure remote access
.\Windows\first-time-setup\work-laptop-setup.ps1

# Setup remote development tools
.\Windows\development\remote-development-setup.ps1
```

### Regular maintenance across all systems:

```bash
# Ubuntu systems
sudo bash Linux/maintenance/system-updates.sh

# Windows systems (as Administrator)
.\Windows\maintenance\startup_script.ps1
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-script`)
3. Follow the existing script structure and conventions
4. Test scripts in appropriate environments
5. Commit changes (`git commit -am 'Add new script'`)
6. Push to branch (`git push origin feature/new-script`)
7. Create a Pull Request

## 📝 Script Conventions

- **Bash scripts**: Use `#!/usr/bin/env bash` shebang
- **PowerShell scripts**: Require PowerShell 7+ and appropriate execution policy
- **Error handling**: Include proper error checking and rollback capabilities
- **Logging**: Use consistent logging format with timestamps
- **Documentation**: Include clear comments and usage instructions
- **Security**: Never hardcode credentials or sensitive information

## ⚠️ Important Notes

- **Test scripts** in non-production environments first
- **Review scripts** before execution to understand what they do
- **Backup important data** before running system modification scripts
- **Check prerequisites** before running any script
- **Run with appropriate privileges** (sudo for Linux, Administrator for Windows)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built for multi-environment development workflows
- Optimized for Ubuntu and Windows 11 compatibility
- Designed with security and best practices in mind
- Inspired by the need for consistent development environments

---

**Maintained by David Dashti**  
_For questions, suggestions, or issues, please open a GitHub issue or contact me directly._
