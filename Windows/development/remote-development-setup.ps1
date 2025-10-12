# Remote Development Setup Script for Windows 11
# Configures tools for remote development with Ubuntu servers
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [switch]$SkipSSH,
    [switch]$SkipVSCode,
    [switch]$SkipPortForwarding
)

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
}

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color $Colors.Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color $Colors.Blue }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color $Colors.Red }

# Setup SSH client and keys
function Setup-SSHClient {
    if ($SkipSSH) {
        Write-Info "Skipping SSH setup"
        return
    }

    Write-Info "Setting up SSH client for remote development..."
    
    # Enable OpenSSH Client (should be available on Windows 11)
    $sshClient = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'
    if ($sshClient.State -ne "Installed") {
        Write-Info "Installing OpenSSH Client..."
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    }
    
    # Create SSH directory if it doesn't exist
    $sshDir = "$env:USERPROFILE\.ssh"
    if (!(Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
        # Set proper permissions
        icacls $sshDir /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
    }
    
    # Check if SSH key exists
    $sshKeyPath = "$sshDir\id_ed25519"
    if (!(Test-Path $sshKeyPath)) {
        Write-Info "SSH key not found. Generating new ED25519 key..."
        $email = Read-Host "Enter your email for SSH key"
        ssh-keygen -t ed25519 -C $email -f $sshKeyPath -N `"`"
        Write-Success "SSH key generated at: $sshKeyPath"
        Write-Info "Public key content:"
        Get-Content "$sshKeyPath.pub"
        Write-Warning "Copy the public key above to your Ubuntu server's ~/.ssh/authorized_keys"
    }
    else {
        Write-Success "SSH key already exists at: $sshKeyPath"
    }
    
    # Start SSH agent and add key
    Start-Service ssh-agent
    Set-Service ssh-agent -StartupType Automatic
    ssh-add $sshKeyPath
    
    Write-Success "SSH client configured"
}

# Setup VS Code for remote development
function Setup-VSCodeRemote {
    if ($SkipVSCode) {
        Write-Info "Skipping VS Code remote setup"
        return
    }

    Write-Info "Setting up VS Code for remote development..."
    
    # Check if VS Code is installed
    if (!(Get-Command code -ErrorAction SilentlyContinue)) {
        Write-Warning "VS Code not found. Installing via Winget..."
        winget install --id Microsoft.VisualStudioCode --silent
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }
    
    # Install essential remote development extensions
    $RemoteExtensions = @(
        'ms-vscode-remote.remote-ssh',
        'ms-vscode-remote.remote-ssh-edit',
        'ms-vscode-remote.remote-containers',
        'ms-vscode-remote.vscode-remote-extensionpack',
        'ms-vscode.remote-explorer',
        'ms-vscode.remote-server'
    )
    
    foreach ($Extension in $RemoteExtensions) {
        try {
            Write-Info "Installing VS Code extension: $Extension"
            code --install-extension $Extension --force
            Write-Success "$Extension installed"
        }
        catch {
            Write-Warning "Failed to install $Extension"
        }
    }
    
    # Create VS Code SSH config template
    $sshConfigPath = "$env:USERPROFILE\.ssh\config"
    if (!(Test-Path $sshConfigPath)) {
        $sshConfigContent = @"
# SSH Config for Remote Development
# Add your server configurations here

# Example Ubuntu Server Configuration
# Host ubuntu-server
#     HostName your-server-ip-or-hostname
#     User your-username
#     Port 22
#     IdentityFile ~/.ssh/id_ed25519
#     ForwardAgent yes
#     ServerAliveInterval 60
#     ServerAliveCountMax 3

# Example Ubuntu Desktop Configuration
# Host ubuntu-desktop
#     HostName your-desktop-ip-or-hostname
#     User your-username
#     Port 22
#     IdentityFile ~/.ssh/id_ed25519
#     ForwardAgent yes
#     ServerAliveInterval 60
#     ServerAliveCountMax 3
"@
        Set-Content -Path $sshConfigPath -Value $sshConfigContent -Encoding UTF8
        Write-Success "SSH config template created at: $sshConfigPath"
        Write-Info "Edit the SSH config file to add your server details"
    }
    
    Write-Success "VS Code remote development configured"
}

# Setup port forwarding utilities
function Setup-PortForwarding {
    if ($SkipPortForwarding) {
        Write-Info "Skipping port forwarding setup"
        return
    }

    Write-Info "Setting up port forwarding utilities..."
    
    # Create port forwarding helper scripts
    $scriptsDir = "$env:USERPROFILE\Development\Scripts"
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
    
    # SSH tunnel script
    $tunnelScript = @'
# SSH Tunnel Helper Script
# Usage: .\ssh-tunnel.ps1 -Server "server-name" -LocalPort 3000 -RemotePort 3000

param(
    [Parameter(Mandatory=$true)]
    [string]$Server,
    
    [Parameter(Mandatory=$true)]
    [int]$LocalPort,
    
    [Parameter(Mandatory=$true)]
    [int]$RemotePort,
    
    [string]$RemoteHost = "localhost"
)

Write-Host "Creating SSH tunnel: localhost:$LocalPort -> $Server:$RemoteHost:$RemotePort" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the tunnel" -ForegroundColor Yellow

ssh -L ${LocalPort}:${RemoteHost}:${RemotePort} $Server -N
'@
    
    Set-Content -Path "$scriptsDir\ssh-tunnel.ps1" -Value $tunnelScript -Encoding UTF8
    
    # Multiple tunnels script
    $multiTunnelScript = @'
# Multiple SSH Tunnels Helper Script
# Usage: .\ssh-multi-tunnel.ps1 -Server "server-name"

param(
    [Parameter(Mandatory=$true)]
    [string]$Server
)

Write-Host "Creating multiple SSH tunnels to $Server" -ForegroundColor Green
Write-Host "Common development ports:" -ForegroundColor Yellow
Write-Host "  3000 -> React/Node.js dev server" -ForegroundColor Cyan
Write-Host "  8000 -> Python dev server" -ForegroundColor Cyan
Write-Host "  8080 -> Alternative HTTP" -ForegroundColor Cyan
Write-Host "  5432 -> PostgreSQL" -ForegroundColor Cyan
Write-Host "  3306 -> MySQL" -ForegroundColor Cyan
Write-Host "  6379 -> Redis" -ForegroundColor Cyan
Write-Host "  9000 -> Portainer" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all tunnels" -ForegroundColor Yellow

# Start multiple tunnels in background
$jobs = @()
$ports = @(3000, 8000, 8080, 5432, 3306, 6379, 9000)

foreach ($port in $ports) {
    $job = Start-Job -ScriptBlock {
        param($server, $port)
        ssh -L ${port}:localhost:${port} $server -N
    } -ArgumentList $Server, $port
    $jobs += $job
    Write-Host "Started tunnel for port $port (Job ID: $($job.Id))" -ForegroundColor Green
}

# Wait for user to stop
try {
    Write-Host "All tunnels started. Press Ctrl+C to stop..." -ForegroundColor Yellow
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "Stopping all tunnels..." -ForegroundColor Yellow
    $jobs | Stop-Job
    $jobs | Remove-Job
    Write-Host "All tunnels stopped." -ForegroundColor Green
}
'@
    
    Set-Content -Path "$scriptsDir\ssh-multi-tunnel.ps1" -Value $multiTunnelScript -Encoding UTF8
    
    Write-Success "Port forwarding utilities created in: $scriptsDir"
}

# Install additional remote development tools
function Install-RemoteDevTools {
    Write-Info "Installing additional remote development tools..."
    
    # Install useful tools via Chocolatey if available
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $tools = @(
            'putty',
            'winscp',
            'mremoteng',
            'terminus',
            'mobaxterm'
        )
        
        foreach ($tool in $tools) {
            try {
                Write-Info "Installing $tool..."
                choco install $tool -y --no-progress
                Write-Success "$tool installed"
            }
            catch {
                Write-Warning "Failed to install $tool"
            }
        }
    }
    
    # Install Windows Terminal if not present
    if (!(Get-Command wt -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Windows Terminal..."
        winget install --id Microsoft.WindowsTerminal --silent
    }
    
    Write-Success "Remote development tools installed"
}

# Configure Windows Terminal for remote development
function Configure-WindowsTerminal {
    Write-Info "Configuring Windows Terminal for remote development..."
    
    $terminalSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    
    if (Test-Path $terminalSettingsPath) {
        Write-Info "Windows Terminal settings found. Consider adding SSH profiles manually."
        Write-Info "Settings location: $terminalSettingsPath"
        
        # Create example SSH profile
        $exampleProfile = @"
Example SSH profile for Windows Terminal settings.json:

{
    "guid": "{new-guid-here}",
    "name": "Ubuntu Server",
    "commandline": "ssh ubuntu-server",
    "icon": "ms-appx:///ProfileIcons/{9acb9455-ca41-5af7-950f-6bca1bc9722f}.png",
    "colorScheme": "Ubuntu",
    "startingDirectory": "~"
}

Add this to the "profiles" -> "list" array in your Windows Terminal settings.
"@
        
        Write-Info $exampleProfile
    }
    else {
        Write-Warning "Windows Terminal settings not found. Install Windows Terminal first."
    }
    
    Write-Success "Windows Terminal configuration guidance provided"
}

# Create development workspace structure
function Setup-DevelopmentWorkspace {
    Write-Info "Setting up development workspace structure..."
    
    $workspaceDir = "$env:USERPROFILE\Development\Remote"
    $directories = @(
        "$workspaceDir\Projects",
        "$workspaceDir\Scripts",
        "$workspaceDir\Configs",
        "$workspaceDir\Logs"
    )
    
    foreach ($dir in $directories) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Create remote development guide
    $guideContent = @"
# Remote Development Workspace

This directory contains tools and configurations for remote development.

## Directory Structure

- **Projects/**: Local copies of remote projects
- **Scripts/**: Helper scripts for remote development
- **Configs/**: SSH configs and other configuration files
- **Logs/**: Connection logs and debugging information

## Quick Start

1. Configure SSH keys and server connections
2. Use VS Code Remote-SSH extension to connect to servers
3. Use port forwarding scripts for accessing remote services
4. Keep local copies of important projects in Projects/

## Useful Commands

```powershell
# Connect to server via SSH
ssh server-name

# Create SSH tunnel for web development
.\Scripts\ssh-tunnel.ps1 -Server "ubuntu-server" -LocalPort 3000 -RemotePort 3000

# Create multiple tunnels for development
.\Scripts\ssh-multi-tunnel.ps1 -Server "ubuntu-server"

# Open VS Code connected to remote server
code --remote ssh-remote+server-name /path/to/project
```

## Tips

- Use SSH config file (~/.ssh/config) to define server shortcuts
- Set up SSH key forwarding for Git operations on remote servers
- Use VS Code Remote-Containers for consistent development environments
- Keep sensitive data on remote servers, not local machine
"@
    
    Set-Content -Path "$workspaceDir\README.md" -Value $guideContent -Encoding UTF8
    
    Write-Success "Development workspace created at: $workspaceDir"
}

# Main execution function
function Main {
    Write-Log "[*] Starting Remote Development Setup..." -Color $Colors.Cyan

    Setup-SSHClient
    Setup-VSCodeRemote
    Setup-PortForwarding
    Install-RemoteDevTools
    Configure-WindowsTerminal
    Setup-DevelopmentWorkspace

    Write-Success "Remote development setup completed successfully!"

    Write-Info "[*] Next steps:"
    Write-Info "  1. Copy your SSH public key to remote servers"
    Write-Info "  2. Edit ~/.ssh/config to add your server configurations"
    Write-Info "  3. Test SSH connection: ssh server-name"
    Write-Info "  4. Open VS Code and use Remote-SSH extension"
    Write-Info "  5. Use port forwarding scripts for accessing remote services"

    Write-Info "[*] Development workspace: $env:USERPROFILE\Development\Remote"
    Write-Info "[*] SSH config: $env:USERPROFILE\.ssh\config"
    Write-Info "[*] Helper scripts: $env:USERPROFILE\Development\Scripts"
}

# Run main function
Main
