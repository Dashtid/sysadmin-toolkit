# SSH Agent Access Setup Script for Claude Code & Git Bash
# This script sets up seamless SSH access without passphrase prompts
# Works by using Windows SSH client which can access Windows SSH agent
# Tested and verified working on Windows 11 with Git Bash
# Author: David Dashti
# GitHub: https://github.com/dashtid
# Date: October 2025
#
# IMPORTANT: You must provide your server details when running this script!
# Example: .\setup-ssh-agent-access.ps1 -ServerIP "192.0.2.10" -ServerUser "myuser"

param(
    [Parameter(Mandatory=$false, HelpMessage="IP address or hostname of your SSH server")]
    [string]$ServerIP = "",

    [Parameter(Mandatory=$false, HelpMessage="Username for SSH connection")]
    [string]$ServerUser = $env:USERNAME,

    [Parameter(Mandatory=$false, HelpMessage="Path to your SSH private key")]
    [string]$SSHKeyPath = "$env:USERPROFILE\.ssh\id_ed25519"
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  SSH Agent Access Setup for Claude Code" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Validate inputs
if ([string]::IsNullOrWhiteSpace($ServerIP)) {
    Write-Host "[!] WARNING: No ServerIP provided. Git Bash shortcuts will not be configured." -ForegroundColor Yellow
    Write-Host "    To configure server shortcuts later, run with: -ServerIP <your-server-ip> -ServerUser <your-username>" -ForegroundColor Gray
    Write-Host ""
}

# Check if running as administrator (not required but good to check)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.SecurityRole]::Administrator)

if ($isAdmin) {
    Write-Host "✓ Running with administrator privileges" -ForegroundColor Green
} else {
    Write-Host "ℹ Running as regular user (this is fine)" -ForegroundColor Yellow
}

# Step 1: Check and configure SSH Agent service
Write-Host "`n[1/8] Configuring SSH Agent Service..." -ForegroundColor Yellow
$sshAgent = Get-Service ssh-agent -ErrorAction SilentlyContinue

if ($sshAgent) {
    if ($sshAgent.StartType -ne 'Automatic') {
        if ($isAdmin) {
            Set-Service ssh-agent -StartupType Automatic
            Write-Host "  ✓ SSH Agent set to automatic startup" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Run as admin to set SSH Agent to automatic startup" -ForegroundColor Yellow
            Write-Host "    Manual command: Set-Service ssh-agent -StartupType Automatic" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  ✓ SSH Agent already set to automatic startup" -ForegroundColor Green
    }

    if ($sshAgent.Status -ne 'Running') {
        Start-Service ssh-agent
        Write-Host "  ✓ SSH Agent service started" -ForegroundColor Green
    } else {
        Write-Host "  ✓ SSH Agent service already running" -ForegroundColor Green
    }
} else {
    Write-Host "  ✗ SSH Agent service not found. Please install OpenSSH Client." -ForegroundColor Red
    Write-Host "    Go to: Settings > Apps > Optional Features > Add Feature > OpenSSH Client" -ForegroundColor DarkGray
    exit 1
}

# Step 2: Set SSH_AUTH_SOCK environment variable
Write-Host "`n[2/8] Setting SSH_AUTH_SOCK environment variable..." -ForegroundColor Yellow
[System.Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', '\\.\pipe\openssh-ssh-agent', 'User')
$env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'
Write-Host "  ✓ SSH_AUTH_SOCK environment variable set" -ForegroundColor Green

# Step 3: Create PowerShell profile for SSH_AUTH_SOCK
Write-Host "`n[3/8] Creating PowerShell profile..." -ForegroundColor Yellow
$profileDir = Split-Path $PROFILE -Parent
if (!(Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

$profileContent = @'
# SSH Agent configuration for Claude Code
$env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'

# Ensure SSH Agent is running
$sshAgent = Get-Service ssh-agent -ErrorAction SilentlyContinue
if ($sshAgent -and $sshAgent.Status -ne 'Running') {
    Start-Service ssh-agent 2>$null
}
'@

if (Test-Path $PROFILE) {
    $currentProfile = Get-Content $PROFILE -Raw
    if ($currentProfile -notmatch 'SSH_AUTH_SOCK') {
        Add-Content $PROFILE "`n$profileContent"
        Write-Host "  ✓ PowerShell profile updated" -ForegroundColor Green
    } else {
        Write-Host "  ✓ PowerShell profile already configured" -ForegroundColor Green
    }
} else {
    Set-Content $PROFILE $profileContent
    Write-Host "  ✓ PowerShell profile created" -ForegroundColor Green
}

# Step 4: Create SSH wrapper script
Write-Host "`n[4/8] Creating SSH wrapper script..." -ForegroundColor Yellow
$wrapperPath = "$env:USERPROFILE\ssh-wrapper.sh"
$wrapperContent = @"
#!/bin/bash
# SSH wrapper that uses Windows OpenSSH client
# This bypasses Git Bash's SSH and uses Windows SSH which can access the agent

# Get the target and command
TARGET="`$1"
shift
COMMAND="`$@"

# Use Windows SSH executable directly
if [ -n "`$COMMAND" ]; then
    /c/Windows/System32/OpenSSH/ssh.exe "`$TARGET" "`$COMMAND"
else
    /c/Windows/System32/OpenSSH/ssh.exe "`$TARGET"
fi
"@

$wrapperContent | Set-Content -Path $wrapperPath -NoNewline
Write-Host "  ✓ SSH wrapper created at: $wrapperPath" -ForegroundColor Green

# Step 5: Create .bashrc for Git Bash
Write-Host "`n[5/8] Creating Git Bash configuration..." -ForegroundColor Yellow
$bashrcPath = "$env:USERPROFILE\.bashrc"

# Base configuration without server-specific shortcuts
$bashrcContent = @'
# ============================================================================
# AUTOMATIC SSH CONFIGURATION - LOADS IN EVERY GIT BASH SESSION
# This ensures Claude Code ALWAYS has SSH access without prompts
# INDEPENDENT of any CLAUDE.md files or repository location
# ============================================================================

# PRIMARY METHOD: Direct wrapper path (ALWAYS use this first)
export SSH_WRAPPER="$HOME/ssh-wrapper.sh"

# Universal SSH function for any host
ssh_wrapped() {
    if [ -f "$SSH_WRAPPER" ]; then
        "$SSH_WRAPPER" "$@"
    else
        # Direct fallback to Windows SSH
        /c/Windows/System32/OpenSSH/ssh.exe "$@"
    fi
}

# Export functions for all subshells
export -f ssh_wrapped

# Environment variable for SSH method
export SSH_METHOD="$HOME/ssh-wrapper.sh"

# Silent verification on startup
[ ! -f "$SSH_WRAPPER" ] && echo "WARNING: SSH wrapper missing at $SSH_WRAPPER"
'@

# Add server-specific shortcuts if server info provided
if (-not [string]::IsNullOrWhiteSpace($ServerIP)) {
    $serverConfig = @"

# ============================================================================
# SERVER-SPECIFIC SHORTCUTS (configured during setup)
# ============================================================================

# Specific function for your server
ssh_server() {
    ssh_wrapped $ServerUser@$ServerIP "`$@"
}

# Export for all subshells
export -f ssh_server

# Environment variables
export SERVER_HOST="$ServerUser@$ServerIP"

# Aliases for convenience
alias server='ssh_server'
alias sshserver='ssh_server'
"@
    $bashrcContent += $serverConfig
}

$bashrcContent | Set-Content -Path $bashrcPath -NoNewline
Write-Host "  ✓ Git Bash configuration created" -ForegroundColor Green

# Step 6: Create .bash_profile if it doesn't exist
Write-Host "`n[6/8] Creating .bash_profile..." -ForegroundColor Yellow
$bashProfilePath = "$env:USERPROFILE\.bash_profile"
if (!(Test-Path $bashProfilePath)) {
    $bashProfileContent = @'
# Load .bashrc if it exists
test -f ~/.bashrc && . ~/.bashrc
'@
    $bashProfileContent | Set-Content -Path $bashProfilePath -NoNewline
    Write-Host "  ✓ .bash_profile created" -ForegroundColor Green
} else {
    Write-Host "  ✓ .bash_profile already exists" -ForegroundColor Green
}

# Step 7: Create SSH key loader script
Write-Host "`n[7/8] Creating SSH key loader script..." -ForegroundColor Yellow
$keyLoaderDir = "$env:USERPROFILE\Documents\SSH-Setup"
if (!(Test-Path $keyLoaderDir)) {
    New-Item -ItemType Directory -Path $keyLoaderDir -Force | Out-Null
}

$keyLoaderPath = "$keyLoaderDir\load-ssh-key.ps1"
$keyLoaderContent = @"
# Load SSH key into agent
param(
    [string]`$KeyPath = "$SSHKeyPath"
)

Write-Host "Loading SSH key into agent..." -ForegroundColor Yellow

# Ensure SSH agent is running
`$agent = Get-Service ssh-agent -ErrorAction SilentlyContinue
if (`$agent -and `$agent.Status -ne 'Running') {
    Start-Service ssh-agent
}

# Add the key
if (Test-Path `$KeyPath) {
    ssh-add `$KeyPath
    Write-Host "SSH key loaded successfully!" -ForegroundColor Green
} else {
    Write-Host "SSH key not found at: `$KeyPath" -ForegroundColor Red
}
"@

$keyLoaderContent | Set-Content -Path $keyLoaderPath
Write-Host "  ✓ SSH key loader script created" -ForegroundColor Green

# Step 8: Create scheduled task for automatic key loading (optional)
Write-Host "`n[8/8] Setting up automatic key loading at startup..." -ForegroundColor Yellow
$taskName = "Load SSH Keys at Startup"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (!$existingTask) {
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -File `"$keyLoaderPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited | Out-Null
        Write-Host "  ✓ Scheduled task created for automatic key loading" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Could not create scheduled task (requires elevation)" -ForegroundColor Yellow
        Write-Host "    You can manually run: $keyLoaderPath" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  ✓ Scheduled task already exists" -ForegroundColor Green
}

# Final summary
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Close and reopen any PowerShell/Git Bash windows" -ForegroundColor White
Write-Host "2. Load your SSH key: ssh-add $SSHKeyPath" -ForegroundColor White

if (-not [string]::IsNullOrWhiteSpace($ServerIP)) {
    Write-Host "3. Test SSH access:" -ForegroundColor White
    Write-Host "   From Git Bash: ssh_server 'hostname'" -ForegroundColor DarkGray
    Write-Host "   From PowerShell: ssh $ServerUser@$ServerIP hostname" -ForegroundColor DarkGray
} else {
    Write-Host "3. Configure your server by running this script again with -ServerIP and -ServerUser" -ForegroundColor White
    Write-Host "   Example: .\setup-ssh-agent-access.ps1 -ServerIP '192.0.2.10' -ServerUser 'myuser'" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "SSH wrapper location: $env:USERPROFILE\ssh-wrapper.sh" -ForegroundColor Cyan
Write-Host "Key loader script: $keyLoaderPath" -ForegroundColor Cyan
Write-Host ""

# Ask if user wants to load SSH key now
$response = Read-Host "Do you want to load your SSH key now? (Y/N)"
if ($response -eq 'Y' -or $response -eq 'y') {
    if (Test-Path $SSHKeyPath) {
        Write-Host "`nYou'll be prompted for your passphrase:" -ForegroundColor Yellow
        ssh-add $SSHKeyPath

        # Test the connection only if server info provided
        if (-not [string]::IsNullOrWhiteSpace($ServerIP)) {
            Write-Host "`nTesting SSH connection..." -ForegroundColor Yellow
            $testResult = & ssh -o ConnectTimeout=5 -o PasswordAuthentication=no "$ServerUser@$ServerIP" "echo 'Connection successful'; hostname" 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] SSH connection successful!" -ForegroundColor Green
                Write-Host $testResult -ForegroundColor DarkGreen
            } else {
                Write-Host "[-] SSH connection failed. Please verify:" -ForegroundColor Red
                Write-Host "  - Public key is on server in ~/.ssh/authorized_keys" -ForegroundColor Yellow
                Write-Host "  - Server IP is correct: $ServerIP" -ForegroundColor Yellow
                Write-Host "  - Username is correct: $ServerUser" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "SSH key not found at: $SSHKeyPath" -ForegroundColor Red
    }
}

Write-Host "`nSetup script completed!" -ForegroundColor Green