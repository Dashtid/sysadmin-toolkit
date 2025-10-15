#Requires -RunAsAdministrator

# Complete SSH Server Setup for Windows Desktop
# Installs OpenSSH Server, configures firewall, and sets up key authentication

# REPLACE WITH YOUR PUBLIC KEY
$PUBLIC_KEY = "ssh-ed25519 AAAAC3Nza... YOUR_PUBLIC_KEY_HERE"

# To get your public key:
# On your client machine: cat ~/.ssh/id_ed25519.pub
# Or: type %USERPROFILE%\.ssh\id_ed25519.pub (Windows)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SSH Server Setup - Windows Desktop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check/Install OpenSSH Server
Write-Host "[1/5] Checking OpenSSH Server..." -ForegroundColor Blue

$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue

if (!$sshService) {
    Write-Host "[*] Installing OpenSSH Server..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Write-Host "[+] OpenSSH Server installed" -ForegroundColor Green
} else {
    Write-Host "[+] OpenSSH Server already installed" -ForegroundColor Green
}

# Step 2: Start and enable SSH service
Write-Host ""
Write-Host "[2/5] Configuring SSH service..." -ForegroundColor Blue

Start-Service sshd -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType 'Automatic'

$sshStatus = Get-Service -Name sshd
if ($sshStatus.Status -eq 'Running') {
    Write-Host "[+] SSH service is running" -ForegroundColor Green
    Write-Host "[+] SSH service set to start automatically" -ForegroundColor Green
} else {
    Write-Host "[-] Failed to start SSH service" -ForegroundColor Red
    exit 1
}

# Step 3: Configure firewall
Write-Host ""
Write-Host "[3/5] Configuring Windows Firewall..." -ForegroundColor Blue

$firewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue

if (!$firewallRule) {
    Write-Host "[*] Creating firewall rule..." -ForegroundColor Yellow
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
        -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -Action Allow `
        -LocalPort 22 | Out-Null
    Write-Host "[+] Firewall rule created" -ForegroundColor Green
} else {
    Write-Host "[+] Firewall rule already exists" -ForegroundColor Green
}

# Step 4: Setup SSH key authentication
Write-Host ""
Write-Host "[4/5] Setting up SSH key authentication..." -ForegroundColor Blue

$sshDir = "$env:USERPROFILE\.ssh"
$authorizedKeysPath = "$sshDir\authorized_keys"

# Create .ssh directory if needed
if (!(Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}

# Check if key already exists
$keyExists = $false
if (Test-Path $authorizedKeysPath) {
    $existingKeys = Get-Content $authorizedKeysPath
    if ($existingKeys -contains $PUBLIC_KEY) {
        $keyExists = $true
    }
}

if (!$keyExists) {
    # Add public key
    Add-Content -Path $authorizedKeysPath -Value $PUBLIC_KEY

    # Set correct permissions
    icacls $authorizedKeysPath /inheritance:r | Out-Null
    icacls $authorizedKeysPath /grant:r "$env:USERNAME`:F" | Out-Null
    icacls $authorizedKeysPath /grant:r "SYSTEM:F" | Out-Null

    Write-Host "[+] SSH public key added and permissions configured" -ForegroundColor Green
} else {
    Write-Host "[+] SSH public key already configured" -ForegroundColor Green
}

# Step 5: Get connection info
Write-Host ""
Write-Host "[5/5] Getting connection information..." -ForegroundColor Blue

$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.InterfaceAlias -notlike "*VirtualBox*"} |
    Select-Object -First 1

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  SSH Server Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[i] Connection Information:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Username:   $env:USERNAME" -ForegroundColor White
Write-Host "    IP Address: $($ipAddresses.IPAddress)" -ForegroundColor White
Write-Host "    Port:       22" -ForegroundColor White
Write-Host ""
Write-Host "[i] Connect from your work laptop:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    ssh $env:USERNAME@$($ipAddresses.IPAddress)" -ForegroundColor Yellow
Write-Host ""
Write-Host "[i] Or add to ~/.ssh/config on work laptop:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Host home-desktop" -ForegroundColor White
Write-Host "        HostName $($ipAddresses.IPAddress)" -ForegroundColor White
Write-Host "        User $env:USERNAME" -ForegroundColor White
Write-Host "        Port 22" -ForegroundColor White
Write-Host ""
Write-Host "    Then connect with: ssh home-desktop" -ForegroundColor Yellow
Write-Host ""
Write-Host "[i] Service Status:" -ForegroundColor Cyan
Get-Service sshd | Format-Table -AutoSize
Write-Host ""
Write-Host "[v] Setup complete - SSH server ready for connections!" -ForegroundColor Green
Write-Host ""
