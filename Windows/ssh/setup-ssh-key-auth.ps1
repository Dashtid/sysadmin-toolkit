#Requires -RunAsAdministrator

# Setup SSH Key Authentication for Windows Desktop
# Adds your work laptop's public key to authorized_keys

# REPLACE WITH YOUR PUBLIC KEY
$PUBLIC_KEY = "ssh-ed25519 AAAAC3Nza... YOUR_PUBLIC_KEY_HERE"

# To get your public key:
# On your client machine: cat ~/.ssh/id_ed25519.pub
# Or: type %USERPROFILE%\.ssh\id_ed25519.pub (Windows)

Write-Host "[*] Setting up SSH key authentication..." -ForegroundColor Cyan
Write-Host ""

# Create .ssh directory if it doesn't exist
$sshDir = "$env:USERPROFILE\.ssh"
if (!(Test-Path $sshDir)) {
    Write-Host "[*] Creating .ssh directory..." -ForegroundColor Blue
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}

# Path to authorized_keys
$authorizedKeysPath = "$sshDir\authorized_keys"

# Check if key already exists
if (Test-Path $authorizedKeysPath) {
    $existingKeys = Get-Content $authorizedKeysPath
    if ($existingKeys -contains $PUBLIC_KEY) {
        Write-Host "[!] Public key already exists in authorized_keys" -ForegroundColor Yellow
        exit 0
    }
}

# Add public key to authorized_keys
Write-Host "[*] Adding public key to authorized_keys..." -ForegroundColor Blue
Add-Content -Path $authorizedKeysPath -Value $PUBLIC_KEY

# Set correct permissions (CRITICAL for SSH to work)
Write-Host "[*] Setting correct permissions..." -ForegroundColor Blue

# Remove inheritance
icacls $authorizedKeysPath /inheritance:r | Out-Null

# Grant full control to current user
icacls $authorizedKeysPath /grant:r "$env:USERNAME`:F" | Out-Null

# Grant full control to SYSTEM
icacls $authorizedKeysPath /grant:r "SYSTEM:F" | Out-Null

Write-Host ""
Write-Host "[+] SSH key authentication configured!" -ForegroundColor Green
Write-Host ""
Write-Host "[i] Authorized keys location:" -ForegroundColor Blue
Write-Host "    $authorizedKeysPath" -ForegroundColor White
Write-Host ""
Write-Host "[i] Current permissions:" -ForegroundColor Blue
icacls $authorizedKeysPath
Write-Host ""
Write-Host "[i] Your desktop IP address:" -ForegroundColor Blue
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object IPAddress, InterfaceAlias
Write-Host ""
Write-Host "[i] Test from work laptop:" -ForegroundColor Blue
Write-Host "    ssh $env:USERNAME@YOUR-IP-ADDRESS" -ForegroundColor Yellow
Write-Host ""
Write-Host "[!] Make sure OpenSSH Server is running:" -ForegroundColor Cyan
Write-Host "    Get-Service sshd" -ForegroundColor White
