# SSH Server Setup for Windows 11

Enable SSH access to Windows 11 desktop from remote machines.

## Quick Setup

```powershell
# Run as Administrator
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

## Step-by-Step

### 1. Install OpenSSH Server
```powershell
# Check if installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

# Install if needed
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

### 2. Start Service
```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
Get-Service sshd  # Verify running
```

### 3. Configure Firewall
```powershell
# Create rule if missing
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
    -DisplayName "OpenSSH Server (sshd)" `
    -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 4. Get IP Address
```powershell
ipconfig | findstr /i "IPv4"
```

### 5. Test Connection
```bash
# From remote machine
ssh username@192.168.x.x
```

## SSH Key Authentication

### On Client (Generate Key)
```bash
ssh-keygen -t ed25519 -C "description"
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host
```

### On Server (Manual)
```powershell
$keyContent = "ssh-ed25519 AAAA... your-key"
Add-Content "$env:USERPROFILE\.ssh\authorized_keys" $keyContent

# Set permissions
icacls "$env:USERPROFILE\.ssh\authorized_keys" /inheritance:r
icacls "$env:USERPROFILE\.ssh\authorized_keys" /grant:r "$env:USERNAME`:F"
```

## Security Hardening

Edit `C:\ProgramData\ssh\sshd_config`:
```
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers username
```

Restart: `Restart-Service sshd`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | `Test-NetConnection localhost -Port 22` |
| Permission denied | Check authorized_keys permissions |
| Service won't start | `Get-EventLog -LogName Application -Source OpenSSH -Newest 10` |
| Config not found | Located at `C:\ProgramData\ssh\sshd_config` |

## SSH Config (Client)

```
Host myserver
    HostName 192.168.x.x
    User username
    IdentityFile ~/.ssh/id_ed25519
```

Then connect with: `ssh myserver`

---
**Last Updated**: 2025-12-26
