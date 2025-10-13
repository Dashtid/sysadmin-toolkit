# SSH Server Setup for Windows 11 Desktop

Guide to enable SSH access to your Windows 11 home desktop from your work laptop via VPN.

## Current Situation

- **Home Desktop:** Windows 11 (this machine)
- **Work Laptop:** Connected to home network via VPN
- **Goal:** SSH from work laptop to home desktop

---

## Step 1: Check if OpenSSH Server is Installed

**Run in PowerShell (as Administrator):**

```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
```

**Expected Output:**
- If installed: `State : Installed`
- If not installed: `State : NotPresent`

---

## Step 2: Install OpenSSH Server (if needed)

**Option A: Via Settings GUI (Easiest)**
1. Open **Settings** > **System** > **Optional Features**
2. Click **View Features** (or **Add a feature**)
3. Search for **OpenSSH Server**
4. Check the box and click **Install**
5. Wait for installation to complete

**Option B: Via PowerShell (Recommended)**

```powershell
# Run as Administrator
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

---

## Step 3: Start and Enable SSH Service

**Run in PowerShell (as Administrator):**

```powershell
# Start the SSH service
Start-Service sshd

# Set SSH to start automatically on boot
Set-Service -Name sshd -StartupType 'Automatic'

# Verify service is running
Get-Service sshd
```

**Expected Output:**
```
Status   Name               DisplayName
------   ----               -----------
Running  sshd               OpenSSH SSH Server
```

---

## Step 4: Configure Windows Firewall

**Check if firewall rule exists:**

```powershell
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
```

**If rule doesn't exist, create it:**

```powershell
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
    -DisplayName "OpenSSH Server (sshd)" `
    -Enabled True `
    -Direction Inbound `
    -Protocol TCP `
    -Action Allow `
    -LocalPort 22
```

**Verify firewall rule:**

```powershell
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" | Select-Object Name, Enabled, Direction, Action
```

---

## Step 5: Test Local SSH Connection

**From this desktop, test SSH locally:**

```powershell
ssh localhost
# Or
ssh david@localhost
```

**Expected:**
- First time: Will ask to trust the host (type `yes`)
- Then: Password prompt
- Success: You're logged in via SSH

---

## Step 6: Find Your Desktop's IP Address

**Get IP address on your home network:**

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object IPAddress, InterfaceAlias
```

**Or simpler:**

```powershell
ipconfig | findstr /i "IPv4"
```

**Note the IP address** (e.g., `192.168.1.100`)

---

## Step 7: Test SSH from Work Laptop

**On your work laptop (connected to VPN):**

```bash
# Replace with your desktop's actual IP
ssh david@192.168.1.100

# Or use hostname if DNS works
ssh david@DESKTOP-NAME
```

---

## Step 8: Set Up SSH Key Authentication (Recommended)

**Why?** More secure than passwords, no password prompt needed.

### On Work Laptop (Generate SSH Key)

**If you don't already have SSH keys:**

```bash
ssh-keygen -t ed25519 -C "work-to-home-desktop"
```

- Save to: `~/.ssh/id_ed25519_home` (or default location)
- Optional: Add passphrase for extra security

### Copy Public Key to Desktop

**Option A: Using ssh-copy-id (if available on work laptop):**

```bash
ssh-copy-id -i ~/.ssh/id_ed25519_home.pub david@192.168.1.100
```

**Option B: Manual Copy**

1. **On work laptop, get public key:**
   ```bash
   cat ~/.ssh/id_ed25519_home.pub
   ```

2. **On home desktop, add to authorized_keys:**
   ```powershell
   # Create .ssh directory if it doesn't exist
   $sshDir = "$env:USERPROFILE\.ssh"
   if (!(Test-Path $sshDir)) {
       New-Item -ItemType Directory -Path $sshDir -Force
   }

   # Append public key to authorized_keys
   Add-Content -Path "$sshDir\authorized_keys" -Value "ssh-ed25519 AAAA... your-public-key-here"

   # Set correct permissions
   icacls "$sshDir\authorized_keys" /inheritance:r
   icacls "$sshDir\authorized_keys" /grant:r "$env:USERNAME`:F"
   icacls "$sshDir\authorized_keys" /grant:r "SYSTEM:F"
   ```

### Test Key-Based Authentication

**From work laptop:**

```bash
ssh -i ~/.ssh/id_ed25519_home david@192.168.1.100
```

Should connect without password prompt!

---

## Step 9: Configure SSH Config (Optional)

**On work laptop, create/edit `~/.ssh/config`:**

```
Host home-desktop
    HostName 192.168.1.100
    User david
    IdentityFile ~/.ssh/id_ed25519_home
    Port 22
```

**Now you can connect with:**

```bash
ssh home-desktop
```

---

## Security Considerations

### [!] IMPORTANT - Security Best Practices

**1. Change SSH Port (Optional)**
- Default port 22 is well-known
- Consider changing to non-standard port (e.g., 2222)
- Update firewall rule accordingly

**2. Disable Password Authentication (After key setup)**

Edit `C:\ProgramData\ssh\sshd_config`:

```
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH service:
```powershell
Restart-Service sshd
```

**3. Limit User Access**

Only allow specific users to SSH:

Add to `C:\ProgramData\ssh\sshd_config`:
```
AllowUsers david
```

**4. Use Strong Passwords**
- Ensure Windows account has strong password
- Or disable password auth entirely (use keys only)

**5. Monitor SSH Logs**

Check for failed login attempts:
```powershell
Get-EventLog -LogName Security -InstanceId 4625 -Newest 20
```

---

## Troubleshooting

### SSH Service Won't Start

```powershell
# Check service status
Get-Service sshd

# Check for errors
Get-EventLog -LogName Application -Source OpenSSH -Newest 10

# Restart service
Restart-Service sshd
```

### Connection Refused

**Check firewall:**
```powershell
Test-NetConnection -ComputerName localhost -Port 22
```

**Check SSH is listening:**
```powershell
netstat -an | findstr :22
```

### Permission Denied (Public Key)

**Check authorized_keys permissions:**
```powershell
icacls C:\Users\david\.ssh\authorized_keys
```

Should only have:
- Your user account (Full control)
- SYSTEM (Full control)
- No other users/groups

### Can't Find sshd_config

**Default location:**
```
C:\ProgramData\ssh\sshd_config
```

If missing:
```powershell
# Reinstall OpenSSH Server
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

---

## Quick Start Script

Save as `setup-ssh-server.ps1` and run as Administrator:

```powershell
#Requires -RunAsAdministrator

Write-Host "[*] Installing OpenSSH Server..." -ForegroundColor Cyan
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Write-Host "[*] Starting SSH service..." -ForegroundColor Cyan
Start-Service sshd

Write-Host "[*] Setting SSH to start automatically..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType 'Automatic'

Write-Host "[*] Configuring firewall..." -ForegroundColor Cyan
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
        -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -Action Allow `
        -LocalPort 22
}

Write-Host "[+] SSH Server setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "[i] Your IP address:" -ForegroundColor Blue
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object IPAddress, InterfaceAlias
Write-Host ""
Write-Host "[i] Test connection from work laptop:" -ForegroundColor Blue
Write-Host "    ssh $env:USERNAME@YOUR-IP-ADDRESS" -ForegroundColor Yellow
```

---

## Summary Checklist

- [ ] Install OpenSSH Server
- [ ] Start and enable sshd service
- [ ] Configure Windows Firewall
- [ ] Test local SSH connection
- [ ] Find desktop IP address
- [ ] Test SSH from work laptop
- [ ] Set up SSH key authentication
- [ ] Disable password authentication (optional)
- [ ] Configure ~/.ssh/config on work laptop
- [ ] Document connection details

---

**Once complete, you can SSH from your work laptop to your home desktop anytime you're connected via VPN!**
