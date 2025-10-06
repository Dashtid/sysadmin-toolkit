# Gitea SSH Tunnel Manager for Windows

A robust PowerShell solution for maintaining persistent SSH tunnels to Gitea servers, designed to work seamlessly with Claude Code, Git, and other development tools on Windows.

## 🎯 The Problem

When using Claude Code (or any Git tool) on Windows with:
- Password-protected SSH keys (security best practice)
- Gitea servers requiring SSH tunnels or VPN access
- Git operations that need authentication

You face these common issues:
1. **Constant passphrase prompts** - Git Bash can't access the Windows SSH agent
2. **Manual tunnel management** - SSH tunnels die when shells close
3. **Failed Git operations** - Commands fail when tunnels aren't active
4. **VPN connectivity issues** - Tunnels fail silently when off VPN

## ✅ The Solution

This PowerShell script provides:
- ✅ **Persistent SSH tunnels** that survive shell closures
- ✅ **Automatic health monitoring** and reconnection
- ✅ **Windows SSH agent integration** - no more passphrase prompts
- ✅ **VPN/network awareness** - detects connectivity issues
- ✅ **Scheduled task support** - tunnel starts automatically at login
- ✅ **Works perfectly with Claude Code** and all Git tools

## 📋 Prerequisites

### 1. Windows OpenSSH Client
Usually pre-installed on Windows 10/11. Verify with:
```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'
```

If not installed:
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

### 2. SSH Agent Running
```powershell
# Set to start automatically
Get-Service ssh-agent | Set-Service -StartupType Automatic

# Start the service
Start-Service ssh-agent
```

### 3. SSH Key Loaded in Agent
```powershell
# Add your SSH key (will prompt for passphrase once)
ssh-add C:\Users\YourName\.ssh\id_ed25519

# Verify it's loaded
ssh-add -l
```

### 4. Git Configured to Use Windows SSH
This is crucial for passphrase-free operation:
```bash
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

## 🚀 Installation

### Step 1: Download the Script
Save `gitea-tunnel-manager.ps1` to a permanent location (e.g., your home directory).

### Step 2: Configure
Edit the script and set these variables for your environment:

```powershell
$LOCAL_PORT = 2222                              # Local port for tunnel
$REMOTE_HOST = "youruser@gitea.example.com"     # Your Gitea SSH server
$REMOTE_PORT = 2222                             # Gitea SSH port on server
$VPN_CHECK_HOST = "gitea.example.com"           # Host to ping for connectivity check
```

### Step 3: Install as Scheduled Task (Recommended)
Run PowerShell as Administrator:
```powershell
powershell -ExecutionPolicy Bypass -File "C:\path\to\gitea-tunnel-manager.ps1" -Install
```

This will:
- Create a scheduled task that runs at login
- Start the tunnel automatically when you log in
- Keep the tunnel running in the background
- Auto-restart if the tunnel fails

## 📖 Usage

### Check Tunnel Status
```powershell
powershell -ExecutionPolicy Bypass -File gitea-tunnel-manager.ps1 -Status
```

Example output:
```
=== Gitea SSH Tunnel Status ===

Network Connection: CONNECTED
Port 2222 listening: YES
Tunnel health: HEALTHY

Tunnel process:
  PID: 12345
  Memory: 13.04 MB

Scheduled task: Ready
```

### Stop the Tunnel
```powershell
powershell -ExecutionPolicy Bypass -File gitea-tunnel-manager.ps1 -Stop
```

### Run Manually (No Scheduled Task)
```powershell
powershell -ExecutionPolicy Bypass -File gitea-tunnel-manager.ps1
```
Press Ctrl+C to stop.

### Uninstall Scheduled Task
```powershell
powershell -ExecutionPolicy Bypass -File gitea-tunnel-manager.ps1 -Uninstall
```

## ⚙️ Git Configuration

Configure your Git remote to use the tunnel:

```bash
# For new repositories
git remote add origin ssh://git@localhost:2222/username/repo.git

# For existing repositories
git remote set-url origin ssh://git@localhost:2222/username/repo.git
```

## 🔧 How It Works

### Tunnel Flow
```
Your Computer              SSH Tunnel             Gitea Server
-------------              ----------             ------------
localhost:2222  ←→  SSH Connection (port 22)  →  Gitea:2222
```

1. **Git connects to `localhost:2222`**
2. **Tunnel forwards through encrypted SSH connection**
3. **Server forwards to Gitea on port 2222**
4. **Windows SSH agent provides your key (no passphrase prompt!)**

### Health Monitoring
The script continuously:
- Checks network connectivity (VPN/network status)
- Verifies the local port is listening
- Tests actual connectivity through the tunnel
- Auto-restarts if unhealthy

### Authentication
- Uses Windows SSH agent for key management
- Keys unlocked once, stored in memory
- No passphrase prompts on subsequent operations
- Secure key storage (encrypted at rest with passphrase)

## 🐛 Troubleshooting

### "Connection refused" Errors
**Check tunnel status:**
```powershell
powershell -File gitea-tunnel-manager.ps1 -Status
```

**If not running**, start it:
```powershell
# Manual start
powershell -File gitea-tunnel-manager.ps1

# Or start scheduled task
Start-ScheduledTask -TaskName "GiteaSSHTunnel"
```

### Still Getting Passphrase Prompts
**Verify Git is using Windows SSH:**
```bash
git config --global --get core.sshCommand
```
Should output: `C:/Windows/System32/OpenSSH/ssh.exe`

**Check if key is in agent:**
```powershell
C:\Windows\System32\OpenSSH\ssh-add.exe -l
```

**If key isn't listed:**
```powershell
C:\Windows\System32\OpenSSH\ssh-add.exe C:\Users\YourName\.ssh\id_ed25519
```

### Network Connectivity Issues
The script will show:
```
Network Connection: DISCONNECTED
  (Cannot reach gitea.example.com)
```

**Solutions:**
- Connect to your VPN
- Check network connectivity
- Verify `$VPN_CHECK_HOST` is correct in the script

### View Detailed Logs
```powershell
Get-Content $env:TEMP\gitea-tunnel.log -Tail 50
```

## 🔐 Security Benefits

This approach maintains security best practices:

✅ **SSH keys stay encrypted** on disk with strong passphrases
✅ **Keys unlocked once** per session in SSH agent
✅ **Unlocked keys stored in memory** only (not on disk)
✅ **All traffic encrypted** through SSH tunnel
✅ **No plaintext credentials** anywhere
✅ **Tunnel uses authenticated SSH** with your key
✅ **Windows SSH agent** provides secure key storage

## 🎓 Use Cases

### With Claude Code
Once configured, Claude Code can:
- Run `git push/pull/fetch` without passphrase prompts
- Perform all Git operations seamlessly
- Work exactly like on Linux/Mac

The tunnel runs silently in the background, automatically recovering from failures.

### With Other Tools
Works with any tool that uses Git/SSH:
- Visual Studio Code
- GitHub Desktop (if configured)
- Command-line Git
- JetBrains IDEs
- Any SSH-based tool

## 🤝 Contributing

Found a bug or have an improvement? Please:
1. Open an issue describing the problem
2. Submit a pull request with your fix
3. Share your use case or modifications

## 📝 License

Free to use and modify. Attribution appreciated but not required.

## 👤 Author

**David Dashti**
- Aspiring security professional
- GitHub: [@dashtid](https://github.com/dashtid)

---

**Made with ❤️ to solve real Windows + SSH + Git frustrations**

*If this helped you, give it a ⭐!*
