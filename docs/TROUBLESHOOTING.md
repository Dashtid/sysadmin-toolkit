# Troubleshooting Guide

Common issues and solutions for the Windows & Linux Sysadmin Toolkit scripts.

**Last Updated:** 2025-10-15

---

## Table of Contents

- [Update Scripts](#update-scripts)
- [SSH and Tunneling](#ssh-and-tunneling)
- [PowerShell Issues](#powershell-issues)
- [Package Manager Issues](#package-manager-issues)
- [Network and Connectivity](#network-and-connectivity)
- [Permissions and Security](#permissions-and-security)
- [General Debugging](#general-debugging)

---

## Update Scripts

### Issue: "Chocolatey is not installed"

**Symptoms:**
```
[!] Chocolatey not found. Please install Chocolatey first.
```

**Solution:**
Install Chocolatey using the official installation script:

```powershell
# Run in an elevated PowerShell session
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

**Verification:**
```powershell
choco --version
```

---

### Issue: "Winget is not installed or not available in PATH"

**Symptoms:**
```
[!] Winget is not installed or not available in PATH
```

**Solution 1 - Install App Installer (includes Winget):**
1. Open Microsoft Store
2. Search for "App Installer"
3. Install or update it

**Solution 2 - Manual Installation:**
```powershell
# Download and install winget-cli from GitHub
$latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
$msixBundle = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
Invoke-WebRequest -Uri $msixBundle.browser_download_url -OutFile "$env:TEMP\winget.msixbundle"
Add-AppxPackage -Path "$env:TEMP\winget.msixbundle"
```

**Solution 3 - Add to PATH:**
If Winget is installed but not in PATH:
```powershell
$env:PATH += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
[Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
```

**Verification:**
```powershell
winget --version
```

---

### Issue: "PSWindowsUpdate module fails to install"

**Symptoms:**
```
[-] Failed to install PSWindowsUpdate module: Unable to resolve package source
```

**Solution 1 - Trust PSGallery:**
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
```

**Solution 2 - Manual proxy configuration (if behind corporate proxy):**
```powershell
$proxy = "http://proxy.company.com:8080"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
```

**Solution 3 - Update NuGet provider:**
```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
```

**Verification:**
```powershell
Get-Module -ListAvailable PSWindowsUpdate
```

---

### Issue: "System restore point creation failed"

**Symptoms:**
```
[!] Failed to create system restore point: The operation failed to start
```

**Solution 1 - Enable System Restore:**
```powershell
# Enable System Restore on C: drive
Enable-ComputerRestore -Drive "C:\"

# Verify it's enabled
Get-ComputerRestorePoint
```

**Solution 2 - Increase disk space allocation:**
```powershell
# Allocate 10% of disk space for System Restore
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%
```

**Solution 3 - Check VSS service:**
```powershell
# Ensure Volume Shadow Copy service is running
Get-Service VSS | Start-Service
```

**Workaround:**
If System Restore cannot be enabled, skip it:
```powershell
.\system-updates.ps1 -SkipRestorePoint
```

---

### Issue: Updates complete but no summary is shown

**Symptoms:**
Script finishes but the update summary section is missing or incomplete.

**Solution:**
This may indicate the script crashed before completion. Check the transcript log:

```powershell
# Find latest transcript
Get-ChildItem logs\ -Filter "transcript_system-updates_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 100
```

Look for error messages at the end of the log.

---

### Issue: "A system reboot is recommended" but AutoReboot doesn't work

**Symptoms:**
Script shows reboot is required but doesn't reboot even with `-AutoReboot`.

**Solution:**
Check if WhatIf mode is enabled:
```powershell
# DON'T use -WhatIf with -AutoReboot
.\system-updates.ps1 -AutoReboot  # Correct

# This won't reboot (WhatIf prevents all actions)
.\system-updates.ps1 -AutoReboot -WhatIf  # Won't reboot
```

**Manual reboot:**
```powershell
Restart-Computer -Force
```

---

## SSH and Tunneling

### Issue: "SSH key passphrase prompt every time"

**Symptoms:**
Git operations or SSH connections always ask for key passphrase.

**Solution:**
Ensure SSH agent is running and key is added:

```powershell
# Check if ssh-agent is running
Get-Service ssh-agent

# Start ssh-agent if not running
Start-Service ssh-agent
Set-Service -Name ssh-agent -StartupType Automatic

# Add your key to ssh-agent (only needed once per session)
ssh-add C:\Users\YourName\.ssh\id_ed25519
```

---

### Issue: "SSH tunnel disconnects randomly"

**Symptoms:**
Gitea tunnel or other SSH tunnels disconnect after a few minutes of inactivity.

**Solution 1 - Enable SSH keepalive (client-side):**

Edit `~/.ssh/config` (or `C:\Users\YourName\.ssh\config`):
```
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

**Solution 2 - Use tunnel manager script:**
The `gitea-tunnel-manager.ps1` script includes automatic reconnection:
```powershell
.\Windows\ssh\gitea-tunnel-manager.ps1 -Install
```

---

### Issue: "Permission denied (publickey)"

**Symptoms:**
```
git@server: Permission denied (publickey).
```

**Solution 1 - Verify key is added:**
```powershell
ssh-add -l
```

If key is not listed:
```powershell
ssh-add C:\Users\YourName\.ssh\id_ed25519
```

**Solution 2 - Check key permissions:**
```powershell
# Private key should be readable only by you
icacls C:\Users\YourName\.ssh\id_ed25519
```

**Solution 3 - Test SSH connection:**
```powershell
ssh -T git@github.com  # For GitHub
ssh -T git@your-server  # For your server
```

---

## PowerShell Issues

### Issue: "This script must be run as Administrator"

**Symptoms:**
```
[-] This script must be run as Administrator
```

**Solution 1 - Run PowerShell as Administrator:**
1. Right-click PowerShell 7 icon
2. Select "Run as Administrator"
3. Navigate to script directory
4. Run script

**Solution 2 - Programmatic elevation (if not in admin mode):**
The script will attempt to auto-elevate. If this fails:
```powershell
Start-Process pwsh -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\script.ps1`"" -Verb RunAs
```

**Verification:**
```powershell
# Check if running as admin
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
```

---

### Issue: "Cannot be loaded because running scripts is disabled"

**Symptoms:**
```
.\script.ps1 : File cannot be loaded because running scripts is disabled on this system.
```

**Solution 1 - Temporary bypass (current session only):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\script.ps1
```

**Solution 2 - Permanent change for current user:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Solution 3 - Check current policy:**
```powershell
Get-ExecutionPolicy -List
```

---

### Issue: "This script requires PowerShell 7 or later"

**Symptoms:**
```
[-] This script requires PowerShell 7 or later. Current version: 5.1.x
```

**Solution - Install PowerShell 7:**

**Method 1 - Winget:**
```powershell
winget install Microsoft.PowerShell
```

**Method 2 - Chocolatey:**
```powershell
choco install powershell-core -y
```

**Method 3 - Manual download:**
Visit: https://github.com/PowerShell/PowerShell/releases

**Verification:**
```powershell
pwsh --version
```

---

## Package Manager Issues

### Issue: Chocolatey updates hang or timeout

**Symptoms:**
Chocolatey update process hangs for a long time or times out.

**Solution 1 - Increase timeout:**
```powershell
choco upgrade all -y --timeout=7200  # 2 hours
```

**Solution 2 - Update packages individually:**
```powershell
# List outdated packages
choco outdated

# Update one at a time
choco upgrade package-name -y
```

**Solution 3 - Clear Chocolatey cache:**
```powershell
choco clearcache
```

---

### Issue: Winget shows "No available upgrade found" but updates exist

**Symptoms:**
Winget says no updates available, but you know updates exist.

**Solution 1 - Update Winget sources:**
```powershell
winget source update --disable-interactivity
winget source reset --force
```

**Solution 2 - Check specific package:**
```powershell
winget list --name "PackageName"
winget upgrade "PackageName" --include-unknown
```

**Solution 3 - Reset Winget:**
```powershell
# Reset Winget settings
Remove-Item "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_*\LocalState\*" -Recurse -Force
winget source reset --force
```

---

## Network and Connectivity

### Issue: "Unable to resolve package source" or timeout errors

**Symptoms:**
```
WARNING: Unable to resolve package source 'https://www.powershellgallery.com/api/v2'.
```

**Solution 1 - Check network connectivity:**
```powershell
Test-NetConnection www.powershellgallery.com -Port 443
Test-NetConnection chocolatey.org -Port 443
Test-NetConnection github.com -Port 443
```

**Solution 2 - Configure proxy (if behind corporate firewall):**
```powershell
# Set proxy for current session
$proxy = "http://proxy.company.com:8080"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)

# For Chocolatey
choco config set proxy $proxy

# For Git
git config --global http.proxy $proxy
```

**Solution 3 - Disable IPv6 temporarily:**
```powershell
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
```

---

### Issue: VPN required but not connected

**Symptoms:**
Script fails to reach update servers that require VPN.

**Solution 1 - Check VPN status:**
```powershell
Get-VpnConnection
Get-VpnConnection -Name "YourVPN" | Select-Object ConnectionStatus
```

**Solution 2 - Connect VPN before running updates:**
```powershell
# Connect to VPN
rasdial "YourVPN" username password

# Or use GUI
vpnui.exe
```

---

## Permissions and Security

### Issue: "Access to the path is denied"

**Symptoms:**
```
[-] Access to the path 'C:\path\to\file' is denied.
```

**Solution 1 - Run as Administrator:**
See "This script must be run as Administrator" above.

**Solution 2 - Check file/folder permissions:**
```powershell
# View permissions
Get-Acl "C:\path\to\file" | Format-List

# Grant yourself full control
$acl = Get-Acl "C:\path\to\file"
$permission = "DOMAIN\Username", "FullControl", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl "C:\path\to\file" $acl
```

---

### Issue: Windows Defender blocks script execution

**Symptoms:**
Script runs but certain operations are blocked by Windows Defender.

**Solution 1 - Add exclusion for script directory:**
```powershell
Add-MpPreference -ExclusionPath "C:\path\to\sysadmin-toolkit"
```

**Solution 2 - Temporary disable (not recommended):**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Run script
Set-MpPreference -DisableRealtimeMonitoring $false
```

---

## General Debugging

### Enable verbose logging

```powershell
# Use -Verbose flag
.\system-updates.ps1 -Verbose

# Or set preference for session
$VerbosePreference = "Continue"
.\system-updates.ps1
```

### Check transcript logs

All scripts now save detailed transcripts:
```powershell
# View latest transcript
$latest = Get-ChildItem logs\ -Filter "transcript_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $latest.FullName | More
```

### Test with WhatIf mode

Before running actual updates:
```powershell
.\system-updates.ps1 -WhatIf
```

### Check CommonFunctions module

If scripts fail with module errors:
```powershell
# Verify module exists
Test-Path "Windows\lib\CommonFunctions.psm1"

# Test module import
Import-Module "Windows\lib\CommonFunctions.psm1" -Force -Verbose

# List exported functions
Get-Command -Module CommonFunctions
```

### Verify PowerShell version and modules

```powershell
# Check PowerShell version
$PSVersionTable

# List installed modules
Get-Module -ListAvailable

# Check execution policy
Get-ExecutionPolicy -List
```

---

## [i] Getting Additional Help

### Script Help
```powershell
Get-Help .\system-updates.ps1 -Full
Get-Help .\system-updates.ps1 -Examples
```

### Log Files
Check logs directory for detailed execution logs:
```
<toolkit-root>/logs/
```

### Community Resources
- PowerShell Gallery: https://www.powershellgallery.com/
- Chocolatey Docs: https://docs.chocolatey.org/
- Winget Documentation: https://learn.microsoft.com/en-us/windows/package-manager/winget/

---

## [!] Still Having Issues?

If you're still experiencing problems:

1. **Check script version** - Ensure you're using the latest version
2. **Review logs** - Detailed transcript logs often contain the root cause
3. **Test in isolation** - Try running individual update commands manually
4. **Check prerequisites** - Verify all required software is installed
5. **Document the issue** - Note exact error messages, commands run, and environment details

---

**Maintainer:** Windows & Linux Sysadmin Toolkit
**Last Updated:** 2025-10-15
