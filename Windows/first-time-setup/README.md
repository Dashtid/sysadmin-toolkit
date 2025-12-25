# Windows 11 First-Time Setup Scripts

Automated setup system for quickly configuring a fresh Windows 11 installation with all your preferred software and settings.

## [*] Overview

This directory contains scripts to:

1. **Export** your current package installations (Winget & Chocolatey)
2. **Install** all packages on a fresh Windows 11 machine
3. **Configure** system settings and development environment

## [+] Quick Start - New Machine Setup

For a brand new Windows 11 installation, run these scripts in order:

```powershell
# 1. Export packages from your CURRENT working machine (run this first!)
.\export-current-packages.ps1

# 2. On your NEW machine, install all packages
.\install-from-exported-packages.ps1

# 3. Or use full setup with profile support
.\fresh-windows-setup.ps1 -Profile Work
```

## [i] Current Package Lists

Your exported packages are stored in:

- **[winget-packages.json](winget-packages.json)** - 57 packages from Windows Package Manager
- **[chocolatey-packages.config](chocolatey-packages.config)** - 52 packages from Chocolatey

### Key Software Installed

**Development Tools:**
- Git, GitHub CLI
- Docker Desktop
- Visual Studio Code
- PowerShell 7+
- Python 3.13, 3.14
- .NET SDK 9.0
- Node.js (via NVM for Windows)
- Maven, OpenJDK, Temurin JDK 17
- Azure CLI
- Pandoc

**Productivity:**
- Obsidian (note-taking)
- Notepad++
- PDF24 Creator
- Microsoft Teams
- Zoom

**Utilities:**
- WinSCP, PuTTY (SSH/FTP)
- Revo Uninstaller
- Bind DNS tools
- Grype, Syft (security scanning)
- OpenVPN, ProtonVPN
- Logitech Options Plus

**Browsers:**
- Google Chrome
- Microsoft Edge
- Brave Browser

**AI/ML:**
- Ollama
- NVIDIA CUDA
- NVIDIA PhysX

**Other:**
- Spotify
- OneDrive
- ProtonMail

## [*] Script Reference

### export-current-packages.ps1

Exports your currently installed packages for backup and automation.

**Usage:**
```powershell
# Export to default location (current directory)
.\export-current-packages.ps1

# Export to custom directory
.\export-current-packages.ps1 -OutputDir "C:\Backups\Packages"
```

**What it does:**
- Exports Winget packages to JSON
- Exports Chocolatey packages to XML config
- Creates a readable text list of all installed programs
- Timestamps the export

**When to run:**
- Before reinstalling Windows
- After installing new software you want to preserve
- Monthly as a backup routine

### install-from-exported-packages.ps1

Installs all packages from previously exported lists.

**Usage:**
```powershell
# Install everything with latest versions (RECOMMENDED)
.\install-from-exported-packages.ps1 -UseLatestVersions

# Install specific versions from export
.\install-from-exported-packages.ps1

# Skip Winget or Chocolatey
.\install-from-exported-packages.ps1 -SkipWinget
.\install-from-exported-packages.ps1 -SkipChocolatey
```

**Parameters:**
- `-UseLatestVersions` - Install latest versions instead of pinned versions (recommended)
- `-SkipWinget` - Skip Winget package installation
- `-SkipChocolatey` - Skip Chocolatey package installation
- `-PackageDir` - Custom directory containing package files

**What it does:**
- Installs Chocolatey if not present
- Installs all packages from Winget JSON export
- Installs all packages from Chocolatey XML config
- Creates detailed installation log
- Refreshes environment variables

**Time estimate:** 30-60 minutes depending on internet speed

### fresh-windows-setup.ps1

Complete automated setup with profile-based configuration (Work/Home).

**Usage:**
```powershell
# Full work profile setup
.\fresh-windows-setup.ps1 -Profile Work

# Full home profile setup (includes gaming packages)
.\fresh-windows-setup.ps1 -Profile Home

# Skip package install (configuration only)
.\fresh-windows-setup.ps1 -Profile Work -SkipPackageInstall

# Minimal setup
.\fresh-windows-setup.ps1 -Profile Work -Minimal
```

**What it does:**
- Installs packages from winget/chocolatey based on profile
- Configures Windows features (Hyper-V, WSL2, Containers)
- Installs PowerShell modules (posh-git, oh-my-posh, etc.)
- Configures PowerShell profile
- Sets up Git configuration
- Creates development directory structure
- Configures Windows settings (dark mode, show extensions, etc.)

## [!] Prerequisites

### Required

- **Windows 11** with latest updates
- **Administrator privileges** for running setup scripts
- **PowerShell 7+** (script will check and prompt if needed)
- **Internet connection** for package downloads

### Installing PowerShell 7+

If you don't have PowerShell 7+, install it first:

```powershell
# Via Winget
winget install Microsoft.PowerShell

# Via MSI installer
# Download from: https://github.com/PowerShell/PowerShell/releases
```

## [*] Step-by-Step: Setting Up a New Windows 11 Desktop

### On Your Current Working Machine

1. **Export your packages:**
   ```powershell
   cd C:\path\to\windows-linux-sysadmin-toolkit\Windows\first-time-setup
   .\export-current-packages.ps1
   ```

2. **Commit changes to Git:**
   ```bash
   git add winget-packages.json chocolatey-packages.config
   git commit -m "update: refresh package exports"
   git push
   ```

### On Your New Windows 11 Machine

1. **Install PowerShell 7:**
   - Download from: https://github.com/PowerShell/PowerShell/releases
   - Or use Windows Store: Search "PowerShell"

2. **Install Git:**
   - Download from: https://git-scm.com/downloads
   - Or use Winget: `winget install Git.Git`

3. **Clone this repository:**
   ```bash
   git clone https://github.com/yourusername/windows-linux-sysadmin-toolkit.git
   cd windows-linux-sysadmin-toolkit/Windows/first-time-setup
   ```

4. **Run installation script (as Administrator):**
   ```powershell
   # Right-click PowerShell 7 -> Run as Administrator
   Set-ExecutionPolicy Bypass -Scope Process
   .\install-from-exported-packages.ps1 -UseLatestVersions
   ```

5. **Wait for installation to complete** (30-60 minutes)

6. **Or run complete setup (alternative to steps 4-5):**
   ```powershell
   .\fresh-windows-setup.ps1 -Profile Work
   ```

7. **Reboot your computer**

8. **Post-installation tasks:**
   - Open Docker Desktop and complete setup
   - Configure WSL2: `wsl --install -d Ubuntu`
   - Generate SSH keys: `ssh-keygen -t ed25519 -C "your_email@example.com"`
   - Configure VS Code extensions
   - Sign in to browsers and apps

## [*] Package Management Best Practices

### Keeping Exports Updated

Run export script periodically:

```powershell
# Monthly or after installing new software
.\export-current-packages.ps1
git add -u
git commit -m "update: refresh package lists $(Get-Date -Format 'yyyy-MM-dd')"
git push
```

### Handling Conflicts Between Winget and Chocolatey

Some packages appear in both package managers. The scripts handle this gracefully:

- **Winget takes priority** if installed via Winget
- **Chocolatey fills gaps** for packages not in Winget
- Duplicates are skipped automatically

**Packages in both lists:**
- Git
- Notepad++
- Obsidian
- Python
- PowerShell
- Azure CLI
- Pandoc

**Recommendation:** Let the scripts handle conflicts automatically. They won't duplicate installations.

### Latest vs. Pinned Versions

**Use `-UseLatestVersions` (RECOMMENDED):**
- Gets security updates
- Avoids compatibility issues with Windows 11
- Faster installation (no version conflicts)

**Use pinned versions only if:**
- You have specific version requirements
- You need to match a specific development environment
- You're debugging version-specific issues

## [+] Maintenance Scripts

### Update All Packages

```powershell
# Winget
winget upgrade --all

# Chocolatey
choco upgrade all -y
```

### Check for Outdated Packages

```powershell
# Winget
winget upgrade

# Chocolatey
choco outdated
```

### List Installed Packages

```powershell
# Winget
winget list

# Chocolatey
choco list --local-only
```

## [!] Troubleshooting

### "Winget not found" error

**Solution 1:** Install App Installer from Microsoft Store
- Open Microsoft Store
- Search "App Installer"
- Click "Install"

**Solution 2:** Update Windows
```powershell
# Check for Windows updates
Start-Process ms-settings:windowsupdate
```

### "Chocolatey not found" error

The script will install Chocolatey automatically. If it fails:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

### Package installation fails

**Check the log file:**
```powershell
Get-Content "$env:USERPROFILE\.setup-logs\package-install-*.log" | Select-String "FAIL|ERROR"
```

**Retry specific package:**
```powershell
# Winget
winget install --id PackageName

# Chocolatey
choco install packagename -y
```

### "Access denied" or "Permission denied" errors

- Run PowerShell as Administrator
- Check antivirus isn't blocking the installation
- Temporarily disable Windows Defender real-time protection (Settings > Update & Security > Windows Security)

### WSL2 installation fails

**Enable virtualization in BIOS:**
1. Restart computer
2. Enter BIOS (usually F2, F10, or Delete during boot)
3. Enable "Intel VT-x" or "AMD-V"
4. Save and exit

**Enable required Windows features:**
```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

## [*] Customization

### Adding New Packages

**To add to Winget:**
1. Install package: `winget install PackageName`
2. Re-run export: `.\export-current-packages.ps1`
3. Commit changes to Git

**To add to Chocolatey:**
1. Install package: `choco install packagename`
2. Re-run export: `.\export-current-packages.ps1`
3. Commit changes to Git

### Removing Packages

Edit the exported JSON/XML files directly:

- **winget-packages.json:** Remove the package object
- **chocolatey-packages.config:** Remove the `<package id="..." />` line

### Adding Custom Configuration

Modify `fresh-windows-setup.ps1` to add:
- Additional Windows registry tweaks
- Custom PowerShell functions
- More PowerShell modules
- Additional development tools

## [i] Logs and Output

All scripts create detailed logs in:
```
C:\Users\YourName\.setup-logs\
```

Log files include:
- `package-install-YYYYMMDD-HHMMSS.log` - Package installation
- `fresh-windows-setup-YYYYMMDD-HHMMSS.log` - System configuration
- `installed-programs.txt` - Full list of installed software
- `chocolatey-packages.txt` - Readable Chocolatey list
- `last-export.txt` - Timestamp of last export

## [*] Security Considerations

### No Credentials in This Repo

These scripts and package lists contain:
- [+] Public package identifiers
- [+] Version numbers
- [+] Configuration settings

They do NOT contain:
- [-] Passwords or API keys
- [-] SSH keys
- [-] Personal data
- [-] License keys

### Post-Installation Security

After setup, configure:

1. **Windows Defender:** Review exclusions and settings
2. **Firewall:** Configure rules for development tools
3. **SSH Keys:** Generate new keys, never reuse old ones
4. **Git Credentials:** Use SSH or Git Credential Manager
5. **VPN:** Configure OpenVPN or ProtonVPN for privacy

## [+] Related Scripts

- **[../ssh/setup-ssh-agent-access.ps1](../ssh/setup-ssh-agent-access.ps1)** - Configure SSH agent for Git
- **[../ssh/gitea-tunnel-manager.ps1](../ssh/gitea-tunnel-manager.ps1)** - SSH tunnel management
- **[../maintenance/system-updates.ps1](../maintenance/system-updates.ps1)** - Windows Update automation

## [i] Support and Feedback

For issues or questions:

1. Check the troubleshooting section above
2. Review log files in `C:\Users\YourName\.setup-logs\`
3. Open an issue on GitHub: https://github.com/Dashtid/sysadmin-toolkit/issues

---

**Last Updated:** 2025-12-25
**Scripts Version:** 2.0
**Winget Packages:** 57
**Chocolatey Packages:** 52
