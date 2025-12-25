# Quick Start - Windows 11 Fresh Install

**TL;DR:** Use these scripts to get your Windows 11 desktop to "tip-top shape" in under an hour.

## [+] One-Command Setup (New Machine)

```powershell
# Open PowerShell 7 as Administrator, then run:
.\fresh-windows-setup.ps1
```

That's it! The script will:
- Install 57 Winget packages
- Install 52 Chocolatey packages
- Configure Windows settings
- Set up development environment
- Create PowerShell profile
- Configure Git

**Time:** 30-60 minutes

## [i] On Your Current Machine (Before Reinstalling)

```powershell
# Export your current setup (run this first!)
.\export-current-packages.ps1

# Commit to git
git add winget-packages.json chocolatey-packages.config
git commit -m "update: refresh package exports"
git push
```

## [*] Script Cheat Sheet

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `export-current-packages.ps1` | Capture current packages | Before reinstalling, monthly backup |
| `fresh-windows-setup.ps1` | Complete automated setup | New Windows 11 installation (supports -Profile Work/Home) |
| `install-from-exported-packages.ps1` | Install packages only | Just need software, skip config |

## [!] Prerequisites

1. **Windows 11** with updates
2. **PowerShell 7+** - [Download](https://github.com/PowerShell/PowerShell/releases)
3. **Administrator privileges**
4. **Git installed** - [Download](https://git-scm.com/downloads)

## [*] What Gets Installed

<details>
<summary><b>Development Tools (Click to expand)</b></summary>

- Git + GitHub CLI
- Docker Desktop
- Visual Studio Code
- Python 3.13, 3.14
- Node.js (via NVM)
- .NET SDK 9.0
- PowerShell 7
- Azure CLI
- Maven, OpenJDK 17

</details>

<details>
<summary><b>Productivity & Utilities</b></summary>

- Obsidian (notes)
- Notepad++
- PDF24 Creator
- Microsoft Teams, Zoom
- WinSCP, PuTTY
- OpenVPN, ProtonVPN
- Revo Uninstaller

</details>

<details>
<summary><b>Browsers</b></summary>

- Google Chrome
- Microsoft Edge
- Brave Browser

</details>

<details>
<summary><b>AI/ML & Other</b></summary>

- Ollama
- NVIDIA CUDA
- Spotify
- OneDrive
- Grype, Syft (security)

</details>

## [+] After Setup Completes

1. **Reboot your computer**
2. **Open Docker Desktop** - Complete setup
3. **Install WSL2 Ubuntu** - `wsl --install -d Ubuntu`
4. **Generate SSH keys** - `ssh-keygen -t ed25519 -C "your@email.com"`
5. **Configure Git** - Set name and email
6. **Sign in to apps** - Chrome, VS Code, Teams, etc.

## [*] Common Scenarios

### Scenario 1: Brand new Windows 11 desktop

```powershell
# Clone this repo first
git clone https://github.com/yourusername/windows-linux-sysadmin-toolkit.git
cd windows-linux-sysadmin-toolkit/Windows/first-time-setup

# Run master setup script
.\fresh-windows-setup.ps1
```

### Scenario 2: Already have some software, just want to fill gaps

```powershell
# Install missing packages only
.\install-from-exported-packages.ps1 -UseLatestVersions
```

### Scenario 3: Just want system configuration (already have software)

```powershell
# Skip package installation
.\fresh-windows-setup.ps1 -SkipPackageInstall
```

### Scenario 4: Minimal installation (essentials only)

```powershell
.\fresh-windows-setup.ps1 -Minimal
```

### Scenario 5: Update package exports on current machine

```powershell
# After installing new software
.\export-current-packages.ps1

# Commit changes
git add -u && git commit -m "update: package lists" && git push
```

## [!] Troubleshooting

**Problem:** "Winget not found"
```powershell
# Solution: Install from Microsoft Store
Start-Process ms-windowsstore://pdp/?ProductId=9NBLGGH4NNS1
```

**Problem:** "Access denied"
```powershell
# Solution: Run PowerShell as Administrator
# Right-click PowerShell 7 -> Run as Administrator
```

**Problem:** Package installation failed
```powershell
# Check logs
Get-Content "$env:USERPROFILE\.setup-logs\*.log" | Select-String "ERROR"

# Retry specific package
winget install PackageName
choco install packagename
```

**Problem:** Script won't run
```powershell
# Allow script execution for this session
Set-ExecutionPolicy Bypass -Scope Process
```

## [*] Maintenance

### Keep packages updated

```powershell
# Update all Winget packages
winget upgrade --all

# Update all Chocolatey packages
choco upgrade all -y
```

### Refresh exports monthly

```powershell
# Run on the 1st of each month
.\export-current-packages.ps1
git add -u && git commit -m "update: monthly package refresh" && git push
```

## [+] Advanced Options

### Use specific versions instead of latest

```powershell
.\install-from-exported-packages.ps1
# (without -UseLatestVersions flag)
```

### Skip Winget or Chocolatey

```powershell
.\fresh-windows-setup.ps1 -SkipPackageInstall
.\install-from-exported-packages.ps1 -SkipWinget
.\install-from-exported-packages.ps1 -SkipChocolatey
```

### Custom package directory

```powershell
.\install-from-exported-packages.ps1 -PackageDir "C:\Backups\Packages"
```

---

**Full documentation:** See [README.md](README.md) for complete details.

**Last Updated:** 2025-12-25
