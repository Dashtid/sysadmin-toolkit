# Fresh Windows 11 Setup - Master Script
# Complete automated setup for a new Windows 11 installation
# This script orchestrates the entire setup process
# Supports Work and Home profiles with different package sets
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [Parameter()]
    [ValidateSet('Work', 'Home')]
    [string]$SetupProfile,               # Setup profile: Work or Home

    [switch]$UseLatestVersions = $true,  # Install latest versions by default
    [switch]$SkipPackageInstall,         # Skip package installation (config only)
    [switch]$SkipSystemConfig,           # Skip system configuration
    [switch]$SkipWSL,                    # Skip WSL2 setup
    [switch]$SkipGaming,                 # Skip gaming packages (Home profile)
    [switch]$Minimal                     # Minimal installation
)

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
    Magenta= 'Magenta'
}

# Logging setup
$LogDir = "$env:USERPROFILE\.setup-logs"
$LogFile = "$LogDir\fresh-windows-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogMessage
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color $Colors.Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color $Colors.Blue }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color $Colors.Red }
function Write-Section { param([string]$Message) Write-Log "`n========================================`n$Message`n========================================" -Color $Colors.Cyan }

# Display banner
function Show-Banner {
    $Banner = @"

    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        Windows 11 Fresh Installation Setup              ║
    ║        Automated Package & System Configuration         ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝

"@
    Write-Host $Banner -ForegroundColor $Colors.Cyan
}

# Check PowerShell version
function Test-PowerShellVersion {
    Write-Info "Checking PowerShell version..."
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)"
        Write-Info "Install PowerShell 7: https://github.com/PowerShell/PowerShell/releases"
        exit 1
    }
    Write-Success "PowerShell version: $($PSVersionTable.PSVersion)"
}

# Check for required files
function Test-RequiredFiles {
    Write-Info "Checking for required package files..."

    $ScriptDir = $PSScriptRoot
    $RequiredFiles = @(
        "install-from-exported-packages.ps1",
        "winget-packages.json",
        "chocolatey-packages.config"
    )

    $MissingFiles = @()
    foreach ($File in $RequiredFiles) {
        $FilePath = Join-Path $ScriptDir $File
        if (!(Test-Path $FilePath)) {
            $MissingFiles += $File
        }
    }

    if ($MissingFiles.Count -gt 0) {
        Write-Error "Missing required files:"
        $MissingFiles | ForEach-Object { Write-Error "  - $_" }
        Write-Info "Run export-current-packages.ps1 on your working machine first"
        exit 1
    }

    Write-Success "All required files found"
}

# Show setup summary
function Show-SetupSummary {
    Write-Section "Setup Configuration"

    Write-Info "Setup Mode: $(if ($Minimal) { 'Minimal' } else { 'Full' })"
    Write-Info "Profile: $(if ($SetupProfile) { $SetupProfile } else { 'Exported Packages' })"
    Write-Info "Package Installation: $(if ($SkipPackageInstall) { 'SKIPPED' } else { 'ENABLED' })"
    Write-Info "System Configuration: $(if ($SkipSystemConfig) { 'SKIPPED' } else { 'ENABLED' })"
    Write-Info "WSL2 Setup: $(if ($SkipWSL) { 'SKIPPED' } else { 'ENABLED' })"
    if ($SetupProfile -eq 'Home') {
        Write-Info "Gaming Packages: $(if ($SkipGaming) { 'SKIPPED' } else { 'ENABLED' })"
    }
    Write-Info "Log File: $LogFile"

    Write-Info ""

    if (!$SkipPackageInstall) {
        if ($SetupProfile) {
            Write-Info "Package source: Profile-based ($SetupProfile)"
            if ($SetupProfile -eq 'Work') {
                Write-Info "  - Includes: Teams, Azure CLI, WatchGuard VPN"
                Write-Info "  - Dev directory: $env:USERPROFILE\Development"
            } else {
                Write-Info "  - Includes: Discord, Spotify, ProtonVPN, Ollama"
                if (-not $SkipGaming) { Write-Info "  - Includes: Steam" }
                Write-Info "  - Dev directory: C:\Code"
            }
        } else {
            $WingetFile = Join-Path $PSScriptRoot "winget-packages.json"
            $ChocoFile = Join-Path $PSScriptRoot "chocolatey-packages.config"

            if (Test-Path $WingetFile) {
                $WingetCount = (Get-Content $WingetFile | ConvertFrom-Json).Sources.Packages.Count
                Write-Info "  - Winget: $WingetCount packages"
            }
            if (Test-Path $ChocoFile) {
                [xml]$ChocoXml = Get-Content $ChocoFile
                $ChocoCount = $ChocoXml.packages.package.Count
                Write-Info "  - Chocolatey: $ChocoCount packages"
            }
        }
    }

    Write-Info ""
    Write-Warning "This process will take 30-60 minutes depending on internet speed"
    Write-Info "Press Ctrl+C to cancel, or any other key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Install packages
function Install-Packages {
    if ($SkipPackageInstall) {
        Write-Info "Skipping package installation (as requested)"
        return
    }

    Write-Section "Installing Packages"

    $ScriptPath = Join-Path $PSScriptRoot "install-from-exported-packages.ps1"

    $InstallArgs = @{
        PackageDir = $PSScriptRoot
    }

    if ($UseLatestVersions) {
        $InstallArgs['UseLatestVersions'] = $true
    }

    Write-Info "Running package installation script..."
    Write-Info "Script: $ScriptPath"

    & $ScriptPath @InstallArgs

    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Write-Warning "Package installation completed with warnings"
    } else {
        Write-Success "Package installation completed"
    }
}

# Configure system based on profile
function Set-SystemConfiguration {
    if ($SkipSystemConfig) {
        Write-Info "Skipping system configuration (as requested)"
        return
    }

    Write-Section "Configuring System Settings"

    # Configure Windows settings (common to all profiles)
    Write-Info "Applying Windows settings..."
    try {
        # Show file extensions
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -ErrorAction SilentlyContinue
        # Show hidden files
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -ErrorAction SilentlyContinue
        # Enable dark mode
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -ErrorAction SilentlyContinue
        # Disable web search in start menu
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -ErrorAction SilentlyContinue
        Write-Success "Windows settings applied"
    } catch {
        Write-Warning "Some Windows settings could not be applied: $($_.Exception.Message)"
    }

    # Setup development directories based on profile
    Write-Info "Setting up development directories..."
    if ($SetupProfile -eq 'Work') {
        $DevDir = "$env:USERPROFILE\Development"
        $Directories = @("$DevDir\Projects", "$DevDir\Scripts", "$DevDir\Tools", "$DevDir\Documentation")
    } else {
        $DevDir = "C:\Code"
        $Directories = @("$DevDir", "$DevDir\personal", "$DevDir\learning", "$DevDir\projects")
    }

    foreach ($Dir in $Directories) {
        if (!(Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }
    Write-Success "Development directories created at: $DevDir"

    # Configure Git
    Write-Info "Configuring Git..."
    if (Get-Command git -ErrorAction SilentlyContinue) {
        git config --global init.defaultBranch main
        git config --global pull.rebase false
        git config --global core.autocrlf true
        git config --global core.editor "code --wait"
        Write-Success "Git configured with VS Code as default editor"
    } else {
        Write-Warning "Git not found. Install Git first, then configure manually."
    }

    # WSL2 setup (Work profile or if not skipped)
    if (-not $SkipWSL -and ($SetupProfile -eq 'Work' -or $null -eq $SetupProfile)) {
        Write-Info "Setting up WSL2..."
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction SilentlyContinue | Out-Null
            wsl --set-default-version 2 2>$null
            Write-Success "WSL2 enabled (run 'wsl --install -d Ubuntu' after reboot)"
        } catch {
            Write-Warning "WSL2 setup failed: $($_.Exception.Message)"
        }
    }

    Write-Success "System configuration completed"
}

# Install profile-specific packages
function Install-ProfilePackages {
    if ($SkipPackageInstall -or $null -eq $SetupProfile) {
        return
    }

    Write-Section "Installing $SetupProfile Profile Packages"

    # Common Winget packages for both profiles
    $CommonWinget = @(
        'Microsoft.VisualStudioCode',
        'Git.Git',
        'Docker.DockerDesktop',
        'OpenJS.NodeJS',
        'GitHub.cli',
        'Microsoft.PowerShell',
        'PuTTY.PuTTY',
        'WinSCP.WinSCP',
        'Google.Chrome',
        'Microsoft.Edge',
        'Brave.Brave',
        'Notepad++.Notepad++',
        'geeksoftwareGmbH.PDF24Creator',
        'Obsidian.Obsidian'
    )

    # Profile-specific Winget packages
    $ProfileWinget = @()
    if ($SetupProfile -eq 'Work') {
        $ProfileWinget = @(
            'Microsoft.AzureCLI',
            'JohnMacFarlane.Pandoc',
            'Microsoft.Teams',
            'Zoom.Zoom.EXE',
            'WatchGuard.MobileVPNWithSSLClient',
            'RevoUninstaller.RevoUninstaller'
        )
    } else {
        # Home profile
        $ProfileWinget = @(
            'Ollama.Ollama',
            'Proton.ProtonVPN',
            'Proton.ProtonMail',
            'Discord.Discord',
            'Spotify.Spotify',
            'OpenVPNTechnologies.OpenVPN',
            'Logitech.OptionsPlus',
            'Zoom.Zoom.EXE'
        )
        if (-not $SkipGaming) {
            $ProfileWinget += 'Valve.Steam'
        }
    }

    $AllWinget = $CommonWinget + $ProfileWinget

    # Install via Winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget source update --accept-source-agreements 2>$null

        foreach ($Package in $AllWinget) {
            Write-Info "Installing $Package..."
            winget install --id $Package --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        }
        Write-Success "Winget packages installed"
    } else {
        Write-Warning "Winget not available. Install packages manually."
    }

    # Common Chocolatey packages
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $ChocoPackages = @('python', 'python3', 'uv', 'pandoc', 'bind-toolsonly', 'grype', 'syft')

        foreach ($Package in $ChocoPackages) {
            Write-Info "Installing $Package via Chocolatey..."
            choco install $Package -y --no-progress 2>&1 | Out-Null
        }
        Write-Success "Chocolatey packages installed"
    }
}

# Show post-installation tasks
function Show-PostInstallation {
    Write-Section "Setup Complete!"

    Write-Success "Windows 11 setup has been completed successfully"
    Write-Info "Log file: $LogFile"
    Write-Info ""

    Write-Info "NEXT STEPS:"
    Write-Info ""
    Write-Info "1. REBOOT YOUR COMPUTER"
    Write-Info "   - Many changes require a restart to take effect"
    Write-Info ""
    Write-Info "2. After reboot, complete these tasks:"
    Write-Info ""
    Write-Info "   [*] Configure Docker Desktop"
    Write-Info "       - Open Docker Desktop and complete initial setup"
    Write-Info "       - Enable WSL2 integration"
    Write-Info ""
    Write-Info "   [*] Setup WSL2 Ubuntu"
    Write-Info "       - Run: wsl --install -d Ubuntu"
    Write-Info "       - Create username and password"
    Write-Info ""
    Write-Info "   [*] Generate SSH Keys"
    Write-Info "       - Run: ssh-keygen -t ed25519 -C 'your_email@example.com'"
    Write-Info "       - Add to GitHub/Gitea"
    Write-Info ""
    Write-Info "   [*] Configure Git"
    Write-Info "       - Set global name: git config --global user.name 'Your Name'"
    Write-Info "       - Set global email: git config --global user.email 'your@email.com'"
    Write-Info ""
    Write-Info "   [*] Sign in to applications"
    Write-Info "       - Browsers (Chrome, Brave, Edge)"
    Write-Info "       - VS Code (sync settings)"
    Write-Info "       - Microsoft Teams"
    Write-Info "       - OneDrive"
    Write-Info "       - ProtonVPN"
    Write-Info ""
    Write-Info "   [*] Configure PowerShell profile"
    Write-Info "       - Profile location: $PROFILE"
    Write-Info "       - Customize as needed"
    Write-Info ""
    Write-Info "3. OPTIONAL: Run additional setup scripts"
    Write-Info "   - SSH Agent: ..\ssh\setup-ssh-agent-access.ps1"
    Write-Info "   - Gitea Tunnel: ..\ssh\gitea-tunnel-manager.ps1 -Install"
    Write-Info ""

    Write-Warning "REBOOT REQUIRED - Restart your computer now to complete setup"
}

# Main execution
function Main {
    Show-Banner

    Write-Info "Starting Fresh Windows 11 Setup..."
    Write-Info "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($SetupProfile) {
        Write-Info "Profile: $SetupProfile"
    }
    Write-Info ""

    # Pre-flight checks
    Test-PowerShellVersion

    # Only check for exported package files if no profile specified
    if (-not $SetupProfile) {
        Test-RequiredFiles
    }

    # Show configuration and confirm
    Show-SetupSummary

    # Execute setup steps
    $StartTime = Get-Date

    # Use profile-based packages if profile specified, otherwise use exported packages
    if ($SetupProfile) {
        Install-ProfilePackages
    } else {
        Install-Packages
    }

    Set-SystemConfiguration

    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime

    # Completion
    Write-Info ""
    Write-Info "Setup duration: $($Duration.ToString('hh\:mm\:ss'))"

    Show-PostInstallation
}

# Error handling
try {
    Main
}
catch {
    Write-Error "Setup failed with error: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    Write-Info "Check log file for details: $LogFile"
    exit 1
}
