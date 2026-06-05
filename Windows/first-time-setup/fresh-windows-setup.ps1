# Fresh Windows 11 Setup - Master Script
# Complete automated setup for a new Windows 11 installation
# This script orchestrates the entire setup process
# Supports Work and Home profiles with different package sets
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0

# Note: admin privileges are enforced at runtime via Assert-Administrator in Main()
# rather than via #Requires, so this script can be dot-sourced for behavioral testing
# without a forced elevation.

[CmdletBinding()]
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

# Shared logging via CommonFunctions (Write-InfoMessage / Success / WarningMessage / ErrorMessage / Section)
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\lib\CommonFunctions.psm1') -Force

# Logging setup: mirror all CommonFunctions log lines to a per-run log file.
$LogDir = "$env:USERPROFILE\.setup-logs"
$LogFile = "$LogDir\fresh-windows-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Set-LogFile -Path $LogFile

# Display banner
function Show-Banner {
    $Banner = @"

    Windows 11 Fresh Installation Setup
    Automated Package & System Configuration

"@
    Write-Host $Banner -ForegroundColor Cyan
}

# Check PowerShell version
function Test-PowerShellVersion {
    Write-InfoMessage "Checking PowerShell version..."
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-ErrorMessage "PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)"
        Write-InfoMessage "Install PowerShell 7: https://github.com/PowerShell/PowerShell/releases"
        exit 1
    }
    Write-Success "PowerShell version: $($PSVersionTable.PSVersion)"
}

# Check for required files
function Test-RequiredFile {
    Write-InfoMessage "Checking for required package files..."

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
        Write-ErrorMessage "Missing required files:"
        $MissingFiles | ForEach-Object { Write-ErrorMessage "  - $_" }
        Write-InfoMessage "Run export-current-packages.ps1 on your working machine first"
        exit 1
    }

    Write-Success "All required files found"
}

# Show setup summary
function Show-SetupSummary {
    Write-Section "Setup Configuration"

    Write-InfoMessage "Setup Mode: $(if ($Minimal) { 'Minimal' } else { 'Full' })"
    Write-InfoMessage "Profile: $(if ($SetupProfile) { $SetupProfile } else { 'Exported Packages' })"
    Write-InfoMessage "Package Installation: $(if ($SkipPackageInstall) { 'SKIPPED' } else { 'ENABLED' })"
    Write-InfoMessage "System Configuration: $(if ($SkipSystemConfig) { 'SKIPPED' } else { 'ENABLED' })"
    Write-InfoMessage "WSL2 Setup: $(if ($SkipWSL) { 'SKIPPED' } else { 'ENABLED' })"
    if ($SetupProfile -eq 'Home') {
        Write-InfoMessage "Gaming Packages: $(if ($SkipGaming) { 'SKIPPED' } else { 'ENABLED' })"
    }
    Write-InfoMessage "Log File: $LogFile"

    Write-InfoMessage ""

    if (!$SkipPackageInstall) {
        if ($SetupProfile) {
            Write-InfoMessage "Package source: Profile-based ($SetupProfile)"
            if ($SetupProfile -eq 'Work') {
                Write-InfoMessage "  - Includes: Teams, Azure CLI, WatchGuard VPN"
                Write-InfoMessage "  - Dev directory: $env:USERPROFILE\Development"
            } else {
                Write-InfoMessage "  - Includes: Discord, Spotify, ProtonVPN, Ollama"
                if (-not $SkipGaming) { Write-InfoMessage "  - Includes: Steam" }
                Write-InfoMessage "  - Dev directory: C:\Code"
            }
        } else {
            $WingetFile = Join-Path $PSScriptRoot "winget-packages.json"
            $ChocoFile = Join-Path $PSScriptRoot "chocolatey-packages.config"

            if (Test-Path $WingetFile) {
                $WingetCount = (Get-Content $WingetFile | ConvertFrom-Json).Sources.Packages.Count
                Write-InfoMessage "  - Winget: $WingetCount packages"
            }
            if (Test-Path $ChocoFile) {
                [xml]$ChocoXml = Get-Content $ChocoFile
                $ChocoCount = $ChocoXml.packages.package.Count
                Write-InfoMessage "  - Chocolatey: $ChocoCount packages"
            }
        }
    }

    Write-InfoMessage ""
    Write-WarningMessage "This process will take 30-60 minutes depending on internet speed"
    Write-InfoMessage "Press Ctrl+C to cancel, or any other key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Install packages
function Install-Package {
    if ($SkipPackageInstall) {
        Write-InfoMessage "Skipping package installation (as requested)"
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

    Write-InfoMessage "Running package installation script..."
    Write-InfoMessage "Script: $ScriptPath"

    & $ScriptPath @InstallArgs

    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Write-WarningMessage "Package installation completed with warnings"
    } else {
        Write-Success "Package installation completed"
    }
}

# Configure system based on profile
function Set-SystemConfiguration {
    if ($SkipSystemConfig) {
        Write-InfoMessage "Skipping system configuration (as requested)"
        return
    }

    Write-Section "Configuring System Settings"

    # Configure Windows settings (common to all profiles)
    Write-InfoMessage "Applying Windows settings..."
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
        Write-WarningMessage "Some Windows settings could not be applied: $($_.Exception.Message)"
    }

    # Setup development directories based on profile
    Write-InfoMessage "Setting up development directories..."
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
    Write-InfoMessage "Configuring Git..."
    if (Get-Command git -ErrorAction SilentlyContinue) {
        git config --global init.defaultBranch main
        git config --global pull.rebase false
        git config --global core.autocrlf true
        git config --global core.editor "code --wait"
        Write-Success "Git configured with VS Code as default editor"
    } else {
        Write-WarningMessage "Git not found. Install Git first, then configure manually."
    }

    # WSL2 setup (Work profile or if not skipped)
    if (-not $SkipWSL -and ($SetupProfile -eq 'Work' -or $null -eq $SetupProfile)) {
        Write-InfoMessage "Setting up WSL2..."
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction SilentlyContinue | Out-Null
            wsl --set-default-version 2 2>$null
            Write-Success "WSL2 enabled (run 'wsl --install -d Ubuntu' after reboot)"
        } catch {
            Write-WarningMessage "WSL2 setup failed: $($_.Exception.Message)"
        }
    }

    Write-Success "System configuration completed"
}

# Install profile-specific packages
function Install-ProfilePackage {
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

    # Install via Winget with error handling
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        # try winget installations with error handling
        try {
            winget source update --accept-source-agreements 2>$null

            foreach ($Package in $AllWinget) {
                Write-InfoMessage "Installing $Package..."
                try {
                    winget install --id $Package --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
                }
                catch {
                    Write-WarningMessage "Failed to install winget package $Package : $($_.Exception.Message)"
                }
            }
            Write-Success "Winget packages installed"
        }
        catch {
            Write-ErrorMessage "Winget installation error: $($_.Exception.Message)"
        }
    } else {
        Write-WarningMessage "Winget not available. Install packages manually."
    }

    # Common Chocolatey packages with error handling
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $ChocoPackages = @('python', 'python3', 'uv', 'pandoc', 'bind-toolsonly', 'grype', 'syft')

        # try choco installations with error handling
        try {
            foreach ($Package in $ChocoPackages) {
                Write-InfoMessage "Installing $Package via Chocolatey..."
                try {
                    choco install $Package -y --no-progress 2>&1 | Out-Null
                }
                catch {
                    Write-WarningMessage "Failed to install choco package $Package : $($_.Exception.Message)"
                }
            }
            Write-Success "Chocolatey packages installed"
        }
        catch {
            Write-ErrorMessage "Chocolatey installation error: $($_.Exception.Message)"
        }
    }
}

# Show post-installation tasks
function Show-PostInstallation {
    Write-Section "Setup Complete!"

    Write-Success "Windows 11 setup has been completed successfully"
    Write-InfoMessage "Log file: $LogFile"
    Write-InfoMessage ""

    Write-InfoMessage "NEXT STEPS:"
    Write-InfoMessage ""
    Write-InfoMessage "1. REBOOT YOUR COMPUTER"
    Write-InfoMessage "   - Many changes require a restart to take effect"
    Write-InfoMessage ""
    Write-InfoMessage "2. After reboot, complete these tasks:"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Configure Docker Desktop"
    Write-InfoMessage "       - Open Docker Desktop and complete initial setup"
    Write-InfoMessage "       - Enable WSL2 integration"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Setup WSL2 Ubuntu"
    Write-InfoMessage "       - Run: wsl --install -d Ubuntu"
    Write-InfoMessage "       - Create username and password"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Generate SSH Keys"
    Write-InfoMessage "       - Run: ssh-keygen -t ed25519 -C 'your_email@example.com'"
    Write-InfoMessage "       - Add to GitHub/Gitea"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Configure Git"
    Write-InfoMessage "       - Set global name: git config --global user.name 'Your Name'"
    Write-InfoMessage "       - Set global email: git config --global user.email 'your@email.com'"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Sign in to applications"
    Write-InfoMessage "       - Browsers (Chrome, Brave, Edge)"
    Write-InfoMessage "       - VS Code (sync settings)"
    Write-InfoMessage "       - Microsoft Teams"
    Write-InfoMessage "       - OneDrive"
    Write-InfoMessage "       - ProtonVPN"
    Write-InfoMessage ""
    Write-InfoMessage "   [*] Configure PowerShell profile"
    Write-InfoMessage "       - Profile location: $PROFILE"
    Write-InfoMessage "       - Customize as needed"
    Write-InfoMessage ""
    Write-WarningMessage "REBOOT REQUIRED - Restart your computer now to complete setup"
}

# Main execution
function Main {
    Assert-Administrator

    Show-Banner

    Write-InfoMessage "Starting Fresh Windows 11 Setup..."
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($SetupProfile) {
        Write-InfoMessage "Profile: $SetupProfile"
    }
    Write-InfoMessage ""

    # Pre-flight checks
    Test-PowerShellVersion

    # Only check for exported package files if no profile specified
    if (-not $SetupProfile) {
        Test-RequiredFile
    }

    # Show configuration and confirm
    Show-SetupSummary

    # Execute setup steps
    $StartTime = Get-Date

    # Use profile-based packages if profile specified, otherwise use exported packages
    if ($SetupProfile) {
        Install-ProfilePackage
    } else {
        Install-Package
    }

    Set-SystemConfiguration

    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime

    # Completion
    Write-InfoMessage ""
    Write-InfoMessage "Setup duration: $($Duration.ToString('hh\:mm\:ss'))"

    Show-PostInstallation
}

# Run Main when invoked as a script. When dot-sourced for testing, skip auto-run
# so test files can load function definitions into scope and exercise them with mocks.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main
    }
    catch {
        Write-ErrorMessage "Setup failed with error: $($_.Exception.Message)"
        Write-ErrorMessage "Stack trace: $($_.ScriptStackTrace)"
        Write-InfoMessage "Check log file for details: $LogFile"
        exit 1
    }
}
