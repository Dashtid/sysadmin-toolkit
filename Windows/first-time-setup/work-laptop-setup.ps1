# Windows 11 Work Laptop Setup Script
# Comprehensive setup for development and work environment
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [switch]$SkipChocolatey,
    [switch]$SkipWinget,
    [switch]$SkipWSL,
    [switch]$Minimal
)

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
}

# Logging setup
$LogDir = "$env:USERPROFILE\.setup-logs"
$LogFile = "$LogDir\work-laptop-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogMessage
}

function Write-Success { param([string]$Message) Write-Log "✅ $Message" -Color $Colors.Green }
function Write-Info { param([string]$Message) Write-Log "ℹ️ $Message" -Color $Colors.Blue }
function Write-Warning { param([string]$Message) Write-Log "⚠️ $Message" -Color $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Log "❌ $Message" -Color $Colors.Red }

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

# Install Chocolatey
function Install-Chocolatey {
    if ($SkipChocolatey) {
        Write-Info "Skipping Chocolatey installation"
        return
    }

    Write-Info "Installing Chocolatey package manager..."
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        choco upgrade chocolatey -y
        return
    }

    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Success "Chocolatey installed successfully"
    }
    catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        return
    }
}

# Install essential packages via Chocolatey
function Install-ChocolateyPackages {
    if ($SkipChocolatey -or !(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Skipping Chocolatey packages"
        return
    }

    Write-Info "Installing essential packages via Chocolatey..."
    
    $EssentialPackages = @(
        'git',
        'vscode',
        'googlechrome',
        'firefox',
        'notepadplusplus',
        '7zip',
        'vlc',
        'putty',
        'winscp',
        'postman',
        'docker-desktop',
        'nodejs',
        'python',
        'golang',
        'rust',
        'jq',
        'curl',
        'wget',
        'grep',
        'sed',
        'awk',
        'which',
        'tree',
        'less'
    )

    $DevPackages = @(
        'visualstudio2022community',
        'jetbrainstoolbox',
        'github-desktop',
        'sourcetree',
        'fiddler',
        'wireshark',
        'sysinternals',
        'powertoys',
        'windows-terminal',
        'oh-my-posh'
    )

    $AllPackages = $EssentialPackages
    if (-not $Minimal) {
        $AllPackages += $DevPackages
    }

    foreach ($Package in $AllPackages) {
        try {
            Write-Info "Installing $Package..."
            choco install $Package -y --no-progress
            Write-Success "$Package installed"
        }
        catch {
            Write-Warning "Failed to install ${Package}: $($_.Exception.Message)"
        }
    }
}

# Setup Winget
function Setup-Winget {
    if ($SkipWinget) {
        Write-Info "Skipping Winget setup"
        return
    }

    Write-Info "Setting up Winget..."
    
    # Winget should be available on Windows 11
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Success "Winget is available"
        
        # Accept source agreements
        winget source update
        
        # Install additional packages via Winget
        $WingetPackages = @(
            'Microsoft.PowerShell',
            'Microsoft.WindowsTerminal',
            'Microsoft.PowerToys',
            'Microsoft.VisualStudioCode',
            'Git.Git',
            'GitHub.GitHubDesktop',
            'Docker.DockerDesktop',
            'Postman.Postman',
            'Google.Chrome',
            'Mozilla.Firefox',
            'Brave.Brave',
            'Discord.Discord',
            'Slack.Slack',
            'Zoom.Zoom',
            'Notion.Notion',
            'Obsidian.Obsidian'
        )

        foreach ($Package in $WingetPackages) {
            try {
                Write-Info "Installing $Package via Winget..."
                winget install --id $Package --silent --accept-package-agreements --accept-source-agreements
                Write-Success "$Package installed via Winget"
            }
            catch {
                Write-Warning "Failed to install ${Package} via Winget: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Warning "Winget not available. Please update Windows or install App Installer from Microsoft Store"
    }
}

# Setup WSL2
function Setup-WSL2 {
    if ($SkipWSL) {
        Write-Info "Skipping WSL2 setup"
        return
    }

    Write-Info "Setting up WSL2..."
    
    try {
        # Enable WSL feature
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        
        # Set WSL2 as default
        wsl --set-default-version 2
        
        # Install Ubuntu (most common distribution)
        Write-Info "Installing Ubuntu for WSL2..."
        wsl --install -d Ubuntu
        
        Write-Success "WSL2 setup completed"
        Write-Warning "Reboot required for WSL2 to work properly"
    }
    catch {
        Write-Warning "WSL2 setup failed: $($_.Exception.Message)"
        Write-Info "You may need to enable virtualization in BIOS"
    }
}

# Configure Windows features
function Configure-WindowsFeatures {
    Write-Info "Configuring Windows features..."
    
    # Enable useful Windows features
    $Features = @(
        'Microsoft-Hyper-V-All',
        'Containers',
        'Microsoft-Windows-Subsystem-Linux',
        'VirtualMachinePlatform'
    )

    foreach ($Feature in $Features) {
        try {
            Write-Info "Enabling $Feature..."
            Enable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart
            Write-Success "$Feature enabled"
        }
        catch {
            Write-Warning "Failed to enable ${Feature}: $($_.Exception.Message)"
        }
    }
}

# Install PowerShell modules
function Install-PowerShellModules {
    Write-Info "Installing useful PowerShell modules..."
    
    $Modules = @(
        'PSReadLine',
        'Terminal-Icons',
        'z',
        'PSFzf',
        'PowerShellGet',
        'PackageManagement',
        'posh-git',
        'oh-my-posh'
    )

    foreach ($Module in $Modules) {
        try {
            Write-Info "Installing PowerShell module: $Module..."
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
            Write-Success "$Module installed"
        }
        catch {
            Write-Warning "Failed to install ${Module}: $($_.Exception.Message)"
        }
    }
}

# Configure PowerShell profile
function Configure-PowerShellProfile {
    Write-Info "Configuring PowerShell profile..."
    
    $ProfileContent = @'
# PowerShell Profile for Development

# Import modules
Import-Module Terminal-Icons
Import-Module z
Import-Module PSFzf
Import-Module posh-git

# Oh My Posh theme
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\paradox.omp.json" | Invoke-Expression

# Aliases
Set-Alias -Name ll -Value Get-ChildItem
Set-Alias -Name la -Value Get-ChildItem
Set-Alias -Name grep -Value Select-String
Set-Alias -Name which -Value Get-Command
Set-Alias -Name cat -Value Get-Content
Set-Alias -Name touch -Value New-Item

# Functions
function .. { Set-Location .. }
function ... { Set-Location ../.. }
function .... { Set-Location ../../.. }

function Get-GitStatus { git status }
function Get-GitLog { git log --oneline -10 }
function Get-GitBranch { git branch }

Set-Alias -Name gs -Value Get-GitStatus
Set-Alias -Name gl -Value Get-GitLog
Set-Alias -Name gb -Value Get-GitBranch

# Docker aliases
function Get-DockerPS { docker ps }
function Get-DockerImages { docker images }
function Get-DockerContainers { docker ps -a }

Set-Alias -Name dps -Value Get-DockerPS
Set-Alias -Name di -Value Get-DockerImages
Set-Alias -Name dca -Value Get-DockerContainers

# System information
function Get-SystemInfo {
    Write-Host "System Information:" -ForegroundColor Green
    Write-Host "OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    Write-Host "User: $env:USERNAME"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Date: $(Get-Date)"
}

Set-Alias -Name sysinfo -Value Get-SystemInfo

# Welcome message
Write-Host "🚀 PowerShell Profile Loaded!" -ForegroundColor Green
Write-Host "Type 'sysinfo' for system information" -ForegroundColor Cyan
'@

    try {
        $ProfilePath = $PROFILE.CurrentUserAllHosts
        $ProfileDir = Split-Path $ProfilePath -Parent
        
        if (!(Test-Path $ProfileDir)) {
            New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
        }
        
        Set-Content -Path $ProfilePath -Value $ProfileContent -Encoding UTF8
        Write-Success "PowerShell profile configured at: $ProfilePath"
    }
    catch {
        Write-Warning "Failed to configure PowerShell profile: $($_.Exception.Message)"
    }
}

# Configure Git
function Configure-Git {
    Write-Info "Configuring Git..."
    
    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Warning "Git not found. Please install Git first."
        return
    }

    # Check if Git is already configured
    $GitUser = git config --global user.name 2>$null
    $GitEmail = git config --global user.email 2>$null

    if (-not $GitUser) {
        $GitUser = Read-Host "Enter your Git username"
        git config --global user.name $GitUser
    }

    if (-not $GitEmail) {
        $GitEmail = Read-Host "Enter your Git email"
        git config --global user.email $GitEmail
    }

    # Configure Git settings
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    git config --global core.autocrlf true
    git config --global core.editor "code --wait"
    git config --global merge.tool vscode
    git config --global mergetool.vscode.cmd "code --wait `$MERGED"
    git config --global diff.tool vscode
    git config --global difftool.vscode.cmd "code --wait --diff `$LOCAL `$REMOTE"

    Write-Success "Git configured for ${GitUser} (${GitEmail})"
}

# Setup development directories
function Setup-DevelopmentDirectories {
    Write-Info "Setting up development directories..."
    
    $DevDir = "$env:USERPROFILE\Development"
    $Directories = @(
        "$DevDir\Projects\Web",
        "$DevDir\Projects\Mobile",
        "$DevDir\Projects\Desktop",
        "$DevDir\Projects\Scripts",
        "$DevDir\Learning\Tutorials",
        "$DevDir\Learning\Courses",
        "$DevDir\Learning\Books",
        "$DevDir\Tools",
        "$DevDir\Scripts"
    )

    foreach ($Dir in $Directories) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }

    # Create README
    $ReadmeContent = @'
# Development Directory Structure

## Projects/
- **Web/**: Web development projects
- **Mobile/**: Mobile app projects  
- **Desktop/**: Desktop application projects
- **Scripts/**: Utility scripts and automation

## Learning/
- **Tutorials/**: Tutorial projects and exercises
- **Courses/**: Course materials and projects
- **Books/**: Book examples and exercises

## Tools/
- Development tools and utilities

## Scripts/
- Personal automation scripts
'@

    Set-Content -Path "$DevDir\README.md" -Value $ReadmeContent -Encoding UTF8
    Write-Success "Development directories created at: $DevDir"
}

# Configure Windows settings
function Configure-WindowsSettings {
    Write-Info "Configuring Windows settings for development..."
    
    try {
        # Show file extensions
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
        
        # Show hidden files
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
        
        # Enable dark mode
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
        
        # Disable web search in start menu
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
        
        # Set Windows Terminal as default
        if (Get-Command wt -ErrorAction SilentlyContinue) {
            # This requires manual setting in Windows Settings
            Write-Info "Set Windows Terminal as default in Settings > Privacy & Security > For developers"
        }
        
        Write-Success "Windows settings configured"
        Write-Warning "Some settings require a restart to take effect"
    }
    catch {
        Write-Warning "Some Windows settings could not be configured: $($_.Exception.Message)"
    }
}

# Create desktop shortcuts
function Create-DesktopShortcuts {
    Write-Info "Creating desktop shortcuts..."
    
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $WshShell = New-Object -comObject WScript.Shell

    # VS Code shortcut
    if (Test-Path "${env:ProgramFiles}\Microsoft VS Code\Code.exe") {
        $Shortcut = $WshShell.CreateShortcut("$Desktop\Visual Studio Code.lnk")
        $Shortcut.TargetPath = "${env:ProgramFiles}\Microsoft VS Code\Code.exe"
        $Shortcut.WorkingDirectory = "$env:USERPROFILE\Development"
        $Shortcut.Save()
    }

    # Windows Terminal shortcut
    $Shortcut = $WshShell.CreateShortcut("$Desktop\Windows Terminal.lnk")
    $Shortcut.TargetPath = "wt.exe"
    $Shortcut.WorkingDirectory = "$env:USERPROFILE\Development"
    $Shortcut.Save()

    Write-Success "Desktop shortcuts created"
}

# Main execution function
function Main {
    Write-Log "🚀 Starting Windows 11 Work Laptop Setup..." -Color $Colors.Cyan
    
    Test-PowerShellVersion
    Install-Chocolatey
    Install-ChocolateyPackages
    Setup-Winget
    Setup-WSL2
    Configure-WindowsFeatures
    Install-PowerShellModules
    Configure-PowerShellProfile
    Configure-Git
    Setup-DevelopmentDirectories
    Configure-WindowsSettings
    Create-DesktopShortcuts
    
    Write-Success "Windows 11 Work Laptop setup completed successfully!"
    Write-Log "📋 Setup log saved to: $LogFile" -Color $Colors.Blue
    
    Write-Info "🔄 Please reboot the system to ensure all changes take effect"
    Write-Info "🐋 After reboot, start Docker Desktop and complete setup"
    Write-Info "🐧 Complete WSL2 Ubuntu setup after reboot"
    Write-Info "🔑 Setup SSH keys for Git: ssh-keygen -t ed25519 -C 'your_email@example.com'"
    Write-Info "📁 Development directory: $env:USERPROFILE\Development"
    Write-Info "🎯 VS Code and development tools are ready"
    
    Write-Warning "Some applications may require manual configuration after installation"
}

# Run main function
Main
