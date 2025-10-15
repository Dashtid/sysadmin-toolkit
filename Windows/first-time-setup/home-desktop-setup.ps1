# Windows 11 Home Desktop Setup Script
# Personal desktop setup for home use (development, gaming, personal productivity)
# Run as Administrator in PowerShell 7+
# NO WORK/CORPORATE TOOLS - This is for personal home desktop only

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [switch]$SkipChocolatey,
    [switch]$SkipWinget,
    [switch]$SkipGaming,
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
$LogFile = "$LogDir\home-desktop-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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

# Display banner
function Show-Banner {
    $Banner = @"

    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        Windows 11 Home Desktop Setup                    ║
    ║        Personal Development & Gaming Environment        ║
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

# Install packages via Chocolatey
function Install-ChocolateyPackages {
    if ($SkipChocolatey -or !(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Skipping Chocolatey packages"
        return
    }

    Write-Info "Installing packages via Chocolatey..."

    # Core development tools - Python focused
    $DevelopmentPackages = @(
        'git',
        'python',
        'python3',
        'uv',                          # Modern Python package manager
        'pandoc',                      # Document converter
        'tesseract',                   # OCR engine
        'bind-toolsonly',              # DNS tools (dig, nslookup)
        'grype',                       # Security scanner
        'syft'                         # SBOM generator
    )

    # CLI tools
    $CLIPackages = @(
        'azure-cli',                   # Azure command line
        'powershell-core'              # PowerShell 7
    )

    # Personal productivity
    $ProductivityPackages = @(
        'obsidian',                    # Note-taking
        'notepadplusplus',             # Text editor
        'spotify',                     # Music
        'discord'                      # Communication
    )

    # Gaming (skip if -SkipGaming)
    $GamingPackages = @(
        'steam'                        # Gaming platform
    )

    $AllPackages = $DevelopmentPackages + $CLIPackages + $ProductivityPackages

    if (-not $SkipGaming) {
        $AllPackages += $GamingPackages
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

# Setup Winget and install packages
function Install-WingetPackages {
    if ($SkipWinget) {
        Write-Info "Skipping Winget packages"
        return
    }

    Write-Info "Setting up Winget packages..."

    if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "Winget not available. Please update Windows or install App Installer from Microsoft Store"
        return
    }

    # Accept source agreements
    winget source update --accept-source-agreements

    # Development tools
    $DevPackages = @(
        'Microsoft.VisualStudioCode',  # Code editor
        'Git.Git',                      # Version control
        'Docker.DockerDesktop',         # Containers
        'OpenJS.NodeJS',                # JavaScript runtime (for VS Code extensions)
        'CoreyButler.NVMforWindows',   # Node version manager
        'GitHub.cli',                   # GitHub CLI
        'Microsoft.PowerShell',         # PowerShell 7
        'Microsoft.AzureCLI',           # Azure CLI
        'JohnMacFarlane.Pandoc',        # Document converter
        'PuTTY.PuTTY',                  # SSH client
        'WinSCP.WinSCP'                 # SFTP/SCP client
    )

    # Browsers
    $BrowserPackages = @(
        'Google.Chrome',
        'Microsoft.Edge',
        'Brave.Brave'
    )

    # Personal productivity & communication
    $ProductivityPackages = @(
        'Obsidian.Obsidian',            # Note-taking
        'Notepad++.Notepad++',          # Text editor
        'geeksoftwareGmbH.PDF24Creator',# PDF tools
        'Ollama.Ollama',                # Local LLM
        'Proton.ProtonVPN',             # VPN
        'Proton.ProtonMail',            # Email client
        'RevoUninstaller.RevoUninstaller', # Uninstaller
        'OpenVPNTechnologies.OpenVPN',  # VPN client
        'Logitech.OptionsPlus',         # Mouse/keyboard
        'Zoom.Zoom.EXE',                # Video conferencing
        'Discord.Discord',              # Communication
        'Spotify.Spotify'               # Music
    )

    # Utilities
    $UtilityPackages = @(
        'MicroDicom.DICOMViewer'       # Medical imaging
    )

    $AllPackages = $DevPackages + $BrowserPackages + $ProductivityPackages + $UtilityPackages

    foreach ($Package in $AllPackages) {
        try {
            Write-Info "Installing $Package via Winget..."
            winget install --id $Package --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            Write-Success "$Package installed"
        }
        catch {
            Write-Warning "Failed to install ${Package}: $($_.Exception.Message)"
        }
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
        Write-Info "Git user not configured. You can configure it later with:"
        Write-Info "  git config --global user.name 'Your Name'"
    }

    if (-not $GitEmail) {
        Write-Info "Git email not configured. You can configure it later with:"
        Write-Info "  git config --global user.email 'your@email.com'"
    }

    # Configure Git settings
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    git config --global core.autocrlf true
    git config --global core.editor "code --wait"

    Write-Success "Git configured with VS Code as default editor"
}

# Setup development directories
function Setup-DevelopmentDirectories {
    Write-Info "Setting up development directories..."

    $CodeDir = "C:\Code"
    $Directories = @(
        "$CodeDir",
        "$CodeDir\personal",
        "$CodeDir\learning",
        "$CodeDir\projects"
    )

    foreach ($Dir in $Directories) {
        if (!(Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }

    Write-Success "Development directories created at: $CodeDir"
}

# Configure Windows settings
function Configure-WindowsSettings {
    Write-Info "Configuring Windows settings..."

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

        Write-Success "Windows settings configured"
        Write-Warning "Some settings require Explorer restart or reboot"
    }
    catch {
        Write-Warning "Some Windows settings could not be configured: $($_.Exception.Message)"
    }
}

# Install Python packages
function Install-PythonPackages {
    Write-Info "Installing common Python packages via uv..."

    if (!(Get-Command uv -ErrorAction SilentlyContinue)) {
        Write-Warning "uv not found. Skipping Python package installation"
        return
    }

    # Common Python tools
    $PythonTools = @(
        'pipx',            # Install Python apps
        'black',           # Code formatter
        'ruff',            # Linter
        'pytest',          # Testing
        'ipython',         # Better REPL
        'requests',        # HTTP library
        'pandas',          # Data analysis
        'numpy'            # Numerical computing
    )

    foreach ($Tool in $PythonTools) {
        try {
            Write-Info "Installing Python package: $Tool..."
            uv tool install $Tool 2>&1 | Out-Null
        }
        catch {
            Write-Warning "Failed to install ${Tool}: $($_.Exception.Message)"
        }
    }

    Write-Success "Python packages installed"
}

# Show post-installation tasks
function Show-PostInstallation {
    Write-Success "`n[*] Home Desktop Setup Complete!"
    Write-Info ""
    Write-Info "Log file: $LogFile"
    Write-Info ""
    Write-Info "NEXT STEPS:"
    Write-Info ""
    Write-Info "1. REBOOT YOUR COMPUTER"
    Write-Info ""
    Write-Info "2. Configure Git (if not done):"
    Write-Info "   git config --global user.name 'Your Name'"
    Write-Info "   git config --global user.email 'your@email.com'"
    Write-Info ""
    Write-Info "3. Generate SSH keys for GitHub:"
    Write-Info "   ssh-keygen -t ed25519 -C 'your_email@example.com'"
    Write-Info ""
    Write-Info "4. Sign in to applications:"
    Write-Info "   - Browsers (Chrome, Brave, Edge)"
    Write-Info "   - VS Code (Settings Sync)"
    Write-Info "   - Discord"
    Write-Info "   - Spotify"
    Write-Info "   - ProtonVPN"
    Write-Info "   - ProtonMail"
    Write-Info ""
    Write-Info "5. Start Docker Desktop and complete setup"
    Write-Info ""
    Write-Info "6. Python development ready at: C:\Code"
    Write-Info ""
    Write-Info "SECURITY REMINDER:"
    Write-Info "   This is a PERSONAL HOME desktop"
    Write-Info "   DO NOT connect to work VPNs or corporate networks"
    Write-Info "   DO NOT install work-related software"
    Write-Info ""
    Write-Warning "REBOOT REQUIRED - Restart to complete setup"
}

# Main execution function
function Main {
    Show-Banner

    Write-Info "Starting Windows 11 Home Desktop Setup..."
    Write-Info "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Info ""

    $StartTime = Get-Date

    Test-PowerShellVersion
    Install-Chocolatey
    Install-ChocolateyPackages
    Install-WingetPackages
    Configure-Git
    Setup-DevelopmentDirectories
    Configure-WindowsSettings
    Install-PythonPackages

    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime

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
