# Install Packages from Exported Lists
# This script installs all packages from previously exported Winget and Chocolatey lists
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [string]$PackageDir = "$PSScriptRoot",
    [switch]$SkipWinget,
    [switch]$SkipChocolatey,
    [switch]$UseLatestVersions  # Install latest versions instead of pinned versions
)

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
}

# Logging setup
$LogDir = "$env:USERPROFILE\.setup-logs"
$LogFile = "$LogDir\package-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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

# Install Chocolatey if needed
function Install-Chocolatey {
    if ($SkipChocolatey) {
        Write-Info "Skipping Chocolatey installation"
        return
    }

    Write-Info "Checking Chocolatey installation..."

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        Write-Info "Upgrading Chocolatey to latest version..."
        choco upgrade chocolatey -y
        return
    }

    try {
        Write-Info "Installing Chocolatey package manager..."
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

# Install packages from Winget export
function Install-WingetPackages {
    if ($SkipWinget) {
        Write-Info "Skipping Winget package installation"
        return
    }

    $WingetFile = Join-Path $PackageDir "winget-packages.json"

    if (!(Test-Path $WingetFile)) {
        Write-Warning "Winget package file not found: $WingetFile"
        Write-Info "Run export-current-packages.ps1 first to create the package list"
        return
    }

    Write-Info "Installing packages from Winget export..."

    if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Error "Winget not available. Please update Windows or install App Installer from Microsoft Store"
        Write-Info "Download: https://aka.ms/getwinget"
        return
    }

    try {
        # Accept source agreements upfront
        Write-Info "Accepting Winget source agreements..."
        winget source update --accept-source-agreements

        # Import packages
        $ImportArgs = @(
            'import',
            '-i', $WingetFile,
            '--accept-package-agreements',
            '--accept-source-agreements'
        )

        if ($UseLatestVersions) {
            Write-Info "Installing latest versions (ignoring version pins)..."
            $ImportArgs += '--ignore-versions'
        }
        else {
            Write-Info "Installing specific versions from export..."
        }

        Write-Info "Running: winget $($ImportArgs -join ' ')"
        & winget @ImportArgs

        Write-Success "Winget packages installation completed"
    }
    catch {
        Write-Error "Failed to install Winget packages: $($_.Exception.Message)"
    }
}

# Install packages from Chocolatey export
function Install-ChocolateyPackages {
    if ($SkipChocolatey) {
        Write-Info "Skipping Chocolatey package installation"
        return
    }

    $ChocoFile = Join-Path $PackageDir "chocolatey-packages.config"

    if (!(Test-Path $ChocoFile)) {
        Write-Warning "Chocolatey package file not found: $ChocoFile"
        Write-Info "Run export-current-packages.ps1 first to create the package list"
        return
    }

    Write-Info "Installing packages from Chocolatey export..."

    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Error "Chocolatey not available"
        return
    }

    try {
        # Read the packages.config file
        [xml]$ChocoConfig = Get-Content $ChocoFile
        $Packages = $ChocoConfig.packages.package

        if ($null -eq $Packages) {
            Write-Warning "No packages found in $ChocoFile"
            return
        }

        $TotalPackages = $Packages.Count
        Write-Info "Found $TotalPackages packages to install"

        # Install each package
        $Current = 0
        foreach ($Package in $Packages) {
            $Current++
            $PackageId = $Package.id
            $PackageVersion = $Package.version

            Write-Info "[$Current/$TotalPackages] Installing $PackageId..."

            try {
                if ($UseLatestVersions) {
                    choco install $PackageId -y --no-progress
                }
                else {
                    choco install $PackageId --version=$PackageVersion -y --no-progress
                }
                Write-Success "$PackageId installed"
            }
            catch {
                Write-Warning "Failed to install ${PackageId}: $($_.Exception.Message)"
            }
        }

        Write-Success "Chocolatey packages installation completed"
    }
    catch {
        Write-Error "Failed to process Chocolatey packages: $($_.Exception.Message)"
    }
}

# Refresh environment variables
function Refresh-Environment {
    Write-Info "Refreshing environment variables..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Success "Environment refreshed"
}

# Main execution function
function Main {
    Write-Info "Starting package installation from exported lists..."
    Write-Info "Package directory: $PackageDir"
    Write-Info "Log file: $LogFile"

    Test-PowerShellVersion
    Install-Chocolatey
    Install-ChocolateyPackages
    Install-WingetPackages
    Refresh-Environment

    Write-Success "Package installation completed!"
    Write-Info "Log saved to: $LogFile"
    Write-Info ""
    Write-Info "Next steps:"
    Write-Info "  1. Review the log file for any errors"
    Write-Info "  2. Restart your computer to ensure all changes take effect"
    Write-Info "  3. Configure installed applications as needed"
    Write-Info "  4. Run work-laptop-setup.ps1 for additional system configuration"
}

# Run main function
Main
