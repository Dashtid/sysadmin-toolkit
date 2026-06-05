# Install Packages from Exported Lists
# This script installs all packages from previously exported Winget and Chocolatey lists
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0

# Note: admin privileges are enforced at runtime via Assert-Administrator in Main()
# rather than via #Requires, so this script can be dot-sourced for behavioral testing
# without a forced elevation.

[CmdletBinding()]
param(
    [string]$PackageDir = "$PSScriptRoot",
    [switch]$SkipWinget,
    [switch]$SkipChocolatey,
    [switch]$UseLatestVersions  # Install latest versions instead of pinned versions
)

# Shared logging via CommonFunctions (Write-InfoMessage / Success / WarningMessage / ErrorMessage / Section)
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\lib\CommonFunctions.psm1') -Force

# Logging setup: mirror all CommonFunctions log lines to a per-run log file.
$LogDir = "$env:USERPROFILE\.setup-logs"
$LogFile = "$LogDir\package-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Set-LogFile -Path $LogFile

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

# Install Chocolatey if needed
function Install-Chocolatey {
    if ($SkipChocolatey) {
        Write-InfoMessage "Skipping Chocolatey installation"
        return
    }

    Write-InfoMessage "Checking Chocolatey installation..."

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        Write-InfoMessage "Upgrading Chocolatey to latest version..."
        choco upgrade chocolatey -y
        return
    }

    try {
        Write-InfoMessage "Installing Chocolatey package manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

        $installScript = Join-Path $env:TEMP "chocolatey-install-$(Get-Date -Format 'yyyyMMddHHmmss').ps1"
        try {
            Invoke-WebRequest -Uri 'https://community.chocolatey.org/install.ps1' -OutFile $installScript -UseBasicParsing
            & $installScript
        }
        finally {
            Remove-Item $installScript -Force -ErrorAction SilentlyContinue
        }

        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        Write-Success "Chocolatey installed successfully"
    }
    catch {
        Write-ErrorMessage "Failed to install Chocolatey: $($_.Exception.Message)"
        return
    }
}

# Install packages from Winget export
function Install-WingetPackage {
    if ($SkipWinget) {
        Write-InfoMessage "Skipping Winget package installation"
        return
    }

    $WingetFile = Join-Path $PackageDir "winget-packages.json"

    if (!(Test-Path $WingetFile)) {
        Write-WarningMessage "Winget package file not found: $WingetFile"
        Write-InfoMessage "Run export-current-packages.ps1 first to create the package list"
        return
    }

    Write-InfoMessage "Installing packages from Winget export..."

    if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-ErrorMessage "Winget not available. Please update Windows or install App Installer from Microsoft Store"
        Write-InfoMessage "Download: https://aka.ms/getwinget"
        return
    }

    try {
        # Accept source agreements upfront
        Write-InfoMessage "Accepting Winget source agreements..."
        winget source update --accept-source-agreements

        # Import packages
        $ImportArgs = @(
            'import',
            '-i', $WingetFile,
            '--accept-package-agreements',
            '--accept-source-agreements'
        )

        if ($UseLatestVersions) {
            Write-InfoMessage "Installing latest versions (ignoring version pins)..."
            $ImportArgs += '--ignore-versions'
        }
        else {
            Write-InfoMessage "Installing specific versions from export..."
        }

        Write-InfoMessage "Running: winget $($ImportArgs -join ' ')"
        & winget @ImportArgs

        Write-Success "Winget packages installation completed"
    }
    catch {
        Write-ErrorMessage "Failed to install Winget packages: $($_.Exception.Message)"
    }
}

# Install packages from Chocolatey export
function Install-ChocolateyPackage {
    if ($SkipChocolatey) {
        Write-InfoMessage "Skipping Chocolatey package installation"
        return
    }

    $ChocoFile = Join-Path $PackageDir "chocolatey-packages.config"

    if (!(Test-Path $ChocoFile)) {
        Write-WarningMessage "Chocolatey package file not found: $ChocoFile"
        Write-InfoMessage "Run export-current-packages.ps1 first to create the package list"
        return
    }

    Write-InfoMessage "Installing packages from Chocolatey export..."

    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-ErrorMessage "Chocolatey not available"
        return
    }

    try {
        # Read the packages.config file
        [xml]$ChocoConfig = Get-Content $ChocoFile
        $Packages = $ChocoConfig.packages.package

        if ($null -eq $Packages) {
            Write-WarningMessage "No packages found in $ChocoFile"
            return
        }

        $TotalPackages = $Packages.Count
        Write-InfoMessage "Found $TotalPackages packages to install"

        # Install each package
        $Current = 0
        foreach ($Package in $Packages) {
            $Current++
            $PackageId = $Package.id
            $PackageVersion = $Package.version

            Write-InfoMessage "[$Current/$TotalPackages] Installing $PackageId..."

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
                Write-WarningMessage "Failed to install ${PackageId}: $($_.Exception.Message)"
            }
        }

        Write-Success "Chocolatey packages installation completed"
    }
    catch {
        Write-ErrorMessage "Failed to process Chocolatey packages: $($_.Exception.Message)"
    }
}

# Refresh environment variables
function Update-Environment {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('$env:Path (current process)', 'Refresh from machine + user PATH')) {
        Write-InfoMessage "Refreshing environment variables..."
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        Write-Success "Environment refreshed"
    }
}

# Main execution function
function Main {
    Assert-Administrator

    Write-InfoMessage "Starting package installation from exported lists..."
    Write-InfoMessage "Package directory: $PackageDir"
    Write-InfoMessage "Log file: $LogFile"

    Test-PowerShellVersion
    Install-Chocolatey
    Install-ChocolateyPackage
    Install-WingetPackage
    Update-Environment

    Write-Success "Package installation completed!"
    Write-InfoMessage "Log saved to: $LogFile"
    Write-InfoMessage ""
    Write-InfoMessage "Next steps:"
    Write-InfoMessage "  1. Review the log file for any errors"
    Write-InfoMessage "  2. Restart your computer to ensure all changes take effect"
    Write-InfoMessage "  3. Configure installed applications as needed"
    Write-InfoMessage "  4. Or run fresh-windows-setup.ps1 -Profile Work for complete setup"
}

# Run Main when invoked as a script. When dot-sourced for testing, skip auto-run
# so test files can load function definitions into scope and exercise them with mocks.
if ($MyInvocation.InvocationName -ne '.') {
    Main
}
