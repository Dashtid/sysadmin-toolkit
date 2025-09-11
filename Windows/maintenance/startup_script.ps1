# Windows Automated Update Script
# Upgrades Chocolatey packages and installs Windows Updates
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
}

# Logging setup
$LogDir = "$PSScriptRoot\..\logs"
$LogFile = "$LogDir\startup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check PowerShell version
function Test-PowerShellVersion {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)"
        Write-Info "Install PowerShell 7: https://github.com/PowerShell/PowerShell/releases"
        exit 1
    }
    Write-Success "PowerShell version: $($PSVersionTable.PSVersion)"
}

# Upgrade Chocolatey packages
function Update-ChocolateyPackages {
    Write-Info "Checking for Chocolatey..."
    
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Warning "Chocolatey not found. Please install Chocolatey first."
        Write-Info "Install Chocolatey: https://chocolatey.org/install"
        return
    }
    
    Write-Info "Upgrading Chocolatey packages..."
    try {
        choco upgrade all -y --no-progress
        Write-Success "Chocolatey packages upgraded successfully"
    }
    catch {
        Write-Error "Failed to upgrade Chocolatey packages: $($_.Exception.Message)"
    }
}

# Install Windows Updates
function Install-WindowsUpdates {
    Write-Info "Checking for Windows Updates..."
    
    # Install PSWindowsUpdate module if not present
    if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Info "Installing PSWindowsUpdate module..."
        try {
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
            Write-Success "PSWindowsUpdate module installed"
        }
        catch {
            Write-Error "Failed to install PSWindowsUpdate module: $($_.Exception.Message)"
            return
        }
    }
    
    # Import the module
    Import-Module PSWindowsUpdate
    
    # Get available updates
    try {
        $Updates = Get-WUList
        if ($Updates.Count -eq 0) {
            Write-Success "No Windows Updates available"
            return
        }
        
        Write-Info "Found $($Updates.Count) Windows Updates"
        foreach ($Update in $Updates) {
            Write-Info "  - $($Update.Title)"
        }
        
        # Install updates
        Write-Info "Installing Windows Updates..."
        Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Verbose
        Write-Success "Windows Updates installed successfully"
        
        # Check if reboot is required
        if (Get-WURebootStatus -Silent) {
            Write-Warning "System reboot is required to complete Windows Updates"
        }
    }
    catch {
        Write-Error "Failed to install Windows Updates: $($_.Exception.Message)"
    }
}

# Clean up old log files
function Clear-OldLogs {
    Write-Info "Cleaning up old log files..."
    
    try {
        $OldLogs = Get-ChildItem -Path $LogDir -Filter "startup-*.log" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) }
        
        if ($OldLogs.Count -eq 0) {
            Write-Info "No old log files to clean up"
            return
        }
        
        Write-Info "Removing $($OldLogs.Count) old log files"
        $OldLogs | Remove-Item -Force
        Write-Success "Old log files cleaned up"
    }
    catch {
        Write-Warning "Failed to clean up old log files: $($_.Exception.Message)"
    }
}

# System cleanup
function Invoke-SystemCleanup {
    Write-Info "Performing system cleanup..."
    
    try {
        # Clean temporary files
        Write-Info "Cleaning temporary files..."
        Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        
        # Clean Windows Update cache
        Write-Info "Cleaning Windows Update cache..."
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        # Run Disk Cleanup
        Write-Info "Running Disk Cleanup..."
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        Write-Success "System cleanup completed"
    }
    catch {
        Write-Warning "Some cleanup operations failed: $($_.Exception.Message)"
    }
}

# Main execution
function Main {
    Write-Log "🚀 Starting Windows Automated Update Script..." -Color $Colors.Cyan
    Write-Log "📋 Log file: $LogFile" -Color $Colors.Blue
    
    # Verify prerequisites
    if (!(Test-Administrator)) {
        Write-Error "This script must be run as Administrator"
        exit 1
    }
    
    Test-PowerShellVersion
    
    # Perform updates and maintenance
    Update-ChocolateyPackages
    Install-WindowsUpdates
    Invoke-SystemCleanup
    Clear-OldLogs
    
    Write-Success "Windows automated update script completed successfully!"
    Write-Info "📊 Check log file for details: $LogFile"
    
    # Display summary
    $EndTime = Get-Date
    Write-Log "⏱️ Script completed at: $EndTime" -Color $Colors.Green
}

# Run main function
Main
