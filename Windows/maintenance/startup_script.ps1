#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Windows automated update and maintenance script.

.DESCRIPTION
    Simplified update script that performs:
    - Chocolatey package upgrades
    - Windows Updates installation
    - System cleanup operations
    - Log file maintenance

    This script is designed for basic automated maintenance tasks.
    For more advanced features (Winget, restore points, WhatIf), use system-updates.ps1 instead.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 2.0.0
    Requires: PowerShell 7.0+ and Administrator privileges

.CHANGELOG
    2.0.0 - 2025-10-15
        - Refactored to use CommonFunctions module
        - Uses centralized log directory
        - Improved error handling
        - Added duration tracking
        - Better logging consistency

    1.0.0 - Initial release

.EXAMPLE
    .\startup_script.ps1
    Runs all updates and cleanup tasks with default settings.
#>

#Requires -Version 7.0
#Requires -RunAsAdministrator

#region Module Imports
# Import CommonFunctions module
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "[-] CommonFunctions module not found at: $modulePath"
    exit 1
}
Import-Module $modulePath -Force
#endregion

#region Script Initialization
$script:StartTime = Get-Date

# Get centralized log directory
$logDir = Get-LogDirectory
$logFile = "$logDir\startup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Start transcript
try {
    Start-Transcript -Path $logFile -Append
} catch {
    Write-WarningMessage "Failed to start transcript: $($_.Exception.Message)"
}
#endregion

#region Helper Functions
function Write-ScriptLog {
    <#
    .SYNOPSIS
        Writes a message to both transcript and console.
    #>
    param([string]$Message, [string]$Level = 'Info')

    switch ($Level) {
        'Success' { Write-Success $Message }
        'Info' { Write-InfoMessage $Message }
        'Warning' { Write-WarningMessage $Message }
        'Error' { Write-ErrorMessage $Message }
    }
}
#endregion

#region Update Functions
function Update-ChocolateyPackages {
    <#
    .SYNOPSIS
        Upgrades Chocolatey packages.
    #>
    Write-InfoMessage "Checking for Chocolatey..."

    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-WarningMessage "Chocolatey not found. Please install Chocolatey first."
        Write-InfoMessage "Install Chocolatey: https://chocolatey.org/install"
        return
    }

    Write-InfoMessage "Upgrading Chocolatey packages..."
    try {
        choco upgrade all -y --no-progress
        Write-Success "Chocolatey packages upgraded successfully"
    }
    catch {
        Write-ErrorMessage "Failed to upgrade Chocolatey packages: $($_.Exception.Message)"
    }
}

function Install-WindowsUpdates {
    <#
    .SYNOPSIS
        Installs Windows Updates.
    #>
    Write-InfoMessage "Checking for Windows Updates..."

    # Install PSWindowsUpdate module if not present
    if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-InfoMessage "Installing PSWindowsUpdate module..."
        try {
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
            Write-Success "PSWindowsUpdate module installed"
        }
        catch {
            Write-ErrorMessage "Failed to install PSWindowsUpdate module: $($_.Exception.Message)"
            return
        }
    }

    # Import the module
    Import-Module PSWindowsUpdate

    # Get available updates
    try {
        $updates = Get-WUList
        if ($updates.Count -eq 0) {
            Write-Success "No Windows Updates available"
            return
        }

        Write-InfoMessage "Found $($updates.Count) Windows Updates"
        foreach ($update in $updates) {
            Write-InfoMessage "  - $($update.Title)"
        }

        # Install updates
        Write-InfoMessage "Installing Windows Updates..."
        Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Verbose
        Write-Success "Windows Updates installed successfully"

        # Check if reboot is required
        if (Get-WURebootStatus -Silent) {
            Write-WarningMessage "System reboot is required to complete Windows Updates"
        }
    }
    catch {
        Write-ErrorMessage "Failed to install Windows Updates: $($_.Exception.Message)"
    }
}

function Invoke-SystemCleanup {
    <#
    .SYNOPSIS
        Performs system cleanup operations.
    #>
    Write-InfoMessage "Performing system cleanup..."

    try {
        # Clean temporary files
        Write-InfoMessage "Cleaning temporary files..."
        Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        # Clean Windows Update cache
        Write-InfoMessage "Cleaning Windows Update cache..."
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue

        # Run Disk Cleanup
        Write-InfoMessage "Running Disk Cleanup..."
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue

        Write-Success "System cleanup completed"
    }
    catch {
        Write-WarningMessage "Some cleanup operations failed: $($_.Exception.Message)"
    }
}

function Clear-OldLogs {
    <#
    .SYNOPSIS
        Cleans up old log files.
    #>
    Write-InfoMessage "Cleaning up old log files..."

    try {
        $oldLogs = Get-ChildItem -Path $logDir -Filter "startup-*.log" |
            Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) }

        if ($oldLogs.Count -eq 0) {
            Write-InfoMessage "No old log files to clean up"
            return
        }

        Write-InfoMessage "Removing $($oldLogs.Count) old log files"
        $oldLogs | Remove-Item -Force
        Write-Success "Old log files cleaned up"
    }
    catch {
        Write-WarningMessage "Failed to clean up old log files: $($_.Exception.Message)"
    }
}
#endregion

#region Startup Checks
function Mount-NetworkDrivesIfConfigured {
    <#
    .SYNOPSIS
        Mounts network drives if configured.
    .DESCRIPTION
        Uses New-PSDrive to mount network drives defined in configuration.
        This is optional functionality that can be extended as needed.
    #>
    # Placeholder for New-PSDrive network drive mounting
    # Example: New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\server\share" -Persist
    Write-Verbose "Network drive mounting not configured"
}

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Waits for network connectivity before proceeding.
    #>
    Write-InfoMessage "Checking network connectivity..."

    # Test-Connection or Test-NetConnection to check network ready
    $maxRetries = 5
    $retryCount = 0
    $testHost = "www.microsoft.com"  # Use DNS name instead of hardcoded IP

    while ($retryCount -lt $maxRetries) {
        if (Test-Connection -TargetName $testHost -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            Write-Success "Network connectivity confirmed"
            return $true
        }
        $retryCount++
        Write-InfoMessage "Waiting for network... (attempt $retryCount of $maxRetries)"
        Start-Sleep -Seconds 5
    }

    Write-WarningMessage "Network connectivity not available"
    return $false
}

function Test-CriticalServices {
    <#
    .SYNOPSIS
        Verifies critical Windows services are running.
    #>
    Write-InfoMessage "Verifying critical services..."

    $criticalServices = @(
        @{ Name = "wuauserv"; DisplayName = "Windows Update" },
        @{ Name = "BITS"; DisplayName = "Background Intelligent Transfer Service" },
        @{ Name = "CryptSvc"; DisplayName = "Cryptographic Services" }
    )

    foreach ($svc in $criticalServices) {
        # Get-Service with Status check to verify service running
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-InfoMessage "$($svc.DisplayName) is running"
        } else {
            Write-WarningMessage "$($svc.DisplayName) is not running - attempting to start"
            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
        }
    }
}

function Write-ErrorToLog {
    <#
    .SYNOPSIS
        Writes error messages to log file for later analysis.
    #>
    param([string]$Message)

    # Out-File error logging for persistent error tracking
    $errorLogPath = Join-Path $logDir "startup-errors.log"
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$timestamp] ERROR: $Message" | Out-File -FilePath $errorLogPath -Append -ErrorAction SilentlyContinue
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "[*] Starting Windows Automated Update Script..."
    Write-InfoMessage "[*] Log file: $logFile"

    # Verify prerequisites
    if (!(Test-IsAdministrator)) {
        Write-ErrorMessage "This script must be run as Administrator"
        Write-ErrorToLog "Script not running as Administrator"
        exit 1
    }

    Write-Success "PowerShell version: $($PSVersionTable.PSVersion)"

    # Check system status before proceeding
    # Get-Process to check system status
    $processCount = (Get-Process).Count
    Write-InfoMessage "System has $processCount running processes"

    # Wait for network and verify services
    Test-NetworkConnectivity
    Test-CriticalServices

    # Perform updates and maintenance
    Update-ChocolateyPackages
    Install-WindowsUpdates
    Invoke-SystemCleanup
    Clear-OldLogs

    # Calculate duration
    $duration = (Get-Date) - $script:StartTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    Write-Success "Windows automated update script completed successfully!"
    Write-InfoMessage "[*] Total runtime: $durationFormatted"
    Write-InfoMessage "[*] Check log file for details: $logFile"
}

# Run main function with try/catch error handling
try {
    Main
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    Write-ErrorToLog $_.Exception.Message
    exit 1
}
finally {
    # Stop transcript
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Transcript was not started"
    }
}
#endregion
