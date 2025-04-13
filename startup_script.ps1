#!/usr/bin/env pwsh

using namespace System.Security.Principal

# Get the script's directory
$scriptPath = $PSScriptRoot
$logFolder = Join-Path -Path $scriptPath -ChildPath "logs"
$logFile = Join-Path -Path $logFolder -ChildPath "security_updates_$(Get-Date -Format 'yyyy-MM-dd').log"

# Create logs directory if it doesn't exist
if (-not (Test-Path -Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}

# Function to write to both log and host
function Write-LogMessage {
    param(
        [string]$Message,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
    
    # Write to host with color
    Write-Host $logMessage -ForegroundColor $Color
}

# Check if running in PowerShell 7
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-LogMessage "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)" -Color Red
    Write-LogMessage "Please run this script with pwsh.exe instead of powershell.exe" -Color Red
    exit 1
}

# Start logging
Write-LogMessage "=== Script Started ===" -Color Cyan
Write-LogMessage "PowerShell Version: $($PSVersionTable.PSVersion)" -Color Gray
Write-LogMessage "Log file: $logFile" -Color Gray

# Elevate to admin privileges if not already running as admin
$isAdmin = [WindowsPrincipal]::new([WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {    
    Write-LogMessage "Requesting administrative privileges..." -Color Yellow
    Start-Process pwsh -Verb RunAs -ArgumentList "-File `"$PSCommandPath`"" -Wait
    exit
}

# 1. Upgrade Chocolatey packages
Write-LogMessage "=== Starting Chocolatey Updates ===" -Color Cyan
try {
    # Check if Chocolatey is installed
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        throw "Chocolatey is not installed. Please install it first."
    }
    
    $chocoOutput = & choco upgrade all -y
    Write-LogMessage ($chocoOutput | Out-String)
    Write-LogMessage "Chocolatey updates completed successfully" -Color Green
} catch {
    Write-LogMessage "Error updating Chocolatey packages: $($_.Exception.Message)" -Color Red
}

# 2. Check and Install Windows Updates
Write-LogMessage "=== Starting Windows Updates ===" -Color Cyan
try {
    # Install the PSWindowsUpdate module if not already installed
    if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-LogMessage "Installing PSWindowsUpdate module..." -Color Yellow
        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
    }
    
    Import-Module PSWindowsUpdate
    
    # Get available updates
    Write-LogMessage "Checking for available Windows Updates..." -Color Yellow
    $updates = Get-WindowsUpdate
    
    if ($null -ne $updates) {
        Write-LogMessage "Found $($updates.Count) updates available" -Color Yellow
        Write-LogMessage ($updates | Format-Table -AutoSize | Out-String)
        
        # Install updates if any are available
        Write-LogMessage "Installing Windows Updates..." -Color Yellow
        $updateResults = Install-WindowsUpdate -AcceptAll -AutoReboot:$false
        Write-LogMessage ($updateResults | Out-String)
    } else {
        Write-LogMessage "No Windows Updates available" -Color Green
    }
} catch {
    Write-LogMessage "Error checking Windows Updates: $($_.Exception.Message)" -Color Red
}

# Script completion
Write-LogMessage "=== Script Completed ===" -Color Green

# Cleanup old logs (keep last 30 days)
$oldLogs = Get-ChildItem -Path $logFolder -Filter "*.log" | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
if ($oldLogs) {
    Write-LogMessage "Cleaning up logs older than 30 days..." -Color Gray
    $oldLogs | ForEach-Object {
        Remove-Item $_.FullName -Force
        Write-LogMessage "Removed old log: $($_.Name)" -Color Gray
    }
}