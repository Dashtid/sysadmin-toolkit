#!/usr/bin/env pwsh

using namespace System.Security.Principal

# Get the script's directory
$scriptPath = $PSScriptRoot
$logFolder = Join-Path -Path $scriptPath -ChildPath "logs"
$logFile = Join-Path -Path $logFolder -ChildPath "updates_$(Get-Date -Format 'yyyy-MM-dd').log"

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
    
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage -ForegroundColor $Color
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-LogMessage "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)" -Color Red
    exit 1
}

# Start logging
Write-LogMessage "=== Update Script Started ===" -Color Cyan
Write-LogMessage "PowerShell Version: $($PSVersionTable.PSVersion)" -Color Gray

# Elevate to admin if needed
$isAdmin = [WindowsPrincipal]::new([WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {    
    Write-LogMessage "Requesting administrative privileges..." -Color Yellow
    Start-Process pwsh -Verb RunAs -ArgumentList "-File `"$PSCommandPath`"" -Wait
    exit
}

# 1. WinGet Updates
Write-LogMessage "=== Starting WinGet Updates ===" -Color Cyan
try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-LogMessage "Upgrading WinGet packages..." -Color Yellow
        $wingetOutput = & winget upgrade --all --include-unknown --silent --accept-source-agreements --accept-package-agreements
        Write-LogMessage ($wingetOutput | Out-String)
        Write-LogMessage "WinGet updates completed" -Color Green
    }
    else {
        Write-LogMessage "WinGet not available" -Color Yellow
    }
}
catch {
    Write-LogMessage "Error updating WinGet packages: $($_.Exception.Message)" -Color Red
}

# 2. Chocolatey Updates
Write-LogMessage "=== Starting Chocolatey Updates ===" -Color Cyan
try {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-LogMessage "Upgrading Chocolatey packages..." -Color Yellow
        $chocoOutput = & choco upgrade all -y
        Write-LogMessage ($chocoOutput | Out-String)
        Write-LogMessage "Chocolatey updates completed" -Color Green
    }
    else {
        Write-LogMessage "Chocolatey not available" -Color Yellow
    }
}
catch {
    Write-LogMessage "Error updating Chocolatey packages: $($_.Exception.Message)" -Color Red
}

# 3. Windows Updates
Write-LogMessage "=== Starting Windows Updates ===" -Color Cyan
try {
    if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-LogMessage "Installing PSWindowsUpdate module..." -Color Yellow
        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
    }
    
    Import-Module PSWindowsUpdate
    
    Write-LogMessage "Checking for Windows Updates..." -Color Yellow
    $updates = Get-WindowsUpdate
    
    if ($null -ne $updates -and $updates.Count -gt 0) {
        Write-LogMessage "Found $($updates.Count) updates available" -Color Yellow
        Write-LogMessage "Installing Windows Updates..." -Color Yellow
        $updateResults = Install-WindowsUpdate -AcceptAll -AutoReboot:$false
        Write-LogMessage ($updateResults | Out-String)
        Write-LogMessage "Windows Updates completed" -Color Green
    }
    else {
        Write-LogMessage "No Windows Updates available" -Color Green
    }
}
catch {
    Write-LogMessage "Error with Windows Updates: $($_.Exception.Message)" -Color Red
}

# Cleanup old logs (keep last 30 days)
$oldLogs = Get-ChildItem -Path $logFolder -Filter "*.log" | 
Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
if ($oldLogs) {
    Write-LogMessage "Cleaning up old logs..." -Color Gray
    $oldLogs | Remove-Item -Force
}

Write-LogMessage "=== Script Completed ===" -Color Green