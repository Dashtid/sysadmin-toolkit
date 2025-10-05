#!/usr/bin/env pwsh

using namespace System.Security.Principal

#region Script Configuration
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipChocolatey,

    [Parameter()]
    [switch]$SkipWindowsUpdate,

    [Parameter()]
    [switch]$AutoReboot,

    [Parameter()]
    [int]$LogRetentionDays = 30,

    [Parameter()]
    [string]$ConfigFile
)

# Script initialization
$scriptPath = $PSScriptRoot
$logFolder = Join-Path -Path $scriptPath -ChildPath "logs"
$logFile = Join-Path -Path $logFolder -ChildPath "security_updates_$(Get-Date -Format 'yyyy-MM-dd').log"
$transcriptFile = Join-Path -Path $logFolder -ChildPath "transcript_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$configPath = Join-Path -Path $scriptPath -ChildPath "config.json"

# Initialize global configuration
$global:config = @{
    AutoReboot        = $AutoReboot.IsPresent
    LogRetentionDays  = $LogRetentionDays
    SkipWindowsUpdate = $SkipWindowsUpdate.IsPresent
    SkipChocolatey    = $SkipChocolatey.IsPresent
    UpdateTypes       = @("Security", "Critical")
}

# Load configuration if specified
if ($ConfigFile) {
    $configPath = $ConfigFile
}

# Load configuration from file if it exists
if (Test-Path -Path $configPath) {
    try {
        $fileConfig = Get-Content -Path $configPath -Raw | ConvertFrom-Json

        # Override with file settings if not explicitly set in parameters
        if (-not $PSBoundParameters.ContainsKey('AutoReboot')) {
            $global:config.AutoReboot = [bool]$fileConfig.AutoReboot
        }
        if (-not $PSBoundParameters.ContainsKey('LogRetentionDays')) {
            $global:config.LogRetentionDays = [int]$fileConfig.LogRetentionDays
        }
        if (-not $PSBoundParameters.ContainsKey('SkipWindowsUpdate')) {
            $global:config.SkipWindowsUpdate = [bool]$fileConfig.SkipWindowsUpdate
        }
        if (-not $PSBoundParameters.ContainsKey('SkipChocolatey')) {
            $global:config.SkipChocolatey = [bool]$fileConfig.SkipChocolatey
        }
        if ($fileConfig.UpdateTypes) {
            $global:config.UpdateTypes = $fileConfig.UpdateTypes
        }
    }
    catch {
        Write-Warning "Failed to load configuration file: $($_.Exception.Message)"
    }
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [Parameter()]
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Add to log file
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }

    # Output to console with color coding
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'Info' { 'White' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            'Success' { 'Green' }
            default { 'White' }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
}

function Initialize-Environment {
    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path $logFolder)) {
        try {
            New-Item -ItemType Directory -Path $logFolder -ErrorAction Stop | Out-Null
            Write-LogMessage "Created log directory: $logFolder" -Level Info
        }
        catch {
            Write-Error "Failed to create log directory: $($_.Exception.Message)"
            exit 1
        }
    }

    # Start transcript logging for debugging
    try {
        Start-Transcript -Path $transcriptFile -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Unable to start transcript: $($_.Exception.Message)"
    }

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-LogMessage "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)" -Level Error
        exit 1
    }

    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        if (-not $env:SKIP_ELEVATION -or $env:SKIP_ELEVATION -ne "1") {
            Write-LogMessage "Restarting with elevated privileges..." -Level Info
            Start-Process -FilePath pwsh.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
            exit
        }
        else {
            Write-LogMessage "Skipping elevation due to testing mode." -Level Warning
            return $false
        }
    }
    return $true
}

function Test-PendingReboot {
    $pendingRebootTests = @(
        @{
            Name     = 'RebootPending'
            Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
            Property = 'RebootPending'
        },
        @{
            Name     = 'RebootRequired'
            Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
            Property = 'RebootRequired'
        },
        @{
            Name     = 'PendingFileRename'
            Path     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            Property = 'PendingFileRenameOperations'
        }
    )

    $pendingReboot = $false

    foreach ($test in $pendingRebootTests) {
        if (Get-ItemProperty -Path $test.Path -Name $test.Property -ErrorAction SilentlyContinue) {
            Write-LogMessage "Pending reboot detected: $($test.Name)" -Level Warning
            $pendingReboot = $true
        }
    }

    return $pendingReboot
}

function Invoke-Reboot {
    param(
        [Parameter()]
        [switch]$Force
    )

    if ($Force -or $global:config.AutoReboot) {
        Write-LogMessage "System will reboot in 60 seconds. Press Ctrl+C to cancel." -Level Warning
        Start-Sleep -Seconds 5  # Reduced for testing
        Restart-Computer -Force
    }
    else {
        Write-LogMessage "A system reboot is recommended to complete updates." -Level Warning
    }
}

function Update-Chocolatey {
    if ($global:config.SkipChocolatey) {
        Write-LogMessage "Skipping Chocolatey updates (disabled in configuration)" -Level Info
        return
    }

    Write-LogMessage "=== Starting Chocolatey Updates ===" -Level Info
    try {
        if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
            throw "Chocolatey is not installed. Please install it first."
        }

        Write-LogMessage "Updating Chocolatey itself..." -Level Info
        $chocoSelfOutput = & choco upgrade chocolatey -y --no-progress
        Write-LogMessage ($chocoSelfOutput | Out-String) -NoConsole

        Write-LogMessage "Updating all Chocolatey packages..." -Level Info
        $chocoOutput = & choco upgrade all -y --no-progress
        Write-LogMessage ($chocoOutput | Out-String) -NoConsole
        Write-LogMessage "Chocolatey updates completed" -Level Success
    }
    catch {
        Write-LogMessage "Error updating Chocolatey packages: $($_.Exception.Message)" -Level Error
    }
}

function Update-Windows {
    if ($global:config.SkipWindowsUpdate) {
        Write-LogMessage "Skipping Windows updates (disabled in configuration)" -Level Info
        return
    }

    Write-LogMessage "=== Starting Windows Updates ===" -Level Info
    try {
        if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-LogMessage "Installing PSWindowsUpdate module..." -Level Info
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
        }

        Import-Module PSWindowsUpdate

        Write-LogMessage "Checking for available Windows Updates..." -Level Info
        $updates = Get-WindowsUpdate

        if ($null -ne $updates -and $updates.Count -gt 0) {
            Write-LogMessage "Found $($updates.Count) updates available" -Level Info
            Write-LogMessage ($updates | Format-Table -AutoSize | Out-String) -NoConsole

            Write-LogMessage "Installing Windows Updates..." -Level Info
            $updateResults = Install-WindowsUpdate -AcceptAll -AutoReboot:$global:config.AutoReboot -Silent
            Write-LogMessage ($updateResults | Out-String) -NoConsole
        }
        else {
            Write-LogMessage "No Windows Updates available" -Level Success
        }
    }
    catch {
        Write-LogMessage "Error checking Windows Updates: $($_.Exception.Message)" -Level Error
    }
}

function Remove-OldLogs {
    $oldLogs = Get-ChildItem -Path $logFolder -Filter "*.log" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$global:config.LogRetentionDays) }

    if ($oldLogs -and $oldLogs.Count -gt 0) {
        Write-LogMessage "Cleaning up logs older than $($global:config.LogRetentionDays) days..." -Level Info
        $oldLogs | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force -ErrorAction Stop
                Write-LogMessage "Removed old log: $($_.Name)" -Level Info -NoConsole
            }
            catch {
                Write-LogMessage "Failed to remove log $($_.Name): $($_.Exception.Message)" -Level Warning -NoConsole
            }
        }
        Write-LogMessage "Removed $($oldLogs.Count) old log files" -Level Success
    }
    else {
        Write-LogMessage "No logs older than $($global:config.LogRetentionDays) days found to clean up." -Level Info
    }
}

# Main execution
Write-LogMessage "=== Script Started ===" -Level Info
Write-LogMessage "PowerShell Version: $($PSVersionTable.PSVersion)" -Level Info
Write-LogMessage "Log file: $logFile" -Level Info

# Initialize environment and check for admin rights
$isAdmin = Initialize-Environment
if (-not $isAdmin -and -not $env:SKIP_ELEVATION) {
    exit
}

# Check for pending reboots
$pendingReboot = Test-PendingReboot
if ($pendingReboot) {
    Write-LogMessage "System has pending reboot from previous updates" -Level Warning
    Invoke-Reboot
}

# Run updates
Update-Chocolatey
Update-Windows

# Clean up old logs
Remove-OldLogs

Write-LogMessage "=== Script Completed ===" -Level Success

# Stop transcript
try {
    Stop-Transcript -ErrorAction SilentlyContinue
}
catch {
    # Ignore errors if transcript wasn't started
}
