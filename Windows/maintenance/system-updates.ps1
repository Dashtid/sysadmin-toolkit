#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Automated system update script for Windows with Chocolatey, Winget, and Windows Update support.

.DESCRIPTION
    This script automates the update process for:
    - Chocolatey packages
    - Winget packages
    - Windows Updates (via PSWindowsUpdate module)

    Features:
    - System restore point creation before updates
    - Configuration file support
    - Automatic reboot handling
    - Pending reboot detection
    - Log retention management
    - Update summary with duration tracking
    - WhatIf support for dry-run mode
    - Pre-update state backup for rollback

.PARAMETER SkipChocolatey
    Skip Chocolatey package updates.

.PARAMETER SkipWinget
    Skip Winget package updates.

.PARAMETER SkipWindowsUpdate
    Skip Windows Updates installation.

.PARAMETER AutoReboot
    Automatically reboot the system if required after updates.

.PARAMETER LogRetentionDays
    Number of days to retain log files (default: 30).

.PARAMETER ConfigFile
    Path to a JSON configuration file for persistent settings.

.PARAMETER SkipRestorePoint
    Skip creating a system restore point before updates.

.EXAMPLE
    .\system-updates.ps1
    Runs all updates with default settings.

.EXAMPLE
    .\system-updates.ps1 -SkipWinget -AutoReboot
    Updates Chocolatey and Windows Update, then automatically reboots if needed.

.EXAMPLE
    .\system-updates.ps1 -WhatIf
    Shows what would be updated without actually performing updates.

.EXAMPLE
    .\system-updates.ps1 -ConfigFile "C:\path\to\config.json"
    Uses settings from a custom configuration file.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 2.0.0
    Requires: PowerShell 7.0+ and Administrator privileges

.CHANGELOG
    2.0.0 - 2025-10-15
        - Refactored to use CommonFunctions module
        - Added system restore point creation
        - Added update summary with duration tracking
        - Added WhatIf support
        - Added pre-update state export for rollback
        - Centralized log directory management
        - Improved error handling and progress reporting

    1.0.0 - Initial release
#>

using namespace System.Security.Principal

#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$SkipChocolatey,

    [Parameter()]
    [switch]$SkipWinget,

    [Parameter()]
    [switch]$SkipWindowsUpdate,

    [Parameter()]
    [switch]$AutoReboot,

    [Parameter()]
    [int]$LogRetentionDays = 30,

    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [switch]$SkipRestorePoint,

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$RebootDelaySeconds = 60
)

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
$script:UpdateSummary = @{
    Chocolatey     = @{ Updated = 0; Failed = 0; Skipped = $false }
    Winget         = @{ Updated = 0; Failed = 0; Skipped = $false }
    WindowsUpdates = @{ Updated = 0; Failed = 0; Skipped = $false }
    RestorePoint   = $null
    RebootRequired = $false
}

# Get centralized log directory
$logFolder = Get-LogDirectory
$logFile = Join-Path -Path $logFolder -ChildPath "system-updates_$(Get-Date -Format 'yyyy-MM-dd').log"
$transcriptFile = Join-Path -Path $logFolder -ChildPath "transcript_system-updates_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"

# Configuration file path
if (-not $ConfigFile) {
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "config.json"
}

# Initialize global configuration
$global:config = @{
    AutoReboot         = $AutoReboot.IsPresent
    LogRetentionDays   = $LogRetentionDays
    SkipWindowsUpdate  = $SkipWindowsUpdate.IsPresent
    SkipChocolatey     = $SkipChocolatey.IsPresent
    SkipWinget         = $SkipWinget.IsPresent
    SkipRestorePoint   = $SkipRestorePoint.IsPresent
    RebootDelaySeconds = $RebootDelaySeconds
    UpdateTypes        = @("Security", "Critical", "Important")
}

# Load configuration from file if it exists
if (Test-Path -Path $ConfigFile) {
    try {
        $fileConfig = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json

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
        if (-not $PSBoundParameters.ContainsKey('SkipWinget')) {
            $global:config.SkipWinget = [bool]$fileConfig.SkipWinget
        }
        if (-not $PSBoundParameters.ContainsKey('SkipRestorePoint')) {
            $global:config.SkipRestorePoint = [bool]$fileConfig.SkipRestorePoint
        }
        if ($fileConfig.UpdateTypes) {
            $global:config.UpdateTypes = $fileConfig.UpdateTypes
        }

        Write-InfoMessage "Loaded configuration from: $ConfigFile"
    }
    catch {
        Write-WarningMessage "Failed to load configuration file: $($_.Exception.Message)"
    }
}
#endregion

#region Logging Functions
function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes a timestamped message to both log file and console.
    #>
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

    # Output to console using CommonFunctions
    if (-not $NoConsole) {
        switch ($Level) {
            'Info' { Write-InfoMessage $Message }
            'Warning' { Write-WarningMessage $Message }
            'Error' { Write-ErrorMessage $Message }
            'Success' { Write-Success $Message }
        }
    }
}
#endregion

#region Helper Functions
function Initialize-Environment {
    <#
    .SYNOPSIS
        Initializes the script environment, checks prerequisites, and starts transcript logging.
    #>

    # Start transcript logging for debugging
    try {
        Start-Transcript -Path $transcriptFile -ErrorAction SilentlyContinue
        Write-Verbose "Transcript started: $transcriptFile"
    }
    catch {
        Write-Warning "Unable to start transcript: $($_.Exception.Message)"
    }

    # Verify administrator privileges
    if (-not (Test-IsAdministrator)) {
        Write-ErrorMessage "This script must be run as Administrator"
        exit 1
    }

    Write-Success "Running with administrator privileges"
    return $true
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks if there is a pending reboot from previous updates.
    #>
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
            Write-WarningMessage "Pending reboot detected: $($test.Name)"
            $pendingReboot = $true
        }
    }

    return $pendingReboot
}

function Invoke-Reboot {
    <#
    .SYNOPSIS
        Handles system reboot based on configuration with configurable delay.
    .DESCRIPTION
        Provides a configurable delay/timeout before reboot to allow user intervention.
        The delay can be set via -RebootDelaySeconds parameter or config file.
    #>
    param(
        [Parameter()]
        [switch]$Force
    )

    $script:UpdateSummary.RebootRequired = $true
    $delaySeconds = $global:config.RebootDelaySeconds

    if ($Force -or $global:config.AutoReboot) {
        if ($PSCmdlet.ShouldProcess("System", "Reboot computer")) {
            # Wait for reboot with configurable delay/timeout
            Write-WarningMessage "System will reboot in $delaySeconds seconds. Press Ctrl+C to cancel."
            Write-InfoMessage "Waiting $delaySeconds seconds before reboot..."
            Start-Sleep -Seconds $delaySeconds
            Restart-Computer -Force
        }
    }
    else {
        Write-WarningMessage "A system reboot is recommended to complete updates."
    }
}

function Test-RestorePointCreation {
    <#
    .SYNOPSIS
        Validates that a restore point was successfully created.
    .DESCRIPTION
        Uses Get-ComputerRestorePoint to verify the restore point exists.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Description
    )

    try {
        # Get-ComputerRestorePoint to verify restore point was created
        $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
            Where-Object { $_.Description -like "*$Description*" }

        if ($restorePoints) {
            Write-InfoMessage "Restore point validated successfully"
            return $true
        }
        else {
            Write-WarningMessage "Could not validate restore point creation"
            return $false
        }
    }
    catch {
        Write-WarningMessage "Error validating restore point: $($_.Exception.Message)"
        return $false
    }
}

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before applying updates.
    .DESCRIPTION
        Creates a restore point and validates its creation using Test-RestorePointCreation.
    #>
    if ($global:config.SkipRestorePoint) {
        Write-InfoMessage "Skipping system restore point creation (disabled in configuration)"
        return $null
    }

    if ($PSCmdlet.ShouldProcess("System", "Create restore point")) {
        try {
            # Enable System Restore if not already enabled
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue

            $description = "Before Automated Updates - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS

            Write-Success "System restore point created: $description"
            $script:UpdateSummary.RestorePoint = $description

            # Validate restore point was created
            Test-RestorePointCreation -Description $description | Out-Null

            return $description
        }
        catch [System.Runtime.InteropServices.COMException] {
            # Handle restore point creation errors gracefully
            Write-WarningMessage "Restore point creation failed (COM error): $($_.Exception.Message)"
            Write-InfoMessage "This may occur if a restore point was created recently"
            return $null
        }
        catch {
            # Catch Restore point errors gracefully
            Write-WarningMessage "Failed to create system restore point: $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

function Export-PreUpdateState {
    <#
    .SYNOPSIS
        Exports current package state before updates for rollback capability.
    #>
    if ($PSCmdlet.ShouldProcess("Package state", "Export to log directory")) {
        $stateFile = Join-Path -Path $logFolder -ChildPath "pre-update-state_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').json"

        $state = @{
            Timestamp = Get-Date -Format 'o'
            Chocolatey = @()
            Winget = @()
        }

        try {
            # Export Chocolatey packages
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                $chocoList = & choco list --local-only --limit-output
                $state.Chocolatey = $chocoList | ForEach-Object {
                    $parts = $_ -split '\|'
                    @{ Name = $parts[0]; Version = $parts[1] }
                }
            }

            # Export Winget packages
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                # Winget list output is harder to parse, storing raw output
                $state.Winget = & winget list | Out-String
            }

            $state | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile
            Write-InfoMessage "Exported pre-update state to: $stateFile"
            return $stateFile
        }
        catch {
            Write-WarningMessage "Failed to export pre-update state: $($_.Exception.Message)"
            return $null
        }
    }
}
#endregion

#region Update Functions
function Update-Winget {
    <#
    .SYNOPSIS
        Updates all Winget packages with error handling.
    .DESCRIPTION
        Uses try/catch to handle winget errors gracefully.
    #>
    if ($global:config.SkipWinget) {
        Write-InfoMessage "Skipping Winget updates (disabled in configuration)"
        $script:UpdateSummary.Winget.Skipped = $true
        return
    }

    Write-InfoMessage "=== Starting Winget Updates ==="

    # try winget updates with comprehensive error handling
    try {
        if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-WarningMessage "Winget is not installed or not available in PATH"
            $script:UpdateSummary.Winget.Skipped = $true
            return
        }

        if ($PSCmdlet.ShouldProcess("Winget packages", "Update all")) {
            # Accept source agreements to avoid interactive prompts
            Write-InfoMessage "Updating Winget sources..."
            try {
                # ErrorAction Stop for winget source update
                $null = & winget source update --disable-interactivity 2>&1
            }
            catch {
                Write-WarningMessage "Winget source update warning: $($_.Exception.Message)"
            }

            Write-InfoMessage "Checking for available Winget updates..."
            $upgradeList = & winget upgrade --include-unknown 2>&1 | Out-String
            Write-LogMessage $upgradeList -NoConsole

            # Check if there are any upgrades available
            if ($upgradeList -match "No installed package found matching input criteria" -or
                $upgradeList -match "No available upgrade found") {
                Write-Success "No Winget updates available"
                return
            }

            # Count available updates (rough estimate)
            $updateCount = ([regex]::Matches($upgradeList, "upgrades available")).Count
            if ($updateCount -gt 0) {
                Write-InfoMessage "Found approximately $updateCount Winget updates available"
            }

            Write-InfoMessage "Upgrading all Winget packages..."
            Write-Progress -Activity "Updating Winget Packages" -Status "In progress..." -PercentComplete 50

            $wingetOutput = & winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | Out-String
            Write-LogMessage $wingetOutput -NoConsole

            Write-Progress -Activity "Updating Winget Packages" -Completed
            Write-Success "Winget updates completed"
            $script:UpdateSummary.Winget.Updated = $updateCount
        }
    }
    catch {
        Write-ErrorMessage "Error updating Winget packages: $($_.Exception.Message)"
        $script:UpdateSummary.Winget.Failed = 1
    }
}

function Update-Chocolatey {
    <#
    .SYNOPSIS
        Updates Chocolatey itself and all installed packages.
    .DESCRIPTION
        Uses try/catch to handle choco errors gracefully.
    #>
    if ($global:config.SkipChocolatey) {
        Write-InfoMessage "Skipping Chocolatey updates (disabled in configuration)"
        $script:UpdateSummary.Chocolatey.Skipped = $true
        return
    }

    Write-InfoMessage "=== Starting Chocolatey Updates ==="

    # try choco updates with comprehensive error handling
    try {
        if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-WarningMessage "Chocolatey is not installed"
            $script:UpdateSummary.Chocolatey.Skipped = $true
            return
        }

        if ($PSCmdlet.ShouldProcess("Chocolatey packages", "Update all")) {
            Write-InfoMessage "Updating Chocolatey itself..."
            Write-Progress -Activity "Updating Chocolatey" -Status "Updating Chocolatey itself..." -PercentComplete 25

            try {
                $chocoSelfOutput = & choco upgrade chocolatey -y --no-progress 2>&1
                Write-LogMessage ($chocoSelfOutput | Out-String) -NoConsole
            }
            catch {
                Write-WarningMessage "Chocolatey self-update warning: $($_.Exception.Message)"
            }

            Write-InfoMessage "Checking for outdated packages..."
            $outdated = & choco outdated --limit-output
            $outdatedCount = ($outdated | Measure-Object).Count

            if ($outdatedCount -gt 0) {
                Write-InfoMessage "Found $outdatedCount outdated Chocolatey packages"
                $script:UpdateSummary.Chocolatey.Updated = $outdatedCount
            }

            Write-InfoMessage "Updating all Chocolatey packages..."
            Write-Progress -Activity "Updating Chocolatey" -Status "Updating all packages..." -PercentComplete 75

            $chocoOutput = & choco upgrade all -y --no-progress 2>&1
            Write-LogMessage ($chocoOutput | Out-String) -NoConsole

            Write-Progress -Activity "Updating Chocolatey" -Completed
            Write-Success "Chocolatey updates completed"
        }
    }
    catch {
        Write-ErrorMessage "Error updating Chocolatey packages: $($_.Exception.Message)"
        $script:UpdateSummary.Chocolatey.Failed = 1
    }
}

function Update-Windows {
    <#
    .SYNOPSIS
        Installs Windows Updates using the PSWindowsUpdate module.
    #>
    if ($global:config.SkipWindowsUpdate) {
        Write-InfoMessage "Skipping Windows updates (disabled in configuration)"
        $script:UpdateSummary.WindowsUpdates.Skipped = $true
        return
    }

    Write-InfoMessage "=== Starting Windows Updates ==="

    try {
        if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-InfoMessage "Installing PSWindowsUpdate module..."
            if ($PSCmdlet.ShouldProcess("PSWindowsUpdate module", "Install")) {
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
                Write-Success "PSWindowsUpdate module installed"
            }
        }

        Import-Module PSWindowsUpdate

        Write-InfoMessage "Checking for available Windows Updates..."
        Write-Progress -Activity "Windows Updates" -Status "Checking for updates..." -PercentComplete 25

        $updates = Get-WindowsUpdate

        if ($null -ne $updates -and $updates.Count -gt 0) {
            Write-InfoMessage "Found $($updates.Count) Windows Updates available"
            Write-LogMessage ($updates | Format-Table -AutoSize | Out-String) -NoConsole

            $script:UpdateSummary.WindowsUpdates.Updated = $updates.Count

            if ($PSCmdlet.ShouldProcess("$($updates.Count) Windows Updates", "Install")) {
                Write-InfoMessage "Installing Windows Updates..."
                $updateCount = 0

                foreach ($update in $updates) {
                    $updateCount++
                    $percentComplete = [math]::Round(($updateCount / $updates.Count) * 100)
                    Write-Progress -Activity "Windows Updates" -Status "Installing update $updateCount of $($updates.Count)" -PercentComplete $percentComplete
                }

                $updateResults = Install-WindowsUpdate -AcceptAll -AutoReboot:$global:config.AutoReboot -Silent
                Write-LogMessage ($updateResults | Out-String) -NoConsole

                Write-Progress -Activity "Windows Updates" -Completed
                Write-Success "Windows Updates installation completed"
            }
        }
        else {
            Write-Success "No Windows Updates available"
        }
    }
    catch {
        # catch Update errors and handle gracefully
        Write-ErrorMessage "Error checking Windows Updates: $($_.Exception.Message)"
        $script:UpdateSummary.WindowsUpdates.Failed = 1
    }
}

function Remove-OldLogs {
    <#
    .SYNOPSIS
        Removes log files older than the configured retention period.
    #>
    Write-InfoMessage "Cleaning up old log files..."

    $oldLogs = Get-ChildItem -Path $logFolder -Filter "*.log" |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$global:config.LogRetentionDays) }

    if ($oldLogs -and $oldLogs.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess("$($oldLogs.Count) log files", "Delete")) {
            $oldLogs | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Write-Verbose "Removed old log: $($_.Name)"
                }
                catch {
                    Write-WarningMessage "Failed to remove log $($_.Name): $($_.Exception.Message)"
                }
            }
            Write-Success "Removed $($oldLogs.Count) old log files (older than $($global:config.LogRetentionDays) days)"
        }
    }
    else {
        Write-InfoMessage "No logs older than $($global:config.LogRetentionDays) days found to clean up"
    }
}

function Show-UpdateSummary {
    <#
    .SYNOPSIS
        Displays a summary of all updates performed.
    #>
    $duration = (Get-Date) - $script:StartTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    Write-Host "`n=== Update Summary ===" -ForegroundColor Cyan

    # Chocolatey
    if ($script:UpdateSummary.Chocolatey.Skipped) {
        Write-Host "[i] Chocolatey: Skipped" -ForegroundColor Yellow
    }
    else {
        $chocoStatus = if ($script:UpdateSummary.Chocolatey.Failed -gt 0) { "[-]" } else { "[+]" }
        $chocoColor = if ($script:UpdateSummary.Chocolatey.Failed -gt 0) { "Red" } else { "Green" }
        Write-Host "$chocoStatus Chocolatey: $($script:UpdateSummary.Chocolatey.Updated) packages updated" -ForegroundColor $chocoColor
    }

    # Winget
    if ($script:UpdateSummary.Winget.Skipped) {
        Write-Host "[i] Winget: Skipped" -ForegroundColor Yellow
    }
    else {
        $wingetStatus = if ($script:UpdateSummary.Winget.Failed -gt 0) { "[-]" } else { "[+]" }
        $wingetColor = if ($script:UpdateSummary.Winget.Failed -gt 0) { "Red" } else { "Green" }
        Write-Host "$wingetStatus Winget: $($script:UpdateSummary.Winget.Updated) packages updated" -ForegroundColor $wingetColor
    }

    # Windows Updates
    if ($script:UpdateSummary.WindowsUpdates.Skipped) {
        Write-Host "[i] Windows Updates: Skipped" -ForegroundColor Yellow
    }
    else {
        $wuStatus = if ($script:UpdateSummary.WindowsUpdates.Failed -gt 0) { "[-]" } else { "[+]" }
        $wuColor = if ($script:UpdateSummary.WindowsUpdates.Failed -gt 0) { "Red" } else { "Green" }
        Write-Host "$wuStatus Windows Updates: $($script:UpdateSummary.WindowsUpdates.Updated) updates installed" -ForegroundColor $wuColor
    }

    # Restore Point
    if ($script:UpdateSummary.RestorePoint) {
        Write-Host "[+] Restore Point: Created - $($script:UpdateSummary.RestorePoint)" -ForegroundColor Green
    }

    # Reboot Status
    if ($script:UpdateSummary.RebootRequired) {
        Write-Host "[!] Reboot Required: YES" -ForegroundColor Yellow
    }
    else {
        Write-Host "[+] Reboot Required: NO" -ForegroundColor Green
    }

    # Duration
    Write-Host "[i] Total Runtime: $durationFormatted" -ForegroundColor Blue
    Write-Host "=====================`n" -ForegroundColor Cyan
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== Windows System Update Script Started ==="
    Write-InfoMessage "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-InfoMessage "Script Version: 2.0.0"
    Write-InfoMessage "Log file: $logFile"

    if ($WhatIfPreference) {
        Write-WarningMessage "Running in WhatIf mode - no changes will be made"
    }

    # Initialize environment and check for admin rights
    $isAdmin = Initialize-Environment
    if (-not $isAdmin) {
        exit 1
    }

    # Check for pending reboots
    $pendingReboot = Test-PendingReboot
    if ($pendingReboot) {
        Write-WarningMessage "System has pending reboot from previous updates"
        Invoke-Reboot
        exit 0
    }

    # Create system restore point
    New-SystemRestorePoint

    # Export pre-update state for rollback
    Export-PreUpdateState

    # Run updates
    Update-Winget
    Update-Chocolatey
    Update-Windows

    # Clean up old logs
    Remove-OldLogs

    # Show summary
    Show-UpdateSummary

    Write-Success "=== Windows System Update Script Completed ==="

    # Check if reboot is needed
    if (Test-PendingReboot) {
        Invoke-Reboot
    }
}
catch {
    Write-ErrorMessage "Fatal error during update process: $($_.Exception.Message)"
    Write-ErrorMessage $_.ScriptStackTrace
    exit 1
}
finally {
    # finally block: Stop-Transcript and cleanup
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore errors if transcript wasn't started
    }
}
#endregion
