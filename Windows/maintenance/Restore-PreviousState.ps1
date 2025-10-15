#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Restores system to a previous package state after failed updates.

.DESCRIPTION
    This script helps rollback to a previous package state by analyzing the
    pre-update state JSON files created by system-updates.ps1.

    The script can:
    - List available backup states
    - Show differences between current and backup state
    - Downgrade packages to previous versions (Chocolatey only)
    - Restore from a System Restore Point

    Note: This is a best-effort rollback. Some updates may not be easily reversible.

.PARAMETER ListBackups
    Lists all available pre-update state backups.

.PARAMETER BackupFile
    Path to a specific pre-update state JSON file to restore from.

.PARAMETER Latest
    Automatically use the most recent backup file.

.PARAMETER ShowDiff
    Only show differences between current and backup state (no changes made).

.PARAMETER RestoreSystemRestorePoint
    Also restore from a System Restore Point (interactive selection).

.EXAMPLE
    .\Restore-PreviousState.ps1 -ListBackups
    Lists all available backup states.

.EXAMPLE
    .\Restore-PreviousState.ps1 -Latest -ShowDiff
    Shows what would change if restoring from the latest backup.

.EXAMPLE
    .\Restore-PreviousState.ps1 -Latest
    Restores from the most recent backup state.

.EXAMPLE
    .\Restore-PreviousState.ps1 -BackupFile "logs\pre-update-state_2025-10-15_10-30-00.json"
    Restores from a specific backup file.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 7.0+ and Administrator privileges

.NOTES
    Limitations:
    - Winget downgrades are not well supported by winget itself
    - Windows Updates cannot be rolled back (use System Restore for that)
    - Chocolatey package downgrades require the specific version to be available
#>

#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$ListBackups,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$BackupFile,

    [Parameter(ParameterSetName = 'RestoreLatest')]
    [switch]$Latest,

    [Parameter()]
    [switch]$ShowDiff,

    [Parameter()]
    [switch]$RestoreSystemRestorePoint
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "[-] CommonFunctions module not found at: $modulePath"
    exit 1
}
Import-Module $modulePath -Force
#endregion

#region Script Initialization
$logDir = Get-LogDirectory

# Verify running as administrator
if (-not (Test-IsAdministrator)) {
    Write-ErrorMessage "This script must be run as Administrator"
    exit 1
}
#endregion

#region Functions
function Get-BackupFiles {
    <#
    .SYNOPSIS
        Gets all available pre-update state backup files.
    #>
    $backupFiles = Get-ChildItem -Path $logDir -Filter "pre-update-state_*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    return $backupFiles
}

function Show-BackupList {
    <#
    .SYNOPSIS
        Displays a list of available backups.
    #>
    $backups = Get-BackupFiles

    if ($backups.Count -eq 0) {
        Write-WarningMessage "No backup state files found in: $logDir"
        Write-InfoMessage "Backup files are created when running system-updates.ps1"
        return
    }

    Write-InfoMessage "Available backup states ($($backups.Count) found):"
    Write-Host ""

    $index = 1
    foreach ($backup in $backups) {
        $content = Get-Content $backup.FullName -Raw | ConvertFrom-Json
        $timestamp = [datetime]::Parse($content.Timestamp)
        $chocoCount = if ($content.Chocolatey) { $content.Chocolatey.Count } else { 0 }

        Write-Host "[$index] " -ForegroundColor Cyan -NoNewline
        Write-Host $backup.Name -ForegroundColor White
        Write-Host "    Created: " -NoNewline
        Write-Host $timestamp.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
        Write-Host "    Chocolatey packages: " -NoNewline
        Write-Host $chocoCount -ForegroundColor Green
        Write-Host "    Path: " -NoNewline
        Write-Host $backup.FullName -ForegroundColor Gray
        Write-Host ""

        $index++
    }
}

function Get-CurrentPackageState {
    <#
    .SYNOPSIS
        Gets the current state of installed packages.
    #>
    $state = @{
        Chocolatey = @()
        Winget = @()
    }

    # Get Chocolatey packages
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            $chocoList = & choco list --local-only --limit-output
            $state.Chocolatey = $chocoList | ForEach-Object {
                $parts = $_ -split '\|'
                @{ Name = $parts[0]; Version = $parts[1] }
            }
        }
        catch {
            Write-WarningMessage "Failed to get Chocolatey package list: $($_.Exception.Message)"
        }
    }

    # Get Winget packages
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            $state.Winget = & winget list | Out-String
        }
        catch {
            Write-WarningMessage "Failed to get Winget package list: $($_.Exception.Message)"
        }
    }

    return $state
}

function Compare-PackageState {
    <#
    .SYNOPSIS
        Compares current package state with backup state.
    #>
    param(
        [Parameter(Mandatory)]
        [object]$BackupState,

        [Parameter(Mandatory)]
        [object]$CurrentState
    )

    $differences = @{
        Chocolatey = @{
            Upgraded = @()
            Downgraded = @()
            Added = @()
            Removed = @()
        }
    }

    # Create hashtables for easier lookup
    $backupChoco = @{}
    foreach ($pkg in $BackupState.Chocolatey) {
        $backupChoco[$pkg.Name] = $pkg.Version
    }

    $currentChoco = @{}
    foreach ($pkg in $CurrentState.Chocolatey) {
        $currentChoco[$pkg.Name] = $pkg.Version
    }

    # Find upgraded/downgraded packages
    foreach ($pkgName in $backupChoco.Keys) {
        if ($currentChoco.ContainsKey($pkgName)) {
            $backupVer = $backupChoco[$pkgName]
            $currentVer = $currentChoco[$pkgName]

            if ($currentVer -ne $backupVer) {
                try {
                    $backupVerObj = [version]$backupVer
                    $currentVerObj = [version]$currentVer

                    if ($currentVerObj -gt $backupVerObj) {
                        $differences.Chocolatey.Upgraded += @{
                            Name = $pkgName
                            OldVersion = $backupVer
                            NewVersion = $currentVer
                        }
                    }
                    else {
                        $differences.Chocolatey.Downgraded += @{
                            Name = $pkgName
                            OldVersion = $backupVer
                            NewVersion = $currentVer
                        }
                    }
                }
                catch {
                    # Version parsing failed, treat as upgraded
                    $differences.Chocolatey.Upgraded += @{
                        Name = $pkgName
                        OldVersion = $backupVer
                        NewVersion = $currentVer
                    }
                }
            }
        }
        else {
            # Package was in backup but not in current state
            $differences.Chocolatey.Removed += @{
                Name = $pkgName
                Version = $backupChoco[$pkgName]
            }
        }
    }

    # Find added packages
    foreach ($pkgName in $currentChoco.Keys) {
        if (-not $backupChoco.ContainsKey($pkgName)) {
            $differences.Chocolatey.Added += @{
                Name = $pkgName
                Version = $currentChoco[$pkgName]
            }
        }
    }

    return $differences
}

function Show-PackageDifferences {
    <#
    .SYNOPSIS
        Displays package differences in a formatted way.
    #>
    param(
        [Parameter(Mandatory)]
        [object]$Differences
    )

    Write-Host "`n=== Package State Differences ===" -ForegroundColor Cyan

    # Upgraded packages
    if ($Differences.Chocolatey.Upgraded.Count -gt 0) {
        Write-Host "`n[i] Upgraded Packages ($($Differences.Chocolatey.Upgraded.Count)):" -ForegroundColor Yellow
        foreach ($pkg in $Differences.Chocolatey.Upgraded) {
            Write-Host "    $($pkg.Name): " -NoNewline
            Write-Host "$($pkg.OldVersion)" -ForegroundColor Red -NoNewline
            Write-Host " -> " -NoNewline
            Write-Host "$($pkg.NewVersion)" -ForegroundColor Green
        }
    }

    # Downgraded packages
    if ($Differences.Chocolatey.Downgraded.Count -gt 0) {
        Write-Host "`n[!] Downgraded Packages ($($Differences.Chocolatey.Downgraded.Count)):" -ForegroundColor Magenta
        foreach ($pkg in $Differences.Chocolatey.Downgraded) {
            Write-Host "    $($pkg.Name): " -NoNewline
            Write-Host "$($pkg.OldVersion)" -ForegroundColor Green -NoNewline
            Write-Host " -> " -NoNewline
            Write-Host "$($pkg.NewVersion)" -ForegroundColor Red
        }
    }

    # Added packages
    if ($Differences.Chocolatey.Added.Count -gt 0) {
        Write-Host "`n[+] Added Packages ($($Differences.Chocolatey.Added.Count)):" -ForegroundColor Green
        foreach ($pkg in $Differences.Chocolatey.Added) {
            Write-Host "    $($pkg.Name) v$($pkg.Version)"
        }
    }

    # Removed packages
    if ($Differences.Chocolatey.Removed.Count -gt 0) {
        Write-Host "`n[-] Removed Packages ($($Differences.Chocolatey.Removed.Count)):" -ForegroundColor Red
        foreach ($pkg in $Differences.Chocolatey.Removed) {
            Write-Host "    $($pkg.Name) v$($pkg.Version)"
        }
    }

    # Summary
    $totalChanges = $Differences.Chocolatey.Upgraded.Count +
                    $Differences.Chocolatey.Downgraded.Count +
                    $Differences.Chocolatey.Added.Count +
                    $Differences.Chocolatey.Removed.Count

    if ($totalChanges -eq 0) {
        Write-Host "`n[+] No package changes detected" -ForegroundColor Green
    }
    else {
        Write-Host "`n[i] Total changes: $totalChanges packages" -ForegroundColor Blue
    }

    Write-Host "================================`n" -ForegroundColor Cyan
}

function Invoke-PackageRestore {
    <#
    .SYNOPSIS
        Restores packages to the backup state.
    #>
    param(
        [Parameter(Mandatory)]
        [object]$Differences
    )

    Write-InfoMessage "Starting package restore process..."

    $restoredCount = 0
    $failedCount = 0

    # Downgrade upgraded packages
    if ($Differences.Chocolatey.Upgraded.Count -gt 0) {
        Write-InfoMessage "Downgrading $($Differences.Chocolatey.Upgraded.Count) upgraded packages..."

        foreach ($pkg in $Differences.Chocolatey.Upgraded) {
            if ($PSCmdlet.ShouldProcess("$($pkg.Name)", "Downgrade from $($pkg.NewVersion) to $($pkg.OldVersion)")) {
                try {
                    Write-InfoMessage "Downgrading $($pkg.Name) to version $($pkg.OldVersion)..."
                    & choco install $pkg.Name --version=$($pkg.OldVersion) --force -y --no-progress | Out-Null

                    if ($LASTEXITCODE -eq 0) {
                        Write-Success "Successfully downgraded $($pkg.Name)"
                        $restoredCount++
                    }
                    else {
                        Write-ErrorMessage "Failed to downgrade $($pkg.Name)"
                        $failedCount++
                    }
                }
                catch {
                    Write-ErrorMessage "Error downgrading $($pkg.Name): $($_.Exception.Message)"
                    $failedCount++
                }
            }
        }
    }

    # Reinstall removed packages
    if ($Differences.Chocolatey.Removed.Count -gt 0) {
        Write-InfoMessage "Reinstalling $($Differences.Chocolatey.Removed.Count) removed packages..."

        foreach ($pkg in $Differences.Chocolatey.Removed) {
            if ($PSCmdlet.ShouldProcess("$($pkg.Name)", "Install version $($pkg.Version)")) {
                try {
                    Write-InfoMessage "Installing $($pkg.Name) version $($pkg.Version)..."
                    & choco install $pkg.Name --version=$($pkg.Version) -y --no-progress | Out-Null

                    if ($LASTEXITCODE -eq 0) {
                        Write-Success "Successfully installed $($pkg.Name)"
                        $restoredCount++
                    }
                    else {
                        Write-ErrorMessage "Failed to install $($pkg.Name)"
                        $failedCount++
                    }
                }
                catch {
                    Write-ErrorMessage "Error installing $($pkg.Name): $($_.Exception.Message)"
                    $failedCount++
                }
            }
        }
    }

    # Report summary
    Write-Host "`n=== Restore Summary ===" -ForegroundColor Cyan
    Write-Host "[+] Successfully restored: " -NoNewline -ForegroundColor Green
    Write-Host $restoredCount
    if ($failedCount -gt 0) {
        Write-Host "[-] Failed to restore: " -NoNewline -ForegroundColor Red
        Write-Host $failedCount
    }
    Write-Host "======================`n" -ForegroundColor Cyan
}

function Invoke-SystemRestore {
    <#
    .SYNOPSIS
        Launches System Restore UI or lists restore points.
    #>
    Write-InfoMessage "Available System Restore Points:"

    $restorePoints = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending

    if ($restorePoints.Count -eq 0) {
        Write-WarningMessage "No restore points available"
        return
    }

    $index = 1
    foreach ($rp in $restorePoints) {
        Write-Host "[$index] " -ForegroundColor Cyan -NoNewline
        Write-Host $rp.Description -ForegroundColor White
        Write-Host "    Created: " -NoNewline
        Write-Host $rp.CreationTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
        Write-Host ""
        $index++
    }

    Write-Host ""
    Write-WarningMessage "System Restore will restart your computer and restore Windows system files."
    Write-InfoMessage "Launching System Restore GUI..."

    # Launch System Restore GUI
    if ($PSCmdlet.ShouldProcess("System", "Launch System Restore GUI")) {
        Start-Process "rstrui.exe"
    }
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== Package State Restore Tool ==="

    # Handle list backups
    if ($ListBackups) {
        Show-BackupList
        exit 0
    }

    # Determine which backup file to use
    $backupPath = $null

    if ($Latest) {
        $backups = Get-BackupFiles
        if ($backups.Count -eq 0) {
            Write-ErrorMessage "No backup files found in: $logDir"
            exit 1
        }
        $backupPath = $backups[0].FullName
        Write-InfoMessage "Using latest backup: $($backups[0].Name)"
    }
    elseif ($BackupFile) {
        $backupPath = $BackupFile
        if (-not (Test-Path $backupPath)) {
            Write-ErrorMessage "Backup file not found: $backupPath"
            exit 1
        }
    }
    else {
        Write-ErrorMessage "Please specify -ListBackups, -Latest, or -BackupFile"
        Write-InfoMessage "Usage: .\Restore-PreviousState.ps1 -Latest -ShowDiff"
        exit 1
    }

    # Load backup state
    Write-InfoMessage "Loading backup state from: $backupPath"
    $backupState = Get-Content $backupPath -Raw | ConvertFrom-Json

    # Get current state
    Write-InfoMessage "Analyzing current package state..."
    $currentState = Get-CurrentPackageState

    # Compare states
    $differences = Compare-PackageState -BackupState $backupState -CurrentState $currentState

    # Show differences
    Show-PackageDifferences -Differences $differences

    # If ShowDiff only, exit here
    if ($ShowDiff) {
        Write-InfoMessage "Showing differences only (no changes made)"
        exit 0
    }

    # Confirm restore
    $totalChanges = $differences.Chocolatey.Upgraded.Count + $differences.Chocolatey.Removed.Count

    if ($totalChanges -eq 0) {
        Write-Success "No restore needed - system is already in backup state"
        exit 0
    }

    Write-WarningMessage "This will attempt to restore $totalChanges package(s) to their previous state"
    Write-WarningMessage "Some operations may require internet connectivity and can take time"

    if (-not $WhatIfPreference) {
        $confirm = Read-Host "Do you want to proceed? (yes/no)"
        if ($confirm -ne "yes") {
            Write-InfoMessage "Restore cancelled by user"
            exit 0
        }
    }

    # Perform restore
    Invoke-PackageRestore -Differences $differences

    # Handle System Restore if requested
    if ($RestoreSystemRestorePoint) {
        Invoke-SystemRestore
    }

    Write-Success "Restore process completed"
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    Write-ErrorMessage $_.ScriptStackTrace
    exit 1
}
#endregion
