#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Restores developer environment from backup.

.DESCRIPTION
    Restores developer environment configurations from a backup created by
    Backup-DeveloperEnvironment.ps1. Supports:
    - Selective restoration (choose which items to restore)
    - Automatic backup of current files before overwriting
    - VSCode extensions reinstallation
    - WhatIf support for preview

    Restores:
    - VSCode settings and keybindings
    - VSCode extensions (reinstalls from list)
    - Windows Terminal settings
    - PowerShell profile
    - Git configuration
    - SSH configuration

.PARAMETER BackupPath
    Path to backup folder containing manifest.json.

.PARAMETER RestoreExtensions
    Reinstall VSCode extensions from backup list. Default: $true

.PARAMETER CreateBackupFirst
    Backup current files before restoring. Default: $true

.PARAMETER Force
    Overwrite existing files without prompting.

.PARAMETER WhatIf
    Shows what would be restored without making changes.

.EXAMPLE
    .\Restore-DeveloperEnvironment.ps1 -BackupPath "C:\Users\User\Backups\DevEnv\20251226-120000"
    Restores from specified backup.

.EXAMPLE
    .\Restore-DeveloperEnvironment.ps1 -BackupPath $backupDir -WhatIf
    Preview what would be restored.

.EXAMPLE
    .\Restore-DeveloperEnvironment.ps1 -BackupPath $backupDir -RestoreExtensions:$false
    Restore without reinstalling VSCode extensions.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+

.LINK
    Backup-DeveloperEnvironment.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BackupPath,

    [Parameter()]
    [switch]$RestoreExtensions = $true,

    [Parameter()]
    [switch]$CreateBackupFirst = $true,

    [Parameter()]
    [switch]$Force
)

#Requires -Version 5.1

# Import CommonFunctions
$modulePath = Join-Path $PSScriptRoot "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    # Fallback logging functions if module not available
    function Write-Success { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param($Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }
}

# ============================================================================
# VALIDATION
# ============================================================================

$manifestPath = Join-Path $BackupPath "manifest.json"
if (-not (Test-Path $manifestPath)) {
    Write-ErrorMessage "Manifest not found: $manifestPath"
    Write-ErrorMessage "This does not appear to be a valid developer environment backup."
    exit 1
}

# Load manifest
try {
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
}
catch {
    Write-ErrorMessage "Failed to parse manifest: $($_.Exception.Message)"
    exit 1
}

Write-InfoMessage "Developer Environment Restore"
Write-InfoMessage "Backup from: $($manifest.BackupDate)"
Write-InfoMessage "Computer: $($manifest.ComputerName)"
Write-InfoMessage "User: $($manifest.UserName)"
Write-Host ""

# ============================================================================
# RESTORE LOGIC
# ============================================================================

$successCount = 0
$skipCount = 0
$errorCount = 0

foreach ($item in $manifest.Items) {
    # Skip VSCode extensions (handled separately)
    if ($item.Name -eq "VSCode-Extensions") {
        continue
    }

    Write-InfoMessage "Processing: $($item.Name)"

    # Check if backup file exists
    if (-not (Test-Path $item.BackupFile)) {
        Write-WarningMessage "Backup file not found: $($item.BackupFile)"
        $skipCount++
        continue
    }

    # Check if original path is valid
    if (-not $item.OriginalPath) {
        Write-WarningMessage "No original path specified for $($item.Name)"
        $skipCount++
        continue
    }

    # Create parent directory if needed
    $parentDir = Split-Path $item.OriginalPath -Parent
    if (-not (Test-Path $parentDir)) {
        if ($PSCmdlet.ShouldProcess($parentDir, "Create directory")) {
            try {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                Write-InfoMessage "Created directory: $parentDir"
            }
            catch {
                Write-ErrorMessage "Failed to create directory: $($_.Exception.Message)"
                $errorCount++
                continue
            }
        }
    }

    # Backup current file before overwriting
    if ($CreateBackupFirst -and (Test-Path $item.OriginalPath)) {
        $backupFile = "$($item.OriginalPath).bak"
        if ($PSCmdlet.ShouldProcess($item.OriginalPath, "Create backup at $backupFile")) {
            try {
                Copy-Item -Path $item.OriginalPath -Destination $backupFile -Force
                Write-InfoMessage "Created backup: $backupFile"
            }
            catch {
                Write-WarningMessage "Failed to create backup of current file: $($_.Exception.Message)"
            }
        }
    }

    # Restore file
    if ($PSCmdlet.ShouldProcess($item.OriginalPath, "Restore from $($item.BackupFile)")) {
        try {
            Copy-Item -Path $item.BackupFile -Destination $item.OriginalPath -Force
            Write-Success "Restored: $($item.Name)"
            $successCount++
        }
        catch {
            Write-ErrorMessage "Failed to restore $($item.Name): $($_.Exception.Message)"
            $errorCount++
        }
    }
}

# Restore VSCode extensions
if ($RestoreExtensions) {
    $extensionsItem = $manifest.Items | Where-Object { $_.Name -eq "VSCode-Extensions" }

    if ($extensionsItem -and (Test-Path $extensionsItem.BackupFile)) {
        Write-Host ""
        Write-InfoMessage "Restoring VSCode extensions..."

        $codeCmd = Get-Command code -ErrorAction SilentlyContinue
        if ($codeCmd) {
            $extensions = Get-Content $extensionsItem.BackupFile

            if ($extensions) {
                $totalExtensions = ($extensions | Measure-Object).Count
                $installedCount = 0

                foreach ($extension in $extensions) {
                    $extension = $extension.Trim()
                    if ([string]::IsNullOrWhiteSpace($extension)) {
                        continue
                    }

                    if ($PSCmdlet.ShouldProcess($extension, "Install VSCode extension")) {
                        try {
                            Write-InfoMessage "Installing: $extension"
                            $result = & code --install-extension $extension --force 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                $installedCount++
                            }
                            else {
                                Write-WarningMessage "Failed to install: $extension"
                            }
                        }
                        catch {
                            Write-WarningMessage "Error installing $extension : $($_.Exception.Message)"
                        }
                    }
                }

                Write-Success "Installed $installedCount of $totalExtensions VSCode extensions"
            }
        }
        else {
            Write-WarningMessage "VSCode CLI (code) not found in PATH - skipping extension restore"
            $skipCount++
        }
    }
    else {
        Write-InfoMessage "No VSCode extensions backup found"
    }
}

# Summary
Write-Host ""
Write-InfoMessage "Restore Summary"
Write-Host "  Restored: $successCount items"
Write-Host "  Skipped:  $skipCount items"
Write-Host "  Errors:   $errorCount items"
Write-Host ""

if ($successCount -gt 0 -and $errorCount -eq 0) {
    Write-Success "Restore complete"
}
elseif ($errorCount -gt 0) {
    Write-WarningMessage "Restore completed with errors"
}
else {
    Write-WarningMessage "No items were restored"
}
