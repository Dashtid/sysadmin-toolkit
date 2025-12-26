#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Backs up developer environment configurations.

.DESCRIPTION
    Creates timestamped backup of developer environment configurations including:
    - VSCode settings and keybindings
    - VSCode extensions list
    - Windows Terminal settings
    - PowerShell profile
    - Git configuration
    - SSH configuration

    Features:
    - Timestamped backup folders
    - Manifest file for tracking backed up items
    - WhatIf support for preview
    - Automatic directory creation

.PARAMETER BackupPath
    Destination folder for backup. Default: $env:USERPROFILE\Backups\DevEnv

.PARAMETER IncludeExtensions
    Include VSCode extensions list in backup. Default: $true

.PARAMETER WhatIf
    Shows what would be backed up without making changes.

.EXAMPLE
    .\Backup-DeveloperEnvironment.ps1
    Creates backup in default location with timestamp.

.EXAMPLE
    .\Backup-DeveloperEnvironment.ps1 -BackupPath D:\Backups\DevEnv
    Creates backup in specified location.

.EXAMPLE
    .\Backup-DeveloperEnvironment.ps1 -WhatIf
    Shows what would be backed up without making changes.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+

.LINK
    Restore-DeveloperEnvironment.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$BackupPath = "$env:USERPROFILE\Backups\DevEnv",

    [Parameter()]
    [switch]$IncludeExtensions = $true
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
# CONFIGURATION
# ============================================================================

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = Join-Path $BackupPath $timestamp

# Define backup targets
$targets = @(
    @{
        Name         = "VSCode-Settings"
        Path         = "$env:APPDATA\Code\User\settings.json"
        Description  = "VSCode user settings"
    }
    @{
        Name         = "VSCode-Keybindings"
        Path         = "$env:APPDATA\Code\User\keybindings.json"
        Description  = "VSCode keyboard shortcuts"
    }
    @{
        Name         = "WindowsTerminal"
        Path         = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        Description  = "Windows Terminal settings"
    }
    @{
        Name         = "PowerShellProfile"
        Path         = $PROFILE
        Description  = "PowerShell profile script"
    }
    @{
        Name         = "GitConfig"
        Path         = "$env:USERPROFILE\.gitconfig"
        Description  = "Git global configuration"
    }
    @{
        Name         = "SSHConfig"
        Path         = "$env:USERPROFILE\.ssh\config"
        Description  = "SSH client configuration"
    }
)

# ============================================================================
# MAIN LOGIC
# ============================================================================

Write-InfoMessage "Developer Environment Backup"
Write-InfoMessage "Backup location: $backupDir"
Write-Host ""

# Create backup directory
if ($PSCmdlet.ShouldProcess($backupDir, "Create backup directory")) {
    try {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Write-Success "Created backup directory"
    }
    catch {
        Write-ErrorMessage "Failed to create backup directory: $($_.Exception.Message)"
        exit 1
    }
}

# Initialize manifest
$manifest = @{
    Timestamp   = $timestamp
    BackupDate  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ComputerName = $env:COMPUTERNAME
    UserName    = $env:USERNAME
    Items       = @()
}

$successCount = 0
$skipCount = 0

# Backup each target file
foreach ($target in $targets) {
    Write-InfoMessage "Processing: $($target.Description)"

    if ($target.Path -and (Test-Path $target.Path)) {
        $destFile = Join-Path $backupDir "$($target.Name)$(Split-Path $target.Path -Extension)"

        if ($PSCmdlet.ShouldProcess($target.Path, "Backup to $destFile")) {
            try {
                Copy-Item -Path $target.Path -Destination $destFile -Force
                $manifest.Items += @{
                    Name         = $target.Name
                    OriginalPath = $target.Path
                    BackupFile   = $destFile
                    Description  = $target.Description
                    FileSize     = (Get-Item $target.Path).Length
                    LastModified = (Get-Item $target.Path).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
                Write-Success "Backed up: $($target.Name)"
                $successCount++
            }
            catch {
                Write-ErrorMessage "Failed to backup $($target.Name): $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-WarningMessage "Not found: $($target.Name) ($($target.Path))"
        $skipCount++
    }
}

# Backup VSCode extensions list
if ($IncludeExtensions) {
    Write-InfoMessage "Processing: VSCode extensions list"

    $codeCmd = Get-Command code -ErrorAction SilentlyContinue
    if ($codeCmd) {
        $destFile = Join-Path $backupDir "VSCode-Extensions.txt"

        if ($PSCmdlet.ShouldProcess("VSCode extensions", "Export list to $destFile")) {
            try {
                $extensions = & code --list-extensions 2>$null
                if ($extensions) {
                    $extensions | Out-File -FilePath $destFile -Encoding UTF8
                    $manifest.Items += @{
                        Name         = "VSCode-Extensions"
                        Command      = "code --list-extensions"
                        BackupFile   = $destFile
                        Description  = "List of installed VSCode extensions"
                        ExtensionCount = ($extensions | Measure-Object).Count
                    }
                    Write-Success "Saved: VSCode extensions ($(($extensions | Measure-Object).Count) extensions)"
                    $successCount++
                }
                else {
                    Write-WarningMessage "No VSCode extensions found"
                    $skipCount++
                }
            }
            catch {
                Write-ErrorMessage "Failed to export VSCode extensions: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-WarningMessage "VSCode CLI (code) not found in PATH"
        $skipCount++
    }
}

# Save manifest
$manifestPath = Join-Path $backupDir "manifest.json"
if ($PSCmdlet.ShouldProcess($manifestPath, "Save backup manifest")) {
    try {
        $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8
        Write-Success "Saved backup manifest"
    }
    catch {
        Write-ErrorMessage "Failed to save manifest: $($_.Exception.Message)"
    }
}

# Summary
Write-Host ""
Write-InfoMessage "Backup Summary"
Write-Host "  Backed up: $successCount items"
Write-Host "  Skipped:   $skipCount items"
Write-Host "  Location:  $backupDir"
Write-Host ""

if ($successCount -gt 0) {
    Write-Success "Backup complete: $backupDir"
}
else {
    Write-WarningMessage "No items were backed up"
}

# Return backup path for scripting
return $backupDir
