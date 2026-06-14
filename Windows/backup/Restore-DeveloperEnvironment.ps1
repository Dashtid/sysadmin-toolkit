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
    Version: 1.1.0
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

function Read-RestoreManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $manifestPath = Join-Path $Source "manifest.json"
    if (-not (Test-Path $manifestPath)) {
        Write-ErrorMessage "Manifest not found: $manifestPath"
        Write-ErrorMessage "This does not appear to be a valid developer environment backup."
        throw "Manifest not found at $manifestPath"
    }

    try {
        return Get-Content $manifestPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-ErrorMessage "Failed to parse manifest: $($_.Exception.Message)"
        throw "Failed to parse manifest: $($_.Exception.Message)"
    }
}

function Restore-ManifestItem {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Item,

        [bool]$BackupCurrentFirst = $true
    )

    # Returns @{ Outcome = 'Restored'|'Skipped'|'Error'; Reason = '...' }

    Write-InfoMessage "Processing: $($Item.Name)"

    if (-not (Test-Path $Item.BackupFile)) {
        Write-WarningMessage "Backup file not found: $($Item.BackupFile)"
        return @{ Outcome = 'Skipped'; Reason = 'BackupFileMissing' }
    }

    if (-not $Item.OriginalPath) {
        Write-WarningMessage "No original path specified for $($Item.Name)"
        return @{ Outcome = 'Skipped'; Reason = 'NoOriginalPath' }
    }

    # Create parent directory if needed
    $parentDir = Split-Path $Item.OriginalPath -Parent
    if (-not (Test-Path $parentDir)) {
        if ($PSCmdlet.ShouldProcess($parentDir, "Create directory")) {
            try {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                Write-InfoMessage "Created directory: $parentDir"
            }
            catch {
                Write-ErrorMessage "Failed to create directory: $($_.Exception.Message)"
                return @{ Outcome = 'Error'; Reason = 'CreateParentFailed' }
            }
        }
    }

    # Backup current file before overwriting
    if ($BackupCurrentFirst -and (Test-Path $Item.OriginalPath)) {
        $backupFile = "$($Item.OriginalPath).bak"
        if ($PSCmdlet.ShouldProcess($Item.OriginalPath, "Create backup at $backupFile")) {
            try {
                Copy-Item -Path $Item.OriginalPath -Destination $backupFile -Force
                Write-InfoMessage "Created backup: $backupFile"
            }
            catch {
                Write-WarningMessage "Failed to create backup of current file: $($_.Exception.Message)"
            }
        }
    }

    # Restore file
    if ($PSCmdlet.ShouldProcess($Item.OriginalPath, "Restore from $($Item.BackupFile)")) {
        try {
            Copy-Item -Path $Item.BackupFile -Destination $Item.OriginalPath -Force
            Write-Success "Restored: $($Item.Name)"
            return @{ Outcome = 'Restored'; Reason = $null }
        }
        catch {
            Write-ErrorMessage "Failed to restore $($Item.Name): $($_.Exception.Message)"
            return @{ Outcome = 'Error'; Reason = 'CopyFailed' }
        }
    }

    return @{ Outcome = 'Skipped'; Reason = 'WhatIf' }
}

function Restore-VsCodeExtension {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $ExtensionsItem
    )

    if (-not (Test-Path $ExtensionsItem.BackupFile)) {
        Write-InfoMessage "No VSCode extensions backup file"
        return @{ Installed = 0; Total = 0; Skipped = $true }
    }

    Write-Host ""
    Write-InfoMessage "Restoring VSCode extensions..."

    $codeCmd = Get-Command code -ErrorAction SilentlyContinue
    if (-not $codeCmd) {
        Write-WarningMessage "VSCode CLI (code) not found in PATH - skipping extension restore"
        return @{ Installed = 0; Total = 0; Skipped = $true }
    }

    $extensions = Get-Content $ExtensionsItem.BackupFile
    if (-not $extensions) {
        return @{ Installed = 0; Total = 0; Skipped = $false }
    }

    $totalExtensions = ($extensions | Measure-Object).Count
    $installedCount = 0

    $retryDelaySeconds = 5

    foreach ($extension in $extensions) {
        $extension = $extension.Trim()
        if ([string]::IsNullOrWhiteSpace($extension)) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($extension, "Install VSCode extension")) {
            $installed = $false
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                try {
                    if ($attempt -eq 1) {
                        Write-InfoMessage "Installing: $extension"
                    }
                    else {
                        Write-InfoMessage "Retrying ($retryDelaySeconds s backoff): $extension"
                        Start-Sleep -Seconds $retryDelaySeconds
                    }

                    $null = & code --install-extension $extension --force 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $installed = $true
                        break
                    }
                }
                catch {
                    if ($attempt -eq 2) {
                        Write-WarningMessage "Error installing $extension : $($_.Exception.Message)"
                    }
                }
            }

            if ($installed) {
                $installedCount++
            }
            else {
                Write-WarningMessage "Failed to install after retry: $extension"
            }
        }
    }

    Write-Success "Installed $installedCount of $totalExtensions VSCode extensions"
    return @{ Installed = $installedCount; Total = $totalExtensions; Skipped = $false }
}

function Invoke-Restore {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [bool]$RestoreVsCodeExtensions = $true,

        [bool]$BackupCurrentFirst = $true
    )

    $manifest = Read-RestoreManifest -Source $Source

    Write-InfoMessage "Developer Environment Restore"
    Write-InfoMessage "Backup from: $($manifest.BackupDate)"
    Write-InfoMessage "Computer: $($manifest.ComputerName)"
    Write-InfoMessage "User: $($manifest.UserName)"
    Write-Host ""

    $successCount = 0
    $skipCount = 0
    $errorCount = 0

    foreach ($item in $manifest.Items) {
        # Skip VSCode extensions (handled separately)
        if ($item.Name -eq "VSCode-Extensions") {
            continue
        }

        $result = Restore-ManifestItem -Item $item -BackupCurrentFirst $BackupCurrentFirst
        switch ($result.Outcome) {
            'Restored' { $successCount++ }
            'Skipped'  { $skipCount++ }
            'Error'    { $errorCount++ }
        }
    }

    if ($RestoreVsCodeExtensions) {
        $extensionsItem = $manifest.Items | Where-Object { $_.Name -eq "VSCode-Extensions" }
        if ($extensionsItem) {
            $extResult = Restore-VsCodeExtension -ExtensionsItem $extensionsItem
            if ($extResult.Skipped) { $skipCount++ }
        }
        else {
            Write-InfoMessage "No VSCode extensions backup found"
        }
    }

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

    return @{ Restored = $successCount; Skipped = $skipCount; Errors = $errorCount }
}

# Run Invoke-Restore when invoked as a script. When dot-sourced for testing, skip
# auto-run so test files can load function definitions into scope and exercise
# them with mocks.
if ($MyInvocation.InvocationName -ne '.') {
    $null = Invoke-Restore `
        -Source $BackupPath `
        -RestoreVsCodeExtensions:$RestoreExtensions `
        -BackupCurrentFirst:$CreateBackupFirst
}
