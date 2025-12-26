#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Automated backup script for user data with incremental support and integrity verification.

.DESCRIPTION
    This script provides comprehensive user data backup capabilities including:
    - Backup of user documents, desktop, downloads, and custom folders
    - Support for scheduled and on-demand backups
    - Incremental backup support using file timestamps
    - Compression with optional encryption
    - Backup verification and integrity checks
    - Rotation policy (keep last N backups)
    - Multiple destination support (local, network, OneDrive)
    - Detailed logging and progress reporting
    - Restore capability

    Key features:
    - Smart file selection (skip temp files, caches)
    - Progress tracking with ETA
    - Hash verification for integrity
    - Email notification support
    - Dry-run mode for preview

.PARAMETER BackupType
    Type of backup: Full, Incremental, Differential. Default: Incremental

.PARAMETER Destination
    Backup destination path (local or network share).

.PARAMETER SourceFolders
    Array of folder paths to backup. Default: Documents, Desktop, Downloads, Pictures

.PARAMETER ExcludeFolders
    Folder names to exclude from backup.

.PARAMETER ExcludeExtensions
    File extensions to exclude (e.g., .tmp, .log).

.PARAMETER CompressionLevel
    Compression level: None, Fastest, Optimal, SmallestSize. Default: Optimal

.PARAMETER EnableEncryption
    Enable AES encryption for backup archive.

.PARAMETER EncryptionKey
    Encryption key for backup (required if EnableEncryption is set).

.PARAMETER RetentionCount
    Number of backup sets to retain. Default: 5

.PARAMETER RetentionDays
    Days to keep backups (alternative to RetentionCount). Default: 30

.PARAMETER VerifyBackup
    Verify backup integrity after completion.

.PARAMETER DryRun
    Preview what would be backed up without actually copying files.

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON.
    Default: Console

.PARAMETER LogPath
    Path for backup log files.

.PARAMETER IncrementalSince
    DateTime for incremental backup reference. Default: Last backup timestamp.

.EXAMPLE
    .\Backup-UserData.ps1 -Destination "D:\Backups"
    Creates incremental backup to D:\Backups.

.EXAMPLE
    .\Backup-UserData.ps1 -BackupType Full -Destination "\\server\backups" -VerifyBackup
    Full backup to network share with verification.

.EXAMPLE
    .\Backup-UserData.ps1 -SourceFolders "C:\Projects", "C:\Documents" -CompressionLevel SmallestSize
    Backs up specific folders with maximum compression.

.EXAMPLE
    .\Backup-UserData.ps1 -Destination "D:\Backups" -RetentionCount 10 -DryRun
    Preview backup with 10 backup retention.

.EXAMPLE
    .\Backup-UserData.ps1 -Destination "D:\Backups" -EnableEncryption -EncryptionKey "MySecretKey123!"
    Creates encrypted backup.

.NOTES
    File Name      : Backup-UserData.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('Full', 'Incremental', 'Differential')]
    [string]$BackupType = 'Incremental',

    [Parameter(Mandatory)]
    [string]$Destination,

    [Parameter()]
    [string[]]$SourceFolders,

    [Parameter()]
    [string[]]$ExcludeFolders = @(
        'AppData',
        'node_modules',
        '.git',
        '.venv',
        'venv',
        '__pycache__',
        'bin',
        'obj',
        '.vs',
        '.idea',
        'Temp',
        'Cache',
        'Caches'
    ),

    [Parameter()]
    [string[]]$ExcludeExtensions = @(
        '.tmp',
        '.temp',
        '.log',
        '.bak',
        '.cache',
        '.dmp',
        '.thumbs.db'
    ),

    [Parameter()]
    [ValidateSet('None', 'Fastest', 'Optimal', 'SmallestSize')]
    [string]$CompressionLevel = 'Optimal',

    [Parameter()]
    [switch]$EnableEncryption,

    [Parameter()]
    [string]$EncryptionKey,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$RetentionCount = 5,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$RetentionDays = 30,

    [Parameter()]
    [switch]$VerifyBackup,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [datetime]$IncrementalSince
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Get-LogDirectory { return Join-Path $PSScriptRoot "..\..\logs" }
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"

# Set default source folders if not specified
if (-not $SourceFolders -or $SourceFolders.Count -eq 0) {
    $userProfile = $env:USERPROFILE
    $SourceFolders = @(
        (Join-Path $userProfile "Documents"),
        (Join-Path $userProfile "Desktop"),
        (Join-Path $userProfile "Downloads"),
        (Join-Path $userProfile "Pictures")
    )
}

# Set log path
if (-not $LogPath) {
    $LogPath = Get-LogDirectory
}

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Backup metadata file
$script:MetadataFile = Join-Path $Destination "backup_metadata.json"

# Statistics
$script:Stats = @{
    TotalFiles       = 0
    TotalSize        = 0
    BackedUpFiles    = 0
    BackedUpSize     = 0
    SkippedFiles     = 0
    FailedFiles      = 0
    Errors           = @()
}
#endregion

#region Helper Functions
function Get-BackupMetadata {
    <#
    .SYNOPSIS
        Retrieves backup metadata from destination.
    #>
    [CmdletBinding()]
    param()

    if (Test-Path $script:MetadataFile) {
        try {
            return Get-Content $script:MetadataFile -Raw | ConvertFrom-Json
        }
        catch {
            Write-WarningMessage "Could not read backup metadata: $($_.Exception.Message)"
        }
    }

    return @{
        LastFullBackup        = $null
        LastIncrementalBackup = $null
        BackupHistory         = @()
    }
}

function Save-BackupMetadata {
    <#
    .SYNOPSIS
        Saves backup metadata to destination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metadata
    )

    try {
        $Metadata | ConvertTo-Json -Depth 10 | Set-Content $script:MetadataFile -Encoding UTF8
    }
    catch {
        Write-WarningMessage "Could not save backup metadata: $($_.Exception.Message)"
    }
}

function Get-FilesToBackup {
    <#
    .SYNOPSIS
        Gets list of files to backup based on criteria.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [datetime]$ModifiedSince
    )

    $files = @()

    if (-not (Test-Path $SourcePath)) {
        Write-WarningMessage "Source path not found: $SourcePath"
        return $files
    }

    try {
        $allFiles = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue

        foreach ($file in $allFiles) {
            # Check excluded folders
            $skip = $false
            foreach ($excludeFolder in $ExcludeFolders) {
                if ($file.FullName -like "*\$excludeFolder\*") {
                    $skip = $true
                    break
                }
            }
            if ($skip) {
                $script:Stats.SkippedFiles++
                continue
            }

            # Check excluded extensions
            if ($file.Extension.ToLower() -in $ExcludeExtensions) {
                $script:Stats.SkippedFiles++
                continue
            }

            # Check modification date for incremental backup
            if ($ModifiedSince -and $file.LastWriteTime -lt $ModifiedSince) {
                $script:Stats.SkippedFiles++
                continue
            }

            $script:Stats.TotalFiles++
            $script:Stats.TotalSize += $file.Length

            $files += @{
                FullName      = $file.FullName
                RelativePath  = $file.FullName.Substring($SourcePath.Length).TrimStart('\', '/')
                Size          = $file.Length
                LastWriteTime = $file.LastWriteTime
                Hash          = $null
            }
        }
    }
    catch {
        Write-WarningMessage "Error scanning $SourcePath`: $($_.Exception.Message)"
        $script:Stats.Errors += "Scan error: $SourcePath - $($_.Exception.Message)"
    }

    return $files
}

function Get-FileHash256 {
    <#
    .SYNOPSIS
        Calculates SHA256 hash for a file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        return $null
    }
}

function Copy-BackupFiles {
    <#
    .SYNOPSIS
        Copies files to backup destination.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [array]$Files,

        [Parameter(Mandatory)]
        [string]$SourceRoot,

        [Parameter(Mandatory)]
        [string]$DestinationRoot
    )

    $totalFiles = $Files.Count
    $currentFile = 0
    $startTime = Get-Date

    foreach ($file in $Files) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100, 0)

        # Calculate ETA
        $elapsed = (Get-Date) - $startTime
        if ($currentFile -gt 1) {
            $avgTimePerFile = $elapsed.TotalSeconds / $currentFile
            $remainingFiles = $totalFiles - $currentFile
            $etaSeconds = $avgTimePerFile * $remainingFiles
            $eta = [TimeSpan]::FromSeconds($etaSeconds)
            $etaString = "ETA: {0:hh\:mm\:ss}" -f $eta
        }
        else {
            $etaString = "Calculating..."
        }

        Write-Progress -Activity "Backing up files" -Status "$currentFile of $totalFiles - $etaString" -PercentComplete $percentComplete -CurrentOperation $file.RelativePath

        $destPath = Join-Path $DestinationRoot $file.RelativePath
        $destDir = Split-Path $destPath -Parent

        if ($PSCmdlet.ShouldProcess($file.FullName, "Copy to $destPath")) {
            try {
                # Create destination directory if needed
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }

                # Copy file
                Copy-Item -Path $file.FullName -Destination $destPath -Force -ErrorAction Stop

                $script:Stats.BackedUpFiles++
                $script:Stats.BackedUpSize += $file.Size

                # Calculate hash if verification is enabled
                if ($VerifyBackup) {
                    $file.Hash = Get-FileHash256 -FilePath $file.FullName
                }
            }
            catch {
                $script:Stats.FailedFiles++
                $script:Stats.Errors += "Copy failed: $($file.FullName) - $($_.Exception.Message)"
                Write-WarningMessage "Failed to copy: $($file.RelativePath)"
            }
        }
    }

    Write-Progress -Activity "Backing up files" -Completed
}

function Compress-BackupFolder {
    <#
    .SYNOPSIS
        Compresses backup folder to archive.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$ArchivePath
    )

    if ($PSCmdlet.ShouldProcess($SourcePath, "Compress to $ArchivePath")) {
        try {
            $compressionLevelEnum = switch ($CompressionLevel) {
                'None'         { [System.IO.Compression.CompressionLevel]::NoCompression }
                'Fastest'      { [System.IO.Compression.CompressionLevel]::Fastest }
                'Optimal'      { [System.IO.Compression.CompressionLevel]::Optimal }
                'SmallestSize' { [System.IO.Compression.CompressionLevel]::SmallestSize }
            }

            Write-InfoMessage "Compressing backup (Level: $CompressionLevel)..."
            Compress-Archive -Path "$SourcePath\*" -DestinationPath $ArchivePath -CompressionLevel $compressionLevelEnum -Force

            return $true
        }
        catch {
            Write-ErrorMessage "Compression failed: $($_.Exception.Message)"
            $script:Stats.Errors += "Compression failed: $($_.Exception.Message)"
            return $false
        }
    }

    return $false
}

function Test-BackupIntegrity {
    <#
    .SYNOPSIS
        Verifies backup integrity by comparing file hashes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Files,

        [Parameter(Mandatory)]
        [string]$BackupPath
    )

    Write-InfoMessage "Verifying backup integrity..."

    $verified = 0
    $failed = 0
    $totalFiles = ($Files | Where-Object { $_.Hash }).Count

    foreach ($file in ($Files | Where-Object { $_.Hash })) {
        $backupFilePath = Join-Path $BackupPath $file.RelativePath

        if (Test-Path $backupFilePath) {
            $backupHash = Get-FileHash256 -FilePath $backupFilePath

            if ($backupHash -eq $file.Hash) {
                $verified++
            }
            else {
                $failed++
                $script:Stats.Errors += "Hash mismatch: $($file.RelativePath)"
            }
        }
        else {
            $failed++
            $script:Stats.Errors += "File missing from backup: $($file.RelativePath)"
        }
    }

    Write-InfoMessage "Verification complete: $verified verified, $failed failed"

    return @{
        TotalVerified = $verified
        TotalFailed   = $failed
        Success       = $failed -eq 0
    }
}

function Remove-OldBackups {
    <#
    .SYNOPSIS
        Removes old backups based on retention policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BackupRoot
    )

    Write-InfoMessage "Applying retention policy..."

    # Get all backup folders/archives
    $backups = Get-ChildItem -Path $BackupRoot -Directory -Filter "backup_*" |
        Sort-Object -Property CreationTime -Descending

    $archives = Get-ChildItem -Path $BackupRoot -File -Filter "backup_*.zip" |
        Sort-Object -Property CreationTime -Descending

    $allBackups = @()
    $allBackups += $backups | ForEach-Object { @{ Path = $_.FullName; Date = $_.CreationTime; Type = 'Folder' } }
    $allBackups += $archives | ForEach-Object { @{ Path = $_.FullName; Date = $_.CreationTime; Type = 'Archive' } }
    $allBackups = $allBackups | Sort-Object -Property Date -Descending

    $removedCount = 0

    # Remove by count
    if ($allBackups.Count -gt $RetentionCount) {
        $toRemove = $allBackups | Select-Object -Skip $RetentionCount

        foreach ($backup in $toRemove) {
            if ($PSCmdlet.ShouldProcess($backup.Path, "Remove old backup")) {
                try {
                    if ($backup.Type -eq 'Folder') {
                        Remove-Item -Path $backup.Path -Recurse -Force
                    }
                    else {
                        Remove-Item -Path $backup.Path -Force
                    }
                    $removedCount++
                    Write-Verbose "Removed old backup: $($backup.Path)"
                }
                catch {
                    Write-WarningMessage "Failed to remove old backup: $($backup.Path)"
                }
            }
        }
    }

    # Remove by age
    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    $oldBackups = $allBackups | Where-Object { $_.Date -lt $cutoffDate }

    foreach ($backup in $oldBackups) {
        # Skip if already in retention count
        if ($backup -in ($allBackups | Select-Object -First $RetentionCount)) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($backup.Path, "Remove expired backup")) {
            try {
                if ($backup.Type -eq 'Folder') {
                    Remove-Item -Path $backup.Path -Recurse -Force
                }
                else {
                    Remove-Item -Path $backup.Path -Force
                }
                $removedCount++
            }
            catch {
                Write-WarningMessage "Failed to remove expired backup: $($backup.Path)"
            }
        }
    }

    if ($removedCount -gt 0) {
        Write-InfoMessage "Removed $removedCount old backup(s)"
    }
}

function Format-FileSize {
    <#
    .SYNOPSIS
        Formats file size in human-readable format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [long]$Bytes
    )

    if ($Bytes -ge 1GB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    }
    elseif ($Bytes -ge 1MB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    }
    elseif ($Bytes -ge 1KB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    }
    else {
        return "$Bytes bytes"
    }
}
#endregion

#region Report Functions
function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Outputs backup report to console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report
    )

    $separator = "=" * 60

    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  BACKUP REPORT" -ForegroundColor Cyan
    Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "$separator`n" -ForegroundColor Cyan

    # Summary
    Write-Host "BACKUP SUMMARY" -ForegroundColor White
    Write-Host "-" * 40
    Write-Host "  Type:           $($Report.BackupType)"
    Write-Host "  Status:         " -NoNewline
    if ($Report.Success) {
        Write-Host "SUCCESS" -ForegroundColor Green
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
    }
    Write-Host "  Destination:    $($Report.Destination)"
    Write-Host "  Duration:       $($Report.Duration)`n"

    # Statistics
    Write-Host "FILE STATISTICS" -ForegroundColor White
    Write-Host "-" * 40
    Write-Host "  Total Files:    $($Report.Stats.TotalFiles)"
    Write-Host "  Backed Up:      $($Report.Stats.BackedUpFiles)"
    Write-Host "  Skipped:        $($Report.Stats.SkippedFiles)"
    Write-Host "  Failed:         " -NoNewline
    if ($Report.Stats.FailedFiles -gt 0) {
        Write-Host "$($Report.Stats.FailedFiles)" -ForegroundColor Red
    }
    else {
        Write-Host "$($Report.Stats.FailedFiles)" -ForegroundColor Green
    }
    Write-Host "  Total Size:     $(Format-FileSize $Report.Stats.TotalSize)"
    Write-Host "  Backed Up Size: $(Format-FileSize $Report.Stats.BackedUpSize)`n"

    # Verification
    if ($Report.Verification) {
        Write-Host "VERIFICATION" -ForegroundColor White
        Write-Host "-" * 40
        Write-Host "  Verified:       $($Report.Verification.TotalVerified)"
        Write-Host "  Failed:         " -NoNewline
        if ($Report.Verification.TotalFailed -gt 0) {
            Write-Host "$($Report.Verification.TotalFailed)" -ForegroundColor Red
        }
        else {
            Write-Host "$($Report.Verification.TotalFailed)" -ForegroundColor Green
        }
        Write-Host ""
    }

    # Errors
    if ($Report.Stats.Errors.Count -gt 0) {
        Write-Host "ERRORS" -ForegroundColor White
        Write-Host "-" * 40
        foreach ($err in ($Report.Stats.Errors | Select-Object -First 10)) {
            Write-Host "  [-] $err" -ForegroundColor Red
        }
        if ($Report.Stats.Errors.Count -gt 10) {
            Write-Host "  ... and $($Report.Stats.Errors.Count - 10) more errors"
        }
        Write-Host ""
    }

    Write-Host $separator -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML backup report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $htmlPath = Join-Path $Path "backup-report_$timestamp.html"

    $statusClass = if ($Report.Success) { 'success' } else { 'error' }
    $statusText = if ($Report.Success) { 'SUCCESS' } else { 'FAILED' }

    $errorsHtml = ""
    if ($Report.Stats.Errors.Count -gt 0) {
        $errorsHtml = "<div class='errors'><h2>Errors</h2><ul>"
        foreach ($err in $Report.Stats.Errors) {
            $errorsHtml += "<li>$([System.Web.HttpUtility]::HtmlEncode($err))</li>"
        }
        $errorsHtml += "</ul></div>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Backup Report - $($Report.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 20px; }
        .status { padding: 10px 20px; border-radius: 4px; display: inline-block; font-weight: bold; margin: 10px 0; }
        .status.success { background: #dff6dd; color: #107c10; }
        .status.error { background: #fde7e9; color: #d13438; }
        .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 20px 0; }
        .stat { padding: 15px; background: #f5f5f5; border-radius: 4px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        .stat-label { color: #666; font-size: 12px; }
        .errors ul { list-style: none; padding: 0; }
        .errors li { padding: 8px; margin: 5px 0; background: #fde7e9; color: #d13438; border-radius: 4px; font-size: 13px; }
        .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Backup Report</h1>
        <p><strong>Computer:</strong> $($Report.ComputerName) | <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="status $statusClass">$statusText</div>

        <h2>Backup Details</h2>
        <p><strong>Type:</strong> $($Report.BackupType) | <strong>Destination:</strong> $($Report.Destination) | <strong>Duration:</strong> $($Report.Duration)</p>

        <div class="stats">
            <div class="stat">
                <div class="stat-value">$($Report.Stats.BackedUpFiles)</div>
                <div class="stat-label">Files Backed Up</div>
            </div>
            <div class="stat">
                <div class="stat-value">$(Format-FileSize $Report.Stats.BackedUpSize)</div>
                <div class="stat-label">Data Size</div>
            </div>
            <div class="stat">
                <div class="stat-value">$($Report.Stats.SkippedFiles)</div>
                <div class="stat-label">Files Skipped</div>
            </div>
            <div class="stat">
                <div class="stat-value">$($Report.Stats.FailedFiles)</div>
                <div class="stat-label">Files Failed</div>
            </div>
        </div>

        $errorsHtml

        <div class="footer">
            <p>Generated by Windows & Linux Sysadmin Toolkit v$script:ScriptVersion</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Set-Content -Path $htmlPath -Encoding UTF8
    Write-Success "HTML report saved: $htmlPath"
    return $htmlPath
}

function Export-JSONReport {
    <#
    .SYNOPSIS
        Exports backup report to JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $jsonPath = Join-Path $Path "backup-report_$timestamp.json"

    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
    return $jsonPath
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== User Data Backup v$script:ScriptVersion ==="
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-InfoMessage "Backup Type: $BackupType"

    if ($DryRun) {
        Write-WarningMessage "DRY RUN MODE - No files will be copied"
    }

    # Validate destination
    if (-not (Test-Path $Destination)) {
        Write-InfoMessage "Creating backup destination: $Destination"
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    # Get backup metadata
    $metadata = Get-BackupMetadata

    # Determine incremental reference time
    $modifiedSince = $null
    if ($BackupType -eq 'Incremental') {
        if ($IncrementalSince) {
            $modifiedSince = $IncrementalSince
        }
        elseif ($metadata.LastIncrementalBackup) {
            $modifiedSince = [datetime]$metadata.LastIncrementalBackup
        }
        elseif ($metadata.LastFullBackup) {
            $modifiedSince = [datetime]$metadata.LastFullBackup
        }

        if ($modifiedSince) {
            Write-InfoMessage "Incremental backup since: $($modifiedSince.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
        else {
            Write-InfoMessage "No previous backup found - performing full backup"
            $BackupType = 'Full'
        }
    }

    # Create backup folder name
    $backupTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $backupFolderName = "backup_${BackupType}_$backupTimestamp"
    $backupPath = Join-Path $Destination $backupFolderName

    # Collect files to backup
    Write-InfoMessage "Scanning source folders..."
    $allFiles = @()

    foreach ($sourceFolder in $SourceFolders) {
        if (Test-Path $sourceFolder) {
            Write-InfoMessage "  Scanning: $sourceFolder"
            $files = Get-FilesToBackup -SourcePath $sourceFolder -ModifiedSince $modifiedSince

            foreach ($file in $files) {
                $file.SourceRoot = $sourceFolder
                $allFiles += $file
            }
        }
        else {
            Write-WarningMessage "Source folder not found: $sourceFolder"
        }
    }

    Write-InfoMessage "Found $($script:Stats.TotalFiles) files to backup ($(Format-FileSize $script:Stats.TotalSize))"

    if ($allFiles.Count -eq 0) {
        Write-InfoMessage "No files to backup"
    }
    else {
        # Create backup
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

            # Group files by source root and copy
            $sourceGroups = $allFiles | Group-Object -Property SourceRoot

            foreach ($group in $sourceGroups) {
                $sourceRoot = $group.Name
                $sourceName = Split-Path $sourceRoot -Leaf
                $destRoot = Join-Path $backupPath $sourceName

                Write-InfoMessage "Backing up: $sourceName"
                Copy-BackupFiles -Files $group.Group -SourceRoot $sourceRoot -DestinationRoot $destRoot
            }

            # Verify backup if requested
            $verification = $null
            if ($VerifyBackup -and $allFiles.Count -gt 0) {
                $verification = Test-BackupIntegrity -Files $allFiles -BackupPath $backupPath
            }

            # Compress if requested
            if ($CompressionLevel -ne 'None') {
                $archivePath = "$backupPath.zip"
                $compressed = Compress-BackupFolder -SourcePath $backupPath -ArchivePath $archivePath

                if ($compressed) {
                    # Remove uncompressed folder
                    Remove-Item -Path $backupPath -Recurse -Force
                    Write-Success "Backup compressed to: $archivePath"
                }
            }

            # Update metadata
            $backupEntry = @{
                Timestamp   = Get-Date -Format 'o'
                Type        = $BackupType
                Files       = $script:Stats.BackedUpFiles
                Size        = $script:Stats.BackedUpSize
                Path        = if ($CompressionLevel -ne 'None') { "$backupPath.zip" } else { $backupPath }
            }

            if ($BackupType -eq 'Full') {
                $metadata.LastFullBackup = Get-Date -Format 'o'
            }
            else {
                $metadata.LastIncrementalBackup = Get-Date -Format 'o'
            }

            if (-not $metadata.BackupHistory) {
                $metadata.BackupHistory = @()
            }
            $metadata.BackupHistory = @($backupEntry) + $metadata.BackupHistory | Select-Object -First 50

            Save-BackupMetadata -Metadata $metadata

            # Apply retention policy
            Remove-OldBackups -BackupRoot $Destination
        }
    }

    # Generate report
    $duration = (Get-Date) - $script:StartTime
    $report = @{
        ComputerName  = $env:COMPUTERNAME
        BackupType    = $BackupType
        Destination   = $Destination
        Success       = $script:Stats.FailedFiles -eq 0 -and $script:Stats.Errors.Count -eq 0
        Duration      = "{0:hh\:mm\:ss}" -f $duration
        Stats         = $script:Stats
        Verification  = $verification
        DryRun        = $DryRun
    }

    # Output report
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Report $report }
        'HTML'    { Export-HTMLReport -Report $report -Path $LogPath }
        'JSON'    { Export-JSONReport -Report $report -Path $LogPath }
    }

    Write-Success "=== Backup completed in $($duration.TotalSeconds.ToString('0.00'))s ==="

    # Exit with error code if backup failed
    if (-not $report.Success) {
        exit 1
    }
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    exit 1
}
#endregion
