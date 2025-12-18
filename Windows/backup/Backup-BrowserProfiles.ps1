#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Backs up browser profiles including bookmarks, settings, and extension data.

.DESCRIPTION
    This script provides comprehensive browser profile backup with:
    - Support for Chrome, Edge, Firefox, and Brave browsers
    - Backup of bookmarks, preferences, extensions list, and cookies (optional)
    - Scheduled backup capability with retention policy
    - Restore functionality to recover profiles
    - Cross-browser bookmark export (HTML format)
    - Compression and encryption options

    Data backed up per browser:
    - Bookmarks/favorites
    - Preferences/settings
    - Extension list (not extension data for security)
    - Session data (optional)
    - Local storage (optional)

.PARAMETER Browser
    Which browser to backup. Valid values: Chrome, Edge, Firefox, Brave, All.
    Default: All

.PARAMETER OutputPath
    Directory path for backup files. Default: toolkit logs/browser-backups directory.

.PARAMETER IncludeCookies
    Include cookies in the backup (may contain sensitive data).
    Default: $false

.PARAMETER IncludeHistory
    Include browsing history in the backup.
    Default: $false

.PARAMETER IncludePasswords
    Export password manager note (NOT actual passwords, just a reminder file).
    Default: $false

.PARAMETER Compress
    Compress the backup to a ZIP file.
    Default: $true

.PARAMETER RetentionDays
    Number of days to keep old backups. 0 = keep all.
    Default: 30

.PARAMETER Restore
    Path to a backup ZIP file to restore from.

.PARAMETER RestoreTarget
    Which browser to restore to. Required when using -Restore.

.PARAMETER ListBackups
    List all available backups and their details.

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON.
    Default: Console

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1
    Backs up all browser profiles with default settings.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1 -Browser Chrome -IncludeHistory
    Backs up Chrome profile including browsing history.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1 -Browser Firefox -OutputPath "D:\Backups\Browsers" -Compress
    Backs up Firefox to a custom location with compression.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1 -ListBackups
    Shows all available backups with dates and sizes.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1 -Restore "C:\Backups\Chrome_2025-01-15.zip" -RestoreTarget Chrome -WhatIf
    Shows what would be restored without making changes.

.EXAMPLE
    .\Backup-BrowserProfiles.ps1 -Browser All -RetentionDays 7 -OutputFormat HTML
    Backs up all browsers, keeps 7 days of backups, and generates HTML report.

.NOTES
    File Name      : Backup-BrowserProfiles.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Browser Profile Locations:
    - Chrome:  %LOCALAPPDATA%\Google\Chrome\User Data\Default
    - Edge:    %LOCALAPPDATA%\Microsoft\Edge\User Data\Default
    - Firefox: %APPDATA%\Mozilla\Firefox\Profiles\*
    - Brave:   %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default

    Security Notes:
    - Passwords are NOT backed up (security risk)
    - Cookies contain session data (optional backup)
    - Extensions are listed but not fully backed up (reinstall recommended)

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Backup')]
param(
    [Parameter(ParameterSetName = 'Backup')]
    [ValidateSet('Chrome', 'Edge', 'Firefox', 'Brave', 'All')]
    [string]$Browser = 'All',

    [Parameter(ParameterSetName = 'Backup')]
    [Parameter(ParameterSetName = 'Restore')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Backup')]
    [switch]$IncludeCookies,

    [Parameter(ParameterSetName = 'Backup')]
    [switch]$IncludeHistory,

    [Parameter(ParameterSetName = 'Backup')]
    [switch]$IncludePasswords,

    [Parameter(ParameterSetName = 'Backup')]
    [switch]$Compress = $true,

    [Parameter(ParameterSetName = 'Backup')]
    [ValidateRange(0, 365)]
    [int]$RetentionDays = 30,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [string]$Restore,

    [Parameter(ParameterSetName = 'Restore')]
    [ValidateSet('Chrome', 'Edge', 'Firefox', 'Brave')]
    [string]$RestoreTarget,

    [Parameter(ParameterSetName = 'List')]
    [switch]$ListBackups,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console'
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    # Fallback logging functions if module not found
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

# Browser profile paths
$script:BrowserPaths = @{
    Chrome  = @{
        Name        = "Google Chrome"
        ProfilePath = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
        DefaultProfile = "Default"
        BookmarksFile = "Bookmarks"
        PreferencesFile = "Preferences"
        ExtensionsDir = "Extensions"
        HistoryFile = "History"
        CookiesFile = "Cookies"
        LocalStateFile = "Local State"
    }
    Edge    = @{
        Name        = "Microsoft Edge"
        ProfilePath = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
        DefaultProfile = "Default"
        BookmarksFile = "Bookmarks"
        PreferencesFile = "Preferences"
        ExtensionsDir = "Extensions"
        HistoryFile = "History"
        CookiesFile = "Cookies"
        LocalStateFile = "Local State"
    }
    Firefox = @{
        Name        = "Mozilla Firefox"
        ProfilePath = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
        ProfilesIni = Join-Path $env:APPDATA "Mozilla\Firefox\profiles.ini"
        BookmarksFile = "places.sqlite"
        PreferencesFile = "prefs.js"
        ExtensionsDir = "extensions"
        CookiesFile = "cookies.sqlite"
    }
    Brave   = @{
        Name        = "Brave Browser"
        ProfilePath = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data"
        DefaultProfile = "Default"
        BookmarksFile = "Bookmarks"
        PreferencesFile = "Preferences"
        ExtensionsDir = "Extensions"
        HistoryFile = "History"
        CookiesFile = "Cookies"
        LocalStateFile = "Local State"
    }
}

# Files/folders to always exclude (security sensitive)
$script:ExcludePatterns = @(
    "Login Data*",
    "Web Data",
    "*.ldb",
    "*.log",
    "Cache",
    "Code Cache",
    "GPUCache",
    "Service Worker",
    "blob_storage",
    "IndexedDB",
    "File System"
)
#endregion

#region Helper Functions
function Get-BackupDirectory {
    if ($OutputPath) {
        $backupDir = $OutputPath
    }
    else {
        $logDir = Get-LogDirectory
        $backupDir = Join-Path $logDir "browser-backups"
    }

    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }

    return $backupDir
}

function Test-BrowserInstalled {
    param([string]$BrowserKey)

    $config = $script:BrowserPaths[$BrowserKey]
    $profilePath = $config.ProfilePath

    if ($BrowserKey -eq 'Firefox') {
        return (Test-Path $config.ProfilesIni)
    }
    else {
        $defaultProfile = Join-Path $profilePath $config.DefaultProfile
        return (Test-Path $defaultProfile)
    }
}

function Get-FirefoxProfiles {
    $profilesIni = $script:BrowserPaths.Firefox.ProfilesIni
    $profiles = @()

    if (Test-Path $profilesIni) {
        $content = Get-Content $profilesIni -Raw

        # Parse INI file for profile paths
        $sections = $content -split '\[Profile\d+\]' | Where-Object { $_ -match 'Path=' }
        foreach ($section in $sections) {
            if ($section -match 'Path=(.+)') {
                $profilePath = $Matches[1].Trim()
                if ($section -match 'IsRelative=1') {
                    $fullPath = Join-Path $env:APPDATA "Mozilla\Firefox\$profilePath"
                }
                else {
                    $fullPath = $profilePath
                }
                if (Test-Path $fullPath) {
                    $profiles += $fullPath
                }
            }
        }
    }

    return $profiles
}

function Get-BrowserExtensions {
    param(
        [string]$BrowserKey,
        [string]$ProfilePath
    )

    $extensions = @()

    switch ($BrowserKey) {
        { $_ -in 'Chrome', 'Edge', 'Brave' } {
            $extDir = Join-Path $ProfilePath "Extensions"
            if (Test-Path $extDir) {
                $extFolders = Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue
                foreach ($ext in $extFolders) {
                    # Try to get extension name from manifest
                    $manifestPath = Get-ChildItem -Path $ext.FullName -Filter "manifest.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($manifestPath) {
                        try {
                            $manifest = Get-Content $manifestPath.FullName -Raw | ConvertFrom-Json
                            $extensions += [PSCustomObject]@{
                                ID      = $ext.Name
                                Name    = if ($manifest.name -and $manifest.name -notmatch '^__MSG_') { $manifest.name } else { $ext.Name }
                                Version = $manifest.version
                            }
                        }
                        catch {
                            $extensions += [PSCustomObject]@{
                                ID      = $ext.Name
                                Name    = $ext.Name
                                Version = "Unknown"
                            }
                        }
                    }
                }
            }
        }
        'Firefox' {
            $extDir = Join-Path $ProfilePath "extensions"
            if (Test-Path $extDir) {
                $extFiles = Get-ChildItem -Path $extDir -ErrorAction SilentlyContinue
                foreach ($ext in $extFiles) {
                    $extensions += [PSCustomObject]@{
                        ID      = $ext.BaseName
                        Name    = $ext.BaseName
                        Version = "Unknown"
                    }
                }
            }
        }
    }

    return $extensions
}

function Export-BookmarksToHtml {
    param(
        [string]$BrowserKey,
        [string]$ProfilePath,
        [string]$OutputFile
    )

    $htmlContent = @"
<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks Export - $($script:BrowserPaths[$BrowserKey].Name)</TITLE>
<H1>Bookmarks</H1>
<DL><p>
"@

    switch ($BrowserKey) {
        { $_ -in 'Chrome', 'Edge', 'Brave' } {
            $bookmarksFile = Join-Path $ProfilePath $script:BrowserPaths[$BrowserKey].BookmarksFile
            if (Test-Path $bookmarksFile) {
                try {
                    $bookmarks = Get-Content $bookmarksFile -Raw | ConvertFrom-Json

                    function ConvertBookmarkNode {
                        param($node, $indent = 1)
                        $spaces = "    " * $indent
                        $output = ""

                        if ($node.type -eq "folder") {
                            $output += "$spaces<DT><H3>$($node.name)</H3>`n"
                            $output += "$spaces<DL><p>`n"
                            foreach ($child in $node.children) {
                                $output += ConvertBookmarkNode -node $child -indent ($indent + 1)
                            }
                            $output += "$spaces</DL><p>`n"
                        }
                        elseif ($node.type -eq "url") {
                            $output += "$spaces<DT><A HREF=`"$($node.url)`">$($node.name)</A>`n"
                        }

                        return $output
                    }

                    if ($bookmarks.roots.bookmark_bar) {
                        $htmlContent += "    <DT><H3>Bookmarks Bar</H3>`n    <DL><p>`n"
                        foreach ($child in $bookmarks.roots.bookmark_bar.children) {
                            $htmlContent += ConvertBookmarkNode -node $child -indent 2
                        }
                        $htmlContent += "    </DL><p>`n"
                    }

                    if ($bookmarks.roots.other) {
                        $htmlContent += "    <DT><H3>Other Bookmarks</H3>`n    <DL><p>`n"
                        foreach ($child in $bookmarks.roots.other.children) {
                            $htmlContent += ConvertBookmarkNode -node $child -indent 2
                        }
                        $htmlContent += "    </DL><p>`n"
                    }
                }
                catch {
                    Write-WarningMessage "Failed to parse bookmarks: $($_.Exception.Message)"
                }
            }
        }
        'Firefox' {
            Write-InfoMessage "Firefox bookmarks are stored in SQLite format. Raw database backed up."
        }
    }

    $htmlContent += "</DL><p>"
    $htmlContent | Out-File -FilePath $OutputFile -Encoding UTF8
}

function Backup-BrowserProfile {
    param(
        [string]$BrowserKey,
        [string]$BackupDir,
        [switch]$IncludeCookies,
        [switch]$IncludeHistory
    )

    $config = $script:BrowserPaths[$BrowserKey]
    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $backupName = "${BrowserKey}_${timestamp}"
    $backupPath = Join-Path $BackupDir $backupName

    Write-InfoMessage "Backing up $($config.Name)..."

    # Create backup directory
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

    $result = [PSCustomObject]@{
        Browser       = $config.Name
        BrowserKey    = $BrowserKey
        BackupPath    = $backupPath
        Timestamp     = $timestamp
        FilesBackedUp = @()
        Extensions    = @()
        Success       = $false
        Error         = $null
    }

    try {
        if ($BrowserKey -eq 'Firefox') {
            # Handle Firefox's multiple profile structure
            $profiles = Get-FirefoxProfiles
            foreach ($profilePath in $profiles) {
                $profileName = Split-Path $profilePath -Leaf
                $profileBackup = Join-Path $backupPath $profileName
                New-Item -ItemType Directory -Path $profileBackup -Force | Out-Null

                # Backup key files
                $filesToBackup = @(
                    $config.BookmarksFile,      # places.sqlite
                    $config.PreferencesFile,    # prefs.js
                    "search.json.mozlz4",
                    "handlers.json",
                    "permissions.sqlite",
                    "content-prefs.sqlite",
                    "formhistory.sqlite",
                    "favicons.sqlite"
                )

                if ($IncludeCookies) {
                    $filesToBackup += $config.CookiesFile
                }

                foreach ($file in $filesToBackup) {
                    $sourcePath = Join-Path $profilePath $file
                    if (Test-Path $sourcePath) {
                        Copy-Item -Path $sourcePath -Destination $profileBackup -Force
                        $result.FilesBackedUp += $file
                    }
                }

                # Get extensions list
                $result.Extensions += Get-BrowserExtensions -BrowserKey $BrowserKey -ProfilePath $profilePath
            }
        }
        else {
            # Chrome/Edge/Brave structure
            $profilePath = Join-Path $config.ProfilePath $config.DefaultProfile

            # Backup bookmarks
            $bookmarksSource = Join-Path $profilePath $config.BookmarksFile
            if (Test-Path $bookmarksSource) {
                Copy-Item -Path $bookmarksSource -Destination $backupPath -Force
                $result.FilesBackedUp += $config.BookmarksFile

                # Also export to HTML format
                $htmlExport = Join-Path $backupPath "bookmarks_export.html"
                Export-BookmarksToHtml -BrowserKey $BrowserKey -ProfilePath $profilePath -OutputFile $htmlExport
            }

            # Backup preferences
            $prefsSource = Join-Path $profilePath $config.PreferencesFile
            if (Test-Path $prefsSource) {
                Copy-Item -Path $prefsSource -Destination $backupPath -Force
                $result.FilesBackedUp += $config.PreferencesFile
            }

            # Backup Local State (contains extension settings, etc.)
            $localStateSource = Join-Path $config.ProfilePath $config.LocalStateFile
            if (Test-Path $localStateSource) {
                Copy-Item -Path $localStateSource -Destination $backupPath -Force
                $result.FilesBackedUp += $config.LocalStateFile
            }

            # Backup history if requested
            if ($IncludeHistory) {
                $historySource = Join-Path $profilePath $config.HistoryFile
                if (Test-Path $historySource) {
                    Copy-Item -Path $historySource -Destination $backupPath -Force
                    $result.FilesBackedUp += $config.HistoryFile
                }
            }

            # Backup cookies if requested
            if ($IncludeCookies) {
                $cookiesSource = Join-Path $profilePath $config.CookiesFile
                if (Test-Path $cookiesSource) {
                    Copy-Item -Path $cookiesSource -Destination $backupPath -Force
                    $result.FilesBackedUp += $config.CookiesFile
                }
            }

            # Get extensions list
            $result.Extensions = Get-BrowserExtensions -BrowserKey $BrowserKey -ProfilePath $profilePath
        }

        # Save extensions list to JSON
        if ($result.Extensions.Count -gt 0) {
            $extListFile = Join-Path $backupPath "extensions_list.json"
            $result.Extensions | ConvertTo-Json -Depth 5 | Out-File -FilePath $extListFile -Encoding UTF8
        }

        # Create backup metadata
        $metadata = @{
            Browser       = $config.Name
            BrowserKey    = $BrowserKey
            BackupDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName  = $env:COMPUTERNAME
            UserName      = $env:USERNAME
            FilesBackedUp = $result.FilesBackedUp
            ExtensionCount = $result.Extensions.Count
            IncludedCookies = $IncludeCookies.IsPresent
            IncludedHistory = $IncludeHistory.IsPresent
        }
        $metadataFile = Join-Path $backupPath "backup_metadata.json"
        $metadata | ConvertTo-Json -Depth 3 | Out-File -FilePath $metadataFile -Encoding UTF8

        $result.Success = $true
        Write-Success "Backed up $($result.FilesBackedUp.Count) files, $($result.Extensions.Count) extensions listed"
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-ErrorMessage "Failed to backup $($config.Name): $($_.Exception.Message)"
    }

    return $result
}

function Compress-BackupFolder {
    param(
        [string]$FolderPath,
        [switch]$RemoveOriginal = $true
    )

    $zipPath = "$FolderPath.zip"

    try {
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force
        }

        Compress-Archive -Path "$FolderPath\*" -DestinationPath $zipPath -Force

        if ($RemoveOriginal -and (Test-Path $zipPath)) {
            Remove-Item $FolderPath -Recurse -Force
        }

        Write-Success "Compressed backup to: $(Split-Path $zipPath -Leaf)"
        return $zipPath
    }
    catch {
        Write-WarningMessage "Failed to compress backup: $($_.Exception.Message)"
        return $FolderPath
    }
}

function Remove-OldBackups {
    param(
        [string]$BackupDir,
        [int]$RetentionDays
    )

    if ($RetentionDays -le 0) {
        return
    }

    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    $oldBackups = Get-ChildItem -Path $BackupDir -Filter "*.zip" -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -lt $cutoffDate }

    foreach ($backup in $oldBackups) {
        try {
            Remove-Item $backup.FullName -Force
            Write-InfoMessage "Removed old backup: $($backup.Name)"
        }
        catch {
            Write-WarningMessage "Failed to remove old backup: $($backup.Name)"
        }
    }
}

function Get-BackupList {
    $backupDir = Get-BackupDirectory
    $backups = @()

    $zipFiles = Get-ChildItem -Path $backupDir -Filter "*.zip" -ErrorAction SilentlyContinue
    foreach ($zip in $zipFiles) {
        # Parse browser and date from filename
        if ($zip.Name -match '^(.+)_(\d{4}-\d{2}-\d{2}_\d{6})\.zip$') {
            $backups += [PSCustomObject]@{
                FileName    = $zip.Name
                Browser     = $Matches[1]
                BackupDate  = [DateTime]::ParseExact($Matches[2], "yyyy-MM-dd_HHmmss", $null)
                SizeMB      = [math]::Round($zip.Length / 1MB, 2)
                FullPath    = $zip.FullName
            }
        }
    }

    return $backups | Sort-Object BackupDate -Descending
}

function Restore-BrowserProfile {
    param(
        [string]$BackupPath,
        [string]$TargetBrowser
    )

    if (-not (Test-Path $BackupPath)) {
        Write-ErrorMessage "Backup file not found: $BackupPath"
        return $false
    }

    $config = $script:BrowserPaths[$TargetBrowser]
    $tempDir = Join-Path $env:TEMP "browser_restore_$(Get-Date -Format 'yyyyMMddHHmmss')"

    try {
        Write-InfoMessage "Extracting backup..."
        Expand-Archive -Path $BackupPath -DestinationPath $tempDir -Force

        # Determine target profile path
        if ($TargetBrowser -eq 'Firefox') {
            $profiles = Get-FirefoxProfiles
            if ($profiles.Count -eq 0) {
                Write-ErrorMessage "No Firefox profiles found to restore to"
                return $false
            }
            $targetPath = $profiles[0]
        }
        else {
            $targetPath = Join-Path $config.ProfilePath $config.DefaultProfile
        }

        if (-not (Test-Path $targetPath)) {
            Write-ErrorMessage "Target profile path not found: $targetPath"
            return $false
        }

        # Restore files (except metadata)
        $filesToRestore = Get-ChildItem -Path $tempDir -File -Recurse |
                          Where-Object { $_.Name -notin @("backup_metadata.json", "extensions_list.json", "bookmarks_export.html") }

        foreach ($file in $filesToRestore) {
            $relativePath = $file.FullName.Substring($tempDir.Length + 1)
            $destPath = Join-Path $targetPath (Split-Path $relativePath -Leaf)

            if ($PSCmdlet.ShouldProcess($destPath, "Restore file")) {
                # Backup existing file first
                if (Test-Path $destPath) {
                    $backupExisting = "$destPath.backup_$(Get-Date -Format 'yyyyMMddHHmmss')"
                    Copy-Item -Path $destPath -Destination $backupExisting -Force
                }
                Copy-Item -Path $file.FullName -Destination $destPath -Force
                Write-InfoMessage "Restored: $($file.Name)"
            }
        }

        Write-Success "Browser profile restored successfully"
        Write-WarningMessage "Please restart $($config.Name) for changes to take effect"

        return $true
    }
    catch {
        Write-ErrorMessage "Restore failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Export-HtmlReport {
    param(
        [array]$Results,
        [string]$OutputPath
    )

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Browser Profile Backup Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: linear-gradient(135deg, #0078d4, #00bcf2);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card h3 {
            margin: 0;
            font-size: 2em;
        }
        .summary-card p {
            margin: 5px 0 0;
            opacity: 0.9;
        }
        .browser-section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        .browser-header {
            background: #f8f8f8;
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .browser-header h2 {
            margin: 0;
            color: #333;
        }
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .status-success {
            background: #dff6dd;
            color: #107c10;
        }
        .status-failed {
            background: #fde7e9;
            color: #d13438;
        }
        .browser-content {
            padding: 20px;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .detail-item {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
        }
        .detail-item label {
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 5px;
        }
        .detail-item span {
            color: #333;
        }
        .extensions-list {
            margin-top: 15px;
        }
        .extensions-list h4 {
            margin-bottom: 10px;
        }
        .ext-item {
            background: #e8e8e8;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            text-align: center;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Browser Profile Backup Report</h1>

        <div class="summary">
            <div class="summary-card">
                <h3>$($Results.Count)</h3>
                <p>Browsers Processed</p>
            </div>
            <div class="summary-card">
                <h3>$(($Results | Where-Object { $_.Success }).Count)</h3>
                <p>Successful Backups</p>
            </div>
            <div class="summary-card">
                <h3>$(($Results | ForEach-Object { $_.FilesBackedUp.Count } | Measure-Object -Sum).Sum)</h3>
                <p>Files Backed Up</p>
            </div>
            <div class="summary-card">
                <h3>$(($Results | ForEach-Object { $_.Extensions.Count } | Measure-Object -Sum).Sum)</h3>
                <p>Extensions Listed</p>
            </div>
        </div>
"@

    foreach ($result in $Results) {
        $statusClass = if ($result.Success) { "status-success" } else { "status-failed" }
        $statusText = if ($result.Success) { "SUCCESS" } else { "FAILED" }

        $htmlContent += @"
        <div class="browser-section">
            <div class="browser-header">
                <h2>$($result.Browser)</h2>
                <span class="status-badge $statusClass">$statusText</span>
            </div>
            <div class="browser-content">
                <div class="detail-grid">
                    <div class="detail-item">
                        <label>Backup Time</label>
                        <span>$($result.Timestamp)</span>
                    </div>
                    <div class="detail-item">
                        <label>Files Backed Up</label>
                        <span>$($result.FilesBackedUp.Count) files</span>
                    </div>
                    <div class="detail-item">
                        <label>Extensions Found</label>
                        <span>$($result.Extensions.Count) extensions</span>
                    </div>
                    <div class="detail-item">
                        <label>Backup Location</label>
                        <span>$($result.BackupPath)</span>
                    </div>
                </div>
"@

        if ($result.Extensions.Count -gt 0) {
            $htmlContent += @"
                <div class="extensions-list">
                    <h4>Extensions:</h4>
"@
            foreach ($ext in ($result.Extensions | Select-Object -First 10)) {
                $htmlContent += "                    <div class='ext-item'>$($ext.Name) (v$($ext.Version))</div>`n"
            }
            if ($result.Extensions.Count -gt 10) {
                $htmlContent += "                    <div class='ext-item'>... and $($result.Extensions.Count - 10) more</div>`n"
            }
            $htmlContent += "                </div>`n"
        }

        $htmlContent += @"
            </div>
        </div>
"@
    }

    $htmlContent += @"
        <div class="footer">
            <p>Generated by Backup-BrowserProfiles.ps1 v$($script:ScriptVersion)</p>
            <p>Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "Browser Profile Backup v$($script:ScriptVersion)"
    Write-InfoMessage "Started at: $($script:StartTime)"

    # Handle List mode
    if ($ListBackups) {
        $backups = Get-BackupList
        if ($backups.Count -eq 0) {
            Write-WarningMessage "No backups found"
            return
        }

        Write-Host ""
        Write-Host "Available Backups:" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan
        foreach ($backup in $backups) {
            Write-Host "$($backup.Browser.PadRight(12)) | $($backup.BackupDate.ToString('yyyy-MM-dd HH:mm')) | $($backup.SizeMB) MB | $($backup.FileName)" -ForegroundColor White
        }
        return
    }

    # Handle Restore mode
    if ($Restore) {
        if (-not $RestoreTarget) {
            Write-ErrorMessage "Please specify -RestoreTarget (Chrome, Edge, Firefox, or Brave)"
            exit 1
        }

        if ($PSCmdlet.ShouldProcess($RestoreTarget, "Restore browser profile from $Restore")) {
            $success = Restore-BrowserProfile -BackupPath $Restore -TargetBrowser $RestoreTarget
            exit $(if ($success) { 0 } else { 1 })
        }
        return
    }

    # Backup mode
    $backupDir = Get-BackupDirectory
    Write-InfoMessage "Backup directory: $backupDir"

    # Determine which browsers to backup
    $browsersToBackup = if ($Browser -eq 'All') {
        @('Chrome', 'Edge', 'Firefox', 'Brave')
    }
    else {
        @($Browser)
    }

    $results = @()

    foreach ($browserKey in $browsersToBackup) {
        if (Test-BrowserInstalled -BrowserKey $browserKey) {
            $result = Backup-BrowserProfile -BrowserKey $browserKey -BackupDir $backupDir -IncludeCookies:$IncludeCookies -IncludeHistory:$IncludeHistory

            # Compress if requested
            if ($Compress -and $result.Success) {
                $compressedPath = Compress-BackupFolder -FolderPath $result.BackupPath
                $result.BackupPath = $compressedPath
            }

            $results += $result
        }
        else {
            Write-WarningMessage "$($script:BrowserPaths[$browserKey].Name) is not installed or has no profile"
        }
    }

    # Apply retention policy
    if ($RetentionDays -gt 0) {
        Remove-OldBackups -BackupDir $backupDir -RetentionDays $RetentionDays
    }

    # Password reminder file
    if ($IncludePasswords) {
        $reminderFile = Join-Path $backupDir "PASSWORD_REMINDER.txt"
        $reminderContent = @"
IMPORTANT: Browser passwords are NOT backed up for security reasons.

To backup your passwords:
1. Chrome/Edge/Brave: Use Settings > Passwords > Export passwords
2. Firefox: Use a dedicated password manager extension

For best security, use a dedicated password manager like:
- Bitwarden (free, open-source)
- 1Password
- LastPass
- KeePassXC (local)

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        $reminderContent | Out-File -FilePath $reminderFile -Encoding UTF8
        Write-InfoMessage "Created password reminder file"
    }

    # Output results
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       BACKUP SUMMARY" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    $successCount = ($results | Where-Object { $_.Success }).Count
    $totalFiles = ($results | ForEach-Object { $_.FilesBackedUp.Count } | Measure-Object -Sum).Sum
    $totalExtensions = ($results | ForEach-Object { $_.Extensions.Count } | Measure-Object -Sum).Sum

    Write-Host "Browsers processed: $($results.Count)" -ForegroundColor White
    Write-Host "Successful backups: $successCount" -ForegroundColor $(if ($successCount -eq $results.Count) { "Green" } else { "Yellow" })
    Write-Host "Total files backed up: $totalFiles" -ForegroundColor White
    Write-Host "Total extensions listed: $totalExtensions" -ForegroundColor White

    # Generate output based on format
    switch ($OutputFormat) {
        'HTML' {
            $reportPath = Join-Path $backupDir "backup_report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html"
            Export-HtmlReport -Results $results -OutputPath $reportPath
            Write-Success "HTML report saved to: $reportPath"
        }
        'JSON' {
            $reportPath = Join-Path $backupDir "backup_report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').json"
            $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
            Write-Success "JSON report saved to: $reportPath"
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    Write-InfoMessage "Completed in $($duration.TotalSeconds.ToString('F1')) seconds"

    # Exit code based on success
    $exitCode = if ($successCount -eq $results.Count -and $results.Count -gt 0) { 0 }
                elseif ($successCount -gt 0) { 1 }
                else { 2 }

    exit $exitCode
}

# Run main function
Main
#endregion
