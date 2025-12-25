#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Validates backup archives are restorable and uncorrupted.

.DESCRIPTION
    This script performs integrity testing on backup archives created by
    Backup-UserData.ps1 or similar backup tools. It supports:
    - Quick mode: Validate archive structure and sample file hashes
    - Full mode: Extract entire archive to temp location, verify all files
    - Restore mode: Actually restore to a target location for testing

    Key features:
    - SHA256 hash verification against backup_metadata.json
    - ZIP archive integrity testing
    - Configurable sample percentage for quick tests
    - Detailed integrity reports (Console, HTML, JSON)
    - Automatic cleanup of test restore folders

.PARAMETER BackupPath
    Path to the backup archive (.zip) or backup folder to test.

.PARAMETER TestType
    Type of integrity test to perform.
    - Quick: Validate structure and sample hashes (fastest)
    - Full: Extract and verify all files (thorough)
    - Restore: Actually restore to target location (most thorough)
    Default: Quick

.PARAMETER RestoreTarget
    Target directory for test restore (required if TestType is Restore).

.PARAMETER SamplePercent
    Percentage of files to verify in Quick mode. Default: 10

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON, All.
    Default: Console

.PARAMETER OutputPath
    Directory for report output files.

.PARAMETER IncludeFileList
    Include list of all verified files in the report.

.PARAMETER CleanupAfterTest
    Remove test restore folder after validation (applies to Full and Restore modes).

.EXAMPLE
    .\Test-BackupIntegrity.ps1 -BackupPath "D:\Backups\backup_2025-12-25.zip"
    Quick integrity check on the specified backup archive.

.EXAMPLE
    .\Test-BackupIntegrity.ps1 -BackupPath "D:\Backups\backup_2025-12-25.zip" -TestType Full -CleanupAfterTest
    Full extraction test with automatic cleanup.

.EXAMPLE
    .\Test-BackupIntegrity.ps1 -BackupPath "D:\Backups\backup_2025-12-25.zip" -TestType Restore -RestoreTarget "D:\TestRestore"
    Restore backup to test location for manual verification.

.NOTES
    File Name      : Test-BackupIntegrity.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+
    Version        : 1.0.0

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BackupPath,

    [ValidateSet('Quick', 'Full', 'Restore')]
    [string]$TestType = 'Quick',

    [string]$RestoreTarget,

    [ValidateRange(1, 100)]
    [int]$SamplePercent = 10,

    [ValidateSet('Console', 'HTML', 'JSON', 'All')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath,

    [switch]$IncludeFileList,

    [switch]$CleanupAfterTest
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
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"
$script:TempFolder = $null
$script:Stats = @{
    TotalFiles       = 0
    FilesVerified    = 0
    FilesFailed      = 0
    HashesMatched    = 0
    HashesFailed     = 0
    TotalSize        = 0
    VerifiedFiles    = @()
    FailedFiles      = @()
    Errors           = @()
    Warnings         = @()
}
#endregion

#region Helper Functions

function Get-BackupInfo {
    <#
    .SYNOPSIS
        Retrieves basic information about the backup.
    #>
    param([string]$Path)

    $info = @{
        Path        = $Path
        IsArchive   = $Path -match '\.zip$'
        Exists      = Test-Path $Path
        Size        = $null
        FileCount   = $null
        BackupDate  = $null
        HasMetadata = $false
    }

    if ($info.IsArchive) {
        $item = Get-Item $Path
        $info.Size = $item.Length
        $info.BackupDate = $item.LastWriteTime

        # Check archive contents
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
            $info.FileCount = $archive.Entries.Count
            $info.HasMetadata = ($archive.Entries | Where-Object { $_.Name -eq 'backup_metadata.json' }).Count -gt 0
            $archive.Dispose()
        }
        catch {
            $script:Stats.Errors += "Could not read archive: $($_.Exception.Message)"
        }
    }
    else {
        $info.Size = (Get-ChildItem $Path -Recurse -File | Measure-Object -Property Length -Sum).Sum
        $info.FileCount = (Get-ChildItem $Path -Recurse -File).Count
        $info.BackupDate = (Get-Item $Path).LastWriteTime
        $info.HasMetadata = Test-Path (Join-Path $Path 'backup_metadata.json')
    }

    return $info
}

function Test-ArchiveStructure {
    <#
    .SYNOPSIS
        Validates the ZIP archive can be opened and read.
    #>
    param([string]$ArchivePath)

    Write-InfoMessage "Testing archive structure..."

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)

        $entryCount = $archive.Entries.Count
        $totalSize = ($archive.Entries | Measure-Object -Property Length -Sum).Sum

        $archive.Dispose()

        Write-Success "  Archive is valid: $entryCount entries, $(Format-FileSize $totalSize)"
        return @{
            Valid      = $true
            EntryCount = $entryCount
            TotalSize  = $totalSize
        }
    }
    catch {
        $script:Stats.Errors += "Archive structure: $($_.Exception.Message)"
        Write-ErrorMessage "  Archive is corrupted or invalid: $($_.Exception.Message)"
        return @{
            Valid      = $false
            EntryCount = 0
            TotalSize  = 0
            Error      = $_.Exception.Message
        }
    }
}

function Get-BackupMetadata {
    <#
    .SYNOPSIS
        Reads backup metadata from archive or folder.
    #>
    param(
        [string]$BackupPath,
        [bool]$IsArchive
    )

    Write-InfoMessage "Reading backup metadata..."

    try {
        if ($IsArchive) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $archive = [System.IO.Compression.ZipFile]::OpenRead($BackupPath)

            $metadataEntry = $archive.Entries | Where-Object { $_.Name -eq 'backup_metadata.json' } | Select-Object -First 1

            if ($metadataEntry) {
                $stream = $metadataEntry.Open()
                $reader = New-Object System.IO.StreamReader($stream)
                $content = $reader.ReadToEnd()
                $reader.Close()
                $stream.Close()
                $archive.Dispose()

                $metadata = $content | ConvertFrom-Json
                Write-Success "  Metadata loaded successfully"
                return $metadata
            }
            else {
                $archive.Dispose()
                Write-WarningMessage "  No metadata file found in archive"
                return $null
            }
        }
        else {
            $metadataPath = Join-Path $BackupPath 'backup_metadata.json'
            if (Test-Path $metadataPath) {
                $metadata = Get-Content $metadataPath -Raw | ConvertFrom-Json
                Write-Success "  Metadata loaded successfully"
                return $metadata
            }
            else {
                Write-WarningMessage "  No metadata file found"
                return $null
            }
        }
    }
    catch {
        $script:Stats.Warnings += "Metadata: $($_.Exception.Message)"
        Write-WarningMessage "  Could not read metadata: $($_.Exception.Message)"
        return $null
    }
}

function Expand-BackupToTemp {
    <#
    .SYNOPSIS
        Extracts archive to a temporary folder for testing.
    #>
    param([string]$ArchivePath)

    Write-InfoMessage "Extracting archive to temporary folder..."

    $tempPath = Join-Path $env:TEMP "BackupIntegrityTest_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    try {
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        Expand-Archive -Path $ArchivePath -DestinationPath $tempPath -Force

        $fileCount = (Get-ChildItem $tempPath -Recurse -File).Count
        Write-Success "  Extracted $fileCount files to: $tempPath"

        $script:TempFolder = $tempPath
        return $tempPath
    }
    catch {
        $script:Stats.Errors += "Extraction: $($_.Exception.Message)"
        Write-ErrorMessage "  Extraction failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-FileHashes {
    <#
    .SYNOPSIS
        Verifies file hashes against metadata.
    #>
    param(
        [string]$FolderPath,
        [object]$Metadata,
        [int]$SamplePercent
    )

    Write-InfoMessage "Verifying file hashes..."

    if (-not $Metadata -or -not $Metadata.FileHashes) {
        Write-WarningMessage "  No hash data in metadata, skipping hash verification"
        return @{
            Verified = 0
            Failed   = 0
            Skipped  = $true
        }
    }

    $hashData = @{}
    if ($Metadata.FileHashes -is [System.Collections.IDictionary]) {
        $hashData = $Metadata.FileHashes
    }
    else {
        # Convert PSObject to hashtable
        $Metadata.FileHashes.PSObject.Properties | ForEach-Object {
            $hashData[$_.Name] = $_.Value
        }
    }

    $allFiles = Get-ChildItem $FolderPath -Recurse -File
    $script:Stats.TotalFiles = $allFiles.Count

    # Sample files if not 100%
    if ($SamplePercent -lt 100) {
        $sampleCount = [Math]::Max(1, [Math]::Ceiling($allFiles.Count * $SamplePercent / 100))
        $filesToCheck = $allFiles | Get-Random -Count $sampleCount
        Write-InfoMessage "  Sampling $sampleCount of $($allFiles.Count) files ($SamplePercent%)"
    }
    else {
        $filesToCheck = $allFiles
    }

    $verified = 0
    $failed = 0

    foreach ($file in $filesToCheck) {
        $relativePath = $file.FullName.Substring($FolderPath.Length + 1)

        if ($hashData.ContainsKey($relativePath)) {
            try {
                $actualHash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                $expectedHash = $hashData[$relativePath]

                if ($actualHash -eq $expectedHash) {
                    $verified++
                    $script:Stats.HashesMatched++
                    if ($IncludeFileList) {
                        $script:Stats.VerifiedFiles += $relativePath
                    }
                }
                else {
                    $failed++
                    $script:Stats.HashesFailed++
                    $script:Stats.FailedFiles += @{
                        Path     = $relativePath
                        Expected = $expectedHash
                        Actual   = $actualHash
                    }
                    Write-WarningMessage "    Hash mismatch: $relativePath"
                }
            }
            catch {
                $failed++
                $script:Stats.Warnings += "Hash check $relativePath`: $($_.Exception.Message)"
            }
        }
        else {
            # File not in metadata (new file or metadata incomplete)
            $script:Stats.FilesVerified++
        }
    }

    $script:Stats.FilesVerified = $verified
    $script:Stats.FilesFailed = $failed

    if ($failed -eq 0) {
        Write-Success "  Verified $verified files, 0 failures"
    }
    else {
        Write-WarningMessage "  Verified $verified files, $failed failures"
    }

    return @{
        Verified = $verified
        Failed   = $failed
        Skipped  = $false
    }
}

function Test-FileExtraction {
    <#
    .SYNOPSIS
        Tests that all files can be extracted from archive.
    #>
    param([string]$ArchivePath)

    Write-InfoMessage "Testing file extraction..."

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)

        $totalEntries = $archive.Entries.Count
        $readable = 0
        $failed = 0

        foreach ($entry in $archive.Entries) {
            if ($entry.Length -gt 0) {
                try {
                    $stream = $entry.Open()
                    $buffer = New-Object byte[] 1024
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    $stream.Close()
                    $readable++
                }
                catch {
                    $failed++
                    $script:Stats.FailedFiles += $entry.FullName
                }
            }
            else {
                $readable++  # Empty file or directory
            }
        }

        $archive.Dispose()

        if ($failed -eq 0) {
            Write-Success "  All $readable entries are readable"
        }
        else {
            Write-WarningMessage "  $readable readable, $failed failed"
        }

        return @{
            Readable = $readable
            Failed   = $failed
            Total    = $totalEntries
        }
    }
    catch {
        $script:Stats.Errors += "Extraction test: $($_.Exception.Message)"
        Write-ErrorMessage "  Extraction test failed: $($_.Exception.Message)"
        return @{
            Readable = 0
            Failed   = 0
            Total    = 0
            Error    = $_.Exception.Message
        }
    }
}

function Restore-ToTarget {
    <#
    .SYNOPSIS
        Restores backup to target location for testing.
    #>
    param(
        [string]$BackupPath,
        [string]$TargetPath,
        [bool]$IsArchive
    )

    Write-InfoMessage "Restoring to target: $TargetPath"

    try {
        if (-not (Test-Path $TargetPath)) {
            New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
        }

        if ($IsArchive) {
            Expand-Archive -Path $BackupPath -DestinationPath $TargetPath -Force
        }
        else {
            Copy-Item -Path "$BackupPath\*" -Destination $TargetPath -Recurse -Force
        }

        $fileCount = (Get-ChildItem $TargetPath -Recurse -File).Count
        Write-Success "  Restored $fileCount files"

        return @{
            Success   = $true
            FileCount = $fileCount
            Path      = $TargetPath
        }
    }
    catch {
        $script:Stats.Errors += "Restore: $($_.Exception.Message)"
        Write-ErrorMessage "  Restore failed: $($_.Exception.Message)"
        return @{
            Success   = $false
            FileCount = 0
            Error     = $_.Exception.Message
        }
    }
}

function Format-FileSize {
    <#
    .SYNOPSIS
        Formats bytes to human-readable size.
    #>
    param([long]$Bytes)

    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    else { return "$Bytes bytes" }
}

function Remove-TempFolder {
    <#
    .SYNOPSIS
        Removes temporary test folder.
    #>
    param([string]$Path)

    if ($Path -and (Test-Path $Path)) {
        try {
            Remove-Item -Path $Path -Recurse -Force
            Write-Success "Cleaned up temporary folder"
        }
        catch {
            Write-WarningMessage "Could not remove temp folder: $Path"
        }
    }
}

function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Displays integrity test results to console.
    #>
    param([hashtable]$Results)

    $separator = "=" * 60
    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  BACKUP INTEGRITY REPORT" -ForegroundColor Cyan
    Write-Host "$separator" -ForegroundColor Cyan

    Write-Host "`nBackup: " -NoNewline
    Write-Host $BackupPath -ForegroundColor White

    Write-Host "Test Type: " -NoNewline
    Write-Host $TestType -ForegroundColor White

    Write-Host "Duration: " -NoNewline
    $duration = (Get-Date) - $script:StartTime
    Write-Host "$($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White

    # Overall status
    $overallSuccess = ($script:Stats.Errors.Count -eq 0) -and ($script:Stats.FilesFailed -eq 0)
    Write-Host "`nOVERALL STATUS: " -NoNewline
    if ($overallSuccess) {
        Write-Host "PASSED" -ForegroundColor Green
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
    }

    # Results
    Write-Host "`nRESULTS:" -ForegroundColor Cyan
    if ($Results.ArchiveValid -ne $null) {
        $status = if ($Results.ArchiveValid) { "[+]" } else { "[-]" }
        $color = if ($Results.ArchiveValid) { "Green" } else { "Red" }
        Write-Host "  $status Archive Structure" -ForegroundColor $color
    }

    if ($Results.HashVerification) {
        $hv = $Results.HashVerification
        if ($hv.Skipped) {
            Write-Host "  [!] Hash Verification (skipped - no metadata)" -ForegroundColor Yellow
        }
        else {
            $status = if ($hv.Failed -eq 0) { "[+]" } else { "[-]" }
            $color = if ($hv.Failed -eq 0) { "Green" } else { "Red" }
            Write-Host "  $status Hash Verification: $($hv.Verified) verified, $($hv.Failed) failed" -ForegroundColor $color
        }
    }

    if ($Results.RestoreResult) {
        $rr = $Results.RestoreResult
        $status = if ($rr.Success) { "[+]" } else { "[-]" }
        $color = if ($rr.Success) { "Green" } else { "Red" }
        Write-Host "  $status Restore Test: $($rr.FileCount) files" -ForegroundColor $color
    }

    # Errors and warnings
    if ($script:Stats.Warnings.Count -gt 0) {
        Write-Host "`nWARNINGS:" -ForegroundColor Yellow
        $script:Stats.Warnings | ForEach-Object { Write-Host "  [!] $_" -ForegroundColor Yellow }
    }

    if ($script:Stats.Errors.Count -gt 0) {
        Write-Host "`nERRORS:" -ForegroundColor Red
        $script:Stats.Errors | ForEach-Object { Write-Host "  [-] $_" -ForegroundColor Red }
    }

    if ($IncludeFileList -and $script:Stats.FailedFiles.Count -gt 0) {
        Write-Host "`nFAILED FILES:" -ForegroundColor Red
        $script:Stats.FailedFiles | ForEach-Object {
            if ($_ -is [string]) {
                Write-Host "  [-] $_" -ForegroundColor Red
            }
            else {
                Write-Host "  [-] $($_.Path)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n$separator`n" -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML integrity report.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    if (-not $OutputPath) { $OutputPath = Split-Path $BackupPath -Parent }

    $htmlPath = Join-Path $OutputPath "integrity-report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $duration = (Get-Date) - $script:StartTime
    $overallSuccess = ($script:Stats.Errors.Count -eq 0) -and ($script:Stats.FilesFailed -eq 0)
    $statusClass = if ($overallSuccess) { 'success' } else { 'error' }
    $statusText = if ($overallSuccess) { 'PASSED' } else { 'FAILED' }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Backup Integrity Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .success { color: #107c10; }
        .error { color: #d13438; }
        .warning { color: #ff8c00; }
        .status-badge { padding: 8px 16px; border-radius: 4px; font-weight: bold; display: inline-block; }
        .status-badge.success { background: #dff6dd; color: #107c10; }
        .status-badge.error { background: #fde7e9; color: #d13438; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Backup Integrity Report</h1>
        <p><strong>Backup:</strong> $BackupPath</p>
        <p><strong>Test Type:</strong> $TestType | <strong>Duration:</strong> $($duration.ToString('hh\:mm\:ss')) | <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <h2>Overall Status: <span class="status-badge $statusClass">$statusText</span></h2>

        <h2>Test Results</h2>
        <table>
            <tr><th>Test</th><th>Result</th><th>Details</th></tr>
            $(if ($Results.ArchiveValid -ne $null) {
                $class = if ($Results.ArchiveValid) { 'success' } else { 'error' }
                $text = if ($Results.ArchiveValid) { 'Passed' } else { 'Failed' }
                "<tr><td>Archive Structure</td><td class='$class'>$text</td><td>$($Results.FileCount) files</td></tr>"
            })
            $(if ($Results.HashVerification) {
                $hv = $Results.HashVerification
                if ($hv.Skipped) {
                    "<tr><td>Hash Verification</td><td class='warning'>Skipped</td><td>No metadata available</td></tr>"
                } else {
                    $class = if ($hv.Failed -eq 0) { 'success' } else { 'error' }
                    $text = if ($hv.Failed -eq 0) { 'Passed' } else { 'Failed' }
                    "<tr><td>Hash Verification</td><td class='$class'>$text</td><td>$($hv.Verified) verified, $($hv.Failed) failed</td></tr>"
                }
            })
            $(if ($Results.RestoreResult) {
                $rr = $Results.RestoreResult
                $class = if ($rr.Success) { 'success' } else { 'error' }
                $text = if ($rr.Success) { 'Passed' } else { 'Failed' }
                "<tr><td>Restore Test</td><td class='$class'>$text</td><td>$($rr.FileCount) files restored</td></tr>"
            })
        </table>

        $(if ($script:Stats.Errors.Count -gt 0) {
            "<h2 class='error'>Errors</h2><ul>" +
            ($script:Stats.Errors | ForEach-Object { "<li>$_</li>" }) +
            "</ul>"
        })
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Success "HTML report saved: $htmlPath"
}

function Export-JSONReport {
    <#
    .SYNOPSIS
        Generates a JSON integrity report.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    if (-not $OutputPath) { $OutputPath = Split-Path $BackupPath -Parent }

    $jsonPath = Join-Path $OutputPath "integrity-report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    $report = @{
        BackupPath       = $BackupPath
        TestType         = $TestType
        TestDate         = Get-Date -Format "o"
        Duration         = ((Get-Date) - $script:StartTime).ToString()
        OverallSuccess   = ($script:Stats.Errors.Count -eq 0) -and ($script:Stats.FilesFailed -eq 0)
        Results          = $Results
        Statistics       = $script:Stats
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
}
#endregion

#region Main Execution
try {
    Write-Host ""
    Write-InfoMessage "========================================"
    Write-InfoMessage "  Backup Integrity Test v$script:ScriptVersion"
    Write-InfoMessage "========================================"

    # Validate parameters
    if ($TestType -eq 'Restore' -and -not $RestoreTarget) {
        Write-ErrorMessage "RestoreTarget is required when TestType is 'Restore'"
        exit 1
    }

    # Get backup info
    $backupInfo = Get-BackupInfo -Path $BackupPath
    Write-InfoMessage "Backup: $(Format-FileSize $backupInfo.Size), $($backupInfo.FileCount) files"

    $results = @{
        BackupInfo = $backupInfo
    }

    # Test archive structure (if ZIP)
    if ($backupInfo.IsArchive) {
        $archiveTest = Test-ArchiveStructure -ArchivePath $BackupPath
        $results.ArchiveValid = $archiveTest.Valid
        $results.FileCount = $archiveTest.EntryCount

        if (-not $archiveTest.Valid) {
            Write-ErrorMessage "Archive is corrupted, cannot continue"
            Write-ConsoleReport -Results $results
            exit 1
        }
    }

    # Get metadata
    $metadata = Get-BackupMetadata -BackupPath $BackupPath -IsArchive $backupInfo.IsArchive
    $results.HasMetadata = ($null -ne $metadata)

    # Perform tests based on TestType
    switch ($TestType) {
        'Quick' {
            # Quick: Test archive readability and sample hashes
            if ($backupInfo.IsArchive) {
                $extractTest = Test-FileExtraction -ArchivePath $BackupPath
                $results.ExtractionTest = $extractTest
            }

            # Sample hash verification (need to extract for this)
            if ($metadata -and $metadata.FileHashes) {
                $tempPath = Expand-BackupToTemp -ArchivePath $BackupPath
                if ($tempPath) {
                    $hashResult = Test-FileHashes -FolderPath $tempPath -Metadata $metadata -SamplePercent $SamplePercent
                    $results.HashVerification = $hashResult
                    Remove-TempFolder -Path $tempPath
                }
            }
            else {
                $results.HashVerification = @{ Skipped = $true }
            }
        }

        'Full' {
            # Full: Extract everything and verify all hashes
            if ($backupInfo.IsArchive) {
                $tempPath = Expand-BackupToTemp -ArchivePath $BackupPath
            }
            else {
                $tempPath = $BackupPath
            }

            if ($tempPath) {
                $hashResult = Test-FileHashes -FolderPath $tempPath -Metadata $metadata -SamplePercent 100
                $results.HashVerification = $hashResult

                if ($CleanupAfterTest -and $backupInfo.IsArchive) {
                    Remove-TempFolder -Path $tempPath
                }
            }
        }

        'Restore' {
            # Restore: Actually restore and verify
            $restoreResult = Restore-ToTarget -BackupPath $BackupPath -TargetPath $RestoreTarget -IsArchive $backupInfo.IsArchive
            $results.RestoreResult = $restoreResult

            if ($restoreResult.Success -and $metadata) {
                $hashResult = Test-FileHashes -FolderPath $RestoreTarget -Metadata $metadata -SamplePercent 100
                $results.HashVerification = $hashResult
            }

            if ($CleanupAfterTest -and $restoreResult.Success) {
                Remove-TempFolder -Path $RestoreTarget
            }
        }
    }

    # Generate reports
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Results $results }
        'HTML'    { Write-ConsoleReport -Results $results; Export-HTMLReport -OutputPath $OutputPath -Results $results }
        'JSON'    { Write-ConsoleReport -Results $results; Export-JSONReport -OutputPath $OutputPath -Results $results }
        'All'     {
            Write-ConsoleReport -Results $results
            Export-HTMLReport -OutputPath $OutputPath -Results $results
            Export-JSONReport -OutputPath $OutputPath -Results $results
        }
    }

    # Exit code based on results
    $success = ($script:Stats.Errors.Count -eq 0) -and ($script:Stats.FilesFailed -eq 0)
    if ($success) {
        Write-Success "Backup integrity verified successfully"
        exit 0
    }
    else {
        Write-ErrorMessage "Backup integrity check failed"
        exit 1
    }
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    Write-ErrorMessage "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
finally {
    # Cleanup temp folder if it exists
    if ($script:TempFolder -and (Test-Path $script:TempFolder)) {
        Remove-TempFolder -Path $script:TempFolder
    }
}
#endregion
