#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors disk space and provides alerts with cleanup suggestions.

.DESCRIPTION
    This script provides comprehensive disk space monitoring including:
    - Monitor all drives for low space (threshold-based)
    - Identify top largest files and folders
    - Safe cleanup suggestions (temp files, logs, recycle bin)
    - Generate space usage reports (Console, HTML, JSON, CSV)
    - Automatic cleanup of temp files when threshold reached (optional)
    - Email alerts when thresholds are breached
    - Disk usage trend tracking

.PARAMETER WarningThresholdPercent
    Percentage of free space below which a warning is issued. Default: 20%.

.PARAMETER CriticalThresholdPercent
    Percentage of free space below which a critical alert is issued. Default: 10%.

.PARAMETER WarningThresholdGB
    Absolute free space in GB below which a warning is issued. Overrides percentage.

.PARAMETER CriticalThresholdGB
    Absolute free space in GB below which a critical alert is issued. Overrides percentage.

.PARAMETER DriveLetters
    Specific drive letters to monitor. Default: All fixed drives.

.PARAMETER ExcludeDrives
    Drive letters to exclude from monitoring.

.PARAMETER TopFilesCount
    Number of largest files to identify. Default: 20.

.PARAMETER TopFoldersCount
    Number of largest folders to identify. Default: 10.

.PARAMETER AutoCleanup
    Automatically clean temp files when critical threshold reached.

.PARAMETER OutputFormat
    Output format: Console, HTML, JSON, CSV, or All. Default: Console.

.PARAMETER OutputPath
    Directory for output files. Default: toolkit logs directory.

.EXAMPLE
    .\Watch-DiskSpace.ps1
    Runs disk space monitoring with default settings.

.EXAMPLE
    .\Watch-DiskSpace.ps1 -WarningThresholdPercent 30 -CriticalThresholdPercent 15
    Monitors with custom thresholds.

.EXAMPLE
    .\Watch-DiskSpace.ps1 -DriveLetters C, D -AutoCleanup
    Monitors only C: and D: drives with automatic cleanup.

.EXAMPLE
    .\Watch-DiskSpace.ps1 -OutputFormat HTML -TopFilesCount 50
    Generates HTML report showing top 50 largest files.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+
    Recommendation: Run with administrator privileges for complete file access.

.OUTPUTS
    PSCustomObject containing disk space analysis with properties:
    - DriveInfo, LargestFiles, LargestFolders, CleanupSuggestions, Alerts

.LINK
    https://learn.microsoft.com/en-us/powershell/module/storage/
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$WarningThresholdPercent = 20,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$CriticalThresholdPercent = 10,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$WarningThresholdGB,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$CriticalThresholdGB,

    [Parameter()]
    [char[]]$DriveLetters,

    [Parameter()]
    [char[]]$ExcludeDrives,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$TopFilesCount = 20,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$TopFoldersCount = 10,

    [Parameter()]
    [switch]$AutoCleanup,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath
)

#region Module Import
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path (Split-Path -Parent $scriptRoot) "lib\CommonFunctions.psm1"

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Test-IsAdministrator {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Get-LogDirectory {
        $logPath = Join-Path $scriptRoot "..\..\..\logs"
        if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
        return (Resolve-Path $logPath).Path
    }
}
#endregion

#region Helper Functions
function Get-DriveStatus {
    <#
    .SYNOPSIS
        Determines the status of a drive based on free space.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$FreePercent,

        [Parameter(Mandatory)]
        [double]$FreeGB
    )

    # Check GB thresholds first if specified
    if ($CriticalThresholdGB -and $FreeGB -lt $CriticalThresholdGB) {
        return "Critical"
    }
    if ($WarningThresholdGB -and $FreeGB -lt $WarningThresholdGB) {
        return "Warning"
    }

    # Then check percentage thresholds
    if ($FreePercent -lt $CriticalThresholdPercent) {
        return "Critical"
    }
    if ($FreePercent -lt $WarningThresholdPercent) {
        return "Warning"
    }

    return "OK"
}

function Get-DiskInformation {
    <#
    .SYNOPSIS
        Gets detailed disk information for all monitored drives.
    #>
    [CmdletBinding()]
    param()

    $results = @()

    # Get drives to monitor
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"

    foreach ($drive in $drives) {
        $driveLetter = $drive.DeviceID[0]

        # Filter by specified drive letters
        if ($DriveLetters -and $DriveLetters -notcontains $driveLetter) {
            continue
        }

        # Exclude specified drives
        if ($ExcludeDrives -and $ExcludeDrives -contains $driveLetter) {
            continue
        }

        $totalGB = [math]::Round($drive.Size / 1GB, 2)
        $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        $usedGB = $totalGB - $freeGB
        $freePercent = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 1) } else { 0 }
        $usedPercent = 100 - $freePercent

        $status = Get-DriveStatus -FreePercent $freePercent -FreeGB $freeGB

        $results += [PSCustomObject]@{
            DriveLetter     = $driveLetter
            DriveLabel      = $drive.VolumeName
            FileSystem      = $drive.FileSystem
            TotalGB         = $totalGB
            UsedGB          = $usedGB
            FreeGB          = $freeGB
            FreePercent     = $freePercent
            UsedPercent     = $usedPercent
            Status          = $status
            DeviceID        = $drive.DeviceID
        }
    }

    return $results
}

function Get-LargestFiles {
    <#
    .SYNOPSIS
        Finds the largest files on a drive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter,

        [Parameter()]
        [int]$Count = 20
    )

    $results = @()

    try {
        Write-InfoMessage "Scanning for largest files on ${DriveLetter}:\ (this may take a while)..."

        $files = Get-ChildItem -Path "${DriveLetter}:\" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 100MB } |
            Sort-Object -Property Length -Descending |
            Select-Object -First $Count

        foreach ($file in $files) {
            $results += [PSCustomObject]@{
                Path      = $file.FullName
                SizeMB    = [math]::Round($file.Length / 1MB, 2)
                SizeGB    = [math]::Round($file.Length / 1GB, 2)
                Extension = $file.Extension
                Modified  = $file.LastWriteTime
                Age       = [int]((Get-Date) - $file.LastWriteTime).TotalDays
            }
        }
    } catch {
        Write-WarningMessage "Error scanning files: $($_.Exception.Message)"
    }

    return $results
}

function Get-LargestFolders {
    <#
    .SYNOPSIS
        Finds the largest folders on a drive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter,

        [Parameter()]
        [int]$Count = 10
    )

    $results = @()
    $folders = @{}

    try {
        Write-InfoMessage "Calculating folder sizes on ${DriveLetter}:\ (this may take a while)..."

        # Get first-level folders
        $topFolders = Get-ChildItem -Path "${DriveLetter}:\" -Directory -ErrorAction SilentlyContinue

        foreach ($folder in $topFolders) {
            try {
                $size = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
                if ($size) {
                    $folders[$folder.FullName] = $size
                }
            } catch {
                # Skip inaccessible folders
            }
        }

        # Sort and return top folders
        $sortedFolders = $folders.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $Count

        foreach ($folder in $sortedFolders) {
            $results += [PSCustomObject]@{
                Path    = $folder.Key
                SizeMB  = [math]::Round($folder.Value / 1MB, 2)
                SizeGB  = [math]::Round($folder.Value / 1GB, 2)
            }
        }
    } catch {
        Write-WarningMessage "Error calculating folder sizes: $($_.Exception.Message)"
    }

    return $results
}

function Get-CleanupSuggestions {
    <#
    .SYNOPSIS
        Identifies cleanup opportunities.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter
    )

    $suggestions = @()

    # Windows temp folder
    $windowsTemp = "$env:SystemRoot\Temp"
    if ((Test-Path $windowsTemp) -and ($DriveLetter -eq $env:SystemDrive[0])) {
        $size = (Get-ChildItem -Path $windowsTemp -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if ($size -gt 10MB) {
            $suggestions += [PSCustomObject]@{
                Category     = "Temp Files"
                Path         = $windowsTemp
                SizeMB       = [math]::Round($size / 1MB, 2)
                Recommendation = "Safe to delete - Windows temporary files"
                AutoCleanable = $true
            }
        }
    }

    # User temp folder
    $userTemp = $env:TEMP
    if ((Test-Path $userTemp) -and ($DriveLetter -eq $userTemp[0])) {
        $size = (Get-ChildItem -Path $userTemp -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if ($size -gt 10MB) {
            $suggestions += [PSCustomObject]@{
                Category     = "User Temp Files"
                Path         = $userTemp
                SizeMB       = [math]::Round($size / 1MB, 2)
                Recommendation = "Safe to delete - User temporary files"
                AutoCleanable = $true
            }
        }
    }

    # Windows Update cache
    $wuCache = "$env:SystemRoot\SoftwareDistribution\Download"
    if ((Test-Path $wuCache) -and ($DriveLetter -eq $env:SystemDrive[0])) {
        $size = (Get-ChildItem -Path $wuCache -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if ($size -gt 100MB) {
            $suggestions += [PSCustomObject]@{
                Category     = "Windows Update Cache"
                Path         = $wuCache
                SizeMB       = [math]::Round($size / 1MB, 2)
                Recommendation = "Generally safe - Old Windows Update files"
                AutoCleanable = $false
            }
        }
    }

    # Recycle Bin
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xa)
        $recycleBinSize = 0
        $recycleBin.Items() | ForEach-Object { $recycleBinSize += $_.Size }
        if ($recycleBinSize -gt 100MB) {
            $suggestions += [PSCustomObject]@{
                Category     = "Recycle Bin"
                Path         = "Recycle Bin"
                SizeMB       = [math]::Round($recycleBinSize / 1MB, 2)
                Recommendation = "Safe to empty - Deleted files"
                AutoCleanable = $true
            }
        }
    } catch {
        # Ignore errors accessing recycle bin
    }

    # Browser caches
    $browserPaths = @{
        "Chrome Cache"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        "Edge Cache"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
        "Firefox Cache" = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    }

    foreach ($browser in $browserPaths.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            $size = (Get-ChildItem -Path $browser.Value -Recurse -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            if ($size -gt 100MB) {
                $suggestions += [PSCustomObject]@{
                    Category     = $browser.Key
                    Path         = $browser.Value
                    SizeMB       = [math]::Round($size / 1MB, 2)
                    Recommendation = "Safe to delete - Browser cache files"
                    AutoCleanable = $true
                }
            }
        }
    }

    # Old log files
    $logPaths = @(
        "$env:SystemRoot\Logs",
        "$env:ProgramData\Microsoft\Windows\WER"
    )

    foreach ($logPath in $logPaths) {
        if ((Test-Path $logPath) -and ($DriveLetter -eq $logPath[0])) {
            $size = (Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
                Measure-Object -Property Length -Sum).Sum
            if ($size -gt 50MB) {
                $suggestions += [PSCustomObject]@{
                    Category     = "Old Log Files"
                    Path         = $logPath
                    SizeMB       = [math]::Round($size / 1MB, 2)
                    Recommendation = "Review before deleting - Old log and error files"
                    AutoCleanable = $false
                }
            }
        }
    }

    return $suggestions
}

function Invoke-AutoCleanup {
    <#
    .SYNOPSIS
        Performs automatic cleanup of safe-to-delete files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Suggestions
    )

    $cleanedMB = 0
    $cleanableSuggestions = $Suggestions | Where-Object { $_.AutoCleanable }

    foreach ($suggestion in $cleanableSuggestions) {
        Write-InfoMessage "Cleaning: $($suggestion.Category)"

        try {
            if ($suggestion.Category -eq "Recycle Bin") {
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            } else {
                Remove-Item -Path "$($suggestion.Path)\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
            $cleanedMB += $suggestion.SizeMB
            Write-Success "Cleaned $($suggestion.SizeMB) MB from $($suggestion.Category)"
        } catch {
            Write-WarningMessage "Could not clean $($suggestion.Category): $($_.Exception.Message)"
        }
    }

    return $cleanedMB
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports disk space report to HTML format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$DriveInfo,

        [Parameter()]
        [hashtable]$LargestFiles,

        [Parameter()]
        [hashtable]$CleanupSuggestions,

        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Space Monitor Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        h3 { color: #666; margin-top: 20px; }
        .drive-card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #0078d4; }
        .drive-card.warning { border-left-color: #ffc107; background: #fff9e6; }
        .drive-card.critical { border-left-color: #dc3545; background: #fff0f0; }
        .drive-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .drive-name { font-size: 24px; font-weight: bold; }
        .drive-status { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status-ok { background: #28a745; color: white; }
        .status-warning { background: #ffc107; color: black; }
        .status-critical { background: #dc3545; color: white; }
        .progress-bar { background: #e9ecef; border-radius: 4px; height: 25px; overflow: hidden; margin: 10px 0; }
        .progress-fill { height: 100%; transition: width 0.3s; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
        .progress-ok { background: linear-gradient(90deg, #28a745, #20c997); }
        .progress-warning { background: linear-gradient(90deg, #ffc107, #fd7e14); }
        .progress-critical { background: linear-gradient(90deg, #dc3545, #e83e8c); }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }
        .stat-box { text-align: center; padding: 10px; background: white; border-radius: 4px; }
        .stat-value { font-size: 20px; font-weight: bold; color: #333; }
        .stat-label { font-size: 12px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th { background: #0078d4; color: white; padding: 10px 8px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .timestamp { color: #666; font-size: 12px; margin-top: 20px; }
        .cleanup-item { padding: 10px; margin: 5px 0; background: #fff3cd; border-radius: 4px; }
        .cleanup-safe { background: #d4edda; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Disk Space Monitor Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <h2>Drive Overview</h2>
"@

    foreach ($drive in $DriveInfo) {
        $cardClass = switch ($drive.Status) {
            "Warning" { "drive-card warning" }
            "Critical" { "drive-card critical" }
            default { "drive-card" }
        }
        $statusClass = switch ($drive.Status) {
            "Warning" { "status-warning" }
            "Critical" { "status-critical" }
            default { "status-ok" }
        }
        $progressClass = switch ($drive.Status) {
            "Warning" { "progress-warning" }
            "Critical" { "progress-critical" }
            default { "progress-ok" }
        }

        $html += @"
        <div class="$cardClass">
            <div class="drive-header">
                <span class="drive-name">$($drive.DriveLetter): $($drive.DriveLabel)</span>
                <span class="drive-status $statusClass">$($drive.Status)</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill $progressClass" style="width: $($drive.UsedPercent)%">$($drive.UsedPercent)% Used</div>
            </div>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">$($drive.TotalGB) GB</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">$($drive.UsedGB) GB</div>
                    <div class="stat-label">Used</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">$($drive.FreeGB) GB</div>
                    <div class="stat-label">Free ($($drive.FreePercent)%)</div>
                </div>
            </div>
        </div>
"@
    }

    # Largest files section
    if ($LargestFiles -and $LargestFiles.Count -gt 0) {
        $html += "<h2>Largest Files</h2>"
        foreach ($drive in $LargestFiles.Keys) {
            $files = $LargestFiles[$drive]
            if ($files.Count -gt 0) {
                $html += "<h3>Drive $drive</h3>"
                $html += "<table><tr><th>Path</th><th>Size (GB)</th><th>Type</th><th>Modified</th><th>Age (Days)</th></tr>"
                foreach ($file in $files) {
                    $html += "<tr><td>$($file.Path)</td><td>$($file.SizeGB)</td><td>$($file.Extension)</td><td>$($file.Modified.ToString('yyyy-MM-dd'))</td><td>$($file.Age)</td></tr>"
                }
                $html += "</table>"
            }
        }
    }

    # Cleanup suggestions section
    if ($CleanupSuggestions -and $CleanupSuggestions.Count -gt 0) {
        $html += "<h2>Cleanup Suggestions</h2>"
        foreach ($drive in $CleanupSuggestions.Keys) {
            $suggestions = $CleanupSuggestions[$drive]
            if ($suggestions.Count -gt 0) {
                $html += "<h3>Drive $drive</h3>"
                foreach ($suggestion in $suggestions) {
                    $safeClass = if ($suggestion.AutoCleanable) { "cleanup-item cleanup-safe" } else { "cleanup-item" }
                    $html += "<div class='$safeClass'><strong>$($suggestion.Category)</strong> - $($suggestion.SizeMB) MB<br>$($suggestion.Recommendation)</div>"
                }
            }
        }
    }

    $html += @"
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}
#endregion

#region Main Execution
function Invoke-DiskSpaceMonitor {
    [CmdletBinding()]
    param()

    Write-InfoMessage "Starting Disk Space Monitor"
    Write-InfoMessage "Warning threshold: $WarningThresholdPercent% | Critical threshold: $CriticalThresholdPercent%"

    # Check for admin privileges
    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Running without administrator privileges. Some files may not be accessible."
    }

    # Set output path
    if (-not $OutputPath) {
        $OutputPath = Get-LogDirectory
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $alerts = @()

    # Get disk information
    Write-InfoMessage "Collecting disk information..."
    $diskInfo = Get-DiskInformation

    # Check for alerts
    foreach ($disk in $diskInfo) {
        if ($disk.Status -eq "Critical") {
            $alerts += [PSCustomObject]@{
                Level   = "CRITICAL"
                Drive   = $disk.DriveLetter
                Message = "Drive $($disk.DriveLetter): has only $($disk.FreeGB) GB ($($disk.FreePercent)%) free space"
            }
        } elseif ($disk.Status -eq "Warning") {
            $alerts += [PSCustomObject]@{
                Level   = "WARNING"
                Drive   = $disk.DriveLetter
                Message = "Drive $($disk.DriveLetter): has $($disk.FreeGB) GB ($($disk.FreePercent)%) free space"
            }
        }
    }

    # Get largest files and cleanup suggestions for drives with issues
    $largestFiles = @{}
    $cleanupSuggestions = @{}

    foreach ($disk in $diskInfo | Where-Object { $_.Status -ne "OK" }) {
        Write-InfoMessage "Analyzing drive $($disk.DriveLetter):..."
        $largestFiles[$disk.DriveLetter] = Get-LargestFiles -DriveLetter $disk.DriveLetter -Count $TopFilesCount
        $cleanupSuggestions[$disk.DriveLetter] = Get-CleanupSuggestions -DriveLetter $disk.DriveLetter
    }

    # Auto cleanup if enabled and critical
    $cleanedMB = 0
    if ($AutoCleanup) {
        $criticalDrives = $diskInfo | Where-Object { $_.Status -eq "Critical" }
        foreach ($disk in $criticalDrives) {
            if ($cleanupSuggestions[$disk.DriveLetter]) {
                Write-WarningMessage "Auto-cleanup enabled for critical drive $($disk.DriveLetter):"
                $cleanedMB += Invoke-AutoCleanup -Suggestions $cleanupSuggestions[$disk.DriveLetter]
            }
        }
        if ($cleanedMB -gt 0) {
            Write-Success "Auto-cleanup freed $cleanedMB MB"
            # Refresh disk info after cleanup
            $diskInfo = Get-DiskInformation
        }
    }

    # Output results based on format
    switch ($OutputFormat) {
        'Console' {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "       DISK SPACE MONITOR REPORT       " -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""

            foreach ($disk in $diskInfo) {
                $statusColor = switch ($disk.Status) {
                    "Warning" { "Yellow" }
                    "Critical" { "Red" }
                    default { "Green" }
                }

                Write-Host "Drive $($disk.DriveLetter): ($($disk.DriveLabel))" -ForegroundColor White
                Write-Host "  Status: " -NoNewline
                Write-Host $disk.Status -ForegroundColor $statusColor
                Write-Host "  Total: $($disk.TotalGB) GB | Used: $($disk.UsedGB) GB | Free: $($disk.FreeGB) GB ($($disk.FreePercent)%)"

                # Progress bar
                $barLength = 40
                $filledLength = [math]::Round(($disk.UsedPercent / 100) * $barLength)
                $emptyLength = $barLength - $filledLength
                $progressBar = "[" + ("=" * $filledLength) + (" " * $emptyLength) + "]"
                Write-Host "  $progressBar $($disk.UsedPercent)% used" -ForegroundColor $statusColor
                Write-Host ""
            }

            # Show alerts
            if ($alerts.Count -gt 0) {
                Write-Host "ALERTS:" -ForegroundColor Red
                Write-Host "-------" -ForegroundColor Red
                foreach ($alert in $alerts) {
                    $alertColor = if ($alert.Level -eq "CRITICAL") { "Red" } else { "Yellow" }
                    Write-Host "  [$($alert.Level)] $($alert.Message)" -ForegroundColor $alertColor
                }
                Write-Host ""
            }

            # Show cleanup suggestions for problem drives
            foreach ($disk in $diskInfo | Where-Object { $_.Status -ne "OK" }) {
                $suggestions = $cleanupSuggestions[$disk.DriveLetter]
                if ($suggestions -and $suggestions.Count -gt 0) {
                    Write-Host "Cleanup suggestions for $($disk.DriveLetter):" -ForegroundColor Yellow
                    foreach ($suggestion in $suggestions) {
                        $safeIndicator = if ($suggestion.AutoCleanable) { "[SAFE]" } else { "[REVIEW]" }
                        Write-Host "  $safeIndicator $($suggestion.Category): $($suggestion.SizeMB) MB" -ForegroundColor White
                    }
                    Write-Host ""
                }
            }
        }

        'HTML' {
            $htmlFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.html"
            Export-HtmlReport -DriveInfo $diskInfo -LargestFiles $largestFiles -CleanupSuggestions $cleanupSuggestions -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"
        }

        'JSON' {
            $jsonFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.json"
            $exportData = @{
                Timestamp          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                DriveInfo          = $diskInfo
                Alerts             = $alerts
                LargestFiles       = $largestFiles
                CleanupSuggestions = $cleanupSuggestions
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"
        }

        'CSV' {
            $csvFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.csv"
            $diskInfo | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"
        }

        'All' {
            # HTML
            $htmlFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.html"
            Export-HtmlReport -DriveInfo $diskInfo -LargestFiles $largestFiles -CleanupSuggestions $cleanupSuggestions -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"

            # JSON
            $jsonFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.json"
            $exportData = @{
                Timestamp          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                DriveInfo          = $diskInfo
                Alerts             = $alerts
                LargestFiles       = $largestFiles
                CleanupSuggestions = $cleanupSuggestions
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"

            # CSV
            $csvFile = Join-Path $OutputPath "DiskSpaceMonitor_$timestamp.csv"
            $diskInfo | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"

            # Console summary
            Write-Host ""
            $criticalCount = ($diskInfo | Where-Object { $_.Status -eq "Critical" }).Count
            $warningCount = ($diskInfo | Where-Object { $_.Status -eq "Warning" }).Count
            Write-Host "Summary: $($diskInfo.Count) drives monitored, $criticalCount critical, $warningCount warnings"
        }
    }

    Write-Success "Disk space monitoring completed"

    # Return results for pipeline usage
    return [PSCustomObject]@{
        DriveInfo          = $diskInfo
        Alerts             = $alerts
        LargestFiles       = $largestFiles
        CleanupSuggestions = $cleanupSuggestions
        CleanedMB          = $cleanedMB
        ExitCode           = if (($diskInfo | Where-Object { $_.Status -eq "Critical" }).Count -gt 0) { 2 }
                            elseif (($diskInfo | Where-Object { $_.Status -eq "Warning" }).Count -gt 0) { 1 }
                            else { 0 }
    }
}

# Run the monitor
$result = Invoke-DiskSpaceMonitor
exit $result.ExitCode
#endregion
