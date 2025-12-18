#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors application health, installed software versions, and detects outdated applications.

.DESCRIPTION
    This script provides comprehensive application health monitoring including:
    - Check if critical applications are installed
    - Verify application versions (detect outdated)
    - Detect application crashes (from Event Log)
    - Monitor application resource usage
    - Auto-update apps via Winget/Chocolatey (optional)
    - Generate application status reports (Console, HTML, JSON, CSV)

.PARAMETER RequiredApps
    Array of application names that must be installed.

.PARAMETER CheckUpdates
    Check for available updates via Winget and Chocolatey.

.PARAMETER AutoUpdate
    Automatically update outdated applications (requires admin).

.PARAMETER CheckCrashes
    Check Event Log for application crashes. Default: $true.

.PARAMETER CrashDays
    Number of days to look back for crashes. Default: 7.

.PARAMETER OutputFormat
    Output format: Console, HTML, JSON, CSV, or All. Default: Console.

.PARAMETER OutputPath
    Directory for output files. Default: toolkit logs directory.

.EXAMPLE
    .\Get-ApplicationHealth.ps1
    Runs application health check with default settings.

.EXAMPLE
    .\Get-ApplicationHealth.ps1 -RequiredApps "Google Chrome", "Visual Studio Code", "Git"
    Checks that specified applications are installed.

.EXAMPLE
    .\Get-ApplicationHealth.ps1 -CheckUpdates -OutputFormat HTML
    Checks for updates and generates HTML report.

.EXAMPLE
    .\Get-ApplicationHealth.ps1 -AutoUpdate -RequiredApps "7-Zip"
    Automatically updates specified applications if outdated.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+
    Recommendation: Run with administrator privileges for complete access.

.OUTPUTS
    PSCustomObject containing application health data with properties:
    - InstalledApps, MissingApps, OutdatedApps, Crashes, ResourceUsage

.LINK
    https://learn.microsoft.com/en-us/powershell/module/packagemanagement/
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$RequiredApps,

    [Parameter()]
    [switch]$CheckUpdates,

    [Parameter()]
    [switch]$AutoUpdate,

    [Parameter()]
    [switch]$CheckCrashes = $true,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$CrashDays = 7,

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
function Get-InstalledApplications {
    <#
    .SYNOPSIS
        Gets all installed applications from registry.
    #>
    [CmdletBinding()]
    param()

    $apps = @()

    # Registry paths for installed applications
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName -ne "" }

            foreach ($item in $items) {
                # Check if already added (avoid duplicates)
                if ($apps | Where-Object { $_.Name -eq $item.DisplayName -and $_.Version -eq $item.DisplayVersion }) {
                    continue
                }

                $apps += [PSCustomObject]@{
                    Name            = $item.DisplayName
                    Version         = $item.DisplayVersion
                    Publisher       = $item.Publisher
                    InstallDate     = if ($item.InstallDate) {
                        try { [datetime]::ParseExact($item.InstallDate, "yyyyMMdd", $null) } catch { $null }
                    } else { $null }
                    InstallLocation = $item.InstallLocation
                    UninstallString = $item.UninstallString
                    Architecture    = if ($path -match "WOW6432Node") { "x86" } else { "x64" }
                    Source          = "Registry"
                }
            }
        } catch {
            Write-Verbose "Error reading registry path ${path}: $($_.Exception.Message)"
        }
    }

    # Also get Windows Store apps
    try {
        $storeApps = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.IsFramework -eq $false }
        foreach ($app in $storeApps) {
            $apps += [PSCustomObject]@{
                Name            = $app.Name
                Version         = $app.Version
                Publisher       = $app.Publisher
                InstallDate     = $null
                InstallLocation = $app.InstallLocation
                UninstallString = $null
                Architecture    = $app.Architecture
                Source          = "WindowsStore"
            }
        }
    } catch {
        Write-Verbose "Error getting Windows Store apps: $($_.Exception.Message)"
    }

    return $apps | Sort-Object Name
}

function Test-ApplicationInstalled {
    <#
    .SYNOPSIS
        Checks if an application is installed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppName,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$InstalledApps
    )

    $found = $InstalledApps | Where-Object {
        $_.Name -like "*$AppName*" -or
        $_.Name -eq $AppName
    }

    return $found
}

function Get-WingetUpdates {
    <#
    .SYNOPSIS
        Gets available updates from Winget.
    #>
    [CmdletBinding()]
    param()

    $updates = @()

    # Check if winget is available
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-WarningMessage "Winget is not installed or not in PATH"
        return $updates
    }

    try {
        Write-InfoMessage "Checking for updates via Winget..."

        # Run winget upgrade and parse output
        $output = winget upgrade --accept-source-agreements 2>$null

        # Parse the output (skip header lines)
        $lines = $output -split "`n" | Where-Object { $_ -match '\S' }
        $headerFound = $false
        $dataStarted = $false

        foreach ($line in $lines) {
            # Skip until we find the header separator
            if ($line -match '^-+') {
                $headerFound = $true
                $dataStarted = $true
                continue
            }

            if (-not $dataStarted) { continue }

            # Skip footer lines
            if ($line -match 'upgrades available' -or $line -match '^$') { continue }

            # Parse the line (format: Name Id Version Available Source)
            if ($line -match '^\s*(.+?)\s{2,}(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$') {
                $updates += [PSCustomObject]@{
                    Name            = $Matches[1].Trim()
                    Id              = $Matches[2]
                    CurrentVersion  = $Matches[3]
                    AvailableVersion = $Matches[4]
                    Source          = $Matches[5]
                    PackageManager  = "Winget"
                }
            }
        }
    } catch {
        Write-WarningMessage "Error checking Winget updates: $($_.Exception.Message)"
    }

    return $updates
}

function Get-ChocolateyUpdates {
    <#
    .SYNOPSIS
        Gets available updates from Chocolatey.
    #>
    [CmdletBinding()]
    param()

    $updates = @()

    # Check if choco is available
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) {
        Write-Verbose "Chocolatey is not installed"
        return $updates
    }

    try {
        Write-InfoMessage "Checking for updates via Chocolatey..."

        $output = choco outdated --limit-output 2>$null

        foreach ($line in $output) {
            if ($line -match '^([^|]+)\|([^|]+)\|([^|]+)\|') {
                $updates += [PSCustomObject]@{
                    Name            = $Matches[1]
                    Id              = $Matches[1]
                    CurrentVersion  = $Matches[2]
                    AvailableVersion = $Matches[3]
                    Source          = "Chocolatey"
                    PackageManager  = "Chocolatey"
                }
            }
        }
    } catch {
        Write-WarningMessage "Error checking Chocolatey updates: $($_.Exception.Message)"
    }

    return $updates
}

function Get-ApplicationCrashes {
    <#
    .SYNOPSIS
        Gets application crash events from Event Log.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Days = 7
    )

    $crashes = @()
    $startTime = (Get-Date).AddDays(-$Days)

    try {
        Write-InfoMessage "Checking Event Log for application crashes (last $Days days)..."

        # Application Error events (Event ID 1000)
        $appErrors = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            Id        = 1000
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $appErrors) {
            $crashes += [PSCustomObject]@{
                TimeCreated     = $event.TimeCreated
                EventId         = $event.Id
                Application     = if ($event.Properties[0]) { $event.Properties[0].Value } else { "Unknown" }
                Version         = if ($event.Properties[1]) { $event.Properties[1].Value } else { "Unknown" }
                FaultingModule  = if ($event.Properties[3]) { $event.Properties[3].Value } else { "Unknown" }
                ExceptionCode   = if ($event.Properties[6]) { $event.Properties[6].Value } else { "Unknown" }
                EventType       = "Application Error"
            }
        }

        # Application Hang events (Event ID 1002)
        $appHangs = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            Id        = 1002
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $appHangs) {
            $crashes += [PSCustomObject]@{
                TimeCreated     = $event.TimeCreated
                EventId         = $event.Id
                Application     = if ($event.Properties[0]) { $event.Properties[0].Value } else { "Unknown" }
                Version         = if ($event.Properties[1]) { $event.Properties[1].Value } else { "Unknown" }
                FaultingModule  = "N/A"
                ExceptionCode   = "Hang"
                EventType       = "Application Hang"
            }
        }

        # Windows Error Reporting events
        $werEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            Id        = 1001
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $werEvents) {
            $crashes += [PSCustomObject]@{
                TimeCreated     = $event.TimeCreated
                EventId         = $event.Id
                Application     = if ($event.Properties[5]) { $event.Properties[5].Value } else { "Unknown" }
                Version         = if ($event.Properties[6]) { $event.Properties[6].Value } else { "Unknown" }
                FaultingModule  = if ($event.Properties[9]) { $event.Properties[9].Value } else { "Unknown" }
                ExceptionCode   = if ($event.Properties[7]) { $event.Properties[7].Value } else { "Unknown" }
                EventType       = "Windows Error Report"
            }
        }

    } catch {
        Write-WarningMessage "Error reading Event Log: $($_.Exception.Message)"
    }

    return $crashes | Sort-Object TimeCreated -Descending
}

function Get-ApplicationResourceUsage {
    <#
    .SYNOPSIS
        Gets current resource usage by applications.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$TopCount = 10
    )

    $usage = @()

    try {
        # Get processes sorted by memory usage
        $processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 50MB } |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First $TopCount

        foreach ($proc in $processes) {
            $cpuPercent = try {
                $proc.CPU / (Get-Date - $proc.StartTime).TotalSeconds * 100
            } catch { 0 }

            $usage += [PSCustomObject]@{
                ProcessName    = $proc.ProcessName
                ProcessId      = $proc.Id
                MemoryMB       = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                CPUSeconds     = [math]::Round($proc.CPU, 2)
                HandleCount    = $proc.HandleCount
                ThreadCount    = $proc.Threads.Count
                StartTime      = $proc.StartTime
                Responding     = $proc.Responding
            }
        }
    } catch {
        Write-WarningMessage "Error getting process information: $($_.Exception.Message)"
    }

    return $usage
}

function Update-Application {
    <#
    .SYNOPSIS
        Updates an application using Winget or Chocolatey.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$UpdateInfo
    )

    try {
        if ($UpdateInfo.PackageManager -eq "Winget") {
            Write-InfoMessage "Updating $($UpdateInfo.Name) via Winget..."
            $result = winget upgrade --id $UpdateInfo.Id --accept-package-agreements --accept-source-agreements 2>&1
            return $?
        } elseif ($UpdateInfo.PackageManager -eq "Chocolatey") {
            Write-InfoMessage "Updating $($UpdateInfo.Name) via Chocolatey..."
            $result = choco upgrade $UpdateInfo.Id -y 2>&1
            return $LASTEXITCODE -eq 0
        }
    } catch {
        Write-ErrorMessage "Failed to update $($UpdateInfo.Name): $($_.Exception.Message)"
        return $false
    }

    return $false
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports application health report to HTML format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$HealthData,

        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Application Health Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #0078d4; }
        .summary-card.warning { border-left-color: #ffc107; }
        .summary-card.danger { border-left-color: #dc3545; }
        .summary-card.success { border-left-color: #28a745; }
        .summary-card h3 { margin: 0 0 5px 0; font-size: 14px; color: #666; }
        .summary-card .value { font-size: 28px; font-weight: bold; color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th { background: #0078d4; color: white; padding: 10px 8px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-missing { color: #dc3545; font-weight: bold; }
        .status-update { color: #ffc107; font-weight: bold; }
        .timestamp { color: #666; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Application Health Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card success">
                <h3>Installed Applications</h3>
                <div class="value">$($HealthData.InstalledApps.Count)</div>
            </div>
            <div class="summary-card $(if($HealthData.MissingApps.Count -gt 0){'danger'}else{'success'})">
                <h3>Missing Required</h3>
                <div class="value">$($HealthData.MissingApps.Count)</div>
            </div>
            <div class="summary-card $(if($HealthData.AvailableUpdates.Count -gt 0){'warning'}else{'success'})">
                <h3>Updates Available</h3>
                <div class="value">$($HealthData.AvailableUpdates.Count)</div>
            </div>
            <div class="summary-card $(if($HealthData.Crashes.Count -gt 0){'danger'}else{'success'})">
                <h3>Recent Crashes</h3>
                <div class="value">$($HealthData.Crashes.Count)</div>
            </div>
        </div>
"@

    # Missing applications section
    if ($HealthData.MissingApps.Count -gt 0) {
        $html += @"
        <h2>Missing Required Applications</h2>
        <table>
            <tr><th>Application Name</th><th>Status</th></tr>
"@
        foreach ($app in $HealthData.MissingApps) {
            $html += "<tr><td>$app</td><td class='status-missing'>Not Installed</td></tr>"
        }
        $html += "</table>"
    }

    # Available updates section
    if ($HealthData.AvailableUpdates.Count -gt 0) {
        $html += @"
        <h2>Available Updates</h2>
        <table>
            <tr><th>Application</th><th>Current Version</th><th>Available Version</th><th>Source</th></tr>
"@
        foreach ($update in $HealthData.AvailableUpdates) {
            $html += "<tr><td>$($update.Name)</td><td>$($update.CurrentVersion)</td><td class='status-update'>$($update.AvailableVersion)</td><td>$($update.Source)</td></tr>"
        }
        $html += "</table>"
    }

    # Recent crashes section
    if ($HealthData.Crashes.Count -gt 0) {
        $html += @"
        <h2>Recent Application Crashes</h2>
        <table>
            <tr><th>Time</th><th>Application</th><th>Version</th><th>Type</th><th>Faulting Module</th></tr>
"@
        foreach ($crash in $HealthData.Crashes | Select-Object -First 20) {
            $html += "<tr><td>$($crash.TimeCreated.ToString('yyyy-MM-dd HH:mm'))</td><td>$($crash.Application)</td><td>$($crash.Version)</td><td>$($crash.EventType)</td><td>$($crash.FaultingModule)</td></tr>"
        }
        $html += "</table>"
    }

    # Resource usage section
    if ($HealthData.ResourceUsage.Count -gt 0) {
        $html += @"
        <h2>Top Resource Consumers</h2>
        <table>
            <tr><th>Process</th><th>Memory (MB)</th><th>CPU (sec)</th><th>Handles</th><th>Threads</th><th>Responding</th></tr>
"@
        foreach ($proc in $HealthData.ResourceUsage) {
            $respondingClass = if ($proc.Responding) { "status-ok" } else { "status-missing" }
            $html += "<tr><td>$($proc.ProcessName)</td><td>$($proc.MemoryMB)</td><td>$($proc.CPUSeconds)</td><td>$($proc.HandleCount)</td><td>$($proc.ThreadCount)</td><td class='$respondingClass'>$(if($proc.Responding){'Yes'}else{'No'})</td></tr>"
        }
        $html += "</table>"
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
function Invoke-ApplicationHealthCheck {
    [CmdletBinding()]
    param()

    Write-InfoMessage "Starting Application Health Check"

    # Check for admin privileges
    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Running without administrator privileges. Some features may be limited."
    }

    # Set output path
    if (-not $OutputPath) {
        $OutputPath = Get-LogDirectory
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Get installed applications
    Write-InfoMessage "Scanning installed applications..."
    $installedApps = Get-InstalledApplications
    Write-Success "Found $($installedApps.Count) installed applications"

    # Check required applications
    $missingApps = @()
    $foundRequiredApps = @()
    if ($RequiredApps) {
        Write-InfoMessage "Checking required applications..."
        foreach ($appName in $RequiredApps) {
            $found = Test-ApplicationInstalled -AppName $appName -InstalledApps $installedApps
            if ($found) {
                $foundRequiredApps += $found | Select-Object -First 1
                Write-Success "Found: $appName (v$($found[0].Version))"
            } else {
                $missingApps += $appName
                Write-ErrorMessage "Missing: $appName"
            }
        }
    }

    # Check for updates
    $availableUpdates = @()
    if ($CheckUpdates -or $AutoUpdate) {
        $wingetUpdates = Get-WingetUpdates
        $chocoUpdates = Get-ChocolateyUpdates
        $availableUpdates = $wingetUpdates + $chocoUpdates

        if ($availableUpdates.Count -gt 0) {
            Write-WarningMessage "Found $($availableUpdates.Count) applications with updates available"
        } else {
            Write-Success "All applications are up to date"
        }
    }

    # Auto-update if requested
    $updatedApps = @()
    if ($AutoUpdate -and $availableUpdates.Count -gt 0) {
        Write-InfoMessage "Auto-updating applications..."
        foreach ($update in $availableUpdates) {
            $success = Update-Application -UpdateInfo $update
            if ($success) {
                $updatedApps += $update.Name
                Write-Success "Updated: $($update.Name)"
            } else {
                Write-ErrorMessage "Failed to update: $($update.Name)"
            }
        }
    }

    # Check for crashes
    $crashes = @()
    if ($CheckCrashes) {
        $crashes = Get-ApplicationCrashes -Days $CrashDays
        if ($crashes.Count -gt 0) {
            Write-WarningMessage "Found $($crashes.Count) application crashes in the last $CrashDays days"
        } else {
            Write-Success "No application crashes found in the last $CrashDays days"
        }
    }

    # Get resource usage
    Write-InfoMessage "Checking application resource usage..."
    $resourceUsage = Get-ApplicationResourceUsage -TopCount 10

    # Compile health data
    $healthData = [PSCustomObject]@{
        InstalledApps    = $installedApps
        RequiredApps     = $foundRequiredApps
        MissingApps      = $missingApps
        AvailableUpdates = $availableUpdates
        UpdatedApps      = $updatedApps
        Crashes          = $crashes
        ResourceUsage    = $resourceUsage
        CheckDate        = Get-Date
    }

    # Output results based on format
    switch ($OutputFormat) {
        'Console' {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "     APPLICATION HEALTH SUMMARY         " -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Installed Applications: $($installedApps.Count)"

            if ($RequiredApps) {
                Write-Host ""
                Write-Host "Required Applications:" -ForegroundColor Yellow
                foreach ($app in $RequiredApps) {
                    $status = if ($missingApps -contains $app) {
                        "[-] MISSING"
                    } else {
                        "[+] Installed"
                    }
                    $color = if ($missingApps -contains $app) { "Red" } else { "Green" }
                    Write-Host "  $status - $app" -ForegroundColor $color
                }
            }

            if ($availableUpdates.Count -gt 0) {
                Write-Host ""
                Write-Host "Available Updates:" -ForegroundColor Yellow
                foreach ($update in $availableUpdates) {
                    Write-Host "  [!] $($update.Name): $($update.CurrentVersion) -> $($update.AvailableVersion)" -ForegroundColor Yellow
                }
            }

            if ($crashes.Count -gt 0) {
                Write-Host ""
                Write-Host "Recent Crashes (Last $CrashDays days):" -ForegroundColor Red
                $crashSummary = $crashes | Group-Object Application | Sort-Object Count -Descending | Select-Object -First 5
                foreach ($group in $crashSummary) {
                    Write-Host "  [-] $($group.Name): $($group.Count) crash(es)" -ForegroundColor Red
                }
            }

            if ($resourceUsage.Count -gt 0) {
                Write-Host ""
                Write-Host "Top Memory Consumers:" -ForegroundColor Cyan
                foreach ($proc in $resourceUsage | Select-Object -First 5) {
                    Write-Host "  $($proc.ProcessName): $($proc.MemoryMB) MB"
                }
            }
        }

        'HTML' {
            $htmlFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.html"
            Export-HtmlReport -HealthData $healthData -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"
        }

        'JSON' {
            $jsonFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.json"
            $healthData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"
        }

        'CSV' {
            $csvFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.csv"
            $installedApps | Select-Object Name, Version, Publisher, InstallDate, Architecture, Source |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"
        }

        'All' {
            # HTML
            $htmlFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.html"
            Export-HtmlReport -HealthData $healthData -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"

            # JSON
            $jsonFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.json"
            $healthData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"

            # CSV
            $csvFile = Join-Path $OutputPath "ApplicationHealth_$timestamp.csv"
            $installedApps | Select-Object Name, Version, Publisher, InstallDate, Architecture, Source |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"

            # Console summary
            Write-Host ""
            Write-Host "Summary: $($installedApps.Count) apps, $($missingApps.Count) missing, $($availableUpdates.Count) updates, $($crashes.Count) crashes"
        }
    }

    Write-Success "Application health check completed"

    # Return results for pipeline usage
    return [PSCustomObject]@{
        HealthData = $healthData
        ExitCode   = if ($missingApps.Count -gt 0) { 2 }
                    elseif ($crashes.Count -gt 10 -or $availableUpdates.Count -gt 5) { 1 }
                    else { 0 }
    }
}

# Run the health check
$result = Invoke-ApplicationHealthCheck
exit $result.ExitCode
#endregion
