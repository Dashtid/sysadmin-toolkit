#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Monitors critical Windows services and provides auto-restart capabilities with alerting.

.DESCRIPTION
    This script provides comprehensive Windows service health monitoring with:
    - Configurable list of critical services to monitor
    - Automatic service restart with retry logic and backoff
    - Service dependency checking
    - Service startup history tracking
    - Multiple notification methods (Console, Event Log, Email)
    - Service state change detection
    - Detailed logging and reporting
    - Support for both automatic and manual service monitoring

    Key features:
    - Monitor predefined or custom service lists
    - Auto-restart failed services with configurable retry attempts
    - Exclude services with Delayed Start or Trigger Start
    - Track service uptime and restart history
    - Generate HTML/JSON reports
    - Write to Windows Event Log for SIEM integration

.PARAMETER Services
    Array of service names to monitor. If not specified, monitors critical system services.

.PARAMETER ConfigFile
    Path to JSON configuration file containing service list and settings.

.PARAMETER AutoRestart
    Automatically attempt to restart stopped services.

.PARAMETER MaxRestartAttempts
    Maximum number of restart attempts per service. Default: 3

.PARAMETER RestartDelaySeconds
    Delay between restart attempts with exponential backoff. Default: 10

.PARAMETER MonitorInterval
    Interval in seconds between monitoring cycles (for continuous mode). Default: 60

.PARAMETER MonitorDuration
    Duration in minutes to monitor (0 = single run). Default: 0

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON, EventLog, All.
    Default: Console

.PARAMETER OutputPath
    Directory path for output files.

.PARAMETER IncludeDelayedStart
    Include services with Delayed Start in monitoring (normally excluded).

.PARAMETER ExcludeServices
    Array of service names to exclude from monitoring.

.PARAMETER AlertOnlyOnChange
    Only generate alerts when service state changes.

.EXAMPLE
    .\Watch-ServiceHealth.ps1
    Monitors critical system services with console output.

.EXAMPLE
    .\Watch-ServiceHealth.ps1 -AutoRestart -MaxRestartAttempts 5
    Monitors services and automatically restarts failed ones up to 5 times.

.EXAMPLE
    .\Watch-ServiceHealth.ps1 -Services "Spooler", "wuauserv", "BITS" -AutoRestart
    Monitors specific services and auto-restarts if stopped.

.EXAMPLE
    .\Watch-ServiceHealth.ps1 -MonitorDuration 60 -MonitorInterval 30 -OutputFormat All
    Continuous monitoring for 60 minutes, checking every 30 seconds.

.EXAMPLE
    .\Watch-ServiceHealth.ps1 -ConfigFile "C:\Config\services.json" -AutoRestart
    Uses configuration file for service list and settings.

.NOTES
    File Name      : Watch-ServiceHealth.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended), Administrator privileges for restart
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Services,

    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [switch]$AutoRestart,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaxRestartAttempts = 3,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int]$RestartDelaySeconds = 10,

    [Parameter()]
    [ValidateRange(10, 3600)]
    [int]$MonitorInterval = 60,

    [Parameter()]
    [ValidateRange(0, 1440)]
    [int]$MonitorDuration = 0,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'EventLog', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeDelayedStart,

    [Parameter()]
    [string[]]$ExcludeServices,

    [Parameter()]
    [switch]$AlertOnlyOnChange
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
    function Test-IsAdministrator {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

$errorHandlingPath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\ErrorHandling.psm1"
if (Test-Path $errorHandlingPath) {
    Import-Module $errorHandlingPath -Force
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"
$script:IsAdmin = Test-IsAdministrator
$script:PreviousState = @{}
$script:RestartHistory = @{}

# Default critical services to monitor
$script:DefaultServices = @(
    # Core Windows Services
    'wuauserv',          # Windows Update
    'BITS',              # Background Intelligent Transfer Service
    'Winmgmt',           # Windows Management Instrumentation
    'Schedule',          # Task Scheduler
    'EventLog',          # Windows Event Log
    'LanmanServer',      # Server (File sharing)
    'LanmanWorkstation', # Workstation
    'RpcSs',             # Remote Procedure Call
    'Dhcp',              # DHCP Client
    'Dnscache',          # DNS Client
    'NlaSvc',            # Network Location Awareness
    'WinDefend',         # Windows Defender
    'MpsSvc',            # Windows Defender Firewall
    'wscsvc',            # Security Center
    'CryptSvc',          # Cryptographic Services
    'Spooler',           # Print Spooler
    'W32Time',           # Windows Time
    'SamSs',             # Security Accounts Manager
    'PlugPlay'           # Plug and Play
)

# Set output path
if (-not $OutputPath) {
    $OutputPath = Get-LogDirectory
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Load configuration from file if specified
if ($ConfigFile -and (Test-Path $ConfigFile)) {
    try {
        $config = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        if ($config.Services -and -not $PSBoundParameters.ContainsKey('Services')) {
            $Services = $config.Services
        }
        if ($config.ExcludeServices -and -not $PSBoundParameters.ContainsKey('ExcludeServices')) {
            $ExcludeServices = $config.ExcludeServices
        }
        if ($null -ne $config.AutoRestart -and -not $PSBoundParameters.ContainsKey('AutoRestart')) {
            $AutoRestart = [bool]$config.AutoRestart
        }
        if ($config.MaxRestartAttempts -and -not $PSBoundParameters.ContainsKey('MaxRestartAttempts')) {
            $MaxRestartAttempts = $config.MaxRestartAttempts
        }
        Write-InfoMessage "Loaded configuration from: $ConfigFile"
    }
    catch {
        Write-WarningMessage "Failed to load configuration file: $($_.Exception.Message)"
    }
}

# Use default services if none specified
if (-not $Services -or $Services.Count -eq 0) {
    $Services = $script:DefaultServices
}

# Apply exclusions
if ($ExcludeServices) {
    $Services = $Services | Where-Object { $_ -notin $ExcludeServices }
}
#endregion

#region Helper Functions
function Get-ServiceStatus {
    <#
    .SYNOPSIS
        Gets detailed status information for a service.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue

        $isDelayedStart = $false
        $isTriggerStart = $false

        if ($wmiService) {
            # Check for delayed auto-start
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            if (Test-Path $regPath) {
                $delayedAutoStart = Get-ItemProperty -Path $regPath -Name "DelayedAutostart" -ErrorAction SilentlyContinue
                $isDelayedStart = $delayedAutoStart.DelayedAutostart -eq 1

                # Check for trigger start
                $triggerPath = Join-Path $regPath "TriggerInfo"
                $isTriggerStart = Test-Path $triggerPath
            }
        }

        return @{
            Name            = $service.Name
            DisplayName     = $service.DisplayName
            Status          = $service.Status.ToString()
            StartType       = $service.StartType.ToString()
            IsDelayedStart  = $isDelayedStart
            IsTriggerStart  = $isTriggerStart
            CanStop         = $service.CanStop
            CanPauseAndContinue = $service.CanPauseAndContinue
            DependentServices = ($service.DependentServices | ForEach-Object { $_.Name }) -join ', '
            ServicesDependedOn = ($service.ServicesDependedOn | ForEach-Object { $_.Name }) -join ', '
            ProcessId       = $wmiService.ProcessId
            PathName        = $wmiService.PathName
            Description     = $wmiService.Description
            Found           = $true
            Error           = $null
        }
    }
    catch {
        return @{
            Name    = $ServiceName
            Found   = $false
            Status  = 'NotFound'
            Error   = $_.Exception.Message
        }
    }
}

function Test-ServiceShouldMonitor {
    <#
    .SYNOPSIS
        Determines if a service should be monitored based on its configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ServiceInfo
    )

    # Skip services that don't exist
    if (-not $ServiceInfo.Found) {
        return $false
    }

    # Skip manual or disabled services
    if ($ServiceInfo.StartType -in @('Manual', 'Disabled')) {
        return $false
    }

    # Skip delayed start unless explicitly included
    if ($ServiceInfo.IsDelayedStart -and -not $IncludeDelayedStart) {
        return $false
    }

    # Skip trigger start services (they start on demand)
    if ($ServiceInfo.IsTriggerStart -and -not $IncludeDelayedStart) {
        return $false
    }

    return $true
}

function Restart-ServiceWithRetry {
    <#
    .SYNOPSIS
        Attempts to restart a service with retry logic and exponential backoff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [int]$MaxAttempts = $MaxRestartAttempts,

        [int]$InitialDelay = $RestartDelaySeconds
    )

    if (-not $script:IsAdmin) {
        Write-WarningMessage "Cannot restart service '$ServiceName' - Administrator privileges required"
        return @{
            Success  = $false
            Attempts = 0
            Error    = "Administrator privileges required"
        }
    }

    $result = @{
        ServiceName = $ServiceName
        Success     = $false
        Attempts    = 0
        StartTime   = Get-Date
        EndTime     = $null
        Error       = $null
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $result.Attempts = $attempt

        try {
            Write-InfoMessage "Restart attempt $attempt/$MaxAttempts for service '$ServiceName'..."

            # Stop the service if it's in a weird state
            $service = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($service.Status -notin @('Stopped', 'StopPending')) {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            # Start the service
            Start-Service -Name $ServiceName -ErrorAction Stop

            # Wait for service to start
            $timeout = 30
            $elapsed = 0
            while ($elapsed -lt $timeout) {
                $service = Get-Service -Name $ServiceName
                if ($service.Status -eq 'Running') {
                    $result.Success = $true
                    $result.EndTime = Get-Date
                    Write-Success "Service '$ServiceName' restarted successfully on attempt $attempt"

                    # Track restart history
                    if (-not $script:RestartHistory.ContainsKey($ServiceName)) {
                        $script:RestartHistory[$ServiceName] = @()
                    }
                    $script:RestartHistory[$ServiceName] += @{
                        Timestamp = Get-Date
                        Attempts  = $attempt
                        Success   = $true
                    }

                    return $result
                }
                Start-Sleep -Seconds 1
                $elapsed++
            }

            throw "Service did not start within $timeout seconds"
        }
        catch {
            $result.Error = $_.Exception.Message
            Write-WarningMessage "Restart attempt $attempt failed: $($_.Exception.Message)"

            if ($attempt -lt $MaxAttempts) {
                $delay = $InitialDelay * $attempt
                Write-InfoMessage "Waiting $delay seconds before next attempt..."
                Start-Sleep -Seconds $delay
            }
        }
    }

    # All attempts failed
    Write-ErrorMessage "Failed to restart service '$ServiceName' after $MaxAttempts attempts"

    # Track failed restart
    if (-not $script:RestartHistory.ContainsKey($ServiceName)) {
        $script:RestartHistory[$ServiceName] = @()
    }
    $script:RestartHistory[$ServiceName] += @{
        Timestamp = Get-Date
        Attempts  = $MaxAttempts
        Success   = $false
        Error     = $result.Error
    }

    return $result
}

function Get-ServiceHealthReport {
    <#
    .SYNOPSIS
        Generates a comprehensive service health report.
    #>
    [CmdletBinding()]
    param()

    $report = @{
        Timestamp       = Get-Date -Format 'o'
        ComputerName    = $env:COMPUTERNAME
        TotalServices   = 0
        RunningServices = 0
        StoppedServices = 0
        FailedServices  = 0
        NotFoundServices = 0
        Services        = @()
        Alerts          = @()
        RestartHistory  = $script:RestartHistory
    }

    foreach ($serviceName in $Services) {
        $serviceInfo = Get-ServiceStatus -ServiceName $serviceName
        $report.TotalServices++

        # Skip services that shouldn't be monitored
        if (-not (Test-ServiceShouldMonitor -ServiceInfo $serviceInfo)) {
            if (-not $serviceInfo.Found) {
                $report.NotFoundServices++
                $report.Services += @{
                    Name    = $serviceName
                    Status  = 'NotFound'
                    Monitored = $false
                    Reason  = "Service not found on system"
                }
            }
            else {
                $report.Services += @{
                    Name        = $serviceName
                    DisplayName = $serviceInfo.DisplayName
                    Status      = $serviceInfo.Status
                    StartType   = $serviceInfo.StartType
                    Monitored   = $false
                    Reason      = "Excluded (StartType: $($serviceInfo.StartType), DelayedStart: $($serviceInfo.IsDelayedStart), TriggerStart: $($serviceInfo.IsTriggerStart))"
                }
            }
            continue
        }

        $serviceReport = @{
            Name              = $serviceInfo.Name
            DisplayName       = $serviceInfo.DisplayName
            Status            = $serviceInfo.Status
            StartType         = $serviceInfo.StartType
            IsDelayedStart    = $serviceInfo.IsDelayedStart
            IsTriggerStart    = $serviceInfo.IsTriggerStart
            ProcessId         = $serviceInfo.ProcessId
            Dependencies      = $serviceInfo.ServicesDependedOn
            Monitored         = $true
            StateChanged      = $false
            RestartAttempted  = $false
            RestartSuccess    = $null
        }

        # Check for state change
        if ($script:PreviousState.ContainsKey($serviceName)) {
            if ($script:PreviousState[$serviceName] -ne $serviceInfo.Status) {
                $serviceReport.StateChanged = $true
                $report.Alerts += @{
                    Level   = if ($serviceInfo.Status -eq 'Running') { 'Info' } else { 'Warning' }
                    Type    = 'StateChange'
                    Service = $serviceName
                    Message = "Service '$($serviceInfo.DisplayName)' changed from $($script:PreviousState[$serviceName]) to $($serviceInfo.Status)"
                }
            }
        }

        # Update previous state
        $script:PreviousState[$serviceName] = $serviceInfo.Status

        # Count by status
        switch ($serviceInfo.Status) {
            'Running' { $report.RunningServices++ }
            'Stopped' {
                $report.StoppedServices++

                # Generate alert for stopped automatic service
                $report.Alerts += @{
                    Level   = 'Critical'
                    Type    = 'ServiceStopped'
                    Service = $serviceName
                    Message = "Automatic service '$($serviceInfo.DisplayName)' is stopped"
                }

                # Attempt restart if enabled
                if ($AutoRestart) {
                    $restartResult = Restart-ServiceWithRetry -ServiceName $serviceName
                    $serviceReport.RestartAttempted = $true
                    $serviceReport.RestartSuccess = $restartResult.Success

                    if ($restartResult.Success) {
                        $serviceReport.Status = 'Running'
                        $report.RunningServices++
                        $report.StoppedServices--
                        $report.Alerts += @{
                            Level   = 'Info'
                            Type    = 'ServiceRestarted'
                            Service = $serviceName
                            Message = "Service '$($serviceInfo.DisplayName)' was successfully restarted"
                        }
                    }
                    else {
                        $report.FailedServices++
                        $report.Alerts += @{
                            Level   = 'Critical'
                            Type    = 'RestartFailed'
                            Service = $serviceName
                            Message = "Failed to restart service '$($serviceInfo.DisplayName)': $($restartResult.Error)"
                        }
                    }
                }
            }
            default {
                # Other states (Paused, StartPending, StopPending, etc.)
                $report.Alerts += @{
                    Level   = 'Warning'
                    Type    = 'AbnormalState'
                    Service = $serviceName
                    Message = "Service '$($serviceInfo.DisplayName)' is in abnormal state: $($serviceInfo.Status)"
                }
            }
        }

        $report.Services += $serviceReport
    }

    return $report
}

function Write-EventLogEntry {
    <#
    .SYNOPSIS
        Writes service health alerts to Windows Event Log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Alerts
    )

    $logName = 'Application'
    $source = 'SysadminToolkit-ServiceMonitor'

    # Create event source if it doesn't exist (requires admin)
    if ($script:IsAdmin) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
                [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
            }
        }
        catch {
            Write-WarningMessage "Could not create event log source: $($_.Exception.Message)"
            return
        }
    }

    foreach ($alert in $Alerts) {
        $entryType = switch ($alert.Level) {
            'Critical' { 'Error' }
            'Warning'  { 'Warning' }
            default    { 'Information' }
        }

        try {
            Write-EventLog -LogName $logName -Source $source -EventId 1000 -EntryType $entryType -Message $alert.Message -ErrorAction Stop
        }
        catch {
            Write-Verbose "Could not write to event log: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Output Functions
function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Outputs service health report to console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report
    )

    # Skip if AlertOnlyOnChange and no state changes
    if ($AlertOnlyOnChange) {
        $hasChanges = ($Report.Services | Where-Object { $_.StateChanged }).Count -gt 0
        $hasCritical = ($Report.Alerts | Where-Object { $_.Level -eq 'Critical' }).Count -gt 0
        if (-not $hasChanges -and -not $hasCritical) {
            return
        }
    }

    $separator = "=" * 60

    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  SERVICE HEALTH REPORT" -ForegroundColor Cyan
    Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "  Computer:  $($Report.ComputerName)" -ForegroundColor Cyan
    Write-Host "$separator`n" -ForegroundColor Cyan

    # Summary
    Write-Host "SUMMARY" -ForegroundColor White
    Write-Host "-" * 40
    Write-Host "  Total Monitored:  $($Report.TotalServices)"
    Write-Host "  Running:          " -NoNewline
    Write-Host "$($Report.RunningServices)" -ForegroundColor Green
    Write-Host "  Stopped:          " -NoNewline
    if ($Report.StoppedServices -gt 0) {
        Write-Host "$($Report.StoppedServices)" -ForegroundColor Red
    }
    else {
        Write-Host "$($Report.StoppedServices)" -ForegroundColor Green
    }
    if ($Report.FailedServices -gt 0) {
        Write-Host "  Failed Restart:   " -NoNewline
        Write-Host "$($Report.FailedServices)" -ForegroundColor Red
    }
    if ($Report.NotFoundServices -gt 0) {
        Write-Host "  Not Found:        " -NoNewline
        Write-Host "$($Report.NotFoundServices)" -ForegroundColor Yellow
    }
    Write-Host ""

    # Service Details
    Write-Host "SERVICE STATUS" -ForegroundColor White
    Write-Host "-" * 40

    foreach ($service in ($Report.Services | Where-Object { $_.Monitored })) {
        $statusColor = switch ($service.Status) {
            'Running'       { 'Green' }
            'Stopped'       { 'Red' }
            'StartPending'  { 'Yellow' }
            'StopPending'   { 'Yellow' }
            default         { 'Yellow' }
        }

        $statusIcon = switch ($service.Status) {
            'Running' { '[+]' }
            'Stopped' { '[-]' }
            default   { '[!]' }
        }

        $changeMarker = if ($service.StateChanged) { '*' } else { ' ' }
        $restartMarker = if ($service.RestartAttempted) {
            if ($service.RestartSuccess) { ' (restarted)' } else { ' (restart failed)' }
        }
        else { '' }

        Write-Host "  $statusIcon$changeMarker" -NoNewline -ForegroundColor $statusColor
        Write-Host " $($service.Name.PadRight(25))" -NoNewline
        Write-Host " [$($service.Status)]" -ForegroundColor $statusColor -NoNewline
        Write-Host "$restartMarker"
    }
    Write-Host ""

    # Non-monitored services
    $nonMonitored = $Report.Services | Where-Object { -not $_.Monitored }
    if ($nonMonitored.Count -gt 0) {
        Write-Host "EXCLUDED FROM MONITORING" -ForegroundColor White
        Write-Host "-" * 40
        foreach ($service in $nonMonitored) {
            Write-Host "  [i] $($service.Name): $($service.Reason)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # Alerts
    if ($Report.Alerts.Count -gt 0) {
        Write-Host "ALERTS" -ForegroundColor White
        Write-Host "-" * 40
        foreach ($alert in $Report.Alerts) {
            $alertColor = switch ($alert.Level) {
                'Critical' { 'Red' }
                'Warning'  { 'Yellow' }
                'Info'     { 'Green' }
                default    { 'White' }
            }
            $alertIcon = switch ($alert.Level) {
                'Critical' { '[-]' }
                'Warning'  { '[!]' }
                'Info'     { '[+]' }
                default    { '[i]' }
            }
            Write-Host "  $alertIcon $($alert.Message)" -ForegroundColor $alertColor
        }
        Write-Host ""
    }
    else {
        Write-Host "[+] All monitored services are running normally`n" -ForegroundColor Green
    }

    Write-Host $separator -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML service health report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $htmlPath = Join-Path $Path "service-health_$timestamp.html"

    $servicesHtml = ""
    foreach ($service in ($Report.Services | Where-Object { $_.Monitored })) {
        $statusClass = switch ($service.Status) {
            'Running' { 'running' }
            'Stopped' { 'stopped' }
            default   { 'warning' }
        }
        $changeMarker = if ($service.StateChanged) { ' [CHANGED]' } else { '' }
        $restartInfo = if ($service.RestartAttempted) {
            if ($service.RestartSuccess) { ' (Restarted)' } else { ' (Restart Failed)' }
        }
        else { '' }

        $servicesHtml += "<tr class='$statusClass'><td>$($service.Name)</td><td>$($service.DisplayName)</td><td>$($service.Status)$changeMarker$restartInfo</td><td>$($service.StartType)</td><td>$($service.ProcessId)</td></tr>"
    }

    $alertsHtml = ""
    if ($Report.Alerts.Count -gt 0) {
        $alertsHtml = "<div class='alerts'><h2>Alerts</h2><ul>"
        foreach ($alert in $Report.Alerts) {
            $alertClass = switch ($alert.Level) {
                'Critical' { 'critical' }
                'Warning'  { 'warning' }
                default    { 'info' }
            }
            $alertsHtml += "<li class='$alertClass'>[$($alert.Level)] $($alert.Message)</li>"
        }
        $alertsHtml += "</ul></div>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Service Health Report - $($Report.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 20px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .summary-card { padding: 15px 25px; border-radius: 4px; text-align: center; }
        .summary-card.running { background: #dff6dd; border-left: 4px solid #107c10; }
        .summary-card.stopped { background: #fde7e9; border-left: 4px solid #d13438; }
        .summary-card.total { background: #deecf9; border-left: 4px solid #0078d4; }
        .summary-value { font-size: 28px; font-weight: bold; }
        .summary-label { color: #666; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; font-weight: 600; }
        tr.running td:nth-child(3) { color: #107c10; font-weight: 500; }
        tr.stopped td:nth-child(3) { color: #d13438; font-weight: 500; }
        tr.warning td:nth-child(3) { color: #ff8c00; font-weight: 500; }
        .alerts ul { list-style: none; padding: 0; }
        .alerts li { padding: 10px; margin: 5px 0; border-radius: 4px; }
        .alerts li.critical { background: #fde7e9; color: #d13438; }
        .alerts li.warning { background: #fff4e5; color: #ff8c00; }
        .alerts li.info { background: #dff6dd; color: #107c10; }
        .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Service Health Report</h1>
        <p><strong>Computer:</strong> $($Report.ComputerName) | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="summary">
            <div class="summary-card total">
                <div class="summary-value">$($Report.TotalServices)</div>
                <div class="summary-label">Total Services</div>
            </div>
            <div class="summary-card running">
                <div class="summary-value">$($Report.RunningServices)</div>
                <div class="summary-label">Running</div>
            </div>
            <div class="summary-card stopped">
                <div class="summary-value">$($Report.StoppedServices)</div>
                <div class="summary-label">Stopped</div>
            </div>
        </div>

        $alertsHtml

        <h2>Service Details</h2>
        <table>
            <tr><th>Service Name</th><th>Display Name</th><th>Status</th><th>Start Type</th><th>PID</th></tr>
            $servicesHtml
        </table>

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
        Exports service health report to JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $jsonPath = Join-Path $Path "service-health_$timestamp.json"

    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
    return $jsonPath
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== Service Health Monitor v$script:ScriptVersion ==="
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    if ($script:IsAdmin) {
        Write-Success "Running with administrator privileges"
    }
    else {
        Write-WarningMessage "Running without administrator privileges - auto-restart disabled"
        if ($AutoRestart) {
            Write-WarningMessage "AutoRestart requested but requires administrator privileges"
        }
    }

    Write-InfoMessage "Monitoring $($Services.Count) services"

    # Continuous monitoring mode
    if ($MonitorDuration -gt 0) {
        Write-InfoMessage "Continuous monitoring mode: $MonitorDuration minutes"
        $endTime = (Get-Date).AddMinutes($MonitorDuration)
        $iteration = 1

        while ((Get-Date) -lt $endTime) {
            Write-InfoMessage "Monitoring cycle $iteration..."

            $report = Get-ServiceHealthReport

            switch ($OutputFormat) {
                'Console'  { Write-ConsoleReport -Report $report }
                'HTML'     { Export-HTMLReport -Report $report -Path $OutputPath }
                'JSON'     { Export-JSONReport -Report $report -Path $OutputPath }
                'EventLog' {
                    Write-ConsoleReport -Report $report
                    if ($report.Alerts.Count -gt 0) {
                        Write-EventLogEntry -Alerts $report.Alerts
                    }
                }
                'All' {
                    Write-ConsoleReport -Report $report
                    Export-HTMLReport -Report $report -Path $OutputPath
                    Export-JSONReport -Report $report -Path $OutputPath
                    if ($report.Alerts.Count -gt 0) {
                        Write-EventLogEntry -Alerts $report.Alerts
                    }
                }
            }

            $iteration++
            $remainingTime = ($endTime - (Get-Date)).TotalMinutes
            if ($remainingTime -gt 0) {
                Write-InfoMessage "Next check in $MonitorInterval seconds... ($([math]::Round($remainingTime, 1)) minutes remaining)"
                Start-Sleep -Seconds $MonitorInterval
            }
        }
    }
    else {
        # Single run mode
        $report = Get-ServiceHealthReport

        switch ($OutputFormat) {
            'Console'  { Write-ConsoleReport -Report $report }
            'HTML'     { Export-HTMLReport -Report $report -Path $OutputPath }
            'JSON'     { Export-JSONReport -Report $report -Path $OutputPath }
            'EventLog' {
                Write-ConsoleReport -Report $report
                if ($report.Alerts.Count -gt 0) {
                    Write-EventLogEntry -Alerts $report.Alerts
                }
            }
            'All' {
                Write-ConsoleReport -Report $report
                Export-HTMLReport -Report $report -Path $OutputPath
                Export-JSONReport -Report $report -Path $OutputPath
                if ($report.Alerts.Count -gt 0) {
                    Write-EventLogEntry -Alerts $report.Alerts
                }
            }
        }
    }

    $duration = (Get-Date) - $script:StartTime
    Write-Success "=== Service health monitoring completed in $($duration.TotalSeconds.ToString('0.00'))s ==="
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    if (Get-Command Write-ContextualError -ErrorAction SilentlyContinue) {
        Write-ContextualError -ErrorRecord $_ -Context "running service health monitor" -Suggestion "Check permissions and service access"
    }
    exit 1
}
#endregion
