#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Analyzes Windows Event Logs for security incidents, errors, and system issues.

.DESCRIPTION
    This script provides comprehensive Windows Event Log analysis including:
    - Parse Application, Security, and System event logs
    - Filter by severity (Critical, Error, Warning, Information)
    - Track failed logon attempts and security incidents
    - Detect privilege escalation attempts
    - Generate security incident reports
    - Pattern detection for common issues
    - Export to HTML, CSV, or JSON for analysis

    Key features:
    - Customizable time range for analysis
    - Security-focused event filtering
    - Failed authentication tracking
    - Service failure detection
    - Application crash analysis
    - Clear/Warning event detection
    - SIEM-friendly output formats

.PARAMETER LogNames
    Event log names to analyze. Default: Application, Security, System

.PARAMETER Hours
    Number of hours to look back. Default: 24

.PARAMETER MaxEvents
    Maximum events to retrieve per log. Default: 1000

.PARAMETER Level
    Minimum severity level to include. Valid: Critical, Error, Warning, Information, All
    Default: Warning (includes Critical, Error, and Warning)

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON, CSV, All.
    Default: Console

.PARAMETER OutputPath
    Directory path for output files.

.PARAMETER IncludeSecurityAnalysis
    Include detailed security event analysis (requires admin for Security log).

.PARAMETER IncludeFailedLogons
    Include failed logon attempt analysis.

.PARAMETER EventIds
    Specific event IDs to filter for.

.PARAMETER SourceFilter
    Filter events by source name (wildcard supported).

.PARAMETER ExcludeSources
    Event sources to exclude from analysis.

.PARAMETER GroupBy
    Group results by: Source, EventId, Level, Hour, Day. Default: Source

.EXAMPLE
    .\Get-EventLogAnalysis.ps1
    Analyzes last 24 hours of Warning and above events with console output.

.EXAMPLE
    .\Get-EventLogAnalysis.ps1 -Hours 72 -Level Error -OutputFormat HTML
    Analyzes last 72 hours for Error and Critical events, generates HTML report.

.EXAMPLE
    .\Get-EventLogAnalysis.ps1 -IncludeSecurityAnalysis -IncludeFailedLogons
    Includes security event analysis and failed logon tracking.

.EXAMPLE
    .\Get-EventLogAnalysis.ps1 -LogNames "Application" -SourceFilter "*SQL*"
    Analyzes only Application log for SQL-related events.

.EXAMPLE
    .\Get-EventLogAnalysis.ps1 -EventIds 1000, 1001, 7034 -Hours 168
    Looks for specific event IDs over the last week.

.NOTES
    File Name      : Get-EventLogAnalysis.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+, Admin for Security log access
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
    [string[]]$LogNames = @('Application', 'Security', 'System'),

    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [Parameter()]
    [ValidateRange(100, 50000)]
    [int]$MaxEvents = 1000,

    [Parameter()]
    [ValidateSet('Critical', 'Error', 'Warning', 'Information', 'All')]
    [string]$Level = 'Warning',

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeSecurityAnalysis,

    [Parameter()]
    [switch]$IncludeFailedLogons,

    [Parameter()]
    [int[]]$EventIds,

    [Parameter()]
    [string]$SourceFilter,

    [Parameter()]
    [string[]]$ExcludeSources,

    [Parameter()]
    [ValidateSet('Source', 'EventId', 'Level', 'Hour', 'Day')]
    [string]$GroupBy = 'Source'
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
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"
$script:IsAdmin = Test-IsAdministrator

# Set output path
if (-not $OutputPath) {
    $OutputPath = Get-LogDirectory
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Level mapping
$script:LevelMapping = @{
    'Critical'    = 1
    'Error'       = 2
    'Warning'     = 3
    'Information' = 4
    'Verbose'     = 5
}

# Important security event IDs
$script:SecurityEventIds = @{
    # Account Logon Events
    FailedLogon           = @(4625)
    SuccessfulLogon       = @(4624)
    LogonWithExplicitCreds = @(4648)
    AccountLockout        = @(4740)

    # Privilege Use
    PrivilegeEscalation   = @(4672, 4673, 4674)
    SensitivePrivilegeUse = @(4673)

    # Account Management
    UserAccountCreated    = @(4720)
    UserAccountDeleted    = @(4726)
    UserAccountChanged    = @(4738)
    UserAddedToGroup      = @(4728, 4732, 4756)
    PasswordChange        = @(4723, 4724)
    PasswordReset         = @(4724)

    # Object Access
    ObjectAccessAttempt   = @(4663)
    FileShareAccess       = @(5140, 5145)

    # Policy Changes
    AuditPolicyChange     = @(4719)
    AuthPolicyChange      = @(4706, 4707)

    # System Events
    EventLogCleared       = @(1102, 104)
    SystemTimeChange      = @(4616)
    ServiceInstalled      = @(4697, 7045)

    # Process Events
    ProcessCreation       = @(4688)
    ProcessTermination    = @(4689)
}

# Common application error event IDs
$script:ApplicationEventIds = @{
    AppCrash              = @(1000, 1001, 1002)
    AppHang               = @(1002)
    WER                   = @(1001)
    DotNetRuntime         = @(1026)
    SideBySide            = @(33, 35, 59, 63, 80)
}

# System event IDs
$script:SystemEventIds = @{
    UnexpectedShutdown    = @(6008)
    ServiceCrash          = @(7034)
    ServiceFailed         = @(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034)
    Bugcheck              = @(1001)
    DiskError             = @(7, 11, 15, 55)
    NTPTimeError          = @(12, 14, 22, 37, 50, 129)
    KernelPowerError      = @(41)
    DriverFailed          = @(219)
}
#endregion

#region Event Collection Functions
function Get-FilteredEvents {
    <#
    .SYNOPSIS
        Retrieves filtered events from specified event log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [datetime]$StartTime,

        [int]$MaxEvents = 1000,

        [int[]]$LevelValues
    )

    $events = @()

    try {
        # Build filter hashtable
        $filterHash = @{
            LogName   = $LogName
            StartTime = $StartTime
        }

        if ($LevelValues -and $LevelValues.Count -gt 0) {
            $filterHash['Level'] = $LevelValues
        }

        if ($EventIds -and $EventIds.Count -gt 0) {
            $filterHash['Id'] = $EventIds
        }

        $rawEvents = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        foreach ($event in $rawEvents) {
            # Apply source filter if specified
            if ($SourceFilter) {
                if ($event.ProviderName -notlike $SourceFilter) {
                    continue
                }
            }

            # Apply exclusions
            if ($ExcludeSources -and $event.ProviderName -in $ExcludeSources) {
                continue
            }

            $levelName = switch ($event.Level) {
                1 { 'Critical' }
                2 { 'Error' }
                3 { 'Warning' }
                4 { 'Information' }
                5 { 'Verbose' }
                0 { 'Information' }  # LogAlways
                default { 'Unknown' }
            }

            $events += @{
                TimeCreated   = $event.TimeCreated
                LogName       = $event.LogName
                Source        = $event.ProviderName
                EventId       = $event.Id
                Level         = $levelName
                LevelValue    = $event.Level
                Message       = $event.Message
                MachineName   = $event.MachineName
                UserId        = $event.UserId
                ProcessId     = $event.ProcessId
                ThreadId      = $event.ThreadId
                Keywords      = $event.Keywords
                TaskCategory  = $event.TaskDisplayName
            }
        }
    }
    catch {
        if ($_.Exception.Message -match "access denied" -or $_.Exception.Message -match "Access is denied") {
            Write-WarningMessage "Access denied to $LogName log (requires administrator privileges)"
        }
        else {
            Write-WarningMessage "Error reading $LogName log: $($_.Exception.Message)"
        }
    }

    return $events
}

function Get-SecurityAnalysis {
    <#
    .SYNOPSIS
        Analyzes security events for potential incidents.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Events
    )

    $analysis = @{
        FailedLogons          = @()
        SuccessfulLogons      = @()
        PrivilegeEscalation   = @()
        AccountChanges        = @()
        PolicyChanges         = @()
        SuspiciousActivity    = @()
        LogCleared            = @()
        ServiceChanges        = @()
    }

    $securityEvents = $Events | Where-Object { $_.LogName -eq 'Security' }

    foreach ($event in $securityEvents) {
        # Failed Logons
        if ($event.EventId -in $script:SecurityEventIds.FailedLogon) {
            $analysis.FailedLogons += $event
        }

        # Successful Logons
        if ($event.EventId -in $script:SecurityEventIds.SuccessfulLogon) {
            $analysis.SuccessfulLogons += $event
        }

        # Privilege Escalation
        if ($event.EventId -in $script:SecurityEventIds.PrivilegeEscalation) {
            $analysis.PrivilegeEscalation += $event
        }

        # Account Changes
        $accountChangeIds = $script:SecurityEventIds.UserAccountCreated +
                           $script:SecurityEventIds.UserAccountDeleted +
                           $script:SecurityEventIds.UserAccountChanged +
                           $script:SecurityEventIds.UserAddedToGroup
        if ($event.EventId -in $accountChangeIds) {
            $analysis.AccountChanges += $event
        }

        # Policy Changes
        if ($event.EventId -in ($script:SecurityEventIds.AuditPolicyChange + $script:SecurityEventIds.AuthPolicyChange)) {
            $analysis.PolicyChanges += $event
        }

        # Log Cleared
        if ($event.EventId -in $script:SecurityEventIds.EventLogCleared) {
            $analysis.LogCleared += $event
        }

        # Service Changes
        if ($event.EventId -in $script:SecurityEventIds.ServiceInstalled) {
            $analysis.ServiceChanges += $event
        }
    }

    # Check for suspicious patterns
    # Multiple failed logons from same source
    $failedLogonGroups = $analysis.FailedLogons | Group-Object -Property { $_.Message -match 'Account Name:\s+(\S+)' | Out-Null; $matches[1] }
    foreach ($group in $failedLogonGroups) {
        if ($group.Count -ge 5) {
            $analysis.SuspiciousActivity += @{
                Type        = 'BruteForce'
                Description = "Multiple failed logon attempts ($($group.Count)) detected"
                Count       = $group.Count
                Events      = $group.Group
            }
        }
    }

    return $analysis
}

function Get-FailedLogonDetails {
    <#
    .SYNOPSIS
        Extracts detailed information from failed logon events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Events
    )

    $failedLogons = @()

    foreach ($event in ($Events | Where-Object { $_.EventId -eq 4625 })) {
        $details = @{
            TimeCreated   = $event.TimeCreated
            EventId       = $event.EventId
            TargetAccount = ''
            TargetDomain  = ''
            SourceIP      = ''
            SourceHost    = ''
            LogonType     = ''
            FailureReason = ''
            Status        = ''
            SubStatus     = ''
        }

        if ($event.Message) {
            # Extract account name
            if ($event.Message -match 'Account Name:\s+(\S+)') {
                $details.TargetAccount = $matches[1]
            }

            # Extract domain
            if ($event.Message -match 'Account Domain:\s+(\S+)') {
                $details.TargetDomain = $matches[1]
            }

            # Extract source IP
            if ($event.Message -match 'Source Network Address:\s+(\S+)') {
                $details.SourceIP = $matches[1]
            }

            # Extract source workstation
            if ($event.Message -match 'Workstation Name:\s+(\S+)') {
                $details.SourceHost = $matches[1]
            }

            # Extract logon type
            if ($event.Message -match 'Logon Type:\s+(\d+)') {
                $logonType = $matches[1]
                $details.LogonType = switch ($logonType) {
                    '2'  { 'Interactive' }
                    '3'  { 'Network' }
                    '4'  { 'Batch' }
                    '5'  { 'Service' }
                    '7'  { 'Unlock' }
                    '8'  { 'NetworkCleartext' }
                    '9'  { 'NewCredentials' }
                    '10' { 'RemoteInteractive (RDP)' }
                    '11' { 'CachedInteractive' }
                    default { $logonType }
                }
            }

            # Extract failure reason
            if ($event.Message -match 'Failure Reason:\s+(.+?)(?:\r|\n)') {
                $details.FailureReason = $matches[1].Trim()
            }

            # Extract status codes
            if ($event.Message -match 'Status:\s+(0x\w+)') {
                $details.Status = $matches[1]
            }
            if ($event.Message -match 'Sub Status:\s+(0x\w+)') {
                $details.SubStatus = $matches[1]
            }
        }

        $failedLogons += $details
    }

    return $failedLogons
}

function Get-SystemIssues {
    <#
    .SYNOPSIS
        Analyzes system events for issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Events
    )

    $issues = @{
        ServiceFailures       = @()
        UnexpectedShutdowns   = @()
        DiskErrors            = @()
        DriverIssues          = @()
        KernelErrors          = @()
    }

    $systemEvents = $Events | Where-Object { $_.LogName -eq 'System' }

    foreach ($event in $systemEvents) {
        # Service Failures
        if ($event.EventId -in $script:SystemEventIds.ServiceFailed) {
            $issues.ServiceFailures += $event
        }

        # Unexpected Shutdowns
        if ($event.EventId -in $script:SystemEventIds.UnexpectedShutdown) {
            $issues.UnexpectedShutdowns += $event
        }

        # Disk Errors
        if ($event.EventId -in $script:SystemEventIds.DiskError) {
            $issues.DiskErrors += $event
        }

        # Driver Issues
        if ($event.EventId -in $script:SystemEventIds.DriverFailed) {
            $issues.DriverIssues += $event
        }

        # Kernel/Power Errors
        if ($event.EventId -in ($script:SystemEventIds.KernelPowerError + $script:SystemEventIds.Bugcheck)) {
            $issues.KernelErrors += $event
        }
    }

    return $issues
}

function Get-ApplicationIssues {
    <#
    .SYNOPSIS
        Analyzes application events for crashes and errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Events
    )

    $issues = @{
        Crashes     = @()
        Hangs       = @()
        DotNetErrors = @()
        SideBySide  = @()
    }

    $appEvents = $Events | Where-Object { $_.LogName -eq 'Application' }

    foreach ($event in $appEvents) {
        # Application Crashes
        if ($event.EventId -in $script:ApplicationEventIds.AppCrash) {
            $issues.Crashes += $event
        }

        # Application Hangs
        if ($event.EventId -in $script:ApplicationEventIds.AppHang) {
            $issues.Hangs += $event
        }

        # .NET Errors
        if ($event.EventId -in $script:ApplicationEventIds.DotNetRuntime) {
            $issues.DotNetErrors += $event
        }

        # Side-by-Side Errors
        if ($event.EventId -in $script:ApplicationEventIds.SideBySide) {
            $issues.SideBySide += $event
        }
    }

    return $issues
}
#endregion

#region Report Generation Functions
function Get-EventLogReport {
    <#
    .SYNOPSIS
        Generates comprehensive event log analysis report.
    #>
    [CmdletBinding()]
    param()

    $report = @{
        Timestamp          = Get-Date -Format 'o'
        ComputerName       = $env:COMPUTERNAME
        AnalysisPeriod     = @{
            StartTime = (Get-Date).AddHours(-$Hours)
            EndTime   = Get-Date
            Hours     = $Hours
        }
        Summary            = @{
            TotalEvents    = 0
            Critical       = 0
            Error          = 0
            Warning        = 0
            Information    = 0
        }
        EventsByLog        = @{}
        EventsBySource     = @{}
        EventsByHour       = @{}
        TopEventIds        = @()
        TopSources         = @()
        AllEvents          = @()
        SecurityAnalysis   = $null
        FailedLogons       = @()
        SystemIssues       = $null
        ApplicationIssues  = $null
        Alerts             = @()
    }

    $startTime = (Get-Date).AddHours(-$Hours)

    # Determine level filter
    $levelValues = switch ($Level) {
        'Critical'    { @(1) }
        'Error'       { @(1, 2) }
        'Warning'     { @(1, 2, 3) }
        'Information' { @(1, 2, 3, 4) }
        'All'         { @() }
    }

    # Collect events from each log
    foreach ($logName in $LogNames) {
        # Skip Security log if not admin and not explicitly requested
        if ($logName -eq 'Security' -and -not $script:IsAdmin) {
            if (-not $IncludeSecurityAnalysis) {
                Write-WarningMessage "Skipping Security log (requires administrator privileges)"
                continue
            }
        }

        Write-InfoMessage "Analyzing $logName log..."
        $events = Get-FilteredEvents -LogName $logName -StartTime $startTime -MaxEvents $MaxEvents -LevelValues $levelValues

        $report.AllEvents += $events
        $report.EventsByLog[$logName] = $events.Count

        Write-InfoMessage "  Found $($events.Count) events in $logName"
    }

    # Calculate summary
    $report.Summary.TotalEvents = $report.AllEvents.Count
    $report.Summary.Critical = ($report.AllEvents | Where-Object { $_.Level -eq 'Critical' }).Count
    $report.Summary.Error = ($report.AllEvents | Where-Object { $_.Level -eq 'Error' }).Count
    $report.Summary.Warning = ($report.AllEvents | Where-Object { $_.Level -eq 'Warning' }).Count
    $report.Summary.Information = ($report.AllEvents | Where-Object { $_.Level -eq 'Information' }).Count

    # Group by source
    $sourceGroups = $report.AllEvents | Group-Object -Property Source | Sort-Object -Property Count -Descending
    foreach ($group in $sourceGroups) {
        $report.EventsBySource[$group.Name] = $group.Count
    }
    $report.TopSources = $sourceGroups | Select-Object -First 10 | ForEach-Object {
        @{ Source = $_.Name; Count = $_.Count }
    }

    # Group by event ID
    $eventIdGroups = $report.AllEvents | Group-Object -Property EventId | Sort-Object -Property Count -Descending
    $report.TopEventIds = $eventIdGroups | Select-Object -First 15 | ForEach-Object {
        $sampleEvent = $_.Group | Select-Object -First 1
        @{
            EventId = $_.Name
            Count   = $_.Count
            Source  = $sampleEvent.Source
            Level   = $sampleEvent.Level
        }
    }

    # Group by hour
    $hourGroups = $report.AllEvents | Group-Object -Property { $_.TimeCreated.ToString('yyyy-MM-dd HH:00') }
    foreach ($group in $hourGroups) {
        $report.EventsByHour[$group.Name] = $group.Count
    }

    # Security analysis
    if ($IncludeSecurityAnalysis -and $script:IsAdmin) {
        Write-InfoMessage "Performing security analysis..."
        $report.SecurityAnalysis = Get-SecurityAnalysis -Events $report.AllEvents
    }

    # Failed logon details
    if ($IncludeFailedLogons -and $script:IsAdmin) {
        Write-InfoMessage "Analyzing failed logon attempts..."
        $report.FailedLogons = Get-FailedLogonDetails -Events $report.AllEvents
    }

    # System issues
    Write-InfoMessage "Analyzing system issues..."
    $report.SystemIssues = Get-SystemIssues -Events $report.AllEvents

    # Application issues
    Write-InfoMessage "Analyzing application issues..."
    $report.ApplicationIssues = Get-ApplicationIssues -Events $report.AllEvents

    # Generate alerts
    if ($report.Summary.Critical -gt 0) {
        $report.Alerts += @{
            Level   = 'Critical'
            Type    = 'CriticalEvents'
            Message = "$($report.Summary.Critical) critical events detected in the last $Hours hours"
        }
    }

    if ($report.SystemIssues.UnexpectedShutdowns.Count -gt 0) {
        $report.Alerts += @{
            Level   = 'Critical'
            Type    = 'UnexpectedShutdown'
            Message = "$($report.SystemIssues.UnexpectedShutdowns.Count) unexpected shutdown(s) detected"
        }
    }

    if ($report.SystemIssues.ServiceFailures.Count -gt 0) {
        $report.Alerts += @{
            Level   = 'Warning'
            Type    = 'ServiceFailure'
            Message = "$($report.SystemIssues.ServiceFailures.Count) service failure(s) detected"
        }
    }

    if ($report.ApplicationIssues.Crashes.Count -gt 0) {
        $report.Alerts += @{
            Level   = 'Warning'
            Type    = 'AppCrash'
            Message = "$($report.ApplicationIssues.Crashes.Count) application crash(es) detected"
        }
    }

    if ($report.SecurityAnalysis -and $report.SecurityAnalysis.LogCleared.Count -gt 0) {
        $report.Alerts += @{
            Level   = 'Critical'
            Type    = 'LogCleared'
            Message = "Event log was cleared $($report.SecurityAnalysis.LogCleared.Count) time(s) - potential security incident"
        }
    }

    if ($report.FailedLogons.Count -ge 10) {
        $report.Alerts += @{
            Level   = 'Warning'
            Type    = 'FailedLogons'
            Message = "$($report.FailedLogons.Count) failed logon attempts detected"
        }
    }

    return $report
}

function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Outputs event log analysis to console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report
    )

    $separator = "=" * 70

    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  EVENT LOG ANALYSIS REPORT" -ForegroundColor Cyan
    Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "  Period: Last $($Report.AnalysisPeriod.Hours) hours" -ForegroundColor Cyan
    Write-Host "$separator`n" -ForegroundColor Cyan

    # Summary
    Write-Host "SUMMARY" -ForegroundColor White
    Write-Host "-" * 50
    Write-Host "  Total Events:  $($Report.Summary.TotalEvents)"
    Write-Host "  Critical:      " -NoNewline
    if ($Report.Summary.Critical -gt 0) {
        Write-Host "$($Report.Summary.Critical)" -ForegroundColor Red
    }
    else {
        Write-Host "$($Report.Summary.Critical)" -ForegroundColor Green
    }
    Write-Host "  Error:         " -NoNewline
    if ($Report.Summary.Error -gt 0) {
        Write-Host "$($Report.Summary.Error)" -ForegroundColor Red
    }
    else {
        Write-Host "$($Report.Summary.Error)" -ForegroundColor Green
    }
    Write-Host "  Warning:       " -NoNewline
    if ($Report.Summary.Warning -gt 0) {
        Write-Host "$($Report.Summary.Warning)" -ForegroundColor Yellow
    }
    else {
        Write-Host "$($Report.Summary.Warning)"
    }
    Write-Host "  Information:   $($Report.Summary.Information)`n"

    # Events by Log
    Write-Host "EVENTS BY LOG" -ForegroundColor White
    Write-Host "-" * 50
    foreach ($log in $Report.EventsByLog.Keys) {
        Write-Host "  $($log.PadRight(20)) $($Report.EventsByLog[$log])"
    }
    Write-Host ""

    # Top Sources
    Write-Host "TOP EVENT SOURCES" -ForegroundColor White
    Write-Host "-" * 50
    foreach ($source in $Report.TopSources | Select-Object -First 10) {
        Write-Host "  $($source.Source.PadRight(35)) $($source.Count)"
    }
    Write-Host ""

    # Top Event IDs
    Write-Host "TOP EVENT IDs" -ForegroundColor White
    Write-Host "-" * 50
    foreach ($eventId in $Report.TopEventIds | Select-Object -First 10) {
        $levelColor = switch ($eventId.Level) {
            'Critical' { 'Red' }
            'Error'    { 'Red' }
            'Warning'  { 'Yellow' }
            default    { 'White' }
        }
        Write-Host "  ID $($eventId.EventId.ToString().PadRight(8))" -NoNewline
        Write-Host " [$($eventId.Level.PadRight(11))]" -ForegroundColor $levelColor -NoNewline
        Write-Host " $($eventId.Count.ToString().PadLeft(5)) - $($eventId.Source)"
    }
    Write-Host ""

    # System Issues
    if ($Report.SystemIssues) {
        Write-Host "SYSTEM ISSUES" -ForegroundColor White
        Write-Host "-" * 50
        Write-Host "  Service Failures:     $($Report.SystemIssues.ServiceFailures.Count)"
        Write-Host "  Unexpected Shutdowns: $($Report.SystemIssues.UnexpectedShutdowns.Count)"
        Write-Host "  Disk Errors:          $($Report.SystemIssues.DiskErrors.Count)"
        Write-Host "  Driver Issues:        $($Report.SystemIssues.DriverIssues.Count)"
        Write-Host "  Kernel Errors:        $($Report.SystemIssues.KernelErrors.Count)`n"
    }

    # Application Issues
    if ($Report.ApplicationIssues) {
        Write-Host "APPLICATION ISSUES" -ForegroundColor White
        Write-Host "-" * 50
        Write-Host "  Crashes:       $($Report.ApplicationIssues.Crashes.Count)"
        Write-Host "  Hangs:         $($Report.ApplicationIssues.Hangs.Count)"
        Write-Host "  .NET Errors:   $($Report.ApplicationIssues.DotNetErrors.Count)"
        Write-Host "  SxS Errors:    $($Report.ApplicationIssues.SideBySide.Count)`n"
    }

    # Failed Logons
    if ($Report.FailedLogons.Count -gt 0) {
        Write-Host "FAILED LOGON ATTEMPTS" -ForegroundColor White
        Write-Host "-" * 50

        # Group by account
        $accountGroups = $Report.FailedLogons | Group-Object -Property TargetAccount | Sort-Object -Property Count -Descending
        foreach ($group in ($accountGroups | Select-Object -First 5)) {
            Write-Host "  $($group.Name): $($group.Count) attempts" -ForegroundColor Yellow
        }

        # Group by source IP
        $ipGroups = $Report.FailedLogons | Where-Object { $_.SourceIP -and $_.SourceIP -ne '-' } |
            Group-Object -Property SourceIP | Sort-Object -Property Count -Descending
        if ($ipGroups.Count -gt 0) {
            Write-Host "`n  Top Source IPs:" -ForegroundColor Cyan
            foreach ($group in ($ipGroups | Select-Object -First 5)) {
                Write-Host "    $($group.Name): $($group.Count) attempts"
            }
        }
        Write-Host ""
    }

    # Security Analysis
    if ($Report.SecurityAnalysis) {
        Write-Host "SECURITY ANALYSIS" -ForegroundColor White
        Write-Host "-" * 50
        Write-Host "  Privilege Escalation Events: $($Report.SecurityAnalysis.PrivilegeEscalation.Count)"
        Write-Host "  Account Changes:             $($Report.SecurityAnalysis.AccountChanges.Count)"
        Write-Host "  Policy Changes:              $($Report.SecurityAnalysis.PolicyChanges.Count)"
        Write-Host "  Log Cleared Events:          $($Report.SecurityAnalysis.LogCleared.Count)"
        Write-Host "  Service Changes:             $($Report.SecurityAnalysis.ServiceChanges.Count)"

        if ($Report.SecurityAnalysis.SuspiciousActivity.Count -gt 0) {
            Write-Host "`n  [!] Suspicious Activity Detected:" -ForegroundColor Red
            foreach ($activity in $Report.SecurityAnalysis.SuspiciousActivity) {
                Write-Host "      - $($activity.Description)" -ForegroundColor Red
            }
        }
        Write-Host ""
    }

    # Alerts
    if ($Report.Alerts.Count -gt 0) {
        Write-Host "ALERTS" -ForegroundColor White
        Write-Host "-" * 50
        foreach ($alert in $Report.Alerts) {
            $alertColor = switch ($alert.Level) {
                'Critical' { 'Red' }
                'Warning'  { 'Yellow' }
                'Info'     { 'Cyan' }
                default    { 'White' }
            }
            $alertIcon = switch ($alert.Level) {
                'Critical' { '[-]' }
                'Warning'  { '[!]' }
                'Info'     { '[i]' }
                default    { '[*]' }
            }
            Write-Host "  $alertIcon $($alert.Message)" -ForegroundColor $alertColor
        }
        Write-Host ""
    }
    else {
        Write-Host "[+] No critical issues detected`n" -ForegroundColor Green
    }

    Write-Host $separator -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML event log analysis report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $htmlPath = Join-Path $Path "eventlog-analysis_$timestamp.html"

    # Build alerts HTML
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

    # Build top events HTML
    $topEventsHtml = ""
    foreach ($eventId in $Report.TopEventIds) {
        $levelClass = switch ($eventId.Level) {
            'Critical' { 'critical' }
            'Error'    { 'error' }
            'Warning'  { 'warning' }
            default    { '' }
        }
        $topEventsHtml += "<tr class='$levelClass'><td>$($eventId.EventId)</td><td>$($eventId.Level)</td><td>$($eventId.Count)</td><td>$($eventId.Source)</td></tr>"
    }

    # Build recent critical events HTML
    $criticalEventsHtml = ""
    $criticalEvents = $Report.AllEvents | Where-Object { $_.Level -in @('Critical', 'Error') } | Select-Object -First 20
    foreach ($event in $criticalEvents) {
        $levelClass = if ($event.Level -eq 'Critical') { 'critical' } else { 'error' }
        $messagePreview = if ($event.Message.Length -gt 100) { $event.Message.Substring(0, 100) + '...' } else { $event.Message }
        $criticalEventsHtml += "<tr class='$levelClass'><td>$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$($event.Source)</td><td>$($event.EventId)</td><td>$($event.Level)</td><td title='$([System.Web.HttpUtility]::HtmlEncode($event.Message))'>$([System.Web.HttpUtility]::HtmlEncode($messagePreview))</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Event Log Analysis - $($Report.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 20px; }
        .summary { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .summary-card { padding: 15px 20px; border-radius: 4px; text-align: center; min-width: 120px; }
        .summary-card.total { background: #deecf9; border-left: 4px solid #0078d4; }
        .summary-card.critical { background: #fde7e9; border-left: 4px solid #d13438; }
        .summary-card.error { background: #fde7e9; border-left: 4px solid #d13438; }
        .summary-card.warning { background: #fff4e5; border-left: 4px solid #ff8c00; }
        .summary-card.info { background: #dff6dd; border-left: 4px solid #107c10; }
        .summary-value { font-size: 24px; font-weight: bold; }
        .summary-label { color: #666; font-size: 11px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; font-size: 13px; }
        th { background: #f0f0f0; font-weight: 600; }
        tr.critical { background: #fde7e9; }
        tr.error { background: #fce4e4; }
        tr.warning { background: #fff4e5; }
        .alerts ul { list-style: none; padding: 0; }
        .alerts li { padding: 10px; margin: 5px 0; border-radius: 4px; }
        .alerts li.critical { background: #fde7e9; color: #d13438; }
        .alerts li.warning { background: #fff4e5; color: #ff8c00; }
        .alerts li.info { background: #deecf9; color: #0078d4; }
        .section { margin: 20px 0; }
        .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Event Log Analysis Report</h1>
        <p><strong>Computer:</strong> $($Report.ComputerName) | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Period:</strong> Last $($Report.AnalysisPeriod.Hours) hours</p>

        <div class="summary">
            <div class="summary-card total">
                <div class="summary-value">$($Report.Summary.TotalEvents)</div>
                <div class="summary-label">Total Events</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-value">$($Report.Summary.Critical)</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card error">
                <div class="summary-value">$($Report.Summary.Error)</div>
                <div class="summary-label">Error</div>
            </div>
            <div class="summary-card warning">
                <div class="summary-value">$($Report.Summary.Warning)</div>
                <div class="summary-label">Warning</div>
            </div>
            <div class="summary-card info">
                <div class="summary-value">$($Report.Summary.Information)</div>
                <div class="summary-label">Information</div>
            </div>
        </div>

        $alertsHtml

        <div class="section">
            <h2>Top Event IDs</h2>
            <table>
                <tr><th>Event ID</th><th>Level</th><th>Count</th><th>Source</th></tr>
                $topEventsHtml
            </table>
        </div>

        $(if ($criticalEventsHtml) { @"
        <div class="section">
            <h2>Recent Critical/Error Events</h2>
            <table>
                <tr><th>Time</th><th>Source</th><th>Event ID</th><th>Level</th><th>Message</th></tr>
                $criticalEventsHtml
            </table>
        </div>
"@ })

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
        Exports event log analysis to JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $jsonPath = Join-Path $Path "eventlog-analysis_$timestamp.json"

    # Create a cleaner export (without full event messages for size)
    $exportReport = @{
        Timestamp         = $Report.Timestamp
        ComputerName      = $Report.ComputerName
        AnalysisPeriod    = $Report.AnalysisPeriod
        Summary           = $Report.Summary
        EventsByLog       = $Report.EventsByLog
        TopEventIds       = $Report.TopEventIds
        TopSources        = $Report.TopSources
        EventsByHour      = $Report.EventsByHour
        Alerts            = $Report.Alerts
        SystemIssues      = @{
            ServiceFailures     = $Report.SystemIssues.ServiceFailures.Count
            UnexpectedShutdowns = $Report.SystemIssues.UnexpectedShutdowns.Count
            DiskErrors          = $Report.SystemIssues.DiskErrors.Count
            DriverIssues        = $Report.SystemIssues.DriverIssues.Count
            KernelErrors        = $Report.SystemIssues.KernelErrors.Count
        }
        ApplicationIssues = @{
            Crashes      = $Report.ApplicationIssues.Crashes.Count
            Hangs        = $Report.ApplicationIssues.Hangs.Count
            DotNetErrors = $Report.ApplicationIssues.DotNetErrors.Count
            SideBySide   = $Report.ApplicationIssues.SideBySide.Count
        }
        FailedLogonCount  = $Report.FailedLogons.Count
    }

    if ($Report.SecurityAnalysis) {
        $exportReport.SecurityAnalysis = @{
            FailedLogons        = $Report.SecurityAnalysis.FailedLogons.Count
            PrivilegeEscalation = $Report.SecurityAnalysis.PrivilegeEscalation.Count
            AccountChanges      = $Report.SecurityAnalysis.AccountChanges.Count
            PolicyChanges       = $Report.SecurityAnalysis.PolicyChanges.Count
            LogCleared          = $Report.SecurityAnalysis.LogCleared.Count
            ServiceChanges      = $Report.SecurityAnalysis.ServiceChanges.Count
            SuspiciousActivity  = $Report.SecurityAnalysis.SuspiciousActivity.Count
        }
    }

    $exportReport | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
    return $jsonPath
}

function Export-CSVReport {
    <#
    .SYNOPSIS
        Exports events to CSV format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $csvPath = Join-Path $Path "eventlog-events_$timestamp.csv"

    $csvData = $Report.AllEvents | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated  = $_.TimeCreated
            LogName      = $_.LogName
            Source       = $_.Source
            EventId      = $_.EventId
            Level        = $_.Level
            TaskCategory = $_.TaskCategory
            Message      = ($_.Message -replace "`r`n", " " -replace "`n", " ").Substring(0, [Math]::Min(500, $_.Message.Length))
        }
    }

    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Success "CSV report saved: $csvPath"
    return $csvPath
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== Event Log Analyzer v$script:ScriptVersion ==="
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-InfoMessage "Analyzing last $Hours hours"

    if ($script:IsAdmin) {
        Write-Success "Running with administrator privileges"
    }
    else {
        Write-WarningMessage "Running without administrator privileges - Security log access limited"
    }

    # Generate report
    $report = Get-EventLogReport

    # Output based on format
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Report $report }
        'HTML'    { Export-HTMLReport -Report $report -Path $OutputPath }
        'JSON'    { Export-JSONReport -Report $report -Path $OutputPath }
        'CSV'     { Export-CSVReport -Report $report -Path $OutputPath }
        'All' {
            Write-ConsoleReport -Report $report
            Export-HTMLReport -Report $report -Path $OutputPath
            Export-JSONReport -Report $report -Path $OutputPath
            Export-CSVReport -Report $report -Path $OutputPath
        }
    }

    $duration = (Get-Date) - $script:StartTime
    Write-Success "=== Event log analysis completed in $($duration.TotalSeconds.ToString('0.00'))s ==="

    # Return exit code based on critical events
    if ($report.Summary.Critical -gt 0) {
        exit 1
    }
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    exit 1
}
#endregion
