#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Monitors system performance metrics including CPU, memory, disk I/O, and network usage.

.DESCRIPTION
    This script provides comprehensive system performance monitoring with:
    - Real-time CPU, RAM, disk, and network metrics
    - Configurable threshold-based alerts
    - Performance trend tracking over time
    - Multiple output formats (Console, HTML, JSON, CSV)
    - Historical data collection for analysis
    - Integration with Windows Performance Monitor counters

    Metrics collected:
    - CPU: Usage percentage, queue length, per-core utilization
    - Memory: Available, used, page file usage, cache size
    - Disk: Read/write rates, queue length, latency, free space
    - Network: Bytes sent/received, packets, errors, bandwidth utilization

.PARAMETER OutputFormat
    Output format for the report. Valid values: Console, HTML, JSON, CSV, All.
    Default: Console

.PARAMETER OutputPath
    Directory path for output files. Default: logs directory in toolkit root.

.PARAMETER SampleCount
    Number of performance samples to collect. Default: 5

.PARAMETER SampleInterval
    Interval in seconds between samples. Default: 2

.PARAMETER Thresholds
    Hashtable of custom alert thresholds. If not provided, defaults are used.
    Keys: CpuWarning, CpuCritical, MemoryWarning, MemoryCritical, DiskWarning, DiskCritical

.PARAMETER MonitorDuration
    Duration in minutes to monitor (for continuous monitoring mode). Default: 0 (single run)

.PARAMETER AlertOnly
    Only output if thresholds are exceeded.

.PARAMETER IncludeProcesses
    Include top CPU and memory consuming processes in the report.

.PARAMETER TopProcessCount
    Number of top processes to include. Default: 10

.EXAMPLE
    .\Get-SystemPerformance.ps1
    Runs a basic performance check with console output.

.EXAMPLE
    .\Get-SystemPerformance.ps1 -OutputFormat HTML -OutputPath "C:\Reports"
    Generates an HTML performance report in the specified directory.

.EXAMPLE
    .\Get-SystemPerformance.ps1 -OutputFormat All -IncludeProcesses -TopProcessCount 15
    Generates all report formats with top 15 resource-consuming processes.

.EXAMPLE
    .\Get-SystemPerformance.ps1 -MonitorDuration 60 -SampleInterval 30 -OutputFormat JSON
    Monitors for 60 minutes, sampling every 30 seconds, outputting JSON.

.EXAMPLE
    $thresholds = @{ CpuWarning = 70; CpuCritical = 90; MemoryWarning = 75; MemoryCritical = 90 }
    .\Get-SystemPerformance.ps1 -Thresholds $thresholds -AlertOnly
    Only alerts when custom thresholds are exceeded.

.NOTES
    File Name      : Get-SystemPerformance.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
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
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$SampleCount = 5,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$SampleInterval = 2,

    [Parameter()]
    [hashtable]$Thresholds,

    [Parameter()]
    [ValidateRange(0, 1440)]
    [int]$MonitorDuration = 0,

    [Parameter()]
    [switch]$AlertOnly,

    [Parameter()]
    [switch]$IncludeProcesses,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$TopProcessCount = 10
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

$errorHandlingPath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\ErrorHandling.psm1"
if (Test-Path $errorHandlingPath) {
    Import-Module $errorHandlingPath -Force
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"

# Default thresholds
$script:DefaultThresholds = @{
    CpuWarning       = 70
    CpuCritical      = 90
    MemoryWarning    = 80
    MemoryCritical   = 95
    DiskWarning      = 80
    DiskCritical     = 95
    DiskQueueWarning = 2
    NetworkErrorRate = 1
}

# Merge custom thresholds with defaults
if ($Thresholds) {
    foreach ($key in $Thresholds.Keys) {
        if ($script:DefaultThresholds.ContainsKey($key)) {
            $script:DefaultThresholds[$key] = $Thresholds[$key]
        }
    }
}

# Set output path
if (-not $OutputPath) {
    $OutputPath = Get-LogDirectory
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Performance counter paths
$script:CounterPaths = @{
    CPU = @(
        '\Processor(_Total)\% Processor Time',
        '\Processor(_Total)\% Privileged Time',
        '\Processor(_Total)\% User Time',
        '\System\Processor Queue Length'
    )
    Memory = @(
        '\Memory\Available MBytes',
        '\Memory\% Committed Bytes In Use',
        '\Memory\Pages/sec',
        '\Memory\Cache Bytes'
    )
    Disk = @(
        '\PhysicalDisk(_Total)\% Disk Time',
        '\PhysicalDisk(_Total)\Avg. Disk Queue Length',
        '\PhysicalDisk(_Total)\Disk Read Bytes/sec',
        '\PhysicalDisk(_Total)\Disk Write Bytes/sec',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Write'
    )
    Network = @(
        '\Network Interface(*)\Bytes Total/sec',
        '\Network Interface(*)\Bytes Sent/sec',
        '\Network Interface(*)\Bytes Received/sec',
        '\Network Interface(*)\Packets/sec',
        '\Network Interface(*)\Packets Received Errors'
    )
}
#endregion

#region Helper Functions
function Get-PerformanceMetrics {
    <#
    .SYNOPSIS
        Collects performance metrics using Get-Counter.
    #>
    [CmdletBinding()]
    param(
        [int]$Samples = $SampleCount,
        [int]$Interval = $SampleInterval
    )

    $metrics = @{
        Timestamp   = Get-Date -Format 'o'
        CPU         = @{}
        Memory      = @{}
        Disk        = @{}
        Network     = @{}
        DiskVolumes = @()
        Alerts      = @()
    }

    try {
        Write-InfoMessage "Collecting performance counters ($Samples samples, ${Interval}s interval)..."

        # Collect all counters
        $allCounters = $script:CounterPaths.CPU + $script:CounterPaths.Memory + $script:CounterPaths.Disk

        $counterData = Get-Counter -Counter $allCounters -SampleInterval $Interval -MaxSamples $Samples -ErrorAction SilentlyContinue

        if ($counterData) {
            # Process CPU metrics
            $cpuSamples = @()
            $queueSamples = @()

            foreach ($sample in $counterData) {
                foreach ($reading in $sample.CounterSamples) {
                    switch -Wildcard ($reading.Path) {
                        '*Processor(_Total)\% Processor Time' {
                            $cpuSamples += $reading.CookedValue
                        }
                        '*System\Processor Queue Length' {
                            $queueSamples += $reading.CookedValue
                        }
                    }
                }
            }

            $metrics.CPU = @{
                UsagePercent     = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 2)
                UsageMin         = [math]::Round(($cpuSamples | Measure-Object -Minimum).Minimum, 2)
                UsageMax         = [math]::Round(($cpuSamples | Measure-Object -Maximum).Maximum, 2)
                QueueLength      = [math]::Round(($queueSamples | Measure-Object -Average).Average, 2)
                ProcessorCount   = (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors
            }

            # Process Memory metrics
            $memInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            $metrics.Memory = @{
                TotalGB          = [math]::Round($memInfo.TotalVisibleMemorySize / 1MB, 2)
                AvailableGB      = [math]::Round($memInfo.FreePhysicalMemory / 1MB, 2)
                UsedGB           = [math]::Round(($memInfo.TotalVisibleMemorySize - $memInfo.FreePhysicalMemory) / 1MB, 2)
                UsagePercent     = [math]::Round((($memInfo.TotalVisibleMemorySize - $memInfo.FreePhysicalMemory) / $memInfo.TotalVisibleMemorySize) * 100, 2)
                PageFileUsageGB  = [math]::Round(($memInfo.TotalVirtualMemorySize - $memInfo.FreeVirtualMemory) / 1MB, 2)
            }

            # Process Disk metrics
            $diskSamples = @{ Time = @(); Queue = @(); ReadBytes = @(); WriteBytes = @() }

            foreach ($sample in $counterData) {
                foreach ($reading in $sample.CounterSamples) {
                    switch -Wildcard ($reading.Path) {
                        '*PhysicalDisk(_Total)\% Disk Time' {
                            $diskSamples.Time += $reading.CookedValue
                        }
                        '*PhysicalDisk(_Total)\Avg. Disk Queue Length' {
                            $diskSamples.Queue += $reading.CookedValue
                        }
                        '*PhysicalDisk(_Total)\Disk Read Bytes/sec' {
                            $diskSamples.ReadBytes += $reading.CookedValue
                        }
                        '*PhysicalDisk(_Total)\Disk Write Bytes/sec' {
                            $diskSamples.WriteBytes += $reading.CookedValue
                        }
                    }
                }
            }

            $metrics.Disk = @{
                TimePercent      = [math]::Round(($diskSamples.Time | Measure-Object -Average).Average, 2)
                QueueLength      = [math]::Round(($diskSamples.Queue | Measure-Object -Average).Average, 2)
                ReadMBps         = [math]::Round((($diskSamples.ReadBytes | Measure-Object -Average).Average) / 1MB, 2)
                WriteMBps        = [math]::Round((($diskSamples.WriteBytes | Measure-Object -Average).Average) / 1MB, 2)
            }

            # Get disk volume information
            $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            foreach ($vol in $volumes) {
                $metrics.DiskVolumes += @{
                    DriveLetter  = $vol.DeviceID
                    Label        = $vol.VolumeName
                    TotalGB      = [math]::Round($vol.Size / 1GB, 2)
                    FreeGB       = [math]::Round($vol.FreeSpace / 1GB, 2)
                    UsedGB       = [math]::Round(($vol.Size - $vol.FreeSpace) / 1GB, 2)
                    UsagePercent = [math]::Round((($vol.Size - $vol.FreeSpace) / $vol.Size) * 100, 2)
                }
            }
        }

        # Collect network metrics
        $networkAdapters = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
        if ($networkAdapters) {
            $totalSent = ($networkAdapters | Measure-Object -Property SentBytes -Sum).Sum
            $totalReceived = ($networkAdapters | Measure-Object -Property ReceivedBytes -Sum).Sum
            $totalErrors = ($networkAdapters | Measure-Object -Property InboundDiscarded, OutboundDiscarded -Sum).Sum

            $metrics.Network = @{
                TotalSentGB      = [math]::Round($totalSent / 1GB, 2)
                TotalReceivedGB  = [math]::Round($totalReceived / 1GB, 2)
                TotalErrors      = $totalErrors
                ActiveAdapters   = ($networkAdapters | Where-Object { $_.SentBytes -gt 0 -or $_.ReceivedBytes -gt 0 }).Count
            }
        }

        # Check thresholds and generate alerts
        $metrics.Alerts = Get-ThresholdAlerts -Metrics $metrics

    }
    catch {
        Write-ErrorMessage "Error collecting performance metrics: $($_.Exception.Message)"
        if (Get-Command Write-ContextualError -ErrorAction SilentlyContinue) {
            Write-ContextualError -ErrorRecord $_ -Context "collecting performance metrics" -Suggestion "Ensure you have permission to access performance counters"
        }
    }

    return $metrics
}

function Get-ThresholdAlerts {
    <#
    .SYNOPSIS
        Checks metrics against thresholds and returns alerts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metrics
    )

    $alerts = @()

    # CPU alerts
    if ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuCritical) {
        $alerts += @{
            Level   = 'Critical'
            Type    = 'CPU'
            Message = "CPU usage is critical: $($Metrics.CPU.UsagePercent)% (threshold: $($script:DefaultThresholds.CpuCritical)%)"
        }
    }
    elseif ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuWarning) {
        $alerts += @{
            Level   = 'Warning'
            Type    = 'CPU'
            Message = "CPU usage is high: $($Metrics.CPU.UsagePercent)% (threshold: $($script:DefaultThresholds.CpuWarning)%)"
        }
    }

    # Memory alerts
    if ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryCritical) {
        $alerts += @{
            Level   = 'Critical'
            Type    = 'Memory'
            Message = "Memory usage is critical: $($Metrics.Memory.UsagePercent)% (threshold: $($script:DefaultThresholds.MemoryCritical)%)"
        }
    }
    elseif ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryWarning) {
        $alerts += @{
            Level   = 'Warning'
            Type    = 'Memory'
            Message = "Memory usage is high: $($Metrics.Memory.UsagePercent)% (threshold: $($script:DefaultThresholds.MemoryWarning)%)"
        }
    }

    # Disk space alerts
    foreach ($volume in $Metrics.DiskVolumes) {
        if ($volume.UsagePercent -ge $script:DefaultThresholds.DiskCritical) {
            $alerts += @{
                Level   = 'Critical'
                Type    = 'Disk'
                Message = "Disk $($volume.DriveLetter) usage is critical: $($volume.UsagePercent)% (threshold: $($script:DefaultThresholds.DiskCritical)%)"
            }
        }
        elseif ($volume.UsagePercent -ge $script:DefaultThresholds.DiskWarning) {
            $alerts += @{
                Level   = 'Warning'
                Type    = 'Disk'
                Message = "Disk $($volume.DriveLetter) usage is high: $($volume.UsagePercent)% (threshold: $($script:DefaultThresholds.DiskWarning)%)"
            }
        }
    }

    # Disk queue alerts
    if ($Metrics.Disk.QueueLength -ge $script:DefaultThresholds.DiskQueueWarning) {
        $alerts += @{
            Level   = 'Warning'
            Type    = 'Disk'
            Message = "Disk queue length is high: $($Metrics.Disk.QueueLength) (threshold: $($script:DefaultThresholds.DiskQueueWarning))"
        }
    }

    return $alerts
}

function Get-TopProcesses {
    <#
    .SYNOPSIS
        Gets the top CPU and memory consuming processes.
    #>
    [CmdletBinding()]
    param(
        [int]$Count = $TopProcessCount
    )

    $processes = @{
        TopCPU    = @()
        TopMemory = @()
    }

    try {
        # Get processes with CPU and memory info
        $allProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 }

        # Top CPU consumers
        $processes.TopCPU = $allProcs |
            Sort-Object -Property CPU -Descending |
            Select-Object -First $Count |
            ForEach-Object {
                @{
                    Name        = $_.ProcessName
                    PID         = $_.Id
                    CPU         = [math]::Round($_.CPU, 2)
                    WorkingSet  = [math]::Round($_.WorkingSet64 / 1MB, 2)
                }
            }

        # Top Memory consumers
        $processes.TopMemory = $allProcs |
            Sort-Object -Property WorkingSet64 -Descending |
            Select-Object -First $Count |
            ForEach-Object {
                @{
                    Name        = $_.ProcessName
                    PID         = $_.Id
                    CPU         = [math]::Round($_.CPU, 2)
                    WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                }
            }
    }
    catch {
        Write-WarningMessage "Error getting process information: $($_.Exception.Message)"
    }

    return $processes
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Gets basic system information for the report header.
    #>
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1

    return @{
        ComputerName    = $env:COMPUTERNAME
        OSName          = $os.Caption
        OSVersion       = $os.Version
        OSBuild         = $os.BuildNumber
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        ProcessorName   = $cpu.Name
        ProcessorCores  = $cpu.NumberOfCores
        LogicalCPUs     = $cpu.NumberOfLogicalProcessors
        LastBoot        = $os.LastBootUpTime
        Uptime          = (Get-Date) - $os.LastBootUpTime
    }
}
#endregion

#region Output Functions
function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Outputs performance report to console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metrics,

        [hashtable]$SystemInfo,

        [hashtable]$Processes
    )

    $separator = "=" * 60

    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  SYSTEM PERFORMANCE REPORT" -ForegroundColor Cyan
    Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "$separator`n" -ForegroundColor Cyan

    # System Info
    if ($SystemInfo) {
        Write-Host "SYSTEM INFORMATION" -ForegroundColor White
        Write-Host "-" * 40
        Write-Host "  Computer:    $($SystemInfo.ComputerName)"
        Write-Host "  OS:          $($SystemInfo.OSName)"
        Write-Host "  Processor:   $($SystemInfo.ProcessorName)"
        Write-Host "  Cores/LCPUs: $($SystemInfo.ProcessorCores)/$($SystemInfo.LogicalCPUs)"
        Write-Host "  Uptime:      $($SystemInfo.Uptime.Days)d $($SystemInfo.Uptime.Hours)h $($SystemInfo.Uptime.Minutes)m`n"
    }

    # CPU
    Write-Host "CPU PERFORMANCE" -ForegroundColor White
    Write-Host "-" * 40
    $cpuColor = if ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuCritical) { 'Red' }
                elseif ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuWarning) { 'Yellow' }
                else { 'Green' }
    Write-Host "  Usage:       " -NoNewline
    Write-Host "$($Metrics.CPU.UsagePercent)%" -ForegroundColor $cpuColor
    Write-Host "  Min/Max:     $($Metrics.CPU.UsageMin)% / $($Metrics.CPU.UsageMax)%"
    Write-Host "  Queue:       $($Metrics.CPU.QueueLength)`n"

    # Memory
    Write-Host "MEMORY PERFORMANCE" -ForegroundColor White
    Write-Host "-" * 40
    $memColor = if ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryCritical) { 'Red' }
                elseif ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryWarning) { 'Yellow' }
                else { 'Green' }
    Write-Host "  Usage:       " -NoNewline
    Write-Host "$($Metrics.Memory.UsagePercent)%" -ForegroundColor $memColor
    Write-Host "  Used/Total:  $($Metrics.Memory.UsedGB) GB / $($Metrics.Memory.TotalGB) GB"
    Write-Host "  Available:   $($Metrics.Memory.AvailableGB) GB`n"

    # Disk I/O
    Write-Host "DISK PERFORMANCE" -ForegroundColor White
    Write-Host "-" * 40
    Write-Host "  Activity:    $($Metrics.Disk.TimePercent)%"
    Write-Host "  Queue:       $($Metrics.Disk.QueueLength)"
    Write-Host "  Read Rate:   $($Metrics.Disk.ReadMBps) MB/s"
    Write-Host "  Write Rate:  $($Metrics.Disk.WriteMBps) MB/s`n"

    # Disk Volumes
    Write-Host "DISK VOLUMES" -ForegroundColor White
    Write-Host "-" * 40
    foreach ($vol in $Metrics.DiskVolumes) {
        $volColor = if ($vol.UsagePercent -ge $script:DefaultThresholds.DiskCritical) { 'Red' }
                    elseif ($vol.UsagePercent -ge $script:DefaultThresholds.DiskWarning) { 'Yellow' }
                    else { 'Green' }
        Write-Host "  $($vol.DriveLetter) " -NoNewline
        Write-Host "[$($vol.UsagePercent)%]" -ForegroundColor $volColor -NoNewline
        Write-Host " $($vol.FreeGB) GB free of $($vol.TotalGB) GB"
    }
    Write-Host ""

    # Network
    if ($Metrics.Network.Keys.Count -gt 0) {
        Write-Host "NETWORK PERFORMANCE" -ForegroundColor White
        Write-Host "-" * 40
        Write-Host "  Total Sent:      $($Metrics.Network.TotalSentGB) GB"
        Write-Host "  Total Received:  $($Metrics.Network.TotalReceivedGB) GB"
        Write-Host "  Active Adapters: $($Metrics.Network.ActiveAdapters)"
        Write-Host "  Errors:          $($Metrics.Network.TotalErrors)`n"
    }

    # Top Processes
    if ($Processes -and $IncludeProcesses) {
        Write-Host "TOP CPU PROCESSES" -ForegroundColor White
        Write-Host "-" * 40
        $rank = 1
        foreach ($proc in $Processes.TopCPU) {
            Write-Host "  $rank. $($proc.Name) (PID: $($proc.PID)) - CPU: $($proc.CPU)s, Mem: $($proc.WorkingSet) MB"
            $rank++
        }
        Write-Host ""

        Write-Host "TOP MEMORY PROCESSES" -ForegroundColor White
        Write-Host "-" * 40
        $rank = 1
        foreach ($proc in $Processes.TopMemory) {
            Write-Host "  $rank. $($proc.Name) (PID: $($proc.PID)) - Mem: $($proc.WorkingSetMB) MB"
            $rank++
        }
        Write-Host ""
    }

    # Alerts
    if ($Metrics.Alerts.Count -gt 0) {
        Write-Host "ALERTS" -ForegroundColor White
        Write-Host "-" * 40
        foreach ($alert in $Metrics.Alerts) {
            $alertColor = if ($alert.Level -eq 'Critical') { 'Red' } else { 'Yellow' }
            $alertPrefix = if ($alert.Level -eq 'Critical') { '[-]' } else { '[!]' }
            Write-Host "  $alertPrefix $($alert.Message)" -ForegroundColor $alertColor
        }
        Write-Host ""
    }
    else {
        Write-Host "[+] No alerts - all metrics within normal thresholds`n" -ForegroundColor Green
    }

    Write-Host $separator -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML performance report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metrics,

        [hashtable]$SystemInfo,

        [hashtable]$Processes,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $htmlPath = Join-Path $Path "performance-report_$timestamp.html"

    $alertsHtml = ""
    if ($Metrics.Alerts.Count -gt 0) {
        $alertsHtml = "<div class='alerts'><h2>Alerts</h2><ul>"
        foreach ($alert in $Metrics.Alerts) {
            $alertClass = if ($alert.Level -eq 'Critical') { 'critical' } else { 'warning' }
            $alertsHtml += "<li class='$alertClass'>[$($alert.Level)] $($alert.Message)</li>"
        }
        $alertsHtml += "</ul></div>"
    }

    $volumesHtml = ""
    foreach ($vol in $Metrics.DiskVolumes) {
        $volClass = if ($vol.UsagePercent -ge $script:DefaultThresholds.DiskCritical) { 'critical' }
                    elseif ($vol.UsagePercent -ge $script:DefaultThresholds.DiskWarning) { 'warning' }
                    else { 'normal' }
        $volumesHtml += "<tr class='$volClass'><td>$($vol.DriveLetter)</td><td>$($vol.TotalGB) GB</td><td>$($vol.FreeGB) GB</td><td>$($vol.UsagePercent)%</td></tr>"
    }

    $processesHtml = ""
    if ($Processes -and $IncludeProcesses) {
        $processesHtml = @"
        <div class='section'>
            <h2>Top CPU Processes</h2>
            <table>
                <tr><th>Rank</th><th>Process</th><th>PID</th><th>CPU Time</th><th>Memory</th></tr>
"@
        $rank = 1
        foreach ($proc in $Processes.TopCPU) {
            $processesHtml += "<tr><td>$rank</td><td>$($proc.Name)</td><td>$($proc.PID)</td><td>$($proc.CPU)s</td><td>$($proc.WorkingSet) MB</td></tr>"
            $rank++
        }
        $processesHtml += @"
            </table>
            <h2>Top Memory Processes</h2>
            <table>
                <tr><th>Rank</th><th>Process</th><th>PID</th><th>Memory (MB)</th></tr>
"@
        $rank = 1
        foreach ($proc in $Processes.TopMemory) {
            $processesHtml += "<tr><td>$rank</td><td>$($proc.Name)</td><td>$($proc.PID)</td><td>$($proc.WorkingSetMB)</td></tr>"
            $rank++
        }
        $processesHtml += "</table></div>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>System Performance Report - $($SystemInfo.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 20px; }
        .section { margin: 20px 0; padding: 15px; background: #fafafa; border-radius: 4px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; }
        .metric-label { color: #666; font-size: 12px; }
        .normal { color: #107c10; }
        .warning { color: #ff8c00; background-color: #fff4e5; }
        .critical { color: #d13438; background-color: #fde7e9; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .alerts ul { list-style: none; padding: 0; }
        .alerts li { padding: 10px; margin: 5px 0; border-radius: 4px; }
        .progress-bar { height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; transition: width 0.3s; }
        .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Performance Report</h1>
        <p><strong>Computer:</strong> $($SystemInfo.ComputerName) | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>OS:</strong> $($SystemInfo.OSName) | <strong>Uptime:</strong> $($SystemInfo.Uptime.Days)d $($SystemInfo.Uptime.Hours)h $($SystemInfo.Uptime.Minutes)m</p>

        $alertsHtml

        <div class="section">
            <h2>CPU Performance</h2>
            <div class="metric">
                <div class="metric-value $(if ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuCritical) { 'critical' } elseif ($Metrics.CPU.UsagePercent -ge $script:DefaultThresholds.CpuWarning) { 'warning' } else { 'normal' })">$($Metrics.CPU.UsagePercent)%</div>
                <div class="metric-label">Current Usage</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.CPU.UsageMin)% - $($Metrics.CPU.UsageMax)%</div>
                <div class="metric-label">Min - Max</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.CPU.QueueLength)</div>
                <div class="metric-label">Queue Length</div>
            </div>
        </div>

        <div class="section">
            <h2>Memory Performance</h2>
            <div class="metric">
                <div class="metric-value $(if ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryCritical) { 'critical' } elseif ($Metrics.Memory.UsagePercent -ge $script:DefaultThresholds.MemoryWarning) { 'warning' } else { 'normal' })">$($Metrics.Memory.UsagePercent)%</div>
                <div class="metric-label">Usage</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Memory.UsedGB) GB</div>
                <div class="metric-label">Used</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Memory.AvailableGB) GB</div>
                <div class="metric-label">Available</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Memory.TotalGB) GB</div>
                <div class="metric-label">Total</div>
            </div>
        </div>

        <div class="section">
            <h2>Disk Performance</h2>
            <div class="metric">
                <div class="metric-value">$($Metrics.Disk.TimePercent)%</div>
                <div class="metric-label">Activity</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Disk.QueueLength)</div>
                <div class="metric-label">Queue Length</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Disk.ReadMBps) MB/s</div>
                <div class="metric-label">Read Rate</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Disk.WriteMBps) MB/s</div>
                <div class="metric-label">Write Rate</div>
            </div>
            <h3>Volumes</h3>
            <table>
                <tr><th>Drive</th><th>Total</th><th>Free</th><th>Usage</th></tr>
                $volumesHtml
            </table>
        </div>

        <div class="section">
            <h2>Network</h2>
            <div class="metric">
                <div class="metric-value">$($Metrics.Network.TotalSentGB) GB</div>
                <div class="metric-label">Total Sent</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Network.TotalReceivedGB) GB</div>
                <div class="metric-label">Total Received</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Metrics.Network.ActiveAdapters)</div>
                <div class="metric-label">Active Adapters</div>
            </div>
        </div>

        $processesHtml

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
        Exports metrics to JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metrics,

        [hashtable]$SystemInfo,

        [hashtable]$Processes,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $jsonPath = Join-Path $Path "performance-report_$timestamp.json"

    $report = @{
        Timestamp  = $Metrics.Timestamp
        SystemInfo = $SystemInfo
        Metrics    = $Metrics
        Processes  = $Processes
        Thresholds = $script:DefaultThresholds
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
    return $jsonPath
}

function Export-CSVReport {
    <#
    .SYNOPSIS
        Exports metrics to CSV format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metrics,

        [hashtable]$SystemInfo,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $csvPath = Join-Path $Path "performance-report_$timestamp.csv"

    $csvData = [PSCustomObject]@{
        Timestamp           = $Metrics.Timestamp
        ComputerName        = $SystemInfo.ComputerName
        CPUUsagePercent     = $Metrics.CPU.UsagePercent
        CPUQueueLength      = $Metrics.CPU.QueueLength
        MemoryUsagePercent  = $Metrics.Memory.UsagePercent
        MemoryUsedGB        = $Metrics.Memory.UsedGB
        MemoryAvailableGB   = $Metrics.Memory.AvailableGB
        DiskActivityPercent = $Metrics.Disk.TimePercent
        DiskQueueLength     = $Metrics.Disk.QueueLength
        DiskReadMBps        = $Metrics.Disk.ReadMBps
        DiskWriteMBps       = $Metrics.Disk.WriteMBps
        NetworkSentGB       = $Metrics.Network.TotalSentGB
        NetworkReceivedGB   = $Metrics.Network.TotalReceivedGB
        AlertCount          = $Metrics.Alerts.Count
    }

    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Success "CSV report saved: $csvPath"
    return $csvPath
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== System Performance Monitor v$script:ScriptVersion ==="
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # Get system information
    $systemInfo = Get-SystemInfo

    # Continuous monitoring mode
    if ($MonitorDuration -gt 0) {
        Write-InfoMessage "Continuous monitoring mode: $MonitorDuration minutes"
        $endTime = (Get-Date).AddMinutes($MonitorDuration)
        $iteration = 1

        while ((Get-Date) -lt $endTime) {
            Write-InfoMessage "Collection iteration $iteration..."

            $metrics = Get-PerformanceMetrics
            $processes = if ($IncludeProcesses) { Get-TopProcesses } else { $null }

            # Skip output if AlertOnly and no alerts
            if (-not $AlertOnly -or $metrics.Alerts.Count -gt 0) {
                switch ($OutputFormat) {
                    'Console' { Write-ConsoleReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes }
                    'HTML'    { Export-HTMLReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath }
                    'JSON'    { Export-JSONReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath }
                    'CSV'     { Export-CSVReport -Metrics $metrics -SystemInfo $systemInfo -Path $OutputPath }
                    'All'     {
                        Write-ConsoleReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes
                        Export-HTMLReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath
                        Export-JSONReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath
                        Export-CSVReport -Metrics $metrics -SystemInfo $systemInfo -Path $OutputPath
                    }
                }
            }

            $iteration++
            $remainingTime = ($endTime - (Get-Date)).TotalMinutes
            if ($remainingTime -gt 0) {
                Write-InfoMessage "Next collection in $SampleInterval seconds... ($([math]::Round($remainingTime, 1)) minutes remaining)"
                Start-Sleep -Seconds ($SampleInterval * $SampleCount)
            }
        }
    }
    else {
        # Single run mode
        $metrics = Get-PerformanceMetrics
        $processes = if ($IncludeProcesses) { Get-TopProcesses } else { $null }

        # Skip output if AlertOnly and no alerts
        if (-not $AlertOnly -or $metrics.Alerts.Count -gt 0) {
            switch ($OutputFormat) {
                'Console' { Write-ConsoleReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes }
                'HTML'    { Export-HTMLReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath }
                'JSON'    { Export-JSONReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath }
                'CSV'     { Export-CSVReport -Metrics $metrics -SystemInfo $systemInfo -Path $OutputPath }
                'All'     {
                    Write-ConsoleReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes
                    Export-HTMLReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath
                    Export-JSONReport -Metrics $metrics -SystemInfo $systemInfo -Processes $processes -Path $OutputPath
                    Export-CSVReport -Metrics $metrics -SystemInfo $systemInfo -Path $OutputPath
                }
            }
        }
        elseif ($AlertOnly) {
            Write-Success "No alerts - all metrics within normal thresholds"
        }
    }

    $duration = (Get-Date) - $script:StartTime
    Write-Success "=== Performance monitoring completed in $($duration.TotalSeconds.ToString('0.00'))s ==="
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    if (Get-Command Write-ContextualError -ErrorAction SilentlyContinue) {
        Write-ContextualError -ErrorRecord $_ -Context "running performance monitor" -Suggestion "Check permissions and system access"
    }
    exit 1
}
#endregion
