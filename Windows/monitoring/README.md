# Windows Monitoring Scripts

System health and performance monitoring tools for Windows workstations and servers.

## [*] Available Scripts

| Script | Purpose | Output Formats |
|--------|---------|----------------|
| [Get-SystemPerformance.ps1](Get-SystemPerformance.ps1) | CPU, RAM, disk, network metrics | Console, HTML, JSON, CSV |
| [Watch-ServiceHealth.ps1](Watch-ServiceHealth.ps1) | Service status monitoring | Console, alerts |
| [Test-NetworkHealth.ps1](Test-NetworkHealth.ps1) | Network connectivity checks | Console, HTML |
| [Get-EventLogAnalysis.ps1](Get-EventLogAnalysis.ps1) | Event log analysis and filtering | Console, HTML, CSV |
| [Get-ApplicationHealth.ps1](Get-ApplicationHealth.ps1) | Application health checks | Console, JSON |

---

## [+] Quick Start

```powershell
# Basic system performance check
.\Get-SystemPerformance.ps1

# Generate HTML report with top processes
.\Get-SystemPerformance.ps1 -OutputFormat HTML -IncludeProcesses

# Monitor services continuously
.\Watch-ServiceHealth.ps1 -MonitorDuration 60

# Check network connectivity
.\Test-NetworkHealth.ps1 -Targets "google.com", "github.com"

# Analyze recent errors in Event Log
.\Get-EventLogAnalysis.ps1 -LogName System -Level Error -Hours 24
```

---

## [*] Get-SystemPerformance.ps1

Comprehensive system performance monitoring with threshold-based alerts.

**Metrics Collected:**
- **CPU**: Usage percentage, queue length, per-core utilization
- **Memory**: Available, used, page file usage, cache size
- **Disk**: Read/write rates, queue length, latency, free space
- **Network**: Bytes sent/received, packets, errors, bandwidth

**Parameters:**
| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputFormat` | Console, HTML, JSON, CSV, All | Console |
| `-OutputPath` | Directory for output files | logs/ |
| `-SampleCount` | Number of samples to collect | 5 |
| `-SampleInterval` | Seconds between samples | 2 |
| `-MonitorDuration` | Minutes to monitor (0 = single run) | 0 |
| `-AlertOnly` | Only output if thresholds exceeded | false |
| `-IncludeProcesses` | Include top CPU/memory processes | false |
| `-TopProcessCount` | Number of top processes | 10 |

**Example - Continuous Monitoring:**
```powershell
.\Get-SystemPerformance.ps1 -MonitorDuration 30 -OutputFormat JSON -AlertOnly
```

---

## [*] Watch-ServiceHealth.ps1

Monitors Windows services and alerts on status changes.

**Features:**
- Watches specified services for status changes
- Automatic restart attempts for failed services
- Alert notifications (console, email, webhook)
- Service dependency tracking

**Example:**
```powershell
# Monitor critical services
.\Watch-ServiceHealth.ps1 -Services "ssh-agent", "W32Time", "Spooler"

# With automatic restart
.\Watch-ServiceHealth.ps1 -Services "MyService" -AutoRestart -MaxRestartAttempts 3
```

---

## [*] Test-NetworkHealth.ps1

Network connectivity and latency testing.

**Features:**
- Ping tests with latency statistics
- DNS resolution checks
- Port connectivity tests
- HTTP/HTTPS endpoint checks
- MTU path discovery

**Example:**
```powershell
# Full network health check
.\Test-NetworkHealth.ps1 -Targets "8.8.8.8", "github.com" -IncludeDNS -IncludePorts 80,443
```

---

## [*] Get-EventLogAnalysis.ps1

Windows Event Log analysis and filtering.

**Features:**
- Filter by log name, level, source, time range
- Pattern matching for specific events
- Export to multiple formats
- Trend analysis over time

**Example:**
```powershell
# Find authentication failures in last 24 hours
.\Get-EventLogAnalysis.ps1 -LogName Security -EventId 4625 -Hours 24

# Export system errors to CSV
.\Get-EventLogAnalysis.ps1 -LogName System -Level Error -OutputFormat CSV
```

---

## [!] Prerequisites

- **PowerShell 7.0+**
- **Administrator privileges** (for some metrics)
- No external modules required (uses built-in cmdlets)

---

## [i] Integration with Monitoring Systems

These scripts can export metrics for external monitoring:

**Prometheus (via node_exporter textfile collector):**
```powershell
.\Get-SystemPerformance.ps1 -OutputFormat Prometheus -OutputPath "C:\node_exporter\textfile"
```

**Scheduled Task for continuous monitoring:**
```powershell
$action = New-ScheduledTaskAction -Execute "pwsh.exe" `
    -Argument "-File `"$PWD\Get-SystemPerformance.ps1`" -OutputFormat JSON -OutputPath `"C:\Logs`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "SystemPerformanceMonitor" -Action $action -Trigger $trigger
```

---

## [*] Related Documentation

- [Troubleshooting Guide](../../docs/TROUBLESHOOTING.md)
- [Script Templates](../../docs/SCRIPT_TEMPLATE.md)

---

**Last Updated**: 2025-12-25
**Scripts Version**: 2.0
