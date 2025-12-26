# Windows Monitoring Scripts

System health and performance monitoring for Windows workstations and servers.

## Scripts

| Script | Purpose |
|--------|---------|
| [Get-SystemPerformance.ps1](Get-SystemPerformance.ps1) | CPU, RAM, disk, network metrics |
| [Watch-ServiceHealth.ps1](Watch-ServiceHealth.ps1) | Service status monitoring with auto-restart |
| [Test-NetworkHealth.ps1](Test-NetworkHealth.ps1) | Network connectivity and latency tests |
| [Get-EventLogAnalysis.ps1](Get-EventLogAnalysis.ps1) | Event log filtering and analysis |
| [Get-ApplicationHealth.ps1](Get-ApplicationHealth.ps1) | Application crash and version monitoring |

## Quick Start

```powershell
# Basic system check
.\Get-SystemPerformance.ps1

# HTML report with processes
.\Get-SystemPerformance.ps1 -OutputFormat HTML -IncludeProcesses

# Monitor services
.\Watch-ServiceHealth.ps1 -Services "ssh-agent", "W32Time"

# Network connectivity
.\Test-NetworkHealth.ps1 -Targets "google.com", "github.com"

# Recent errors
.\Get-EventLogAnalysis.ps1 -LogName System -Level Error -Hours 24
```

## Key Parameters

### Get-SystemPerformance.ps1

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputFormat` | Console, HTML, JSON, CSV, Prometheus | Console |
| `-OutputPath` | Output directory | logs/ |
| `-MonitorDuration` | Minutes to monitor (0 = single) | 0 |
| `-AlertOnly` | Only output on threshold breach | false |
| `-IncludeProcesses` | Include top processes | false |

### Watch-ServiceHealth.ps1

| Parameter | Description |
|-----------|-------------|
| `-Services` | Services to monitor |
| `-AutoRestart` | Restart failed services |
| `-MaxRestartAttempts` | Max restart tries |
| `-MonitorDuration` | Minutes to monitor |

## Prometheus Integration

```powershell
.\Get-SystemPerformance.ps1 -OutputFormat Prometheus -OutputPath "C:\node_exporter\textfile"
```

## Scheduled Monitoring

```powershell
$action = New-ScheduledTaskAction -Execute "pwsh.exe" `
    -Argument "-File `"$PWD\Get-SystemPerformance.ps1`" -OutputFormat JSON"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "SystemMonitor" -Action $action -Trigger $trigger
```

## Prerequisites

- PowerShell 7.0+
- Administrator privileges (for some metrics)

Use `Get-Help .\<Script>.ps1 -Full` for detailed parameter info.

---
**Last Updated**: 2025-12-26
