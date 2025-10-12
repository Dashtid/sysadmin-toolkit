# Gitea SSH Tunnel Manager for Windows
# Manages a persistent SSH tunnel for Gitea access through Claude Code and Git
# Author: David Dashti
# https://github.com/dashtid
#
# USAGE:
#   Check status: .\gitea-tunnel-manager.ps1 -Status
#   Install as scheduled task: .\gitea-tunnel-manager.ps1 -Install
#   Stop tunnel: .\gitea-tunnel-manager.ps1 -Stop
#   Uninstall task: .\gitea-tunnel-manager.ps1 -Uninstall

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Stop
)

# Configuration - CUSTOMIZE THESE VALUES
$TUNNEL_NAME = "GiteaSSHTunnel"
$LOCAL_PORT = 2222                              # Local port for tunnel
$REMOTE_HOST = "youruser@gitea.example.com"     # Your Gitea server SSH host
$REMOTE_PORT = 2222                             # Gitea SSH port on server
$SSH_EXE = "C:\Windows\System32\OpenSSH\ssh.exe"
$LOG_FILE = "$env:TEMP\gitea-tunnel.log"
$CHECK_INTERVAL = 30                            # Health check interval (seconds)
$VPN_CHECK_HOST = "gitea.example.com"           # Host to ping to verify network connectivity

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Add-Content -Path $LOG_FILE -Value $logMessage
    Write-Host $logMessage
}

function Test-VPNConnection {
    # Test if we can reach the target network
    $ping = Test-Connection -ComputerName $VPN_CHECK_HOST -Count 1 -Quiet -ErrorAction SilentlyContinue
    return $ping
}

function Test-TunnelPort {
    $listening = Get-NetTCPConnection -LocalPort $LOCAL_PORT -State Listen -ErrorAction SilentlyContinue
    return $null -ne $listening
}

function Test-TunnelHealth {
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect("127.0.0.1", $LOCAL_PORT)
        $tcpClient.Close()
        return $true
    } catch {
        return $false
    }
}

function Get-TunnelProcess {
    $processes = Get-Process ssh -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
        if ($cmdLine -match "-L $LOCAL_PORT" -and $cmdLine -match $REMOTE_HOST) {
            return $proc
        }
    }
    return $null
}

function Start-Tunnel {
    Write-Log "Starting SSH tunnel: localhost:$LOCAL_PORT -> $REMOTE_HOST`:$REMOTE_PORT"

    # Check network connectivity first
    if (-not (Test-VPNConnection)) {
        Write-Log "Network unreachable - cannot reach $VPN_CHECK_HOST"
        Write-Log "Please connect to VPN/network and tunnel will start automatically"
        return $false
    }

    if (Test-TunnelPort) {
        Write-Log "Tunnel port $LOCAL_PORT is already in use"
        if (Test-TunnelHealth) {
            Write-Log "Existing tunnel is healthy"
            return $true
        } else {
            Write-Log "Existing tunnel is unhealthy, cleaning up..."
            Stop-Tunnel
            Start-Sleep -Seconds 2
        }
    }

    $arguments = @(
        "-N",
        "-L", "${LOCAL_PORT}:localhost:${REMOTE_PORT}",
        "-o", "ServerAliveInterval=60",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=no",
        $REMOTE_HOST
    )

    try {
        $processInfo = Start-Process -FilePath $SSH_EXE `
            -ArgumentList $arguments `
            -WindowStyle Hidden `
            -PassThru

        Start-Sleep -Seconds 3

        if (Test-TunnelHealth) {
            Write-Log "Tunnel started successfully (PID: $($processInfo.Id))"
            return $true
        } else {
            Write-Log "Tunnel failed to establish properly"
            Stop-Process -Id $processInfo.Id -Force -ErrorAction SilentlyContinue
            return $false
        }
    } catch {
        Write-Log "Error starting tunnel: $_"
        return $false
    }
}

function Stop-Tunnel {
    Write-Log "Stopping SSH tunnel..."
    $proc = Get-TunnelProcess
    if ($proc) {
        Stop-Process -Id $proc.Id -Force
        Write-Log "Tunnel stopped (PID: $($proc.Id))"
    } else {
        Write-Log "No tunnel process found"
    }
}

function Start-TunnelMonitor {
    Write-Log "Starting tunnel monitor (checking every $CHECK_INTERVAL seconds)"
    Write-Log "Press Ctrl+C to stop"

    while ($true) {
        if (-not (Test-TunnelPort)) {
            Write-Log "Tunnel not detected, attempting to start..."
            Start-Tunnel
        } elseif (-not (Test-TunnelHealth)) {
            Write-Log "Tunnel unhealthy, restarting..."
            Stop-Tunnel
            Start-Sleep -Seconds 2
            Start-Tunnel
        } else {
            Write-Log "Tunnel healthy"
        }

        Start-Sleep -Seconds $CHECK_INTERVAL
    }
}

function Install-TunnelTask {
    Write-Host "Installing Gitea SSH Tunnel as scheduled task..." -ForegroundColor Cyan

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    try {
        Register-ScheduledTask -TaskName $TUNNEL_NAME `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Description "Maintains persistent SSH tunnel to Gitea server for Claude Code" `
            -Force

        Write-Host "Scheduled task installed successfully!" -ForegroundColor Green
        Write-Host "The tunnel will start automatically at login" -ForegroundColor Gray
    } catch {
        Write-Host "Failed to install scheduled task: $_" -ForegroundColor Red
    }
}

function Uninstall-TunnelTask {
    Write-Host "Uninstalling Gitea SSH Tunnel scheduled task..." -ForegroundColor Cyan

    try {
        Unregister-ScheduledTask -TaskName $TUNNEL_NAME -Confirm:$false
        Write-Host "Scheduled task uninstalled successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to uninstall: $_" -ForegroundColor Red
    }
}

function Show-Status {
    Write-Host "`n=== Gitea SSH Tunnel Status ===" -ForegroundColor Cyan

    # Check network connectivity first
    $networkConnected = Test-VPNConnection
    Write-Host "`nNetwork Connection: " -NoNewline
    if ($networkConnected) {
        Write-Host "CONNECTED" -ForegroundColor Green
    } else {
        Write-Host "DISCONNECTED" -ForegroundColor Red
        Write-Host "  (Cannot reach $VPN_CHECK_HOST)" -ForegroundColor Yellow
    }

    $portOpen = Test-TunnelPort
    Write-Host "`nPort $LOCAL_PORT listening: " -NoNewline
    if ($portOpen) {
        Write-Host "YES" -ForegroundColor Green
    } else {
        Write-Host "NO" -ForegroundColor Red
    }

    if ($portOpen) {
        $healthy = Test-TunnelHealth
        Write-Host "Tunnel health: " -NoNewline
        if ($healthy) {
            Write-Host "HEALTHY" -ForegroundColor Green
        } else {
            Write-Host "UNHEALTHY" -ForegroundColor Yellow
        }
    }

    $proc = Get-TunnelProcess
    if ($proc) {
        Write-Host "`nTunnel process:" -ForegroundColor Cyan
        Write-Host "  PID: $($proc.Id)"
        Write-Host "  Memory: $([math]::Round($proc.WorkingSet64/1MB, 2)) MB"
    } else {
        Write-Host "`nTunnel process: " -NoNewline
        Write-Host "NOT RUNNING" -ForegroundColor Red
    }

    $task = Get-ScheduledTask -TaskName $TUNNEL_NAME -ErrorAction SilentlyContinue
    Write-Host "`nScheduled task: " -NoNewline
    if ($task) {
        Write-Host "$($task.State)" -ForegroundColor Green
    } else {
        Write-Host "NOT INSTALLED" -ForegroundColor Yellow
    }

    if (Test-Path $LOG_FILE) {
        Write-Host "`nRecent logs (last 5 lines):" -ForegroundColor Cyan
        Get-Content $LOG_FILE -Tail 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }

    Write-Host ""
}

# Main script logic
if ($Install) {
    Install-TunnelTask
} elseif ($Uninstall) {
    Stop-Tunnel
    Uninstall-TunnelTask
} elseif ($Status) {
    Show-Status
} elseif ($Stop) {
    Stop-Tunnel
} else {
    Write-Log "Gitea SSH Tunnel Manager Started"
    Start-Tunnel
    Start-TunnelMonitor
}
