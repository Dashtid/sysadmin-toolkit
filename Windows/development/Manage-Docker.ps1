#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manages Docker Desktop and containers on Windows.

.DESCRIPTION
    This script provides comprehensive Docker management capabilities:
    - Docker Desktop status and control
    - Container lifecycle management (start, stop, restart, remove)
    - Image management (list, pull, remove, prune)
    - Volume and network management
    - Resource usage monitoring
    - Cleanup of unused resources
    - Health checks and diagnostics
    - Container log viewing

    Features:
    - Easy container management without memorizing commands
    - Resource monitoring with configurable alerts
    - Automated cleanup of unused images/volumes
    - Docker Desktop integration
    - Container health monitoring

.PARAMETER Action
    The action to perform. Valid values:
    - Status: Show Docker status and running containers
    - Start: Start Docker Desktop or a container
    - Stop: Stop Docker Desktop or a container
    - Restart: Restart Docker Desktop or a container
    - List: List containers, images, volumes, or networks
    - Logs: View container logs
    - Shell: Open shell in a container
    - Prune: Clean up unused resources
    - Pull: Pull an image
    - Build: Build an image from Dockerfile
    - Stats: Show resource usage statistics
    - Troubleshoot: Diagnose Docker issues
    - Health: Check container health status
    Default: Status

.PARAMETER Target
    Target type for list/prune operations. Valid values: Containers, Images, Volumes, Networks, All.
    Default: Containers

.PARAMETER ContainerName
    Name or ID of a container for container-specific operations.

.PARAMETER ImageName
    Name of an image for image operations.

.PARAMETER All
    Include stopped containers in list, or remove all in prune operations.

.PARAMETER Follow
    Follow log output (like tail -f).

.PARAMETER Lines
    Number of log lines to show. Default: 100

.PARAMETER Force
    Force removal operations without confirmation.

.PARAMETER OutputFormat
    Output format. Valid values: Console, JSON, HTML.
    Default: Console

.EXAMPLE
    .\Manage-Docker.ps1 -Action Status
    Shows Docker Desktop status and running containers.

.EXAMPLE
    .\Manage-Docker.ps1 -Action List -Target Images
    Lists all Docker images.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Logs -ContainerName myapp -Follow -Lines 50
    Shows last 50 log lines from 'myapp' and follows new output.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Stop -ContainerName myapp
    Stops the container named 'myapp'.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Prune -Target All -Force
    Removes all unused containers, images, volumes, and networks.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Stats
    Shows live resource usage for all running containers.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Pull -ImageName nginx:latest
    Pulls the nginx:latest image from Docker Hub.

.EXAMPLE
    .\Manage-Docker.ps1 -Action Shell -ContainerName myapp
    Opens an interactive shell in the 'myapp' container.

.NOTES
    File Name      : Manage-Docker.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
                     Docker Desktop for Windows
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Docker Desktop must be installed for this script to work.
    Some operations may require Docker to be running.

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Status', 'Start', 'Stop', 'Restart', 'List', 'Logs', 'Shell', 'Prune', 'Pull', 'Build', 'Stats', 'Troubleshoot', 'Health')]
    [string]$Action = 'Status',

    [Parameter()]
    [ValidateSet('Containers', 'Images', 'Volumes', 'Networks', 'All')]
    [string]$Target = 'Containers',

    [Parameter()]
    [string]$ContainerName,

    [Parameter()]
    [string]$ImageName,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [switch]$Follow,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$Lines = 100,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateSet('Console', 'JSON', 'HTML')]
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
$script:DockerDesktopPath = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
$script:DockerCli = "docker"
#endregion

#region Helper Functions
function Test-DockerInstalled {
    try {
        $dockerPath = Get-Command docker -ErrorAction SilentlyContinue
        return ($null -ne $dockerPath)
    }
    catch {
        return $false
    }
}

function Test-DockerRunning {
    try {
        $result = docker info 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Test-DockerDesktopInstalled {
    return (Test-Path $script:DockerDesktopPath)
}

function Get-DockerVersion {
    try {
        $version = docker version --format '{{.Server.Version}}' 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $version
        }
        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

function Get-DockerInfo {
    try {
        $info = docker info --format '{{json .}}' 2>&1 | ConvertFrom-Json
        return $info
    }
    catch {
        return $null
    }
}

function Get-DockerContainers {
    param([switch]$All)

    $containers = @()

    try {
        $format = '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.State}}'
        $args = @('ps', '--format', $format)
        if ($All) {
            $args += '-a'
        }

        $output = docker @args 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            foreach ($line in $output) {
                if ($line -and $line.Trim()) {
                    $parts = $line -split '\t'
                    if ($parts.Count -ge 6) {
                        $containers += [PSCustomObject]@{
                            ID     = $parts[0]
                            Name   = $parts[1]
                            Image  = $parts[2]
                            Status = $parts[3]
                            Ports  = $parts[4]
                            State  = $parts[5]
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get containers: $($_.Exception.Message)"
    }

    return $containers
}

function Get-DockerImages {
    $images = @()

    try {
        $format = '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}'
        $output = docker images --format $format 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            foreach ($line in $output) {
                if ($line -and $line.Trim()) {
                    $parts = $line -split '\t'
                    if ($parts.Count -ge 5) {
                        $images += [PSCustomObject]@{
                            ID         = $parts[0]
                            Repository = $parts[1]
                            Tag        = $parts[2]
                            Size       = $parts[3]
                            Created    = $parts[4]
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get images: $($_.Exception.Message)"
    }

    return $images
}

function Get-DockerVolumes {
    $volumes = @()

    try {
        $format = '{{.Name}}\t{{.Driver}}\t{{.Scope}}'
        $output = docker volume ls --format $format 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            foreach ($line in $output) {
                if ($line -and $line.Trim()) {
                    $parts = $line -split '\t'
                    if ($parts.Count -ge 3) {
                        $volumes += [PSCustomObject]@{
                            Name   = $parts[0]
                            Driver = $parts[1]
                            Scope  = $parts[2]
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get volumes: $($_.Exception.Message)"
    }

    return $volumes
}

function Get-DockerNetworks {
    $networks = @()

    try {
        $format = '{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}'
        $output = docker network ls --format $format 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            foreach ($line in $output) {
                if ($line -and $line.Trim()) {
                    $parts = $line -split '\t'
                    if ($parts.Count -ge 4) {
                        $networks += [PSCustomObject]@{
                            ID     = $parts[0]
                            Name   = $parts[1]
                            Driver = $parts[2]
                            Scope  = $parts[3]
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get networks: $($_.Exception.Message)"
    }

    return $networks
}

function Get-ContainerStats {
    param([string]$ContainerName)

    try {
        $format = '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}'

        if ($ContainerName) {
            $output = docker stats --no-stream --format $format $ContainerName 2>&1
        }
        else {
            $output = docker stats --no-stream --format $format 2>&1
        }

        $stats = @()
        if ($LASTEXITCODE -eq 0 -and $output) {
            foreach ($line in $output) {
                if ($line -and $line.Trim()) {
                    $parts = $line -split '\t'
                    if ($parts.Count -ge 6) {
                        $stats += [PSCustomObject]@{
                            Name     = $parts[0]
                            CPU      = $parts[1]
                            Memory   = $parts[2]
                            NetIO    = $parts[3]
                            BlockIO  = $parts[4]
                            PIDs     = $parts[5]
                        }
                    }
                }
            }
        }

        return $stats
    }
    catch {
        Write-WarningMessage "Failed to get stats: $($_.Exception.Message)"
        return @()
    }
}

function Show-DockerStatus {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       DOCKER STATUS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    # Check installation
    Write-Host "Installation:" -ForegroundColor White
    if (Test-DockerInstalled) {
        Write-Host "  [+] Docker CLI installed" -ForegroundColor Green
    }
    else {
        Write-Host "  [-] Docker CLI not found" -ForegroundColor Red
        return
    }

    if (Test-DockerDesktopInstalled) {
        Write-Host "  [+] Docker Desktop installed" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] Docker Desktop not found at default location" -ForegroundColor Yellow
    }

    # Check if running
    Write-Host ""
    Write-Host "Status:" -ForegroundColor White
    if (Test-DockerRunning) {
        Write-Host "  [+] Docker is running" -ForegroundColor Green
        $version = Get-DockerVersion
        Write-Host "  [i] Version: $version" -ForegroundColor Blue

        # Get more info
        $info = Get-DockerInfo
        if ($info) {
            Write-Host "  [i] Server OS: $($info.OperatingSystem)" -ForegroundColor Blue
            Write-Host "  [i] CPUs: $($info.NCPU)" -ForegroundColor Blue
            Write-Host "  [i] Memory: $([math]::Round($info.MemTotal / 1GB, 1)) GB" -ForegroundColor Blue
        }
    }
    else {
        Write-Host "  [-] Docker is not running" -ForegroundColor Red
        Write-Host "  [i] Start Docker Desktop or run: .\Manage-Docker.ps1 -Action Start" -ForegroundColor Yellow
        return
    }

    # Running containers
    Write-Host ""
    Write-Host "Running Containers:" -ForegroundColor White
    $containers = Get-DockerContainers

    if ($containers.Count -gt 0) {
        foreach ($c in $containers) {
            $stateColor = switch ($c.State) {
                "running"  { "Green" }
                "exited"   { "Red" }
                "paused"   { "Yellow" }
                default    { "Gray" }
            }
            Write-Host "  - $($c.Name)" -ForegroundColor White
            Write-Host "    Image: $($c.Image)" -ForegroundColor Gray
            Write-Host "    State: " -NoNewline -ForegroundColor Gray
            Write-Host "$($c.State)" -ForegroundColor $stateColor
            if ($c.Ports) {
                Write-Host "    Ports: $($c.Ports)" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-Host "  [i] No running containers" -ForegroundColor Gray
    }

    # Quick stats
    $allContainers = Get-DockerContainers -All
    $images = Get-DockerImages
    $volumes = Get-DockerVolumes

    Write-Host ""
    Write-Host "Summary:" -ForegroundColor White
    Write-Host "  Containers: $($containers.Count) running / $($allContainers.Count) total" -ForegroundColor Gray
    Write-Host "  Images: $($images.Count)" -ForegroundColor Gray
    Write-Host "  Volumes: $($volumes.Count)" -ForegroundColor Gray
}

function Start-DockerDesktop {
    if (-not (Test-DockerDesktopInstalled)) {
        Write-ErrorMessage "Docker Desktop not found"
        return $false
    }

    if (Test-DockerRunning) {
        Write-InfoMessage "Docker is already running"
        return $true
    }

    Write-InfoMessage "Starting Docker Desktop..."

    try {
        Start-Process -FilePath $script:DockerDesktopPath -WindowStyle Hidden

        # Wait for Docker to start
        $maxWait = 120  # 2 minutes
        $waited = 0
        $interval = 5

        while ($waited -lt $maxWait) {
            Start-Sleep -Seconds $interval
            $waited += $interval

            if (Test-DockerRunning) {
                Write-Success "Docker Desktop started successfully"
                return $true
            }

            Write-Host "." -NoNewline
        }

        Write-ErrorMessage "Docker Desktop failed to start within $maxWait seconds"
        return $false
    }
    catch {
        Write-ErrorMessage "Failed to start Docker Desktop: $($_.Exception.Message)"
        return $false
    }
}

function Stop-DockerDesktop {
    if (-not (Test-DockerRunning)) {
        Write-InfoMessage "Docker is not running"
        return $true
    }

    Write-InfoMessage "Stopping Docker Desktop..."

    try {
        # Stop all containers first
        $containers = Get-DockerContainers
        if ($containers.Count -gt 0) {
            Write-InfoMessage "Stopping $($containers.Count) running container(s)..."
            docker stop $(docker ps -q) 2>&1 | Out-Null
        }

        # Stop Docker Desktop
        Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Process -Name "com.docker.*" -ErrorAction SilentlyContinue | Stop-Process -Force

        Start-Sleep -Seconds 3

        Write-Success "Docker Desktop stopped"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to stop Docker Desktop: $($_.Exception.Message)"
        return $false
    }
}

function Start-Container {
    param([string]$Name)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return $false
    }

    Write-InfoMessage "Starting container '$Name'..."

    try {
        $result = docker start $Name 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Container '$Name' started"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to start container: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error: $($_.Exception.Message)"
        return $false
    }
}

function Stop-Container {
    param([string]$Name)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return $false
    }

    Write-InfoMessage "Stopping container '$Name'..."

    try {
        $result = docker stop $Name 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Container '$Name' stopped"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to stop container: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error: $($_.Exception.Message)"
        return $false
    }
}

function Restart-Container {
    param([string]$Name)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return $false
    }

    Write-InfoMessage "Restarting container '$Name'..."

    try {
        $result = docker restart $Name 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Container '$Name' restarted"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to restart container: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error: $($_.Exception.Message)"
        return $false
    }
}

function Show-ContainerLogs {
    param(
        [string]$Name,
        [int]$Tail,
        [switch]$Follow
    )

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return
    }

    Write-InfoMessage "Showing logs for '$Name'..."

    $args = @('logs')
    if ($Tail -gt 0) {
        $args += '--tail'
        $args += $Tail
    }
    if ($Follow) {
        $args += '-f'
    }
    $args += $Name

    try {
        & docker @args
    }
    catch {
        Write-ErrorMessage "Error getting logs: $($_.Exception.Message)"
    }
}

function Open-ContainerShell {
    param([string]$Name)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return
    }

    Write-InfoMessage "Opening shell in '$Name'..."
    Write-InfoMessage "Type 'exit' to leave the container shell"

    # Try bash first, fall back to sh
    $result = docker exec -it $Name bash 2>&1
    if ($LASTEXITCODE -ne 0) {
        docker exec -it $Name sh
    }
}

function Invoke-DockerPrune {
    param(
        [string]$Target,
        [switch]$Force
    )

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return $false
    }

    $forceFlag = if ($Force) { '-f' } else { '' }

    switch ($Target) {
        'Containers' {
            Write-InfoMessage "Removing stopped containers..."
            if ($Force) {
                docker container prune -f
            }
            else {
                docker container prune
            }
        }
        'Images' {
            Write-InfoMessage "Removing unused images..."
            if ($Force) {
                docker image prune -a -f
            }
            else {
                docker image prune -a
            }
        }
        'Volumes' {
            Write-InfoMessage "Removing unused volumes..."
            if ($Force) {
                docker volume prune -f
            }
            else {
                docker volume prune
            }
        }
        'Networks' {
            Write-InfoMessage "Removing unused networks..."
            if ($Force) {
                docker network prune -f
            }
            else {
                docker network prune
            }
        }
        'All' {
            Write-InfoMessage "Running full system prune..."
            if ($Force) {
                docker system prune -a --volumes -f
            }
            else {
                docker system prune -a --volumes
            }
        }
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Prune completed"
        return $true
    }
    else {
        Write-WarningMessage "Prune may have encountered issues"
        return $false
    }
}

function Pull-DockerImage {
    param([string]$Name)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return $false
    }

    Write-InfoMessage "Pulling image '$Name'..."

    try {
        docker pull $Name

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Image '$Name' pulled successfully"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to pull image"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error: $($_.Exception.Message)"
        return $false
    }
}

function Get-ContainerHealth {
    param([string]$ContainerName)

    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return @()
    }

    $containers = if ($ContainerName) {
        Get-DockerContainers -All | Where-Object { $_.Name -eq $ContainerName -or $_.ID -like "$ContainerName*" }
    }
    else {
        Get-DockerContainers -All
    }

    $healthResults = @()

    foreach ($container in $containers) {
        $health = [PSCustomObject]@{
            Name   = $container.Name
            State  = $container.State
            Status = $container.Status
            Health = "N/A"
            Issues = @()
        }

        # Get detailed health info
        try {
            $inspect = docker inspect $container.ID 2>&1 | ConvertFrom-Json

            if ($inspect.State.Health) {
                $health.Health = $inspect.State.Health.Status

                if ($inspect.State.Health.Log) {
                    $lastLog = $inspect.State.Health.Log | Select-Object -Last 1
                    if ($lastLog.ExitCode -ne 0) {
                        $health.Issues += "Last health check failed: $($lastLog.Output)"
                    }
                }
            }

            # Check for common issues
            if ($container.State -eq "exited") {
                $exitCode = $inspect.State.ExitCode
                if ($exitCode -ne 0) {
                    $health.Issues += "Container exited with code $exitCode"
                }
            }

            if ($inspect.State.OOMKilled) {
                $health.Issues += "Container was killed due to OOM (Out of Memory)"
            }
        }
        catch { }

        $healthResults += $health
    }

    return $healthResults
}

function Invoke-DockerTroubleshoot {
    Write-InfoMessage "Running Docker diagnostics..."
    Write-Host ""

    $results = @()

    # 1. Check Docker CLI
    Write-Host "1. Checking Docker CLI..." -ForegroundColor Cyan
    if (Test-DockerInstalled) {
        $results += [PSCustomObject]@{ Check = "Docker CLI"; Status = "PASS"; Details = "Installed" }
        Write-Host "   [+] Docker CLI is installed" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{ Check = "Docker CLI"; Status = "FAIL"; Details = "Not found" }
        Write-Host "   [-] Docker CLI not found" -ForegroundColor Red
        return $results
    }

    # 2. Check Docker Desktop
    Write-Host "2. Checking Docker Desktop..." -ForegroundColor Cyan
    if (Test-DockerDesktopInstalled) {
        $results += [PSCustomObject]@{ Check = "Docker Desktop"; Status = "PASS"; Details = "Installed" }
        Write-Host "   [+] Docker Desktop is installed" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{ Check = "Docker Desktop"; Status = "WARN"; Details = "Not at default location" }
        Write-Host "   [!] Docker Desktop not at default location" -ForegroundColor Yellow
    }

    # 3. Check if Docker is running
    Write-Host "3. Checking Docker daemon..." -ForegroundColor Cyan
    if (Test-DockerRunning) {
        $results += [PSCustomObject]@{ Check = "Docker Daemon"; Status = "PASS"; Details = "Running" }
        Write-Host "   [+] Docker daemon is running" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{ Check = "Docker Daemon"; Status = "FAIL"; Details = "Not running" }
        Write-Host "   [-] Docker daemon is not running" -ForegroundColor Red
    }

    # 4. Check version
    Write-Host "4. Checking Docker version..." -ForegroundColor Cyan
    $version = Get-DockerVersion
    $results += [PSCustomObject]@{ Check = "Docker Version"; Status = "INFO"; Details = $version }
    Write-Host "   [i] Version: $version" -ForegroundColor Blue

    # 5. Check disk space
    Write-Host "5. Checking Docker disk usage..." -ForegroundColor Cyan
    try {
        $diskUsage = docker system df 2>&1
        if ($LASTEXITCODE -eq 0) {
            $results += [PSCustomObject]@{ Check = "Disk Usage"; Status = "INFO"; Details = "Retrieved" }
            Write-Host "   [i] Disk usage retrieved" -ForegroundColor Blue
            Write-Host $diskUsage
        }
    }
    catch {
        $results += [PSCustomObject]@{ Check = "Disk Usage"; Status = "WARN"; Details = "Could not retrieve" }
    }

    # 6. Check WSL backend
    Write-Host "6. Checking WSL2 backend..." -ForegroundColor Cyan
    try {
        $wslList = wsl --list --verbose 2>&1
        if ($LASTEXITCODE -eq 0 -and $wslList -match "docker") {
            $results += [PSCustomObject]@{ Check = "WSL2 Backend"; Status = "PASS"; Details = "Docker WSL distro found" }
            Write-Host "   [+] Docker WSL2 integration enabled" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{ Check = "WSL2 Backend"; Status = "INFO"; Details = "May be using Hyper-V" }
            Write-Host "   [i] Docker may be using Hyper-V backend" -ForegroundColor Gray
        }
    }
    catch {
        $results += [PSCustomObject]@{ Check = "WSL2 Backend"; Status = "UNKNOWN"; Details = "Could not check" }
    }

    # 7. Check network
    Write-Host "7. Checking Docker network..." -ForegroundColor Cyan
    try {
        $networks = docker network ls 2>&1
        if ($LASTEXITCODE -eq 0) {
            $results += [PSCustomObject]@{ Check = "Docker Networks"; Status = "PASS"; Details = "Networks accessible" }
            Write-Host "   [+] Docker networks are accessible" -ForegroundColor Green
        }
    }
    catch {
        $results += [PSCustomObject]@{ Check = "Docker Networks"; Status = "WARN"; Details = "Could not list" }
    }

    # 8. Check container health
    Write-Host "8. Checking container health..." -ForegroundColor Cyan
    $containers = Get-DockerContainers -All
    $unhealthy = $containers | Where-Object { $_.State -eq "exited" -or $_.Status -match "unhealthy" }
    if ($unhealthy.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = "Container Health"; Status = "WARN"; Details = "$($unhealthy.Count) unhealthy containers" }
        Write-Host "   [!] $($unhealthy.Count) container(s) may need attention" -ForegroundColor Yellow
    }
    else {
        $results += [PSCustomObject]@{ Check = "Container Health"; Status = "PASS"; Details = "All containers healthy" }
        Write-Host "   [+] All containers appear healthy" -ForegroundColor Green
    }

    # Summary
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       DIAGNOSTIC SUMMARY" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    $passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count

    Write-Host "Passed: $passCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "Warnings: $warnCount" -ForegroundColor Yellow

    if ($failCount -gt 0 -or $warnCount -gt 0) {
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Cyan

        if (($results | Where-Object { $_.Check -eq "Docker Daemon" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Start Docker Desktop or run: docker info" -ForegroundColor White
        }
        if (($results | Where-Object { $_.Check -eq "Container Health" -and $_.Status -eq "WARN" })) {
            Write-Host "  - Check unhealthy containers: docker ps -a" -ForegroundColor White
            Write-Host "  - View logs: docker logs <container-name>" -ForegroundColor White
        }
    }

    return $results
}

function Show-ResourceStats {
    if (-not (Test-DockerRunning)) {
        Write-ErrorMessage "Docker is not running"
        return
    }

    Write-InfoMessage "Showing container resource usage..."
    Write-InfoMessage "Press Ctrl+C to stop"

    docker stats
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "Docker Manager v$($script:ScriptVersion)"

    switch ($Action) {
        'Status' {
            Show-DockerStatus
        }

        'Start' {
            if ($ContainerName) {
                if ($PSCmdlet.ShouldProcess($ContainerName, "Start container")) {
                    $success = Start-Container -Name $ContainerName
                    exit $(if ($success) { 0 } else { 1 })
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess("Docker Desktop", "Start")) {
                    $success = Start-DockerDesktop
                    exit $(if ($success) { 0 } else { 1 })
                }
            }
        }

        'Stop' {
            if ($ContainerName) {
                if ($PSCmdlet.ShouldProcess($ContainerName, "Stop container")) {
                    $success = Stop-Container -Name $ContainerName
                    exit $(if ($success) { 0 } else { 1 })
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess("Docker Desktop", "Stop")) {
                    $success = Stop-DockerDesktop
                    exit $(if ($success) { 0 } else { 1 })
                }
            }
        }

        'Restart' {
            if ($ContainerName) {
                if ($PSCmdlet.ShouldProcess($ContainerName, "Restart container")) {
                    $success = Restart-Container -Name $ContainerName
                    exit $(if ($success) { 0 } else { 1 })
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess("Docker Desktop", "Restart")) {
                    Stop-DockerDesktop
                    Start-Sleep -Seconds 3
                    Start-DockerDesktop
                }
            }
        }

        'List' {
            if (-not (Test-DockerRunning)) {
                Write-ErrorMessage "Docker is not running"
                exit 1
            }

            switch ($Target) {
                'Containers' {
                    $items = Get-DockerContainers -All:$All
                    Write-Host ""
                    Write-Host "Containers$(if ($All) { ' (including stopped)' }):" -ForegroundColor Cyan
                    $items | Format-Table -AutoSize
                }
                'Images' {
                    $items = Get-DockerImages
                    Write-Host ""
                    Write-Host "Images:" -ForegroundColor Cyan
                    $items | Format-Table -AutoSize
                }
                'Volumes' {
                    $items = Get-DockerVolumes
                    Write-Host ""
                    Write-Host "Volumes:" -ForegroundColor Cyan
                    $items | Format-Table -AutoSize
                }
                'Networks' {
                    $items = Get-DockerNetworks
                    Write-Host ""
                    Write-Host "Networks:" -ForegroundColor Cyan
                    $items | Format-Table -AutoSize
                }
                'All' {
                    Write-Host ""
                    Write-Host "=== Containers ===" -ForegroundColor Cyan
                    Get-DockerContainers -All | Format-Table -AutoSize
                    Write-Host "=== Images ===" -ForegroundColor Cyan
                    Get-DockerImages | Format-Table -AutoSize
                    Write-Host "=== Volumes ===" -ForegroundColor Cyan
                    Get-DockerVolumes | Format-Table -AutoSize
                    Write-Host "=== Networks ===" -ForegroundColor Cyan
                    Get-DockerNetworks | Format-Table -AutoSize
                }
            }
        }

        'Logs' {
            if (-not $ContainerName) {
                Write-ErrorMessage "Please specify -ContainerName"
                exit 1
            }
            Show-ContainerLogs -Name $ContainerName -Tail $Lines -Follow:$Follow
        }

        'Shell' {
            if (-not $ContainerName) {
                Write-ErrorMessage "Please specify -ContainerName"
                exit 1
            }
            Open-ContainerShell -Name $ContainerName
        }

        'Prune' {
            if ($PSCmdlet.ShouldProcess($Target, "Prune Docker resources")) {
                $success = Invoke-DockerPrune -Target $Target -Force:$Force
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Pull' {
            if (-not $ImageName) {
                Write-ErrorMessage "Please specify -ImageName"
                exit 1
            }
            if ($PSCmdlet.ShouldProcess($ImageName, "Pull image")) {
                $success = Pull-DockerImage -Name $ImageName
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Stats' {
            if ($ContainerName) {
                $stats = Get-ContainerStats -ContainerName $ContainerName
                $stats | Format-Table -AutoSize
            }
            else {
                Show-ResourceStats
            }
        }

        'Troubleshoot' {
            $results = Invoke-DockerTroubleshoot

            if ($OutputFormat -eq 'JSON') {
                $outputPath = Join-Path (Get-LogDirectory) "docker_diagnostic_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $results | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding UTF8
                Write-Success "JSON report saved to: $outputPath"
            }
        }

        'Health' {
            $health = Get-ContainerHealth -ContainerName $ContainerName
            if ($health.Count -gt 0) {
                Write-Host ""
                Write-Host "Container Health Status:" -ForegroundColor Cyan
                foreach ($h in $health) {
                    $stateColor = switch ($h.State) {
                        "running" { "Green" }
                        "exited"  { "Red" }
                        default   { "Yellow" }
                    }
                    Write-Host "  $($h.Name):" -ForegroundColor White
                    Write-Host "    State: " -NoNewline -ForegroundColor Gray
                    Write-Host $h.State -ForegroundColor $stateColor
                    Write-Host "    Status: $($h.Status)" -ForegroundColor Gray
                    Write-Host "    Health: $($h.Health)" -ForegroundColor Gray
                    if ($h.Issues.Count -gt 0) {
                        Write-Host "    Issues:" -ForegroundColor Yellow
                        foreach ($issue in $h.Issues) {
                            Write-Host "      - $issue" -ForegroundColor Yellow
                        }
                    }
                }
            }
            else {
                Write-InfoMessage "No containers found"
            }
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    Write-InfoMessage "Completed in $($duration.TotalSeconds.ToString('F1')) seconds"
}

# Run main function
Main
#endregion
