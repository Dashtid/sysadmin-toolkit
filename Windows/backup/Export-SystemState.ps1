#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Exports complete system configuration for disaster recovery.

.DESCRIPTION
    This script exports critical system state information including:
    - Installed drivers with version information
    - Registry keys for startup programs and services
    - Network configuration (adapters, IP, DNS, routes, firewall)
    - Scheduled tasks with full XML definitions
    - Windows optional features state
    - Service configurations
    - Installed packages (Winget and Chocolatey)
    - Event logs (optional)

    The export creates a structured folder with all components,
    optionally compressed into a single archive.

.PARAMETER Destination
    Export destination folder path.

.PARAMETER Include
    Components to export. Valid values: All, Drivers, Registry, Network, Tasks, Features, Services, Packages.
    Default: All

.PARAMETER Compress
    Create a ZIP archive of the export folder.

.PARAMETER OutputFormat
    Output format for the summary report. Valid values: Console, HTML, JSON, All.
    Default: Console

.PARAMETER IncludeEventLogs
    Include recent event logs in export (can be large).

.PARAMETER EventLogDays
    Number of days of event logs to export. Default: 7

.PARAMETER DryRun
    Preview what would be exported without actually exporting.

.EXAMPLE
    .\Export-SystemState.ps1 -Destination "D:\Backups\SystemState"
    Exports all system state components to the specified folder.

.EXAMPLE
    .\Export-SystemState.ps1 -Destination "D:\Backups" -Include Drivers,Network -Compress
    Exports only drivers and network config, compressed into a ZIP.

.EXAMPLE
    .\Export-SystemState.ps1 -Destination "D:\Backups" -IncludeEventLogs -EventLogDays 30
    Exports all components including 30 days of event logs.

.NOTES
    File Name      : Export-SystemState.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+, some components require Administrator
    Version        : 1.0.0

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [ValidateSet('All', 'Drivers', 'Registry', 'Network', 'Tasks', 'Features', 'Services', 'Packages')]
    [string[]]$Include = @('All'),

    [switch]$Compress,

    [ValidateSet('Console', 'HTML', 'JSON', 'All')]
    [string]$OutputFormat = 'Console',

    [switch]$IncludeEventLogs,

    [ValidateRange(1, 365)]
    [int]$EventLogDays = 7,

    [switch]$DryRun
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    # Fallback inline definitions
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Test-IsAdministrator {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"
$script:ExportFolder = $null
$script:Stats = @{
    ComponentsExported = 0
    FilesCreated       = 0
    TotalSize          = 0
    Errors             = @()
    Warnings           = @()
}
#endregion

#region Helper Functions

function Get-ExportComponents {
    <#
    .SYNOPSIS
        Determines which components to export based on Include parameter.
    #>
    param([string[]]$Include)

    $allComponents = @('Drivers', 'Registry', 'Network', 'Tasks', 'Features', 'Services', 'Packages')

    if ($Include -contains 'All') {
        return $allComponents
    }
    return $Include
}

function New-ExportFolder {
    <#
    .SYNOPSIS
        Creates the export folder structure.
    #>
    param([string]$BasePath)

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $folderName = "SystemState_$timestamp"
    $exportPath = Join-Path $BasePath $folderName

    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null

        # Create subdirectories
        @('drivers', 'registry', 'network', 'tasks', 'tasks\xml', 'features', 'services', 'packages', 'eventlogs') | ForEach-Object {
            New-Item -ItemType Directory -Path (Join-Path $exportPath $_) -Force | Out-Null
        }
    }

    return $exportPath
}

function Export-Drivers {
    <#
    .SYNOPSIS
        Exports installed driver information.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting drivers..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export driver information"
        return @{ Success = $true; Files = 0 }
    }

    $driversPath = Join-Path $ExportPath "drivers"
    $filesCreated = 0

    try {
        # Get PnP devices with driver info
        $drivers = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Class } | ForEach-Object {
            $driverInfo = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name            = $_.FriendlyName
                Class           = $_.Class
                Status          = $_.Status
                InstanceId      = $_.InstanceId
                Manufacturer    = $_.Manufacturer
                DriverVersion   = $driverInfo.Data
                Present         = $_.Present
            }
        }

        # Export as JSON
        $jsonPath = Join-Path $driversPath "drivers.json"
        $drivers | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
        $filesCreated++

        # Export as CSV for spreadsheet viewing
        $csvPath = Join-Path $driversPath "drivers.csv"
        $drivers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $filesCreated++

        # Also run driverquery for raw output
        $driverQueryPath = Join-Path $driversPath "driverquery.txt"
        driverquery /v /fo list | Out-File -FilePath $driverQueryPath -Encoding UTF8
        $filesCreated++

        $script:Stats.FilesCreated += $filesCreated
        Write-Success "  Exported $($drivers.Count) drivers ($filesCreated files)"
        return @{ Success = $true; Files = $filesCreated; Count = $drivers.Count }
    }
    catch {
        $script:Stats.Errors += "Drivers: $($_.Exception.Message)"
        Write-ErrorMessage "  Failed to export drivers: $($_.Exception.Message)"
        return @{ Success = $false; Files = 0 }
    }
}

function Export-RegistryKeys {
    <#
    .SYNOPSIS
        Exports important registry keys.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting registry keys..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export registry keys"
        return @{ Success = $true; Files = 0 }
    }

    $registryPath = Join-Path $ExportPath "registry"
    $filesCreated = 0

    $keysToExport = @(
        @{ Name = "run-keys-hklm"; Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Name = "run-keys-hkcu"; Path = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Name = "runonce-hklm"; Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Name = "shell-folders"; Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" },
        @{ Name = "environment-system"; Path = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" },
        @{ Name = "environment-user"; Path = "HKCU\Environment" }
    )

    foreach ($key in $keysToExport) {
        try {
            $regFile = Join-Path $registryPath "$($key.Name).reg"
            $result = reg export $key.Path $regFile /y 2>&1

            if (Test-Path $regFile) {
                $filesCreated++
                Write-Success "  Exported: $($key.Name)"
            }
        }
        catch {
            $script:Stats.Warnings += "Registry key $($key.Name): $($_.Exception.Message)"
            Write-WarningMessage "  Could not export $($key.Name)"
        }
    }

    $script:Stats.FilesCreated += $filesCreated
    return @{ Success = $true; Files = $filesCreated }
}

function Export-NetworkConfig {
    <#
    .SYNOPSIS
        Exports network configuration.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting network configuration..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export network configuration"
        return @{ Success = $true; Files = 0 }
    }

    $networkPath = Join-Path $ExportPath "network"
    $filesCreated = 0

    try {
        # Network adapters
        $adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, MediaType
        $adapters | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "adapters.json") -Encoding UTF8
        $filesCreated++

        # IP configuration
        $ipConfig = Get-NetIPConfiguration | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias  = $_.InterfaceAlias
                InterfaceIndex  = $_.InterfaceIndex
                IPv4Address     = $_.IPv4Address.IPAddress
                IPv4Gateway     = $_.IPv4DefaultGateway.NextHop
                DNSServer       = $_.DNSServer.ServerAddresses -join ', '
                NetProfile      = $_.NetProfile.Name
            }
        }
        $ipConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "ip-config.json") -Encoding UTF8
        $filesCreated++

        # Routes
        $routes = Get-NetRoute | Where-Object { $_.DestinationPrefix -ne '::' -and $_.DestinationPrefix -ne '::/0' } |
            Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, AddressFamily
        $routes | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "routes.json") -Encoding UTF8
        $filesCreated++

        # DNS settings
        $dns = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } |
            Select-Object InterfaceAlias, AddressFamily, ServerAddresses
        $dns | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "dns.json") -Encoding UTF8
        $filesCreated++

        # Firewall profiles
        $firewall = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName
        $firewall | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "firewall-profiles.json") -Encoding UTF8
        $filesCreated++

        # Firewall rules (enabled only to reduce size)
        $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
            Select-Object Name, DisplayName, Direction, Action, Profile, Enabled | Sort-Object DisplayName
        $firewallRules | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $networkPath "firewall-rules.json") -Encoding UTF8
        $filesCreated++

        $script:Stats.FilesCreated += $filesCreated
        Write-Success "  Exported network configuration ($filesCreated files)"
        return @{ Success = $true; Files = $filesCreated }
    }
    catch {
        $script:Stats.Errors += "Network: $($_.Exception.Message)"
        Write-ErrorMessage "  Failed to export network config: $($_.Exception.Message)"
        return @{ Success = $false; Files = $filesCreated }
    }
}

function Export-ScheduledTasks {
    <#
    .SYNOPSIS
        Exports scheduled tasks.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting scheduled tasks..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export scheduled tasks"
        return @{ Success = $true; Files = 0 }
    }

    $tasksPath = Join-Path $ExportPath "tasks"
    $xmlPath = Join-Path $tasksPath "xml"
    $filesCreated = 0

    try {
        # Get all tasks (excluding Microsoft system tasks to reduce noise)
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object TaskName, TaskPath, State, Description, Author, @{N='Triggers';E={$_.Triggers.Count}}, @{N='Actions';E={$_.Actions.Count}}

        # Export summary
        $tasks | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $tasksPath "tasks-summary.json") -Encoding UTF8
        $filesCreated++

        # Export individual task XMLs
        $exportedTasks = 0
        foreach ($task in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
            try {
                $safeName = $task.TaskName -replace '[\\/:*?"<>|]', '_'
                $xmlFile = Join-Path $xmlPath "$safeName.xml"
                Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-File -FilePath $xmlFile -Encoding UTF8
                $filesCreated++
                $exportedTasks++
            }
            catch {
                $script:Stats.Warnings += "Task $($task.TaskName): $($_.Exception.Message)"
            }
        }

        $script:Stats.FilesCreated += $filesCreated
        Write-Success "  Exported $exportedTasks scheduled tasks"
        return @{ Success = $true; Files = $filesCreated; Count = $exportedTasks }
    }
    catch {
        $script:Stats.Errors += "Tasks: $($_.Exception.Message)"
        Write-ErrorMessage "  Failed to export tasks: $($_.Exception.Message)"
        return @{ Success = $false; Files = $filesCreated }
    }
}

function Export-WindowsFeatures {
    <#
    .SYNOPSIS
        Exports Windows optional features state.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting Windows features..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export Windows features"
        return @{ Success = $true; Files = 0 }
    }

    $featuresPath = Join-Path $ExportPath "features"

    try {
        $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Select-Object FeatureName, State, Description | Sort-Object FeatureName

        $jsonPath = Join-Path $featuresPath "windows-features.json"
        $features | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8

        $script:Stats.FilesCreated++
        Write-Success "  Exported $($features.Count) Windows features"
        return @{ Success = $true; Files = 1; Count = $features.Count }
    }
    catch {
        $script:Stats.Errors += "Features: $($_.Exception.Message)"
        Write-ErrorMessage "  Failed to export features: $($_.Exception.Message)"
        return @{ Success = $false; Files = 0 }
    }
}

function Export-Services {
    <#
    .SYNOPSIS
        Exports Windows services configuration.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting services..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export services"
        return @{ Success = $true; Files = 0 }
    }

    $servicesPath = Join-Path $ExportPath "services"

    try {
        $services = Get-Service | ForEach-Object {
            $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                Status      = $_.Status
                StartType   = $_.StartType
                Description = $wmiService.Description
                PathName    = $wmiService.PathName
                Account     = $wmiService.StartName
            }
        } | Sort-Object Name

        $jsonPath = Join-Path $servicesPath "services.json"
        $services | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8

        # Also export CSV for easy viewing
        $csvPath = Join-Path $servicesPath "services.csv"
        $services | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        $script:Stats.FilesCreated += 2
        Write-Success "  Exported $($services.Count) services"
        return @{ Success = $true; Files = 2; Count = $services.Count }
    }
    catch {
        $script:Stats.Errors += "Services: $($_.Exception.Message)"
        Write-ErrorMessage "  Failed to export services: $($_.Exception.Message)"
        return @{ Success = $false; Files = 0 }
    }
}

function Export-InstalledPackages {
    <#
    .SYNOPSIS
        Exports installed packages from Winget and Chocolatey.
    #>
    param([string]$ExportPath)

    Write-InfoMessage "Exporting installed packages..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export installed packages"
        return @{ Success = $true; Files = 0 }
    }

    $packagesPath = Join-Path $ExportPath "packages"
    $filesCreated = 0

    # Winget export
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            $wingetFile = Join-Path $packagesPath "winget-packages.json"
            winget export -o $wingetFile --accept-source-agreements 2>&1 | Out-Null

            if (Test-Path $wingetFile) {
                $wingetCount = (Get-Content $wingetFile | ConvertFrom-Json).Sources.Packages.Count
                Write-Success "  Exported $wingetCount Winget packages"
                $filesCreated++
            }
        }
        catch {
            $script:Stats.Warnings += "Winget export: $($_.Exception.Message)"
            Write-WarningMessage "  Winget export failed"
        }
    }
    else {
        Write-WarningMessage "  Winget not found, skipping"
    }

    # Chocolatey export
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            $chocoFile = Join-Path $packagesPath "chocolatey-packages.config"
            choco export $chocoFile 2>&1 | Out-Null

            if (Test-Path $chocoFile) {
                $chocoCount = ([xml](Get-Content $chocoFile)).packages.package.Count
                Write-Success "  Exported $chocoCount Chocolatey packages"
                $filesCreated++
            }
        }
        catch {
            $script:Stats.Warnings += "Chocolatey export: $($_.Exception.Message)"
            Write-WarningMessage "  Chocolatey export failed"
        }
    }
    else {
        Write-WarningMessage "  Chocolatey not found, skipping"
    }

    $script:Stats.FilesCreated += $filesCreated
    return @{ Success = $true; Files = $filesCreated }
}

function Export-EventLogs {
    <#
    .SYNOPSIS
        Exports recent event logs.
    #>
    param(
        [string]$ExportPath,
        [int]$Days
    )

    Write-InfoMessage "Exporting event logs (last $Days days)..."

    if ($DryRun) {
        Write-InfoMessage "  [DryRun] Would export event logs"
        return @{ Success = $true; Files = 0 }
    }

    $logsPath = Join-Path $ExportPath "eventlogs"
    $filesCreated = 0
    $startDate = (Get-Date).AddDays(-$Days)

    $logsToExport = @('System', 'Application', 'Security')

    foreach ($logName in $logsToExport) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $startDate
            } -MaxEvents 5000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, Message

            if ($events) {
                $jsonFile = Join-Path $logsPath "$logName-${Days}days.json"
                $events | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonFile -Encoding UTF8
                $filesCreated++
                Write-Success "  Exported $($events.Count) events from $logName"
            }
        }
        catch {
            $script:Stats.Warnings += "EventLog $logName`: $($_.Exception.Message)"
            Write-WarningMessage "  Could not export $logName log"
        }
    }

    $script:Stats.FilesCreated += $filesCreated
    return @{ Success = $true; Files = $filesCreated }
}

function New-ExportManifest {
    <#
    .SYNOPSIS
        Creates a manifest file documenting the export.
    #>
    param(
        [string]$ExportPath,
        [string[]]$Components,
        [hashtable]$Results
    )

    $manifest = [PSCustomObject]@{
        ExportDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName    = $env:COMPUTERNAME
        UserName        = $env:USERNAME
        OSVersion       = (Get-CimInstance Win32_OperatingSystem).Caption
        ScriptVersion   = $script:ScriptVersion
        Components      = $Components
        IncludedEventLogs = $IncludeEventLogs.IsPresent
        EventLogDays    = if ($IncludeEventLogs) { $EventLogDays } else { $null }
        Statistics      = @{
            FilesCreated = $script:Stats.FilesCreated
            Errors       = $script:Stats.Errors.Count
            Warnings     = $script:Stats.Warnings.Count
        }
        Results         = $Results
    }

    $manifestPath = Join-Path $ExportPath "manifest.json"
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8

    return $manifestPath
}

function Compress-ExportFolder {
    <#
    .SYNOPSIS
        Compresses the export folder into a ZIP archive.
    #>
    param([string]$FolderPath)

    $archivePath = "$FolderPath.zip"

    try {
        Compress-Archive -Path "$FolderPath\*" -DestinationPath $archivePath -Force
        Remove-Item -Path $FolderPath -Recurse -Force
        Write-Success "Created archive: $archivePath"
        return $archivePath
    }
    catch {
        $script:Stats.Errors += "Compression: $($_.Exception.Message)"
        Write-ErrorMessage "Failed to compress: $($_.Exception.Message)"
        return $FolderPath
    }
}

function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Displays the export summary to console.
    #>
    param([hashtable]$Results)

    $separator = "=" * 60
    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  SYSTEM STATE EXPORT REPORT" -ForegroundColor Cyan
    Write-Host "$separator" -ForegroundColor Cyan

    Write-Host "`nExport Location: " -NoNewline
    Write-Host $script:ExportFolder -ForegroundColor White

    Write-Host "Duration: " -NoNewline
    $duration = (Get-Date) - $script:StartTime
    Write-Host "$($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White

    Write-Host "`nCOMPONENTS:" -ForegroundColor Cyan
    foreach ($component in $Results.Keys) {
        $result = $Results[$component]
        $status = if ($result.Success) { "[+]" } else { "[-]" }
        $color = if ($result.Success) { "Green" } else { "Red" }
        Write-Host "  $status $component" -ForegroundColor $color -NoNewline
        if ($result.Count) {
            Write-Host " ($($result.Count) items)" -ForegroundColor Gray
        }
        else {
            Write-Host ""
        }
    }

    Write-Host "`nSTATISTICS:" -ForegroundColor Cyan
    Write-Host "  Files Created: $($script:Stats.FilesCreated)"

    if ($script:Stats.Warnings.Count -gt 0) {
        Write-Host "`nWARNINGS:" -ForegroundColor Yellow
        $script:Stats.Warnings | ForEach-Object { Write-Host "  [!] $_" -ForegroundColor Yellow }
    }

    if ($script:Stats.Errors.Count -gt 0) {
        Write-Host "`nERRORS:" -ForegroundColor Red
        $script:Stats.Errors | ForEach-Object { Write-Host "  [-] $_" -ForegroundColor Red }
    }

    Write-Host "`n$separator`n" -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML report of the export.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    $htmlPath = Join-Path $OutputPath "export-report.html"
    $duration = (Get-Date) - $script:StartTime

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System State Export Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .success { color: #107c10; }
        .error { color: #d13438; }
        .warning { color: #ff8c00; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { flex: 1; padding: 15px; background: #f0f0f0; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0078d4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System State Export Report</h1>
        <p><strong>Computer:</strong> $env:COMPUTERNAME | <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Duration:</strong> $($duration.ToString('hh\:mm\:ss'))</p>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">$($script:Stats.FilesCreated)</div>
                <div>Files Created</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($Results.Keys.Count)</div>
                <div>Components</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">$($script:Stats.Errors.Count)</div>
                <div>Errors</div>
            </div>
        </div>

        <h2>Export Components</h2>
        <table>
            <tr><th>Component</th><th>Status</th><th>Details</th></tr>
            $(foreach ($component in $Results.Keys) {
                $r = $Results[$component]
                $statusClass = if ($r.Success) { 'success' } else { 'error' }
                $statusText = if ($r.Success) { 'Success' } else { 'Failed' }
                $details = if ($r.Count) { "$($r.Count) items" } else { "$($r.Files) files" }
                "<tr><td>$component</td><td class='$statusClass'>$statusText</td><td>$details</td></tr>"
            })
        </table>

        <p><strong>Export Location:</strong> $script:ExportFolder</p>
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
        Generates a JSON report of the export.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    $jsonPath = Join-Path $OutputPath "export-report.json"

    $report = @{
        ComputerName = $env:COMPUTERNAME
        ExportDate   = Get-Date -Format "o"
        Duration     = ((Get-Date) - $script:StartTime).ToString()
        ExportPath   = $script:ExportFolder
        Statistics   = $script:Stats
        Results      = $Results
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
}
#endregion

#region Main Execution
try {
    Write-Host ""
    Write-InfoMessage "========================================"
    Write-InfoMessage "  System State Export v$script:ScriptVersion"
    Write-InfoMessage "========================================"

    if ($DryRun) {
        Write-WarningMessage "DRY RUN MODE - No files will be created"
    }

    # Check admin for full functionality
    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Running without admin privileges. Some exports may be limited."
    }

    # Create export folder
    if (-not (Test-Path $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $script:ExportFolder = New-ExportFolder -BasePath $Destination
    Write-InfoMessage "Export folder: $script:ExportFolder"

    # Determine components to export
    $components = Get-ExportComponents -Include $Include
    Write-InfoMessage "Components to export: $($components -join ', ')"

    # Export each component
    $results = @{}

    if ($components -contains 'Drivers') {
        $results['Drivers'] = Export-Drivers -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Registry') {
        $results['Registry'] = Export-RegistryKeys -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Network') {
        $results['Network'] = Export-NetworkConfig -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Tasks') {
        $results['Tasks'] = Export-ScheduledTasks -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Features') {
        $results['Features'] = Export-WindowsFeatures -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Services') {
        $results['Services'] = Export-Services -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    if ($components -contains 'Packages') {
        $results['Packages'] = Export-InstalledPackages -ExportPath $script:ExportFolder
        $script:Stats.ComponentsExported++
    }

    # Event logs (optional)
    if ($IncludeEventLogs) {
        $results['EventLogs'] = Export-EventLogs -ExportPath $script:ExportFolder -Days $EventLogDays
        $script:Stats.ComponentsExported++
    }

    # Create manifest
    if (-not $DryRun) {
        New-ExportManifest -ExportPath $script:ExportFolder -Components $components -Results $results | Out-Null
        $script:Stats.FilesCreated++
    }

    # Compress if requested
    if ($Compress -and -not $DryRun) {
        Write-InfoMessage "Compressing export..."
        $script:ExportFolder = Compress-ExportFolder -FolderPath $script:ExportFolder
    }

    # Generate reports
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Results $results }
        'HTML'    { Write-ConsoleReport -Results $results; Export-HTMLReport -OutputPath $Destination -Results $results }
        'JSON'    { Write-ConsoleReport -Results $results; Export-JSONReport -OutputPath $Destination -Results $results }
        'All'     {
            Write-ConsoleReport -Results $results
            Export-HTMLReport -OutputPath $Destination -Results $results
            Export-JSONReport -OutputPath $Destination -Results $results
        }
    }

    Write-Success "Export complete: $script:ExportFolder"

    if ($script:Stats.Errors.Count -gt 0) {
        exit 1
    }
    exit 0
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    Write-ErrorMessage "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
#endregion
