#Requires -Version 5.1
<#
.SYNOPSIS
    Generates comprehensive system information reports.

.DESCRIPTION
    This script generates detailed system reports including:
    - Hardware inventory (CPU, RAM, GPU, storage, motherboard)
    - Software inventory (OS, installed apps, updates)
    - Network configuration (adapters, IP, DNS, routes)
    - Security settings audit
    - Performance baseline metrics
    - Export to HTML, PDF-ready HTML, JSON, or CSV

.PARAMETER IncludeHardware
    Include hardware inventory. Default: $true.

.PARAMETER IncludeSoftware
    Include software inventory. Default: $true.

.PARAMETER IncludeNetwork
    Include network configuration. Default: $true.

.PARAMETER IncludeSecurity
    Include security settings. Default: $true.

.PARAMETER IncludePerformance
    Include performance metrics. Default: $true.

.PARAMETER OutputFormat
    Output format: Console, HTML, JSON, CSV, or All. Default: Console.

.PARAMETER OutputPath
    Directory for output files. Default: toolkit logs directory.

.PARAMETER ComputerName
    Remote computer to query. Default: local computer.

.EXAMPLE
    .\Get-SystemReport.ps1
    Generates a full system report to console.

.EXAMPLE
    .\Get-SystemReport.ps1 -OutputFormat HTML
    Generates an HTML system report.

.EXAMPLE
    .\Get-SystemReport.ps1 -IncludeHardware -OutputFormat JSON
    Generates hardware-only JSON report.

.EXAMPLE
    .\Get-SystemReport.ps1 -OutputFormat All -OutputPath "C:\Reports"
    Generates all report formats to specified directory.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+
    Recommendation: Run with administrator privileges for complete information.

.OUTPUTS
    PSCustomObject containing system information with properties:
    - Hardware, Software, Network, Security, Performance

.LINK
    https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeHardware = $true,

    [Parameter()]
    [switch]$IncludeSoftware = $true,

    [Parameter()]
    [switch]$IncludeNetwork = $true,

    [Parameter()]
    [switch]$IncludeSecurity = $true,

    [Parameter()]
    [switch]$IncludePerformance = $true,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME
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
function Get-HardwareInfo {
    <#
    .SYNOPSIS
        Gets comprehensive hardware information.
    #>
    [CmdletBinding()]
    param()

    Write-InfoMessage "Collecting hardware information..."

    $hardware = @{}

    # Computer System
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hardware.ComputerSystem = [PSCustomObject]@{
            Name              = $cs.Name
            Domain            = $cs.Domain
            Manufacturer      = $cs.Manufacturer
            Model             = $cs.Model
            SystemType        = $cs.SystemType
            TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            NumberOfProcessors = $cs.NumberOfProcessors
            NumberOfLogicalProcessors = $cs.NumberOfLogicalProcessors
        }
    } catch {
        Write-WarningMessage "Could not get computer system info: $($_.Exception.Message)"
    }

    # BIOS
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $hardware.BIOS = [PSCustomObject]@{
            Manufacturer    = $bios.Manufacturer
            Name            = $bios.Name
            Version         = $bios.Version
            SerialNumber    = $bios.SerialNumber
            ReleaseDate     = $bios.ReleaseDate
            SMBIOSVersion   = $bios.SMBIOSBIOSVersion
        }
    } catch {
        Write-WarningMessage "Could not get BIOS info: $($_.Exception.Message)"
    }

    # Motherboard
    try {
        $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
        $hardware.Motherboard = [PSCustomObject]@{
            Manufacturer = $baseboard.Manufacturer
            Product      = $baseboard.Product
            SerialNumber = $baseboard.SerialNumber
            Version      = $baseboard.Version
        }
    } catch {
        Write-WarningMessage "Could not get motherboard info: $($_.Exception.Message)"
    }

    # CPU
    try {
        $cpus = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $hardware.CPU = @()
        foreach ($cpu in $cpus) {
            $hardware.CPU += [PSCustomObject]@{
                Name                  = $cpu.Name
                Manufacturer          = $cpu.Manufacturer
                Description           = $cpu.Description
                MaxClockSpeedMHz      = $cpu.MaxClockSpeed
                NumberOfCores         = $cpu.NumberOfCores
                NumberOfLogicalProcessors = $cpu.NumberOfLogicalProcessors
                L2CacheSizeKB         = $cpu.L2CacheSize
                L3CacheSizeKB         = $cpu.L3CacheSize
                Architecture          = switch ($cpu.Architecture) {
                    0 { "x86" }
                    5 { "ARM" }
                    9 { "x64" }
                    12 { "ARM64" }
                    default { "Unknown" }
                }
                SocketDesignation     = $cpu.SocketDesignation
            }
        }
    } catch {
        Write-WarningMessage "Could not get CPU info: $($_.Exception.Message)"
    }

    # Memory
    try {
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
        $hardware.Memory = @()
        foreach ($dimm in $memory) {
            $hardware.Memory += [PSCustomObject]@{
                Manufacturer     = $dimm.Manufacturer
                CapacityGB       = [math]::Round($dimm.Capacity / 1GB, 2)
                SpeedMHz         = $dimm.Speed
                MemoryType       = switch ($dimm.SMBIOSMemoryType) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Unknown ($($dimm.SMBIOSMemoryType))" }
                }
                FormFactor       = switch ($dimm.FormFactor) {
                    8 { "DIMM" }
                    12 { "SODIMM" }
                    default { "Unknown" }
                }
                DeviceLocator    = $dimm.DeviceLocator
                PartNumber       = $dimm.PartNumber
            }
        }
        $hardware.TotalMemoryGB = ($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB
    } catch {
        Write-WarningMessage "Could not get memory info: $($_.Exception.Message)"
    }

    # Storage
    try {
        $disks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
        $hardware.Storage = @()
        foreach ($disk in $disks) {
            $hardware.Storage += [PSCustomObject]@{
                Model          = $disk.Model
                InterfaceType  = $disk.InterfaceType
                MediaType      = $disk.MediaType
                SizeGB         = [math]::Round($disk.Size / 1GB, 2)
                Partitions     = $disk.Partitions
                SerialNumber   = $disk.SerialNumber
                Status         = $disk.Status
            }
        }

        # Logical drives
        $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        $hardware.Volumes = @()
        foreach ($vol in $volumes) {
            $hardware.Volumes += [PSCustomObject]@{
                DriveLetter  = $vol.DeviceID
                VolumeName   = $vol.VolumeName
                FileSystem   = $vol.FileSystem
                SizeGB       = [math]::Round($vol.Size / 1GB, 2)
                FreeSpaceGB  = [math]::Round($vol.FreeSpace / 1GB, 2)
                FreePercent  = if ($vol.Size -gt 0) { [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 1) } else { 0 }
            }
        }
    } catch {
        Write-WarningMessage "Could not get storage info: $($_.Exception.Message)"
    }

    # GPU
    try {
        $gpus = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
        $hardware.GPU = @()
        foreach ($gpu in $gpus) {
            $hardware.GPU += [PSCustomObject]@{
                Name                = $gpu.Name
                AdapterRAMGB        = [math]::Round($gpu.AdapterRAM / 1GB, 2)
                DriverVersion       = $gpu.DriverVersion
                DriverDate          = $gpu.DriverDate
                VideoModeDescription = $gpu.VideoModeDescription
                CurrentRefreshRate  = $gpu.CurrentRefreshRate
                Status              = $gpu.Status
            }
        }
    } catch {
        Write-WarningMessage "Could not get GPU info: $($_.Exception.Message)"
    }

    # Monitors
    try {
        $monitors = Get-CimInstance -ClassName Win32_DesktopMonitor -ErrorAction Stop | Where-Object { $_.Status -eq "OK" }
        $hardware.Monitors = @()
        foreach ($monitor in $monitors) {
            $hardware.Monitors += [PSCustomObject]@{
                Name             = $monitor.Name
                ScreenWidth      = $monitor.ScreenWidth
                ScreenHeight     = $monitor.ScreenHeight
                PixelsPerXLogicalInch = $monitor.PixelsPerXLogicalInch
                Status           = $monitor.Status
            }
        }
    } catch {
        Write-WarningMessage "Could not get monitor info: $($_.Exception.Message)"
    }

    return $hardware
}

function Get-SoftwareInfo {
    <#
    .SYNOPSIS
        Gets software and OS information.
    #>
    [CmdletBinding()]
    param()

    Write-InfoMessage "Collecting software information..."

    $software = @{}

    # Operating System
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $software.OperatingSystem = [PSCustomObject]@{
            Name                = $os.Caption
            Version             = $os.Version
            BuildNumber         = $os.BuildNumber
            Architecture        = $os.OSArchitecture
            InstallDate         = $os.InstallDate
            LastBootUpTime      = $os.LastBootUpTime
            Uptime              = (Get-Date) - $os.LastBootUpTime
            RegisteredUser      = $os.RegisteredUser
            Organization        = $os.Organization
            WindowsDirectory    = $os.WindowsDirectory
            SystemDrive         = $os.SystemDrive
        }
    } catch {
        Write-WarningMessage "Could not get OS info: $($_.Exception.Message)"
    }

    # PowerShell Version
    $software.PowerShell = [PSCustomObject]@{
        Version     = $PSVersionTable.PSVersion.ToString()
        Edition     = $PSVersionTable.PSEdition
        CLRVersion  = $PSVersionTable.CLRVersion
        WSManStackVersion = $PSVersionTable.WSManStackVersion
    }

    # .NET Framework
    try {
        $dotnet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
        if ($dotnet) {
            $software.DotNetFramework = [PSCustomObject]@{
                Version = $dotnet.Version
                Release = $dotnet.Release
            }
        }
    } catch {
        Write-WarningMessage "Could not get .NET info: $($_.Exception.Message)"
    }

    # Installed Hotfixes
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 20
        $software.RecentHotfixes = @()
        foreach ($hf in $hotfixes) {
            $software.RecentHotfixes += [PSCustomObject]@{
                HotFixID    = $hf.HotFixID
                Description = $hf.Description
                InstalledOn = $hf.InstalledOn
                InstalledBy = $hf.InstalledBy
            }
        }
        $software.TotalHotfixes = (Get-HotFix).Count
    } catch {
        Write-WarningMessage "Could not get hotfix info: $($_.Exception.Message)"
    }

    # Installed Applications (count and summary)
    try {
        $apps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName }
        $software.InstalledApplicationsCount = $apps.Count
        $software.TopApplications = $apps | Select-Object DisplayName, DisplayVersion, Publisher |
            Sort-Object DisplayName | Select-Object -First 50
    } catch {
        Write-WarningMessage "Could not get installed apps: $($_.Exception.Message)"
    }

    # Windows Features
    try {
        if (Test-IsAdministrator) {
            $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq "Enabled" } | Select-Object FeatureName
            $software.EnabledFeatures = $features.FeatureName
        }
    } catch {
        Write-Verbose "Could not get Windows features (may require admin)"
    }

    return $software
}

function Get-NetworkInfo {
    <#
    .SYNOPSIS
        Gets network configuration information.
    #>
    [CmdletBinding()]
    param()

    Write-InfoMessage "Collecting network information..."

    $network = @{}

    # Network Adapters
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        $network.Adapters = @()
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -ne "WellKnown" }

            $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.AddressFamily -eq 2 }

            $network.Adapters += [PSCustomObject]@{
                Name            = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status          = $adapter.Status
                MacAddress      = $adapter.MacAddress
                LinkSpeed       = $adapter.LinkSpeed
                MediaType       = $adapter.MediaType
                IPv4Address     = ($ipConfig.IPAddress -join ", ")
                SubnetMask      = ($ipConfig.PrefixLength -join ", ")
                DefaultGateway  = (Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop
                DNSServers      = ($dnsServers.ServerAddresses -join ", ")
                DHCPEnabled     = (Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
            }
        }
    } catch {
        Write-WarningMessage "Could not get network adapter info: $($_.Exception.Message)"
    }

    # DNS Configuration
    try {
        $network.DNSClientConfiguration = Get-DnsClient -ErrorAction Stop | Select-Object -First 1
    } catch {
        Write-WarningMessage "Could not get DNS client config: $($_.Exception.Message)"
    }

    # Routing Table
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.NextHop -ne "0.0.0.0" -and $_.DestinationPrefix -ne "255.255.255.255/32" } |
            Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
        $network.RoutingTable = $routes
    } catch {
        Write-WarningMessage "Could not get routing table: $($_.Exception.Message)"
    }

    # Open Ports (listening)
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort
        $network.ListeningPorts = @()
        foreach ($listener in $listeners | Select-Object -Unique LocalPort) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            $network.ListeningPorts += [PSCustomObject]@{
                Port        = $listener.LocalPort
                Address     = $listener.LocalAddress
                ProcessName = $proc.ProcessName
                ProcessId   = $listener.OwningProcess
            }
        }
    } catch {
        Write-WarningMessage "Could not get listening ports: $($_.Exception.Message)"
    }

    # Proxy Settings
    try {
        $proxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        $network.ProxySettings = [PSCustomObject]@{
            ProxyEnabled    = [bool]$proxy.ProxyEnable
            ProxyServer     = $proxy.ProxyServer
            ProxyOverride   = $proxy.ProxyOverride
            AutoConfigURL   = $proxy.AutoConfigURL
        }
    } catch {
        Write-WarningMessage "Could not get proxy settings: $($_.Exception.Message)"
    }

    return $network
}

function Get-SecurityInfo {
    <#
    .SYNOPSIS
        Gets security configuration information.
    #>
    [CmdletBinding()]
    param()

    Write-InfoMessage "Collecting security information..."

    $security = @{}

    # Windows Defender Status
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $security.WindowsDefender = [PSCustomObject]@{
                AMServiceEnabled            = $defender.AMServiceEnabled
                AntispywareEnabled          = $defender.AntispywareEnabled
                AntivirusEnabled            = $defender.AntivirusEnabled
                RealTimeProtectionEnabled   = $defender.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
                AntivirusSignatureVersion   = $defender.AntivirusSignatureVersion
                QuickScanEndTime            = $defender.QuickScanEndTime
                FullScanEndTime             = $defender.FullScanEndTime
            }
        }
    } catch {
        Write-Verbose "Windows Defender status not available"
    }

    # Firewall Status
    try {
        $firewall = Get-NetFirewallProfile -ErrorAction Stop
        $security.Firewall = @()
        foreach ($profile in $firewall) {
            $security.Firewall += [PSCustomObject]@{
                Profile         = $profile.Name
                Enabled         = $profile.Enabled
                DefaultInboundAction = $profile.DefaultInboundAction
                DefaultOutboundAction = $profile.DefaultOutboundAction
                LogAllowed      = $profile.LogAllowed
                LogBlocked      = $profile.LogBlocked
            }
        }
    } catch {
        Write-WarningMessage "Could not get firewall status: $($_.Exception.Message)"
    }

    # BitLocker Status
    try {
        if (Test-IsAdministrator) {
            $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
            $security.BitLocker = @()
            foreach ($vol in $bitlocker) {
                $security.BitLocker += [PSCustomObject]@{
                    MountPoint      = $vol.MountPoint
                    ProtectionStatus = $vol.ProtectionStatus
                    EncryptionMethod = $vol.EncryptionMethod
                    VolumeStatus    = $vol.VolumeStatus
                    EncryptionPercentage = $vol.EncryptionPercentage
                }
            }
        }
    } catch {
        Write-Verbose "BitLocker status not available (may require admin)"
    }

    # Local Admin Accounts
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $security.LocalAdmins = @()
        foreach ($admin in $admins) {
            $security.LocalAdmins += [PSCustomObject]@{
                Name        = $admin.Name
                ObjectClass = $admin.ObjectClass
                PrincipalSource = $admin.PrincipalSource
            }
        }
    } catch {
        Write-WarningMessage "Could not get local admins: $($_.Exception.Message)"
    }

    # UAC Status
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        $security.UAC = [PSCustomObject]@{
            Enabled         = [bool]$uac.EnableLUA
            ConsentPromptBehaviorAdmin = switch ($uac.ConsentPromptBehaviorAdmin) {
                0 { "Elevate without prompting" }
                1 { "Prompt for credentials on secure desktop" }
                2 { "Prompt for consent on secure desktop" }
                3 { "Prompt for credentials" }
                4 { "Prompt for consent" }
                5 { "Prompt for consent for non-Windows binaries" }
                default { "Unknown" }
            }
            PromptOnSecureDesktop = [bool]$uac.PromptOnSecureDesktop
        }
    } catch {
        Write-WarningMessage "Could not get UAC status: $($_.Exception.Message)"
    }

    # Remote Desktop Status
    try {
        $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
        $security.RemoteDesktop = [PSCustomObject]@{
            Enabled         = -not [bool]$rdp.fDenyTSConnections
            NLARequired     = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
        }
    } catch {
        Write-WarningMessage "Could not get RDP status: $($_.Exception.Message)"
    }

    return $security
}

function Get-PerformanceInfo {
    <#
    .SYNOPSIS
        Gets current performance metrics.
    #>
    [CmdletBinding()]
    param()

    Write-InfoMessage "Collecting performance metrics..."

    $performance = @{}

    # CPU Usage
    try {
        $cpuCounter = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        $performance.CPUUsagePercent = [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 2)
    } catch {
        Write-WarningMessage "Could not get CPU usage: $($_.Exception.Message)"
    }

    # Memory Usage
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $performance.Memory = [PSCustomObject]@{
            TotalGB         = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            FreeGB          = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            UsedGB          = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
            UsedPercent     = [math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100, 1)
        }
    } catch {
        Write-WarningMessage "Could not get memory usage: $($_.Exception.Message)"
    }

    # Top Processes
    try {
        $processes = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10
        $performance.TopProcesses = @()
        foreach ($proc in $processes) {
            $performance.TopProcesses += [PSCustomObject]@{
                Name        = $proc.ProcessName
                Id          = $proc.Id
                MemoryMB    = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                CPUSeconds  = [math]::Round($proc.CPU, 2)
                Handles     = $proc.HandleCount
            }
        }
    } catch {
        Write-WarningMessage "Could not get process info: $($_.Exception.Message)"
    }

    # Services Status
    try {
        $services = Get-Service -ErrorAction Stop
        $performance.Services = [PSCustomObject]@{
            Total       = $services.Count
            Running     = ($services | Where-Object { $_.Status -eq 'Running' }).Count
            Stopped     = ($services | Where-Object { $_.Status -eq 'Stopped' }).Count
            StartPending = ($services | Where-Object { $_.Status -eq 'StartPending' }).Count
            StopPending  = ($services | Where-Object { $_.Status -eq 'StopPending' }).Count
        }
    } catch {
        Write-WarningMessage "Could not get service status: $($_.Exception.Message)"
    }

    return $performance
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports system report to HTML format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ReportData,

        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Information Report - $($ReportData.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        h3 { color: #666; margin-top: 20px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .info-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #0078d4; }
        .info-card h4 { margin: 0 0 10px 0; color: #0078d4; }
        .info-row { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #eee; }
        .info-label { color: #666; }
        .info-value { font-weight: 500; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }
        th { background: #0078d4; color: white; padding: 10px 8px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        .timestamp { color: #666; font-size: 12px; }
        .toc { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .toc a { color: #0078d4; text-decoration: none; display: block; padding: 5px 0; }
        .toc a:hover { text-decoration: underline; }
        @media print { .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Information Report</h1>
        <p class="timestamp">Computer: <strong>$($ReportData.ComputerName)</strong> | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="toc">
            <strong>Table of Contents</strong>
"@

    if ($ReportData.Hardware) { $html += '<a href="#hardware">Hardware Information</a>' }
    if ($ReportData.Software) { $html += '<a href="#software">Software Information</a>' }
    if ($ReportData.Network) { $html += '<a href="#network">Network Configuration</a>' }
    if ($ReportData.Security) { $html += '<a href="#security">Security Settings</a>' }
    if ($ReportData.Performance) { $html += '<a href="#performance">Performance Metrics</a>' }

    $html += "</div>"

    # Hardware Section
    if ($ReportData.Hardware) {
        $hw = $ReportData.Hardware
        $html += @"
        <h2 id="hardware">Hardware Information</h2>
        <div class="info-grid">
            <div class="info-card">
                <h4>System</h4>
                <div class="info-row"><span class="info-label">Manufacturer</span><span class="info-value">$($hw.ComputerSystem.Manufacturer)</span></div>
                <div class="info-row"><span class="info-label">Model</span><span class="info-value">$($hw.ComputerSystem.Model)</span></div>
                <div class="info-row"><span class="info-label">System Type</span><span class="info-value">$($hw.ComputerSystem.SystemType)</span></div>
                <div class="info-row"><span class="info-label">Total Memory</span><span class="info-value">$($hw.ComputerSystem.TotalPhysicalMemoryGB) GB</span></div>
            </div>
            <div class="info-card">
                <h4>BIOS</h4>
                <div class="info-row"><span class="info-label">Manufacturer</span><span class="info-value">$($hw.BIOS.Manufacturer)</span></div>
                <div class="info-row"><span class="info-label">Version</span><span class="info-value">$($hw.BIOS.Version)</span></div>
                <div class="info-row"><span class="info-label">Serial</span><span class="info-value">$($hw.BIOS.SerialNumber)</span></div>
            </div>
        </div>
"@

        # CPU
        if ($hw.CPU) {
            $html += "<h3>Processors</h3><table><tr><th>Name</th><th>Cores</th><th>Logical</th><th>Max Speed</th><th>Architecture</th></tr>"
            foreach ($cpu in $hw.CPU) {
                $html += "<tr><td>$($cpu.Name)</td><td>$($cpu.NumberOfCores)</td><td>$($cpu.NumberOfLogicalProcessors)</td><td>$($cpu.MaxClockSpeedMHz) MHz</td><td>$($cpu.Architecture)</td></tr>"
            }
            $html += "</table>"
        }

        # Memory
        if ($hw.Memory) {
            $html += "<h3>Memory Modules</h3><table><tr><th>Manufacturer</th><th>Capacity</th><th>Speed</th><th>Type</th><th>Location</th></tr>"
            foreach ($mem in $hw.Memory) {
                $html += "<tr><td>$($mem.Manufacturer)</td><td>$($mem.CapacityGB) GB</td><td>$($mem.SpeedMHz) MHz</td><td>$($mem.MemoryType)</td><td>$($mem.DeviceLocator)</td></tr>"
            }
            $html += "</table>"
        }

        # Storage
        if ($hw.Volumes) {
            $html += "<h3>Storage Volumes</h3><table><tr><th>Drive</th><th>Label</th><th>File System</th><th>Size</th><th>Free</th><th>Free %</th></tr>"
            foreach ($vol in $hw.Volumes) {
                $freeClass = if ($vol.FreePercent -lt 10) { "status-error" } elseif ($vol.FreePercent -lt 20) { "status-warning" } else { "status-ok" }
                $html += "<tr><td>$($vol.DriveLetter)</td><td>$($vol.VolumeName)</td><td>$($vol.FileSystem)</td><td>$($vol.SizeGB) GB</td><td>$($vol.FreeSpaceGB) GB</td><td class='$freeClass'>$($vol.FreePercent)%</td></tr>"
            }
            $html += "</table>"
        }

        # GPU
        if ($hw.GPU) {
            $html += "<h3>Graphics</h3><table><tr><th>Name</th><th>RAM</th><th>Driver Version</th><th>Resolution</th></tr>"
            foreach ($gpu in $hw.GPU) {
                $html += "<tr><td>$($gpu.Name)</td><td>$($gpu.AdapterRAMGB) GB</td><td>$($gpu.DriverVersion)</td><td>$($gpu.VideoModeDescription)</td></tr>"
            }
            $html += "</table>"
        }
    }

    # Software Section
    if ($ReportData.Software) {
        $sw = $ReportData.Software
        $html += @"
        <h2 id="software">Software Information</h2>
        <div class="info-grid">
            <div class="info-card">
                <h4>Operating System</h4>
                <div class="info-row"><span class="info-label">Name</span><span class="info-value">$($sw.OperatingSystem.Name)</span></div>
                <div class="info-row"><span class="info-label">Version</span><span class="info-value">$($sw.OperatingSystem.Version)</span></div>
                <div class="info-row"><span class="info-label">Build</span><span class="info-value">$($sw.OperatingSystem.BuildNumber)</span></div>
                <div class="info-row"><span class="info-label">Architecture</span><span class="info-value">$($sw.OperatingSystem.Architecture)</span></div>
                <div class="info-row"><span class="info-label">Last Boot</span><span class="info-value">$($sw.OperatingSystem.LastBootUpTime)</span></div>
            </div>
            <div class="info-card">
                <h4>PowerShell</h4>
                <div class="info-row"><span class="info-label">Version</span><span class="info-value">$($sw.PowerShell.Version)</span></div>
                <div class="info-row"><span class="info-label">Edition</span><span class="info-value">$($sw.PowerShell.Edition)</span></div>
            </div>
        </div>
        <p>Total Installed Applications: <strong>$($sw.InstalledApplicationsCount)</strong> | Total Hotfixes: <strong>$($sw.TotalHotfixes)</strong></p>
"@
    }

    # Network Section
    if ($ReportData.Network) {
        $net = $ReportData.Network
        $html += "<h2 id='network'>Network Configuration</h2>"
        if ($net.Adapters) {
            $html += "<h3>Network Adapters</h3><table><tr><th>Name</th><th>Status</th><th>IP Address</th><th>Gateway</th><th>DNS</th><th>Speed</th></tr>"
            foreach ($adapter in $net.Adapters) {
                $html += "<tr><td>$($adapter.Name)</td><td class='status-ok'>$($adapter.Status)</td><td>$($adapter.IPv4Address)</td><td>$($adapter.DefaultGateway)</td><td>$($adapter.DNSServers)</td><td>$($adapter.LinkSpeed)</td></tr>"
            }
            $html += "</table>"
        }
    }

    # Security Section
    if ($ReportData.Security) {
        $sec = $ReportData.Security
        $html += "<h2 id='security'>Security Settings</h2><div class='info-grid'>"

        if ($sec.WindowsDefender) {
            $defenderStatus = if ($sec.WindowsDefender.RealTimeProtectionEnabled) { "status-ok" } else { "status-error" }
            $html += @"
            <div class="info-card">
                <h4>Windows Defender</h4>
                <div class="info-row"><span class="info-label">Real-Time Protection</span><span class="info-value $defenderStatus">$(if($sec.WindowsDefender.RealTimeProtectionEnabled){'Enabled'}else{'Disabled'})</span></div>
                <div class="info-row"><span class="info-label">Antivirus Enabled</span><span class="info-value">$($sec.WindowsDefender.AntivirusEnabled)</span></div>
                <div class="info-row"><span class="info-label">Signature Updated</span><span class="info-value">$($sec.WindowsDefender.AntivirusSignatureLastUpdated)</span></div>
            </div>
"@
        }

        if ($sec.Firewall) {
            $html += "<div class='info-card'><h4>Firewall</h4>"
            foreach ($profile in $sec.Firewall) {
                $fwStatus = if ($profile.Enabled) { "status-ok" } else { "status-warning" }
                $html += "<div class='info-row'><span class='info-label'>$($profile.Profile)</span><span class='info-value $fwStatus'>$(if($profile.Enabled){'Enabled'}else{'Disabled'})</span></div>"
            }
            $html += "</div>"
        }

        $html += "</div>"
    }

    # Performance Section
    if ($ReportData.Performance) {
        $perf = $ReportData.Performance
        $html += @"
        <h2 id="performance">Performance Metrics</h2>
        <div class="info-grid">
            <div class="info-card">
                <h4>CPU</h4>
                <div class="info-row"><span class="info-label">Current Usage</span><span class="info-value">$($perf.CPUUsagePercent)%</span></div>
            </div>
            <div class="info-card">
                <h4>Memory</h4>
                <div class="info-row"><span class="info-label">Total</span><span class="info-value">$($perf.Memory.TotalGB) GB</span></div>
                <div class="info-row"><span class="info-label">Used</span><span class="info-value">$($perf.Memory.UsedGB) GB ($($perf.Memory.UsedPercent)%)</span></div>
                <div class="info-row"><span class="info-label">Free</span><span class="info-value">$($perf.Memory.FreeGB) GB</span></div>
            </div>
            <div class="info-card">
                <h4>Services</h4>
                <div class="info-row"><span class="info-label">Running</span><span class="info-value">$($perf.Services.Running)</span></div>
                <div class="info-row"><span class="info-label">Stopped</span><span class="info-value">$($perf.Services.Stopped)</span></div>
                <div class="info-row"><span class="info-label">Total</span><span class="info-value">$($perf.Services.Total)</span></div>
            </div>
        </div>
"@
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
function Invoke-SystemReport {
    [CmdletBinding()]
    param()

    Write-InfoMessage "Generating System Information Report for $ComputerName"

    # Check for admin privileges
    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Running without administrator privileges. Some information may be limited."
    }

    # Set output path
    if (-not $OutputPath) {
        $OutputPath = Get-LogDirectory
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Collect data
    $reportData = [PSCustomObject]@{
        ComputerName = $ComputerName
        ReportDate   = Get-Date
        Hardware     = $null
        Software     = $null
        Network      = $null
        Security     = $null
        Performance  = $null
    }

    if ($IncludeHardware) { $reportData.Hardware = Get-HardwareInfo }
    if ($IncludeSoftware) { $reportData.Software = Get-SoftwareInfo }
    if ($IncludeNetwork) { $reportData.Network = Get-NetworkInfo }
    if ($IncludeSecurity) { $reportData.Security = Get-SecurityInfo }
    if ($IncludePerformance) { $reportData.Performance = Get-PerformanceInfo }

    # Output results based on format
    switch ($OutputFormat) {
        'Console' {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "       SYSTEM INFORMATION REPORT        " -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Computer: $ComputerName"
            Write-Host "Report Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Write-Host ""

            if ($reportData.Hardware) {
                Write-Host "HARDWARE" -ForegroundColor Yellow
                Write-Host "--------"
                Write-Host "  System: $($reportData.Hardware.ComputerSystem.Manufacturer) $($reportData.Hardware.ComputerSystem.Model)"
                Write-Host "  CPU: $(($reportData.Hardware.CPU | Select-Object -First 1).Name)"
                Write-Host "  RAM: $($reportData.Hardware.TotalMemoryGB) GB"
                Write-Host "  Drives: $(($reportData.Hardware.Volumes | ForEach-Object { "$($_.DriveLetter) ($($_.FreeGB)GB free)" }) -join ', ')"
                Write-Host ""
            }

            if ($reportData.Software) {
                Write-Host "SOFTWARE" -ForegroundColor Yellow
                Write-Host "--------"
                Write-Host "  OS: $($reportData.Software.OperatingSystem.Name)"
                Write-Host "  Version: $($reportData.Software.OperatingSystem.Version) (Build $($reportData.Software.OperatingSystem.BuildNumber))"
                Write-Host "  Uptime: $($reportData.Software.OperatingSystem.Uptime.Days) days, $($reportData.Software.OperatingSystem.Uptime.Hours) hours"
                Write-Host "  Installed Apps: $($reportData.Software.InstalledApplicationsCount)"
                Write-Host ""
            }

            if ($reportData.Network) {
                Write-Host "NETWORK" -ForegroundColor Yellow
                Write-Host "-------"
                foreach ($adapter in $reportData.Network.Adapters) {
                    Write-Host "  $($adapter.Name): $($adapter.IPv4Address) ($($adapter.LinkSpeed))"
                }
                Write-Host ""
            }

            if ($reportData.Security) {
                Write-Host "SECURITY" -ForegroundColor Yellow
                Write-Host "--------"
                if ($reportData.Security.WindowsDefender) {
                    $defenderStatus = if ($reportData.Security.WindowsDefender.RealTimeProtectionEnabled) { "[+] Enabled" } else { "[-] Disabled" }
                    Write-Host "  Windows Defender: $defenderStatus"
                }
                Write-Host "  Local Admins: $(($reportData.Security.LocalAdmins | ForEach-Object { $_.Name.Split('\')[-1] }) -join ', ')"
                Write-Host ""
            }

            if ($reportData.Performance) {
                Write-Host "PERFORMANCE" -ForegroundColor Yellow
                Write-Host "-----------"
                Write-Host "  CPU Usage: $($reportData.Performance.CPUUsagePercent)%"
                Write-Host "  Memory Usage: $($reportData.Performance.Memory.UsedGB) GB / $($reportData.Performance.Memory.TotalGB) GB ($($reportData.Performance.Memory.UsedPercent)%)"
                Write-Host "  Services: $($reportData.Performance.Services.Running) running / $($reportData.Performance.Services.Total) total"
            }
        }

        'HTML' {
            $htmlFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.html"
            Export-HtmlReport -ReportData $reportData -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"
        }

        'JSON' {
            $jsonFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.json"
            $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"
        }

        'CSV' {
            # CSV export - flatten key data into single row
            $csvFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.csv"
            $flatData = [PSCustomObject]@{
                ComputerName    = $ComputerName
                ReportDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Manufacturer    = $reportData.Hardware.ComputerSystem.Manufacturer
                Model           = $reportData.Hardware.ComputerSystem.Model
                TotalMemoryGB   = $reportData.Hardware.TotalMemoryGB
                OSName          = $reportData.Software.OperatingSystem.Name
                OSVersion       = $reportData.Software.OperatingSystem.Version
                CPUUsage        = $reportData.Performance.CPUUsagePercent
                MemoryUsage     = $reportData.Performance.Memory.UsedPercent
            }
            $flatData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"
        }

        'All' {
            # HTML
            $htmlFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.html"
            Export-HtmlReport -ReportData $reportData -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"

            # JSON
            $jsonFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.json"
            $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"

            # CSV
            $csvFile = Join-Path $OutputPath "SystemReport_${ComputerName}_$timestamp.csv"
            $flatData = [PSCustomObject]@{
                ComputerName    = $ComputerName
                ReportDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Manufacturer    = $reportData.Hardware.ComputerSystem.Manufacturer
                Model           = $reportData.Hardware.ComputerSystem.Model
                TotalMemoryGB   = $reportData.Hardware.TotalMemoryGB
                OSName          = $reportData.Software.OperatingSystem.Name
                OSVersion       = $reportData.Software.OperatingSystem.Version
                CPUUsage        = $reportData.Performance.CPUUsagePercent
                MemoryUsage     = $reportData.Performance.Memory.UsedPercent
            }
            $flatData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"
        }
    }

    Write-Success "System report generation completed"

    return $reportData
}

# Run the report
$result = Invoke-SystemReport
#endregion
