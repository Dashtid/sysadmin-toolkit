#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Comprehensive network diagnostics suite for connectivity testing and troubleshooting.

.DESCRIPTION
    This script provides extensive network diagnostic capabilities including:
    - Connectivity testing to configured hosts (ping, TCP port tests)
    - DNS resolution validation
    - Port availability testing for common services
    - Traceroute to key destinations
    - Network adapter information and statistics
    - Proxy and DNS configuration detection
    - Network speed estimation
    - Comprehensive HTML/JSON report generation

    Key features:
    - Test internal and external connectivity
    - Validate DNS resolution for critical domains
    - Check common service ports (HTTP, HTTPS, SSH, RDP, etc.)
    - Detect potential network issues (proxy, firewall, DNS)
    - Color-coded pass/fail indicators
    - Historical comparison support

.PARAMETER Hosts
    Array of hostnames or IP addresses to test connectivity.

.PARAMETER Ports
    Array of ports to test for each host. Default: 80, 443

.PARAMETER DNSServers
    DNS servers to test. If not specified, uses system DNS.

.PARAMETER DomainsToResolve
    Domains to test DNS resolution for.

.PARAMETER TracerouteTargets
    Targets for traceroute testing.

.PARAMETER TestTimeout
    Timeout in seconds for connectivity tests. Default: 5

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON, All.
    Default: Console

.PARAMETER OutputPath
    Directory path for output files.

.PARAMETER SkipDNS
    Skip DNS resolution tests.

.PARAMETER SkipTraceroute
    Skip traceroute tests.

.PARAMETER SkipPortScan
    Skip port connectivity tests.

.PARAMETER QuickTest
    Run a quick test with minimal hosts and ports.

.PARAMETER ConfigFile
    Path to JSON configuration file containing test targets.

.EXAMPLE
    .\Test-NetworkHealth.ps1
    Runs default network diagnostics with console output.

.EXAMPLE
    .\Test-NetworkHealth.ps1 -Hosts "google.com", "8.8.8.8" -Ports 80, 443, 22
    Tests specific hosts on specified ports.

.EXAMPLE
    .\Test-NetworkHealth.ps1 -OutputFormat HTML -OutputPath "C:\Reports"
    Generates HTML network health report.

.EXAMPLE
    .\Test-NetworkHealth.ps1 -QuickTest
    Runs a quick connectivity test.

.EXAMPLE
    .\Test-NetworkHealth.ps1 -TracerouteTargets "8.8.8.8" -SkipPortScan
    Runs traceroute only.

.NOTES
    File Name      : Test-NetworkHealth.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+
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
    [string[]]$Hosts,

    [Parameter()]
    [int[]]$Ports,

    [Parameter()]
    [string[]]$DNSServers,

    [Parameter()]
    [string[]]$DomainsToResolve,

    [Parameter()]
    [string[]]$TracerouteTargets,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$TestTimeout = 5,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$SkipDNS,

    [Parameter()]
    [switch]$SkipTraceroute,

    [Parameter()]
    [switch]$SkipPortScan,

    [Parameter()]
    [switch]$QuickTest,

    [Parameter()]
    [string]$ConfigFile
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
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"

# Default test targets
$script:DefaultHosts = @(
    '8.8.8.8',           # Google DNS
    '1.1.1.1',           # Cloudflare DNS
    'google.com',        # Google
    'microsoft.com',     # Microsoft
    'github.com'         # GitHub
)

$script:DefaultPorts = @(80, 443)

$script:DefaultDomainsToResolve = @(
    'google.com',
    'microsoft.com',
    'github.com',
    'cloudflare.com',
    'dns.google'
)

$script:CommonPorts = @{
    20   = 'FTP-Data'
    21   = 'FTP'
    22   = 'SSH'
    23   = 'Telnet'
    25   = 'SMTP'
    53   = 'DNS'
    80   = 'HTTP'
    110  = 'POP3'
    143  = 'IMAP'
    443  = 'HTTPS'
    445  = 'SMB'
    587  = 'SMTP-TLS'
    993  = 'IMAPS'
    995  = 'POP3S'
    1433 = 'MSSQL'
    3306 = 'MySQL'
    3389 = 'RDP'
    5432 = 'PostgreSQL'
    5985 = 'WinRM-HTTP'
    5986 = 'WinRM-HTTPS'
    8080 = 'HTTP-Alt'
    8443 = 'HTTPS-Alt'
}

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
        if ($config.Hosts -and -not $PSBoundParameters.ContainsKey('Hosts')) {
            $Hosts = $config.Hosts
        }
        if ($config.Ports -and -not $PSBoundParameters.ContainsKey('Ports')) {
            $Ports = $config.Ports
        }
        if ($config.DomainsToResolve -and -not $PSBoundParameters.ContainsKey('DomainsToResolve')) {
            $DomainsToResolve = $config.DomainsToResolve
        }
        Write-InfoMessage "Loaded configuration from: $ConfigFile"
    }
    catch {
        Write-WarningMessage "Failed to load configuration file: $($_.Exception.Message)"
    }
}

# Apply defaults
if (-not $Hosts -or $Hosts.Count -eq 0) {
    $Hosts = if ($QuickTest) { @('8.8.8.8', 'google.com') } else { $script:DefaultHosts }
}

if (-not $Ports -or $Ports.Count -eq 0) {
    $Ports = if ($QuickTest) { @(443) } else { $script:DefaultPorts }
}

if (-not $DomainsToResolve -or $DomainsToResolve.Count -eq 0) {
    $DomainsToResolve = if ($QuickTest) { @('google.com', 'microsoft.com') } else { $script:DefaultDomainsToResolve }
}

if (-not $TracerouteTargets -or $TracerouteTargets.Count -eq 0) {
    $TracerouteTargets = @('8.8.8.8')
}
#endregion

#region Network Information Functions
function Get-NetworkAdapterInfo {
    <#
    .SYNOPSIS
        Gets detailed network adapter information.
    #>
    [CmdletBinding()]
    param()

    $adapters = @()

    try {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }

        foreach ($adapter in $netAdapters) {
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }

            $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.AddressFamily -eq 2 } | Select-Object -ExpandProperty ServerAddresses

            $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty NextHop -First 1

            $adapters += @{
                Name           = $adapter.Name
                Description    = $adapter.InterfaceDescription
                MacAddress     = $adapter.MacAddress
                Speed          = "$([math]::Round($adapter.LinkSpeed / 1000000))Mbps"
                Status         = $adapter.Status
                IPAddress      = ($ipConfig | Select-Object -ExpandProperty IPAddress) -join ', '
                SubnetMask     = if ($ipConfig) { "/$($ipConfig.PrefixLength)" } else { '' }
                Gateway        = $gateway
                DNSServers     = $dnsServers -join ', '
                DHCPEnabled    = ($ipConfig | Select-Object -First 1).PrefixOrigin -eq 'Dhcp'
            }
        }
    }
    catch {
        Write-WarningMessage "Error getting network adapter info: $($_.Exception.Message)"
    }

    return $adapters
}

function Get-NetworkConfiguration {
    <#
    .SYNOPSIS
        Gets current network configuration including proxy settings.
    #>
    [CmdletBinding()]
    param()

    $config = @{
        Hostname       = $env:COMPUTERNAME
        Domain         = $env:USERDNSDOMAIN
        ProxyEnabled   = $false
        ProxyServer    = $null
        ProxyBypass    = $null
        WINSEnabled    = $false
    }

    try {
        # Check IE/Windows proxy settings
        $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxySettings = Get-ItemProperty -Path $proxyKey -ErrorAction SilentlyContinue

        if ($proxySettings) {
            $config.ProxyEnabled = [bool]$proxySettings.ProxyEnable
            $config.ProxyServer = $proxySettings.ProxyServer
            $config.ProxyBypass = $proxySettings.ProxyOverride
        }

        # Check system proxy
        $envProxy = $env:HTTP_PROXY ?? $env:HTTPS_PROXY
        if ($envProxy) {
            $config.ProxyEnabled = $true
            $config.ProxyServer = $envProxy
        }
    }
    catch {
        Write-Verbose "Error checking proxy settings: $($_.Exception.Message)"
    }

    return $config
}
#endregion

#region Connectivity Test Functions
function Test-HostConnectivity {
    <#
    .SYNOPSIS
        Tests basic connectivity to a host using ping.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [int]$Count = 4,

        [int]$Timeout = $TestTimeout
    )

    $result = @{
        Host          = $HostName
        Success       = $false
        ResponseTime  = $null
        MinTime       = $null
        MaxTime       = $null
        AvgTime       = $null
        PacketLoss    = 100
        IPAddress     = $null
        Error         = $null
    }

    try {
        $pingResults = Test-Connection -ComputerName $HostName -Count $Count -ErrorAction Stop

        if ($pingResults) {
            $successfulPings = $pingResults | Where-Object { $_.StatusCode -eq 0 -or $_.Status -eq 'Success' }

            if ($successfulPings) {
                $result.Success = $true

                # Handle both PowerShell 5 and 7 response time properties
                $times = $successfulPings | ForEach-Object {
                    if ($null -ne $_.ResponseTime) { $_.ResponseTime }
                    elseif ($null -ne $_.Latency) { $_.Latency }
                    else { 0 }
                }

                if ($times) {
                    $result.MinTime = ($times | Measure-Object -Minimum).Minimum
                    $result.MaxTime = ($times | Measure-Object -Maximum).Maximum
                    $result.AvgTime = [math]::Round(($times | Measure-Object -Average).Average, 2)
                    $result.ResponseTime = $result.AvgTime
                }

                $result.PacketLoss = [math]::Round((($Count - $successfulPings.Count) / $Count) * 100, 0)

                # Get IP address
                $firstResult = $successfulPings | Select-Object -First 1
                $result.IPAddress = if ($firstResult.Address) { $firstResult.Address.ToString() }
                                   elseif ($firstResult.IPV4Address) { $firstResult.IPV4Address.ToString() }
                                   else { $null }
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-PortConnectivity {
    <#
    .SYNOPSIS
        Tests TCP port connectivity to a host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$Timeout = $TestTimeout
    )

    $result = @{
        Host        = $HostName
        Port        = $Port
        ServiceName = $script:CommonPorts[$Port] ?? 'Unknown'
        Success     = $false
        ResponseMs  = $null
        Error       = $null
    }

    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Use Test-NetConnection if available (more reliable), fallback to TcpClient
        if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
            $testResult = Test-NetConnection -ComputerName $HostName -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

            $stopwatch.Stop()

            if ($testResult.TcpTestSucceeded) {
                $result.Success = $true
                $result.ResponseMs = $stopwatch.ElapsedMilliseconds
            }
            else {
                $result.Error = "Port $Port is not reachable"
            }
        }
        else {
            # Fallback to TcpClient
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcpClient.ConnectAsync($HostName, $Port)

            if ($connectTask.Wait($Timeout * 1000)) {
                $stopwatch.Stop()
                if ($tcpClient.Connected) {
                    $result.Success = $true
                    $result.ResponseMs = $stopwatch.ElapsedMilliseconds
                }
            }
            else {
                $result.Error = "Connection timed out"
            }

            $tcpClient.Close()
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-DNSResolution {
    <#
    .SYNOPSIS
        Tests DNS resolution for a domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [string]$DNSServer
    )

    $result = @{
        Domain      = $Domain
        Success     = $false
        IPAddresses = @()
        ResponseMs  = $null
        DNSServer   = $DNSServer ?? 'System Default'
        RecordType  = 'A'
        Error       = $null
    }

    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $params = @{
            Name        = $Domain
            Type        = 'A'
            ErrorAction = 'Stop'
        }

        if ($DNSServer) {
            $params['Server'] = $DNSServer
        }

        $dnsResult = Resolve-DnsName @params

        $stopwatch.Stop()

        if ($dnsResult) {
            $result.Success = $true
            $result.ResponseMs = $stopwatch.ElapsedMilliseconds
            $result.IPAddresses = ($dnsResult | Where-Object { $_.Type -eq 'A' } | Select-Object -ExpandProperty IPAddress)

            # Also check for AAAA records
            $ipv6Results = $dnsResult | Where-Object { $_.Type -eq 'AAAA' }
            if ($ipv6Results) {
                $result.IPAddresses += ($ipv6Results | Select-Object -ExpandProperty IPAddress)
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Invoke-Traceroute {
    <#
    .SYNOPSIS
        Performs a traceroute to a target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int]$MaxHops = 30,

        [int]$Timeout = 3000
    )

    $result = @{
        Target      = $Target
        Success     = $false
        Hops        = @()
        TotalHops   = 0
        TotalTimeMs = 0
        Error       = $null
    }

    try {
        Write-InfoMessage "Running traceroute to $Target (max $MaxHops hops)..."

        # Use Test-NetConnection with TraceRoute if available
        $traceResult = Test-NetConnection -ComputerName $Target -TraceRoute -WarningAction SilentlyContinue -ErrorAction Stop

        if ($traceResult.TraceRoute) {
            $result.Success = $traceResult.PingSucceeded
            $hopNumber = 1

            foreach ($hop in $traceResult.TraceRoute) {
                $hopInfo = @{
                    Hop       = $hopNumber
                    Address   = $hop
                    HostName  = $null
                    TimeMs    = $null
                }

                # Try to resolve hostname
                try {
                    $resolved = Resolve-DnsName -Name $hop -ErrorAction SilentlyContinue
                    if ($resolved.NameHost) {
                        $hopInfo.HostName = $resolved.NameHost
                    }
                }
                catch { }

                $result.Hops += $hopInfo
                $hopNumber++
            }

            $result.TotalHops = $result.Hops.Count
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}
#endregion

#region Report Generation Functions
function Get-NetworkHealthReport {
    <#
    .SYNOPSIS
        Generates comprehensive network health report.
    #>
    [CmdletBinding()]
    param()

    $report = @{
        Timestamp         = Get-Date -Format 'o'
        ComputerName      = $env:COMPUTERNAME
        NetworkConfig     = $null
        Adapters          = @()
        ConnectivityTests = @()
        PortTests         = @()
        DNSTests          = @()
        TracerouteResults = @()
        Summary           = @{
            TotalTests    = 0
            PassedTests   = 0
            FailedTests   = 0
            Warnings      = 0
        }
        Alerts            = @()
    }

    # Get network configuration
    Write-InfoMessage "Getting network configuration..."
    $report.NetworkConfig = Get-NetworkConfiguration

    # Get adapter information
    Write-InfoMessage "Getting network adapter information..."
    $report.Adapters = Get-NetworkAdapterInfo

    if ($report.Adapters.Count -eq 0) {
        $report.Alerts += @{
            Level   = 'Critical'
            Type    = 'NoAdapter'
            Message = 'No active network adapters found'
        }
    }

    # Check proxy configuration
    if ($report.NetworkConfig.ProxyEnabled) {
        $report.Alerts += @{
            Level   = 'Info'
            Type    = 'Proxy'
            Message = "Proxy enabled: $($report.NetworkConfig.ProxyServer)"
        }
    }

    # Connectivity tests (ping)
    Write-InfoMessage "Testing host connectivity..."
    foreach ($targetHost in $Hosts) {
        $connectResult = Test-HostConnectivity -HostName $targetHost
        $report.ConnectivityTests += $connectResult
        $report.Summary.TotalTests++

        if ($connectResult.Success) {
            $report.Summary.PassedTests++

            # Check for high latency
            if ($connectResult.AvgTime -gt 200) {
                $report.Summary.Warnings++
                $report.Alerts += @{
                    Level   = 'Warning'
                    Type    = 'HighLatency'
                    Message = "High latency to $host`: $($connectResult.AvgTime)ms"
                }
            }

            # Check for packet loss
            if ($connectResult.PacketLoss -gt 0) {
                $report.Summary.Warnings++
                $report.Alerts += @{
                    Level   = 'Warning'
                    Type    = 'PacketLoss'
                    Message = "Packet loss to $host`: $($connectResult.PacketLoss)%"
                }
            }
        }
        else {
            $report.Summary.FailedTests++
            $report.Alerts += @{
                Level   = 'Critical'
                Type    = 'ConnectivityFailed'
                Message = "Cannot reach $host`: $($connectResult.Error)"
            }
        }
    }

    # Port connectivity tests
    if (-not $SkipPortScan) {
        Write-InfoMessage "Testing port connectivity..."
        foreach ($targetHost in $Hosts) {
            foreach ($port in $Ports) {
                $portResult = Test-PortConnectivity -HostName $targetHost -Port $port
                $report.PortTests += $portResult
                $report.Summary.TotalTests++

                if ($portResult.Success) {
                    $report.Summary.PassedTests++
                }
                else {
                    $report.Summary.FailedTests++
                    $report.Alerts += @{
                        Level   = 'Warning'
                        Type    = 'PortBlocked'
                        Message = "Port $port ($($portResult.ServiceName)) blocked on $host"
                    }
                }
            }
        }
    }

    # DNS resolution tests
    if (-not $SkipDNS) {
        Write-InfoMessage "Testing DNS resolution..."
        foreach ($domain in $DomainsToResolve) {
            $dnsResult = Test-DNSResolution -Domain $domain
            $report.DNSTests += $dnsResult
            $report.Summary.TotalTests++

            if ($dnsResult.Success) {
                $report.Summary.PassedTests++
            }
            else {
                $report.Summary.FailedTests++
                $report.Alerts += @{
                    Level   = 'Critical'
                    Type    = 'DNSFailure'
                    Message = "DNS resolution failed for $domain`: $($dnsResult.Error)"
                }
            }
        }

        # Test with custom DNS servers if specified
        if ($DNSServers) {
            foreach ($dnsServer in $DNSServers) {
                $testDomain = $DomainsToResolve | Select-Object -First 1
                $dnsResult = Test-DNSResolution -Domain $testDomain -DNSServer $dnsServer
                $dnsResult.DNSServer = $dnsServer
                $report.DNSTests += $dnsResult
                $report.Summary.TotalTests++

                if ($dnsResult.Success) {
                    $report.Summary.PassedTests++
                }
                else {
                    $report.Summary.FailedTests++
                    $report.Alerts += @{
                        Level   = 'Warning'
                        Type    = 'DNSServerFailure'
                        Message = "DNS server $dnsServer failed to resolve $testDomain"
                    }
                }
            }
        }
    }

    # Traceroute tests
    if (-not $SkipTraceroute -and -not $QuickTest) {
        Write-InfoMessage "Running traceroute tests..."
        foreach ($target in $TracerouteTargets) {
            $traceResult = Invoke-Traceroute -Target $target
            $report.TracerouteResults += $traceResult

            if (-not $traceResult.Success) {
                $report.Alerts += @{
                    Level   = 'Warning'
                    Type    = 'TracerouteIncomplete'
                    Message = "Traceroute to $target did not complete successfully"
                }
            }
        }
    }

    return $report
}

function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Outputs network health report to console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report
    )

    $separator = "=" * 70

    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  NETWORK HEALTH REPORT" -ForegroundColor Cyan
    Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "  Computer:  $($Report.ComputerName)" -ForegroundColor Cyan
    Write-Host "$separator`n" -ForegroundColor Cyan

    # Summary
    Write-Host "SUMMARY" -ForegroundColor White
    Write-Host "-" * 50
    Write-Host "  Total Tests:  $($Report.Summary.TotalTests)"
    Write-Host "  Passed:       " -NoNewline
    Write-Host "$($Report.Summary.PassedTests)" -ForegroundColor Green
    Write-Host "  Failed:       " -NoNewline
    if ($Report.Summary.FailedTests -gt 0) {
        Write-Host "$($Report.Summary.FailedTests)" -ForegroundColor Red
    }
    else {
        Write-Host "$($Report.Summary.FailedTests)" -ForegroundColor Green
    }
    Write-Host "  Warnings:     " -NoNewline
    if ($Report.Summary.Warnings -gt 0) {
        Write-Host "$($Report.Summary.Warnings)" -ForegroundColor Yellow
    }
    else {
        Write-Host "$($Report.Summary.Warnings)"
    }
    Write-Host ""

    # Network Adapters
    Write-Host "NETWORK ADAPTERS" -ForegroundColor White
    Write-Host "-" * 50
    foreach ($adapter in $Report.Adapters) {
        Write-Host "  $($adapter.Name) ($($adapter.Speed))"
        Write-Host "    IP:      $($adapter.IPAddress)$($adapter.SubnetMask)"
        Write-Host "    Gateway: $($adapter.Gateway)"
        Write-Host "    DNS:     $($adapter.DNSServers)"
        Write-Host ""
    }

    # Connectivity Tests
    Write-Host "CONNECTIVITY TESTS (PING)" -ForegroundColor White
    Write-Host "-" * 50
    foreach ($test in $Report.ConnectivityTests) {
        $status = if ($test.Success) { '[+]' } else { '[-]' }
        $color = if ($test.Success) { 'Green' } else { 'Red' }

        Write-Host "  $status " -NoNewline -ForegroundColor $color
        Write-Host "$($test.Host.PadRight(25))" -NoNewline
        if ($test.Success) {
            Write-Host " Avg: $($test.AvgTime)ms, Loss: $($test.PacketLoss)%"
        }
        else {
            Write-Host " FAILED: $($test.Error)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # Port Tests
    if ($Report.PortTests.Count -gt 0) {
        Write-Host "PORT CONNECTIVITY TESTS" -ForegroundColor White
        Write-Host "-" * 50

        $groupedByHost = $Report.PortTests | Group-Object -Property Host

        foreach ($hostGroup in $groupedByHost) {
            Write-Host "  $($hostGroup.Name):" -ForegroundColor Cyan
            foreach ($test in $hostGroup.Group) {
                $status = if ($test.Success) { '[+]' } else { '[-]' }
                $color = if ($test.Success) { 'Green' } else { 'Red' }

                Write-Host "    $status " -NoNewline -ForegroundColor $color
                Write-Host "Port $($test.Port.ToString().PadRight(5)) ($($test.ServiceName.PadRight(12)))" -NoNewline
                if ($test.Success) {
                    Write-Host " OK ($($test.ResponseMs)ms)"
                }
                else {
                    Write-Host " BLOCKED" -ForegroundColor Red
                }
            }
        }
        Write-Host ""
    }

    # DNS Tests
    if ($Report.DNSTests.Count -gt 0) {
        Write-Host "DNS RESOLUTION TESTS" -ForegroundColor White
        Write-Host "-" * 50
        foreach ($test in $Report.DNSTests) {
            $status = if ($test.Success) { '[+]' } else { '[-]' }
            $color = if ($test.Success) { 'Green' } else { 'Red' }

            Write-Host "  $status " -NoNewline -ForegroundColor $color
            Write-Host "$($test.Domain.PadRight(25))" -NoNewline
            if ($test.Success) {
                $ips = ($test.IPAddresses | Select-Object -First 3) -join ', '
                Write-Host " -> $ips ($($test.ResponseMs)ms)"
            }
            else {
                Write-Host " FAILED: $($test.Error)" -ForegroundColor Red
            }
        }
        Write-Host ""
    }

    # Traceroute
    if ($Report.TracerouteResults.Count -gt 0) {
        Write-Host "TRACEROUTE RESULTS" -ForegroundColor White
        Write-Host "-" * 50
        foreach ($trace in $Report.TracerouteResults) {
            Write-Host "  Target: $($trace.Target) ($($trace.TotalHops) hops)" -ForegroundColor Cyan

            $hopNum = 1
            foreach ($hop in $trace.Hops) {
                $hopName = if ($hop.HostName) { "$($hop.Address) ($($hop.HostName))" } else { $hop.Address }
                Write-Host "    $($hopNum.ToString().PadLeft(2)). $hopName"
                $hopNum++
            }
            Write-Host ""
        }
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
        Write-Host "[+] No issues detected - network health is good`n" -ForegroundColor Green
    }

    Write-Host $separator -ForegroundColor Cyan
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML network health report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $htmlPath = Join-Path $Path "network-health_$timestamp.html"

    # Build connectivity tests HTML
    $connectivityHtml = ""
    foreach ($test in $Report.ConnectivityTests) {
        $statusClass = if ($test.Success) { 'pass' } else { 'fail' }
        $statusText = if ($test.Success) { "OK ($($test.AvgTime)ms, $($test.PacketLoss)% loss)" } else { "FAILED: $($test.Error)" }
        $connectivityHtml += "<tr class='$statusClass'><td>$($test.Host)</td><td>$($test.IPAddress)</td><td>$statusText</td></tr>"
    }

    # Build port tests HTML
    $portHtml = ""
    foreach ($test in $Report.PortTests) {
        $statusClass = if ($test.Success) { 'pass' } else { 'fail' }
        $statusText = if ($test.Success) { "Open ($($test.ResponseMs)ms)" } else { 'Blocked' }
        $portHtml += "<tr class='$statusClass'><td>$($test.Host)</td><td>$($test.Port)</td><td>$($test.ServiceName)</td><td>$statusText</td></tr>"
    }

    # Build DNS tests HTML
    $dnsHtml = ""
    foreach ($test in $Report.DNSTests) {
        $statusClass = if ($test.Success) { 'pass' } else { 'fail' }
        $ips = if ($test.IPAddresses) { ($test.IPAddresses | Select-Object -First 3) -join ', ' } else { '-' }
        $statusText = if ($test.Success) { "$ips ($($test.ResponseMs)ms)" } else { "FAILED: $($test.Error)" }
        $dnsHtml += "<tr class='$statusClass'><td>$($test.Domain)</td><td>$($test.DNSServer)</td><td>$statusText</td></tr>"
    }

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

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Network Health Report - $($Report.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 20px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .summary-card { padding: 15px 25px; border-radius: 4px; text-align: center; flex: 1; }
        .summary-card.passed { background: #dff6dd; border-left: 4px solid #107c10; }
        .summary-card.failed { background: #fde7e9; border-left: 4px solid #d13438; }
        .summary-card.warnings { background: #fff4e5; border-left: 4px solid #ff8c00; }
        .summary-value { font-size: 28px; font-weight: bold; }
        .summary-label { color: #666; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; font-weight: 600; }
        tr.pass td:last-child { color: #107c10; }
        tr.fail td:last-child { color: #d13438; }
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
        <h1>Network Health Report</h1>
        <p><strong>Computer:</strong> $($Report.ComputerName) | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="summary">
            <div class="summary-card passed">
                <div class="summary-value">$($Report.Summary.PassedTests)</div>
                <div class="summary-label">Tests Passed</div>
            </div>
            <div class="summary-card failed">
                <div class="summary-value">$($Report.Summary.FailedTests)</div>
                <div class="summary-label">Tests Failed</div>
            </div>
            <div class="summary-card warnings">
                <div class="summary-value">$($Report.Summary.Warnings)</div>
                <div class="summary-label">Warnings</div>
            </div>
        </div>

        $alertsHtml

        <div class="section">
            <h2>Connectivity Tests (Ping)</h2>
            <table>
                <tr><th>Host</th><th>IP Address</th><th>Status</th></tr>
                $connectivityHtml
            </table>
        </div>

        $(if ($Report.PortTests.Count -gt 0) { @"
        <div class="section">
            <h2>Port Connectivity Tests</h2>
            <table>
                <tr><th>Host</th><th>Port</th><th>Service</th><th>Status</th></tr>
                $portHtml
            </table>
        </div>
"@ })

        $(if ($Report.DNSTests.Count -gt 0) { @"
        <div class="section">
            <h2>DNS Resolution Tests</h2>
            <table>
                <tr><th>Domain</th><th>DNS Server</th><th>Result</th></tr>
                $dnsHtml
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
        Exports network health report to JSON format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Report,

        [string]$Path
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $jsonPath = Join-Path $Path "network-health_$timestamp.json"

    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
    return $jsonPath
}
#endregion

#region Main Execution
try {
    Write-InfoMessage "=== Network Health Diagnostics v$script:ScriptVersion ==="
    Write-InfoMessage "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    if ($QuickTest) {
        Write-InfoMessage "Running quick test mode"
    }

    # Generate report
    $report = Get-NetworkHealthReport

    # Output based on format
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Report $report }
        'HTML'    { Export-HTMLReport -Report $report -Path $OutputPath }
        'JSON'    { Export-JSONReport -Report $report -Path $OutputPath }
        'All' {
            Write-ConsoleReport -Report $report
            Export-HTMLReport -Report $report -Path $OutputPath
            Export-JSONReport -Report $report -Path $OutputPath
        }
    }

    $duration = (Get-Date) - $script:StartTime
    Write-Success "=== Network diagnostics completed in $($duration.TotalSeconds.ToString('0.00'))s ==="

    # Return exit code based on results
    if ($report.Summary.FailedTests -gt 0) {
        exit 1
    }
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    exit 1
}
#endregion
