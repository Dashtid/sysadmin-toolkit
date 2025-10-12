<#
.SYNOPSIS
    Configure a static IP address for a network adapter on Windows.

.DESCRIPTION
    This script configures a static IP address, subnet mask, default gateway,
    and DNS servers for a specified network adapter. It includes validation
    and verification steps.

.PARAMETER AdapterName
    Name of the network adapter to configure (e.g., "Ethernet", "Wi-Fi")

.PARAMETER IPAddress
    Static IP address to assign (e.g., "192.168.0.100")

.PARAMETER PrefixLength
    Subnet prefix length (e.g., 24 for 255.255.255.0)

.PARAMETER Gateway
    Default gateway IP address (e.g., "192.168.0.1")

.PARAMETER DNSServers
    Array of DNS server IP addresses (e.g., @("8.8.8.8", "8.8.4.4"))

.EXAMPLE
    .\Set-StaticIP.ps1 -AdapterName "Ethernet" -IPAddress "192.168.0.100" -PrefixLength 24 -Gateway "192.168.0.1" -DNSServers @("8.8.8.8", "8.8.4.4")

.NOTES
    Author: System Administrator
    Requires: Administrator privileges
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AdapterName,

    [Parameter(Mandatory = $false)]
    [string]$IPAddress,

    [Parameter(Mandatory = $false)]
    [int]$PrefixLength,

    [Parameter(Mandatory = $false)]
    [string]$Gateway,

    [Parameter(Mandatory = $false)]
    [string[]]$DNSServers
)

# Requires Administrator privileges
#Requires -RunAsAdministrator

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Type) {
        "SUCCESS" { Write-Host "[+] $timestamp - $Message" -ForegroundColor Green }
        "ERROR"   { Write-Host "[-] $timestamp - $Message" -ForegroundColor Red }
        "WARN"    { Write-Host "[!] $timestamp - $Message" -ForegroundColor Yellow }
        default   { Write-Host "[*] $timestamp - $Message" -ForegroundColor Cyan }
    }
}

function Get-NetworkAdapters {
    Write-Status "Available network adapters:"
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue

        Write-Host "`n  Adapter: $($adapter.Name)" -ForegroundColor Yellow
        Write-Host "    Status: $($adapter.Status)"
        Write-Host "    Interface: $($adapter.InterfaceDescription)"
        Write-Host "    MAC: $($adapter.MacAddress)"

        if ($ipConfig) {
            Write-Host "    Current IP: $($ipConfig.IPAddress)"
            Write-Host "    Prefix Length: $($ipConfig.PrefixLength)"
            Write-Host "    DHCP Enabled: $($ipConfig.PrefixOrigin -eq 'Dhcp')"
        }

        if ($gateway) {
            Write-Host "    Gateway: $($gateway.NextHop)"
        }
    }
    Write-Host ""

    return $adapters
}

function Test-IPAddress {
    param([string]$IP)

    try {
        [System.Net.IPAddress]::Parse($IP) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Set-StaticIPConfiguration {
    param(
        [string]$Adapter,
        [string]$IP,
        [int]$Prefix,
        [string]$GW,
        [string[]]$DNS
    )

    try {
        # Get the adapter
        $netAdapter = Get-NetAdapter -Name $Adapter -ErrorAction Stop
        $interfaceIndex = $netAdapter.ifIndex

        Write-Status "Configuring static IP for adapter: $Adapter"

        # Remove existing IP configuration
        Write-Status "Removing existing IP configuration..."
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        # Set static IP address
        Write-Status "Setting IP address: $IP/$Prefix"
        New-NetIPAddress -InterfaceIndex $interfaceIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $GW -ErrorAction Stop | Out-Null

        # Set DNS servers
        if ($DNS -and $DNS.Count -gt 0) {
            Write-Status "Setting DNS servers: $($DNS -join ', ')"
            Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $DNS -ErrorAction Stop
        }

        Write-Status "Static IP configuration applied successfully" "SUCCESS"

        # Verify configuration
        Start-Sleep -Seconds 2
        Write-Status "Verifying configuration..."

        $newIPConfig = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4
        $newGateway = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix "0.0.0.0/0"
        $newDNS = Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4

        Write-Host "`n[+] Configuration verified:" -ForegroundColor Green
        Write-Host "    IP Address: $($newIPConfig.IPAddress)"
        Write-Host "    Prefix Length: $($newIPConfig.PrefixLength)"
        Write-Host "    Gateway: $($newGateway.NextHop)"
        Write-Host "    DNS Servers: $($newDNS.ServerAddresses -join ', ')"

        # Test connectivity
        Write-Status "Testing connectivity to gateway..."
        $pingResult = Test-Connection -ComputerName $GW -Count 2 -Quiet
        if ($pingResult) {
            Write-Status "Gateway is reachable" "SUCCESS"
        }
        else {
            Write-Status "Warning: Gateway is not responding to ping" "WARN"
        }

        return $true
    }
    catch {
        Write-Status "Error configuring static IP: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main execution
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  Windows Static IP Configuration Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Display current network configuration
$adapters = Get-NetworkAdapters

# Interactive mode if parameters not provided
if (-not $AdapterName) {
    $AdapterName = Read-Host "Enter the adapter name to configure (e.g., 'Ethernet')"
}

# Verify adapter exists
$selectedAdapter = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
if (-not $selectedAdapter) {
    Write-Status "Error: Adapter '$AdapterName' not found" "ERROR"
    exit 1
}

# Get current configuration for suggestions
$currentIP = Get-NetIPAddress -InterfaceIndex $selectedAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
$currentGW = Get-NetRoute -InterfaceIndex $selectedAdapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue

if (-not $IPAddress) {
    if ($currentIP) {
        Write-Host "[*] Current IP: $($currentIP.IPAddress)" -ForegroundColor Cyan
    }
    $IPAddress = Read-Host "Enter the static IP address"
}

if (-not (Test-IPAddress $IPAddress)) {
    Write-Status "Error: Invalid IP address format" "ERROR"
    exit 1
}

if (-not $PrefixLength) {
    if ($currentIP) {
        Write-Host "[*] Current Prefix Length: $($currentIP.PrefixLength)" -ForegroundColor Cyan
    }
    $PrefixLength = Read-Host "Enter the prefix length (e.g., 24 for 255.255.255.0)"
}

if (-not $Gateway) {
    if ($currentGW) {
        Write-Host "[*] Current Gateway: $($currentGW.NextHop)" -ForegroundColor Cyan
    }
    $Gateway = Read-Host "Enter the default gateway"
}

if (-not (Test-IPAddress $Gateway)) {
    Write-Status "Error: Invalid gateway address format" "ERROR"
    exit 1
}

if (-not $DNSServers) {
    Write-Host "[*] Common DNS options:" -ForegroundColor Cyan
    Write-Host "    1. Google DNS: 8.8.8.8, 8.8.4.4"
    Write-Host "    2. Cloudflare DNS: 1.1.1.1, 1.0.0.1"
    Write-Host "    3. Quad9 DNS: 9.9.9.9, 149.112.112.112"
    $dnsInput = Read-Host "Enter DNS servers (comma-separated) or press Enter to use Google DNS"

    if ([string]::IsNullOrWhiteSpace($dnsInput)) {
        $DNSServers = @("8.8.8.8", "8.8.4.4")
    }
    else {
        $DNSServers = $dnsInput -split ',' | ForEach-Object { $_.Trim() }
    }
}

# Validate DNS servers
foreach ($dns in $DNSServers) {
    if (-not (Test-IPAddress $dns)) {
        Write-Status "Error: Invalid DNS server address: $dns" "ERROR"
        exit 1
    }
}

# Display configuration summary
Write-Host "`n[*] Configuration Summary:" -ForegroundColor Yellow
Write-Host "    Adapter: $AdapterName"
Write-Host "    IP Address: $IPAddress"
Write-Host "    Prefix Length: $PrefixLength"
Write-Host "    Gateway: $Gateway"
Write-Host "    DNS Servers: $($DNSServers -join ', ')"
Write-Host ""

$confirm = Read-Host "Apply this configuration? (Y/N)"
if ($confirm -ne 'Y' -and $confirm -ne 'y') {
    Write-Status "Configuration cancelled by user" "WARN"
    exit 0
}

# Apply configuration
$result = Set-StaticIPConfiguration -Adapter $AdapterName -IP $IPAddress -Prefix $PrefixLength -GW $Gateway -DNS $DNSServers

if ($result) {
    Write-Host "`n[+] Static IP configuration completed successfully!" -ForegroundColor Green
    Write-Host "[*] Note: Some applications may require a restart to recognize the new configuration." -ForegroundColor Yellow
    exit 0
}
else {
    Write-Host "`n[-] Static IP configuration failed!" -ForegroundColor Red
    exit 1
}
