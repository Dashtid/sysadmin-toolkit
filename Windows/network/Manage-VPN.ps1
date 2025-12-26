#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manages VPN connections including connection, monitoring, and troubleshooting.

.DESCRIPTION
    This script provides comprehensive VPN management capabilities:
    - Connect/disconnect VPN profiles
    - Auto-connect on startup
    - VPN connection health monitoring
    - Automatic reconnection on disconnect
    - VPN profile management (list, create, remove)
    - Connection troubleshooting
    - VPN connection logging and history

    Supports:
    - Windows built-in VPN (PPTP, L2TP, SSTP, IKEv2)
    - Split tunneling configuration
    - Auto-reconnect with exponential backoff
    - Connection statistics and monitoring

.PARAMETER Action
    The action to perform. Valid values:
    - Connect: Connect to a VPN profile
    - Disconnect: Disconnect from a VPN
    - Status: Show current VPN status
    - List: List all VPN profiles
    - Monitor: Continuously monitor VPN connection
    - Troubleshoot: Diagnose VPN issues
    - Create: Create a new VPN profile
    - Remove: Remove a VPN profile
    - History: Show connection history
    Default: Status

.PARAMETER ProfileName
    Name of the VPN profile to use. Required for Connect, Disconnect, Remove actions.

.PARAMETER ServerAddress
    VPN server address. Required when creating a new profile.

.PARAMETER VpnType
    VPN protocol type for new profiles. Valid values: Pptp, L2tp, Sstp, Ikev2, Automatic.
    Default: Ikev2

.PARAMETER AuthMethod
    Authentication method. Valid values: Pap, Chap, MSChapv2, Eap, Certificate.
    Default: MSChapv2

.PARAMETER SplitTunnel
    Enable split tunneling (only route VPN traffic for specific networks).
    Default: $false

.PARAMETER AutoReconnect
    Enable automatic reconnection if VPN drops.
    Default: $true

.PARAMETER ReconnectAttempts
    Maximum number of reconnection attempts. 0 = unlimited.
    Default: 5

.PARAMETER ReconnectDelay
    Initial delay in seconds between reconnection attempts.
    Default: 5

.PARAMETER MonitorInterval
    Interval in seconds between connection checks during monitoring.
    Default: 30

.PARAMETER OutputFormat
    Output format. Valid values: Console, JSON, HTML.
    Default: Console

.PARAMETER Credential
    PSCredential object for VPN authentication.

.EXAMPLE
    .\Manage-VPN.ps1 -Action Status
    Shows the current VPN connection status.

.EXAMPLE
    .\Manage-VPN.ps1 -Action List
    Lists all configured VPN profiles.

.EXAMPLE
    .\Manage-VPN.ps1 -Action Connect -ProfileName "Work VPN"
    Connects to the "Work VPN" profile.

.EXAMPLE
    .\Manage-VPN.ps1 -Action Monitor -ProfileName "Work VPN" -AutoReconnect
    Monitors the VPN connection and automatically reconnects if it drops.

.EXAMPLE
    .\Manage-VPN.ps1 -Action Create -ProfileName "NewVPN" -ServerAddress "vpn.example.com" -VpnType Ikev2
    Creates a new IKEv2 VPN profile.

.EXAMPLE
    .\Manage-VPN.ps1 -Action Troubleshoot -ProfileName "Work VPN"
    Diagnoses connection issues with the specified VPN.

.EXAMPLE
    $cred = Get-Credential
    .\Manage-VPN.ps1 -Action Connect -ProfileName "Work VPN" -Credential $cred
    Connects to VPN using provided credentials.

.NOTES
    File Name      : Manage-VPN.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    VPN Types:
    - Pptp: Point-to-Point Tunneling Protocol (legacy, less secure)
    - L2tp: Layer 2 Tunneling Protocol (with IPsec)
    - Sstp: Secure Socket Tunneling Protocol
    - Ikev2: Internet Key Exchange v2 (recommended)

    Administrator rights required for:
    - Creating/removing VPN profiles
    - Modifying VPN settings
    - Split tunnel configuration

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Connect', 'Disconnect', 'Status', 'List', 'Monitor', 'Troubleshoot', 'Create', 'Remove', 'History')]
    [string]$Action = 'Status',

    [Parameter()]
    [string]$ProfileName,

    [Parameter()]
    [string]$ServerAddress,

    [Parameter()]
    [ValidateSet('Pptp', 'L2tp', 'Sstp', 'Ikev2', 'Automatic')]
    [string]$VpnType = 'Ikev2',

    [Parameter()]
    [ValidateSet('Pap', 'Chap', 'MSChapv2', 'Eap', 'Certificate')]
    [string]$AuthMethod = 'MSChapv2',

    [Parameter()]
    [switch]$SplitTunnel,

    [Parameter()]
    [switch]$AutoReconnect = $true,

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$ReconnectAttempts = 5,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$ReconnectDelay = 5,

    [Parameter()]
    [ValidateRange(5, 3600)]
    [int]$MonitorInterval = 30,

    [Parameter()]
    [ValidateSet('Console', 'JSON', 'HTML')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [PSCredential]$Credential
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
$script:LogFile = Join-Path (Get-LogDirectory) "vpn_history.log"
$script:StopMonitoring = $false

# VPN connection states
$script:ConnectionStates = @{
    Connected    = "Connected"
    Connecting   = "Connecting"
    Disconnected = "Disconnected"
    Dormant      = "Dormant"
    Limited      = "Limited"
}
#endregion

#region Helper Functions
function Write-VpnLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    $logDir = Split-Path $script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-VpnProfiles {
    try {
        $profiles = Get-VpnConnection -ErrorAction SilentlyContinue
        return $profiles
    }
    catch {
        Write-ErrorMessage "Failed to get VPN profiles: $($_.Exception.Message)"
        return @()
    }
}

function Get-VpnConnectionStatus {
    param([string]$Name)

    try {
        $vpn = Get-VpnConnection -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            Name              = $vpn.Name
            ServerAddress     = $vpn.ServerAddress
            ConnectionStatus  = $vpn.ConnectionStatus
            TunnelType        = $vpn.TunnelType
            AuthenticationMethod = $vpn.AuthenticationMethod -join ", "
            SplitTunneling    = $vpn.SplitTunneling
            RememberCredential = $vpn.RememberCredential
            IdleDisconnectSeconds = $vpn.IdleDisconnectSeconds
        }
    }
    catch {
        return $null
    }
}

function Test-VpnConnectivity {
    param([string]$ProfileName)

    $vpn = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
    if (-not $vpn) {
        return $false
    }

    return $vpn.ConnectionStatus -eq "Connected"
}

function Connect-VpnProfile {
    param(
        [string]$Name,
        [PSCredential]$Credential
    )

    $vpn = Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue
    if (-not $vpn) {
        Write-ErrorMessage "VPN profile '$Name' not found"
        return $false
    }

    if ($vpn.ConnectionStatus -eq "Connected") {
        Write-WarningMessage "Already connected to '$Name'"
        return $true
    }

    Write-InfoMessage "Connecting to '$Name'..."
    Write-VpnLog "Attempting connection to '$Name'" "INFO"

    try {
        if ($Credential) {
            # Use rasdial for credential-based connection
            $username = $Credential.UserName
            $password = $Credential.GetNetworkCredential().Password

            $result = & rasdial $Name $username $password 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Connected to '$Name'"
                Write-VpnLog "Successfully connected to '$Name'" "INFO"
                return $true
            }
            else {
                Write-ErrorMessage "Connection failed: $result"
                Write-VpnLog "Connection failed: $result" "ERROR"
                return $false
            }
        }
        else {
            # Use rasdial without credentials (use saved or prompt)
            $result = & rasdial $Name 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Connected to '$Name'"
                Write-VpnLog "Successfully connected to '$Name'" "INFO"
                return $true
            }
            else {
                # Try Set-VpnConnection approach
                $null = rasphone -d $Name
                Start-Sleep -Seconds 2

                $vpnCheck = Get-VpnConnection -Name $Name
                if ($vpnCheck.ConnectionStatus -eq "Connected") {
                    Write-Success "Connected to '$Name'"
                    Write-VpnLog "Successfully connected to '$Name'" "INFO"
                    return $true
                }
                else {
                    Write-ErrorMessage "Connection failed"
                    Write-VpnLog "Connection failed for '$Name'" "ERROR"
                    return $false
                }
            }
        }
    }
    catch {
        Write-ErrorMessage "Connection error: $($_.Exception.Message)"
        Write-VpnLog "Connection error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disconnect-VpnProfile {
    param([string]$Name)

    $vpn = Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue
    if (-not $vpn) {
        Write-ErrorMessage "VPN profile '$Name' not found"
        return $false
    }

    if ($vpn.ConnectionStatus -ne "Connected") {
        Write-WarningMessage "'$Name' is not connected"
        return $true
    }

    Write-InfoMessage "Disconnecting from '$Name'..."
    Write-VpnLog "Attempting disconnection from '$Name'" "INFO"

    try {
        $result = & rasdial $Name /disconnect 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Disconnected from '$Name'"
            Write-VpnLog "Successfully disconnected from '$Name'" "INFO"
            return $true
        }
        else {
            Write-ErrorMessage "Disconnection failed: $result"
            Write-VpnLog "Disconnection failed: $result" "ERROR"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Disconnection error: $($_.Exception.Message)"
        Write-VpnLog "Disconnection error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-VpnProfile {
    param(
        [string]$Name,
        [string]$Server,
        [string]$Type,
        [string]$Auth,
        [switch]$Split
    )

    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Creating VPN profiles may require administrator privileges"
    }

    Write-InfoMessage "Creating VPN profile '$Name'..."

    try {
        $params = @{
            Name               = $Name
            ServerAddress      = $Server
            TunnelType         = $Type
            AuthenticationMethod = $Auth
            RememberCredential = $true
            SplitTunneling     = $Split.IsPresent
            Force              = $true
        }

        # Handle L2tp specific settings
        if ($Type -eq 'L2tp') {
            $params['L2tpPsk'] = Read-Host "Enter L2TP Pre-Shared Key" -AsSecureString | ConvertFrom-SecureString
        }

        Add-VpnConnection @params -ErrorAction Stop

        Write-Success "VPN profile '$Name' created successfully"
        Write-VpnLog "Created VPN profile '$Name' (Server: $Server, Type: $Type)" "INFO"

        return $true
    }
    catch {
        Write-ErrorMessage "Failed to create profile: $($_.Exception.Message)"
        Write-VpnLog "Failed to create profile '$Name': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-VpnProfile {
    param([string]$Name)

    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Removing VPN profiles may require administrator privileges"
    }

    $vpn = Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue
    if (-not $vpn) {
        Write-ErrorMessage "VPN profile '$Name' not found"
        return $false
    }

    # Disconnect first if connected
    if ($vpn.ConnectionStatus -eq "Connected") {
        Disconnect-VpnProfile -Name $Name
    }

    Write-InfoMessage "Removing VPN profile '$Name'..."

    try {
        Remove-VpnConnection -Name $Name -Force -ErrorAction Stop
        Write-Success "VPN profile '$Name' removed"
        Write-VpnLog "Removed VPN profile '$Name'" "INFO"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to remove profile: $($_.Exception.Message)"
        Write-VpnLog "Failed to remove profile '$Name': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-VpnMonitor {
    param(
        [string]$Name,
        [switch]$AutoReconnect,
        [int]$MaxAttempts,
        [int]$BaseDelay,
        [int]$Interval
    )

    Write-InfoMessage "Starting VPN monitor for '$Name'"
    Write-InfoMessage "Press Ctrl+C to stop monitoring"
    Write-VpnLog "Started monitoring '$Name'" "INFO"

    $reconnectCount = 0
    $currentDelay = $BaseDelay

    # Handle Ctrl+C gracefully
    $null = Register-EngineEvent PowerShell.Exiting -Action {
        $script:StopMonitoring = $true
    }

    try {
        while (-not $script:StopMonitoring) {
            $status = Get-VpnConnectionStatus -Name $Name

            if ($status) {
                $timestamp = Get-Date -Format "HH:mm:ss"

                if ($status.ConnectionStatus -eq "Connected") {
                    Write-Host "[$timestamp] [+] Connected to $Name" -ForegroundColor Green
                    $reconnectCount = 0
                    $currentDelay = $BaseDelay
                }
                else {
                    Write-Host "[$timestamp] [-] Disconnected from $Name" -ForegroundColor Red

                    if ($AutoReconnect) {
                        if ($MaxAttempts -eq 0 -or $reconnectCount -lt $MaxAttempts) {
                            $reconnectCount++
                            Write-Host "[$timestamp] [i] Reconnection attempt $reconnectCount..." -ForegroundColor Yellow
                            Write-VpnLog "Reconnection attempt $reconnectCount for '$Name'" "INFO"

                            $connected = Connect-VpnProfile -Name $Name

                            if (-not $connected) {
                                Write-Host "[$timestamp] [!] Waiting $currentDelay seconds before next attempt..." -ForegroundColor Yellow
                                Start-Sleep -Seconds $currentDelay
                                # Exponential backoff (max 5 minutes)
                                $currentDelay = [Math]::Min($currentDelay * 2, 300)
                            }
                        }
                        else {
                            Write-Host "[$timestamp] [X] Maximum reconnection attempts reached" -ForegroundColor Red
                            Write-VpnLog "Maximum reconnection attempts reached for '$Name'" "ERROR"
                            $script:StopMonitoring = $true
                        }
                    }
                }
            }
            else {
                Write-WarningMessage "VPN profile '$Name' not found"
                $script:StopMonitoring = $true
            }

            if (-not $script:StopMonitoring) {
                Start-Sleep -Seconds $Interval
            }
        }
    }
    finally {
        Write-VpnLog "Stopped monitoring '$Name'" "INFO"
        Write-InfoMessage "Monitoring stopped"
    }
}

function Invoke-VpnTroubleshoot {
    param([string]$Name)

    Write-InfoMessage "Running VPN diagnostics for '$Name'..."
    Write-Host ""

    $results = @()

    # 1. Check if profile exists
    Write-Host "1. Checking VPN profile..." -ForegroundColor Cyan
    $vpn = Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue
    if ($vpn) {
        $results += [PSCustomObject]@{
            Check   = "Profile Exists"
            Status  = "PASS"
            Details = "Server: $($vpn.ServerAddress)"
        }
        Write-Host "   [+] Profile found: $($vpn.ServerAddress)" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{
            Check   = "Profile Exists"
            Status  = "FAIL"
            Details = "Profile '$Name' not found"
        }
        Write-Host "   [-] Profile not found" -ForegroundColor Red
        return $results
    }

    # 2. Check network connectivity
    Write-Host "2. Checking network connectivity..." -ForegroundColor Cyan
    $testTarget = "8.8.8.8"  # Google DNS for connectivity check
    $networkTest = Test-NetConnection -ComputerName $testTarget -WarningAction SilentlyContinue
    if ($networkTest.PingSucceeded) {
        $results += [PSCustomObject]@{
            Check   = "Internet Connectivity"
            Status  = "PASS"
            Details = "Can reach internet"
        }
        Write-Host "   [+] Internet connectivity OK" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{
            Check   = "Internet Connectivity"
            Status  = "FAIL"
            Details = "Cannot reach internet"
        }
        Write-Host "   [-] No internet connectivity" -ForegroundColor Red
    }

    # 3. Check DNS resolution of VPN server
    Write-Host "3. Checking VPN server DNS resolution..." -ForegroundColor Cyan
    try {
        $dnsResult = Resolve-DnsName -Name $vpn.ServerAddress -ErrorAction Stop
        $results += [PSCustomObject]@{
            Check   = "DNS Resolution"
            Status  = "PASS"
            Details = "Server resolves to: $($dnsResult[0].IPAddress)"
        }
        Write-Host "   [+] Server resolves to: $($dnsResult[0].IPAddress)" -ForegroundColor Green
    }
    catch {
        $results += [PSCustomObject]@{
            Check   = "DNS Resolution"
            Status  = "FAIL"
            Details = "Cannot resolve server hostname"
        }
        Write-Host "   [-] Cannot resolve VPN server hostname" -ForegroundColor Red
    }

    # 4. Check VPN server connectivity
    Write-Host "4. Checking VPN server connectivity..." -ForegroundColor Cyan
    $vpnPing = Test-NetConnection -ComputerName $vpn.ServerAddress -WarningAction SilentlyContinue
    if ($vpnPing.PingSucceeded) {
        $results += [PSCustomObject]@{
            Check   = "Server Reachability"
            Status  = "PASS"
            Details = "Server responds to ping"
        }
        Write-Host "   [+] VPN server is reachable" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{
            Check   = "Server Reachability"
            Status  = "WARN"
            Details = "Server does not respond to ping (may be blocked)"
        }
        Write-Host "   [!] Server does not respond to ping (may be normal)" -ForegroundColor Yellow
    }

    # 5. Check VPN ports
    Write-Host "5. Checking VPN ports..." -ForegroundColor Cyan
    $portMap = @{
        'Pptp'  = @(1723)
        'L2tp'  = @(500, 4500, 1701)
        'Sstp'  = @(443)
        'Ikev2' = @(500, 4500)
    }

    $portsToCheck = $portMap[$vpn.TunnelType]
    if ($portsToCheck) {
        foreach ($port in $portsToCheck) {
            $portTest = Test-NetConnection -ComputerName $vpn.ServerAddress -Port $port -WarningAction SilentlyContinue
            if ($portTest.TcpTestSucceeded) {
                $results += [PSCustomObject]@{
                    Check   = "Port $port"
                    Status  = "PASS"
                    Details = "Port is open"
                }
                Write-Host "   [+] Port $port is open" -ForegroundColor Green
            }
            else {
                $results += [PSCustomObject]@{
                    Check   = "Port $port"
                    Status  = "WARN"
                    Details = "Port may be filtered"
                }
                Write-Host "   [!] Port $port may be filtered" -ForegroundColor Yellow
            }
        }
    }

    # 6. Check Windows VPN services
    Write-Host "6. Checking VPN services..." -ForegroundColor Cyan
    $services = @(
        @{ Name = "RasMan"; DisplayName = "Remote Access Connection Manager" },
        @{ Name = "IKEEXT"; DisplayName = "IKE and AuthIP IPsec Keying Modules" },
        @{ Name = "PolicyAgent"; DisplayName = "IPsec Policy Agent" }
    )

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $results += [PSCustomObject]@{
                Check   = $svc.DisplayName
                Status  = "PASS"
                Details = "Service is running"
            }
            Write-Host "   [+] $($svc.DisplayName) is running" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{
                Check   = $svc.DisplayName
                Status  = "FAIL"
                Details = "Service is not running"
            }
            Write-Host "   [-] $($svc.DisplayName) is not running" -ForegroundColor Red
        }
    }

    # 7. Check firewall
    Write-Host "7. Checking Windows Firewall..." -ForegroundColor Cyan
    $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
    if ($firewall) {
        $results += [PSCustomObject]@{
            Check   = "Windows Firewall"
            Status  = "INFO"
            Details = "Active profiles: $($firewall.Name -join ', ')"
        }
        Write-Host "   [i] Firewall active: $($firewall.Name -join ', ')" -ForegroundColor Blue
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

    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Cyan
        if (($results | Where-Object { $_.Check -eq "Internet Connectivity" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Check your local network connection" -ForegroundColor White
        }
        if (($results | Where-Object { $_.Check -eq "DNS Resolution" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Verify VPN server address is correct" -ForegroundColor White
            Write-Host "  - Try using IP address instead of hostname" -ForegroundColor White
        }
        if (($results | Where-Object { $_.Check -match "Remote Access|IKE|IPsec" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Start required Windows services:" -ForegroundColor White
            Write-Host "    net start RasMan" -ForegroundColor Gray
            Write-Host "    net start IKEEXT" -ForegroundColor Gray
            Write-Host "    net start PolicyAgent" -ForegroundColor Gray
        }
    }

    Write-VpnLog "Diagnostics completed for '$Name': $passCount passed, $failCount failed, $warnCount warnings" "INFO"
    return $results
}

function Get-VpnHistory {
    param([int]$Lines = 50)

    if (Test-Path $script:LogFile) {
        $history = Get-Content $script:LogFile -Tail $Lines
        return $history
    }
    else {
        Write-WarningMessage "No VPN history log found"
        return @()
    }
}

function Show-VpnStatus {
    $profiles = Get-VpnProfiles

    if ($profiles.Count -eq 0) {
        Write-WarningMessage "No VPN profiles configured"
        return
    }

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       VPN CONNECTION STATUS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($vpn in $profiles) {
        $statusColor = switch ($vpn.ConnectionStatus) {
            "Connected"    { "Green" }
            "Connecting"   { "Yellow" }
            "Disconnected" { "Red" }
            default        { "White" }
        }

        Write-Host "Profile: $($vpn.Name)" -ForegroundColor White
        Write-Host "  Server:     $($vpn.ServerAddress)" -ForegroundColor Gray
        Write-Host "  Status:     " -NoNewline -ForegroundColor Gray
        Write-Host "$($vpn.ConnectionStatus)" -ForegroundColor $statusColor
        Write-Host "  Type:       $($vpn.TunnelType)" -ForegroundColor Gray
        Write-Host "  Split:      $($vpn.SplitTunneling)" -ForegroundColor Gray
        Write-Host ""
    }
}

function Show-VpnList {
    $profiles = Get-VpnProfiles

    if ($profiles.Count -eq 0) {
        Write-WarningMessage "No VPN profiles configured"
        return @()
    }

    $profileList = @()
    foreach ($vpn in $profiles) {
        $profileList += [PSCustomObject]@{
            Name         = $vpn.Name
            Server       = $vpn.ServerAddress
            Type         = $vpn.TunnelType
            Status       = $vpn.ConnectionStatus
            SplitTunnel  = $vpn.SplitTunneling
            Remember     = $vpn.RememberCredential
        }
    }

    return $profileList
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "VPN Manager v$($script:ScriptVersion)"

    switch ($Action) {
        'Status' {
            Show-VpnStatus
        }

        'List' {
            $profiles = Show-VpnList
            if ($profiles.Count -gt 0) {
                Write-Host ""
                Write-Host "VPN Profiles:" -ForegroundColor Cyan
                Write-Host "=============" -ForegroundColor Cyan
                $profiles | Format-Table -AutoSize
            }
        }

        'Connect' {
            if (-not $ProfileName) {
                Write-ErrorMessage "Please specify -ProfileName"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ProfileName, "Connect to VPN")) {
                $success = Connect-VpnProfile -Name $ProfileName -Credential $Credential
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Disconnect' {
            if (-not $ProfileName) {
                Write-ErrorMessage "Please specify -ProfileName"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ProfileName, "Disconnect from VPN")) {
                $success = Disconnect-VpnProfile -Name $ProfileName
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Monitor' {
            if (-not $ProfileName) {
                Write-ErrorMessage "Please specify -ProfileName"
                exit 1
            }

            Start-VpnMonitor -Name $ProfileName -AutoReconnect:$AutoReconnect -MaxAttempts $ReconnectAttempts -BaseDelay $ReconnectDelay -Interval $MonitorInterval
        }

        'Troubleshoot' {
            if (-not $ProfileName) {
                Write-ErrorMessage "Please specify -ProfileName"
                exit 1
            }

            $results = Invoke-VpnTroubleshoot -Name $ProfileName

            if ($OutputFormat -eq 'JSON') {
                $outputPath = Join-Path (Get-LogDirectory) "vpn_diagnostic_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $results | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding UTF8
                Write-Success "JSON report saved to: $outputPath"
            }
        }

        'Create' {
            if (-not $ProfileName -or -not $ServerAddress) {
                Write-ErrorMessage "Please specify -ProfileName and -ServerAddress"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ProfileName, "Create VPN profile")) {
                $success = New-VpnProfile -Name $ProfileName -Server $ServerAddress -Type $VpnType -Auth $AuthMethod -Split:$SplitTunnel
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Remove' {
            if (-not $ProfileName) {
                Write-ErrorMessage "Please specify -ProfileName"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ProfileName, "Remove VPN profile")) {
                $success = Remove-VpnProfile -Name $ProfileName
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'History' {
            $history = Get-VpnHistory
            if ($history.Count -gt 0) {
                Write-Host ""
                Write-Host "VPN Connection History (last 50 entries):" -ForegroundColor Cyan
                Write-Host "==========================================" -ForegroundColor Cyan
                $history | ForEach-Object { Write-Host $_ }
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
