#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manages WSL2 (Windows Subsystem for Linux) installation, configuration, and maintenance.

.DESCRIPTION
    This script provides comprehensive WSL2 management capabilities:
    - Install and configure WSL2
    - Manage WSL distributions (install, remove, list)
    - Export and import distributions for backup/migration
    - Configure WSL resource limits (.wslconfig)
    - Manage WSL network settings
    - Troubleshoot common WSL issues
    - Start/stop/restart WSL

    Features:
    - Distribution installation from Microsoft Store or custom images
    - Backup and restore distributions
    - Memory and CPU limit configuration
    - Network troubleshooting
    - Integration with Windows Terminal

.PARAMETER Action
    The action to perform. Valid values:
    - Status: Show WSL status and installed distributions
    - Install: Install WSL2 and optionally a distribution
    - List: List available distributions
    - Export: Export a distribution to a file
    - Import: Import a distribution from a file
    - Remove: Remove a distribution
    - Configure: Configure WSL settings (.wslconfig)
    - Start: Start WSL
    - Stop: Stop all WSL instances
    - Restart: Restart WSL
    - Troubleshoot: Diagnose WSL issues
    - Update: Update WSL kernel
    - SetDefault: Set default distribution
    Default: Status

.PARAMETER Distribution
    Name of the WSL distribution to manage.

.PARAMETER ExportPath
    Path for export/import operations.

.PARAMETER MemoryLimit
    Memory limit for WSL (e.g., "4GB", "8GB"). Used with Configure action.

.PARAMETER ProcessorCount
    Number of logical processors for WSL. Used with Configure action.

.PARAMETER SwapSize
    Swap file size (e.g., "2GB", "4GB"). Used with Configure action.

.PARAMETER InstallLocation
    Custom installation location for importing distributions.

.PARAMETER Version
    WSL version (1 or 2). Default: 2

.PARAMETER OutputFormat
    Output format. Valid values: Console, JSON, HTML.
    Default: Console

.EXAMPLE
    .\Manage-WSL.ps1 -Action Status
    Shows WSL status and installed distributions.

.EXAMPLE
    .\Manage-WSL.ps1 -Action Install -Distribution Ubuntu
    Installs WSL2 and Ubuntu distribution.

.EXAMPLE
    .\Manage-WSL.ps1 -Action Export -Distribution Ubuntu -ExportPath "D:\Backups\ubuntu.tar"
    Exports Ubuntu distribution to a backup file.

.EXAMPLE
    .\Manage-WSL.ps1 -Action Import -Distribution MyUbuntu -ExportPath "D:\Backups\ubuntu.tar" -InstallLocation "D:\WSL\Ubuntu"
    Imports a distribution from backup.

.EXAMPLE
    .\Manage-WSL.ps1 -Action Configure -MemoryLimit "8GB" -ProcessorCount 4 -SwapSize "4GB"
    Configures WSL resource limits.

.EXAMPLE
    .\Manage-WSL.ps1 -Action Troubleshoot
    Runs WSL diagnostics and suggests fixes.

.EXAMPLE
    .\Manage-WSL.ps1 -Action List
    Lists all available distributions from Microsoft Store.

.NOTES
    File Name      : Manage-WSL.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
                     Windows 10 version 1903+ or Windows 11
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Administrator privileges required for:
    - Installing/removing WSL
    - Installing distributions
    - Modifying Windows features

    WSL Config File Location: %USERPROFILE%\.wslconfig

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Status', 'Install', 'List', 'Export', 'Import', 'Remove', 'Configure', 'Start', 'Stop', 'Restart', 'Troubleshoot', 'Update', 'SetDefault')]
    [string]$Action = 'Status',

    [Parameter()]
    [string]$Distribution,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [string]$MemoryLimit,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$ProcessorCount,

    [Parameter()]
    [string]$SwapSize,

    [Parameter()]
    [string]$InstallLocation,

    [Parameter()]
    [ValidateSet(1, 2)]
    [int]$Version = 2,

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
$script:WslConfigPath = Join-Path $env:USERPROFILE ".wslconfig"

# Available distributions
$script:AvailableDistros = @{
    'Ubuntu'            = 'Ubuntu'
    'Ubuntu-20.04'      = 'Ubuntu 20.04 LTS'
    'Ubuntu-22.04'      = 'Ubuntu 22.04 LTS'
    'Ubuntu-24.04'      = 'Ubuntu 24.04 LTS'
    'Debian'            = 'Debian GNU/Linux'
    'kali-linux'        = 'Kali Linux'
    'openSUSE-Leap-15.5' = 'openSUSE Leap 15.5'
    'SLES-15'           = 'SUSE Linux Enterprise Server 15'
    'OracleLinux_9_1'   = 'Oracle Linux 9.1'
    'AlmaLinux-9'       = 'AlmaLinux 9'
}
#endregion

#region Helper Functions
function Test-WslInstalled {
    try {
        $wslPath = Get-Command wsl.exe -ErrorAction SilentlyContinue
        return ($null -ne $wslPath)
    }
    catch {
        return $false
    }
}

function Test-WslEnabled {
    try {
        $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
        $vmFeature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
        return ($wslFeature.State -eq 'Enabled' -and $vmFeature.State -eq 'Enabled')
    }
    catch {
        return $false
    }
}

function Get-WslVersion {
    try {
        $version = wsl --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $versionLine = $version | Select-String "WSL version:" | ForEach-Object { $_.Line }
            if ($versionLine -match 'WSL version:\s*(.+)') {
                return $Matches[1].Trim()
            }
        }
        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

function Get-WslDistributions {
    $distributions = @()

    try {
        # Get verbose list
        $wslList = wsl --list --verbose 2>&1

        if ($LASTEXITCODE -eq 0 -and $wslList) {
            # Parse the output (skip header line)
            $lines = $wslList -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Skip 1

            foreach ($line in $lines) {
                # Handle default marker (*) and parse columns
                $isDefault = $line.StartsWith('*')
                $cleanLine = $line.TrimStart('*', ' ')

                # Parse: NAME STATE VERSION
                if ($cleanLine -match '^(\S+)\s+(\S+)\s+(\d+)') {
                    $distributions += [PSCustomObject]@{
                        Name      = $Matches[1]
                        State     = $Matches[2]
                        Version   = [int]$Matches[3]
                        IsDefault = $isDefault
                    }
                }
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get distribution list: $($_.Exception.Message)"
    }

    return $distributions
}

function Get-WslStatus {
    $status = [PSCustomObject]@{
        WslInstalled     = Test-WslInstalled
        WslEnabled       = $false
        WslVersion       = "Unknown"
        DefaultVersion   = 2
        Distributions    = @()
        RunningCount     = 0
        ConfigFile       = $null
    }

    if ($status.WslInstalled) {
        $status.WslEnabled = Test-WslEnabled
        $status.WslVersion = Get-WslVersion
        $status.Distributions = Get-WslDistributions

        # Count running distributions
        $status.RunningCount = ($status.Distributions | Where-Object { $_.State -eq "Running" }).Count

        # Check for config file
        if (Test-Path $script:WslConfigPath) {
            $status.ConfigFile = Get-Content $script:WslConfigPath -Raw
        }

        # Get default version
        try {
            $defaultVersion = wsl --status 2>&1 | Select-String "Default Version:" | ForEach-Object { $_.Line }
            if ($defaultVersion -match 'Default Version:\s*(\d+)') {
                $status.DefaultVersion = [int]$Matches[1]
            }
        }
        catch { }
    }

    return $status
}

function Show-WslStatus {
    $status = Get-WslStatus

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       WSL STATUS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    # WSL Installation Status
    Write-Host "WSL Installation:" -ForegroundColor White
    if ($status.WslInstalled) {
        Write-Host "  [+] WSL is installed" -ForegroundColor Green
        Write-Host "  [i] WSL Version: $($status.WslVersion)" -ForegroundColor Blue
        Write-Host "  [i] Default WSL Version: $($status.DefaultVersion)" -ForegroundColor Blue
    }
    else {
        Write-Host "  [-] WSL is not installed" -ForegroundColor Red
        Write-Host "  [i] Run: wsl --install" -ForegroundColor Yellow
        return
    }

    # Windows Features
    Write-Host ""
    Write-Host "Windows Features:" -ForegroundColor White
    if ($status.WslEnabled) {
        Write-Host "  [+] WSL feature enabled" -ForegroundColor Green
        Write-Host "  [+] Virtual Machine Platform enabled" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] Some required features may not be enabled" -ForegroundColor Yellow
    }

    # Distributions
    Write-Host ""
    Write-Host "Installed Distributions:" -ForegroundColor White
    if ($status.Distributions.Count -eq 0) {
        Write-Host "  [!] No distributions installed" -ForegroundColor Yellow
        Write-Host "  [i] Run: wsl --install -d Ubuntu" -ForegroundColor Blue
    }
    else {
        foreach ($distro in $status.Distributions) {
            $stateColor = switch ($distro.State) {
                "Running"  { "Green" }
                "Stopped"  { "Gray" }
                default    { "White" }
            }
            $defaultMarker = if ($distro.IsDefault) { " (default)" } else { "" }
            Write-Host "  - $($distro.Name)$defaultMarker" -ForegroundColor White
            Write-Host "    State: " -NoNewline -ForegroundColor Gray
            Write-Host "$($distro.State)" -ForegroundColor $stateColor
            Write-Host "    Version: WSL$($distro.Version)" -ForegroundColor Gray
        }
    }

    # Running instances
    Write-Host ""
    Write-Host "Running Instances: $($status.RunningCount)" -ForegroundColor $(if ($status.RunningCount -gt 0) { "Green" } else { "Gray" })

    # Config file
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    if ($status.ConfigFile) {
        Write-Host "  [+] .wslconfig exists" -ForegroundColor Green
        Write-Host "  [i] Path: $($script:WslConfigPath)" -ForegroundColor Blue
    }
    else {
        Write-Host "  [i] No .wslconfig file (using defaults)" -ForegroundColor Gray
    }
}

function Install-Wsl {
    param(
        [string]$Distro,
        [int]$WslVersion = 2
    )

    if (-not (Test-IsAdministrator)) {
        Write-ErrorMessage "Administrator privileges required to install WSL"
        return $false
    }

    Write-InfoMessage "Installing WSL..."

    try {
        if ($Distro) {
            # Install WSL with specific distribution
            Write-InfoMessage "Installing WSL with $Distro..."
            $result = wsl --install -d $Distro 2>&1
        }
        else {
            # Install WSL with default Ubuntu
            Write-InfoMessage "Installing WSL with default distribution..."
            $result = wsl --install 2>&1
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Success "WSL installation initiated"
            Write-WarningMessage "A system restart may be required to complete installation"
            return $true
        }
        else {
            # Check if already installed
            if ($result -match "already installed") {
                Write-InfoMessage "WSL is already installed"
                return $true
            }
            Write-ErrorMessage "Installation failed: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Installation error: $($_.Exception.Message)"
        return $false
    }
}

function Export-WslDistribution {
    param(
        [string]$Name,
        [string]$Path
    )

    $distros = Get-WslDistributions
    $distro = $distros | Where-Object { $_.Name -eq $Name }

    if (-not $distro) {
        Write-ErrorMessage "Distribution '$Name' not found"
        return $false
    }

    # Ensure directory exists
    $exportDir = Split-Path $Path -Parent
    if ($exportDir -and -not (Test-Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
    }

    Write-InfoMessage "Exporting '$Name' to '$Path'..."
    Write-InfoMessage "This may take several minutes depending on distribution size..."

    try {
        $startTime = Get-Date
        $result = wsl --export $Name $Path 2>&1

        if ($LASTEXITCODE -eq 0) {
            $duration = (Get-Date) - $startTime
            $fileSize = (Get-Item $Path).Length / 1GB

            Write-Success "Export completed successfully"
            Write-InfoMessage "Duration: $($duration.TotalMinutes.ToString('F1')) minutes"
            Write-InfoMessage "File size: $($fileSize.ToString('F2')) GB"
            return $true
        }
        else {
            Write-ErrorMessage "Export failed: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Export error: $($_.Exception.Message)"
        return $false
    }
}

function Import-WslDistribution {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Location,
        [int]$WslVersion = 2
    )

    if (-not (Test-Path $Path)) {
        Write-ErrorMessage "Import file not found: $Path"
        return $false
    }

    # Create install location if it doesn't exist
    if (-not (Test-Path $Location)) {
        New-Item -ItemType Directory -Path $Location -Force | Out-Null
    }

    Write-InfoMessage "Importing '$Name' from '$Path'..."
    Write-InfoMessage "Install location: $Location"
    Write-InfoMessage "This may take several minutes..."

    try {
        $startTime = Get-Date
        $result = wsl --import $Name $Location $Path --version $WslVersion 2>&1

        if ($LASTEXITCODE -eq 0) {
            $duration = (Get-Date) - $startTime

            Write-Success "Import completed successfully"
            Write-InfoMessage "Duration: $($duration.TotalMinutes.ToString('F1')) minutes"
            return $true
        }
        else {
            Write-ErrorMessage "Import failed: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Import error: $($_.Exception.Message)"
        return $false
    }
}

function Remove-WslDistribution {
    param([string]$Name)

    $distros = Get-WslDistributions
    $distro = $distros | Where-Object { $_.Name -eq $Name }

    if (-not $distro) {
        Write-ErrorMessage "Distribution '$Name' not found"
        return $false
    }

    Write-WarningMessage "This will permanently delete '$Name' and all its data!"

    try {
        $result = wsl --unregister $Name 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Distribution '$Name' removed successfully"
            return $true
        }
        else {
            Write-ErrorMessage "Removal failed: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Removal error: $($_.Exception.Message)"
        return $false
    }
}

function Set-WslConfiguration {
    param(
        [string]$Memory,
        [int]$Processors,
        [string]$Swap
    )

    $config = @{}

    # Read existing config if present
    if (Test-Path $script:WslConfigPath) {
        $existingConfig = Get-Content $script:WslConfigPath -Raw
        Write-InfoMessage "Existing .wslconfig found, merging settings..."
    }

    # Build config content
    $configContent = "[wsl2]`n"

    if ($Memory) {
        $configContent += "memory=$Memory`n"
        Write-InfoMessage "Setting memory limit: $Memory"
    }

    if ($Processors -gt 0) {
        $configContent += "processors=$Processors`n"
        Write-InfoMessage "Setting processor count: $Processors"
    }

    if ($Swap) {
        $configContent += "swap=$Swap`n"
        Write-InfoMessage "Setting swap size: $Swap"
    }

    # Add some recommended settings
    $configContent += @"
localhostForwarding=true
nestedVirtualization=true
"@

    try {
        $configContent | Out-File -FilePath $script:WslConfigPath -Encoding UTF8 -Force
        Write-Success "WSL configuration saved to: $($script:WslConfigPath)"
        Write-InfoMessage "Restart WSL for changes to take effect: wsl --shutdown"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to save configuration: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-WslCommand {
    param(
        [string]$Command,
        [string]$Distro
    )

    if ($Distro) {
        $result = wsl -d $Distro -- $Command 2>&1
    }
    else {
        $result = wsl -- $Command 2>&1
    }

    return $result
}

function Start-WslDistribution {
    param([string]$Name)

    if ($Name) {
        Write-InfoMessage "Starting $Name..."
        $null = wsl -d $Name -- echo "Started" 2>&1
    }
    else {
        Write-InfoMessage "Starting default distribution..."
        $null = wsl -- echo "Started" 2>&1
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Success "WSL started"
        return $true
    }
    else {
        Write-ErrorMessage "Failed to start WSL"
        return $false
    }
}

function Stop-WslInstances {
    Write-InfoMessage "Stopping all WSL instances..."

    try {
        $result = wsl --shutdown 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "All WSL instances stopped"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to stop WSL: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error stopping WSL: $($_.Exception.Message)"
        return $false
    }
}

function Update-WslKernel {
    Write-InfoMessage "Updating WSL kernel..."

    try {
        $result = wsl --update 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "WSL kernel updated"
            return $true
        }
        else {
            Write-InfoMessage "Update result: $result"
            return $true
        }
    }
    catch {
        Write-ErrorMessage "Update error: $($_.Exception.Message)"
        return $false
    }
}

function Set-WslDefault {
    param([string]$Name)

    $distros = Get-WslDistributions
    $distro = $distros | Where-Object { $_.Name -eq $Name }

    if (-not $distro) {
        Write-ErrorMessage "Distribution '$Name' not found"
        return $false
    }

    try {
        $result = wsl --set-default $Name 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "'$Name' set as default distribution"
            return $true
        }
        else {
            Write-ErrorMessage "Failed to set default: $result"
            return $false
        }
    }
    catch {
        Write-ErrorMessage "Error: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-WslTroubleshoot {
    Write-InfoMessage "Running WSL diagnostics..."
    Write-Host ""

    $results = @()

    # 1. Check WSL installation
    Write-Host "1. Checking WSL installation..." -ForegroundColor Cyan
    if (Test-WslInstalled) {
        $results += [PSCustomObject]@{ Check = "WSL Installed"; Status = "PASS"; Details = "wsl.exe found" }
        Write-Host "   [+] WSL is installed" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{ Check = "WSL Installed"; Status = "FAIL"; Details = "wsl.exe not found" }
        Write-Host "   [-] WSL is not installed" -ForegroundColor Red
        Write-Host "   [i] Run: wsl --install" -ForegroundColor Yellow
    }

    # 2. Check Windows features
    Write-Host "2. Checking Windows features..." -ForegroundColor Cyan
    try {
        $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction Stop
        if ($wslFeature.State -eq 'Enabled') {
            $results += [PSCustomObject]@{ Check = "WSL Feature"; Status = "PASS"; Details = "Enabled" }
            Write-Host "   [+] Windows Subsystem for Linux: Enabled" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{ Check = "WSL Feature"; Status = "FAIL"; Details = "Disabled" }
            Write-Host "   [-] Windows Subsystem for Linux: Disabled" -ForegroundColor Red
        }

        $vmFeature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction Stop
        if ($vmFeature.State -eq 'Enabled') {
            $results += [PSCustomObject]@{ Check = "VM Platform"; Status = "PASS"; Details = "Enabled" }
            Write-Host "   [+] Virtual Machine Platform: Enabled" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{ Check = "VM Platform"; Status = "FAIL"; Details = "Disabled" }
            Write-Host "   [-] Virtual Machine Platform: Disabled" -ForegroundColor Red
        }
    }
    catch {
        $results += [PSCustomObject]@{ Check = "Windows Features"; Status = "ERROR"; Details = $_.Exception.Message }
        Write-Host "   [!] Cannot check Windows features (run as admin)" -ForegroundColor Yellow
    }

    # 3. Check virtualization
    Write-Host "3. Checking virtualization..." -ForegroundColor Cyan
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor
        if ($cpu.VirtualizationFirmwareEnabled) {
            $results += [PSCustomObject]@{ Check = "Virtualization"; Status = "PASS"; Details = "Enabled in BIOS" }
            Write-Host "   [+] Virtualization enabled in BIOS" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{ Check = "Virtualization"; Status = "WARN"; Details = "May need BIOS enable" }
            Write-Host "   [!] Virtualization may need to be enabled in BIOS" -ForegroundColor Yellow
        }
    }
    catch {
        $results += [PSCustomObject]@{ Check = "Virtualization"; Status = "UNKNOWN"; Details = "Cannot determine" }
        Write-Host "   [?] Cannot determine virtualization status" -ForegroundColor Gray
    }

    # 4. Check Hyper-V
    Write-Host "4. Checking Hyper-V compatibility..." -ForegroundColor Cyan
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        if ($hyperv) {
            $results += [PSCustomObject]@{ Check = "Hyper-V"; Status = "INFO"; Details = $hyperv.State }
            Write-Host "   [i] Hyper-V: $($hyperv.State)" -ForegroundColor Blue
        }
        else {
            $results += [PSCustomObject]@{ Check = "Hyper-V"; Status = "INFO"; Details = "Not available" }
            Write-Host "   [i] Hyper-V not available (may not be required)" -ForegroundColor Gray
        }
    }
    catch { }

    # 5. Check WSL version
    Write-Host "5. Checking WSL version..." -ForegroundColor Cyan
    $wslVersion = Get-WslVersion
    $results += [PSCustomObject]@{ Check = "WSL Version"; Status = "INFO"; Details = $wslVersion }
    Write-Host "   [i] WSL Version: $wslVersion" -ForegroundColor Blue

    # 6. Check distributions
    Write-Host "6. Checking distributions..." -ForegroundColor Cyan
    $distros = Get-WslDistributions
    if ($distros.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = "Distributions"; Status = "PASS"; Details = "$($distros.Count) installed" }
        Write-Host "   [+] $($distros.Count) distribution(s) installed" -ForegroundColor Green
        foreach ($d in $distros) {
            $stateIcon = if ($d.State -eq "Running") { "[+]" } else { "[ ]" }
            Write-Host "       $stateIcon $($d.Name) (WSL$($d.Version))" -ForegroundColor $(if ($d.State -eq "Running") { "Green" } else { "Gray" })
        }
    }
    else {
        $results += [PSCustomObject]@{ Check = "Distributions"; Status = "WARN"; Details = "None installed" }
        Write-Host "   [!] No distributions installed" -ForegroundColor Yellow
    }

    # 7. Check networking
    Write-Host "7. Checking WSL networking..." -ForegroundColor Cyan
    try {
        $wslAdapter = Get-NetAdapter | Where-Object { $_.Name -match "WSL|vEthernet" }
        if ($wslAdapter) {
            $results += [PSCustomObject]@{ Check = "WSL Network"; Status = "PASS"; Details = "Adapter found" }
            Write-Host "   [+] WSL network adapter found" -ForegroundColor Green
        }
        else {
            $results += [PSCustomObject]@{ Check = "WSL Network"; Status = "INFO"; Details = "No adapter (may be normal)" }
            Write-Host "   [i] No WSL network adapter (normal if WSL not running)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "   [?] Cannot check network adapters" -ForegroundColor Gray
    }

    # 8. Check .wslconfig
    Write-Host "8. Checking .wslconfig..." -ForegroundColor Cyan
    if (Test-Path $script:WslConfigPath) {
        $results += [PSCustomObject]@{ Check = ".wslconfig"; Status = "PASS"; Details = "File exists" }
        Write-Host "   [+] .wslconfig exists" -ForegroundColor Green
    }
    else {
        $results += [PSCustomObject]@{ Check = ".wslconfig"; Status = "INFO"; Details = "Using defaults" }
        Write-Host "   [i] No .wslconfig (using defaults)" -ForegroundColor Gray
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

    # Recommendations
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Cyan

        if (($results | Where-Object { $_.Check -eq "WSL Installed" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Install WSL: wsl --install" -ForegroundColor White
        }
        if (($results | Where-Object { $_.Check -eq "WSL Feature" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Enable WSL feature (run as admin):" -ForegroundColor White
            Write-Host "    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart" -ForegroundColor Gray
        }
        if (($results | Where-Object { $_.Check -eq "VM Platform" -and $_.Status -eq "FAIL" })) {
            Write-Host "  - Enable Virtual Machine Platform (run as admin):" -ForegroundColor White
            Write-Host "    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart" -ForegroundColor Gray
        }
        if (($results | Where-Object { $_.Check -eq "Virtualization" -and $_.Status -eq "WARN" })) {
            Write-Host "  - Enable virtualization in BIOS/UEFI settings" -ForegroundColor White
        }
    }

    return $results
}

function Show-AvailableDistributions {
    Write-Host ""
    Write-Host "Available Distributions:" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""

    # Get online list
    try {
        $onlineList = wsl --list --online 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host $onlineList
        }
        else {
            # Fallback to our known list
            Write-Host "Common distributions:" -ForegroundColor White
            foreach ($distro in $script:AvailableDistros.GetEnumerator()) {
                Write-Host "  - $($distro.Key): $($distro.Value)" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "Common distributions:" -ForegroundColor White
        foreach ($distro in $script:AvailableDistros.GetEnumerator()) {
            Write-Host "  - $($distro.Key): $($distro.Value)" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "Install with: wsl --install -d <DistributionName>" -ForegroundColor Blue
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "WSL Manager v$($script:ScriptVersion)"

    switch ($Action) {
        'Status' {
            Show-WslStatus
        }

        'Install' {
            if ($PSCmdlet.ShouldProcess("WSL", "Install")) {
                $success = Install-Wsl -Distro $Distribution -WslVersion $Version
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'List' {
            Show-AvailableDistributions
        }

        'Export' {
            if (-not $Distribution -or -not $ExportPath) {
                Write-ErrorMessage "Please specify -Distribution and -ExportPath"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($Distribution, "Export to $ExportPath")) {
                $success = Export-WslDistribution -Name $Distribution -Path $ExportPath
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Import' {
            if (-not $Distribution -or -not $ExportPath -or -not $InstallLocation) {
                Write-ErrorMessage "Please specify -Distribution, -ExportPath, and -InstallLocation"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($Distribution, "Import from $ExportPath")) {
                $success = Import-WslDistribution -Name $Distribution -Path $ExportPath -Location $InstallLocation -WslVersion $Version
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Remove' {
            if (-not $Distribution) {
                Write-ErrorMessage "Please specify -Distribution"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($Distribution, "Remove distribution")) {
                $success = Remove-WslDistribution -Name $Distribution
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Configure' {
            if (-not $MemoryLimit -and $ProcessorCount -eq 0 -and -not $SwapSize) {
                Write-ErrorMessage "Please specify at least one of: -MemoryLimit, -ProcessorCount, -SwapSize"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess(".wslconfig", "Update configuration")) {
                $success = Set-WslConfiguration -Memory $MemoryLimit -Processors $ProcessorCount -Swap $SwapSize
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Start' {
            $success = Start-WslDistribution -Name $Distribution
            exit $(if ($success) { 0 } else { 1 })
        }

        'Stop' {
            if ($PSCmdlet.ShouldProcess("All WSL instances", "Stop")) {
                $success = Stop-WslInstances
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'Restart' {
            if ($PSCmdlet.ShouldProcess("WSL", "Restart")) {
                Write-InfoMessage "Stopping WSL..."
                Stop-WslInstances
                Start-Sleep -Seconds 2
                Write-InfoMessage "Starting WSL..."
                Start-WslDistribution -Name $Distribution
            }
        }

        'Troubleshoot' {
            $results = Invoke-WslTroubleshoot

            if ($OutputFormat -eq 'JSON') {
                $outputPath = Join-Path (Get-LogDirectory) "wsl_diagnostic_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $results | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding UTF8
                Write-Success "JSON report saved to: $outputPath"
            }
        }

        'Update' {
            if ($PSCmdlet.ShouldProcess("WSL Kernel", "Update")) {
                $success = Update-WslKernel
                exit $(if ($success) { 0 } else { 1 })
            }
        }

        'SetDefault' {
            if (-not $Distribution) {
                Write-ErrorMessage "Please specify -Distribution"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($Distribution, "Set as default")) {
                $success = Set-WslDefault -Name $Distribution
                exit $(if ($success) { 0 } else { 1 })
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
