#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Auto-fixes common Windows issues including DNS, network, Windows Update, and cache problems.

.DESCRIPTION
    This script provides automated fixes for common Windows issues:
    - DNS resolution issues (flush DNS, reset DNS client)
    - Network adapter reset and configuration
    - Windows Update troubleshooting (reset components, clear cache)
    - Browser and system cache clearing
    - Winsock catalog reset
    - TCP/IP stack reset
    - Windows Store cache reset
    - Printer spooler reset
    - System file checker (SFC) and DISM repairs

.PARAMETER Fix
    Specify which fix(es) to apply. Options:
    - All: Apply all fixes
    - DNS: Fix DNS resolution issues
    - Network: Reset network adapters and configuration
    - WindowsUpdate: Fix Windows Update issues
    - Cache: Clear system and browser caches
    - Winsock: Reset Winsock catalog
    - TCPIP: Reset TCP/IP stack
    - Store: Reset Windows Store cache
    - Printer: Reset print spooler
    - SystemFiles: Run SFC and DISM repairs

.PARAMETER DryRun
    Show what would be done without making changes.

.PARAMETER Force
    Skip confirmation prompts.

.PARAMETER CreateRestorePoint
    Create a system restore point before making changes. Default: $true.

.PARAMETER LogPath
    Path for the repair log file.

.EXAMPLE
    .\Repair-CommonIssues.ps1 -Fix DNS
    Fixes DNS resolution issues only.

.EXAMPLE
    .\Repair-CommonIssues.ps1 -Fix Network, Winsock -Force
    Resets network and Winsock without prompts.

.EXAMPLE
    .\Repair-CommonIssues.ps1 -Fix All -DryRun
    Shows all fixes that would be applied without making changes.

.EXAMPLE
    .\Repair-CommonIssues.ps1 -Fix WindowsUpdate -CreateRestorePoint
    Creates restore point then fixes Windows Update issues.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+, Administrator privileges
    Warning: Some fixes require a system restart to take effect.

.OUTPUTS
    PSCustomObject containing repair results with properties:
    - FixApplied, Success, Message, RequiresRestart

.LINK
    https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('All', 'DNS', 'Network', 'WindowsUpdate', 'Cache', 'Winsock', 'TCPIP', 'Store', 'Printer', 'SystemFiles')]
    [string[]]$Fix,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$CreateRestorePoint = $true,

    [Parameter()]
    [string]$LogPath
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
    function Get-LogDirectory {
        $logPath = Join-Path $scriptRoot "..\..\..\logs"
        if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
        return (Resolve-Path $logPath).Path
    }
}
#endregion

#region Variables
$script:Results = @()
$script:RequiresRestart = $false
$script:LogFile = $null
#endregion

#region Helper Functions
function Write-RepairLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logEntry
    }

    switch ($Level) {
        "SUCCESS" { Write-Success $Message }
        "WARNING" { Write-WarningMessage $Message }
        "ERROR"   { Write-ErrorMessage $Message }
        default   { Write-InfoMessage $Message }
    }
}

function Add-RepairResult {
    param(
        [string]$FixName,
        [bool]$Success,
        [string]$Message,
        [bool]$RequiresRestart = $false
    )

    $script:Results += [PSCustomObject]@{
        FixApplied      = $FixName
        Success         = $Success
        Message         = $Message
        RequiresRestart = $RequiresRestart
        Timestamp       = Get-Date
    }

    if ($RequiresRestart) {
        $script:RequiresRestart = $true
    }
}

function Invoke-CommandWithLogging {
    param(
        [string]$Description,
        [scriptblock]$Command,
        [bool]$RequiresRestart = $false
    )

    if ($DryRun) {
        Write-RepairLog "[DRY RUN] Would execute: $Description" -Level "INFO"
        Add-RepairResult -FixName $Description -Success $true -Message "Dry run - not executed"
        return $true
    }

    try {
        Write-RepairLog "Executing: $Description" -Level "INFO"
        $output = & $Command 2>&1
        if ($output) {
            Write-Verbose ($output | Out-String)
        }
        Write-RepairLog "Completed: $Description" -Level "SUCCESS"
        Add-RepairResult -FixName $Description -Success $true -Message "Completed successfully" -RequiresRestart $RequiresRestart
        return $true
    } catch {
        Write-RepairLog "Failed: $Description - $($_.Exception.Message)" -Level "ERROR"
        Add-RepairResult -FixName $Description -Success $false -Message $_.Exception.Message
        return $false
    }
}
#endregion

#region Fix Functions
function Repair-DNSIssues {
    <#
    .SYNOPSIS
        Fixes DNS resolution issues.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       FIXING DNS ISSUES               " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Flush DNS cache
    Invoke-CommandWithLogging -Description "Flush DNS resolver cache" -Command {
        Clear-DnsClientCache
    }

    # Release and renew DHCP (if applicable)
    Invoke-CommandWithLogging -Description "Release DHCP lease" -Command {
        ipconfig /release | Out-Null
    }

    Invoke-CommandWithLogging -Description "Renew DHCP lease" -Command {
        ipconfig /renew | Out-Null
    }

    # Register DNS
    Invoke-CommandWithLogging -Description "Register DNS" -Command {
        ipconfig /registerdns | Out-Null
    }

    # Reset DNS client service
    Invoke-CommandWithLogging -Description "Restart DNS Client service" -Command {
        Restart-Service -Name Dnscache -Force -ErrorAction Stop
    }

    Write-Success "DNS fixes completed"
}

function Repair-NetworkIssues {
    <#
    .SYNOPSIS
        Resets network adapters and configuration.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       FIXING NETWORK ISSUES           " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Get active network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    foreach ($adapter in $adapters) {
        Invoke-CommandWithLogging -Description "Restart network adapter: $($adapter.Name)" -Command {
            Restart-NetAdapter -Name $adapter.Name -Confirm:$false
        }
    }

    # Reset network configuration
    Invoke-CommandWithLogging -Description "Reset IP configuration" -Command {
        netsh int ip reset | Out-Null
    } -RequiresRestart $true

    # Disable and re-enable IPv6 (common fix)
    Invoke-CommandWithLogging -Description "Reset IPv6 configuration" -Command {
        netsh int ipv6 reset | Out-Null
    } -RequiresRestart $true

    Write-Success "Network fixes completed (restart may be required)"
}

function Repair-WinsockIssues {
    <#
    .SYNOPSIS
        Resets Winsock catalog.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       RESETTING WINSOCK               " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Invoke-CommandWithLogging -Description "Reset Winsock catalog" -Command {
        netsh winsock reset | Out-Null
    } -RequiresRestart $true

    Invoke-CommandWithLogging -Description "Reset Winsock catalog (alternate)" -Command {
        netsh winsock reset catalog | Out-Null
    } -RequiresRestart $true

    Write-Success "Winsock reset completed (restart required)"
}

function Repair-TCPIPIssues {
    <#
    .SYNOPSIS
        Resets TCP/IP stack.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       RESETTING TCP/IP STACK          " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Invoke-CommandWithLogging -Description "Reset TCP/IP stack" -Command {
        netsh int ip reset | Out-Null
    } -RequiresRestart $true

    Invoke-CommandWithLogging -Description "Reset TCP/IP to default" -Command {
        netsh int tcp reset | Out-Null
    } -RequiresRestart $true

    # Reset routing table
    Invoke-CommandWithLogging -Description "Reset routing table" -Command {
        route /f | Out-Null
    }

    Write-Success "TCP/IP reset completed (restart required)"
}

function Repair-WindowsUpdateIssues {
    <#
    .SYNOPSIS
        Fixes Windows Update issues.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       FIXING WINDOWS UPDATE           " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Stop Windows Update services
    $services = @('wuauserv', 'cryptSvc', 'bits', 'msiserver')

    foreach ($service in $services) {
        Invoke-CommandWithLogging -Description "Stop service: $service" -Command {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        }
    }

    # Clear Windows Update cache
    Invoke-CommandWithLogging -Description "Clear SoftwareDistribution folder" -Command {
        $sdPath = "$env:SystemRoot\SoftwareDistribution"
        if (Test-Path $sdPath) {
            Remove-Item -Path "$sdPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Invoke-CommandWithLogging -Description "Clear catroot2 folder" -Command {
        $catroot = "$env:SystemRoot\System32\catroot2"
        if (Test-Path $catroot) {
            Remove-Item -Path "$catroot\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Re-register Windows Update DLLs
    $dlls = @(
        'atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll',
        'jscript.dll', 'vbscript.dll', 'scrrun.dll', 'msxml.dll', 'msxml3.dll',
        'msxml6.dll', 'actxprxy.dll', 'softpub.dll', 'wintrust.dll', 'dssenh.dll',
        'rsaenh.dll', 'gpkcsp.dll', 'sccbase.dll', 'slbcsp.dll', 'cryptdlg.dll',
        'oleaut32.dll', 'ole32.dll', 'shell32.dll', 'initpki.dll', 'wuapi.dll',
        'wuaueng.dll', 'wuaueng1.dll', 'wucltui.dll', 'wups.dll', 'wups2.dll',
        'wuweb.dll', 'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'muweb.dll', 'wuwebv.dll'
    )

    Invoke-CommandWithLogging -Description "Re-register Windows Update DLLs" -Command {
        foreach ($dll in $dlls) {
            $dllPath = Join-Path $env:SystemRoot "System32\$dll"
            if (Test-Path $dllPath) {
                regsvr32.exe /s $dllPath 2>$null
            }
        }
    }

    # Reset BITS and Windows Update
    Invoke-CommandWithLogging -Description "Reset BITS service" -Command {
        Start-Process -FilePath "bitsadmin.exe" -ArgumentList "/reset /allusers" -Wait -NoNewWindow
    }

    # Restart services
    foreach ($service in $services) {
        Invoke-CommandWithLogging -Description "Start service: $service" -Command {
            Start-Service -Name $service -ErrorAction SilentlyContinue
        }
    }

    Write-Success "Windows Update fixes completed"
}

function Repair-CacheIssues {
    <#
    .SYNOPSIS
        Clears system and application caches.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       CLEARING CACHES                 " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Windows temp files
    Invoke-CommandWithLogging -Description "Clear Windows temp folder" -Command {
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    }

    Invoke-CommandWithLogging -Description "Clear system temp folder" -Command {
        Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Prefetch
    Invoke-CommandWithLogging -Description "Clear prefetch cache" -Command {
        Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue
    }

    # Thumbnail cache
    Invoke-CommandWithLogging -Description "Clear thumbnail cache" -Command {
        $thumbPath = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
        Remove-Item -Path "$thumbPath\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    }

    # Icon cache
    Invoke-CommandWithLogging -Description "Clear icon cache" -Command {
        $iconPath = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
        Remove-Item -Path "$iconPath\iconcache_*.db" -Force -ErrorAction SilentlyContinue
    }

    # Browser caches (Chrome)
    $chromePath = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Cache"
    if (Test-Path $chromePath) {
        Invoke-CommandWithLogging -Description "Clear Chrome cache" -Command {
            Remove-Item -Path "$chromePath\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Browser caches (Edge)
    $edgePath = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data\Default\Cache"
    if (Test-Path $edgePath) {
        Invoke-CommandWithLogging -Description "Clear Edge cache" -Command {
            Remove-Item -Path "$edgePath\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Browser caches (Firefox)
    $firefoxPath = Join-Path $env:LOCALAPPDATA "Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Invoke-CommandWithLogging -Description "Clear Firefox cache" -Command {
            Get-ChildItem -Path $firefoxPath -Directory | ForEach-Object {
                $cachePath = Join-Path $_.FullName "cache2"
                if (Test-Path $cachePath) {
                    Remove-Item -Path "$cachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Write-Success "Cache clearing completed"
}

function Repair-StoreIssues {
    <#
    .SYNOPSIS
        Resets Windows Store cache.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       RESETTING WINDOWS STORE         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Invoke-CommandWithLogging -Description "Reset Windows Store cache" -Command {
        Start-Process -FilePath "wsreset.exe" -Wait -NoNewWindow
    }

    # Re-register Store app
    Invoke-CommandWithLogging -Description "Re-register Windows Store app" -Command {
        Get-AppXPackage -AllUsers *WindowsStore* | Foreach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
        }
    }

    Write-Success "Windows Store reset completed"
}

function Repair-PrinterIssues {
    <#
    .SYNOPSIS
        Resets print spooler.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       RESETTING PRINT SPOOLER         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Stop spooler
    Invoke-CommandWithLogging -Description "Stop Print Spooler service" -Command {
        Stop-Service -Name Spooler -Force -ErrorAction Stop
    }

    # Clear print queue
    Invoke-CommandWithLogging -Description "Clear print queue" -Command {
        $spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"
        Remove-Item -Path "$spoolPath\*" -Force -ErrorAction SilentlyContinue
    }

    # Start spooler
    Invoke-CommandWithLogging -Description "Start Print Spooler service" -Command {
        Start-Service -Name Spooler -ErrorAction Stop
    }

    Write-Success "Print spooler reset completed"
}

function Repair-SystemFiles {
    <#
    .SYNOPSIS
        Runs SFC and DISM repairs.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       REPAIRING SYSTEM FILES          " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-WarningMessage "This may take 15-30 minutes to complete..."

    # DISM first
    Invoke-CommandWithLogging -Description "DISM: Check health" -Command {
        $result = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -ne 0) { throw "DISM CheckHealth failed" }
    }

    Invoke-CommandWithLogging -Description "DISM: Scan health" -Command {
        $result = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -ne 0) { throw "DISM ScanHealth failed" }
    }

    Invoke-CommandWithLogging -Description "DISM: Restore health" -Command {
        $result = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -ne 0) { throw "DISM RestoreHealth failed" }
    }

    # SFC
    Invoke-CommandWithLogging -Description "SFC: Scan and repair system files" -Command {
        $result = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -ne 0) { throw "SFC scan failed" }
    } -RequiresRestart $true

    Write-Success "System file repair completed (restart may be required)"
}
#endregion

#region Main Execution
function Invoke-CommonRepairs {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    WINDOWS COMMON ISSUE AUTO-FIXER    " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Setup logging
    if (-not $LogPath) {
        $LogPath = Get-LogDirectory
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:LogFile = Join-Path $LogPath "Repair-CommonIssues_$timestamp.log"

    Write-RepairLog "Starting Common Issue Auto-Fixer" -Level "INFO"
    Write-RepairLog "Selected fixes: $($Fix -join ', ')" -Level "INFO"

    if ($DryRun) {
        Write-WarningMessage "DRY RUN MODE - No changes will be made"
    }

    # Expand 'All' to all fixes
    if ($Fix -contains 'All') {
        $Fix = @('DNS', 'Network', 'Winsock', 'TCPIP', 'WindowsUpdate', 'Cache', 'Store', 'Printer', 'SystemFiles')
    }

    # Create restore point if requested
    if ($CreateRestorePoint -and -not $DryRun) {
        Write-InfoMessage "Creating system restore point..."
        try {
            $description = "Before Repair-CommonIssues - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Success "System restore point created"
        } catch {
            Write-WarningMessage "Could not create restore point: $($_.Exception.Message)"
        }
    }

    # Confirm if not forced
    if (-not $Force -and -not $DryRun) {
        Write-Host ""
        Write-WarningMessage "The following fixes will be applied: $($Fix -join ', ')"
        Write-WarningMessage "Some fixes may require a system restart."
        Write-Host ""
        $confirm = Read-Host "Do you want to continue? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-InfoMessage "Operation cancelled by user"
            return
        }
    }

    # Apply selected fixes
    foreach ($fixType in $Fix) {
        switch ($fixType) {
            'DNS'           { Repair-DNSIssues }
            'Network'       { Repair-NetworkIssues }
            'Winsock'       { Repair-WinsockIssues }
            'TCPIP'         { Repair-TCPIPIssues }
            'WindowsUpdate' { Repair-WindowsUpdateIssues }
            'Cache'         { Repair-CacheIssues }
            'Store'         { Repair-StoreIssues }
            'Printer'       { Repair-PrinterIssues }
            'SystemFiles'   { Repair-SystemFiles }
        }
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "            REPAIR SUMMARY             " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $successCount = ($script:Results | Where-Object { $_.Success }).Count
    $failCount = ($script:Results | Where-Object { -not $_.Success }).Count

    Write-Host "Total operations: $($script:Results.Count)"
    Write-Host "Successful: $successCount" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "Failed: $failCount" -ForegroundColor Red
    }

    if ($script:RequiresRestart) {
        Write-Host ""
        Write-WarningMessage "RESTART REQUIRED: Some fixes require a system restart to take effect."
    }

    Write-RepairLog "Repair operations completed. Success: $successCount, Failed: $failCount" -Level "INFO"
    Write-Success "Log saved to: $($script:LogFile)"

    # Return results
    return [PSCustomObject]@{
        Results         = $script:Results
        SuccessCount    = $successCount
        FailedCount     = $failCount
        RequiresRestart = $script:RequiresRestart
        LogFile         = $script:LogFile
        ExitCode        = if ($failCount -gt 0) { 1 } else { 0 }
    }
}

# Run repairs
$result = Invoke-CommonRepairs
exit $result.ExitCode
#endregion
