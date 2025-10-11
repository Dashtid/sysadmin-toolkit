<#
.SYNOPSIS
    Updates Windows Defender antivirus definitions.

.DESCRIPTION
    This script updates Windows Defender antivirus signatures using both the
    Update-MpSignature cmdlet and MpCmdRun.exe for redundancy. It provides
    detailed logging and status reporting before and after the update.

.PARAMETER LogPath
    Optional custom path for log files. Defaults to a 'logs' subfolder in the script directory.

.PARAMETER SkipVersionCheck
    Skip the version comparison check after update.

.EXAMPLE
    .\update-defender.ps1

.EXAMPLE
    .\update-defender.ps1 -LogPath "C:\CustomLogs\Defender"

.NOTES
    Requires Administrator privileges.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [switch]$SkipVersionCheck
)

# Initialize logging
if (-not $LogPath) {
    $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "logs"
}

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$logFile = Join-Path -Path $LogPath -ChildPath "DefenderUpdate_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').txt"
Start-Transcript -Path $logFile

try {
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "This script must be run as an administrator."
        exit 1
    }

    # Get initial Defender status
    Write-Host "`n=== Initial Defender Status ===" -ForegroundColor Cyan
    $initialStatus = Get-MpComputerStatus
    $initialStatus | Select-Object AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AntivirusEnabled | Format-Table -AutoSize

    # Check Windows Defender service status
    Write-Host "`n=== Defender Service Status ===" -ForegroundColor Cyan
    $defenderService = Get-Service WinDefend
    $defenderService | Select-Object Status, StartType, DisplayName | Format-Table -AutoSize

    if ($defenderService.Status -ne 'Running') {
        Write-Warning "Windows Defender service is not running. Attempting to start..."
        Start-Service WinDefend
        Start-Sleep -Seconds 5
    }

    # Update Windows Defender Definitions
    Write-Host "`n=== Updating Windows Defender Definitions ===" -ForegroundColor Cyan
    try {
        # Method 1: Use Update-MpSignature cmdlet
        Write-Host "Updating via Update-MpSignature..." -ForegroundColor Yellow
        Update-MpSignature -UpdateSource MicrosoftUpdateServer -Verbose

        # Method 2: Use MpCmdRun.exe for redundancy
        Write-Host "Updating via MpCmdRun.exe..." -ForegroundColor Yellow
        $mpCmdPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
        if (Test-Path $mpCmdPath) {
            & $mpCmdPath -SignatureUpdate
        }
        else {
            Write-Warning "MpCmdRun.exe not found at expected path: $mpCmdPath"
        }

        Write-Host "Update commands completed." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to update Defender signatures: $($_.Exception.Message)"
        exit 1
    }

    # Wait for updates to process
    Write-Host "`nWaiting for updates to apply..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10

    # Get final status
    Write-Host "`n=== Final Defender Status ===" -ForegroundColor Cyan
    $finalStatus = Get-MpComputerStatus
    $finalStatus | Select-Object AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AntivirusEnabled | Format-Table -AutoSize

    # Compare versions
    if (-not $SkipVersionCheck) {
        Write-Host "`n=== Version Comparison ===" -ForegroundColor Cyan
        if ($finalStatus.AntivirusSignatureVersion -gt $initialStatus.AntivirusSignatureVersion) {
            Write-Host "[+] Update successful!" -ForegroundColor Green
            Write-Host "  Version increased from $($initialStatus.AntivirusSignatureVersion) to $($finalStatus.AntivirusSignatureVersion)" -ForegroundColor Green
        }
        elseif ($finalStatus.AntivirusSignatureVersion -eq $initialStatus.AntivirusSignatureVersion) {
            Write-Host "○ No new updates available" -ForegroundColor Yellow
            Write-Host "  Current version: $($finalStatus.AntivirusSignatureVersion)" -ForegroundColor Yellow
        }
        else {
            Write-Host "[-] Warning: Version appears to have decreased" -ForegroundColor Red
            Write-Host "  This is unusual and may indicate an issue" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Update Process Completed ===" -ForegroundColor Green
    exit 0
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}
finally {
    Stop-Transcript
}
