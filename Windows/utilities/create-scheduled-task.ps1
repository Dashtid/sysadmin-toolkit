<#
.SYNOPSIS
    Creates a scheduled task to run a PowerShell script at logon.

.DESCRIPTION
    This script creates a Windows scheduled task that executes a specified PowerShell script
    with elevated privileges when the user logs on. The task runs hidden in the background.

.PARAMETER ScriptPath
    The full path to the PowerShell script that should be executed by the scheduled task.

.PARAMETER TaskName
    The name of the scheduled task to create.

.PARAMETER Description
    Optional description for the scheduled task.

.EXAMPLE
    .\create-scheduled-task.ps1 -ScriptPath "C:\Scripts\maintenance.ps1" -TaskName "DailyMaintenance"

.NOTES
    Requires PowerShell 7+ and Administrator privileges.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ScriptPath,

    [Parameter(Mandatory = $true)]
    [string]$TaskName,

    [Parameter()]
    [string]$Description = "Automated PowerShell script execution"
)

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Verify PowerShell 7 installation
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
if (-not (Test-Path $pwshPath)) {
    Write-Error "PowerShell 7 not found at: $pwshPath"
    exit 1
}

try {
    # Define task action
    $Action = New-ScheduledTaskAction `
        -Execute $pwshPath `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

    # Define trigger (at logon)
    $Trigger = New-ScheduledTaskTrigger -AtLogOn

    # Define principal (current user with highest privileges)
    $Principal = New-ScheduledTaskPrincipal `
        -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -RunLevel Highest

    # Define settings
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -Hidden

    # Register the task
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Settings $Settings `
        -Description $Description `
        -Force

    Write-Host "Successfully created scheduled task: $TaskName" -ForegroundColor Green
    Write-Host "Script path: $ScriptPath" -ForegroundColor Cyan
    Write-Host "Trigger: At user logon" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to create scheduled task: $($_.Exception.Message)"
    exit 1
}
