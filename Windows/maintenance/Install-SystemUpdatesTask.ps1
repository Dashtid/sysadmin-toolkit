#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Registers a Windows Task Scheduler entry that runs system-updates.ps1 on a recurring schedule.

.DESCRIPTION
    Creates (or replaces with -Force) a scheduled task that invokes the toolkit's
    system-updates.ps1 on a weekly cadence. Defaults are chosen for laptop dev environments:

    - Runs as the current user with RunLevel=Highest (no UAC prompt, full winget user-scope access)
    - Weekly on the chosen day/time (default: Sunday 10:00)
    - StartWhenAvailable so a missed window catches up after wake/logon
    - Battery-friendly: starts and continues on battery
    - 3-hour execution cap; concurrent runs ignored

    Use -SystemAccount to run as SYSTEM instead (server scenarios where no user is logged in).
    Note: SYSTEM context misses user-scope winget packages -- only use when you understand
    the tradeoff.

.PARAMETER TaskName
    Scheduled task name (default: SystemUpdates). Use -Force to replace an existing task with this name.

.PARAMETER DayOfWeek
    Day of the week to run on (default: Sunday).

.PARAMETER Time
    Time of day to run (default: 10:00). Accepts any string DateTime can parse.

.PARAMETER AutoReboot
    Pass -AutoReboot through to system-updates.ps1. Disabled by default.

.PARAMETER SystemAccount
    Register the task to run as the SYSTEM account instead of the current user.
    Required when no user is interactively logged in; not recommended for winget-heavy
    workloads (user-scope packages are invisible to SYSTEM).

.PARAMETER Force
    Replace an existing task with the same name. Without -Force, the script fails if the task exists.

.EXAMPLE
    .\Install-SystemUpdatesTask.ps1
    Registers SystemUpdates to run as the current user every Sunday at 10:00.

.EXAMPLE
    .\Install-SystemUpdatesTask.ps1 -DayOfWeek Saturday -Time 06:30 -Force
    Replaces any existing SystemUpdates task with one that runs every Saturday at 06:30.

.EXAMPLE
    .\Install-SystemUpdatesTask.ps1 -SystemAccount -AutoReboot
    Registers the task to run as SYSTEM and auto-reboot if updates require it.
    Suitable for headless servers.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 7.0+ and Administrator privileges (Register-ScheduledTask requires admin)
#>

#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$TaskName = 'SystemUpdates',

    [Parameter()]
    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string]$DayOfWeek = 'Sunday',

    [Parameter()]
    [string]$Time = '10:00',

    [Parameter()]
    [switch]$AutoReboot,

    [Parameter()]
    [switch]$SystemAccount,

    [Parameter()]
    [switch]$Force
)

# Import CommonFunctions for consistent logging
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\lib\CommonFunctions.psm1'
if (-not (Test-Path $modulePath)) {
    Write-Error "[-] CommonFunctions module not found at: $modulePath"
    exit 1
}
Import-Module $modulePath -Force

# Locate the sibling system-updates.ps1
$updateScript = Join-Path -Path $PSScriptRoot -ChildPath 'system-updates.ps1'
if (-not (Test-Path $updateScript)) {
    Write-ErrorMessage "system-updates.ps1 not found at expected path: $updateScript"
    exit 1
}
Write-InfoMessage "Target script: $updateScript"

# Locate pwsh
$pwshPath = Get-PowerShell7Path
if (-not $pwshPath) {
    Write-ErrorMessage 'PowerShell 7 (pwsh.exe) not found. Install it before registering this task.'
    exit 1
}
Write-InfoMessage "PowerShell: $pwshPath"

# Check for existing task
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Force) {
        Write-ErrorMessage "Task '$TaskName' already exists. Re-run with -Force to replace it."
        exit 1
    }
    Write-WarningMessage "Existing task '$TaskName' will be replaced (-Force)."
    if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister existing scheduled task')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

# Build action
$scriptArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$updateScript`""
if ($AutoReboot) { $scriptArgs += ' -AutoReboot' }
$action = New-ScheduledTaskAction -Execute $pwshPath -Argument $scriptArgs -WorkingDirectory $PSScriptRoot

# Build trigger
$triggerTime = [DateTime]::Parse($Time)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $triggerTime

# Build principal
if ($SystemAccount) {
    Write-WarningMessage 'Registering as SYSTEM. User-scope winget packages will not be visible to the task.'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
}
else {
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
}

# Build settings -- laptop-friendly defaults
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 3)

# Register
$description = "Weekly system updates (Winget + Chocolatey + Windows Update) via system-updates.ps1. Installed by Install-SystemUpdatesTask.ps1."
if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Description $description `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings | Out-Null

    Write-Success "Registered scheduled task: $TaskName"
}

# Verify
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task -and $info) {
    Write-InfoMessage "State        : $($task.State)"
    Write-InfoMessage "NextRunTime  : $($info.NextRunTime)"
    Write-InfoMessage "Principal    : $($task.Principal.UserId) (LogonType=$($task.Principal.LogonType), RunLevel=$($task.Principal.RunLevel))"
    Write-InfoMessage "Action       : $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"
}
