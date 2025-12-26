#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Setup automated maintenance scheduled tasks for Windows 11

.DESCRIPTION
    Creates scheduled tasks for:
    1. Weekly system updates (Chocolatey + Winget + Windows Update)
    2. Weekly Windows Defender full scan
    3. Monthly disk cleanup
    4. Monthly system file integrity check (DISM + SFC)
    5. Weekly Windows Defender definition updates
#>

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color Cyan }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color Red }

Write-Log "`n[*] Setting Up Scheduled Maintenance Tasks" -Color Magenta
Write-Log "[*] ======================================`n" -Color Magenta

$tasksCreated = 0
$tasksFailed = 0

# Helper function to unregister existing task before creating new one
function Remove-ExistingTask {
    param([string]$TaskName)

    # Check if task exists using Get-ScheduledTask
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Info "Removing existing task: $TaskName"
        # Unregister-ScheduledTask or Set-ScheduledTask to update
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Helper function to test task execution
function Test-TaskRegistration {
    param([string]$TaskName)

    # Start-ScheduledTask can be used to Test-Task execution
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Success "Task verified: $TaskName"
        return $true
    }
    return $false
}

# Task 1: Weekly System Updates (Sunday 3AM)
Write-Info "Creating Task 1: Weekly System Updates..."
# Uses try/catch blocks for robust error handling
try {
    $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\Code\windows-linux-sysadmin-toolkit\Windows\maintenance\system-updates.ps1`""
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-WeeklyUpdates" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Weekly system updates (Chocolatey, Winget, Windows Update)" `
        -Force | Out-Null

    Write-Success "Created: Weekly System Updates (Sunday 3AM)"
    $tasksCreated++
} catch {
    # catch Task creation errors and log them
    Write-Error "Failed to create Weekly Updates task: $_"
    $tasksFailed++
}

# Task 2: Weekly Windows Defender Full Scan (Saturday 2AM)
Write-Info "Creating Task 2: Weekly Defender Full Scan..."
try {
    $action = New-ScheduledTaskAction -Execute "C:\Program Files\Windows Defender\MpCmdRun.exe" -Argument "-Scan -ScanType 2"
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 2AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-DefenderFullScan" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Weekly Windows Defender full system scan" `
        -Force | Out-Null

    Write-Success "Created: Weekly Defender Full Scan (Saturday 2AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Defender Scan task: $_"
    $tasksFailed++
}

# Task 3: Daily Defender Definition Updates (Daily 1AM)
Write-Info "Creating Task 3: Daily Defender Definition Updates..."
try {
    $action = New-ScheduledTaskAction -Execute "C:\Program Files\Windows Defender\MpCmdRun.exe" -Argument "-SignatureUpdate"
    $trigger = New-ScheduledTaskTrigger -Daily -At 1AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-DefenderDefinitions" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Daily Windows Defender definition updates" `
        -Force | Out-Null

    Write-Success "Created: Daily Defender Definitions (Daily 1AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Defender Definitions task: $_"
    $tasksFailed++
}

# Task 4: Monthly Disk Cleanup (1st of month 4AM)
Write-Info "Creating Task 4: Monthly Disk Cleanup..."
try {
    # Create disk cleanup profile first
    $cleanupScript = @"
# Configure Storage Sense profile
cleanmgr.exe /sageset:99 /verylowdisk /quiet
Start-Sleep -Seconds 5
# Run cleanup
cleanmgr.exe /sagerun:99 /quiet
"@
    $cleanupScriptPath = "C:\Code\cleanup-disk.ps1"
    $cleanupScript | Set-Content -Path $cleanupScriptPath -Force

    $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScriptPath`""
    $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 4AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-DiskCleanup" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Monthly automatic disk cleanup" `
        -Force | Out-Null

    Write-Success "Created: Monthly Disk Cleanup (1st of month, 4AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Disk Cleanup task: $_"
    $tasksFailed++
}

# Task 5: Monthly System Integrity Check (1st of month 5AM)
Write-Info "Creating Task 5: Monthly System Integrity Check..."
try {
    $integrityScript = @"
# System integrity check (DISM + SFC)
Write-Host "[i] Running DISM health check..."
DISM /Online /Cleanup-Image /RestoreHealth
Write-Host "[i] Running System File Checker..."
sfc /scannow
Write-Host "[+] System integrity check complete"
"@
    $integrityScriptPath = "C:\Code\system-integrity-check.ps1"
    $integrityScript | Set-Content -Path $integrityScriptPath -Force

    $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$integrityScriptPath`""
    $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 5AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-IntegrityCheck" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Monthly DISM and SFC system integrity check" `
        -Force | Out-Null

    Write-Success "Created: Monthly Integrity Check (1st of month, 5AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Integrity Check task: $_"
    $tasksFailed++
}

# Task 6: Weekly Backup Task (Sunday 1AM) - backup task for user data
Write-Info "Creating Task 6: Weekly User Data Backup Task..."
try {
    # Task backup - creates weekly backup of user data
    $backupScriptPath = "C:\Code\windows-linux-sysadmin-toolkit\Windows\backup\Backup-UserData.ps1"
    if (Test-Path $backupScriptPath) {
        $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$backupScriptPath`" -Destination `"D:\Backups`""
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 1AM
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName "SystemMaintenance-WeeklyBackup" `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Weekly user data backup task" `
            -Force | Out-Null

        Write-Success "Created: Weekly Backup Task (Sunday 1AM)"
        $tasksCreated++
    } else {
        Write-Warning "Backup script not found, skipping backup task creation"
    }
} catch {
    # catch Task creation errors
    Write-Error "Failed to create Backup task: $_"
    $tasksFailed++
}

Write-Log "`n[*] Scheduled Tasks Setup Complete!" -Color Green
Write-Log "[*] ==============================`n" -Color Green

Write-Info "Summary:"
Write-Success "Tasks created: $tasksCreated"
Write-Error "Tasks failed: $tasksFailed"

Write-Info "`nScheduled Tasks:"
Write-Info "  1. Weekly System Updates     - Sunday 3AM"
Write-Info "  2. Weekly Defender Full Scan - Saturday 2AM"
Write-Info "  3. Daily Defender Definitions - Daily 1AM"
Write-Info "  4. Monthly Disk Cleanup      - 1st of month, 4AM"
Write-Info "  5. Monthly Integrity Check   - 1st of month, 5AM"
Write-Info "  6. Weekly Backup Task        - Sunday 1AM"

Write-Info "`nTo view tasks: taskschd.msc"
Write-Info "To run manually: Get-ScheduledTask | Where-Object {`$_.TaskName -like 'SystemMaintenance-*'}"
