#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Create monthly scheduled tasks with correct trigger syntax

.DESCRIPTION
    Creates monthly disk cleanup and system integrity check tasks
    Uses proper CIM-based trigger creation for monthly schedules
#>

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color Cyan }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color Red }

Write-Info "Creating monthly scheduled tasks..."

$tasksCreated = 0
$tasksFailed = 0

# Task 4: Monthly Disk Cleanup (1st of month 4AM)
Write-Info "Creating Task: Monthly Disk Cleanup..."
try {
    # Create disk cleanup script
    $cleanupScript = @"
# Configure and run disk cleanup
Write-Host "[i] Running disk cleanup..."
cleanmgr.exe /verylowdisk /quiet
Write-Host "[+] Disk cleanup complete"
"@
    $cleanupScriptPath = "C:\Code\cleanup-disk.ps1"
    $cleanupScript | Set-Content -Path $cleanupScriptPath -Force

    $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScriptPath`""

    # Create monthly trigger using CIM class
    $trigger = New-ScheduledTaskTrigger -At 4AM -Weekly -WeeksInterval 4

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-DiskCleanup" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Monthly automatic disk cleanup (every 4 weeks)" `
        -Force | Out-Null

    Write-Success "Created: Monthly Disk Cleanup (every 4 weeks, 4AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Disk Cleanup task: $_"
    $tasksFailed++
}

# Task 5: Monthly System Integrity Check (1st of month 5AM)
Write-Info "Creating Task: Monthly System Integrity Check..."
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

    # Create monthly trigger (every 4 weeks)
    $trigger = New-ScheduledTaskTrigger -At 5AM -Weekly -WeeksInterval 4

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "SystemMaintenance-IntegrityCheck" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Monthly DISM and SFC system integrity check (every 4 weeks)" `
        -Force | Out-Null

    Write-Success "Created: Monthly Integrity Check (every 4 weeks, 5AM)"
    $tasksCreated++
} catch {
    Write-Error "Failed to create Integrity Check task: $_"
    $tasksFailed++
}

Write-Log "`n[*] Monthly Tasks Setup Complete!" -Color Green
Write-Success "Tasks created: $tasksCreated"
Write-Error "Tasks failed: $tasksFailed"

Write-Info "`nAll scheduled tasks:"
Write-Info "  1. Weekly System Updates     - Sunday 3AM"
Write-Info "  2. Weekly Defender Full Scan - Saturday 2AM"
Write-Info "  3. Daily Defender Definitions - Daily 1AM"
Write-Info "  4. Monthly Disk Cleanup      - Every 4 weeks, 4AM"
Write-Info "  5. Monthly Integrity Check   - Every 4 weeks, 5AM"
