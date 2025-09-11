# Schedule Task Script
# Creates a scheduled task to run startup_script.ps1 at user logon
# Run as Administrator in PowerShell 7+

#Requires -Version 7.0
#Requires -RunAsAdministrator

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
}

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$Timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "✅ $Message" -Color $Colors.Green }
function Write-Info { param([string]$Message) Write-Log "ℹ️ $Message" -Color $Colors.Blue }
function Write-Warning { param([string]$Message) Write-Log "⚠️ $Message" -Color $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Log "❌ $Message" -Color $Colors.Red }

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Create scheduled task
function New-StartupTask {
    param(
        [string]$TaskName = "Windows Automated Updates",
        [string]$TaskDescription = "Automated Chocolatey and Windows Updates at startup"
    )
    
    Write-Info "Creating scheduled task: $TaskName"
    
    # Get the path to the startup script
    $ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) "maintenance\startup_script.ps1"
    
    if (!(Test-Path $ScriptPath)) {
        Write-Error "Startup script not found at: $ScriptPath"
        Write-Info "Please ensure startup_script.ps1 exists in the maintenance directory"
        return $false
    }
    
    Write-Info "Script path: $ScriptPath"
    
    try {
        # Check if task already exists
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($ExistingTask) {
            Write-Warning "Task '$TaskName' already exists. Removing existing task..."
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        
        # Create task action
        $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""
        
        # Create task trigger (at logon)
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        
        # Create task settings
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
        
        # Create task principal (run with highest privileges)
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Register the task
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $TaskDescription
        
        Write-Success "Scheduled task '$TaskName' created successfully"
        Write-Info "Task will run at system startup with highest privileges"
        Write-Info "Task will execute: pwsh.exe -ExecutionPolicy Bypass -File `"$ScriptPath`""
        
        return $true
    }
    catch {
        Write-Error "Failed to create scheduled task: $($_.Exception.Message)"
        return $false
    }
}

# Remove scheduled task
function Remove-StartupTask {
    param(
        [string]$TaskName = "Windows Automated Updates"
    )
    
    Write-Info "Removing scheduled task: $TaskName"
    
    try {
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (!$ExistingTask) {
            Write-Warning "Task '$TaskName' does not exist"
            return $true
        }
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Success "Scheduled task '$TaskName' removed successfully"
        return $true
    }
    catch {
        Write-Error "Failed to remove scheduled task: $($_.Exception.Message)"
        return $false
    }
}

# Show task status
function Show-TaskStatus {
    param(
        [string]$TaskName = "Windows Automated Updates"
    )
    
    Write-Info "Checking status of scheduled task: $TaskName"
    
    try {
        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (!$Task) {
            Write-Warning "Task '$TaskName' does not exist"
            return
        }
        
        $TaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        
        Write-Success "Task '$TaskName' exists"
        Write-Info "State: $($Task.State)"
        Write-Info "Last Run Time: $($TaskInfo.LastRunTime)"
        Write-Info "Last Task Result: $($TaskInfo.LastTaskResult)"
        Write-Info "Next Run Time: $($TaskInfo.NextRunTime)"
        Write-Info "Number of Missed Runs: $($TaskInfo.NumberOfMissedRuns)"
        
        # Show task details
        Write-Info "Task Details:"
        Write-Info "  Description: $($Task.Description)"
        Write-Info "  Author: $($Task.Author)"
        Write-Info "  Principal: $($Task.Principal.UserId)"
        Write-Info "  Run Level: $($Task.Principal.RunLevel)"
        
        # Show triggers
        Write-Info "Triggers:"
        foreach ($Trigger in $Task.Triggers) {
            Write-Info "  - $($Trigger.CimClass.CimClassName): $($Trigger.Enabled)"
        }
        
        # Show actions
        Write-Info "Actions:"
        foreach ($Action in $Task.Actions) {
            Write-Info "  - Execute: $($Action.Execute)"
            Write-Info "    Arguments: $($Action.Arguments)"
        }
    }
    catch {
        Write-Error "Failed to get task status: $($_.Exception.Message)"
    }
}

# Main execution
function Main {
    param(
        [Parameter(Position = 0)]
        [ValidateSet("create", "remove", "status", "help")]
        [string]$Action = "create"
    )
    
    Write-Log "🚀 Windows Scheduled Task Manager" -Color $Colors.Cyan
    
    # Verify prerequisites
    if (!(Test-Administrator)) {
        Write-Error "This script must be run as Administrator"
        exit 1
    }
    
    switch ($Action.ToLower()) {
        "create" {
            Write-Info "Creating scheduled task for automated updates..."
            if (New-StartupTask) {
                Write-Success "Scheduled task created successfully!"
                Write-Info "The startup script will now run automatically at system startup"
                Write-Info "Use 'schedule_task.ps1 status' to check task status"
            }
        }
        "remove" {
            Write-Info "Removing scheduled task..."
            if (Remove-StartupTask) {
                Write-Success "Scheduled task removed successfully!"
            }
        }
        "status" {
            Show-TaskStatus
        }
        "help" {
            Write-Info "Windows Scheduled Task Manager"
            Write-Info ""
            Write-Info "Usage: .\schedule_task.ps1 [action]"
            Write-Info ""
            Write-Info "Actions:"
            Write-Info "  create  - Create the scheduled task (default)"
            Write-Info "  remove  - Remove the scheduled task"
            Write-Info "  status  - Show task status and details"
            Write-Info "  help    - Show this help message"
            Write-Info ""
            Write-Info "Examples:"
            Write-Info "  .\schedule_task.ps1          # Create task"
            Write-Info "  .\schedule_task.ps1 create   # Create task"
            Write-Info "  .\schedule_task.ps1 remove   # Remove task"
            Write-Info "  .\schedule_task.ps1 status   # Show status"
        }
        default {
            Write-Error "Unknown action: $Action"
            Write-Info "Use 'schedule_task.ps1 help' for usage information"
            exit 1
        }
    }
}

# Parse command line arguments and run
if ($args.Count -eq 0) {
    Main -Action "create"
}
else {
    Main -Action $args[0]
}
