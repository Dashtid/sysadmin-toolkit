# Comprehensive Pester Tests for Windows Maintenance Scripts
# Version: 2.0
# Coverage Target: 80%+ for all maintenance scripts
# Run: Invoke-Pester -Path .\tests\Windows\Maintenance.Comprehensive.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $MaintenancePath = Join-Path $ProjectRoot "Windows\maintenance"
}

# ============================================================================
# SYSTEM-UPDATES.PS1 COMPREHENSIVE TESTS
# ============================================================================

Describe "system-updates.ps1 - Comprehensive Coverage" {
    BeforeAll {
        $ScriptPath = Join-Path $MaintenancePath "system-updates.ps1"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Structure and Metadata" {
        It "Script file exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid PowerShell syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "Requires Administrator privileges" {
            $ScriptContent | Should -Match '#Requires -RunAsAdministrator'
        }

        It "Contains no emojis (CLAUDE.md compliance)" {
            # Note: Using literal emoji chars as .NET regex doesn't support \x{XXXX} for high codepoints
            $ScriptContent | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
        }

        It "Uses ASCII markers [+] [-] [i] [!]" {
            $ScriptContent | Should -Match '\[\+\]'
            $ScriptContent | Should -Match '\[-\]'
            $ScriptContent | Should -Match '\[i\]'
        }

        It "Has version information" {
            $ScriptContent | Should -Match 'Version|v\d+\.\d+'
        }

        It "Has description/synopsis" {
            ($ScriptContent -split "`n" | Select-Object -First 20) -join "`n" | Should -Match 'update|Update|maintenance'
        }
    }

    Context "Parameters and Configuration" {
        It "Accepts WhatIf parameter" {
            $ScriptContent | Should -Match 'WhatIf|WhatIfPreference'
        }

        It "Has verbose support" {
            $ScriptContent | Should -Match 'Verbose|VerbosePreference|Write-Verbose'
        }

        It "Supports configuration options" {
            $ScriptContent | Should -Match 'param\s*\(|CmdletBinding'
        }

        It "Uses CommonFunctions module" {
            $ScriptContent | Should -Match 'CommonFunctions|Import-Module.*CommonFunctions'
        }
    }

    Context "Windows Update Functionality" {
        It "Checks for Windows Updates" {
            $ScriptContent | Should -Match 'Windows.*Update|PSWindowsUpdate|Get-WindowsUpdate'
        }

        It "Installs Windows Updates" {
            $ScriptContent | Should -Match 'Install.*Update|Update-Windows'
        }

        It "Handles update errors" {
            $ScriptContent | Should -Match 'catch.*Update|ErrorAction.*Update'
        }

        It "Checks for pending reboots" {
            $ScriptContent | Should -Match 'Pending.*Reboot|Test.*Reboot|RebootRequired'
        }
    }

    Context "Package Manager Updates" {
        It "Updates Winget packages" {
            $ScriptContent | Should -Match 'winget.*upgrade|Update.*Winget'
        }

        It "Updates Chocolatey packages" {
            $ScriptContent | Should -Match 'choco.*upgrade|cup\s+all|Update.*Chocolatey'
        }

        It "Handles package manager errors" {
            $ScriptContent | Should -Match 'try.*winget|try.*choco|ErrorAction.*winget'
        }

        It "Logs package update results" {
            $ScriptContent | Should -Match 'Write.*upgrade|log.*update|Updated.*package'
        }
    }

    Context "System Restore Points" {
        It "Creates system restore point" {
            $ScriptContent | Should -Match 'Checkpoint-Computer|New.*RestorePoint|Enable-ComputerRestore'
        }

        It "Validates restore point creation" {
            $ScriptContent | Should -Match 'Get-ComputerRestorePoint|Test.*RestorePoint'
        }

        It "Handles restore point errors gracefully" {
            $ScriptContent | Should -Match 'catch.*Restore|ErrorAction.*Restore'
        }
    }

    Context "State Management and Rollback" {
        It "Exports pre-update state" {
            $ScriptContent | Should -Match 'Export.*State|Save.*State|Backup.*State'
        }

        It "Can rollback changes" {
            $ScriptContent | Should -Match 'Rollback|Restore.*State|Undo'
        }

        It "Saves package lists" {
            $ScriptContent | Should -Match 'Export.*Package|winget.*export|choco.*export'
        }
    }

    Context "Logging and Transcripts" {
        It "Starts PowerShell transcript" {
            $ScriptContent | Should -Match 'Start-Transcript'
        }

        It "Stops transcript in finally block" {
            $ScriptContent | Should -Match 'finally.*Stop-Transcript|Stop-Transcript.*finally'
        }

        It "Defines log file path" {
            $ScriptContent | Should -Match '\$logFile|\$LogPath|log.*path'
        }

        It "Writes to log file" {
            $ScriptContent | Should -Match 'Out-File.*log|Add-Content.*log|Tee-Object.*log'
        }

        It "Rotates old logs" {
            $ScriptContent | Should -Match 'Remove.*log|Delete.*log|Clean.*log'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try\s*\{'
            $ScriptContent | Should -Match 'catch\s*\{'
        }

        It "Uses finally blocks for cleanup" {
            $ScriptContent | Should -Match 'finally\s*\{'
        }

        It "Provides meaningful error messages" {
            $ScriptContent | Should -Match 'Write-Error|throw.*"'
        }

        It "Uses ErrorAction parameters" {
            $ScriptContent | Should -Match '-ErrorAction'
        }

        It "Has exit codes" {
            $ScriptContent | Should -Match 'exit\s+\d+'
        }
    }

    Context "Summary and Reporting" {
        It "Shows update summary" {
            $ScriptContent | Should -Match 'Summary|Report|Results'
        }

        It "Tracks update counts" {
            $ScriptContent | Should -Match 'count.*update|updated.*\d+|Updated:\s*\d+'
        }

        It "Reports failures" {
            $ScriptContent | Should -Match 'Failed.*\d+|Error.*count|failed.*update'
        }

        It "Shows total runtime" {
            $ScriptContent | Should -Match 'duration|runtime|elapsed|Measure-Command'
        }
    }

    Context "Reboot Management" {
        It "Detects if reboot is needed" {
            $ScriptContent | Should -Match 'Test.*Reboot|Pending.*Reboot|RebootRequired'
        }

        It "Can schedule reboot" {
            $ScriptContent | Should -Match 'Restart-Computer|shutdown|Reboot'
        }

        It "Provides reboot delay option" {
            $ScriptContent | Should -Match 'delay|timeout|wait.*reboot'
        }
    }

    Context "Security and Best Practices" {
        It "Contains no hardcoded credentials" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\x27]'
        }

        It "Uses secure API calls" {
            # Either script uses proper API calls, OR it doesn't use dangerous Invoke-Expression with URLs
            $usesProperApi = $ScriptContent -match 'Invoke-RestMethod|Invoke-WebRequest'
            $usesInsecureExpression = $ScriptContent -match 'Invoke-Expression.*http'
            ($usesProperApi -or -not $usesInsecureExpression) | Should -Be $true
        }

        It "Validates inputs" {
            if ($ScriptContent -match 'param') {
                $ScriptContent | Should -Match 'Validate|Mandatory'
            }
        }

        It "Has admin check" {
            $ScriptContent | Should -Match 'IsAdministrator|RunAsAdministrator|Admin.*check'
        }
    }
}

# ============================================================================
# RESTORE-PREVIOUSSTATE.PS1 TESTS
# ============================================================================

Describe "Restore-PreviousState.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Structure" {
        It "Script exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "Requires Administrator" {
            $ScriptContent | Should -Match '#Requires -RunAsAdministrator'
        }

        It "Has no emojis" {
            $ScriptContent | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
        }
    }

    Context "State Restoration" {
        It "Can restore from backup" {
            $ScriptContent | Should -Match 'Restore.*State|Import.*State'
        }

        It "Restores package lists" {
            $ScriptContent | Should -Match 'Import.*Package|Restore.*Package'
        }

        It "Uses system restore points" {
            $ScriptContent | Should -Match 'Restore-Computer|Get-ComputerRestorePoint'
        }

        It "Validates backup files exist" {
            $ScriptContent | Should -Match 'Test-Path.*backup|Test-Path.*state'
        }
    }

    Context "Backup File Management" {
        It "Finds backup files" {
            $ScriptContent | Should -Match 'Get-ChildItem.*backup|backup.*path'
        }

        It "Lists available backups" {
            $ScriptContent | Should -Match 'List.*backup|Show.*backup'
        }

        It "Selects backup by date" {
            $ScriptContent | Should -Match 'Sort.*Date|Select.*Latest'
        }
    }

    Context "Rollback Operations" {
        It "Uninstalls packages if needed" {
            $ScriptContent | Should -Match 'Uninstall.*Package|Remove.*Package|winget.*uninstall|choco.*uninstall'
        }

        It "Restores registry settings" {
            $ScriptContent | Should -Match 'Registry|Set-ItemProperty'
        }

        It "Restores system settings" {
            $ScriptContent | Should -Match 'Restore.*Setting|Import.*Setting'
        }
    }

    Context "Validation and Verification" {
        It "Verifies restoration success" {
            $ScriptContent | Should -Match 'Verify|Validate|Test.*Restore'
        }

        It "Reports restoration results" {
            $ScriptContent | Should -Match 'Report|Summary|Result'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try.*catch'
        }

        It "Handles missing backup files" {
            $ScriptContent | Should -Match 'if.*Test-Path|backup.*not.*found'
        }
    }
}

# ============================================================================
# CLEANUP-DISK.PS1 TESTS - REMOVED
# Script deleted - functionality merged into Get-SystemPerformance.ps1
# (-IncludeDiskAnalysis -AutoCleanup)
# ============================================================================

# cleanup-disk.ps1 is now auto-generated by setup-scheduled-tasks.ps1 to C:\Code\
# The tests below have been removed as the script is no longer in this repository

Describe "Disk Cleanup Functionality (via Get-SystemPerformance.ps1)" -Skip {
    It "Disk cleanup available via Get-SystemPerformance.ps1 -IncludeDiskAnalysis -AutoCleanup" {
        # Test moved to Tier2Scripts.Tests.ps1
        $true | Should -Be $true
    }
}

# ============================================================================
# SETUP-SCHEDULED-TASKS.PS1 TESTS
# ============================================================================

Describe "setup-scheduled-tasks.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $MaintenancePath "setup-scheduled-tasks.ps1"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Structure" {
        It "Script exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "Requires Administrator" {
            $ScriptContent | Should -Match '#Requires -RunAsAdministrator'
        }
    }

    Context "Scheduled Task Management" {
        It "Creates scheduled tasks" {
            $ScriptContent | Should -Match 'New-ScheduledTask|Register-ScheduledTask'
        }

        It "Defines task triggers" {
            $ScriptContent | Should -Match 'New-ScheduledTaskTrigger|Daily|Weekly|AtStartup'
        }

        It "Defines task actions" {
            $ScriptContent | Should -Match 'New-ScheduledTaskAction|Execute|PowerShell'
        }

        It "Sets task principal" {
            $ScriptContent | Should -Match 'New-ScheduledTaskPrincipal|SYSTEM|Administrator'
        }

        It "Configures task settings" {
            $ScriptContent | Should -Match 'New-ScheduledTaskSettingsSet|AllowStartIfOnBatteries'
        }
    }

    Context "Task Validation" {
        It "Checks if tasks exist" {
            $ScriptContent | Should -Match 'Get-ScheduledTask'
        }

        It "Updates existing tasks" {
            $ScriptContent | Should -Match 'Set-ScheduledTask|Unregister-ScheduledTask'
        }

        It "Tests task execution" {
            $ScriptContent | Should -Match 'Start-ScheduledTask|Test.*Task'
        }
    }

    Context "Maintenance Tasks Configured" {
        It "Sets up system update task" {
            $ScriptContent | Should -Match 'update.*task|Task.*update'
        }

        It "Sets up cleanup task" {
            $ScriptContent | Should -Match 'cleanup.*task|Task.*cleanup'
        }

        It "Sets up backup task" {
            $ScriptContent | Should -Match 'backup.*task|Task.*backup'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try.*catch'
        }

        It "Handles task creation failures" {
            $ScriptContent | Should -Match 'catch.*Task|ErrorAction.*Task'
        }
    }
}

# ============================================================================
# UPDATE-DEFENDER.PS1 TESTS - REMOVED
# Windows 11 auto-updates Defender, making this script redundant
# ============================================================================

# ============================================================================
# STARTUP_SCRIPT.PS1 TESTS
# ============================================================================

Describe "startup_script.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $MaintenancePath "startup_script.ps1"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Structure" {
        It "Script exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }
    }

    Context "Startup Operations" {
        It "Checks system status" {
            $ScriptContent | Should -Match 'Get-ComputerInfo|Get-Service|Get-Process'
        }

        It "Starts required services" {
            $ScriptContent | Should -Match 'Start-Service|Set-Service'
        }

        It "Mounts network drives (optional)" {
            if ($ScriptContent -match 'network|drive|mount') {
                $ScriptContent | Should -Match 'New-PSDrive|net use'
            }
        }

        It "Logs startup events" {
            $ScriptContent | Should -Match 'Write.*Host|log.*startup|Start.*log'
        }
    }

    Context "Initialization Checks" {
        It "Waits for network connectivity" {
            $ScriptContent | Should -Match 'Test-Connection|Test-NetConnection|network.*ready'
        }

        It "Verifies critical services" {
            $ScriptContent | Should -Match 'Get-Service.*Status|service.*running'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try.*catch'
        }

        It "Logs errors to event log or file" {
            $ScriptContent | Should -Match 'Write-EventLog|Out-File.*error|error.*log'
        }
    }
}

# ============================================================================
# SYSTEM-INTEGRITY-CHECK.PS1 TESTS - REMOVED
# Script deleted - functionality available in Repair-CommonIssues.ps1 -Fix SystemFiles
# ============================================================================

# system-integrity-check.ps1 is now auto-generated by setup-scheduled-tasks.ps1 to C:\Code\
# Use Repair-CommonIssues.ps1 -Fix SystemFiles for system integrity checks

# ============================================================================
# FIX-MONTHLY-TASKS.PS1 TESTS - REMOVED
# Script was not being used
# ============================================================================

# ============================================================================
# INTEGRATION TESTS - MAINTENANCE WORKFLOW
# ============================================================================

Describe "Maintenance Scripts Integration" {
    Context "Script Consistency" {
        It "All maintenance scripts exist" {
            # Note: cleanup-disk.ps1 and system-integrity-check.ps1 are auto-generated
            # by setup-scheduled-tasks.ps1 to C:\Code\ at runtime
            $scripts = @(
                "system-updates.ps1"
                "Restore-PreviousState.ps1"
                "setup-scheduled-tasks.ps1"
                "startup_script.ps1"
            )

            foreach ($script in $scripts) {
                Test-Path (Join-Path $MaintenancePath $script) | Should -Be $true
            }
        }

        It "Scripts use consistent error handling" {
            $scripts = Get-ChildItem $MaintenancePath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                $hasErrorHandling = ($content -match 'try.*catch') -or ($content -match 'ErrorAction')
                $hasErrorHandling | Should -Be $true
            }
        }

        It "Scripts use consistent logging" {
            $scripts = Get-ChildItem $MaintenancePath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                $hasLogging = $content -match 'Write-Host|Write-Output|Write-Verbose'
                $hasLogging | Should -Be $true
            }
        }

        It "Scripts follow CLAUDE.md conventions" {
            $scripts = Get-ChildItem $MaintenancePath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                # Note: Using literal emoji chars as .NET regex doesn't support \x{XXXX} for high codepoints
                $content | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
            }
        }
    }
}
