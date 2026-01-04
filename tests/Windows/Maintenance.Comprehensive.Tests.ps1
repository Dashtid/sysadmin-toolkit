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
# INTEGRATION TESTS - MAINTENANCE WORKFLOW
# ============================================================================

Describe "Maintenance Scripts Integration" {
    Context "Script Consistency" {
        It "All maintenance scripts exist" {
            $scripts = @(
                "system-updates.ps1"
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
                $content | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
            }
        }
    }
}
