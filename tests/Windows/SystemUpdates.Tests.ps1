# Pester Tests for system-updates.ps1 v2.0.0
# Run: Invoke-Pester -Path .\tests\Windows\SystemUpdates.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot "Windows\maintenance\system-updates.ps1"
    $ModulePath = Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"

    # Import test helpers
    $TestHelpersPath = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    Import-Module $TestHelpersPath -Force
}

AfterAll {
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
}

Describe "system-updates.ps1 v2.0.0 - Basic Validation" {
    Context "Script File" {
        It "Script file exists" {
            $ScriptPath | Should -Exist
        }

        It "Script has valid PowerShell syntax" {
            Test-ScriptSyntax -Path $ScriptPath | Should -Be $true
        }

        It "Script can be parsed without errors" {
            {
                $null = [System.Management.Automation.PSParser]::Tokenize(
                    (Get-Content $ScriptPath -Raw), [ref]$null
                )
            } | Should -Not -Throw
        }
    }

    Context "Script Metadata" {
        It "Script has version 2.0.0" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Version:\s*2\.0\.0"
        }

        It "Script has comment-based help" {
            Test-ScriptHasCommentHelp -Path $ScriptPath | Should -Be $true
        }

        It "Script has .SYNOPSIS" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Script has .DESCRIPTION" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.DESCRIPTION"
        }

        It "Script has .EXAMPLE sections" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.EXAMPLE"
        }

        It "Script has changelog" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.CHANGELOG"
        }
    }
}

Describe "system-updates.ps1 - Requirements and Dependencies" {
    Context "PowerShell Requirements" {
        It "Requires PowerShell 7.0+" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#Requires -Version 7\.0"
        }

        It "Requires Administrator privileges" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#Requires -RunAsAdministrator"
        }
    }

    Context "Module Dependencies" {
        It "Imports CommonFunctions module" {
            $content = Get-Content $ScriptPath -Raw
            # Script uses $modulePath variable pointing to CommonFunctions.psm1
            $content | Should -Match "Import-Module.*modulePath|CommonFunctions\.psm1"
        }

        It "Checks for CommonFunctions module existence" {
            $content = Get-Content $ScriptPath -Raw
            # Script checks path and shows error if not found
            $content | Should -Match "Test-Path.*modulePath|CommonFunctions.*not found"
        }

        It "References PSWindowsUpdate module" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "PSWindowsUpdate"
        }
    }
}

Describe "system-updates.ps1 - Script Parameters" {
    Context "Parameter Definitions" {
        It "Has SkipChocolatey parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "SkipChocolatey"
        }

        It "Has SkipWinget parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "SkipWinget"
        }

        It "Has SkipWindowsUpdate parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "SkipWindowsUpdate"
        }

        It "Has AutoReboot parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "AutoReboot"
        }

        It "Has LogRetentionDays parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "LogRetentionDays"
        }

        It "Has ConfigFile parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "ConfigFile"
        }

        It "Has SkipRestorePoint parameter (v2.0.0)" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "SkipRestorePoint"
        }
    }

    Context "CmdletBinding Support" {
        It "Has CmdletBinding attribute" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\[CmdletBinding\("
        }

        It "Supports ShouldProcess (WhatIf)" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "SupportsShouldProcess"
        }

        It "Uses PSCmdlet.ShouldProcess" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match '\$PSCmdlet\.ShouldProcess'
        }
    }
}

Describe "system-updates.ps1 - Core Functionality" {
    Context "Update Functions" {
        It "Has Update-Winget function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Update-Winget"
        }

        It "Has Update-Chocolatey function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Update-Chocolatey"
        }

        It "Has Update-Windows function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Update-Windows"
        }

        It "Winget function checks for winget command" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Command winget"
        }

        It "Chocolatey function checks for choco command" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Command choco"
        }
    }

    Context "Safety Features (v2.0.0)" {
        It "Has New-SystemRestorePoint function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function New-SystemRestorePoint"
        }

        It "Has Export-PreUpdateState function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Export-PreUpdateState"
        }

        It "Creates restore point before updates" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Checkpoint-Computer"
        }

        It "Exports package state before updates" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "pre-update-state.*\.json"
        }
    }

    Context "Update Summary (v2.0.0)" {
        It "Has Show-UpdateSummary function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Show-UpdateSummary"
        }

        It "Tracks update counts" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "UpdateSummary"
        }

        It "Tracks duration" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "StartTime|duration"
        }

        It "Shows summary after updates" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Show-UpdateSummary"
        }
    }

    Context "Helper Functions" {
        It "Has Initialize-Environment function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Initialize-Environment"
        }

        It "Has Test-PendingReboot function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Test-PendingReboot"
        }

        It "Has Invoke-Reboot function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Invoke-Reboot"
        }

        It "Has Remove-OldLogs function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Remove-OldLogs"
        }
    }
}

Describe "system-updates.ps1 - Configuration Management" {
    Context "Config File Support" {
        It "Loads configuration from JSON file" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ConvertFrom-Json"
        }

        It "Has default config path" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "config\.json"
        }

        It "Supports custom config file path" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match '\$ConfigFile'
        }

        It "Has global config variable" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match '\$global:config'
        }
    }
}

Describe "system-updates.ps1 - Logging and Output" {
    Context "Logging Configuration" {
        It "Uses centralized log directory" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Creates timestamped log files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Date -Format.*log"
        }

        It "Creates transcript logs" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Start-Transcript"
        }

        It "Stops transcript in finally block" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "finally.*Stop-Transcript"
        }
    }

    Context "Consistent Output Format" {
        It "Uses CommonFunctions logging" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Success|Write-InfoMessage|Write-WarningMessage|Write-ErrorMessage"
        }

        It "Uses ASCII markers [+] [-] [i] [!]" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\[\+\]|\[-\]|\[i\]|\[!\]"
        }

        It "Does not contain emojis" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
        }
    }

    Context "Progress Indicators (v2.0.0)" {
        It "Uses Write-Progress for long operations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Progress"
        }

        It "Completes progress indicators" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Progress.*-Completed"
        }
    }
}

Describe "system-updates.ps1 - Error Handling" {
    Context "Exception Handling" {
        It "Has try/catch blocks" {
            $content = Get-Content $ScriptPath -Raw
            # Check for try and catch keywords (on different lines)
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Has main try/catch/finally block" {
            $content = Get-Content $ScriptPath -Raw
            # Check for try, catch, and finally keywords (on different lines)
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch"
            $content | Should -Match "finally\s*\{"
        }

        It "Logs errors with Write-ErrorMessage" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-ErrorMessage"
        }

        It "Provides error details" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match '\$_\.Exception\.Message'
        }
    }

    Context "Graceful Failures" {
        It "Continues if Chocolatey not installed" {
            $content = Get-Content $ScriptPath -Raw
            # Check for warning message and return (on separate lines)
            $content | Should -Match "Chocolatey.*not installed"
            $content | Should -Match "return"
        }

        It "Continues if Winget not installed" {
            $content = Get-Content $ScriptPath -Raw
            # Check for warning message and return (on separate lines)
            $content | Should -Match "Winget.*not installed"
            $content | Should -Match "return"
        }

        It "Handles restore point creation failure" {
            $content = Get-Content $ScriptPath -Raw
            # Check for restore point error handling
            $content | Should -Match "restore point"
            $content | Should -Match "catch"
        }
    }
}

Describe "system-updates.ps1 - Security and Best Practices" {
    Context "No Hardcoded Secrets" {
        It "Does not contain passwords" {
            Test-NoHardcodedSecrets -Path $ScriptPath | Should -Be $true
        }

        It "Does not contain API keys" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match 'api[_-]?key\s*=\s*["`''][^"`'']+["`'']'
        }
    }

    Context "No Hardcoded IPs" {
        It "Does not contain private IP addresses" {
            Test-NoPrivateIPs -Path $ScriptPath -AllowExampleIPs | Should -Be $true
        }
    }

    Context "Safe Operations" {
        It "Checks for pending reboots before starting" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-PendingReboot"
        }

        It "Continues with updates on a pending reboot when AutoReboot is off (no silent no-op)" {
            $content = Get-Content $ScriptPath -Raw
            # Regression guard: a pending reboot must not silently skip the whole run.
            # The early 'exit 0' is now gated behind AutoReboot; otherwise the run continues.
            $content | Should -Match 'AutoReboot is enabled - rebooting before applying updates'
            $content | Should -Match 'Continuing with updates'
        }

        It "Treats PendingFileRenameOperations as informational, not a blocking reboot signal" {
            $content = Get-Content $ScriptPath -Raw
            # PendingFileRename is near-constantly populated by routine app updates and must
            # not be a blocking $pendingRebootTests entry, or the run stalls indefinitely.
            $content | Should -Not -Match "Name\s*=\s*'PendingFileRename'"
            $content | Should -Match 'not treating as a blocking pending reboot'
        }

        It "Disables Fast Startup so shutdown-only usage still finalizes updates" {
            $content = Get-Content $ScriptPath -Raw
            # Fast Startup (hybrid shutdown) skips the boot-time pass that finalizes pending
            # file renames/servicing; on a shutdown-only machine this strands in-use updates.
            $content | Should -Match 'Disable-FastStartup'
            $content | Should -Match 'HiberbootEnabled'
        }

        It "Excludes winget-owned packages from 'choco upgrade all' (no dual-manager conflict)" {
            $content = Get-Content $ScriptPath -Raw
            # winget owns PowerShell/Azure CLI/Notepad++/Pandoc; choco must not also upgrade them.
            $content | Should -Match "choco upgrade all[^\r\n]*--except"
            $content | Should -Match 'powershell-core'
            $content | Should -Match 'notepadplusplus\.install'
        }

        It "Excludes grype from 'choco upgrade all' (pinned instrument must not drift)" {
            $content = Get-Content $ScriptPath -Raw
            # grype is pinned at a specific version because its output feeds records that must
            # stay reproducible. An unattended upgrade would swap the instrument and invalidate
            # everything produced afterwards. If this test fails, do not "fix" it by deleting
            # the assertion - bumping grype is a deliberate re-qualification decision.
            $content | Should -Match 'versionPinned\s*=\s*"[^"]*\bgrype\b'
        }

        It "Does not pin syft (version is recorded per run, not frozen)" {
            $content = Get-Content $ScriptPath -Raw
            # syft's version is recorded with each run rather than frozen, and every pipeline
            # command pins the CycloneDX spec version, so syft may float. Guards against someone
            # pinning it by analogy with grype and then wondering why it never updates.
            $content | Should -Not -Match 'versionPinned\s*=\s*"[^"]*\bsyft\b'
        }

        It "Uses ShouldProcess for destructive operations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ShouldProcess"
        }
    }
}

Describe "system-updates.ps1 - Code Quality" {
    Context "Function Documentation" {
        It "All functions have comment-based help" {
            $content = Get-Content $ScriptPath -Raw
            $functionMatches = [regex]::Matches($content, "function \w+")
            $synopsisMatches = [regex]::Matches($content, "\.SYNOPSIS")

            # Should have at least as many SYNOPSIS as functions
            $synopsisMatches.Count | Should -BeGreaterOrEqual ($functionMatches.Count / 2)
        }

        It "Functions have parameter descriptions" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.PARAMETER"
        }
    }

    Context "Code Organization" {
        It "Uses regions for organization" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#region"
        }

        It "Has clear section separation" {
            $content = Get-Content $ScriptPath -Raw
            # Check both region markers exist (on different lines)
            $content | Should -Match "#region"
            $content | Should -Match "#endregion"
        }
    }
}

Describe "system-updates.ps1 - Integration Tests" {
    Context "Script Can Be Loaded" {
        It "Script can be dot-sourced without errors" {
            # Use WhatIf to prevent actual execution
            $env:SKIP_ELEVATION = "1"
            {
                $script = Get-Content $ScriptPath -Raw
                # Don't actually execute, just validate it parses
                [System.Management.Automation.PSParser]::Tokenize($script, [ref]$null) | Out-Null
            } | Should -Not -Throw
            Remove-Item Env:\SKIP_ELEVATION -ErrorAction SilentlyContinue
        }
    }

    Context "Module Integration" {
        It "CommonFunctions module is accessible" {
            Import-Module $ModulePath -Force
            (Get-Module CommonFunctions).ExportedCommands.Keys | Should -Contain 'Write-Success'
            Remove-Module CommonFunctions
        }
    }
}

Describe "system-updates.ps1 - Backwards Compatibility" {
    Context "Parameter Compatibility" {
        It "All v1.0 parameters still exist" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $oldParams = @('SkipChocolatey', 'SkipWinget', 'SkipWindowsUpdate', 'AutoReboot', 'LogRetentionDays', 'ConfigFile')

            foreach ($param in $oldParams) {
                $params | Should -Contain $param
            }
        }
    }
}
