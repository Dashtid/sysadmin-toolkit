# Pester Tests for Windows Maintenance Scripts
# Run: Invoke-Pester -Path .\tests\Windows\Maintenance.Tests.ps1
# Updated: 2025-10-15 for v2.0.0 scripts

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $MaintenancePath = Join-Path $ProjectRoot "Windows\maintenance"

    # Import test helpers
    $TestHelpersPath = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    Import-Module $TestHelpersPath -Force
}

AfterAll {
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
}

Describe "Maintenance Script Existence" {
    Context "Core Scripts" {
        It "system-updates.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $scriptPath | Should -Exist
        }

        It "startup_script.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "startup_script.ps1"
            $scriptPath | Should -Exist
        }

        It "update-defender.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $scriptPath | Should -Exist
        }

        It "Restore-PreviousState.ps1 should exist (v2.0.0)" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $scriptPath | Should -Exist
        }
    }

    Context "Configuration Files" {
        It "config.example.json should exist" {
            $configPath = Join-Path $MaintenancePath "config.example.json"
            $configPath | Should -Exist
        }

        It "README.md should exist" {
            $readmePath = Join-Path $MaintenancePath "README.md"
            $readmePath | Should -Exist
        }
    }

    Context "Examples Directory" {
        It "examples directory should exist" {
            $examplesPath = Join-Path $MaintenancePath "examples"
            $examplesPath | Should -Exist
        }

        It "weekly-updates-task.xml should exist" {
            $taskPath = Join-Path $MaintenancePath "examples\weekly-updates-task.xml"
            $taskPath | Should -Exist
        }
    }
}

Describe "Maintenance Script Syntax" {
    Context "PowerShell Syntax Validation" {
        It "system-updates.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            Test-ScriptSyntax -Path $scriptPath | Should -Be $true
        }

        It "startup_script.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "startup_script.ps1"
            Test-ScriptSyntax -Path $scriptPath | Should -Be $true
        }

        It "update-defender.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            Test-ScriptSyntax -Path $scriptPath | Should -Be $true
        }

        It "Restore-PreviousState.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            Test-ScriptSyntax -Path $scriptPath | Should -Be $true
        }
    }
}

Describe "Maintenance Script Requirements" {
    Context "Administrator Privileges" {
        It "system-updates.ps1 requires admin" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            ($content -match "#Requires -RunAsAdministrator") | Should -Be $true
        }

        It "startup_script.ps1 requires admin" {
            $scriptPath = Join-Path $MaintenancePath "startup_script.ps1"
            $content = Get-Content $scriptPath -Raw
            ($content -match "#Requires -RunAsAdministrator") | Should -Be $true
        }

        It "Restore-PreviousState.ps1 requires admin" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $content = Get-Content $scriptPath -Raw
            ($content -match "#Requires -RunAsAdministrator") | Should -Be $true
        }
    }

    Context "PowerShell Version" {
        It "Scripts require PowerShell 7.0+" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                if ($content -match "#Requires -Version (\d+)") {
                    [int]$matches[1] | Should -BeGreaterOrEqual 7
                }
            }
        }
    }

    Context "Module Dependencies (v2.0.0)" {
        It "Scripts import CommonFunctions module" {
            $scripts = @("system-updates.ps1", "startup_script.ps1", "Restore-PreviousState.ps1")
            foreach ($script in $scripts) {
                $scriptPath = Join-Path $MaintenancePath $script
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "Import-Module.*\`$modulePath|CommonFunctions\.psm1"
            }
        }

        It "Scripts check for CommonFunctions existence" {
            $scripts = @("system-updates.ps1", "startup_script.ps1", "Restore-PreviousState.ps1")
            foreach ($script in $scripts) {
                $scriptPath = Join-Path $MaintenancePath $script
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "Test-Path.*modulePath|CommonFunctions"
            }
        }
    }
}

Describe "Maintenance Script Content - v2.0.0 Features" {
    Context "Windows Update Functionality" {
        It "system-updates.ps1 uses Windows Update cmdlets" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "PSWindowsUpdate|Get-WindowsUpdate|Install-WindowsUpdate"
        }

        It "Scripts check for pending reboots" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Test-PendingReboot"
        }
    }

    Context "Winget Support" {
        It "system-updates.ps1 includes Winget updates" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "winget|Update-Winget"
        }

        It "system-updates.ps1 has SkipWinget parameter" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "SkipWinget"
        }
    }

    Context "Chocolatey Support" {
        It "system-updates.ps1 includes Chocolatey updates" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "choco|Update-Chocolatey"
        }

        It "system-updates.ps1 has SkipChocolatey parameter" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "SkipChocolatey"
        }
    }

    Context "Safety Features - v2.0.0" {
        It "system-updates.ps1 creates system restore points" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "New-SystemRestorePoint|Checkpoint-Computer"
        }

        It "system-updates.ps1 exports pre-update state" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Export-PreUpdateState|pre-update-state"
        }

        It "system-updates.ps1 supports WhatIf mode" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "SupportsShouldProcess|PSCmdlet\.ShouldProcess"
        }
    }

    Context "Update Summary - v2.0.0" {
        It "system-updates.ps1 shows update summary" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Show-UpdateSummary|Update Summary"
        }

        It "system-updates.ps1 tracks duration" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "StartTime|duration|Total Runtime"
        }
    }
}

Describe "Maintenance Script Error Handling" {
    Context "Exception Handling" {
        It "All maintenance scripts have try/catch blocks" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "try\s*\{.*catch"
            }
        }

        It "Scripts have finally blocks for cleanup" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "finally"
        }
    }
}

Describe "Maintenance Script Output - v2.0.0" {
    Context "Consistent Logging Format" {
        It "Scripts use CommonFunctions logging" {
            $scripts = @("system-updates.ps1", "startup_script.ps1")
            foreach ($script in $scripts) {
                $scriptPath = Join-Path $MaintenancePath $script
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "Write-Success|Write-InfoMessage|Write-WarningMessage|Write-ErrorMessage"
            }
        }

        It "Scripts use ASCII markers [+]" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[\+\]"
            }
        }

        It "Scripts use ASCII markers [-]" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[-\]"
            }
        }
    }

    Context "No Emojis (CLAUDE.md Compliance)" {
        It "Scripts don't contain emojis" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
            }
        }
    }

    Context "Progress Indicators - v2.0.0" {
        It "system-updates.ps1 uses Write-Progress" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Write-Progress"
        }
    }
}

Describe "Maintenance Script Security" {
    Context "No Hardcoded Credentials" {
        It "Scripts don't contain passwords" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                Test-NoHardcodedSecrets -Path $_.FullName | Should -Be $true
            }
        }

        It "Scripts don't contain private IPs" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                Test-NoPrivateIPs -Path $_.FullName -AllowExampleIPs | Should -Be $true
            }
        }
    }
}

Describe "Maintenance Script Configuration - v2.0.0" {
    Context "Config File Support" {
        It "system-updates.ps1 supports config files" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "ConfigFile|ConvertFrom-Json"
        }

        It "config.example.json is valid JSON" {
            $configPath = Join-Path $MaintenancePath "config.example.json"
            {
                $config = Get-Content $configPath -Raw | ConvertFrom-Json
                $config | Should -Not -BeNullOrEmpty
            } | Should -Not -Throw
        }

        It "config.example.json has expected properties" {
            $configPath = Join-Path $MaintenancePath "config.example.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.PSObject.Properties.Name | Should -Contain "AutoReboot"
            $config.PSObject.Properties.Name | Should -Contain "SkipWinget"
            $config.PSObject.Properties.Name | Should -Contain "SkipChocolatey"
        }
    }
}

Describe "Maintenance Script Logging - v2.0.0" {
    Context "Centralized Logging" {
        It "Scripts use Get-LogDirectory" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Scripts create timestamped log files" {
            $scripts = @("system-updates.ps1", "startup_script.ps1")
            foreach ($script in $scripts) {
                $scriptPath = Join-Path $MaintenancePath $script
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "Get-Date.*Format.*log"
            }
        }

        It "Scripts use transcript logging" {
            $scripts = @("system-updates.ps1", "startup_script.ps1")
            foreach ($script in $scripts) {
                $scriptPath = Join-Path $MaintenancePath $script
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "Start-Transcript"
            }
        }
    }
}

Describe "Maintenance Script Documentation - v2.0.0" {
    Context "Comment-Based Help" {
        It "All scripts have comment-based help" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" -Exclude "*.backup.ps1" | ForEach-Object {
                Test-ScriptHasCommentHelp -Path $_.FullName | Should -Be $true
            }
        }

        It "Scripts have version information" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Version:\s*2\.0\.0"
        }

        It "Scripts have changelog" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.CHANGELOG"
        }
    }

    Context "README Documentation" {
        It "README.md exists" {
            $readmePath = Join-Path $MaintenancePath "README.md"
            $readmePath | Should -Exist
        }

        It "README documents system-updates.ps1" {
            $readmePath = Join-Path $MaintenancePath "README.md"
            $content = Get-Content $readmePath -Raw
            $content | Should -Match "system-updates\.ps1"
        }

        It "README documents configuration" {
            $readmePath = Join-Path $MaintenancePath "README.md"
            $content = Get-Content $readmePath -Raw
            $content | Should -Match "config\.json|Configuration"
        }
    }
}

Describe "Rollback Capability - v2.0.0" {
    Context "Restore-PreviousState.ps1" {
        It "Restore script exists" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $scriptPath | Should -Exist
        }

        It "Restore script has ListBackups parameter" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "ListBackups"
        }

        It "Restore script has Latest parameter" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\`$Latest"
        }

        It "Restore script has ShowDiff parameter" {
            $scriptPath = Join-Path $MaintenancePath "Restore-PreviousState.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "ShowDiff"
        }
    }
}
