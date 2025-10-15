# Pester Tests for Restore-PreviousState.ps1 v1.0.0
# Run: Invoke-Pester -Path .\tests\Windows\RestorePreviousState.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot "Windows\maintenance\Restore-PreviousState.ps1"
    $ModulePath = Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"

    # Import test helpers
    $TestHelpersPath = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    Import-Module $TestHelpersPath -Force
}

AfterAll {
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
}

Describe "Restore-PreviousState.ps1 - Basic Validation" {
    Context "Script File" {
        It "Script file exists" {
            $ScriptPath | Should -Exist
        }

        It "Script has valid PowerShell syntax" {
            Test-ScriptSyntax -Path $ScriptPath | Should -Be $true
        }
    }

    Context "Script Metadata" {
        It "Script has version 1.0.0" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Version:\s*1\.0\.0"
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
            ([regex]::Matches($content, "\.EXAMPLE")).Count | Should -BeGreaterOrEqual 3
        }

        It "Script has .NOTES sections" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.NOTES"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Requirements" {
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
            $content | Should -Match "Import-Module.*\`$modulePath|CommonFunctions\.psm1"
        }

        It "Checks for CommonFunctions module existence" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-Path.*modulePath|CommonFunctions"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Script Parameters" {
    Context "Parameter Definitions" {
        It "Has ListBackups parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "ListBackups"
        }

        It "Has BackupFile parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "BackupFile"
        }

        It "Has Latest parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "Latest"
        }

        It "Has ShowDiff parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "ShowDiff"
        }

        It "Has RestoreSystemRestorePoint parameter" {
            $params = Get-ScriptParameters -Path $ScriptPath
            $params | Should -Contain "RestoreSystemRestorePoint"
        }
    }

    Context "Parameter Sets" {
        It "Has parameter sets defined" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ParameterSetName"
        }

        It "Has List parameter set" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ParameterSetName.*List"
        }

        It "Has Restore parameter set" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ParameterSetName.*Restore"
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
    }
}

Describe "Restore-PreviousState.ps1 - Core Functions" {
    Context "Backup Management Functions" {
        It "Has Get-BackupFiles function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Get-BackupFiles"
        }

        It "Has Show-BackupList function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Show-BackupList"
        }

        It "Get-BackupFiles uses Get-LogDirectory" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Searches for pre-update-state JSON files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "pre-update-state.*\.json"
        }
    }

    Context "State Comparison Functions" {
        It "Has Get-CurrentPackageState function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Get-CurrentPackageState"
        }

        It "Has Compare-PackageState function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Compare-PackageState"
        }

        It "Has Show-PackageDifferences function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Show-PackageDifferences"
        }

        It "Gets Chocolatey package list" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco list.*local"
        }

        It "Gets Winget package list" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "winget list"
        }
    }

    Context "Restore Functions" {
        It "Has Invoke-PackageRestore function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Invoke-PackageRestore"
        }

        It "Has Invoke-SystemRestore function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Invoke-SystemRestore"
        }

        It "Supports package downgrade" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco install.*--version"
        }

        It "Checks for System Restore Points" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-ComputerRestorePoint"
        }

        It "Can launch System Restore GUI" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "rstrui\.exe"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Package Handling" {
    Context "Chocolatey Support" {
        It "Handles Chocolatey package restoration" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco install"
        }

        It "Tracks Chocolatey changes" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Chocolatey.*Upgraded|Downgraded|Added|Removed"
        }

        It "Handles Chocolatey not installed gracefully" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Command choco.*ErrorAction.*SilentlyContinue"
        }
    }

    Context "Winget Support" {
        It "Gets Winget package list" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "winget list"
        }

        It "Handles Winget not installed gracefully" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Command winget.*ErrorAction.*SilentlyContinue"
        }

        It "Documents Winget downgrade limitations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Winget.*downgrade|not well supported"
        }
    }

    Context "Difference Tracking" {
        It "Tracks upgraded packages" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Upgraded"
        }

        It "Tracks downgraded packages" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Downgraded"
        }

        It "Tracks added packages" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Added"
        }

        It "Tracks removed packages" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Removed"
        }
    }
}

Describe "Restore-PreviousState.ps1 - User Interface" {
    Context "Output Formatting" {
        It "Uses CommonFunctions logging" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Success|Write-InfoMessage|Write-WarningMessage|Write-ErrorMessage"
        }

        It "Uses ASCII markers" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\[\+\]|\[-\]|\[i\]|\[!\]"
        }

        It "Does not contain emojis" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
        }

        It "Displays differences with colors" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ForegroundColor"
        }
    }

    Context "Interactive Prompts" {
        It "Prompts for confirmation before restore" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Read-Host.*proceed"
        }

        It "Shows summary of changes" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Restore Summary|Update Summary"
        }

        It "Displays package counts" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Count|Total changes"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Safety Features" {
    Context "Validation and Checks" {
        It "Checks if backup file exists" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-Path.*backup"
        }

        It "Validates JSON structure" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ConvertFrom-Json"
        }

        It "Handles no changes gracefully" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "No.*changes|already in.*state"
        }
    }

    Context "ShouldProcess Support" {
        It "Uses PSCmdlet.ShouldProcess" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\`$PSCmdlet\.ShouldProcess"
        }

        It "Supports WhatIf mode" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "WhatIfPreference"
        }
    }

    Context "Error Handling" {
        It "Has try/catch blocks" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "(?s)try\s*\{.*catch"
        }

        It "Has main exception handler" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Fatal error"
        }

        It "Handles restore failures" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Failed to.*restore|Error.*restoring"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Security" {
    Context "No Hardcoded Secrets" {
        It "Does not contain passwords" {
            Test-NoHardcodedSecrets -Path $ScriptPath | Should -Be $true
        }

        It "Does not contain API keys" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match 'api[_-]?key\s*=\s*["`''][^"`'']+["`'']'
        }

        It "Does not contain private IPs" {
            Test-NoPrivateIPs -Path $ScriptPath -AllowExampleIPs | Should -Be $true
        }
    }
}

Describe "Restore-PreviousState.ps1 - Code Quality" {
    Context "Function Documentation" {
        It "Functions have synopsis" {
            $content = Get-Content $ScriptPath -Raw
            $functionMatches = [regex]::Matches($content, "function \w+")
            $synopsisMatches = [regex]::Matches($content, "\.SYNOPSIS")

            # Should have at least as many SYNOPSIS as major functions
            $synopsisMatches.Count | Should -BeGreaterOrEqual 5
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
            $content | Should -Match "(?s)#region.*#endregion"
        }

        It "Has Main Execution region" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#region Main Execution"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Integration" {
    Context "Module Integration" {
        It "Uses Get-LogDirectory from CommonFunctions" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Uses CommonFunctions logging" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Success|Write-InfoMessage"
        }

        It "Uses Test-IsAdministrator" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-IsAdministrator"
        }
    }

    Context "system-updates.ps1 Integration" {
        It "Works with pre-update-state files from system-updates.ps1" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "pre-update-state_.*\.json"
        }

        It "Reads JSON structure created by system-updates.ps1" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "(?s)Chocolatey.*Winget"
        }
    }
}

Describe "Restore-PreviousState.ps1 - Limitations and Documentation" {
    Context "Known Limitations" {
        It "Documents Winget limitations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "(?s)Winget.*downgrade.*not.*supported|Limitations"
        }

        It "Documents Windows Update limitations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "(?s)Windows Update.*cannot.*rolled back|System Restore"
        }

        It "Has NOTES section with limitations" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "(?s)\.NOTES.*Limitations"
        }
    }
}
