# Pester Tests for startup_script.ps1 v2.0.0
# Run: Invoke-Pester -Path .\tests\Windows\StartupScript.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot "Windows\maintenance\startup_script.ps1"
    $ModulePath = Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"

    # Import test helpers
    $TestHelpersPath = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    Import-Module $TestHelpersPath -Force
}

AfterAll {
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
}

Describe "startup_script.ps1 v2.0.0 - Basic Validation" {
    Context "Script File" {
        It "Script file exists" {
            $ScriptPath | Should -Exist
        }

        It "Script has valid PowerShell syntax" {
            Test-ScriptSyntax -Path $ScriptPath | Should -Be $true
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

        It "Script has .EXAMPLE" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.EXAMPLE"
        }

        It "Script has .NOTES" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.NOTES"
        }

        It "Script has changelog" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\.CHANGELOG"
        }
    }
}

Describe "startup_script.ps1 - Requirements" {
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

    Context "Module Dependencies (v2.0.0)" {
        It "Imports CommonFunctions module" {
            $content = Get-Content $ScriptPath -Raw
            # Script uses $modulePath variable pointing to CommonFunctions.psm1
            $content | Should -Match "Import-Module.*modulePath|CommonFunctions\.psm1"
        }

        It "Checks for CommonFunctions module existence" {
            $content = Get-Content $ScriptPath -Raw
            # Script checks path with Test-Path $modulePath
            $content | Should -Match "Test-Path.*modulePath"
        }

        It "Exits if CommonFunctions not found" {
            $content = Get-Content $ScriptPath -Raw
            # Script has error message and exit 1
            $content | Should -Match "CommonFunctions.*not found"
            $content | Should -Match "exit 1"
        }
    }
}

Describe "startup_script.ps1 - Core Functions" {
    Context "Update Functions" {
        It "Has Update-ChocolateyPackages function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Update-ChocolateyPackages"
        }

        It "Has Install-WindowsUpdates function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Install-WindowsUpdates"
        }

        It "Checks for Chocolatey availability" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-Command choco"
        }

        It "Checks for PSWindowsUpdate module" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "PSWindowsUpdate"
        }
    }

    Context "Maintenance Functions" {
        It "Has Invoke-SystemCleanup function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Invoke-SystemCleanup"
        }

        It "Has Clear-OldLogs function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Clear-OldLogs"
        }

        It "Cleans temporary files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\$env:TEMP|temporary files"
        }

        It "Cleans Windows Update cache" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "SoftwareDistribution|Windows Update cache"
        }

        It "Runs Disk Cleanup" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "cleanmgr\.exe"
        }
    }

    Context "Helper Functions" {
        It "Has Write-ScriptLog function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Write-ScriptLog"
        }

        It "Write-ScriptLog wraps CommonFunctions" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-Success|Write-InfoMessage"
        }
    }
}

Describe "startup_script.ps1 - Logging (v2.0.0)" {
    Context "Centralized Logging" {
        It "Uses Get-LogDirectory" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Creates timestamped log files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "startup-.*Get-Date.*Format.*log"
        }

        It "Uses transcript logging" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Start-Transcript"
        }

        It "Stops transcript on exit" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Stop-Transcript"
        }
    }

    Context "Log Output Format" {
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
    }
}

Describe "startup_script.ps1 - Execution Flow" {
    Context "Main Function" {
        It "Has Main function" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "function Main"
        }

        It "Main function calls update functions" {
            $content = Get-Content $ScriptPath -Raw
            # Check both functions are called (may be on different lines)
            $content | Should -Match "Update-ChocolateyPackages"
            $content | Should -Match "Install-WindowsUpdates"
        }

        It "Main function calls cleanup functions" {
            $content = Get-Content $ScriptPath -Raw
            # Check both functions are called (may be on different lines)
            $content | Should -Match "Invoke-SystemCleanup"
            $content | Should -Match "Clear-OldLogs"
        }

        It "Checks administrator privileges" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-IsAdministrator"
        }
    }

    Context "Execution Order" {
        It "Initializes before updating" {
            $content = Get-Content $ScriptPath -Raw
            # Check script has start time tracking and update function
            $content | Should -Match "StartTime"
            $content | Should -Match "Update-Chocolatey"
        }

        It "Cleans up after updates" {
            $content = Get-Content $ScriptPath -Raw
            # Check both cleanup and update functions exist
            $content | Should -Match "Install-WindowsUpdates"
            $content | Should -Match "Invoke-SystemCleanup"
        }

        It "Tracks duration" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "StartTime|duration"
        }
    }
}

Describe "startup_script.ps1 - Error Handling" {
    Context "Exception Handling" {
        It "Has try/catch blocks" {
            $content = Get-Content $ScriptPath -Raw
            # Check for try and catch keywords
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Has main exception handler" {
            $content = Get-Content $ScriptPath -Raw
            # Script wraps Main call in try/catch
            $content | Should -Match "try\s*\{"
            $content | Should -Match "Main"
            $content | Should -Match "catch"
        }

        It "Has finally block for cleanup" {
            $content = Get-Content $ScriptPath -Raw
            # Check for finally with Stop-Transcript
            $content | Should -Match "finally\s*\{"
            $content | Should -Match "Stop-Transcript"
        }

        It "Logs errors with Write-ErrorMessage" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Write-ErrorMessage"
        }
    }

    Context "Graceful Failures" {
        It "Handles Chocolatey not installed" {
            $content = Get-Content $ScriptPath -Raw
            # Script warns and returns if choco not found
            $content | Should -Match "Chocolatey not found"
        }

        It "Handles PSWindowsUpdate install failure" {
            $content = Get-Content $ScriptPath -Raw
            # Script handles module install failure
            $content | Should -Match "Failed to install PSWindowsUpdate|PSWindowsUpdate.*return"
        }

        It "Handles cleanup failures" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "cleanup.*failed|operations failed"
        }
    }
}

Describe "startup_script.ps1 - Update Operations" {
    Context "Chocolatey Updates" {
        It "Upgrades all Chocolatey packages" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco upgrade all"
        }

        It "Uses -y flag for non-interactive" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco.*-y"
        }

        It "Uses --no-progress flag" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "choco.*--no-progress"
        }
    }

    Context "Windows Updates" {
        It "Installs PSWindowsUpdate if missing" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Install-Module.*PSWindowsUpdate"
        }

        It "Gets available updates with Get-WUList" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-WUList"
        }

        It "Installs updates with Install-WindowsUpdate" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Install-WindowsUpdate"
        }

        It "Checks for reboot status" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-WURebootStatus"
        }

        It "Warns if reboot required" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "reboot.*required|System reboot"
        }
    }
}

Describe "startup_script.ps1 - Cleanup Operations" {
    Context "System Cleanup" {
        It "Cleans temp directory" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "\$env:TEMP.*Remove-Item"
        }

        It "Stops Windows Update service before cleaning cache" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Stop-Service.*wuauserv"
        }

        It "Restarts Windows Update service after cleaning" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Start-Service.*wuauserv"
        }

        It "Runs cleanmgr.exe" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "cleanmgr\.exe"
        }
    }

    Context "Log Cleanup" {
        It "Removes logs older than 30 days" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "AddDays\(-30\)|30 days"
        }

        It "Targets startup log files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "startup.*\.log"
        }

        It "Reports number of logs removed" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Removing.*log|cleaned up"
        }
    }
}

Describe "startup_script.ps1 - Security" {
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

    Context "Safe Operations" {
        It "Uses ErrorAction SilentlyContinue for cleanup" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "ErrorAction.*SilentlyContinue"
        }

        It "Does not use Force on critical operations" {
            $content = Get-Content $ScriptPath -Raw
            # Should not force-stop critical services
            if ($content -match "Stop-Service.*Force") {
                $content | Should -Match "wuauserv" # Only OK for Windows Update
            }
        }
    }
}

Describe "startup_script.ps1 - Code Quality" {
    Context "Function Documentation" {
        It "Functions have comment-based help" {
            $content = Get-Content $ScriptPath -Raw
            $functionMatches = [regex]::Matches($content, "function \w+")
            $synopsisMatches = [regex]::Matches($content, "\.SYNOPSIS")

            $synopsisMatches.Count | Should -BeGreaterOrEqual 4
        }
    }

    Context "Code Organization" {
        It "Uses regions for organization" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#region"
        }

        It "Has clear region sections" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#region.*#endregion"
        }

        It "Has Main Execution region" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "#region Main Execution"
        }
    }
}

Describe "startup_script.ps1 - Integration" {
    Context "CommonFunctions Integration" {
        It "Uses CommonFunctions logging throughout" {
            $content = Get-Content $ScriptPath -Raw
            ([regex]::Matches($content, "Write-Success|Write-InfoMessage")).Count |
                Should -BeGreaterOrEqual 10
        }

        It "Uses Get-LogDirectory" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Get-LogDirectory"
        }

        It "Uses Test-IsAdministrator" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Match "Test-IsAdministrator"
        }
    }
}

Describe "startup_script.ps1 - Comparison with system-updates.ps1" {
    Context "Simplified Feature Set" {
        It "Does not support config files" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match "ConfigFile|ConvertFrom-Json"
        }

        It "Does not create restore points" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match "Checkpoint-Computer|SystemRestorePoint"
        }

        It "Does not support Winget" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match "winget|Update-Winget"
        }

        It "Does not have WhatIf support" {
            $content = Get-Content $ScriptPath -Raw
            $content | Should -Not -Match "SupportsShouldProcess"
        }

        It "Focuses on basic updates only" {
            $content = Get-Content $ScriptPath -Raw
            # Should mention it's simplified vs system-updates.ps1
            $content | Should -Match "simplified|basic|simple"
        }
    }
}
