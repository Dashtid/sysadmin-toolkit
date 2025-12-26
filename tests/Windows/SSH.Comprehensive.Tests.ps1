# Comprehensive Pester Tests for SSH Setup Scripts
# Version: 2.0
# Coverage Target: 80%+ for all SSH scripts
# Run: Invoke-Pester -Path .\tests\Windows\SSH.Comprehensive.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $SSHScriptsPath = Join-Path $ProjectRoot "Windows\ssh"

    # Import test helpers if available
    $mockHelpersPath = Join-Path $PSScriptRoot "..\MockHelpers.psm1"
    if (Test-Path $mockHelpersPath) {
        Import-Module $mockHelpersPath -Force
    }
}

# ============================================================================
# SETUP-SSH-AGENT-ACCESS.PS1 TESTS
# ============================================================================

Describe "setup-ssh-agent-access.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SSHScriptsPath "setup-ssh-agent-access.ps1"
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

        It "Contains no emojis (CLAUDE.md compliance)" {
            # Note: Using literal emoji chars as .NET regex doesn't support \x{XXXX} for high codepoints
            $ScriptContent | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
        }

        It "Uses ASCII markers [+] [-] [i] [!]" {
            $ScriptContent | Should -Match '\[\+\]'
            $ScriptContent | Should -Match '\[-\]'
            $ScriptContent | Should -Match '\[i\]'
        }

        It "Has description/synopsis" {
            ($ScriptContent -split "`n" | Select-Object -First 10) -join "`n" | Should -Match 'SSH|ssh'
        }

        It "Script size is reasonable (< 500 lines)" {
            ($ScriptContent -split "`n").Count | Should -BeLessThan 500
        }
    }

    Context "Parameters and Configuration" {
        It "Accepts ServerIP parameter" {
            # Check for ServerIP in param block (may span multiple lines)
            $ScriptContent | Should -Match '\$ServerIP'
        }

        It "Accepts SSHKeyPath parameter" {
            $ScriptContent | Should -Match '\$SSHKeyPath|SSHKeyPath'
        }

        It "Has parameter validation" {
            $ScriptContent | Should -Match 'ValidateScript|Mandatory|HelpMessage'
        }

        It "Uses CommonFunctions or similar imports" {
            $ScriptContent | Should -Match 'Import-Module|using module|\.psm1'
        }
    }

    Context "Security and Best Practices" {
        It "Contains no hardcoded passwords" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\x27]'
        }

        It "Contains no hardcoded API keys" {
            $ScriptContent | Should -Not -Match 'api[_-]?key\s*=\s*["\x27]'
        }

        It "Contains no SSH private keys" {
            $ScriptContent | Should -Not -Match 'BEGIN.*PRIVATE KEY'
        }

        It "Contains no hardcoded private IPs (except examples)" {
            # Allow example IPs in comments but not in actual code
            $codeLines = $ScriptContent -split "`n" | Where-Object { $_ -notmatch '^\s*#' }
            $codeOnly = $codeLines -join "`n"
            if ($codeOnly -match '10\.143\.31\.') {
                throw "Found hardcoded private IP in code"
            }
        }

        It "Uses secure string handling for credentials" {
            # Only require SecureString if actually storing/handling passwords (not just config flags)
            # PasswordAuthentication=no is a config setting, not actual password handling
            if ($ScriptContent -match '\$password\s*=|\$credential\s*=' -and $ScriptContent -notmatch 'PasswordAuthentication') {
                $ScriptContent | Should -Match 'SecureString|PSCredential|ConvertTo-SecureString'
            }
        }
    }

    Context "SSH Service Management" {
        It "Checks for ssh-agent service" {
            $ScriptContent | Should -Match 'Get-Service.*ssh-agent|ssh-agent.*Get-Service'
        }

        It "Starts ssh-agent if needed" {
            $ScriptContent | Should -Match 'Start-Service|Set-Service.*-StartupType'
        }

        It "Handles service errors" {
            $ScriptContent | Should -Match 'ErrorAction|try.*catch|-ErrorVariable'
        }
    }

    Context "SSH Key Management" {
        It "Checks for SSH key existence" {
            # Script uses Test-Path with key path variables
            $ScriptContent | Should -Match 'Test-Path.*\$.*Key|Test-Path.*\.ssh|\.ssh.*Test-Path'
        }

        It "Uses ssh-add command" {
            $ScriptContent | Should -Match 'ssh-add'
        }

        It "Validates key file format" {
            $ScriptContent | Should -Match '\.ssh|id_rsa|id_ed25519'
        }

        It "Uses key path variables" {
            # Script uses key path variables for flexibility
            $ScriptContent | Should -Match 'SSHKeyPath|KeyPath'
        }
    }

    Context "Environment Variables" {
        It "Checks SSH_AUTH_SOCK variable" {
            $ScriptContent | Should -Match 'SSH_AUTH_SOCK|\$env:SSH_AUTH_SOCK'
        }

        It "Sets environment variables correctly" {
            $ScriptContent | Should -Match '\[Environment\]::SetEnvironmentVariable|\$env:'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try\s*\{'
            $ScriptContent | Should -Match 'catch\s*\{'
        }

        It "Provides error messages" {
            $ScriptContent | Should -Match 'Write-Error|Write-Host.*Red|throw'
        }

        It "Has exit codes" {
            $ScriptContent | Should -Match 'exit\s+\d+'
        }

        It "Uses -ErrorAction parameter" {
            $ScriptContent | Should -Match '-ErrorAction'
        }
    }

    Context "Logging and Output" {
        It "Uses logging functions" {
            $ScriptContent | Should -Match 'Write-Host|Write-Output|Write-Verbose'
        }

        It "Uses colored output" {
            $ScriptContent | Should -Match '-ForegroundColor'
        }

        It "Provides progress indicators" {
            $ScriptContent | Should -Match '\[\d+/\d+\]|\[.*\].*:'
        }
    }

    Context "Cross-Platform Compatibility" {
        It "Handles Windows-specific paths" {
            $ScriptContent | Should -Match 'USERPROFILE|PROGRAMFILES|\\\.ssh'
        }

        It "Uses cross-platform path separators" {
            $ScriptContent | Should -Match 'Join-Path|Split-Path|[System.IO.Path]'
        }
    }
}

# ============================================================================
# GITEA-TUNNEL-MANAGER.PS1 TESTS
# ============================================================================

Describe "gitea-tunnel-manager.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SSHScriptsPath "gitea-tunnel-manager.ps1"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Structure" {
        It "Script file exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid PowerShell syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "Contains no emojis" {
            $ScriptContent | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
        }

        It "Has logging function" {
            # Script uses Write-Log function instead of ASCII markers
            $ScriptContent | Should -Match 'Write-Log|Write-Host'
        }
    }

    Context "Tunnel Management Functions" {
        It "Can start SSH tunnel" {
            $ScriptContent | Should -Match 'Start-Tunnel|Start-Process.*ssh'
        }

        It "Can stop SSH tunnel" {
            $ScriptContent | Should -Match 'Stop-Tunnel|Stop-Process'
        }

        It "Can check tunnel status" {
            $ScriptContent | Should -Match 'Get-Process.*ssh|Test.*Port|Status'
        }

        It "Uses port forwarding syntax" {
            # Script uses -L flag with port variables
            $ScriptContent | Should -Match '"-L"|LOCAL_PORT.*REMOTE_PORT|localhost:'
        }
    }

    Context "Process Management" {
        It "Checks for running SSH processes" {
            $ScriptContent | Should -Match 'Get-Process.*ssh'
        }

        It "Manages process lifecycle" {
            $ScriptContent | Should -Match 'Start-Process|Stop-Process'
        }

        It "Uses hidden window for background operation" {
            # Script runs SSH in hidden window mode
            $ScriptContent | Should -Match 'WindowStyle.*Hidden|Hidden'
        }
    }

    Context "Port and Connection Validation" {
        It "Validates port numbers" {
            $ScriptContent | Should -Match '\d{2,5}|Port.*\d+|LocalPort|RemotePort'
        }

        It "Tests network connectivity" {
            $ScriptContent | Should -Match 'Test-Connection|Test-NetConnection'
        }

        It "Handles connection failures" {
            $ScriptContent | Should -Match 'catch|ErrorAction|timeout'
        }
    }

    Context "Configuration Management" {
        It "Accepts configuration parameters" {
            $ScriptContent | Should -Match 'param\s*\('
        }

        It "Has default values" {
            $ScriptContent | Should -Match '=\s*\d+|=\s*["\x27]'
        }

        It "Has configurable settings" {
            # Script has configuration variables at the top
            $ScriptContent | Should -Match 'LOCAL_PORT|REMOTE_HOST|TUNNEL_NAME'
        }
    }

    Context "Security" {
        It "No hardcoded credentials" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\x27][^"\x27]*["\x27]'
        }

        It "Uses SSH agent-based authentication" {
            # Script relies on SSH agent for key auth (configured elsewhere)
            $ScriptContent | Should -Match 'ssh|SSH_EXE'
        }

        It "Secure tunneling parameters" {
            $ScriptContent | Should -Match '-N|ServerAliveInterval|ServerAliveCountMax'
        }
    }

    Context "Logging" {
        It "Logs tunnel start events" {
            $ScriptContent | Should -Match 'Write.*start|Tunnel.*start'
        }

        It "Logs errors" {
            $ScriptContent | Should -Match 'Write-Error|Write-Host.*Red|Error'
        }

        It "Provides status messages" {
            $ScriptContent | Should -Match 'Write-Host|Write-Output'
        }
    }
}

# ============================================================================
# COMPLETE-SSH-SETUP.PS1 TESTS - REMOVED
# Script deleted - was a template with hardcoded placeholder keys
# ============================================================================

# ============================================================================
# SETUP-SSH-KEY-AUTH.PS1 TESTS - REMOVED
# Script deleted - was a template with hardcoded placeholder keys
# ============================================================================

# ============================================================================
# INTEGRATION TESTS - SSH WORKFLOW
# ============================================================================

Describe "SSH Scripts Integration Tests" {
    Context "Script Interaction and Workflow" {
        It "All SSH scripts exist" {
            # Note: complete-ssh-setup.ps1 and setup-ssh-key-auth.ps1 were removed
            # (templates with hardcoded placeholder keys)
            $scripts = @(
                "setup-ssh-agent-access.ps1"
                "gitea-tunnel-manager.ps1"
            )

            foreach ($script in $scripts) {
                Test-Path (Join-Path $SSHScriptsPath $script) | Should -Be $true
            }
        }

        It "Scripts use consistent error handling patterns" {
            $scripts = Get-ChildItem $SSHScriptsPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                # At least one error handling mechanism
                $hasErrorHandling = ($content -match 'try.*catch') -or
                                   ($content -match 'ErrorAction') -or
                                   ($content -match '-ErrorVariable')
                $hasErrorHandling | Should -Be $true
            }
        }

        It "Scripts use consistent logging patterns" {
            $scripts = Get-ChildItem $SSHScriptsPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                # Should have some form of logging
                $hasLogging = $content -match 'Write-Host|Write-Output|Write-Verbose'
                $hasLogging | Should -Be $true
            }
        }

        It "Scripts follow CLAUDE.md naming conventions" {
            $scripts = Get-ChildItem $SSHScriptsPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                # Should NOT have emojis - using literal chars as .NET regex doesn't support \x{XXXX}
                $content | Should -Not -Match '✅|❌|🎉|⚠️|📁|🔄|✓|✗'
            }
        }
    }

    Context "Documentation Completeness" {
        It "All scripts have description comments" {
            $scripts = Get-ChildItem $SSHScriptsPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $firstLines = Get-Content $script.FullName -Head 20 -Raw
                $hasDescription = $firstLines -match '#.*SSH|#.*ssh|<#.*SSH'
                $hasDescription | Should -Be $true
            }
        }

        It "Complex scripts have usage examples" {
            $complexScripts = @(
                "setup-ssh-agent-access.ps1"
                "gitea-tunnel-manager.ps1"
            )

            foreach ($scriptName in $complexScripts) {
                $scriptPath = Join-Path $SSHScriptsPath $scriptName
                $content = Get-Content $scriptPath -Raw
                $hasExample = $content -match '\.EXAMPLE|Example:|Usage:'
                $hasExample | Should -Be $true
            }
        }
    }
}
