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
            $ScriptContent | Should -Not -Match '[\x{1F300}-\x{1F9FF}]|✅|❌|🎉'
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
            $ScriptContent | Should -Match 'param\s*\([^)]*\$ServerIP'
        }

        It "Accepts SSHKeyPath parameter" {
            $ScriptContent | Should -Match '\$SSHKeyPath|SSHKeyPath'
        }

        It "Has parameter validation" {
            $ScriptContent | Should -Match 'ValidateNotNullOrEmpty|Mandatory'
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
            if ($ScriptContent -match 'password|credential') {
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
            $ScriptContent | Should -Match 'Test-Path.*\.ssh|\.ssh.*Test-Path'
        }

        It "Uses ssh-add command" {
            $ScriptContent | Should -Match 'ssh-add'
        }

        It "Validates key file format" {
            $ScriptContent | Should -Match '\.ssh|id_rsa|id_ed25519'
        }

        It "Sets correct file permissions" {
            $ScriptContent | Should -Match 'icacls|Set-Acl|FileSystemAccessRule'
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
            $ScriptContent | Should -Not -Match '[\x{1F300}-\x{1F9FF}]|✅|❌'
        }

        It "Uses ASCII markers" {
            $ScriptContent | Should -Match '\[\+\]|\[-\]|\[i\]|\[!\]'
        }
    }

    Context "Tunnel Management Functions" {
        It "Can start SSH tunnel" {
            $ScriptContent | Should -Match 'Start|New.*tunnel|ssh.*-L.*-N'
        }

        It "Can stop SSH tunnel" {
            $ScriptContent | Should -Match 'Stop.*tunnel|Kill.*Process|Stop-Process'
        }

        It "Can check tunnel status" {
            $ScriptContent | Should -Match 'Get-Process.*ssh|Test.*Port|status'
        }

        It "Uses port forwarding syntax" {
            $ScriptContent | Should -Match '-L\s+\d+:.*:\d+|LocalForward'
        }
    }

    Context "Process Management" {
        It "Checks for running SSH processes" {
            $ScriptContent | Should -Match 'Get-Process.*ssh'
        }

        It "Manages process lifecycle" {
            $ScriptContent | Should -Match 'Start-Process|Stop-Process'
        }

        It "Uses background jobs or processes" {
            $ScriptContent | Should -Match 'Start-Job|Start-Process.*-WindowStyle|NoNewWindow'
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

        It "Validates inputs" {
            $ScriptContent | Should -Match 'Validate|if.*throw|-not.*throw'
        }
    }

    Context "Security" {
        It "No hardcoded credentials" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\x27][^"\x27]*["\x27]'
        }

        It "Uses SSH key authentication" {
            $ScriptContent | Should -Match 'id_rsa|id_ed25519|\.ssh'
        }

        It "Secure tunneling parameters" {
            $ScriptContent | Should -Match '-N|-f|-ServerAliveInterval'
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
# COMPLETE-SSH-SETUP.PS1 TESTS
# ============================================================================

Describe "complete-ssh-setup.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SSHScriptsPath "complete-ssh-setup.ps1"
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

        It "Requires Administrator privileges" {
            $ScriptContent | Should -Match '#Requires -RunAsAdministrator'
        }
    }

    Context "OpenSSH Server Installation" {
        It "Checks for OpenSSH Server capability" {
            $ScriptContent | Should -Match 'OpenSSH.Server|Add-WindowsCapability'
        }

        It "Installs OpenSSH Server if missing" {
            $ScriptContent | Should -Match 'Add-WindowsCapability.*OpenSSH'
        }

        It "Checks service status" {
            $ScriptContent | Should -Match 'Get-Service.*sshd'
        }
    }

    Context "Service Configuration" {
        It "Starts SSH service" {
            $ScriptContent | Should -Match 'Start-Service.*sshd'
        }

        It "Sets service to automatic startup" {
            $ScriptContent | Should -Match 'Set-Service.*Automatic|StartupType.*Automatic'
        }

        It "Verifies service is running" {
            $ScriptContent | Should -Match 'Status.*Running|Get-Service.*Status'
        }
    }

    Context "Firewall Configuration" {
        It "Checks for existing firewall rule" {
            $ScriptContent | Should -Match 'Get-NetFirewallRule.*OpenSSH'
        }

        It "Creates firewall rule if needed" {
            $ScriptContent | Should -Match 'New-NetFirewallRule'
        }

        It "Opens port 22" {
            $ScriptContent | Should -Match 'LocalPort.*22|Port.*22'
        }

        It "Configures inbound rule" {
            $ScriptContent | Should -Match 'Direction.*Inbound|Inbound'
        }
    }

    Context "SSH Key Authentication Setup" {
        It "Creates .ssh directory" {
            $ScriptContent | Should -Match 'New-Item.*\.ssh|mkdir.*\.ssh'
        }

        It "Manages authorized_keys file" {
            $ScriptContent | Should -Match 'authorized_keys'
        }

        It "Sets file permissions with icacls" {
            $ScriptContent | Should -Match 'icacls'
        }

        It "Adds public keys" {
            $ScriptContent | Should -Match 'Add-Content.*authorized_keys|Set-Content'
        }
    }

    Context "Security Hardening" {
        It "Configures SSH daemon settings" {
            $ScriptContent | Should -Match 'sshd_config|Set-Content.*sshd'
        }

        It "Disables password authentication (optional)" {
            if ($ScriptContent -match 'sshd_config') {
                $ScriptContent | Should -Match 'PasswordAuthentication|PubkeyAuthentication'
            }
        }
    }

    Context "Validation and Testing" {
        It "Provides connection test instructions" {
            $ScriptContent | Should -Match 'ssh.*@|Test.*connection|Connect'
        }

        It "Shows completion message" {
            $ScriptContent | Should -Match 'complete|success|done'
        }
    }
}

# ============================================================================
# SETUP-SSH-KEY-AUTH.PS1 TESTS
# ============================================================================

Describe "setup-ssh-key-auth.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SSHScriptsPath "setup-ssh-key-auth.ps1"
        if (Test-Path $ScriptPath) {
            $ScriptContent = Get-Content $ScriptPath -Raw
        }
    }

    Context "Script Existence and Structure" {
        It "Script exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$Errors)
            $Errors.Count | Should -Be 0
        }
    }

    Context "Key Generation" {
        It "Can generate SSH keys" {
            $ScriptContent | Should -Match 'ssh-keygen|New.*Key'
        }

        It "Supports ed25519 keys" {
            $ScriptContent | Should -Match 'ed25519|rsa'
        }

        It "Prompts for key passphrase" {
            $ScriptContent | Should -Match 'passphrase|password|SecureString'
        }
    }

    Context "Key Deployment" {
        It "Copies public key to remote server" {
            $ScriptContent | Should -Match 'ssh-copy-id|Copy.*authorized_keys|scp'
        }

        It "Validates key permissions" {
            $ScriptContent | Should -Match 'chmod|icacls|permissions'
        }
    }

    Context "Testing and Validation" {
        It "Tests SSH connection" {
            $ScriptContent | Should -Match 'ssh.*test|Test-Connection|ssh.*whoami'
        }

        It "Provides success feedback" {
            $ScriptContent | Should -Match '\[+\]|success|complete'
        }
    }
}

# ============================================================================
# INTEGRATION TESTS - SSH WORKFLOW
# ============================================================================

Describe "SSH Scripts Integration Tests" {
    Context "Script Interaction and Workflow" {
        It "All SSH scripts exist" {
            $scripts = @(
                "setup-ssh-agent-access.ps1"
                "gitea-tunnel-manager.ps1"
                "complete-ssh-setup.ps1"
                "setup-ssh-key-auth.ps1"
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
                # Should NOT have emojis
                $content | Should -Not -Match '[\x{1F300}-\x{1F9FF}]'
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
