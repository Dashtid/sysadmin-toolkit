# Pester Tests for SSH Setup Scripts
# Run: Invoke-Pester -Path .\tests\Windows\SSH.Tests.ps1

# Setup variables (compatible with Pester v3 and v5)
$script:ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:SSHScripts = Join-Path $ProjectRoot "Windows\ssh"

Describe "SSH Setup Scripts" {

    BeforeAll {
        # This block runs before all tests in Pester v5
    }

    Context "Script Files Exist" {

        It "setup-ssh-agent-access.ps1 exists" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }

        It "gitea-tunnel-manager.ps1 exists" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }
    }

    Context "Script Syntax Validation" {

        It "setup-ssh-agent-access.ps1 has valid syntax" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "gitea-tunnel-manager.ps1 has valid syntax" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$Errors)
            $Errors.Count | Should -Be 0
        }
    }

    Context "SSH Agent Setup Script Parameters" {

        It "Accepts ServerIP parameter" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[string\]\$ServerIP'
        }

        It "Accepts ServerUser parameter" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[string\]\$ServerUser'
        }
    }

    Context "Gitea Tunnel Manager Parameters" {

        It "Accepts Status switch" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$Status'
        }

        It "Accepts Install switch" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$Install'
        }

        It "Accepts Stop switch" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$Stop'
        }

        It "Accepts Uninstall switch" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$Uninstall'
        }
    }

    Context "No Hardcoded Credentials or IPs" {

        It "setup-ssh-agent-access.ps1 doesn't contain private IPs" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Check for specific private IP patterns that shouldn't be hardcoded
            $Content | Should -Not -Match '10\.143\.31\.18'
        }

        It "gitea-tunnel-manager.ps1 uses configuration variables" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Should have configurable variables at the top
            $Content | Should -Match '\$LOCAL_PORT\s*='
            $Content | Should -Match '\$REMOTE_HOST\s*='
        }

        It "Scripts don't contain SSH private keys" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match 'BEGIN.*PRIVATE KEY'
        }

        It "Scripts don't contain passwords" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match 'password\s*=\s*["\'].*["\']'
        }
    }

    Context "Logging and Error Handling" {

        It "Scripts use Write-Host for output" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'Write-Host'
        }

        It "Scripts handle errors appropriately" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'try\s*\{|catch\s*\{|-ErrorAction'
        }
    }

    Context "SSH Configuration Safety" {

        It "setup-ssh-agent-access.ps1 checks for existing SSH agent" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'ssh-agent|Get-Service.*ssh-agent'
        }

        It "gitea-tunnel-manager.ps1 checks for existing tunnels" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'Get-Process.*ssh|netstat'
        }
    }

    Context "Documentation Comments" {

        It "Scripts have description comments" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '^#.*[Ss]etup|^#.*[Cc]onfigure'
        }

        It "Scripts explain usage" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Should have usage comments or help
            $Content | Should -Match '#.*[Uu]sage|\.SYNOPSIS|\.DESCRIPTION'
        }
    }

    Context "Windows-Specific Functionality" {

        It "setup-ssh-agent-access.ps1 configures Windows SSH agent service" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'Set-Service.*ssh-agent|Start-Service'
        }

        It "gitea-tunnel-manager.ps1 can create scheduled tasks" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'Register-ScheduledTask|New-ScheduledTaskAction'
        }
    }

    Context "No Emojis (Per CLAUDE.md Rules)" {

        It "setup-ssh-agent-access.ps1 uses ASCII markers only" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[\+\]|\[-\]|\[i\]|\[!\]'
            # Should not contain emojis
            $Content | Should -Not -Match '[\x{1F300}-\x{1F9FF}]|✅|❌|⚠️|ℹ️'
        }

        It "gitea-tunnel-manager.ps1 uses ASCII markers only" {
            $ScriptPath = Join-Path $SSHScripts "gitea-tunnel-manager.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match '[\x{1F300}-\x{1F9FF}]|✅|❌|⚠️|ℹ️'
        }
    }
}

Describe "SSH Script Integration" {

    Context "SSH Wrapper Creation" {

        It "setup-ssh-agent-access.ps1 creates ssh-wrapper.sh" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match 'ssh-wrapper\.sh'
        }

        It "SSH wrapper uses Windows OpenSSH" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Should reference Windows OpenSSH path
            $Content | Should -Match 'C:/Windows/System32/OpenSSH/ssh\.exe|/c/Windows/System32/OpenSSH'
        }
    }

    Context "Git Bash Compatibility" {

        It "Scripts are Git Bash compatible" {
            $ScriptPath = Join-Path $SSHScripts "setup-ssh-agent-access.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Should handle path conversions for Git Bash
            $Content | Should -Match '\$HOME|~/'
        }
    }
}
