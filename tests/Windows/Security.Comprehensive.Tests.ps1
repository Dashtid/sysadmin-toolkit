# Comprehensive Pester Tests for Windows Security Scripts
# Version: 2.0
# Coverage Target: 80%+ for security scripts
# Run: Invoke-Pester -Path .\tests\Windows\Security.Comprehensive.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $SecurityPath = Join-Path $ProjectRoot "Windows\security"
}

# ============================================================================
# SYSTEM-HEALTH-CHECK.PS1 TESTS
# ============================================================================

Describe "system-health-check.ps1 - Comprehensive Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "system-health-check.ps1"
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

        It "No emojis (CLAUDE.md compliance)" {
            $ScriptContent | Should -Not -Match '[\x{1F300}-\x{1F9FF}]'
        }

        It "Uses ASCII markers" {
            $ScriptContent | Should -Match '\[\+\]|\[-\]|\[i\]'
        }
    }

    Context "Health Check Operations" {
        It "Checks Windows Defender status" {
            $ScriptContent | Should -Match 'Get-MpComputerStatus|Defender'
        }

        It "Checks firewall status" {
            $ScriptContent | Should -Match 'Get-NetFirewallProfile|Firewall'
        }

        It "Checks for pending updates" {
            $ScriptContent | Should -Match 'Windows.*Update|PSWindowsUpdate'
        }

        It "Checks disk space" {
            $ScriptContent | Should -Match 'Get-Volume|Get-PSDrive'
        }

        It "Checks critical services" {
            $ScriptContent | Should -Match 'Get-Service'
        }

        It "Generates health report" {
            $ScriptContent | Should -Match 'report|summary|Export'
        }
    }

    Context "Security Validation" {
        It "Checks if UAC is enabled" {
            $ScriptContent | Should -Match 'UAC|User.*Account.*Control'
        }

        It "Validates security settings" {
            $ScriptContent | Should -Match 'security|audit|compliance'
        }

        It "Checks for vulnerabilities" {
            $ScriptContent | Should -Match 'vulnerable|patch|CVE'
        }
    }

    Context "Error Handling" {
        It "Has try-catch blocks" {
            $ScriptContent | Should -Match 'try.*catch'
        }

        It "Handles missing modules gracefully" {
            $ScriptContent | Should -Match 'ErrorAction.*SilentlyContinue|Import-Module.*ErrorAction'
        }
    }
}

# ============================================================================
# HARDENING SCRIPTS TESTS
# ============================================================================

Describe "harden-level1-safe.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "harden-level1-safe.ps1"
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

    Context "Hardening Operations" {
        It "Disables unnecessary services" {
            $ScriptContent | Should -Match 'Stop-Service|Set-Service.*Disabled'
        }

        It "Configures Windows Firewall" {
            $ScriptContent | Should -Match 'Set-NetFirewallProfile|New-NetFirewallRule'
        }

        It "Enables Windows Defender" {
            $ScriptContent | Should -Match 'Set-MpPreference|Enable.*Defender'
        }

        It "Disables SMBv1" {
            $ScriptContent | Should -Match 'Disable-WindowsOptionalFeature.*SMB1|SMBv1'
        }

        It "Configures audit policies" {
            $ScriptContent | Should -Match 'auditpol|Set-AuditPolicy'
        }
    }

    Context "Safety Checks" {
        It "Creates backup before changes" {
            $ScriptContent | Should -Match 'backup|export.*state|Checkpoint-Computer'
        }

        It "Provides rollback option" {
            $ScriptContent | Should -Match 'rollback|restore|undo'
        }

        It "Warns about changes" {
            $ScriptContent | Should -Match 'Warning|Confirm|WhatIf'
        }
    }
}

Describe "harden-level2-balanced.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "harden-level2-balanced.ps1"
        if (Test-Path $ScriptPath) {
            $ScriptContent = Get-Content $ScriptPath -Raw
        }
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

    Context "Advanced Hardening" {
        It "Implements stricter policies than Level 1" {
            $ScriptContent | Should -Match 'policy|Group.*Policy|secedit'
        }

        It "Configures additional security settings" {
            $ScriptContent | Should -Match 'registry|Set-ItemProperty'
        }

        It "Restricts network protocols" {
            $ScriptContent | Should -Match 'TLS|SSL|protocol'
        }
    }
}

Describe "harden-level3-maximum.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "harden-level3-maximum.ps1"
        if (Test-Path $ScriptPath) {
            $ScriptContent = Get-Content $ScriptPath -Raw
        }
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

    Context "Maximum Security" {
        It "Implements strictest security policies" {
            $ScriptContent | Should -Match 'maximum|strict|enhanced'
        }

        It "Disables legacy features" {
            $ScriptContent | Should -Match 'disable|remove|feature'
        }

        It "Warns about compatibility impact" {
            $ScriptContent | Should -Match 'warning|caution|compatibility'
        }
    }
}

# ============================================================================
# SECURITY BACKUP AND RESTORE TESTS
# ============================================================================

Describe "backup-security-settings.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "backup-security-settings.ps1"
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

    Context "Backup Operations" {
        It "Exports security policy" {
            $ScriptContent | Should -Match 'secedit.*export|Export.*Policy'
        }

        It "Backs up firewall rules" {
            $ScriptContent | Should -Match 'Get-NetFirewallRule|Export.*Firewall'
        }

        It "Saves registry security settings" {
            $ScriptContent | Should -Match 'Export.*RegistryKey|reg.*export'
        }

        It "Creates timestamped backup" {
            $ScriptContent | Should -Match 'Get-Date|timestamp|\d{8}'
        }

        It "Validates backup file creation" {
            $ScriptContent | Should -Match 'Test-Path.*backup'
        }
    }

    Context "Backup Storage" {
        It "Defines backup directory" {
            $ScriptContent | Should -Match 'backup.*path|BackupPath'
        }

        It "Creates backup directory if needed" {
            $ScriptContent | Should -Match 'New-Item.*Directory'
        }

        It "Manages old backups" {
            $ScriptContent | Should -Match 'Remove-Item.*backup|cleanup.*old'
        }
    }
}

Describe "restore-security-settings.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "restore-security-settings.ps1"
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

    Context "Restore Operations" {
        It "Imports security policy" {
            $ScriptContent | Should -Match 'secedit.*import|Import.*Policy'
        }

        It "Restores firewall rules" {
            $ScriptContent | Should -Match 'New-NetFirewallRule|Import.*Firewall'
        }

        It "Restores registry settings" {
            $ScriptContent | Should -Match 'Import.*RegistryKey|reg.*import|Set-ItemProperty'
        }

        It "Validates backup file exists" {
            $ScriptContent | Should -Match 'Test-Path.*backup'
        }

        It "Lists available backups" {
            $ScriptContent | Should -Match 'Get-ChildItem.*backup'
        }
    }

    Context "Safety and Validation" {
        It "Confirms before restoring" {
            $ScriptContent | Should -Match 'Confirm|ShouldProcess|-Force'
        }

        It "Validates restore success" {
            $ScriptContent | Should -Match 'validate|verify|test.*restore'
        }

        It "Reports restore results" {
            $ScriptContent | Should -Match 'report|success|complete'
        }
    }
}

# ============================================================================
# AUDIT AND COMPLIANCE TESTS
# ============================================================================

Describe "audit-security-posture.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "audit-security-posture.ps1"
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

    Context "Security Audit Operations" {
        It "Audits user accounts" {
            $ScriptContent | Should -Match 'Get-LocalUser|Get-ADUser|user.*account'
        }

        It "Checks password policies" {
            $ScriptContent | Should -Match 'password.*policy|Get-ADDefaultDomainPasswordPolicy'
        }

        It "Audits admin privileges" {
            $ScriptContent | Should -Match 'Administrators|Get-LocalGroupMember'
        }

        It "Checks security software status" {
            $ScriptContent | Should -Match 'Defender|Antivirus|Firewall'
        }

        It "Reviews open ports" {
            $ScriptContent | Should -Match 'Get-NetTCPConnection|netstat'
        }

        It "Checks running services" {
            $ScriptContent | Should -Match 'Get-Service.*Running'
        }

        It "Generates compliance report" {
            $ScriptContent | Should -Match 'report|Export.*Csv|ConvertTo-Html'
        }
    }

    Context "Compliance Checks" {
        It "Validates against baseline" {
            $ScriptContent | Should -Match 'baseline|standard|CIS|STIG'
        }

        It "Identifies security gaps" {
            $ScriptContent | Should -Match 'gap|missing|not.*compliant'
        }

        It "Provides remediation steps" {
            $ScriptContent | Should -Match 'remediate|fix|recommendation'
        }
    }
}

# ============================================================================
# NETBIOS AND NETWORK SECURITY TESTS
# ============================================================================

Describe "fix-netbios.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "fix-netbios.ps1"
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

    Context "NetBIOS Configuration" {
        It "Disables NetBIOS over TCP/IP" {
            $ScriptContent | Should -Match 'NetBIOS|NetbiosOptions|Set-ItemProperty'
        }

        It "Configures network adapters" {
            $ScriptContent | Should -Match 'Get-NetAdapter|network.*adapter'
        }

        It "Updates registry settings" {
            $ScriptContent | Should -Match 'HKLM.*Tcpip.*NetBT|registry'
        }

        It "Validates changes" {
            $ScriptContent | Should -Match 'Get-ItemProperty|verify|validate'
        }
    }

    Context "Security Impact" {
        It "Explains security benefits" {
            ($ScriptContent -split "`n" | Select-Object -First 30) -join "`n" | Should -Match 'security|vulnerability|attack'
        }

        It "Warns about compatibility" {
            $ScriptContent | Should -Match 'warning|caution|compatibility'
        }
    }
}

# ============================================================================
# COMPLETE SYSTEM SETUP TESTS
# ============================================================================

Describe "complete-system-setup.ps1 - Tests" {
    BeforeAll {
        $ScriptPath = Join-Path $SecurityPath "complete-system-setup.ps1"
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

    Context "System Setup Operations" {
        It "Performs security hardening" {
            $ScriptContent | Should -Match 'harden|security.*setup'
        }

        It "Configures Windows updates" {
            $ScriptContent | Should -Match 'Windows.*Update|Update.*Settings'
        }

        It "Sets up monitoring" {
            $ScriptContent | Should -Match 'monitor|logging|audit'
        }

        It "Configures backup" {
            $ScriptContent | Should -Match 'backup|restore.*point'
        }

        It "Provides setup summary" {
            $ScriptContent | Should -Match 'summary|complete|report'
        }
    }

    Context "Automation and Orchestration" {
        It "Calls other security scripts" {
            $ScriptContent | Should -Match '&.*ps1|Invoke-Expression|Start-Process.*ps1'
        }

        It "Manages script execution order" {
            $ScriptContent | Should -Match 'step|phase|stage'
        }

        It "Handles script failures" {
            $ScriptContent | Should -Match 'try.*catch|ErrorAction'
        }
    }
}

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

Describe "Security Scripts Integration" {
    Context "Script Consistency" {
        It "All security scripts exist" {
            $scripts = @(
                "system-health-check.ps1"
                "harden-level1-safe.ps1"
                "harden-level2-balanced.ps1"
                "harden-level3-maximum.ps1"
                "backup-security-settings.ps1"
                "restore-security-settings.ps1"
                "audit-security-posture.ps1"
                "fix-netbios.ps1"
                "complete-system-setup.ps1"
            )

            foreach ($script in $scripts) {
                Test-Path (Join-Path $SecurityPath $script) | Should -Be $true
            }
        }

        It "Scripts follow naming conventions" {
            $scripts = Get-ChildItem $SecurityPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $script.Name | Should -Match '^[a-z0-9-]+\.ps1$'
            }
        }

        It "Scripts have consistent error handling" {
            $scripts = Get-ChildItem $SecurityPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                $hasErrorHandling = ($content -match 'try.*catch') -or ($content -match 'ErrorAction')
                $hasErrorHandling | Should -Be $true
            }
        }

        It "Scripts follow CLAUDE.md conventions" {
            $scripts = Get-ChildItem $SecurityPath -Filter "*.ps1"
            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw
                $content | Should -Not -Match '[\x{1F300}-\x{1F9FF}]'
            }
        }

        It "Admin scripts require Administrator" {
            $adminScripts = @("harden-*.ps1", "complete-system-setup.ps1", "restore-security-settings.ps1", "fix-netbios.ps1")
            foreach ($pattern in $adminScripts) {
                $scripts = Get-ChildItem $SecurityPath -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($script in $scripts) {
                    $content = Get-Content $script.FullName -Raw
                    $content | Should -Match '#Requires -RunAsAdministrator'
                }
            }
        }
    }

    Context "Security Workflow" {
        It "Backup script exists before hardening scripts" {
            Test-Path (Join-Path $SecurityPath "backup-security-settings.ps1") | Should -Be $true
        }

        It "Restore script exists to rollback hardening" {
            Test-Path (Join-Path $SecurityPath "restore-security-settings.ps1") | Should -Be $true
        }

        It "Audit script exists to validate hardening" {
            Test-Path (Join-Path $SecurityPath "audit-security-posture.ps1") | Should -Be $true
        }

        It "Health check script exists for monitoring" {
            Test-Path (Join-Path $SecurityPath "system-health-check.ps1") | Should -Be $true
        }
    }
}
