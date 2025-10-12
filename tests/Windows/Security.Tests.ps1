# Pester tests for Windows Security hardening scripts
# Tests validate script structure, parameter handling, and safety features

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $SecurityPath = Join-Path $ProjectRoot "Windows\security"

    # Import scripts for testing (dot-source)
    $AuditScript = Join-Path $SecurityPath "audit-security-posture.ps1"
    $BackupScript = Join-Path $SecurityPath "backup-security-settings.ps1"
    $RestoreScript = Join-Path $SecurityPath "restore-security-settings.ps1"
    $HardenLevel1Script = Join-Path $SecurityPath "harden-level1-safe.ps1"
    $HardenLevel2Script = Join-Path $SecurityPath "harden-level2-balanced.ps1"
    $HardenLevel3Script = Join-Path $SecurityPath "harden-level3-maximum.ps1"
}

Describe "Security Script Existence" {
    Context "Script Files" {
        It "audit-security-posture.ps1 should exist" {
            $AuditScript | Should -Exist
        }

        It "backup-security-settings.ps1 should exist" {
            $BackupScript | Should -Exist
        }

        It "restore-security-settings.ps1 should exist" {
            $RestoreScript | Should -Exist
        }

        It "harden-level1-safe.ps1 should exist" {
            $HardenLevel1Script | Should -Exist
        }

        It "harden-level2-balanced.ps1 should exist" {
            $HardenLevel2Script | Should -Exist
        }

        It "harden-level3-maximum.ps1 should exist" {
            $HardenLevel3Script | Should -Exist
        }
    }
}

Describe "Security Script Syntax" {
    Context "PowerShell Syntax Validation" {
        It "audit-security-posture.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $AuditScript -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "backup-security-settings.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $BackupScript -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "harden-level1-safe.ps1 should have valid syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $HardenLevel1Script -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }
    }
}

Describe "audit-security-posture.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $AuditScript -Raw
    }

    Context "Script Structure" {
        It "Should have comment-based help" {
            $scriptContent | Should -Match '<#'
            $scriptContent | Should -Match '\.SYNOPSIS'
            $scriptContent | Should -Match '\.DESCRIPTION'
        }

        It "Should have proper error handling" {
            $scriptContent | Should -Match '\$ErrorActionPreference'
        }

        It "Should use consistent logging format" {
            $scriptContent | Should -Match '\[i\]|\[INFO\]'
            $scriptContent | Should -Match '\[\+\]|\[SUCCESS\]'
        }

        It "Should have version information" {
            $scriptContent | Should -Match 'Version'
        }
    }

    Context "Security Checks" {
        It "Should check Windows Defender status" {
            $scriptContent | Should -Match 'Defender|MpPreference'
        }

        It "Should check Windows Firewall" {
            $scriptContent | Should -Match 'Firewall|NetFirewall'
        }

        It "Should check Windows Update" {
            $scriptContent | Should -Match 'Update|WindowsUpdate'
        }

        It "Should check UAC settings" {
            $scriptContent | Should -Match 'UAC|UserAccountControl|EnableLUA'
        }
    }

    Context "Output Format" {
        It "Should not contain hardcoded credentials" {
            $scriptContent | Should -Not -Match 'password\s*=\s*[''"]'
            $scriptContent | Should -Not -Match 'apikey\s*=\s*[''"]'
        }

        It "Should use Write-Host or Write-Output for messages" {
            $scriptContent | Should -Match 'Write-Host|Write-Output|Write-Information'
        }
    }
}

Describe "backup-security-settings.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $BackupScript -Raw
    }

    Context "Script Parameters" {
        It "Should accept BackupPath parameter" {
            $scriptContent | Should -Match 'param\s*\('
            $scriptContent | Should -Match '\$?BackupPath'
        }

        It "Should have parameter validation" {
            $scriptContent | Should -Match '\[Parameter'
        }
    }

    Context "Backup Functionality" {
        It "Should create backup directory" {
            $scriptContent | Should -Match 'New-Item.*-ItemType Directory|mkdir'
        }

        It "Should export registry settings" {
            $scriptContent | Should -Match 'Export.*Registry|reg export'
        }

        It "Should create System Restore Point" {
            $scriptContent | Should -Match 'Checkpoint-Computer|RestorePoint'
        }

        It "Should handle backup errors" {
            $scriptContent | Should -Match 'try|catch'
        }
    }

    Context "Safety Features" {
        It "Should check if backup path exists" {
            $scriptContent | Should -Match 'Test-Path'
        }

        It "Should not overwrite existing backups without warning" {
            $scriptContent | Should -Match 'Test-Path.*Backup|Force|Confirm'
        }
    }
}

Describe "restore-security-settings.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $RestoreScript -Raw
    }

    Context "Script Parameters" {
        It "Should accept BackupPath parameter" {
            $scriptContent | Should -Match 'param\s*\('
            $scriptContent | Should -Match '\$?BackupPath'
        }

        It "Should require BackupPath parameter" {
            $scriptContent | Should -Match 'Mandatory.*=.*\$true'
        }
    }

    Context "Restore Functionality" {
        It "Should validate backup exists before restore" {
            $scriptContent | Should -Match 'Test-Path.*Backup'
        }

        It "Should restore registry settings" {
            $scriptContent | Should -Match 'Import.*Registry|reg import'
        }

        It "Should handle restore errors" {
            $scriptContent | Should -Match 'try|catch'
        }
    }

    Context "Safety Features" {
        It "Should warn before making changes" {
            $scriptContent | Should -Match 'WhatIf|Confirm|ShouldProcess'
        }

        It "Should require elevation" {
            $scriptContent | Should -Match '#Requires.*Administrator|RunAsAdministrator'
        }
    }
}

Describe "harden-level1-safe.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $HardenLevel1Script -Raw
    }

    Context "Script Safety" {
        It "Should support WhatIf parameter" {
            $scriptContent | Should -Match 'WhatIf|SupportsShouldProcess'
        }

        It "Should create backup before changes" {
            $scriptContent | Should -Match 'backup|Backup|Checkpoint'
        }

        It "Should require administrator privileges" {
            $scriptContent | Should -Match '#Requires.*Administrator|RunAsAdministrator'
        }
    }

    Context "Level 1 Hardening" {
        It "Should disable SMBv1" {
            $scriptContent | Should -Match 'SMB.*v1|Disable-WindowsOptionalFeature.*SMB1'
        }

        It "Should configure Windows Defender" {
            $scriptContent | Should -Match 'Set-MpPreference|Defender'
        }

        It "Should configure Windows Firewall" {
            $scriptContent | Should -Match 'NetFirewallProfile|Set-NetFirewall'
        }

        It "Should configure UAC" {
            $scriptContent | Should -Match 'EnableLUA|ConsentPromptBehavior'
        }
    }

    Context "Error Handling" {
        It "Should log all changes" {
            $scriptContent | Should -Match 'log|Log|Write-'
        }

        It "Should handle errors gracefully" {
            $scriptContent | Should -Match 'try.*catch'
        }

        It "Should provide rollback information" {
            $scriptContent | Should -Match 'rollback|Rollback|restore|Restore'
        }
    }
}

Describe "harden-level2-balanced.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $HardenLevel2Script -Raw
    }

    Context "Script Safety" {
        It "Should support WhatIf parameter" {
            $scriptContent | Should -Match 'WhatIf|SupportsShouldProcess'
        }

        It "Should warn about potential impact" {
            $scriptContent | Should -Match 'warning|Warning|impact|Impact'
        }

        It "Should require administrator privileges" {
            $scriptContent | Should -Match '#Requires.*Administrator|RunAsAdministrator'
        }
    }

    Context "Level 2 Hardening" {
        It "Should configure Credential Guard" {
            $scriptContent | Should -Match 'CredentialGuard|DeviceGuard'
        }

        It "Should configure ASR rules" {
            $scriptContent | Should -Match 'AttackSurfaceReduction|Add-MpPreference.*AttackSurface'
        }

        It "Should configure HVCI" {
            $scriptContent | Should -Match 'HVCI|HypervisorEnforcedCodeIntegrity'
        }
    }
}

Describe "harden-level3-maximum.ps1" {
    BeforeAll {
        $scriptContent = Get-Content $HardenLevel3Script -Raw
    }

    Context "Script Safety" {
        It "Should have strong warnings about impact" {
            $scriptContent | Should -Match 'WARNING|CAUTION|IMPORTANT'
        }

        It "Should support WhatIf parameter" {
            $scriptContent | Should -Match 'WhatIf|SupportsShouldProcess'
        }

        It "Should require explicit confirmation" {
            $scriptContent | Should -Match 'Confirm|ConfirmImpact.*High'
        }
    }

    Context "Level 3 Hardening" {
        It "Should mention AppLocker" {
            $scriptContent | Should -Match 'AppLocker'
        }

        It "Should mention Constrained Language Mode" {
            $scriptContent | Should -Match 'ConstrainedLanguage|__PSLockdownPolicy'
        }

        It "Should mention strict security policies" {
            $scriptContent | Should -Match 'policy|Policy|security|Security'
        }
    }

    Context "Documentation" {
        It "Should document compatibility issues" {
            $scriptContent | Should -Match 'compatibility|Compatibility|compatible|Compatible'
        }

        It "Should provide testing recommendations" {
            $scriptContent | Should -Match 'test|Test|testing|Testing'
        }
    }
}

Describe "Security Script Best Practices" {
    Context "No Hardcoded Secrets" {
        It "audit-security-posture.ps1 should not contain secrets" {
            $content = Get-Content $AuditScript -Raw
            $content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
            $content | Should -Not -Match 'apikey\s*=\s*[''"][^''"]+'
        }

        It "backup-security-settings.ps1 should not contain secrets" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
        }

        It "harden-level1-safe.ps1 should not contain secrets" {
            $content = Get-Content $HardenLevel1Script -Raw
            $content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
        }
    }

    Context "Consistent Output Format" {
        It "All scripts should use consistent success markers" {
            foreach ($script in @($AuditScript, $BackupScript, $HardenLevel1Script)) {
                $content = Get-Content $script -Raw
                $content | Should -Match '\[\+\]|\[SUCCESS\]|\[OK\]'
            }
        }

        It "All scripts should use consistent error markers" {
            foreach ($script in @($AuditScript, $BackupScript, $HardenLevel1Script)) {
                $content = Get-Content $script -Raw
                $content | Should -Match '\[-\]|\[ERROR\]|\[FAIL\]|\[X\]'
            }
        }
    }
}
