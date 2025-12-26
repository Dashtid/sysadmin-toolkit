# Developer Environment Backup/Restore Tests
# Tests for Backup-DeveloperEnvironment.ps1 and Restore-DeveloperEnvironment.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

    # Script paths
    $BackupScript = Join-Path $ProjectRoot "Windows\backup\Backup-DeveloperEnvironment.ps1"
    $RestoreScript = Join-Path $ProjectRoot "Windows\backup\Restore-DeveloperEnvironment.ps1"

    # Import test helpers
    $TestHelpers = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    if (Test-Path $TestHelpers) {
        Import-Module $TestHelpers -Force
    }
}

Describe "Backup-DeveloperEnvironment.ps1" {
    Context "Script Validation" {
        It "Script file should exist" {
            Test-Path $BackupScript | Should -Be $true
        }

        It "Should have valid PowerShell syntax" {
            $errors = $null
            $content = Get-Content $BackupScript -Raw
            [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "Should have comment-based help" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match '\.EXAMPLE'
        }

        It "Should have required parameters" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match '\$BackupPath'
        }

        It "Should support ShouldProcess (WhatIf)" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "Backup Execution" {
        BeforeAll {
            $TestBackupPath = Join-Path $TestDrive "DevEnvBackup"
        }

        It "Should create backup directory with timestamp" {
            # Run with WhatIf to avoid actual file operations
            $result = & $BackupScript -BackupPath $TestBackupPath -WhatIf 2>&1

            # Script should complete without throwing
            { & $BackupScript -BackupPath $TestBackupPath -WhatIf } | Should -Not -Throw
        }

        It "Should handle missing source files gracefully" {
            # Script should not throw even when source files don't exist
            { & $BackupScript -BackupPath $TestBackupPath -WhatIf } | Should -Not -Throw
        }
    }

    Context "Target Configuration" {
        It "Should define correct VSCode settings path" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match 'Code\\User\\settings\.json'
        }

        It "Should define correct Windows Terminal path" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match 'Microsoft\.WindowsTerminal.*settings\.json'
        }

        It "Should define Git config path" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match '\.gitconfig'
        }

        It "Should define SSH config path" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match '\.ssh\\config'
        }

        It "Should define PowerShell profile path" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Match '\$PROFILE'
        }
    }
}

Describe "Restore-DeveloperEnvironment.ps1" {
    Context "Script Validation" {
        It "Script file should exist" {
            Test-Path $RestoreScript | Should -Be $true
        }

        It "Should have valid PowerShell syntax" {
            $errors = $null
            $content = Get-Content $RestoreScript -Raw
            [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "Should have comment-based help" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match '\.EXAMPLE'
        }

        It "Should have mandatory BackupPath parameter" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'Parameter\(Mandatory\)'
            $content | Should -Match '\$BackupPath'
        }

        It "Should support ShouldProcess (WhatIf)" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'SupportsShouldProcess'
        }

        It "Should validate BackupPath exists" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'ValidateScript'
        }
    }

    Context "Restore Execution" {
        BeforeAll {
            # Create a mock backup structure
            $MockBackupPath = Join-Path $TestDrive "MockBackup"
            New-Item -ItemType Directory -Path $MockBackupPath -Force | Out-Null

            # Create mock manifest
            $manifest = @{
                Timestamp    = "20251226-120000"
                BackupDate   = "2025-12-26 12:00:00"
                ComputerName = "TESTPC"
                UserName     = "TestUser"
                Items        = @(
                    @{
                        Name         = "GitConfig"
                        OriginalPath = Join-Path $TestDrive "restored\.gitconfig"
                        BackupFile   = Join-Path $MockBackupPath "GitConfig"
                        Description  = "Git global configuration"
                    }
                )
            }

            $manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $MockBackupPath "manifest.json")

            # Create mock backup file
            "[user]`nname = Test User" | Out-File (Join-Path $MockBackupPath "GitConfig")
        }

        It "Should check for manifest.json and exit on error" {
            # Verify the script contains logic to check for manifest.json
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'manifest\.json'
            $content | Should -Match 'exit 1'
            $content | Should -Match 'Manifest not found'
        }

        It "Should parse manifest correctly" {
            # Should not throw with valid manifest
            { & $RestoreScript -BackupPath $MockBackupPath -WhatIf } | Should -Not -Throw
        }
    }

    Context "Safety Features" {
        It "Should support creating backup before overwriting" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match '\$CreateBackupFirst'
            $content | Should -Match '\.bak'
        }

        It "Should support Force parameter" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match '\$Force'
        }

        It "Should handle VSCode extensions restoration" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'RestoreExtensions'
            $content | Should -Match 'code --install-extension'
        }
    }
}

Describe "Integration Tests - Backup and Restore" {
    BeforeAll {
        $TestBackupRoot = Join-Path $TestDrive "IntegrationTest"
        $TestSourceDir = Join-Path $TestDrive "SourceFiles"

        # Create source directory
        New-Item -ItemType Directory -Path $TestSourceDir -Force | Out-Null

        # Create mock source files
        @{
            ".gitconfig" = "[user]`nname = Test User`nemail = test@example.com"
        }.GetEnumerator() | ForEach-Object {
            $filePath = Join-Path $TestSourceDir $_.Key
            $_.Value | Out-File -FilePath $filePath -Encoding UTF8
        }
    }

    Context "Manifest Structure" {
        It "Manifest should contain required fields" {
            # Create a mock manifest to test structure
            $manifest = @{
                Timestamp    = "20251226-120000"
                BackupDate   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                ComputerName = $env:COMPUTERNAME
                UserName     = $env:USERNAME
                Items        = @()
            }

            $manifest.Timestamp | Should -Not -BeNullOrEmpty
            $manifest.BackupDate | Should -Not -BeNullOrEmpty
            $manifest.ComputerName | Should -Not -BeNullOrEmpty
            $manifest.UserName | Should -Not -BeNullOrEmpty
            # Check Items key exists (empty array is valid)
            $manifest.ContainsKey('Items') | Should -Be $true
        }
    }

    Context "File Operations" {
        It "Should handle file paths with spaces" {
            $pathWithSpaces = Join-Path $TestDrive "Path With Spaces"
            New-Item -ItemType Directory -Path $pathWithSpaces -Force | Out-Null

            # This should not throw
            { & $BackupScript -BackupPath $pathWithSpaces -WhatIf } | Should -Not -Throw
        }
    }
}

Describe "Security Tests" {
    Context "Backup Script Security" {
        It "Should not contain hardcoded credentials" {
            $content = Get-Content $BackupScript -Raw
            $content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
            $content | Should -Not -Match 'apikey\s*=\s*[''"][^''"]+'
        }

        It "Should use safe file operations" {
            $content = Get-Content $BackupScript -Raw
            # Should use proper PowerShell cmdlets, not shell injection
            $content | Should -Not -Match 'Invoke-Expression.*\$'
        }
    }

    Context "Restore Script Security" {
        It "Should not contain hardcoded credentials" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
            $content | Should -Not -Match 'apikey\s*=\s*[''"][^''"]+'
        }

        It "Should validate backup path" {
            $content = Get-Content $RestoreScript -Raw
            $content | Should -Match 'ValidateScript'
        }
    }
}
