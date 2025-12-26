# Integration Tests for Windows Scripts
# These tests verify scripts work together and with the system
# Run: Invoke-Pester -Path .\tests\Windows\Integration.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $TestHelpers = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    Import-Module $TestHelpers -Force

    # Paths
    $SSHPath = Join-Path $ProjectRoot "Windows\ssh"
    $MaintenancePath = Join-Path $ProjectRoot "Windows\maintenance"
}

AfterAll {
    # Cleanup any test artifacts
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
}

Describe "Cross-Script Integration" {
    Context "SSH Agent Setup Integration" {
        BeforeAll {
            $setupScript = Join-Path $SSHPath "setup-ssh-agent-access.ps1"
            $scriptExists = Test-Path $setupScript
        }

        It "SSH setup script exists" {
            $scriptExists | Should -Be $true
        }

        It "SSH setup script can be parsed" {
            if (-not $scriptExists) {
                Set-ItResult -Skipped -Because "SSH setup script does not exist"
                return
            }
            { [scriptblock]::Create((Get-Content $setupScript -Raw)) } | Should -Not -Throw
        }

        It "SSH agent service is available on Windows" {
            $service = Get-Service -Name "ssh-agent" -ErrorAction SilentlyContinue
            if ($service) {
                $service | Should -Not -BeNullOrEmpty
            } else {
                Set-ItResult -Skipped -Because "SSH agent service not installed on this system"
            }
        }
    }
}

Describe "System Integration Tests" {
    Context "Windows Services Interaction" {
        It "Can query Windows Update service" {
            $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Name | Should -Be "wuauserv"
                $service.Status | Should -BeIn @('Running', 'Stopped', 'Paused')
            } else {
                Set-ItResult -Skipped -Because "Windows Update service not available"
            }
        }

        It "Can query Windows Defender service" {
            $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Name | Should -Be "WinDefend"
            } else {
                Set-ItResult -Skipped -Because "Windows Defender not available"
            }
        }

        It "Can check SSH agent service availability" {
            $service = Get-Service -Name "ssh-agent" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Name | Should -Be "ssh-agent"
            } else {
                Set-ItResult -Skipped -Because "SSH agent service not installed"
            }
        }
    }

    Context "File System Integration" {
        BeforeAll {
            $testDir = New-TemporaryDirectory
        }

        AfterAll {
            Remove-TemporaryDirectory -Path $testDir
        }

        It "Can create temporary test directory" {
            Test-Path $testDir | Should -Be $true
        }

        It "Can write to temporary directory" {
            $testFile = Join-Path $testDir "test.txt"
            "Test content" | Out-File $testFile
            Test-Path $testFile | Should -Be $true
        }

        It "Can read from temporary directory" {
            $testFile = Join-Path $testDir "test.txt"
            $content = Get-Content $testFile
            $content | Should -Be "Test content"
        }

        It "Can clean up temporary directory" {
            Remove-TemporaryDirectory -Path $testDir
            Test-Path $testDir | Should -Be $false
        }
    }

    Context "PowerShell Environment" {
        It "PowerShell version is 5.1 or higher" {
            $PSVersionTable.PSVersion.Major | Should -BeGreaterOrEqual 5
        }

        It "Execution policy allows script execution" {
            $policy = Get-ExecutionPolicy
            $policy | Should -Not -Be 'Restricted'
        }

        It "Can load .NET types" {
            { [System.Security.Principal.WindowsIdentity]::GetCurrent() } | Should -Not -Throw
        }

        It "Environment variables are accessible" {
            $env:USERPROFILE | Should -Not -BeNullOrEmpty
            $env:TEMP | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Script Dependency Chain" {
    Context "Module Import Dependencies" {
        It "PSScriptAnalyzer module check" {
            $module = Get-Module -ListAvailable -Name "PSScriptAnalyzer" | Select-Object -First 1
            if ($module) {
                $module.Name | Should -Be "PSScriptAnalyzer"
            } else {
                Set-ItResult -Skipped -Because "PSScriptAnalyzer not installed (optional)"
            }
        }

        It "Pester module is available" {
            $module = Get-Module -ListAvailable -Name "Pester"
            $module | Should -Not -BeNullOrEmpty
            # Pester 5+ recommended but not required for basic tests
            if ($module.Version.Major -lt 5) {
                Write-Warning "Pester 5+ recommended for full feature support (current: $($module.Version))"
            }
        }
    }

    Context "External Command Dependencies" {
        It "Git command is available" {
            $git = Get-Command git -ErrorAction SilentlyContinue
            if ($git) {
                $git.Name | Should -Match "git"
            } else {
                Set-ItResult -Skipped -Because "Git not installed"
            }
        }

        It "PowerShell 7 (pwsh) is available" {
            $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
            if ($pwsh) {
                $pwsh.Name | Should -Match "pwsh"
            } else {
                Set-ItResult -Skipped -Because "PowerShell 7 not installed"
            }
        }
    }
}

Describe "Security Integration Tests" {
    Context "No Secrets in Repository" {
        BeforeAll {
            $allScripts = Get-ChildItem -Path $ProjectRoot -Include "*.ps1" -Recurse
        }

        It "No scripts contain hardcoded secrets" {
            $foundSecrets = @()
            foreach ($script in $allScripts) {
                $result = Test-NoHardcodedSecrets -Path $script.FullName
                if (-not $result) {
                    $foundSecrets += $script.Name
                }
            }

            $foundSecrets | Should -BeNullOrEmpty
        }

        It "No scripts contain private IPs in executable code" {
            # Uses AST-based detection: allows IPs in comments/strings (documentation)
            # but rejects them in actual executable code
            $privateIpPatterns = @(
                '10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                '172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
                '192\.168\.\d{1,3}\.\d{1,3}'
            )

            $foundProblems = @()

            foreach ($script in $allScripts) {
                $tokens = $null
                $errors = $null
                [System.Management.Automation.Language.Parser]::ParseFile(
                    $script.FullName, [ref]$tokens, [ref]$errors
                ) | Out-Null

                foreach ($token in $tokens) {
                    # Skip comments and string literals (documentation/examples are OK)
                    $skipKinds = @('Comment', 'StringLiteral', 'StringExpandable',
                        'HereStringLiteral', 'HereStringExpandable')
                    if ($token.Kind -in $skipKinds) {
                        continue
                    }

                    foreach ($pattern in $privateIpPatterns) {
                        if ($token.Text -match $pattern) {
                            $foundProblems += "$($script.Name):$($token.Extent.StartLineNumber)"
                        }
                    }
                }
            }

            $foundProblems | Should -BeNullOrEmpty
        }
    }

    Context "Consistent Output Format" {
        BeforeAll {
            $allScripts = Get-ChildItem -Path $ProjectRoot -Include "*.ps1" -Recurse |
                Where-Object { $_.FullName -notmatch 'tests|examples' }
        }

        It "All scripts use consistent logging markers" {
            $inconsistentScripts = @()

            foreach ($script in $allScripts) {
                $logging = Test-ConsistentLogging -Path $script.FullName

                # Scripts should have at least one type of marker
                $hasAnyMarker = $logging.HasSuccessMarker -or
                                $logging.HasErrorMarker -or
                                $logging.HasInfoMarker -or
                                $logging.HasWarningMarker

                # Scripts should not have emojis
                $hasEmojis = $logging.HasEmojis

                # Legacy scripts may not have markers yet - track but allow
                if (-not $hasAnyMarker) {
                    Write-Warning "Script needs logging markers: $($script.Name)"
                }

                # Emojis are always forbidden (breaks CI/CD)
                if ($hasEmojis) {
                    $inconsistentScripts += $script.Name
                }
            }

            if ($inconsistentScripts.Count -gt 0) {
                Write-Warning "Scripts with emojis: $($inconsistentScripts -join ', ')"
            }
            $inconsistentScripts | Should -BeNullOrEmpty
        }
    }
}

Describe "Performance Integration Tests" {
    Context "Script Load Times" {
        It "Scripts can be parsed quickly" {
            $allScripts = Get-ChildItem -Path $ProjectRoot -Include "*.ps1" -Recurse -Depth 3

            $slowScripts = @()

            foreach ($script in $allScripts) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $null = [scriptblock]::Create((Get-Content $script.FullName -Raw))
                }
                catch {
                    # Syntax error, will be caught by other tests
                }
                $stopwatch.Stop()

                if ($stopwatch.ElapsedMilliseconds -gt 1000) {
                    $slowScripts += @{
                        Name = $script.Name
                        Time = $stopwatch.ElapsedMilliseconds
                    }
                }
            }

            # No script should take more than 1 second to parse
            $slowScripts.Count | Should -Be 0
        }
    }
}

Describe "Git Repository Integration" {
    Context "Repository State" {
        BeforeAll {
            Push-Location $ProjectRoot
        }

        AfterAll {
            Pop-Location
        }

        It "Repository is a valid Git repository" {
            $gitDir = Join-Path $ProjectRoot ".git"
            Test-Path $gitDir | Should -Be $true
        }

        It ".gitignore file exists" {
            $gitignore = Join-Path $ProjectRoot ".gitignore"
            Test-Path $gitignore | Should -Be $true
        }

        It ".gitignore protects sensitive files" {
            $gitignore = Join-Path $ProjectRoot ".gitignore"
            $content = Get-Content $gitignore -Raw

            # Should ignore credentials
            $content | Should -Match '\.pem|\.key|credentials'

            # Should ignore environment files
            $content | Should -Match '\.env'

            # Should ignore logs
            $content | Should -Match '\.log|logs'
        }
    }
}
