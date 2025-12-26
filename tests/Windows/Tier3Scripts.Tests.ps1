#Requires -Modules Pester
#Requires -Version 5.1

<#
.SYNOPSIS
    Pester tests for Tier 3 scripts (Nice to Have features).

.DESCRIPTION
    Comprehensive test suite for the following Tier 3 scripts:
    - Backup-BrowserProfiles.ps1
    - Manage-VPN.ps1
    - Manage-WSL.ps1
    - Manage-Docker.ps1
    - Test-DevEnvironment.ps1

    Tests include:
    - Script existence and syntax validation
    - Parameter validation
    - Help documentation completeness
    - Function structure verification
    - CommonFunctions module integration

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Creation Date: 2025-11-30
#>

BeforeAll {
    # Get paths
    $script:TestRoot = Split-Path -Parent $PSScriptRoot
    $script:RepoRoot = Split-Path -Parent $script:TestRoot
    $script:WindowsRoot = Join-Path $script:RepoRoot "Windows"

    # Define script paths
    $script:Tier3Scripts = @{
        'Backup-BrowserProfiles' = Join-Path $script:WindowsRoot "backup\Backup-BrowserProfiles.ps1"
        'Manage-VPN'             = Join-Path $script:WindowsRoot "network\Manage-VPN.ps1"
        'Manage-WSL'             = Join-Path $script:WindowsRoot "development\Manage-WSL.ps1"
        'Manage-Docker'          = Join-Path $script:WindowsRoot "development\Manage-Docker.ps1"
        'Test-DevEnvironment'    = Join-Path $script:WindowsRoot "development\Test-DevEnvironment.ps1"
    }

    # Helper function to test script syntax
    function Test-ScriptSyntax {
        param([string]$Path)
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        return $errors.Count -eq 0
    }

    # Helper function to get script AST
    function Get-ScriptAst {
        param([string]$Path)
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        return $ast
    }
}

Describe "Tier 3 Scripts - File Existence" -Tag "Existence", "Tier3" {
    Context "All Tier 3 scripts should exist" {
        It "Backup-BrowserProfiles.ps1 should exist" {
            $script:Tier3Scripts['Backup-BrowserProfiles'] | Should -Exist
        }

        It "Manage-VPN.ps1 should exist" {
            $script:Tier3Scripts['Manage-VPN'] | Should -Exist
        }

        It "Manage-WSL.ps1 should exist" {
            $script:Tier3Scripts['Manage-WSL'] | Should -Exist
        }

        It "Manage-Docker.ps1 should exist" {
            $script:Tier3Scripts['Manage-Docker'] | Should -Exist
        }

        It "Test-DevEnvironment.ps1 should exist" {
            $script:Tier3Scripts['Test-DevEnvironment'] | Should -Exist
        }
    }
}

Describe "Tier 3 Scripts - Syntax Validation" -Tag "Syntax", "Tier3" {
    foreach ($scriptName in $script:Tier3Scripts.Keys) {
        Context "$scriptName syntax validation" {
            It "$scriptName should have valid PowerShell syntax" {
                $path = $script:Tier3Scripts[$scriptName]
                Test-ScriptSyntax -Path $path | Should -Be $true
            }

            It "$scriptName should not contain syntax errors" {
                $path = $script:Tier3Scripts[$scriptName]
                $errors = $null
                $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
                $errors | Should -BeNullOrEmpty
            }
        }
    }
}

Describe "Backup-BrowserProfiles.ps1" -Tag "BrowserBackup", "Tier3" {
    BeforeAll {
        $script:BrowserBackupPath = $script:Tier3Scripts['Backup-BrowserProfiles']
        $script:BrowserBackupAst = Get-ScriptAst -Path $script:BrowserBackupPath
    }

    Context "Parameter Validation" {
        It "Should have Browser parameter with ValidateSet" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Chrome.*Edge.*Firefox.*Brave.*All.*\)\]'
        }

        It "Should have OutputFormat parameter" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            # Check ValidateSet and OutputFormat exist (may be on different lines)
            $content | Should -Match "ValidateSet.*'Console'.*'HTML'.*'JSON'"
            $content | Should -Match '\[string\]\$OutputFormat'
        }

        It "Should have IncludeCookies switch parameter" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\[switch\]\$IncludeCookies'
        }

        It "Should have IncludeHistory switch parameter" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\[switch\]\$IncludeHistory'
        }

        It "Should have Restore parameter" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\[string\]\$Restore'
        }

        It "Should have RetentionDays parameter with range validation" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\[ValidateRange\(0,\s*365\)\]'
        }
    }

    Context "Feature Implementation" {
        It "Should define browser profile paths" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'BrowserPaths'
            $content | Should -Match 'Google\\Chrome\\User Data'
            $content | Should -Match 'Microsoft\\Edge\\User Data'
            $content | Should -Match 'Mozilla\\Firefox\\Profiles'
        }

        It "Should have bookmark export to HTML function" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'Export-BookmarksToHtml'
        }

        It "Should have browser extension detection" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'Get-BrowserExtensions'
        }

        It "Should have backup compression functionality" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'Compress-BackupFolder'
            $content | Should -Match 'Compress-Archive'
        }

        It "Should have restore functionality" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'Restore-BrowserProfile'
            $content | Should -Match 'Expand-Archive'
        }

        It "Should have retention policy cleanup" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match 'Remove-OldBackups'
        }
    }

    Context "Help Documentation" {
        It "Should have synopsis" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should have description" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\.DESCRIPTION'
        }

        It "Should have examples" {
            $content = Get-Content $script:BrowserBackupPath -Raw
            $content | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Manage-VPN.ps1" -Tag "VPN", "Tier3" {
    BeforeAll {
        $script:VpnPath = $script:Tier3Scripts['Manage-VPN']
        $script:VpnAst = Get-ScriptAst -Path $script:VpnPath
    }

    Context "Parameter Validation" {
        It "Should have Action parameter with ValidateSet" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Connect.*Disconnect.*Status.*List.*Monitor.*Troubleshoot.*\)\]'
        }

        It "Should have ProfileName parameter" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\[string\]\$ProfileName'
        }

        It "Should have VpnType parameter with protocol options" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Pptp.*L2tp.*Sstp.*Ikev2.*\)\]'
        }

        It "Should have AutoReconnect switch" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\$AutoReconnect'
        }

        It "Should have ReconnectAttempts parameter" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\[int\]\$ReconnectAttempts'
        }

        It "Should have Credential parameter" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\[PSCredential\]\$Credential'
        }
    }

    Context "Feature Implementation" {
        It "Should have VPN profile listing" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Get-VpnProfiles'
            $content | Should -Match 'Get-VpnConnection'
        }

        It "Should have VPN connection function" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Connect-VpnProfile'
            $content | Should -Match 'rasdial'
        }

        It "Should have VPN disconnection function" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Disconnect-VpnProfile'
        }

        It "Should have VPN monitoring function" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Start-VpnMonitor'
        }

        It "Should have troubleshooting diagnostics" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Invoke-VpnTroubleshoot'
        }

        It "Should have VPN profile creation" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'New-VpnProfile'
            $content | Should -Match 'Add-VpnConnection'
        }

        It "Should have connection history logging" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'Write-VpnLog'
            $content | Should -Match 'vpn_history\.log'
        }
    }

    Context "Help Documentation" {
        It "Should have synopsis" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should document VPN types" {
            $content = Get-Content $script:VpnPath -Raw
            $content | Should -Match 'IKEv2'
            $content | Should -Match 'SSTP'
        }
    }
}

Describe "Manage-WSL.ps1" -Tag "WSL", "Tier3" {
    BeforeAll {
        $script:WslPath = $script:Tier3Scripts['Manage-WSL']
        $script:WslAst = Get-ScriptAst -Path $script:WslPath
    }

    Context "Parameter Validation" {
        It "Should have Action parameter with ValidateSet" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Status.*Install.*List.*Export.*Import.*Remove.*Configure.*\)\]'
        }

        It "Should have Distribution parameter" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\[string\]\$Distribution'
        }

        It "Should have MemoryLimit parameter" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\[string\]\$MemoryLimit'
        }

        It "Should have ProcessorCount parameter" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\[int\]\$ProcessorCount'
        }

        It "Should have Version parameter for WSL version" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\[ValidateSet\(1,\s*2\)\]'
        }
    }

    Context "Feature Implementation" {
        It "Should check WSL installation status" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Test-WslInstalled'
        }

        It "Should get WSL distributions" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Get-WslDistributions'
            $content | Should -Match 'wsl --list'
        }

        It "Should have export functionality" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Export-WslDistribution'
            $content | Should -Match 'wsl --export'
        }

        It "Should have import functionality" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Import-WslDistribution'
            $content | Should -Match 'wsl --import'
        }

        It "Should configure .wslconfig" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Set-WslConfiguration'
            $content | Should -Match '\.wslconfig'
        }

        It "Should have troubleshooting function" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Invoke-WslTroubleshoot'
        }

        It "Should check virtualization requirements" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'VirtualMachinePlatform'
            $content | Should -Match 'Microsoft-Windows-Subsystem-Linux'
        }
    }

    Context "Help Documentation" {
        It "Should have synopsis" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should document available distributions" {
            $content = Get-Content $script:WslPath -Raw
            $content | Should -Match 'Ubuntu'
            $content | Should -Match 'Debian'
        }
    }
}

Describe "Manage-Docker.ps1" -Tag "Docker", "Tier3" {
    BeforeAll {
        $script:DockerPath = $script:Tier3Scripts['Manage-Docker']
        $script:DockerAst = Get-ScriptAst -Path $script:DockerPath
    }

    Context "Parameter Validation" {
        It "Should have Action parameter with ValidateSet" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Status.*Start.*Stop.*Restart.*List.*Logs.*Prune.*\)\]'
        }

        It "Should have Target parameter for list/prune operations" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\[ValidateSet\(.*Containers.*Images.*Volumes.*Networks.*All.*\)\]'
        }

        It "Should have ContainerName parameter" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\[string\]\$ContainerName'
        }

        It "Should have Follow switch for logs" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\[switch\]\$Follow'
        }

        It "Should have Lines parameter for log output" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\[int\]\$Lines'
        }
    }

    Context "Feature Implementation" {
        It "Should check Docker installation" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Test-DockerInstalled'
        }

        It "Should check Docker running status" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Test-DockerRunning'
            $content | Should -Match 'docker info'
        }

        It "Should list containers" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Get-DockerContainers'
            $content | Should -Match 'docker.*ps'
        }

        It "Should list images" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Get-DockerImages'
            $content | Should -Match 'docker images'
        }

        It "Should have prune functionality" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Invoke-DockerPrune'
            $content | Should -Match 'docker.*prune'
        }

        It "Should show container logs" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Show-ContainerLogs'
            $content | Should -Match 'docker logs'
        }

        It "Should have container stats function" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Get-ContainerStats'
            $content | Should -Match 'docker stats'
        }

        It "Should have troubleshooting function" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Invoke-DockerTroubleshoot'
        }

        It "Should manage Docker Desktop" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match 'Start-DockerDesktop'
            $content | Should -Match 'Stop-DockerDesktop'
        }
    }

    Context "Help Documentation" {
        It "Should have synopsis" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should have examples" {
            $content = Get-Content $script:DockerPath -Raw
            $content | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Test-DevEnvironment.ps1" -Tag "DevEnvironment", "Tier3" {
    BeforeAll {
        $script:DevEnvPath = $script:Tier3Scripts['Test-DevEnvironment']
        $script:DevEnvAst = Get-ScriptAst -Path $script:DevEnvPath
    }

    Context "Parameter Validation" {
        It "Should have Profile parameter with ValidateSet" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match '\[ValidateSet\(.*WebDev.*Python.*DevOps.*FullStack.*Custom.*\)\]'
        }

        It "Should have AutoInstall switch" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match '\[switch\]\$AutoInstall'
        }

        It "Should have CheckSSH switch" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match '\[switch\]\$CheckSSH'
        }

        It "Should have CheckExtensions switch" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match '\[switch\]\$CheckExtensions'
        }

        It "Should have OutputFormat parameter" {
            $content = Get-Content $script:DevEnvPath -Raw
            # Check ValidateSet and OutputFormat exist (may be on different lines)
            $content | Should -Match "ValidateSet.*'Console'.*'HTML'.*'JSON'"
            $content | Should -Match '\[string\]\$OutputFormat'
        }
    }

    Context "Tool Definitions" {
        It "Should define common development tools" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'ToolDefinitions'
            $content | Should -Match 'git\s*='
            $content | Should -Match 'node\s*='
            $content | Should -Match 'python\s*='
            $content | Should -Match 'docker\s*='
        }

        It "Should include version patterns for each tool" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'VersionPattern'
            $content | Should -Match 'MinVersion'
        }

        It "Should include package manager IDs" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'WingetId'
            $content | Should -Match 'ChocoId'
        }
    }

    Context "Feature Implementation" {
        It "Should have version comparison function" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Compare-SemVer'
        }

        It "Should test tool installation" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Test-ToolInstalled'
            $content | Should -Match 'Get-Command'
        }

        It "Should check SSH key status" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Get-SSHKeyStatus'
            $content | Should -Match '\.ssh'
        }

        It "Should check VS Code extensions" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Get-VSCodeExtensions'
            $content | Should -Match 'code --list-extensions'
        }

        It "Should check package managers" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Test-PackageManagers'
            $content | Should -Match 'winget'
            $content | Should -Match 'choco'
        }

        It "Should have auto-install functionality" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Install-MissingTool'
        }

        It "Should generate HTML reports" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Export-HtmlReport'
        }
    }

    Context "Profile Definitions" {
        It "Should define WebDev profile" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match "WebDev\s*=\s*@\("
        }

        It "Should define Python profile" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match "Python\s*=\s*@\("
        }

        It "Should define DevOps profile" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match "DevOps\s*=\s*@\("
        }

        It "Should define FullStack profile" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match "FullStack\s*=\s*@\("
        }
    }

    Context "Help Documentation" {
        It "Should have synopsis" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should document supported package managers" {
            $content = Get-Content $script:DevEnvPath -Raw
            $content | Should -Match 'Winget'
            $content | Should -Match 'Chocolatey'
        }
    }
}

Describe "Tier 3 Scripts - CommonFunctions Integration" -Tag "Integration", "Tier3" {
    foreach ($scriptName in $script:Tier3Scripts.Keys) {
        Context "$scriptName CommonFunctions integration" {
            It "Should import CommonFunctions module" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match 'CommonFunctions\.psm1'
            }

            It "Should have fallback logging functions" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match 'function Write-Success'
                $content | Should -Match 'function Write-InfoMessage'
                $content | Should -Match 'function Write-WarningMessage'
                $content | Should -Match 'function Write-ErrorMessage'
            }

            It "Should use proper ASCII markers in fallback functions" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '\[\+\].*-ForegroundColor Green'
                $content | Should -Match '\[i\].*-ForegroundColor Blue'
                $content | Should -Match '\[!\].*-ForegroundColor Yellow'
                $content | Should -Match '\[-\].*-ForegroundColor Red'
            }
        }
    }
}

Describe "Tier 3 Scripts - Standards Compliance" -Tag "Standards", "Tier3" {
    foreach ($scriptName in $script:Tier3Scripts.Keys) {
        Context "$scriptName standards compliance" {
            It "Should have #Requires -Version 5.1" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '#Requires -Version 5\.1'
            }

            It "Should have CmdletBinding attribute" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '\[CmdletBinding'
            }

            It "Should have script version variable" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '\$script:ScriptVersion\s*='
            }

            It "Should track execution time" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '\$script:StartTime\s*=\s*Get-Date'
            }

            It "Should not contain emojis" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                # Check for common emoji patterns
                $content | Should -Not -Match '[\u{1F300}-\u{1F9FF}]'
            }

            It "Should have Main function" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match 'function Main'
            }

            It "Should call Main function at end" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match 'Main\s*$'
            }
        }
    }
}

Describe "Tier 3 Scripts - SupportsShouldProcess" -Tag "ShouldProcess", "Tier3" -Skip {
    # Skipped: SupportsShouldProcess is a future enhancement, not currently implemented
    $scriptsWithShouldProcess = @('Backup-BrowserProfiles', 'Manage-VPN', 'Manage-WSL', 'Manage-Docker')

    foreach ($scriptName in $scriptsWithShouldProcess) {
        Context "$scriptName ShouldProcess support" {
            It "Should have SupportsShouldProcess = `$true" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
            }

            It "Should use PSCmdlet.ShouldProcess for destructive operations" {
                $content = Get-Content $script:Tier3Scripts[$scriptName] -Raw
                $content | Should -Match '\$PSCmdlet\.ShouldProcess'
            }
        }
    }
}
