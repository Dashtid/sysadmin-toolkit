# Pester Tests for First-Time Setup Scripts
# Run: Invoke-Pester -Path .\tests\Windows\FirstTimeSetup.Tests.ps1

# Setup variables (compatible with Pester v3 and v5)
$script:ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:WindowsScripts = Join-Path $ProjectRoot "Windows\first-time-setup"

Describe "First-Time Setup Scripts" {

    BeforeAll {
        # This block runs before all tests in Pester v5
        $ErrorActionPreference = 'Stop'
    }

    Context "Script Files Exist" {

        It "export-current-packages.ps1 exists" {
            $ScriptPath = Join-Path $WindowsScripts "export-current-packages.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }

        It "install-from-exported-packages.ps1 exists" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }

        It "fresh-windows-setup.ps1 exists" {
            $ScriptPath = Join-Path $WindowsScripts "fresh-windows-setup.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }

        It "work-laptop-setup.ps1 exists" {
            $ScriptPath = Join-Path $WindowsScripts "work-laptop-setup.ps1"
            Test-Path $ScriptPath | Should -Be $true
        }
    }

    Context "Script Syntax Validation" {

        It "export-current-packages.ps1 has valid syntax" {
            $ScriptPath = Join-Path $WindowsScripts "export-current-packages.ps1"
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "install-from-exported-packages.ps1 has valid syntax" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$Errors)
            $Errors.Count | Should -Be 0
        }

        It "fresh-windows-setup.ps1 has valid syntax" {
            $ScriptPath = Join-Path $WindowsScripts "fresh-windows-setup.ps1"
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$Errors)
            $Errors.Count | Should -Be 0
        }
    }

    Context "Package Export Files" {

        It "winget-packages.json exists" {
            $JsonPath = Join-Path $WindowsScripts "winget-packages.json"
            Test-Path $JsonPath | Should -Be $true
        }

        It "winget-packages.json is valid JSON" {
            $JsonPath = Join-Path $WindowsScripts "winget-packages.json"
            { Get-Content $JsonPath | ConvertFrom-Json } | Should -Not -Throw
        }

        It "winget-packages.json contains packages" {
            $JsonPath = Join-Path $WindowsScripts "winget-packages.json"
            $Json = Get-Content $JsonPath | ConvertFrom-Json
            $Json.Sources.Packages.Count | Should -BeGreaterThan 0
        }

        It "chocolatey-packages.config exists" {
            $ConfigPath = Join-Path $WindowsScripts "chocolatey-packages.config"
            Test-Path $ConfigPath | Should -Be $true
        }

        It "chocolatey-packages.config is valid XML" {
            $ConfigPath = Join-Path $WindowsScripts "chocolatey-packages.config"
            { [xml](Get-Content $ConfigPath) } | Should -Not -Throw
        }

        It "chocolatey-packages.config contains packages" {
            $ConfigPath = Join-Path $WindowsScripts "chocolatey-packages.config"
            [xml]$Xml = Get-Content $ConfigPath
            $Xml.packages.package.Count | Should -BeGreaterThan 0
        }
    }

    Context "Documentation Files" {

        It "README.md exists" {
            $ReadmePath = Join-Path $WindowsScripts "README.md"
            Test-Path $ReadmePath | Should -Be $true
        }

        It "README.md is not empty" {
            $ReadmePath = Join-Path $WindowsScripts "README.md"
            (Get-Content $ReadmePath).Length | Should -BeGreaterThan 10
        }

        It "QUICKSTART.md exists" {
            $QuickstartPath = Join-Path $WindowsScripts "QUICKSTART.md"
            Test-Path $QuickstartPath | Should -Be $true
        }
    }

    Context "Script Requirements" {

        It "Scripts require PowerShell 7+" {
            $ScriptPath = Join-Path $WindowsScripts "fresh-windows-setup.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match "#Requires -Version 7"
        }

        It "Admin scripts require RunAsAdministrator" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match "#Requires -RunAsAdministrator"
        }
    }

    Context "Script Parameters" {

        It "install-from-exported-packages.ps1 accepts UseLatestVersions parameter" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$UseLatestVersions'
        }

        It "install-from-exported-packages.ps1 accepts SkipWinget parameter" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$SkipWinget'
        }

        It "install-from-exported-packages.ps1 accepts SkipChocolatey parameter" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[switch\]\$SkipChocolatey'
        }
    }

    Context "No Emojis in Scripts (Per CLAUDE.md Rules)" {

        It "Scripts don't contain common emojis" {
            $ScriptPath = Join-Path $WindowsScripts "export-current-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            # Check for specific emoji characters
            $Content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
        }

        It "Scripts use ASCII markers [+] [-] [i] [!]" {
            $ScriptPath = Join-Path $WindowsScripts "export-current-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Match '\[\+\]|\[-\]|\[i\]|\[!\]'
        }
    }

    Context "No Hardcoded Credentials" {

        It "Scripts don't contain passwords" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match "password\s*=\s*[`"'].*[`"']"
        }

        It "Scripts don't contain API keys" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match "api[_-]?key\s*=\s*[`"'].*[`"']"
        }
    }
}

Describe "Package Lists Validation" {

    Context "Winget Package List" {

        It "Contains essential development tools" {
            $JsonPath = Join-Path $WindowsScripts "winget-packages.json"
            $Json = Get-Content $JsonPath | ConvertFrom-Json
            $PackageIds = $Json.Sources.Packages.PackageIdentifier

            $PackageIds | Should -Contain "Git.Git"
            $PackageIds | Should -Contain "Microsoft.VisualStudioCode"
            $PackageIds | Should -Contain "Docker.DockerDesktop"
        }

        It "Contains PowerShell 7" {
            $JsonPath = Join-Path $WindowsScripts "winget-packages.json"
            $Json = Get-Content $JsonPath | ConvertFrom-Json
            $PackageIds = $Json.Sources.Packages.PackageIdentifier

            $PackageIds | Should -Contain "Microsoft.PowerShell"
        }
    }

    Context "Chocolatey Package List" {

        It "Contains Git package" {
            $ConfigPath = Join-Path $WindowsScripts "chocolatey-packages.config"
            [xml]$Xml = Get-Content $ConfigPath
            $PackageIds = $Xml.packages.package.id

            $PackageIds | Should -Contain "git"
        }

        It "Contains Python packages" {
            $ConfigPath = Join-Path $WindowsScripts "chocolatey-packages.config"
            [xml]$Xml = Get-Content $ConfigPath
            $PackageIds = $Xml.packages.package.id

            ($PackageIds -match 'python') | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Script Functions" {

    Context "Logging Functions" {

        It "Scripts define logging functions" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw

            $Content | Should -Match 'function Write-Log'
            $Content | Should -Match 'function Write-Success'
            $Content | Should -Match 'function Write-Info'
            $Content | Should -Match 'function Write-Warning'
            $Content | Should -Match 'function Write-Error'
        }
    }

    Context "Main Execution Function" {

        It "Scripts have Main function" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath -Raw

            $Content | Should -Match 'function Main'
        }

        It "Scripts call Main function" {
            $ScriptPath = Join-Path $WindowsScripts "install-from-exported-packages.ps1"
            $Content = Get-Content $ScriptPath

            # Check if "Main" is called at the end of the script
            $Content | Where-Object { $_ -match '^\s*Main\s*$' } | Should -Not -BeNullOrEmpty
        }
    }
}
