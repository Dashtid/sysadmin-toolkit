# Behavioral Pester tests for fresh-windows-setup.ps1
# Run: Invoke-Pester -Path .\tests\Windows\FreshWindowsSetup.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Main on dot-source).
# Set-SystemConfiguration, Install-ProfilePackage, Install-Package, and Main
# take explicit params so tests don't need to mutate script-scope state.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\first-time-setup\fresh-windows-setup.ps1'
    . $ScriptPath

    function winget { param() }
    function choco { param() }
    function git { param() }
    function wsl { param() }
}

Describe 'fresh-windows-setup.ps1 - Install-Package' {
    Context 'When -Skip is true' {
        BeforeEach {
            Mock Write-Section { throw 'should not be called' }
        }

        It 'Returns immediately without entering the install flow' {
            { Install-Package -Skip $true } | Should -Not -Throw
            Should -Invoke Write-Section -Times 0
        }
    }
}

Describe 'fresh-windows-setup.ps1 - Set-SystemConfiguration' {
    Context 'When -Skip is true' {
        BeforeEach {
            Mock Set-ItemProperty { throw 'should not be called' }
            Mock Enable-WindowsOptionalFeature { throw 'should not be called' }
        }

        It 'Returns immediately without applying any settings' {
            { Set-SystemConfiguration -Skip $true } | Should -Not -Throw
            Should -Invoke Set-ItemProperty -Times 0
            Should -Invoke Enable-WindowsOptionalFeature -Times 0
        }
    }

    Context 'When -Skip is false' {
        BeforeEach {
            Mock Set-ItemProperty { }
            Mock New-Item { }
            Mock Test-Path { $true }
            Mock Get-Command { $null }   # treat git as missing for these tests
            Mock Enable-WindowsOptionalFeature { }
            Mock wsl { }
        }

        It 'Applies the five Explorer/dark-mode/Bing registry edits' {
            Set-SystemConfiguration -Skip $false -ProfileName 'Work' -SkipWslSetup $true
            Should -Invoke Set-ItemProperty -Times 5
        }

        It 'Uses the Work development directory when -ProfileName is Work' {
            $script:CreatedPaths = @()
            Mock New-Item { $script:CreatedPaths += $Path }
            Mock Test-Path { $false }   # force New-Item to fire
            Set-SystemConfiguration -Skip $false -ProfileName 'Work' -SkipWslSetup $true
            ($script:CreatedPaths -join '|') | Should -Match 'Development'
        }

        It 'Uses C:\Code directory when -ProfileName is Home' {
            $script:CreatedPaths = @()
            Mock New-Item { $script:CreatedPaths += $Path }
            Mock Test-Path { $false }
            Set-SystemConfiguration -Skip $false -ProfileName 'Home' -SkipWslSetup $true
            ($script:CreatedPaths -join '|') | Should -Match 'C:\\Code'
        }

        It 'Enables WSL when -SkipWslSetup is false and Work profile' {
            Set-SystemConfiguration -Skip $false -ProfileName 'Work' -SkipWslSetup $false
            Should -Invoke Enable-WindowsOptionalFeature -Times 2
        }

        It 'Skips WSL when -SkipWslSetup is true' {
            Set-SystemConfiguration -Skip $false -ProfileName 'Work' -SkipWslSetup $true
            Should -Invoke Enable-WindowsOptionalFeature -Times 0
        }

        It 'Skips WSL for Home profile even when -SkipWslSetup is false' {
            Set-SystemConfiguration -Skip $false -ProfileName 'Home' -SkipWslSetup $false
            Should -Invoke Enable-WindowsOptionalFeature -Times 0
        }
    }
}

Describe 'fresh-windows-setup.ps1 - Install-ProfilePackage' {
    BeforeEach {
        Mock Get-Command { $null }   # neither winget nor choco for default branch
        Mock winget { }
        Mock choco { }
    }

    Context 'When -Skip is true' {
        It 'Returns immediately' {
            Install-ProfilePackage -ProfileName 'Work' -Skip $true
            Should -Invoke winget -Times 0
            Should -Invoke choco -Times 0
        }
    }

    Context 'When ProfileName is empty' {
        It 'Returns immediately (no profile = use exported packages instead)' {
            Install-ProfilePackage -ProfileName '' -Skip $false
            Should -Invoke winget -Times 0
        }
    }

    Context 'When winget is available' {
        BeforeEach {
            $script:WingetCalls = @()
            Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
            Mock winget {
                $script:WingetCalls += , @($args)
            }
        }

        It 'Installs Microsoft.Teams for Work profile' {
            Install-ProfilePackage -ProfileName 'Work' -Skip $false
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Match 'Microsoft\.Teams'
        }

        It 'Does NOT install Microsoft.Teams for Home profile' {
            Install-ProfilePackage -ProfileName 'Home' -Skip $false
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Not -Match 'Microsoft\.Teams'
        }

        It 'Installs Discord for Home profile' {
            Install-ProfilePackage -ProfileName 'Home' -Skip $false
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Match 'Discord\.Discord'
        }

        It 'Includes Valve.Steam when Home profile and -SkipGamingPackages is false (default)' {
            Install-ProfilePackage -ProfileName 'Home' -Skip $false -SkipGamingPackages $false
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Match 'Valve\.Steam'
        }

        It 'Excludes Valve.Steam when -SkipGamingPackages is true' {
            Install-ProfilePackage -ProfileName 'Home' -Skip $false -SkipGamingPackages $true
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Not -Match 'Valve\.Steam'
        }

        It 'Always installs the common packages (e.g. Git.Git) regardless of profile' {
            Install-ProfilePackage -ProfileName 'Home' -Skip $false
            ($script:WingetCalls | ForEach-Object { $_ -join ' ' }) -join '|' | Should -Match 'Git\.Git'
        }
    }
}

Describe 'fresh-windows-setup.ps1 - Main' {
    BeforeEach {
        Mock Assert-Administrator { }
        Mock Show-Banner { }
        Mock Test-PowerShellVersion { }
        Mock Test-RequiredFile { }
        Mock Show-SetupSummary { throw 'interactive prompt should not fire in tests' }
        Mock Install-Package { }
        Mock Install-ProfilePackage { }
        Mock Set-SystemConfiguration { }
        Mock Show-PostInstallation { }
    }

    It 'Calls Assert-Administrator first (admin gating moved from #Requires)' {
        Main -ProfileName 'Work' -Interactive $false
        Should -Invoke Assert-Administrator -Times 1
    }

    It 'Skips the interactive Show-SetupSummary in non-interactive mode' {
        { Main -ProfileName 'Work' -Interactive $false } | Should -Not -Throw
    }

    It 'Dispatches to Install-ProfilePackage when -ProfileName is set' {
        Main -ProfileName 'Work' -Interactive $false
        Should -Invoke Install-ProfilePackage -Times 1
        Should -Invoke Install-Package -Times 0
    }

    It 'Dispatches to Install-Package when -ProfileName is empty' {
        Main -ProfileName '' -Interactive $false
        Should -Invoke Install-Package -Times 1
        Should -Invoke Install-ProfilePackage -Times 0
    }

    It 'Calls Test-RequiredFile only when ProfileName is empty' {
        Main -ProfileName '' -Interactive $false
        Should -Invoke Test-RequiredFile -Times 1

        Main -ProfileName 'Work' -Interactive $false
        # After both runs: only the first call should have hit Test-RequiredFile
        Should -Invoke Test-RequiredFile -Times 1
    }

    It 'Always calls Set-SystemConfiguration' {
        Main -ProfileName 'Work' -Interactive $false
        Should -Invoke Set-SystemConfiguration -Times 1
    }

    It 'Always calls Show-PostInstallation at the end' {
        Main -ProfileName 'Work' -Interactive $false
        Should -Invoke Show-PostInstallation -Times 1
    }
}
