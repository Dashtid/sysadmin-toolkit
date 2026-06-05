# Behavioral Pester tests for install-from-exported-packages.ps1
# Run: Invoke-Pester -Path .\tests\Windows\InstallFromExportedPackages.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Main on dot-source). Each
# install function takes explicit -PackageDirectory / -Skip / -UseLatest params,
# so tests don't need to mutate the dot-sourced script's variable scope.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\first-time-setup\install-from-exported-packages.ps1'
    . $ScriptPath

    # Stub native commands so Pester's Mock can intercept calls inside the
    # dot-sourced script.
    function winget { param() }
    function choco { param() }
}

Describe 'install-from-exported-packages.ps1 - Install-Chocolatey' {
    Context 'When -Skip is set' {
        BeforeEach {
            Mock Get-Command { throw 'should not be called' }
            Mock Invoke-WebRequest { throw 'should not be called' }
        }

        It 'Returns without invoking Get-Command or Invoke-WebRequest' {
            { Install-Chocolatey -Skip $true } | Should -Not -Throw
            Should -Invoke Get-Command -Times 0
            Should -Invoke Invoke-WebRequest -Times 0
        }
    }

    Context 'When choco is already installed' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
            Mock choco { }
            Mock Invoke-WebRequest { throw 'should not be called' }
        }

        It 'Runs choco upgrade and does not re-download the installer' {
            Install-Chocolatey -Skip $false
            Should -Invoke choco -Times 1
            Should -Invoke Invoke-WebRequest -Times 0
        }
    }

    Context 'When choco is missing' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
            Mock Invoke-WebRequest { }
            Mock Remove-Item { }
        }

        It 'Downloads the installer via Invoke-WebRequest (not iex-DownloadString)' {
            Install-Chocolatey -Skip $false
            Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                $Uri -eq 'https://community.chocolatey.org/install.ps1'
            }
        }

        It 'Cleans up the temp install script' {
            Install-Chocolatey -Skip $false
            Should -Invoke Remove-Item -Times 1
        }
    }

    Context 'When choco bootstrap throws' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
            Mock Invoke-WebRequest { throw 'network down' }
            Mock Remove-Item { }
        }

        It 'Does not propagate the exception' {
            { Install-Chocolatey -Skip $false } | Should -Not -Throw
        }

        It 'Still attempts cleanup of the temp file (finally block)' {
            Install-Chocolatey -Skip $false
            Should -Invoke Remove-Item -Times 1
        }
    }
}

Describe 'install-from-exported-packages.ps1 - Install-WingetPackage' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    Context 'When -Skip is set' {
        BeforeEach {
            Mock Test-Path { throw 'should not be called' }
            Mock winget { throw 'should not be called' }
        }

        It 'Returns without doing anything' {
            { Install-WingetPackage -PackageDirectory $script:Dir -Skip $true } | Should -Not -Throw
            Should -Invoke winget -Times 0
        }
    }

    Context 'When winget-packages.json is missing' {
        BeforeEach {
            Mock winget { throw 'should not be called' }
        }

        It 'Returns without invoking winget' {
            Install-WingetPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke winget -Times 0
        }
    }

    Context 'When winget command is unavailable' {
        BeforeEach {
            '{"Sources":[]}' | Out-File (Join-Path $script:Dir 'winget-packages.json')
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
            Mock winget { throw 'should not be called' }
        }

        It 'Returns without invoking winget' {
            Install-WingetPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke winget -Times 0
        }
    }

    Context 'When winget is available with a package file' {
        BeforeEach {
            '{"Sources":[]}' | Out-File (Join-Path $script:Dir 'winget-packages.json')
            Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
            Mock winget { }
        }

        It 'Calls winget source update and winget import' {
            Install-WingetPackage -PackageDirectory $script:Dir -Skip $false
            # Two calls expected: source update + import
            Should -Invoke winget -Times 2
        }

        It 'Adds --ignore-versions when -UseLatest is true' {
            Install-WingetPackage -PackageDirectory $script:Dir -Skip $false -UseLatest $true
            Should -Invoke winget -ParameterFilter {
                $args -contains '--ignore-versions'
            }
        }

        It 'Omits --ignore-versions by default' {
            Install-WingetPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke winget -Times 0 -ParameterFilter {
                $args -contains '--ignore-versions'
            }
        }
    }
}

Describe 'install-from-exported-packages.ps1 - Install-ChocolateyPackage' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    Context 'When -Skip is set' {
        BeforeEach {
            Mock choco { throw 'should not be called' }
        }

        It 'Returns without invoking choco' {
            { Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $true } | Should -Not -Throw
            Should -Invoke choco -Times 0
        }
    }

    Context 'When chocolatey-packages.config is missing' {
        BeforeEach {
            Mock choco { throw 'should not be called' }
        }

        It 'Returns without invoking choco' {
            Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke choco -Times 0
        }
    }

    Context 'When choco command is unavailable' {
        BeforeEach {
            @'
<?xml version="1.0"?>
<packages><package id="git" version="1.0" /></packages>
'@ | Out-File (Join-Path $script:Dir 'chocolatey-packages.config')
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
            Mock choco { throw 'should not be called' }
        }

        It 'Returns without invoking choco' {
            Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke choco -Times 0
        }
    }

    Context 'When choco is available with multiple packages' {
        BeforeEach {
            @'
<?xml version="1.0"?>
<packages>
  <package id="git" version="2.40.0" />
  <package id="vscode" version="1.80.0" />
  <package id="nodejs" version="20.0.0" />
</packages>
'@ | Out-File (Join-Path $script:Dir 'chocolatey-packages.config')
            Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
            Mock choco { }
        }

        It 'Iterates each package once' {
            Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $false
            Should -Invoke choco -Times 3
        }

        It 'Passes --version=<pinned> when -UseLatest is false' {
            Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $false -UseLatest $false
            Should -Invoke choco -ParameterFilter {
                $args -join ' ' -match '--version='
            }
        }

        It 'Omits --version when -UseLatest is true' {
            Install-ChocolateyPackage -PackageDirectory $script:Dir -Skip $false -UseLatest $true
            Should -Invoke choco -Times 0 -ParameterFilter {
                $args -join ' ' -match '--version='
            }
        }
    }
}

Describe 'install-from-exported-packages.ps1 - Update-Environment' {
    BeforeEach {
        $script:OriginalPath = $env:Path
    }
    AfterEach {
        $env:Path = $script:OriginalPath
    }

    It 'Reassigns $env:Path (verified by no exception)' {
        { Update-Environment } | Should -Not -Throw
    }

    It 'Respects -WhatIf and does not actually change $env:Path' {
        $before = $env:Path
        Update-Environment -WhatIf
        $env:Path | Should -Be $before
    }
}

Describe 'install-from-exported-packages.ps1 - Main' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        Mock Assert-Administrator { }
        Mock Test-PowerShellVersion { }
        Mock Install-Chocolatey { }
        Mock Install-ChocolateyPackage { }
        Mock Install-WingetPackage { }
        Mock Update-Environment { }
    }

    It 'Calls Assert-Administrator first (admin gating moved from #Requires)' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Assert-Administrator -Times 1
    }

    It 'Calls Test-PowerShellVersion' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Test-PowerShellVersion -Times 1
    }

    It 'Calls Install-Chocolatey' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Install-Chocolatey -Times 1
    }

    It 'Calls Install-ChocolateyPackage' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Install-ChocolateyPackage -Times 1
    }

    It 'Calls Install-WingetPackage' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Install-WingetPackage -Times 1
    }

    It 'Calls Update-Environment' {
        Main -PackageDirectory $script:Dir
        Should -Invoke Update-Environment -Times 1
    }
}
