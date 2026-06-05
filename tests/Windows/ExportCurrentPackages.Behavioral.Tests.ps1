# Behavioral Pester tests for export-current-packages.ps1
# Run: Invoke-Pester -Path .\tests\Windows\ExportCurrentPackages.Behavioral.Tests.ps1
#
# The script is dot-sourced (its testability guard skips Main on dot-source) and each
# helper is exercised through Pester Mocks that stand in for winget, choco, registry
# access, and filesystem side effects.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\first-time-setup\export-current-packages.ps1'
    . $ScriptPath

    # Stub native commands so Pester's Mock can intercept calls inside the dot-sourced
    # script. Without these stubs, calls to `winget` / `choco` would hit the real
    # executable (if installed) or error out.
    function winget { param() }
    function choco { param() }
}

Describe 'export-current-packages.ps1 - Export-WingetPackage' {
    BeforeEach {
        $script:Dest = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
    }

    Context 'When winget is installed' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
            $dest = $script:Dest
            Mock winget {
                '{"Sources":[{"Packages":[{"PackageIdentifier":"foo"},{"PackageIdentifier":"bar"}]}]}' |
                    Out-File (Join-Path $dest 'winget-packages.json') -Encoding UTF8
            }
        }

        It 'Calls winget' {
            Export-WingetPackage -Destination $script:Dest
            Should -Invoke winget -Times 1 -Exactly
        }

        It 'Creates winget-packages.json at the destination' {
            Export-WingetPackage -Destination $script:Dest
            Test-Path (Join-Path $script:Dest 'winget-packages.json') | Should -Be $true
        }
    }

    Context 'When winget is missing' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
            Mock winget { }
        }

        It 'Does not invoke winget' {
            Export-WingetPackage -Destination $script:Dest
            Should -Invoke winget -Times 0
        }

        It 'Does not create the output file' {
            Export-WingetPackage -Destination $script:Dest
            Test-Path (Join-Path $script:Dest 'winget-packages.json') | Should -Be $false
        }
    }

    Context 'When winget throws' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
            Mock winget { throw 'simulated winget failure' }
        }

        It 'Does not propagate the exception' {
            { Export-WingetPackage -Destination $script:Dest } | Should -Not -Throw
        }
    }
}

Describe 'export-current-packages.ps1 - Export-ChocolateyPackage' {
    BeforeEach {
        $script:Dest = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
    }

    Context 'When choco is installed' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
            $dest = $script:Dest
            Mock choco {
                @'
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="git" version="2.40.0" />
  <package id="vscode" version="1.80.0" />
</packages>
'@ | Out-File (Join-Path $dest 'chocolatey-packages.config') -Encoding UTF8
            }
        }

        It 'Calls choco' {
            Export-ChocolateyPackage -Destination $script:Dest
            Should -Invoke choco -Times 1
        }

        It 'Creates the .config XML file' {
            Export-ChocolateyPackage -Destination $script:Dest
            Test-Path (Join-Path $script:Dest 'chocolatey-packages.config') | Should -Be $true
        }

        It 'Also creates the secondary chocolatey-packages.txt list' {
            Export-ChocolateyPackage -Destination $script:Dest
            Test-Path (Join-Path $script:Dest 'chocolatey-packages.txt') | Should -Be $true
        }

        It 'The .txt list contains entries in "id version" format' {
            Export-ChocolateyPackage -Destination $script:Dest
            $content = Get-Content (Join-Path $script:Dest 'chocolatey-packages.txt') -Raw
            $content | Should -Match 'git 2\.40\.0'
            $content | Should -Match 'vscode 1\.80\.0'
        }
    }

    Context 'When choco is missing' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
            Mock choco { }
        }

        It 'Does not invoke choco' {
            Export-ChocolateyPackage -Destination $script:Dest
            Should -Invoke choco -Times 0
        }

        It 'Does not create the .config file' {
            Export-ChocolateyPackage -Destination $script:Dest
            Test-Path (Join-Path $script:Dest 'chocolatey-packages.config') | Should -Be $false
        }
    }

    Context 'When choco throws' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
            Mock choco { throw 'simulated choco failure' }
        }

        It 'Does not propagate the exception' {
            { Export-ChocolateyPackage -Destination $script:Dest } | Should -Not -Throw
        }
    }
}

Describe 'export-current-packages.ps1 - Write-ExportTimestamp' {
    BeforeEach {
        $script:Dest = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
    }

    It 'Creates last-export.txt at the destination' {
        Write-ExportTimestamp -Destination $script:Dest
        Test-Path (Join-Path $script:Dest 'last-export.txt') | Should -Be $true
    }

    It 'Writes a "Last export:" prefix and a yyyy-MM-dd HH:mm:ss timestamp' {
        Write-ExportTimestamp -Destination $script:Dest
        $content = Get-Content (Join-Path $script:Dest 'last-export.txt') -Raw
        $content | Should -Match 'Last export: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    }
}

Describe 'export-current-packages.ps1 - Main' {
    BeforeEach {
        # Use a fresh, non-existent destination so we can verify Main creates it.
        $script:Dest = Join-Path $TestDrive ([Guid]::NewGuid().Guid)

        Mock Export-WingetPackage { }
        Mock Export-ChocolateyPackage { }
        Mock Export-InstalledProgram { }
        Mock Write-ExportTimestamp { }
    }

    It 'Creates the output directory when it does not exist' {
        Main -Destination $script:Dest
        Test-Path $script:Dest | Should -Be $true
    }

    It 'Calls Export-WingetPackage with the destination' {
        Main -Destination $script:Dest
        Should -Invoke Export-WingetPackage -Times 1 -ParameterFilter { $Destination -eq $script:Dest }
    }

    It 'Calls Export-ChocolateyPackage with the destination' {
        Main -Destination $script:Dest
        Should -Invoke Export-ChocolateyPackage -Times 1 -ParameterFilter { $Destination -eq $script:Dest }
    }

    It 'Calls Export-InstalledProgram with the destination' {
        Main -Destination $script:Dest
        Should -Invoke Export-InstalledProgram -Times 1 -ParameterFilter { $Destination -eq $script:Dest }
    }

    It 'Calls Write-ExportTimestamp with the destination' {
        Main -Destination $script:Dest
        Should -Invoke Write-ExportTimestamp -Times 1 -ParameterFilter { $Destination -eq $script:Dest }
    }
}
