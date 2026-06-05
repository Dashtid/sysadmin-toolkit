# Behavioral Pester tests for Restore-DeveloperEnvironment.ps1
# Run: Invoke-Pester -Path .\tests\Windows\RestoreDeveloperEnvironment.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-Restore on dot-source).
# The script's -BackupPath param is Mandatory + ValidateScript, so dot-source
# passes the repo root as a placeholder; tests use TestDrive paths for actual
# restore operations.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Restore-DeveloperEnvironment.ps1'
    . $ScriptPath -BackupPath $ProjectRoot

    # Stub the `code` CLI so Pester Mock can intercept extension installs.
    function code { param() }
}

Describe 'Restore-DeveloperEnvironment.ps1 - Read-RestoreManifest' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    Context 'When manifest.json is missing' {
        It 'Throws with a clear message' {
            { Read-RestoreManifest -Source $script:Dir } | Should -Throw '*Manifest not found*'
        }
    }

    Context 'When manifest.json is malformed JSON' {
        BeforeEach {
            'this is not json' | Out-File (Join-Path $script:Dir 'manifest.json')
        }

        It 'Throws with a parse-failure message' {
            { Read-RestoreManifest -Source $script:Dir } | Should -Throw '*Failed to parse manifest*'
        }
    }

    Context 'When manifest.json is valid' {
        BeforeEach {
            @{
                BackupDate   = '2026-05-15'
                ComputerName = 'WORKLAPTOP'
                UserName     = 'david.dashti'
                Items        = @()
            } | ConvertTo-Json | Out-File (Join-Path $script:Dir 'manifest.json')
        }

        It 'Returns the parsed object with expected fields' {
            $manifest = Read-RestoreManifest -Source $script:Dir
            $manifest.BackupDate | Should -Be '2026-05-15'
            $manifest.ComputerName | Should -Be 'WORKLAPTOP'
        }
    }
}

Describe 'Restore-DeveloperEnvironment.ps1 - Restore-ManifestItem' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        $script:BackupFile = Join-Path $script:Dir 'source.txt'
        $script:OriginalPath = Join-Path $script:Dir 'destination\target.txt'
        'restored content' | Out-File $script:BackupFile

        $script:Item = [PSCustomObject]@{
            Name         = 'PowerShell-Profile'
            BackupFile   = $script:BackupFile
            OriginalPath = $script:OriginalPath
        }
    }

    Context 'When the backup file is missing' {
        BeforeEach {
            Remove-Item $script:BackupFile -Force
        }

        It 'Returns Outcome=Skipped with reason BackupFileMissing' {
            $result = Restore-ManifestItem -Item $script:Item
            $result.Outcome | Should -Be 'Skipped'
            $result.Reason | Should -Be 'BackupFileMissing'
        }
    }

    Context 'When the item has no OriginalPath' {
        BeforeEach {
            $script:Item.OriginalPath = $null
        }

        It 'Returns Outcome=Skipped with reason NoOriginalPath' {
            $result = Restore-ManifestItem -Item $script:Item
            $result.Outcome | Should -Be 'Skipped'
            $result.Reason | Should -Be 'NoOriginalPath'
        }
    }

    Context 'When the destination parent does not exist' {
        It 'Creates the parent directory and restores' {
            $result = Restore-ManifestItem -Item $script:Item
            $result.Outcome | Should -Be 'Restored'
            Test-Path (Split-Path $script:OriginalPath -Parent) | Should -Be $true
            Test-Path $script:OriginalPath | Should -Be $true
        }
    }

    Context 'When -BackupCurrentFirst is true and original file exists' {
        BeforeEach {
            New-Item -ItemType Directory -Path (Split-Path $script:OriginalPath -Parent) | Out-Null
            'pre-existing' | Out-File $script:OriginalPath
        }

        It 'Creates a .bak copy of the original before overwriting' {
            $null = Restore-ManifestItem -Item $script:Item -BackupCurrentFirst $true
            Test-Path "$($script:OriginalPath).bak" | Should -Be $true
            (Get-Content "$($script:OriginalPath).bak" -Raw).Trim() | Should -Be 'pre-existing'
        }
    }

    Context 'When -BackupCurrentFirst is false' {
        BeforeEach {
            New-Item -ItemType Directory -Path (Split-Path $script:OriginalPath -Parent) | Out-Null
            'pre-existing' | Out-File $script:OriginalPath
        }

        It 'Does NOT create a .bak copy' {
            $null = Restore-ManifestItem -Item $script:Item -BackupCurrentFirst $false
            Test-Path "$($script:OriginalPath).bak" | Should -Be $false
        }
    }

    Context 'With -WhatIf' {
        It 'Does not actually copy the file' {
            $result = Restore-ManifestItem -Item $script:Item -WhatIf
            Test-Path $script:OriginalPath | Should -Be $false
        }
    }
}

Describe 'Restore-DeveloperEnvironment.ps1 - Restore-VsCodeExtension' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        $script:ExtFile = Join-Path $script:Dir 'extensions.txt'
        @(
            'ms-python.python'
            'dbaeumer.vscode-eslint'
            'esbenp.prettier-vscode'
        ) | Out-File $script:ExtFile

        $script:ExtItem = [PSCustomObject]@{
            Name       = 'VSCode-Extensions'
            BackupFile = $script:ExtFile
        }
    }

    Context 'When the extensions backup file is missing' {
        BeforeEach {
            Remove-Item $script:ExtFile -Force
        }

        It 'Returns Skipped=$true without invoking code' {
            Mock code { throw 'should not be called' }
            $result = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem
            $result.Skipped | Should -Be $true
        }
    }

    Context 'When code CLI is not in PATH' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'code' }
            Mock code { throw 'should not be called' }
        }

        It 'Returns Skipped=$true without invoking code' {
            $result = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem
            $result.Skipped | Should -Be $true
        }
    }

    Context 'When code CLI is available and three extensions are listed' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
            Mock code { $global:LASTEXITCODE = 0 }
        }

        It 'Calls code --install-extension once per extension' {
            $null = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem
            Should -Invoke code -Times 3
        }

        It 'Counts only successful installs (LASTEXITCODE 0) in Installed' {
            $result = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem
            $result.Installed | Should -Be 3
            $result.Total | Should -Be 3
        }
    }

    Context 'When some extensions fail to install' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
            $script:CallCount = 0
            Mock code {
                $script:CallCount++
                $global:LASTEXITCODE = if ($script:CallCount -eq 2) { 1 } else { 0 }
            }
        }

        It 'Continues iterating past failures and reports partial count' {
            $result = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem
            $result.Installed | Should -Be 2
            $result.Total | Should -Be 3
        }
    }

    Context 'With -WhatIf' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
            Mock code { throw 'should not be called' }
        }

        It 'Does not invoke code at all' {
            $null = Restore-VsCodeExtension -ExtensionsItem $script:ExtItem -WhatIf
            Should -Invoke code -Times 0
        }
    }
}

Describe 'Restore-DeveloperEnvironment.ps1 - Invoke-Restore' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        @{
            BackupDate   = '2026-05-15'
            ComputerName = 'TEST'
            UserName     = 'tester'
            Items        = @(
                @{ Name = 'A'; BackupFile = 'x'; OriginalPath = 'y' },
                @{ Name = 'B'; BackupFile = 'x'; OriginalPath = 'y' },
                @{ Name = 'VSCode-Extensions'; BackupFile = 'z'; OriginalPath = '' }
            )
        } | ConvertTo-Json -Depth 4 | Out-File (Join-Path $script:Dir 'manifest.json')

        Mock Restore-ManifestItem { @{ Outcome = 'Restored'; Reason = $null } }
        Mock Restore-VsCodeExtension { @{ Installed = 0; Total = 0; Skipped = $false } }
    }

    It 'Calls Restore-ManifestItem once per non-extension item' {
        $null = Invoke-Restore -Source $script:Dir
        Should -Invoke Restore-ManifestItem -Times 2
    }

    It 'Calls Restore-VsCodeExtension when -RestoreVsCodeExtensions is true (default)' {
        $null = Invoke-Restore -Source $script:Dir
        Should -Invoke Restore-VsCodeExtension -Times 1
    }

    It 'Does NOT call Restore-VsCodeExtension when -RestoreVsCodeExtensions is false' {
        $null = Invoke-Restore -Source $script:Dir -RestoreVsCodeExtensions $false
        Should -Invoke Restore-VsCodeExtension -Times 0
    }

    It 'Returns counts hashtable with Restored/Skipped/Errors keys' {
        $result = Invoke-Restore -Source $script:Dir
        $result.Restored | Should -Be 2
        $result.Errors | Should -Be 0
    }

    It 'Throws when the manifest is missing' {
        $emptyDir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $emptyDir | Out-Null
        { Invoke-Restore -Source $emptyDir } | Should -Throw '*Manifest not found*'
    }
}
