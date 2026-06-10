# Behavioral Pester tests for Backup-DeveloperEnvironment.ps1
# Run: Invoke-Pester -Path .\tests\Windows\BackupDeveloperEnvironment.Behavioral.Tests.ps1
#
# Implementation note (PS7): Out-File's -Encoding parameter is typed as
# [System.Text.Encoding] but has an ArgumentTransformationAttribute that
# converts strings like "UTF8" into the encoding object. Pester's Mock
# replicates the parameter type but NOT the transformer, so mocking Out-File
# breaks the script's `-Encoding UTF8` call with a binding error. Tests that
# need the manifest/extensions code paths to succeed must NOT mock Out-File;
# they let the real cmdlet write into $TestDrive instead.

BeforeAll {
    # Stub the native `code` CLI so Mock can attach to it.
    function code { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Backup-DeveloperEnvironment.ps1'
    . $ScriptPath
}

Describe 'Backup-DeveloperEnvironment.ps1 - Invoke-DeveloperEnvironmentBackup directory creation' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Get-Command { $null }       # No `code` CLI by default
        Mock Test-Path { $false }        # No targets exist by default
    }

    It 'Creates the timestamped backup directory under the provided BackupPath' {
        Mock New-Item { } -Verifiable -ParameterFilter {
            $ItemType -eq 'Directory' -and $Path -like (Join-Path $TestDrive '*')
        }
        $result = Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -InvokeVerifiable
        $result | Should -Not -BeNullOrEmpty
        $result | Should -BeLike (Join-Path $TestDrive '*')
    }

    It 'Returns $null when New-Item throws (directory creation fails)' {
        Mock New-Item { throw 'access denied' }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false | Should -BeNullOrEmpty
        Should -Invoke Write-ErrorMessage -Times 1 -ParameterFilter { $Message -match 'Failed to create backup directory' }
    }
}

Describe 'Backup-DeveloperEnvironment.ps1 - Invoke-DeveloperEnvironmentBackup target file backup' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Get-Command { $null }
        Mock Copy-Item { }    # Catch-all so unmatched targets do not hit the real filesystem
        Mock Get-Item {
            [PSCustomObject]@{
                Length        = 1234
                LastWriteTime = [DateTime]'2026-01-01 10:00:00'
            }
        }
    }

    It 'Copies each existing target into the backup directory' {
        Mock Test-Path { $true }
        Mock Copy-Item { } -Verifiable
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        # Six targets defined: VSCode-Settings, VSCode-Keybindings, WindowsTerminal,
        # PowerShellProfile, GitConfig, SSHConfig
        Should -Invoke Copy-Item -Times 6
    }

    It 'Skips targets whose source path does not exist (warns instead of copying)' {
        Mock Test-Path { $false }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -Invoke Copy-Item -Times 0
        Should -Invoke Write-WarningMessage -Times 6 -ParameterFilter { $Message -match 'Not found' }
    }

    It 'Continues to remaining targets when Copy-Item throws on one target' {
        Mock Test-Path { $true }
        $script:CallCount = 0
        Mock Copy-Item {
            $script:CallCount++
            if ($script:CallCount -eq 1) { throw 'access denied' }
        }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        # All six targets were attempted; one failed, five succeeded.
        $script:CallCount | Should -Be 6
        Should -Invoke Write-ErrorMessage -Times 1 -ParameterFilter { $Message -match 'Failed to backup' }
    }

    It 'Names each destination file after the target Name with the source extension' {
        Mock Test-Path { $true }
        Mock Copy-Item { } -Verifiable -ParameterFilter {
            $Destination -match 'VSCode-Settings\.json$'
        }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -InvokeVerifiable
    }
}

Describe 'Backup-DeveloperEnvironment.ps1 - Invoke-DeveloperEnvironmentBackup VSCode extensions' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Test-Path { $false }       # Skip every file target; isolate to extensions path
        # No Mock Out-File / Mock New-Item: real cmdlets write into $TestDrive.
    }

    It 'Logs success and the extension count when the code CLI emits names' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
        Mock code { 'ms-python.python'; 'ms-vscode.powershell' }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions
        Should -Invoke Write-Success -ParameterFilter {
            $Message -match 'Saved: VSCode extensions \(2 extensions\)'
        }
    }

    It 'Warns and skips when the code CLI is missing from PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'code' }
        Mock code { throw 'should not be called' }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions
        Should -Invoke code -Times 0
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'VSCode CLI .* not found' }
    }

    It 'Warns when the code CLI exists but emits no extensions' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
        Mock code { $null }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'No VSCode extensions found' }
    }

    It 'Does not attempt the extensions step when -IncludeExtensions:$false' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'code' } }
        Mock code { @('should-not-run') }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -Invoke code -Times 0
        Should -Invoke Get-Command -Times 0 -ParameterFilter { $Name -eq 'code' }
    }
}

Describe 'Backup-DeveloperEnvironment.ps1 - Invoke-DeveloperEnvironmentBackup manifest and return value' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Test-Path { $false }
        Mock Get-Command { $null }
        # No Mock Out-File / Mock New-Item: see file header for why.
    }

    It 'Writes the manifest to disk and logs success' {
        $result = Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        # Real Out-File wrote a real manifest.json into the timestamped folder.
        # Use .NET File.Exists to bypass the mocked Test-Path in BeforeEach.
        $manifestPath = Join-Path $result 'manifest.json'
        [System.IO.File]::Exists($manifestPath) | Should -BeTrue
        Should -Invoke Write-Success -ParameterFilter { $Message -match 'Saved backup manifest' }
    }

    It 'Logs an error but does not throw when ConvertTo-Json fails (manifest write path)' {
        # Force the try-block to throw without touching Out-File's mock-encoding bug.
        Mock ConvertTo-Json { throw 'unserializable' }
        { Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false } | Should -Not -Throw
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Failed to save manifest' }
    }

    It 'Returns the timestamped backup directory path (BackupPath\yyyyMMdd-HHmmss)' {
        $result = Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        # Path is BackupPath joined with a 15-char yyyyMMdd-HHmmss timestamp (8 + 1 + 6).
        $leaf = Split-Path $result -Leaf
        $leaf | Should -Match '^\d{8}-\d{6}$'
        (Split-Path $result -Parent) | Should -Be $TestDrive
    }

    It 'Serializes the manifest with ConvertTo-Json -Depth 5' {
        # Spy on ConvertTo-Json; pass through to real implementation by returning
        # a valid JSON string so Out-File's catch block does not trigger.
        Mock ConvertTo-Json { '{"manifest":"spied"}' } -Verifiable -ParameterFilter { $Depth -eq 5 }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false | Out-Null
        Should -InvokeVerifiable
    }
}

Describe 'Backup-DeveloperEnvironment.ps1 - Invoke-DeveloperEnvironmentBackup summary messaging' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Get-Command { $null }
        Mock Copy-Item { }
        Mock Get-Item {
            [PSCustomObject]@{ Length = 0; LastWriteTime = [DateTime]'2026-01-01' }
        }
        # Real New-Item + real Out-File so the manifest write path succeeds.
    }

    It 'Emits "Backup complete" success when at least one target was backed up' {
        Mock Test-Path { $true }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -Invoke Write-Success -ParameterFilter { $Message -match 'Backup complete' }
    }

    It 'Emits "No items were backed up" warning when every target was missing' {
        Mock Test-Path { $false }
        Invoke-DeveloperEnvironmentBackup -BackupPath $TestDrive -IncludeExtensions:$false
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'No items were backed up' }
    }
}
