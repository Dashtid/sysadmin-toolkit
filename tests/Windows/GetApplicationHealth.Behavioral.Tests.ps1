# Behavioral Pester tests for Get-ApplicationHealth.ps1
# Run: Invoke-Pester -Path .\tests\Windows\GetApplicationHealth.Behavioral.Tests.ps1

BeforeAll {
    # Native-command stubs so Pester Mock can attach.
    function winget { param() }
    function choco { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\monitoring\Get-ApplicationHealth.ps1'
    . $ScriptPath

    $global:LASTEXITCODE = 0
}

Describe 'Get-ApplicationHealth.ps1 - Get-InstalledApplications' {
    BeforeEach {
        Mock Write-Verbose { }
    }

    It 'Maps DisplayName / DisplayVersion / Publisher from registry items' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                DisplayName     = 'Notepad++'
                DisplayVersion  = '8.6.0'
                Publisher       = 'Notepad++ Team'
                InstallDate     = '20260101'
                InstallLocation = 'C:\Program Files\Notepad++'
                UninstallString = 'C:\Program Files\Notepad++\uninstall.exe'
            }
        } -ParameterFilter { $Path -like 'HKLM:*' -or $Path -like 'HKCU:*' }
        Mock Get-AppxPackage { @() }

        $apps = @(Get-InstalledApplications)
        ($apps | Where-Object { $_.Name -eq 'Notepad++' })[0].Version | Should -Be '8.6.0'
    }

    It 'Tags WOW6432Node entries as x86 and others as x64' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                DisplayName    = 'WOWApp'
                DisplayVersion = '1.0'
                Publisher      = 'X'
            }
        } -ParameterFilter { $Path -like '*WOW6432Node*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                DisplayName    = 'NativeApp'
                DisplayVersion = '2.0'
                Publisher      = 'Y'
            }
        } -ParameterFilter { -not ($Path -like '*WOW6432Node*') -and ($Path -like 'HKLM:*' -or $Path -like 'HKCU:*') }
        Mock Get-AppxPackage { @() }

        $apps = @(Get-InstalledApplications)
        @($apps | Where-Object { $_.Name -eq 'WOWApp' })[0].Architecture | Should -Be 'x86'
        @($apps | Where-Object { $_.Name -eq 'NativeApp' })[0].Architecture | Should -Be 'x64'
    }

    It 'De-duplicates apps with the same Name + Version' {
        # Same app returned twice from registry — only one record should land.
        $script:Calls = 0
        Mock Get-ItemProperty {
            $script:Calls++
            [PSCustomObject]@{ DisplayName = 'DupApp'; DisplayVersion = '1.0'; Publisher = 'X' }
        } -ParameterFilter { $Path -like 'HKLM:*' -or $Path -like 'HKCU:*' }
        Mock Get-AppxPackage { @() }

        $apps = @(Get-InstalledApplications)
        @($apps | Where-Object { $_.Name -eq 'DupApp' }).Count | Should -Be 1
    }

    It 'Includes Windows Store apps with Source=WindowsStore' {
        Mock Get-ItemProperty { $null }
        Mock Get-AppxPackage {
            @([PSCustomObject]@{
                Name            = 'Microsoft.Calculator'
                Version         = '1.0.0.0'
                Publisher       = 'Microsoft'
                InstallLocation = 'C:\X'
                Architecture    = 'X64'
                IsFramework     = $false
            })
        }

        $apps = @(Get-InstalledApplications)
        ($apps | Where-Object { $_.Name -eq 'Microsoft.Calculator' })[0].Source | Should -Be 'WindowsStore'
    }
}

Describe 'Get-ApplicationHealth.ps1 - Test-ApplicationInstalled' {
    BeforeEach {
        $script:Apps = @(
            [PSCustomObject]@{ Name = 'Visual Studio Code' }
            [PSCustomObject]@{ Name = 'Notepad++' }
        )
    }

    It 'Returns the match for an exact name' {
        $found = Test-ApplicationInstalled -AppName 'Notepad++' -InstalledApps $script:Apps
        $found.Name | Should -Be 'Notepad++'
    }

    It 'Returns the match for a wildcard partial name' {
        $found = Test-ApplicationInstalled -AppName 'Visual Studio' -InstalledApps $script:Apps
        $found.Name | Should -Be 'Visual Studio Code'
    }

    It 'Returns null for an app that is not installed' {
        $found = Test-ApplicationInstalled -AppName 'Nonexistent' -InstalledApps $script:Apps
        $found | Should -BeNullOrEmpty
    }
}

Describe 'Get-ApplicationHealth.ps1 - Get-WingetUpdates' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Returns an empty array when winget is not on PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
        $updates = @(Get-WingetUpdates)
        $updates.Count | Should -Be 0
    }

    It 'Parses winget upgrade output into PSCustomObjects' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
        Mock winget {
            $global:LASTEXITCODE = 0
            @(
                "Name                                 Id                       Version    Available  Source"
                "------------------------------------------------------------------------------------------"
                "PowerShell                           Microsoft.PowerShell     7.4.0      7.4.1      winget"
                "Git                                  Git.Git                  2.42.0     2.43.0     winget"
                ""
                "2 upgrades available."
            )
        }

        $updates = @(Get-WingetUpdates)
        $updates.Count | Should -Be 2
        ($updates | Where-Object { $_.Name -eq 'PowerShell' })[0].AvailableVersion | Should -Be '7.4.1'
    }
}

Describe 'Get-ApplicationHealth.ps1 - Get-ChocolateyUpdates' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Verbose { }
        Mock Write-WarningMessage { }
    }

    It 'Returns an empty array when choco is not installed' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
        $updates = @(Get-ChocolateyUpdates)
        $updates.Count | Should -Be 0
    }

    It 'Parses choco outdated --limit-output into PSCustomObjects' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
        Mock choco {
            $global:LASTEXITCODE = 0
            @(
                'nodejs|18.0.0|20.0.0|false'
                'python|3.10.0|3.12.0|false'
            )
        }

        $updates = @(Get-ChocolateyUpdates)
        $updates.Count | Should -Be 2
        ($updates | Where-Object { $_.Name -eq 'nodejs' })[0].AvailableVersion | Should -Be '20.0.0'
    }
}

Describe 'Get-ApplicationHealth.ps1 - Get-ApplicationCrashes' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Extracts Application name from Properties[0] for Event 1000 (Application Error)' {
        Mock Get-WinEvent {
            @([PSCustomObject]@{
                TimeCreated = (Get-Date)
                Id          = 1000
                Properties  = @(
                    [PSCustomObject]@{ Value = 'crashy.exe' }
                    [PSCustomObject]@{ Value = '1.2.3' }
                    [PSCustomObject]@{ Value = 'whatever' }
                    [PSCustomObject]@{ Value = 'kernel32.dll' }
                    [PSCustomObject]@{ Value = 'a' }
                    [PSCustomObject]@{ Value = 'b' }
                    [PSCustomObject]@{ Value = '0xC0000005' }
                )
            })
        } -ParameterFilter { $FilterHashtable.Id -eq 1000 }
        Mock Get-WinEvent { @() } -ParameterFilter { $FilterHashtable.Id -ne 1000 }

        $crashes = @(Get-ApplicationCrashes -Days 7)
        $crashes.Count | Should -Be 1
        $crashes[0].Application | Should -Be 'crashy.exe'
        $crashes[0].FaultingModule | Should -Be 'kernel32.dll'
        $crashes[0].ExceptionCode | Should -Be '0xC0000005'
        $crashes[0].EventType | Should -Be 'Application Error'
    }

    It "Labels Event 1002 entries as 'Application Hang' with ExceptionCode='Hang'" {
        Mock Get-WinEvent {
            @([PSCustomObject]@{
                TimeCreated = (Get-Date)
                Id          = 1002
                Properties  = @(
                    [PSCustomObject]@{ Value = 'hangy.exe' }
                    [PSCustomObject]@{ Value = '2.0' }
                )
            })
        } -ParameterFilter { $FilterHashtable.Id -eq 1002 }
        Mock Get-WinEvent { @() } -ParameterFilter { $FilterHashtable.Id -ne 1002 }

        $crashes = @(Get-ApplicationCrashes -Days 7)
        $crashes.Count | Should -Be 1
        $crashes[0].EventType | Should -Be 'Application Hang'
        $crashes[0].ExceptionCode | Should -Be 'Hang'
    }

    It 'Returns empty when there are no matching events' {
        Mock Get-WinEvent { @() }
        $crashes = @(Get-ApplicationCrashes -Days 7)
        $crashes.Count | Should -Be 0
    }
}

Describe 'Get-ApplicationHealth.ps1 - Get-ApplicationResourceUsage' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Returns only processes with WorkingSet64 > 50MB, sorted descending, capped at TopCount' {
        $now = Get-Date
        Mock Get-Process {
            @(
                [PSCustomObject]@{ ProcessName = 'small'; Id = 1; WorkingSet64 = 10MB; CPU = 1; HandleCount = 100; StartTime = $now; Responding = $true; Threads = @(1, 2) }
                [PSCustomObject]@{ ProcessName = 'big1';  Id = 2; WorkingSet64 = 200MB; CPU = 5; HandleCount = 200; StartTime = $now; Responding = $true; Threads = @(1, 2, 3) }
                [PSCustomObject]@{ ProcessName = 'big2';  Id = 3; WorkingSet64 = 150MB; CPU = 3; HandleCount = 150; StartTime = $now; Responding = $true; Threads = @(1) }
            )
        }

        $usage = @(Get-ApplicationResourceUsage -TopCount 5)
        $usage.Count | Should -Be 2   # 'small' filtered out
        $usage[0].ProcessName | Should -Be 'big1'
        $usage[0].MemoryMB | Should -Be 200
    }
}

Describe 'Get-ApplicationHealth.ps1 - Update-Application' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-ErrorMessage { }
    }

    It 'Calls winget upgrade for Winget package manager' {
        Mock winget { $global:LASTEXITCODE = 0; 'OK' } -Verifiable -ParameterFilter {
            $args -contains 'upgrade' -and $args -contains '--id'
        }
        $info = [PSCustomObject]@{ Name = 'Git'; Id = 'Git.Git'; PackageManager = 'Winget' }
        Update-Application -UpdateInfo $info | Out-Null
        Should -InvokeVerifiable
    }

    It 'Calls choco upgrade for Chocolatey package manager and returns true on success' {
        Mock choco { $global:LASTEXITCODE = 0; 'OK' }
        $info = [PSCustomObject]@{ Name = 'nodejs'; Id = 'nodejs'; PackageManager = 'Chocolatey' }
        Update-Application -UpdateInfo $info | Should -Be $true
    }

    It 'Returns false when choco exits non-zero' {
        Mock choco { $global:LASTEXITCODE = 1; 'err' }
        $info = [PSCustomObject]@{ Name = 'nodejs'; Id = 'nodejs'; PackageManager = 'Chocolatey' }
        Update-Application -UpdateInfo $info | Should -Be $false
    }
}
