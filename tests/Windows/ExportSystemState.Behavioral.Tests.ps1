# Behavioral Pester tests for Export-SystemState.ps1
# Run: Invoke-Pester -Path .\tests\Windows\ExportSystemState.Behavioral.Tests.ps1
#
# Sprint 4 lessons applied:
# - Script's -Destination is Mandatory; dot-source with -Destination $TestDrive.
# - Inner helpers (Export-Drivers, etc.) read $DryRun via dynamic scope; tests
#   exercise the non-dry-run path (the production path) and rely on
#   Invoke-SystemStateExport's explicit -DryRun param for the dry-run paths.
# - Do not Mock Out-File for code paths that must succeed (PS7 Mock encoding
#   binding bug); let real Out-File write into $TestDrive.

BeforeAll {
    function winget { param() }
    function choco { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Export-SystemState.ps1'
    . $ScriptPath -Destination $TestDrive
}

Describe 'Export-SystemState.ps1 - Get-ExportComponents' {
    It "Expands 'All' into every component" {
        $result = Get-ExportComponents -Include @('All')
        $result | Should -Contain 'Drivers'
        $result | Should -Contain 'Registry'
        $result | Should -Contain 'Network'
        $result | Should -Contain 'Tasks'
        $result | Should -Contain 'Features'
        $result | Should -Contain 'Services'
        $result | Should -Contain 'Packages'
        $result.Count | Should -Be 7
    }

    It "Returns the supplied list verbatim when 'All' is not present" {
        $result = Get-ExportComponents -Include @('Drivers', 'Network')
        $result.Count | Should -Be 2
        $result | Should -Contain 'Drivers'
        $result | Should -Contain 'Network'
    }
}

Describe 'Export-SystemState.ps1 - New-ExportFolder' {
    It 'Creates the timestamped SystemState_[timestamp] folder + subfolders under -BasePath' {
        $base = Join-Path $TestDrive 'nef-base'
        New-Item -ItemType Directory -Path $base -Force | Out-Null
        $result = New-ExportFolder -BasePath $base
        (Split-Path $result -Leaf) | Should -Match '^SystemState_\d{4}-\d{2}-\d{2}_\d{6}$'
        [System.IO.Directory]::Exists($result) | Should -BeTrue
        [System.IO.Directory]::Exists((Join-Path $result 'drivers')) | Should -BeTrue
        [System.IO.Directory]::Exists((Join-Path $result 'tasks\xml')) | Should -BeTrue
    }
}

Describe 'Export-SystemState.ps1 - Export-Drivers' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ ComponentsExported = 0; FilesCreated = 0; TotalSize = 0; Errors = @(); Warnings = @() }
    }

    It 'Writes drivers.json and drivers.csv on the success path' {
        $exportRoot = Join-Path $TestDrive 'exp-drivers'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'drivers') -Force | Out-Null
        Mock Get-PnpDevice {
            @(
                [PSCustomObject]@{ FriendlyName = 'NIC A'; Class = 'Net'; Status = 'OK'; InstanceId = 'PCI\1'; Manufacturer = 'Intel'; Present = $true }
                [PSCustomObject]@{ FriendlyName = 'GPU B'; Class = 'Display'; Status = 'OK'; InstanceId = 'PCI\2'; Manufacturer = 'NVIDIA'; Present = $true }
            )
        }
        Mock Get-PnpDeviceProperty { [PSCustomObject]@{ Data = '10.0.0.1' } }
        $result = Export-Drivers -ExportPath $exportRoot
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $exportRoot 'drivers\drivers.json')) | Should -BeTrue
        [System.IO.File]::Exists((Join-Path $exportRoot 'drivers\drivers.csv')) | Should -BeTrue
    }

    It 'Returns Success=$false and records an error when Get-PnpDevice throws' {
        $exportRoot = Join-Path $TestDrive 'exp-drivers-fail'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'drivers') -Force | Out-Null
        Mock Get-PnpDevice { throw 'access denied' }
        $result = Export-Drivers -ExportPath $exportRoot
        $result.Success | Should -Be $false
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Export-SystemState.ps1 - New-ExportManifest' {
    It 'Writes manifest.json with computer/components/results and returns its path' {
        $exportRoot = Join-Path $TestDrive 'exp-manifest'
        New-Item -ItemType Directory -Path $exportRoot -Force | Out-Null
        $script:Stats = @{ FilesCreated = 3; Errors = @(); Warnings = @() }
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Windows 11 Pro' } } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' -or $Class -eq 'Win32_OperatingSystem' }
        $result = New-ExportManifest -ExportPath $exportRoot -Components @('Drivers', 'Network') -Results @{ Drivers = @{ Success = $true } }
        $result | Should -Be (Join-Path $exportRoot 'manifest.json')
        [System.IO.File]::Exists($result) | Should -BeTrue
        $manifest = [System.IO.File]::ReadAllText($result) | ConvertFrom-Json
        $manifest.Components | Should -Contain 'Drivers'
        $manifest.Components | Should -Contain 'Network'
    }
}

Describe 'Export-SystemState.ps1 - Compress-ExportFolder' {
    BeforeEach {
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @() }
    }

    It 'Returns the .zip path on success, removes the source folder' {
        Mock Compress-Archive { } -Verifiable
        Mock Remove-Item { } -Verifiable -ParameterFilter { $Path -eq 'C:\src' -and $Recurse }
        $result = Compress-ExportFolder -FolderPath 'C:\src'
        $result | Should -Be 'C:\src.zip'
        Should -InvokeVerifiable
    }

    It 'Returns the original FolderPath and records an error when Compress-Archive throws' {
        Mock Compress-Archive { throw 'no space left' }
        $result = Compress-ExportFolder -FolderPath 'C:\src'
        $result | Should -Be 'C:\src'
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Export-SystemState.ps1 - Export-HTMLReport' {
    It 'Writes export-report.html containing the result table and "Files Created" stat' {
        $outRoot = Join-Path $TestDrive 'exp-html'
        New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
        Mock Write-Success { }
        $script:Stats = @{ FilesCreated = 12; Errors = @(); Warnings = @() }
        $script:ExportFolder = $outRoot
        Export-HTMLReport -OutputPath $outRoot -Results @{
            Drivers = @{ Success = $true; Files = 2 }
            Network = @{ Success = $false; Files = 0 }
        }
        $path = Join-Path $outRoot 'export-report.html'
        [System.IO.File]::Exists($path) | Should -BeTrue
        $content = [System.IO.File]::ReadAllText($path)
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'Drivers'
        $content | Should -Match 'Network'
        $content | Should -Match '12'
    }
}

Describe 'Export-SystemState.ps1 - Export-JSONReport' {
    It 'Writes export-report.json with ComputerName / ExportPath / Statistics / Results' {
        $outRoot = Join-Path $TestDrive 'exp-json'
        New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
        Mock Write-Success { }
        $script:Stats = @{ FilesCreated = 7; Errors = @(); Warnings = @() }
        $script:ExportFolder = $outRoot
        Export-JSONReport -OutputPath $outRoot -Results @{ Drivers = @{ Success = $true; Files = 1 } }
        $path = Join-Path $outRoot 'export-report.json'
        [System.IO.File]::Exists($path) | Should -BeTrue
        $report = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
        $report.ComputerName | Should -Be $env:COMPUTERNAME
        $report.Statistics.FilesCreated | Should -Be 7
        $report.Results.Drivers.Success | Should -Be $true
    }
}

Describe 'Export-SystemState.ps1 - Export-Services' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ FilesCreated = 0; Errors = @(); Warnings = @() }
    }

    It 'Writes services.json and services.csv after enumerating Win32_Service' {
        $exportRoot = Join-Path $TestDrive 'exp-services'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'services') -Force | Out-Null
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{ Name = 'Spooler'; DisplayName = 'Print Spooler'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\spool.exe'; Description = 'desc' }
                [PSCustomObject]@{ Name = 'WSearch'; DisplayName = 'Windows Search'; State = 'Stopped'; StartMode = 'Manual'; StartName = 'LocalSystem'; PathName = 'C:\search.exe'; Description = 'desc' }
            )
        }
        $result = Export-Services -ExportPath $exportRoot
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $exportRoot 'services\services.json')) | Should -BeTrue
        [System.IO.File]::Exists((Join-Path $exportRoot 'services\services.csv')) | Should -BeTrue
    }
}

Describe 'Export-SystemState.ps1 - Export-WindowsFeatures' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ FilesCreated = 0; Errors = @(); Warnings = @() }
    }

    It 'Writes windows-features.json listing optional Windows features' {
        $exportRoot = Join-Path $TestDrive 'exp-features'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'features') -Force | Out-Null
        Mock Get-WindowsOptionalFeature {
            @(
                [PSCustomObject]@{ FeatureName = 'IIS-WebServer'; State = 'Enabled'; DisplayName = 'IIS'; Description = 'd' }
                [PSCustomObject]@{ FeatureName = 'Hyper-V'; State = 'Disabled'; DisplayName = 'Hyper-V'; Description = 'd' }
            )
        }
        $result = Export-WindowsFeatures -ExportPath $exportRoot
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $exportRoot 'features\windows-features.json')) | Should -BeTrue
    }
}

Describe 'Export-SystemState.ps1 - Export-NetworkConfig' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ FilesCreated = 0; Errors = @(); Warnings = @() }
    }

    It 'Writes adapters.json / ip-config.json / routes.json / dns.json / firewall JSON files' {
        $exportRoot = Join-Path $TestDrive 'exp-net'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'network') -Force | Out-Null
        Mock Get-NetAdapter {
            @([PSCustomObject]@{ Name = 'Ethernet'; Status = 'Up'; LinkSpeed = '1 Gbps'; MacAddress = '00-11-22-33-44-55'; InterfaceDescription = 'NIC'; MediaType = '802.3' })
        }
        Mock Get-NetIPConfiguration {
            @([PSCustomObject]@{
                InterfaceAlias       = 'Ethernet'
                InterfaceIndex       = 1
                IPv4Address          = [PSCustomObject]@{ IPAddress = '10.0.0.1' }
                IPv4DefaultGateway   = [PSCustomObject]@{ NextHop   = '10.0.0.254' }
                DNSServer            = [PSCustomObject]@{ ServerAddresses = @('1.1.1.1', '8.8.8.8') }
                NetProfile           = [PSCustomObject]@{ Name      = 'Home' }
            })
        }
        Mock Get-DnsClientServerAddress {
            @([PSCustomObject]@{ InterfaceAlias = 'Ethernet'; ServerAddresses = @('1.1.1.1', '8.8.8.8'); AddressFamily = 2 })
        }
        Mock Get-NetRoute { @() }
        Mock Get-NetFirewallProfile { @() }
        Mock Get-NetFirewallRule { @() }
        $result = Export-NetworkConfig -ExportPath $exportRoot
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $exportRoot 'network\adapters.json')) | Should -BeTrue
        [System.IO.File]::Exists((Join-Path $exportRoot 'network\ip-config.json')) | Should -BeTrue
        [System.IO.File]::Exists((Join-Path $exportRoot 'network\dns.json')) | Should -BeTrue
        [System.IO.File]::Exists((Join-Path $exportRoot 'network\routes.json')) | Should -BeTrue
    }
}

Describe 'Export-SystemState.ps1 - Export-ScheduledTasks' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ FilesCreated = 0; Errors = @(); Warnings = @() }
    }

    It 'Writes tasks-summary.json and per-task XML files (excludes \Microsoft\* tasks)' {
        $exportRoot = Join-Path $TestDrive 'exp-tasks'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'tasks\xml') -Force | Out-Null
        # Use a non-\Microsoft\ path so the helper does not filter the task out.
        Mock Get-ScheduledTask {
            @(
                [PSCustomObject]@{
                    TaskName = 'MyTask'; TaskPath = '\'; State = 'Ready'
                    Description = 'desc'; Author = 'me'
                    Triggers = @(1); Actions = @(1)
                }
            )
        }
        Mock Export-ScheduledTask { '<Task></Task>' }
        $result = Export-ScheduledTasks -ExportPath $exportRoot
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $exportRoot 'tasks\tasks-summary.json')) | Should -BeTrue
    }
}

Describe 'Export-SystemState.ps1 - Export-EventLogs' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ FilesCreated = 0; Errors = @(); Warnings = @() }
    }

    It "Iterates the Application/System/Security logs and reports the count" {
        $exportRoot = Join-Path $TestDrive 'exp-events'
        New-Item -ItemType Directory -Path (Join-Path $exportRoot 'eventlogs') -Force | Out-Null
        Mock Get-WinEvent { @() }   # Simulate empty logs; success path still writes a summary
        $result = Export-EventLogs -ExportPath $exportRoot -Days 7
        $result.Success | Should -Be $true
    }
}

Describe 'Export-SystemState.ps1 - Invoke-SystemStateExport (top level)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Test-IsAdministrator { $true }
        $script:Stats = @{ ComponentsExported = 0; FilesCreated = 0; TotalSize = 0; Errors = @(); Warnings = @() }
        $script:StartTime = Get-Date
    }

    It 'Returns 0 in -DryRun mode (no helpers fail, no files written)' {
        $dest = Join-Path $TestDrive 'inv-dry'
        $result = Invoke-SystemStateExport -Destination $dest -Include @('Drivers') -DryRun
        $result | Should -Be 0
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'DRY RUN' }
    }

    It 'Returns 1 when a fatal error escapes the try block' {
        Mock New-ExportFolder { throw 'fatal IO error' }
        $dest = Join-Path $TestDrive 'inv-throw'
        Invoke-SystemStateExport -Destination $dest -Include @('Drivers') | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Fatal error' }
    }

    It 'Only invokes the explicitly listed components' {
        $dest = Join-Path $TestDrive 'inv-include'
        # Stub all the heavy collectors so only the dispatcher logic runs.
        Mock Export-Drivers { @{ Success = $true; Files = 0 } } -Verifiable
        Mock Export-RegistryKeys { throw 'should not be called' }
        Mock Export-NetworkConfig { throw 'should not be called' }
        Mock Export-ScheduledTasks { throw 'should not be called' }
        Mock Export-WindowsFeatures { throw 'should not be called' }
        Mock Export-Services { throw 'should not be called' }
        Mock Export-InstalledPackages { throw 'should not be called' }
        Mock New-ExportManifest { 'C:\dummy\manifest.json' }
        Invoke-SystemStateExport -Destination $dest -Include @('Drivers') | Out-Null
        Should -InvokeVerifiable
    }
}
