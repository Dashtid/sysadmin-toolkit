# Behavioral Pester tests for Get-SystemPerformance.ps1
# Run: Invoke-Pester -Path .\tests\Windows\GetSystemPerformance.Behavioral.Tests.ps1
#
# Notes:
# - No Mandatory params on the script; dot-source plain.
# - Invoke-DiskAutoCleanup is the destructive helper -- tests mock Remove-Item
#   and Clear-RecycleBin so no real file deletion can happen.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\monitoring\Get-SystemPerformance.ps1'
    . $ScriptPath
}

Describe 'Get-SystemPerformance.ps1 - Get-ThresholdAlerts' {
    It 'Returns a Critical CPU alert when CPU usage meets the critical threshold' {
        $metrics = @{
            CPU         = @{ UsagePercent = 95 }
            Memory      = @{ UsagePercent = 10 }
            Disk        = @{ QueueLength = 0 }
            DiskVolumes = @()
        }
        $alerts = @(Get-ThresholdAlerts -Metrics $metrics)
        $alerts.Count | Should -Be 1
        $alerts[0].Level | Should -Be 'Critical'
        $alerts[0].Type | Should -Be 'CPU'
    }

    It 'Returns a Warning CPU alert in the [warning, critical) band' {
        $metrics = @{
            CPU         = @{ UsagePercent = 75 }
            Memory      = @{ UsagePercent = 10 }
            Disk        = @{ QueueLength = 0 }
            DiskVolumes = @()
        }
        $alerts = @(Get-ThresholdAlerts -Metrics $metrics)
        $alerts[0].Level | Should -Be 'Warning'
    }

    It 'Emits Critical Memory + Critical Disk + Disk-queue Warning alerts together' {
        $metrics = @{
            CPU         = @{ UsagePercent = 10 }
            Memory      = @{ UsagePercent = 96 }
            Disk        = @{ QueueLength = 5 }
            DiskVolumes = @(
                [PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 96 }
            )
        }
        $alerts = @(Get-ThresholdAlerts -Metrics $metrics)
        @($alerts | Where-Object { $_.Type -eq 'Memory'  -and $_.Level -eq 'Critical' }).Count | Should -Be 1
        @($alerts | Where-Object { $_.Type -eq 'Disk'    -and $_.Level -eq 'Critical' }).Count | Should -Be 1
        @($alerts | Where-Object { $_.Type -eq 'Disk'    -and $_.Message -match 'queue length' }).Count | Should -Be 1
    }

    It 'Returns an empty alerts array when everything is below thresholds' {
        $metrics = @{
            CPU         = @{ UsagePercent = 10 }
            Memory      = @{ UsagePercent = 10 }
            Disk        = @{ QueueLength = 0 }
            DiskVolumes = @(
                [PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 10 }
            )
        }
        @(Get-ThresholdAlerts -Metrics $metrics).Count | Should -Be 0
    }
}

Describe 'Get-SystemPerformance.ps1 - Get-TopProcesses' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Returns TopCPU and TopMemory hashtables sorted as expected' {
        Mock Get-Process {
            @(
                [PSCustomObject]@{ ProcessName = 'low';  Id = 1; CPU = 1;   WorkingSet64 = 100MB }
                [PSCustomObject]@{ ProcessName = 'mid';  Id = 2; CPU = 50;  WorkingSet64 = 500MB }
                [PSCustomObject]@{ ProcessName = 'high'; Id = 3; CPU = 100; WorkingSet64 = 1GB   }
            )
        }
        $result = Get-TopProcesses -Count 2
        $result.TopCPU.Count | Should -Be 2
        $result.TopCPU[0].Name | Should -Be 'high'
        $result.TopMemory[0].Name | Should -Be 'high'
        $result.TopMemory[0].WorkingSetMB | Should -BeGreaterOrEqual 1000
    }

    It 'Filters out PID 0 (system idle)' {
        Mock Get-Process {
            @(
                [PSCustomObject]@{ ProcessName = 'idle'; Id = 0; CPU = 10000; WorkingSet64 = 1024 }
                [PSCustomObject]@{ ProcessName = 'real'; Id = 5; CPU = 1;     WorkingSet64 = 1MB  }
            )
        }
        $result = Get-TopProcesses -Count 5
        ($result.TopCPU | Where-Object { $_.PID -eq 0 }).Count | Should -Be 0
    }

    It 'Returns empty arrays and warns when Get-Process throws' {
        Mock Get-Process { throw 'access denied' }
        $result = Get-TopProcesses -Count 10
        $result.TopCPU.Count | Should -Be 0
        Should -Invoke Write-WarningMessage
    }
}

Describe 'Get-SystemPerformance.ps1 - Get-SystemInfo' {
    It 'Aggregates Win32_OperatingSystem / Win32_ComputerSystem / Win32_Processor into a flat hashtable' {
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem'  { [PSCustomObject]@{ Caption = 'Windows 11 Pro'; Version = '10.0'; BuildNumber = '22000'; LastBootUpTime = (Get-Date).AddDays(-5) } }
                'Win32_ComputerSystem'   { [PSCustomObject]@{ Manufacturer = 'Dell'; Model = 'XPS 15' } }
                'Win32_Processor'        { [PSCustomObject]@{ Name = 'Intel i9'; NumberOfCores = 8; NumberOfLogicalProcessors = 16 } }
            }
        }
        $info = Get-SystemInfo
        $info.OSName | Should -Be 'Windows 11 Pro'
        $info.Manufacturer | Should -Be 'Dell'
        $info.ProcessorName | Should -Be 'Intel i9'
        $info.LogicalCPUs | Should -Be 16
        $info.Uptime.TotalDays | Should -BeGreaterOrEqual 4
    }
}

Describe 'Get-SystemPerformance.ps1 - Get-LargestFiles' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Returns only files larger than 100MB, sorted descending by Length' {
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ FullName = 'C:\big.bin';   Length = 200MB; Extension = '.bin'; LastWriteTime = (Get-Date).AddDays(-10) }
                [PSCustomObject]@{ FullName = 'C:\small.txt'; Length = 1KB;   Extension = '.txt'; LastWriteTime = (Get-Date).AddDays(-1)  }
                [PSCustomObject]@{ FullName = 'C:\huge.iso';  Length = 5GB;   Extension = '.iso'; LastWriteTime = (Get-Date).AddDays(-30) }
            )
        }
        $result = @(Get-LargestFiles -DriveLetter 'C' -Count 10)
        $result.Count | Should -Be 2
        $result[0].Path | Should -Be 'C:\huge.iso'
        $result[1].Path | Should -Be 'C:\big.bin'
    }
}

Describe 'Get-SystemPerformance.ps1 - Get-CleanupSuggestions' {
    BeforeEach {
        Mock Write-InfoMessage { }
        # Block ALL real Get-ChildItem calls; supply the size via Measure-Object below.
    }

    It 'Adds a "Temp Files" suggestion when the Windows temp folder exceeds the 10MB minimum' {
        # Make every Test-Path return true so the Temp / Update / browser branches all evaluate
        # their size; we only care about the Temp Files outcome.
        Mock Test-Path { $true }
        Mock Get-ChildItem { @([PSCustomObject]@{ Length = 50MB }) }
        Mock Measure-Object { [PSCustomObject]@{ Sum = 50MB } }
        $suggestions = @(Get-CleanupSuggestions -DriveLetter $env:SystemDrive[0])
        ($suggestions | Where-Object { $_.Category -eq 'Temp Files' }).Count | Should -BeGreaterOrEqual 1
    }

    It 'Skips the Windows Update cache when the directory does not exist' {
        Mock Test-Path { $false }
        Mock Get-ChildItem { @() }
        Mock Measure-Object { [PSCustomObject]@{ Sum = 0 } }
        $suggestions = @(Get-CleanupSuggestions -DriveLetter $env:SystemDrive[0])
        ($suggestions | Where-Object { $_.Category -eq 'Windows Update Cache' }).Count | Should -Be 0
    }
}

Describe 'Get-SystemPerformance.ps1 - Invoke-DiskAutoCleanup (destructive helper)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        # Block destructive operations on the host.
        Mock Remove-Item { }
        Mock Clear-RecycleBin { }
    }

    It 'Calls Remove-Item on each AutoCleanable=$true suggestion and returns the cumulative MB cleaned' {
        $suggestions = @(
            [PSCustomObject]@{ Category = 'Temp Files'; Path = 'C:\windows\Temp'; SizeMB = 50;  AutoCleanable = $true  }
            [PSCustomObject]@{ Category = 'Cache';      Path = 'C:\cache';       SizeMB = 100; AutoCleanable = $true  }
            [PSCustomObject]@{ Category = 'Logs';       Path = 'C:\logs';        SizeMB = 200; AutoCleanable = $false }
        )
        $result = Invoke-DiskAutoCleanup -Suggestions $suggestions
        $result | Should -Be 150
        Should -Invoke Remove-Item -Times 2
    }

    It 'Routes the Recycle Bin category through Clear-RecycleBin instead of Remove-Item' {
        $suggestions = @(
            [PSCustomObject]@{ Category = 'Recycle Bin'; Path = 'Recycle Bin'; SizeMB = 500; AutoCleanable = $true }
        )
        $result = Invoke-DiskAutoCleanup -Suggestions $suggestions
        $result | Should -Be 500
        Should -Invoke Clear-RecycleBin -Times 1
        Should -Invoke Remove-Item -Times 0
    }

    It 'Skips every entry when none are AutoCleanable' {
        $suggestions = @(
            [PSCustomObject]@{ Category = 'Logs'; Path = 'C:\logs'; SizeMB = 100; AutoCleanable = $false }
        )
        $result = Invoke-DiskAutoCleanup -Suggestions $suggestions
        $result | Should -Be 0
        Should -Invoke Remove-Item -Times 0
        Should -Invoke Clear-RecycleBin -Times 0
    }
}

Describe 'Get-SystemPerformance.ps1 - Get-DiskAnalysis (dispatcher)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
        Mock Get-LargestFiles { @() }
        Mock Get-LargestFolders { @() }
        Mock Get-CleanupSuggestions { @() }
        Mock Invoke-DiskAutoCleanup { 0 }
    }

    It 'Only analyzes drives whose UsagePercent meets the Warning threshold' {
        $volumes = @(
            [PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 10 }   # below threshold -> skip
            [PSCustomObject]@{ DriveLetter = 'D:'; UsagePercent = 85 }   # at warning -> analyze
        )
        $result = Get-DiskAnalysis -DiskVolumes $volumes
        $result.LargestFiles.Keys | Should -Contain 'D'
        $result.LargestFiles.Keys | Should -Not -Contain 'C'
    }

    It 'Triggers Invoke-DiskAutoCleanup only when -EnableAutoCleanup is set AND disk is Critical' {
        Mock Get-CleanupSuggestions { @([PSCustomObject]@{ Category = 'Temp'; SizeMB = 100; AutoCleanable = $true; Path = 'C:\t' }) }
        Mock Invoke-DiskAutoCleanup { 100 } -Verifiable
        $volumes = @([PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 96 })
        $result = Get-DiskAnalysis -DiskVolumes $volumes -EnableAutoCleanup
        Should -InvokeVerifiable
        $result.CleanedMB | Should -Be 100
    }

    It 'Does NOT trigger Invoke-DiskAutoCleanup at Warning level even with -EnableAutoCleanup' {
        $volumes = @([PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 85 })
        Get-DiskAnalysis -DiskVolumes $volumes -EnableAutoCleanup | Out-Null
        Should -Invoke Invoke-DiskAutoCleanup -Times 0
    }
}

Describe 'Get-SystemPerformance.ps1 - Export-JSONReport' {
    It 'Writes a JSON file containing Timestamp / SystemInfo / Metrics' {
        Mock Write-Success { }
        $outDir = Join-Path $TestDrive 'gsp-json'
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $metrics = @{ CPU = @{ UsagePercent = 50 }; Memory = @{}; Disk = @{}; Network = @{}; DiskVolumes = @(); Alerts = @() }
        $sysInfo = @{ ComputerName = 'TEST' }
        $result = Export-JSONReport -Metrics $metrics -SystemInfo $sysInfo -Processes $null -Path $outDir
        [System.IO.File]::Exists($result) | Should -BeTrue
        $payload = [System.IO.File]::ReadAllText($result) | ConvertFrom-Json
        $payload.SystemInfo.ComputerName | Should -Be 'TEST'
        $payload.Metrics.CPU.UsagePercent | Should -Be 50
    }
}

Describe 'Get-SystemPerformance.ps1 - Export-CSVReport' {
    It 'Writes a CSV file with Timestamp / CPU columns' {
        Mock Write-Success { }
        $outDir = Join-Path $TestDrive 'gsp-csv'
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $metrics = @{
            CPU         = @{ UsagePercent = 42 }
            Memory      = @{ UsagePercent = 30; AvailableMB = 8000; TotalMB = 16000 }
            Disk        = @{ QueueLength = 0; ReadBytesPerSec = 0; WriteBytesPerSec = 0 }
            Network     = @{ TotalBytesPerSec = 0; TotalErrors = 0 }
            DiskVolumes = @()
            Alerts      = @()
        }
        $sysInfo = @{ ComputerName = 'TEST' }
        $result = Export-CSVReport -Metrics $metrics -SystemInfo $sysInfo -Path $outDir
        [System.IO.File]::Exists($result) | Should -BeTrue
        $content = [System.IO.File]::ReadAllText($result)
        $content | Should -Match 'CPU'
        $content | Should -Match '42'
    }
}

Describe 'Get-SystemPerformance.ps1 - Invoke-SystemPerformance (top level)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Get-SystemInfo { @{ ComputerName = 'TEST'; OSName = 'Win11' } }
        Mock Get-PerformanceMetrics {
            @{
                CPU         = @{ UsagePercent = 10 }
                Memory      = @{ UsagePercent = 20 }
                Disk        = @{ QueueLength = 0 }
                Network     = @{}
                DiskVolumes = @()
                Alerts      = @()
            }
        }
        Mock Write-ConsoleReport { }
    }

    It 'Returns 0 on the happy path with no alerts' {
        Invoke-SystemPerformance -OutputFormat 'Console' -SampleCount 1 -SampleInterval 1 | Should -Be 0
    }

    It 'Returns 1 when the metric collector throws' {
        Mock Get-PerformanceMetrics { throw 'Get-Counter failed' }
        Invoke-SystemPerformance -OutputFormat 'Console' -SampleCount 1 -SampleInterval 1 | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Fatal error' }
    }

    It 'In -AlertOnly mode with no alerts, logs success and skips report output' {
        Invoke-SystemPerformance -OutputFormat 'Console' -AlertOnly -SampleCount 1 -SampleInterval 1 | Out-Null
        Should -Invoke Write-Success -ParameterFilter { $Message -match 'No alerts' }
        Should -Invoke Write-ConsoleReport -Times 0
    }

    It "Wires up Get-DiskAnalysis when -IncludeDiskAnalysis is set (Sprint 5.1 bug-fix)" {
        Mock Get-PerformanceMetrics {
            @{
                CPU         = @{ UsagePercent = 10 }
                Memory      = @{ UsagePercent = 20 }
                Disk        = @{ QueueLength = 0 }
                Network     = @{}
                DiskVolumes = @([PSCustomObject]@{ DriveLetter = 'C:'; UsagePercent = 50 })
                Alerts      = @()
            }
        }
        Mock Get-DiskAnalysis { @{ LargestFiles = @{}; LargestFolders = @{}; CleanupSuggestions = @{}; CleanedMB = 0 } } -Verifiable
        Invoke-SystemPerformance -OutputFormat 'Console' -IncludeDiskAnalysis -SampleCount 1 -SampleInterval 1 | Out-Null
        Should -InvokeVerifiable
    }
}
