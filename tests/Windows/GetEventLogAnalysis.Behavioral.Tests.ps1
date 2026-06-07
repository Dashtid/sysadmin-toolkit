# Behavioral Pester tests for Get-EventLogAnalysis.ps1
# Run: Invoke-Pester -Path .\tests\Windows\GetEventLogAnalysis.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-EventLogAnalysis on
# dot-source). Helper functions are exercised through Pester Mocks of Get-WinEvent
# and the analysis functions themselves.

BeforeAll {
    Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\monitoring\Get-EventLogAnalysis.ps1'
    . $ScriptPath
}

Describe 'Get-EventLogAnalysis.ps1 - Get-FilteredEvents' {
    It 'Maps Get-WinEvent objects into TimeCreated/Source/EventId/Level fields' {
        Mock Get-WinEvent {
            @([PSCustomObject]@{
                Level             = 2
                Id                = 1000
                ProviderName      = 'AppHost'
                TimeCreated       = (Get-Date)
                Message           = 'boom'
                LogName           = 'Application'
                MachineName       = 'TEST'
                UserId            = $null
                ProcessId         = 42
                ThreadId          = 7
                Keywords          = 0
                TaskDisplayName   = 'General'
            })
        }
        $events = @(Get-FilteredEvents -LogName 'Application' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @(1, 2))
        $events.Count | Should -Be 1
        $events[0].EventId | Should -Be 1000
        $events[0].Level | Should -Be 'Error'
        $events[0].Source | Should -Be 'AppHost'
    }

    It "Maps Level 1->'Critical', 3->'Warning', 4->'Information', unknown->'Unknown'" {
        Mock Get-WinEvent {
            @(
                [PSCustomObject]@{ Level = 1; Id = 1; ProviderName = 'A'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
                [PSCustomObject]@{ Level = 3; Id = 2; ProviderName = 'A'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
                [PSCustomObject]@{ Level = 4; Id = 3; ProviderName = 'A'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
                [PSCustomObject]@{ Level = 99; Id = 4; ProviderName = 'A'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
            )
        }
        $events = Get-FilteredEvents -LogName 'Application' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @()
        $events[0].Level | Should -Be 'Critical'
        $events[1].Level | Should -Be 'Warning'
        $events[2].Level | Should -Be 'Information'
        $events[3].Level | Should -Be 'Unknown'
    }

    It 'Applies SourceFilter wildcard and skips non-matching events' {
        Mock Get-WinEvent {
            @(
                [PSCustomObject]@{ Level = 2; Id = 1; ProviderName = 'MSSQLSERVER'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
                [PSCustomObject]@{ Level = 2; Id = 2; ProviderName = 'Outlook'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
            )
        }
        $events = @(Get-FilteredEvents -LogName 'Application' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @() -SourceFilter '*SQL*')
        $events.Count | Should -Be 1
        $events[0].Source | Should -Be 'MSSQLSERVER'
    }

    It 'Applies ExcludeSources and drops matching events' {
        Mock Get-WinEvent {
            @(
                [PSCustomObject]@{ Level = 2; Id = 1; ProviderName = 'NoisySvc'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
                [PSCustomObject]@{ Level = 2; Id = 2; ProviderName = 'RealError'; TimeCreated = (Get-Date); Message = ''; LogName = 'Application'; MachineName = ''; UserId = $null; ProcessId = 0; ThreadId = 0; Keywords = 0; TaskDisplayName = '' }
            )
        }
        $events = @(Get-FilteredEvents -LogName 'Application' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @() -ExcludeSources @('NoisySvc'))
        $events.Count | Should -Be 1
        $events[0].Source | Should -Be 'RealError'
    }

    It "Returns empty collection and writes a warning when Get-WinEvent throws 'Access is denied'" {
        Mock Get-WinEvent { throw 'Access is denied' }
        Mock Write-WarningMessage { }
        $events = Get-FilteredEvents -LogName 'Security' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @()
        $events.Count | Should -Be 0
        Should -Invoke Write-WarningMessage -Times 1 -ParameterFilter { $Message -match 'administrator privileges' }
    }

    It 'Passes EventIds into the Get-WinEvent filter hashtable when supplied' {
        Mock Get-WinEvent { @() }
        $null = Get-FilteredEvents -LogName 'System' -StartTime (Get-Date).AddHours(-1) -MaxEvents 100 -LevelValues @(2) -EventIds @(7034, 6008)
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter {
            $FilterHashtable.Id -contains 7034 -and $FilterHashtable.Id -contains 6008 -and $FilterHashtable.Level -contains 2
        }
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Get-SecurityAnalysis' {
    It 'Buckets a 4625 event into FailedLogons and a 4624 into SuccessfulLogons' {
        $events = @(
            @{ LogName = 'Security'; EventId = 4625; Message = 'Account Name: alice' }
            @{ LogName = 'Security'; EventId = 4624; Message = 'Account Name: bob' }
        )
        $analysis = Get-SecurityAnalysis -Events $events
        $analysis.FailedLogons.Count | Should -Be 1
        $analysis.SuccessfulLogons.Count | Should -Be 1
    }

    It 'Buckets 4672 into PrivilegeEscalation and 4720 into AccountChanges' {
        $events = @(
            @{ LogName = 'Security'; EventId = 4672; Message = '' }
            @{ LogName = 'Security'; EventId = 4720; Message = '' }
        )
        $analysis = Get-SecurityAnalysis -Events $events
        $analysis.PrivilegeEscalation.Count | Should -Be 1
        $analysis.AccountChanges.Count | Should -Be 1
    }

    It 'Detects brute-force pattern when same account has >=5 failed logons' {
        # All six events have identical 'Account Name: attacker' so the Group-Object
        # scriptblock relying on $matches[1] always resolves to the same key.
        $events = 1..6 | ForEach-Object {
            @{ LogName = 'Security'; EventId = 4625; Message = 'Account Name: attacker' }
        }
        $analysis = Get-SecurityAnalysis -Events $events
        @($analysis.SuspiciousActivity | Where-Object { $_.Type -eq 'BruteForce' }).Count | Should -Be 1
    }

    It 'Buckets 1102 into LogCleared' {
        $events = @(@{ LogName = 'Security'; EventId = 1102; Message = '' })
        $analysis = Get-SecurityAnalysis -Events $events
        $analysis.LogCleared.Count | Should -Be 1
    }

    It 'Ignores non-Security log events entirely' {
        $events = @(
            @{ LogName = 'System'; EventId = 4625; Message = '' }
            @{ LogName = 'Application'; EventId = 4720; Message = '' }
        )
        $analysis = Get-SecurityAnalysis -Events $events
        $analysis.FailedLogons.Count | Should -Be 0
        $analysis.AccountChanges.Count | Should -Be 0
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Get-FailedLogonDetails' {
    It 'Extracts TargetAccount, SourceIP, and LogonType from a 4625 message' {
        $msg = "Account Name: alice`nAccount Domain: CORP`nLogon Type: 10`nSource Network Address: 10.0.0.5`n"
        $events = @(@{ EventId = 4625; TimeCreated = (Get-Date); Message = $msg })
        $details = @(Get-FailedLogonDetails -Events $events)
        $details[0].TargetAccount | Should -Be 'alice'
        $details[0].SourceIP | Should -Be '10.0.0.5'
        $details[0].LogonType | Should -Be 'RemoteInteractive (RDP)'
        $details[0].TargetDomain | Should -Be 'CORP'
    }

    It 'Returns empty when no 4625 events are present' {
        $events = @(@{ EventId = 4624; TimeCreated = (Get-Date); Message = 'whatever' })
        $details = Get-FailedLogonDetails -Events $events
        $details.Count | Should -Be 0
    }

    It "Maps numeric LogonType 2 to 'Interactive' and unknown numbers pass through" {
        $events = @(
            @{ EventId = 4625; TimeCreated = (Get-Date); Message = "Account Name: a`nLogon Type: 2`n" }
            @{ EventId = 4625; TimeCreated = (Get-Date); Message = "Account Name: b`nLogon Type: 99`n" }
        )
        $details = @(Get-FailedLogonDetails -Events $events)
        $details[0].LogonType | Should -Be 'Interactive'
        $details[1].LogonType | Should -Be '99'
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Get-SystemIssues' {
    It 'Buckets 7034 into ServiceFailures and 6008 into UnexpectedShutdowns' {
        $events = @(
            @{ LogName = 'System'; EventId = 7034 }
            @{ LogName = 'System'; EventId = 6008 }
        )
        $issues = Get-SystemIssues -Events $events
        $issues.ServiceFailures.Count | Should -Be 1
        $issues.UnexpectedShutdowns.Count | Should -Be 1
    }

    It 'Buckets DiskError (id 7) and KernelPowerError (id 41) correctly' {
        $events = @(
            @{ LogName = 'System'; EventId = 7 }
            @{ LogName = 'System'; EventId = 41 }
        )
        $issues = Get-SystemIssues -Events $events
        $issues.DiskErrors.Count | Should -Be 1
        $issues.KernelErrors.Count | Should -Be 1
    }

    It "Ignores events whose LogName is not 'System'" {
        $events = @(
            @{ LogName = 'Application'; EventId = 7034 }
            @{ LogName = 'Application'; EventId = 6008 }
        )
        $issues = Get-SystemIssues -Events $events
        $issues.ServiceFailures.Count | Should -Be 0
        $issues.UnexpectedShutdowns.Count | Should -Be 0
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Get-ApplicationIssues' {
    It 'Buckets 1000 into Crashes and 1026 into DotNetErrors' {
        $events = @(
            @{ LogName = 'Application'; EventId = 1000 }
            @{ LogName = 'Application'; EventId = 1026 }
        )
        $issues = Get-ApplicationIssues -Events $events
        $issues.Crashes.Count | Should -Be 1
        $issues.DotNetErrors.Count | Should -Be 1
    }

    It 'Buckets SideBySide event ID 33 correctly' {
        $events = @(@{ LogName = 'Application'; EventId = 33 })
        $issues = Get-ApplicationIssues -Events $events
        $issues.SideBySide.Count | Should -Be 1
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Get-EventLogReport' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
    }

    It 'Aggregates Summary counters by Level across all logs' {
        Mock Get-FilteredEvents {
            @(
                @{ Level = 'Critical'; LogName = 'Application'; EventId = 1; Source = 'A'; TimeCreated = (Get-Date); Message = '' }
                @{ Level = 'Error'; LogName = 'Application'; EventId = 2; Source = 'A'; TimeCreated = (Get-Date); Message = '' }
                @{ Level = 'Warning'; LogName = 'Application'; EventId = 3; Source = 'A'; TimeCreated = (Get-Date); Message = '' }
            )
        }
        $report = Get-EventLogReport -Hours 24 -Level 'Warning' -LogNames @('Application') -MaxEvents 100 -IsAdmin $true
        $report.Summary.TotalEvents | Should -Be 3
        $report.Summary.Critical | Should -Be 1
        $report.Summary.Error | Should -Be 1
        $report.Summary.Warning | Should -Be 1
    }

    It 'Skips Security log and emits a warning when not admin and IncludeSecurityAnalysis is not set' {
        Mock Get-FilteredEvents { @() }
        $null = Get-EventLogReport -Hours 1 -Level 'Warning' -LogNames @('Security') -MaxEvents 100 -IsAdmin $false
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'Skipping Security log' }
        Should -Invoke Get-FilteredEvents -Times 0
    }

    It 'Adds a Critical alert when Summary.Critical > 0' {
        Mock Get-FilteredEvents {
            @(@{ Level = 'Critical'; LogName = 'Application'; EventId = 1; Source = 'A'; TimeCreated = (Get-Date); Message = '' })
        }
        $report = Get-EventLogReport -Hours 1 -Level 'Critical' -LogNames @('Application') -MaxEvents 100 -IsAdmin $true
        @($report.Alerts | Where-Object { $_.Type -eq 'CriticalEvents' }).Count | Should -Be 1
    }

    It 'Adds a Critical alert for UnexpectedShutdown when System events include 6008' {
        Mock Get-FilteredEvents {
            @(@{ Level = 'Error'; LogName = 'System'; EventId = 6008; Source = 'EventLog'; TimeCreated = (Get-Date); Message = '' })
        }
        $report = Get-EventLogReport -Hours 1 -Level 'Warning' -LogNames @('System') -MaxEvents 100 -IsAdmin $true
        @($report.Alerts | Where-Object { $_.Type -eq 'UnexpectedShutdown' }).Count | Should -Be 1
    }

    It 'Populates SecurityAnalysis when IncludeSecurityAnalysis is set and IsAdmin is true' {
        Mock Get-FilteredEvents {
            @(@{ Level = 'Information'; LogName = 'Security'; EventId = 4625; Source = 'Audit'; TimeCreated = (Get-Date); Message = 'Account Name: alice' })
        }
        $report = Get-EventLogReport -Hours 1 -Level 'Information' -LogNames @('Security') -MaxEvents 100 -IsAdmin $true -IncludeSecurityAnalysis $true
        $report.SecurityAnalysis | Should -Not -BeNullOrEmpty
        $report.SecurityAnalysis.FailedLogons.Count | Should -Be 1
    }
}

Describe 'Get-EventLogAnalysis.ps1 - Export-JSONReport / Export-CSVReport / Export-HTMLReport' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    It 'Export-JSONReport writes a JSON file with computer name and summary fields' {
        $report = @{
            Timestamp         = (Get-Date).ToString('o')
            ComputerName      = 'TEST'
            AnalysisPeriod    = @{ Hours = 1; StartTime = (Get-Date); EndTime = (Get-Date) }
            Summary           = @{ TotalEvents = 1; Critical = 0; Error = 0; Warning = 1; Information = 0 }
            EventsByLog       = @{ Application = 1 }
            TopEventIds       = @()
            TopSources        = @()
            EventsByHour      = @{}
            AllEvents         = @()
            Alerts            = @()
            SystemIssues      = @{ ServiceFailures = @(); UnexpectedShutdowns = @(); DiskErrors = @(); DriverIssues = @(); KernelErrors = @() }
            ApplicationIssues = @{ Crashes = @(); Hangs = @(); DotNetErrors = @(); SideBySide = @() }
            FailedLogons      = @()
        }
        $jsonPath = Export-JSONReport -Report $report -Path $script:Dir
        Test-Path $jsonPath | Should -Be $true
        (Get-Content $jsonPath -Raw | ConvertFrom-Json).ComputerName | Should -Be 'TEST'
    }

    It 'Export-CSVReport writes one CSV row per event in AllEvents' {
        $report = @{
            ComputerName = 'TEST'
            AllEvents    = @(
                @{ TimeCreated = (Get-Date); LogName = 'Application'; Source = 'AppHost'; EventId = 1000; Level = 'Error'; TaskCategory = 'General'; Message = 'boom' }
                @{ TimeCreated = (Get-Date); LogName = 'System'; Source = 'Service Control Manager'; EventId = 7034; Level = 'Error'; TaskCategory = 'None'; Message = 'svc crashed' }
            )
        }
        $csvPath = Export-CSVReport -Report $report -Path $script:Dir
        Test-Path $csvPath | Should -Be $true
        (Import-Csv $csvPath).Count | Should -Be 2
    }

    It 'Export-HTMLReport writes an HTML file mentioning the computer name and DOCTYPE' {
        $report = @{
            ComputerName   = 'TEST'
            AnalysisPeriod = @{ Hours = 1; StartTime = (Get-Date); EndTime = (Get-Date) }
            Summary        = @{ TotalEvents = 0; Critical = 0; Error = 0; Warning = 0; Information = 0 }
            Alerts         = @()
            TopEventIds    = @()
            AllEvents      = @()
        }
        $htmlPath = Export-HTMLReport -Report $report -Path $script:Dir
        Test-Path $htmlPath | Should -Be $true
        $content = Get-Content $htmlPath -Raw
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'TEST'
    }
}
