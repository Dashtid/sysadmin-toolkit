# Behavioral Pester tests for Watch-ServiceHealth.ps1
# Run: Invoke-Pester -Path .\tests\Windows\WatchServiceHealth.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-ServiceHealthCheck on
# dot-source). Helper functions (Get-ServiceStatus, Test-ServiceShouldMonitor,
# Restart-ServiceWithRetry, Get-ServiceHealthReport, Export-JSONReport,
# Export-HTMLReport) are exercised through Pester Mocks.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\monitoring\Watch-ServiceHealth.ps1'
    . $ScriptPath
}

Describe 'Watch-ServiceHealth.ps1 - Test-ServiceShouldMonitor' {
    It 'Returns false when the service is Not Found' {
        $info = @{ Found = $false; StartType = 'Automatic'; IsDelayedStart = $false; IsTriggerStart = $false }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $false
    }

    It 'Returns false when StartType is Manual' {
        $info = @{ Found = $true; StartType = 'Manual'; IsDelayedStart = $false; IsTriggerStart = $false }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $false
    }

    It 'Returns false when StartType is Disabled' {
        $info = @{ Found = $true; StartType = 'Disabled'; IsDelayedStart = $false; IsTriggerStart = $false }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $false
    }

    It 'Returns false when IsDelayedStart and -IncludeDelayedStart not set' {
        $IncludeDelayedStart = $false
        $info = @{ Found = $true; StartType = 'Automatic'; IsDelayedStart = $true; IsTriggerStart = $false }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $false
    }

    It 'Returns false when IsTriggerStart and -IncludeDelayedStart not set' {
        $IncludeDelayedStart = $false
        $info = @{ Found = $true; StartType = 'Automatic'; IsDelayedStart = $false; IsTriggerStart = $true }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $false
    }

    It 'Returns true for an Automatic service that is not delayed/trigger' {
        $info = @{ Found = $true; StartType = 'Automatic'; IsDelayedStart = $false; IsTriggerStart = $false }
        Test-ServiceShouldMonitor -ServiceInfo $info | Should -Be $true
    }
}

Describe 'Watch-ServiceHealth.ps1 - Get-ServiceStatus' {
    Context 'When the service exists' {
        BeforeEach {
            Mock Get-Service {
                [PSCustomObject]@{
                    Name                = 'TestSvc'
                    DisplayName         = 'Test Service'
                    Status              = 'Running'
                    StartType           = 'Automatic'
                    CanStop             = $true
                    CanPauseAndContinue = $false
                    DependentServices   = @()
                    ServicesDependedOn  = @()
                }
            }
            Mock Get-CimInstance {
                [PSCustomObject]@{ ProcessId = 1234; PathName = 'C:\foo.exe'; Description = 'test' }
            }
            Mock Test-Path { $false }   # No DelayedAutostart, no TriggerInfo
            Mock Get-ItemProperty { $null }
        }

        It 'Returns Found=true' {
            $result = Get-ServiceStatus -ServiceName 'TestSvc'
            $result.Found | Should -Be $true
        }

        It 'Surfaces Status and StartType' {
            $result = Get-ServiceStatus -ServiceName 'TestSvc'
            $result.Status | Should -Be 'Running'
            $result.StartType | Should -Be 'Automatic'
        }

        It 'Defaults IsDelayedStart and IsTriggerStart to false when registry is absent' {
            $result = Get-ServiceStatus -ServiceName 'TestSvc'
            $result.IsDelayedStart | Should -Be $false
            $result.IsTriggerStart | Should -Be $false
        }
    }

    Context 'When the service is not found' {
        BeforeEach {
            Mock Get-Service { throw 'Cannot find any service with service name' }
        }

        It 'Returns Found=false with the error message' {
            $result = Get-ServiceStatus -ServiceName 'MissingSvc'
            $result.Found | Should -Be $false
            $result.Status | Should -Be 'NotFound'
            $result.Error | Should -Match 'Cannot find'
        }
    }
}

Describe 'Watch-ServiceHealth.ps1 - Restart-ServiceWithRetry' {
    BeforeEach {
        # Always clear restart history between tests so counts don't leak across.
        $script:RestartHistory = @{}
        # Skip the real sleeps to keep tests fast.
        Mock Start-Sleep { }
    }

    Context 'When not running as Administrator' {
        BeforeEach {
            $script:IsAdmin = $false
            Mock Get-Service { throw 'should not be called' }
        }
        AfterEach {
            $script:IsAdmin = $true
        }

        It 'Returns Success=false without touching the service' {
            $result = Restart-ServiceWithRetry -ServiceName 'Spooler'
            $result.Success | Should -Be $false
            $result.Error | Should -Match 'Administrator'
        }
    }

    Context 'When the service starts cleanly on first attempt' {
        BeforeEach {
            $script:IsAdmin = $true
            $script:Calls = 0
            Mock Get-Service {
                $script:Calls++
                # First call: stopped. Subsequent: running (after Start-Service).
                [PSCustomObject]@{ Status = if ($script:Calls -eq 1) { 'Stopped' } else { 'Running' } }
            }
            Mock Stop-Service { }
            Mock Start-Service { }
        }

        It 'Returns Success=true with Attempts=1' {
            $result = Restart-ServiceWithRetry -ServiceName 'Spooler' -MaxAttempts 3 -InitialDelay 1
            $result.Success | Should -Be $true
            $result.Attempts | Should -Be 1
        }

        It 'Records the success in $script:RestartHistory' {
            $null = Restart-ServiceWithRetry -ServiceName 'Spooler' -MaxAttempts 3 -InitialDelay 1
            $script:RestartHistory['Spooler'] | Should -Not -BeNullOrEmpty
            $script:RestartHistory['Spooler'][0].Success | Should -Be $true
        }
    }

    Context 'When Start-Service throws on every attempt' {
        BeforeEach {
            $script:IsAdmin = $true
            Mock Get-Service { [PSCustomObject]@{ Status = 'Stopped' } }
            Mock Stop-Service { }
            Mock Start-Service { throw 'simulated startup failure' }
        }

        It 'Returns Success=false after MaxAttempts attempts' {
            $result = Restart-ServiceWithRetry -ServiceName 'Spooler' -MaxAttempts 3 -InitialDelay 1
            $result.Success | Should -Be $false
            $result.Attempts | Should -Be 3
        }

        It 'Records the failure with Attempts=MaxAttempts in $script:RestartHistory' {
            $null = Restart-ServiceWithRetry -ServiceName 'Spooler' -MaxAttempts 3 -InitialDelay 1
            $script:RestartHistory['Spooler'][0].Success | Should -Be $false
            $script:RestartHistory['Spooler'][0].Attempts | Should -Be 3
        }
    }
}

Describe 'Watch-ServiceHealth.ps1 - Get-ServiceHealthReport' {
    BeforeEach {
        $script:PreviousState = @{}
        $script:RestartHistory = @{}
    }

    Context 'With a running and a stopped service' {
        BeforeEach {
            $script:CallNum = 0
            Mock Get-ServiceStatus {
                $script:CallNum++
                if ($script:CallNum -eq 1) {
                    @{ Found = $true; Name = 'Spooler'; DisplayName = 'Print Spooler';
                       Status = 'Running'; StartType = 'Automatic'; IsDelayedStart = $false;
                       IsTriggerStart = $false; ProcessId = 100; ServicesDependedOn = '' }
                } else {
                    @{ Found = $true; Name = 'BITS'; DisplayName = 'BITS';
                       Status = 'Stopped'; StartType = 'Automatic'; IsDelayedStart = $false;
                       IsTriggerStart = $false; ProcessId = $null; ServicesDependedOn = '' }
                }
            }
        }

        It 'Counts RunningServices=1 and StoppedServices=1' {
            $report = Get-ServiceHealthReport -ServiceList @('Spooler', 'BITS') -AutoRestartOnStopped $false
            $report.RunningServices | Should -Be 1
            $report.StoppedServices | Should -Be 1
        }

        It 'Generates a Critical alert for the stopped service' {
            $report = Get-ServiceHealthReport -ServiceList @('Spooler', 'BITS') -AutoRestartOnStopped $false
            ($report.Alerts | Where-Object { $_.Level -eq 'Critical' }).Count | Should -BeGreaterOrEqual 1
        }

        It 'Records both services in PreviousState for next cycle' {
            $null = Get-ServiceHealthReport -ServiceList @('Spooler', 'BITS') -AutoRestartOnStopped $false
            $script:PreviousState['Spooler'] | Should -Be 'Running'
            $script:PreviousState['BITS'] | Should -Be 'Stopped'
        }
    }

    Context 'When a service is missing entirely' {
        BeforeEach {
            $script:CallNum = 0
            Mock Get-ServiceStatus {
                $script:CallNum++
                @{ Found = $false; Name = "Missing$script:CallNum"; Status = 'NotFound'; Error = 'not found' }
            }
        }

        It 'Increments NotFoundServices' {
            $report = Get-ServiceHealthReport -ServiceList @('Foo', 'Bar') -AutoRestartOnStopped $false
            $report.NotFoundServices | Should -Be 2
        }

        It 'Marks the missing entry as Monitored=false' {
            $report = Get-ServiceHealthReport -ServiceList @('Foo', 'Bar') -AutoRestartOnStopped $false
            ($report.Services | Where-Object { -not $_.Monitored }).Count | Should -Be 2
        }
    }

    Context 'When the previous state differs from current state' {
        BeforeEach {
            $script:PreviousState = @{ Spooler = 'Stopped' }
            Mock Get-ServiceStatus {
                @{ Found = $true; Name = 'Spooler'; DisplayName = 'Print Spooler';
                   Status = 'Running'; StartType = 'Automatic'; IsDelayedStart = $false;
                   IsTriggerStart = $false; ProcessId = 100; ServicesDependedOn = '' }
            }
        }

        It 'Generates a StateChange alert' {
            $report = Get-ServiceHealthReport -ServiceList @('Spooler') -AutoRestartOnStopped $false
            ($report.Alerts | Where-Object { $_.Type -eq 'StateChange' }).Count | Should -BeGreaterOrEqual 1
        }
    }
}

Describe 'Watch-ServiceHealth.ps1 - Export-JSONReport' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    It 'Writes a JSON file containing the report fields' {
        $report = @{
            Timestamp       = '2026-06-05'
            ComputerName    = 'TEST'
            TotalServices   = 3
            RunningServices = 2
            StoppedServices = 1
            Services        = @()
            Alerts          = @()
        }
        $jsonPath = Export-JSONReport -Report $report -Path $script:Dir
        Test-Path $jsonPath | Should -Be $true
        $written = Get-Content $jsonPath -Raw | ConvertFrom-Json
        $written.ComputerName | Should -Be 'TEST'
        $written.RunningServices | Should -Be 2
    }
}

Describe 'Watch-ServiceHealth.ps1 - Export-HTMLReport' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    It 'Writes an HTML file that mentions the computer name and counts' {
        $report = @{
            ComputerName    = 'TEST'
            TotalServices   = 2
            RunningServices = 1
            StoppedServices = 1
            Services        = @()
            Alerts          = @()
        }
        $htmlPath = Export-HTMLReport -Report $report -Path $script:Dir
        Test-Path $htmlPath | Should -Be $true
        $content = Get-Content $htmlPath -Raw
        $content | Should -Match 'TEST'
        $content | Should -Match '<!DOCTYPE html>'
    }
}
