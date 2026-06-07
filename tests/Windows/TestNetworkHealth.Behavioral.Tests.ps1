# Behavioral Pester tests for Test-NetworkHealth.ps1
# Run: Invoke-Pester -Path .\tests\Windows\TestNetworkHealth.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-NetworkHealthCheck on
# dot-source). All "external" calls (Test-Connection, Test-NetConnection,
# Resolve-DnsName, Get-NetworkConfiguration, etc.) are built-in PowerShell
# cmdlets or in-script helpers that Pester Mock can intercept directly.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\monitoring\Test-NetworkHealth.ps1'
    . $ScriptPath
}

Describe 'Test-NetworkHealth.ps1 - Test-HostConnectivity' {
    It 'Returns Success=true with timing stats when ping succeeds' {
        Mock Test-Connection {
            @(
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 10; Address = '8.8.8.8' }
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 20; Address = '8.8.8.8' }
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 30; Address = '8.8.8.8' }
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 40; Address = '8.8.8.8' }
            )
        }
        $r = Test-HostConnectivity -HostName '8.8.8.8' -Count 4
        $r.Success | Should -Be $true
        $r.MinTime | Should -Be 10
        $r.MaxTime | Should -Be 40
        $r.AvgTime | Should -Be 25
        $r.PacketLoss | Should -Be 0
        $r.IPAddress | Should -Be '8.8.8.8'
    }

    It 'Returns Success=false with Error when Test-Connection throws' {
        Mock Test-Connection { throw 'No such host is known' }
        $r = Test-HostConnectivity -HostName 'nonexistent.invalid'
        $r.Success | Should -Be $false
        $r.Error | Should -Match 'No such host'
        $r.PacketLoss | Should -Be 100
    }

    It 'Calculates packet loss when some pings fail' {
        Mock Test-Connection {
            @(
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 10; Address = '1.2.3.4' }
                [PSCustomObject]@{ StatusCode = 0; ResponseTime = 10; Address = '1.2.3.4' }
                [PSCustomObject]@{ StatusCode = 11010; ResponseTime = 0; Address = $null }
                [PSCustomObject]@{ StatusCode = 11010; ResponseTime = 0; Address = $null }
            )
        }
        $r = Test-HostConnectivity -HostName 'flaky.example' -Count 4
        $r.Success | Should -Be $true
        $r.PacketLoss | Should -Be 50
    }

    It 'Uses Latency property when ResponseTime is not present (PowerShell 7 shape)' {
        Mock Test-Connection {
            @(
                [PSCustomObject]@{ Status = 'Success'; Latency = 15; Address = '1.1.1.1' }
            )
        }
        $r = Test-HostConnectivity -HostName '1.1.1.1' -Count 1
        $r.Success | Should -Be $true
        $r.AvgTime | Should -Be 15
    }
}

Describe 'Test-NetworkHealth.ps1 - Test-PortConnectivity' {
    It 'Returns Success=true and looks up ServiceName from CommonPorts when port is reachable' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
        $r = Test-PortConnectivity -HostName 'github.com' -Port 443
        $r.Success | Should -Be $true
        $r.ServiceName | Should -Be 'HTTPS'
        $r.ResponseMs | Should -Not -BeNullOrEmpty
    }

    It "Returns Success=false with 'not reachable' error when TcpTestSucceeded is false" {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $r = Test-PortConnectivity -HostName 'github.com' -Port 22
        $r.Success | Should -Be $false
        $r.Error | Should -Match 'not reachable'
        $r.ServiceName | Should -Be 'SSH'
    }

    It "Reports ServiceName='Unknown' for ports not in CommonPorts table" {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
        $r = Test-PortConnectivity -HostName 'host' -Port 9999
        $r.ServiceName | Should -Be 'Unknown'
    }
}

Describe 'Test-NetworkHealth.ps1 - Test-DNSResolution' {
    It 'Returns Success=true with IPAddresses populated for an A record' {
        Mock Resolve-DnsName { @([PSCustomObject]@{ Type = 'A'; IPAddress = '142.250.190.78' }) }
        $r = Test-DNSResolution -Domain 'google.com'
        $r.Success | Should -Be $true
        $r.IPAddresses | Should -Contain '142.250.190.78'
        $r.DNSServer | Should -Be 'System Default'
    }

    It 'Includes both A and AAAA addresses in result' {
        Mock Resolve-DnsName {
            @(
                [PSCustomObject]@{ Type = 'A'; IPAddress = '1.2.3.4' }
                [PSCustomObject]@{ Type = 'AAAA'; IPAddress = '::1' }
            )
        }
        $r = Test-DNSResolution -Domain 'example.com'
        $r.IPAddresses.Count | Should -Be 2
        $r.IPAddresses | Should -Contain '1.2.3.4'
        $r.IPAddresses | Should -Contain '::1'
    }

    It 'Records the supplied DNSServer when one is passed' {
        Mock Resolve-DnsName { @([PSCustomObject]@{ Type = 'A'; IPAddress = '8.8.4.4' }) }
        $r = Test-DNSResolution -Domain 'dns.google' -DNSServer '8.8.8.8'
        $r.DNSServer | Should -Be '8.8.8.8'
        $r.Success | Should -Be $true
    }

    It 'Returns Success=false with Error when Resolve-DnsName throws' {
        Mock Resolve-DnsName { throw 'DNS name does not exist' }
        $r = Test-DNSResolution -Domain 'no-such-domain.invalid'
        $r.Success | Should -Be $false
        $r.Error | Should -Match 'DNS name does not exist'
    }
}

Describe 'Test-NetworkHealth.ps1 - Invoke-Traceroute' {
    It 'Returns Success=true and a hop list when Test-NetConnection returns TraceRoute and PingSucceeded' {
        Mock Test-NetConnection {
            [PSCustomObject]@{
                PingSucceeded = $true
                TraceRoute    = @('10.0.0.1', '10.0.0.2', '8.8.8.8')
            }
        }
        Mock Resolve-DnsName { $null }
        Mock Write-InfoMessage { }
        $r = Invoke-Traceroute -Target '8.8.8.8'
        $r.Success | Should -Be $true
        $r.TotalHops | Should -Be 3
        $r.Hops[0].Address | Should -Be '10.0.0.1'
    }

    It 'Returns Success=false with Error when Test-NetConnection throws' {
        Mock Test-NetConnection { throw 'destination unreachable' }
        Mock Write-InfoMessage { }
        $r = Invoke-Traceroute -Target 'unreachable.invalid'
        $r.Success | Should -Be $false
        $r.Error | Should -Match 'destination unreachable'
        $r.TotalHops | Should -Be 0
    }
}

Describe 'Test-NetworkHealth.ps1 - Get-NetworkHealthReport' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Get-NetworkConfiguration { @{ Hostname = 'TEST'; ProxyEnabled = $false; ProxyServer = $null } }
        Mock Get-NetworkAdapterInfo { @() }
    }

    It 'Counts PassedTests for successful ping/port/DNS and produces NoAdapter alert when no adapters' {
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $true; AvgTime = 5; PacketLoss = 0; IPAddress = '1.2.3.4'; Error = $null } }
        Mock Test-PortConnectivity { @{ Host = $HostName; Port = $Port; ServiceName = 'HTTPS'; Success = $true; ResponseMs = 10; Error = $null } }
        Mock Test-DNSResolution { @{ Domain = $Domain; Success = $true; IPAddresses = @('1.2.3.4'); ResponseMs = 5; DNSServer = 'Default'; Error = $null } }
        Mock Invoke-Traceroute { @{ Target = $Target; Success = $true; Hops = @(); TotalHops = 0 } }

        $r = Get-NetworkHealthReport -HostList @('a', 'b') -PortList @(443) -DomainList @('x.com') -TraceTargets @('8.8.8.8') -DoSkipPortScan $false -DoSkipDNS $false -DoSkipTraceroute $false -DoQuickTest $false

        # 2 ping + 2 port (a,b x 443) + 1 dns = 5 passed
        $r.Summary.PassedTests | Should -Be 5
        $r.Summary.FailedTests | Should -Be 0
        @($r.Alerts | Where-Object { $_.Type -eq 'NoAdapter' }).Count | Should -Be 1
    }

    It 'Generates HighLatency warning when AvgTime > 200ms' {
        Mock Get-NetworkAdapterInfo { @(@{ Name = 'Eth0' }) }
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $true; AvgTime = 350; PacketLoss = 0; IPAddress = '1.2.3.4' } }

        $r = Get-NetworkHealthReport -HostList @('slow.example') -PortList @() -DomainList @() -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        @($r.Alerts | Where-Object { $_.Type -eq 'HighLatency' }).Count | Should -Be 1
        $r.Summary.Warnings | Should -BeGreaterOrEqual 1
    }

    It 'Generates PacketLoss warning when PacketLoss > 0' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $true; AvgTime = 10; PacketLoss = 25; IPAddress = '1.2.3.4' } }

        $r = Get-NetworkHealthReport -HostList @('flaky') -PortList @() -DomainList @() -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        @($r.Alerts | Where-Object { $_.Type -eq 'PacketLoss' }).Count | Should -Be 1
    }

    It 'Generates ConnectivityFailed critical alert when ping fails' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $false; Error = 'timeout' } }

        $r = Get-NetworkHealthReport -HostList @('dead.host') -PortList @() -DomainList @() -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        $r.Summary.FailedTests | Should -Be 1
        @($r.Alerts | Where-Object { $_.Type -eq 'ConnectivityFailed' -and $_.Level -eq 'Critical' }).Count | Should -Be 1
    }

    It 'Skips port scan tests when DoSkipPortScan is true' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $true; AvgTime = 5; PacketLoss = 0 } }
        Mock Test-PortConnectivity { throw 'should not be called' }

        $r = Get-NetworkHealthReport -HostList @('a') -PortList @(443) -DomainList @() -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        $r.PortTests.Count | Should -Be 0
        Should -Invoke Test-PortConnectivity -Times 0
    }

    It 'Generates PortBlocked warning when a port test fails' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Host = $HostName; Success = $true; AvgTime = 5; PacketLoss = 0 } }
        Mock Test-PortConnectivity { @{ Host = $HostName; Port = $Port; ServiceName = 'SSH'; Success = $false; Error = 'blocked' } }

        $r = Get-NetworkHealthReport -HostList @('host') -PortList @(22) -DomainList @() -TraceTargets @() -DoSkipPortScan $false -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        @($r.Alerts | Where-Object { $_.Type -eq 'PortBlocked' }).Count | Should -Be 1
        $r.Summary.FailedTests | Should -Be 1
    }

    It 'Skips DNS tests when DoSkipDNS is true' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Success = $true; AvgTime = 5; PacketLoss = 0 } }
        Mock Test-DNSResolution { throw 'should not be called' }

        $r = Get-NetworkHealthReport -HostList @('h') -PortList @() -DomainList @('x.com') -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        $r.DNSTests.Count | Should -Be 0
        Should -Invoke Test-DNSResolution -Times 0
    }

    It 'Adds custom DNSServer tests when DNSServerList is provided' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Success = $true; AvgTime = 5; PacketLoss = 0 } }
        Mock Test-DNSResolution { @{ Domain = $Domain; Success = $true; IPAddresses = @('1.2.3.4'); DNSServer = ($DNSServer); Error = $null } }

        # 1 domain * (1 default + 2 custom) = 3 DNS tests
        $r = Get-NetworkHealthReport -HostList @('h') -PortList @() -DomainList @('google.com') -DNSServerList @('8.8.8.8', '1.1.1.1') -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $false -DoSkipTraceroute $true -DoQuickTest $false

        $r.DNSTests.Count | Should -Be 3
    }

    It 'Adds Proxy info alert when ProxyEnabled is true' {
        Mock Get-NetworkConfiguration { @{ Hostname = 'TEST'; ProxyEnabled = $true; ProxyServer = 'proxy.corp:8080' } }
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Success = $true; AvgTime = 5; PacketLoss = 0 } }

        $r = Get-NetworkHealthReport -HostList @('h') -PortList @() -DomainList @() -TraceTargets @() -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $true -DoQuickTest $false

        @($r.Alerts | Where-Object { $_.Type -eq 'Proxy' -and $_.Level -eq 'Info' }).Count | Should -Be 1
    }

    It 'Skips traceroute when DoQuickTest is true even with DoSkipTraceroute=$false' {
        Mock Get-NetworkAdapterInfo { @(@{}) }
        Mock Test-HostConnectivity { @{ Success = $true; AvgTime = 5; PacketLoss = 0 } }
        Mock Invoke-Traceroute { throw 'should not be called' }

        $r = Get-NetworkHealthReport -HostList @('h') -PortList @() -DomainList @() -TraceTargets @('8.8.8.8') -DoSkipPortScan $true -DoSkipDNS $true -DoSkipTraceroute $false -DoQuickTest $true

        $r.TracerouteResults.Count | Should -Be 0
        Should -Invoke Invoke-Traceroute -Times 0
    }
}

Describe 'Test-NetworkHealth.ps1 - Export-JSONReport' {
    It 'Writes a JSON file containing the report fields' {
        $dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $report = @{
            Timestamp         = '2026-06-07'
            ComputerName      = 'TEST'
            Summary           = @{ TotalTests = 3; PassedTests = 2; FailedTests = 1; Warnings = 0 }
            ConnectivityTests = @()
            PortTests         = @()
            DNSTests          = @()
            TracerouteResults = @()
            Alerts            = @()
        }

        $jsonPath = Export-JSONReport -Report $report -Path $dir

        Test-Path $jsonPath | Should -Be $true
        $written = Get-Content $jsonPath -Raw | ConvertFrom-Json
        $written.ComputerName | Should -Be 'TEST'
        $written.Summary.PassedTests | Should -Be 2
    }
}

Describe 'Test-NetworkHealth.ps1 - Export-HTMLReport' {
    It 'Writes an HTML file that mentions computer name and summary counts' {
        $dir = Join-Path $TestDrive ([Guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $report = @{
            ComputerName      = 'TESTHOST'
            Summary           = @{ PassedTests = 4; FailedTests = 1; Warnings = 2 }
            ConnectivityTests = @(@{ Host = 'a'; IPAddress = '1.2.3.4'; Success = $true; AvgTime = 5; PacketLoss = 0 })
            PortTests         = @()
            DNSTests          = @()
            Alerts            = @(@{ Level = 'Critical'; Message = 'boom' })
        }

        $htmlPath = Export-HTMLReport -Report $report -Path $dir

        Test-Path $htmlPath | Should -Be $true
        $content = Get-Content $htmlPath -Raw
        $content | Should -Match 'TESTHOST'
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'boom'
    }
}

Describe 'Test-NetworkHealth.ps1 - Write-ConsoleReport' {
    It 'Runs without throwing on a minimal report and writes to host' {
        Mock Write-Host { }
        $report = @{
            ComputerName      = 'TEST'
            Summary           = @{ TotalTests = 1; PassedTests = 1; FailedTests = 0; Warnings = 0 }
            Adapters          = @()
            ConnectivityTests = @(@{ Host = 'a'; Success = $true; AvgTime = 5; PacketLoss = 0 })
            PortTests         = @()
            DNSTests          = @()
            TracerouteResults = @()
            Alerts            = @()
        }
        { Write-ConsoleReport -Report $report } | Should -Not -Throw
        Should -Invoke Write-Host -Scope It
    }

    It "Writes the 'No issues detected' line when Alerts is empty" {
        $script:Captured = New-Object System.Collections.Generic.List[string]
        Mock Write-Host {
            if ($Object) { $script:Captured.Add([string]$Object) }
        }
        $report = @{
            ComputerName      = 'TEST'
            Summary           = @{ TotalTests = 1; PassedTests = 1; FailedTests = 0; Warnings = 0 }
            Adapters          = @()
            ConnectivityTests = @()
            PortTests         = @()
            DNSTests          = @()
            TracerouteResults = @()
            Alerts            = @()
        }
        Write-ConsoleReport -Report $report
        ($script:Captured -join ' ') | Should -Match 'No issues detected'
    }
}
