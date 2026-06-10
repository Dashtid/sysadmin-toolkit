# Behavioral Pester tests for Set-StaticIP.ps1
# Run: Invoke-Pester -Path .\tests\Windows\SetStaticIP.Behavioral.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\network\Set-StaticIP.ps1'
    . $ScriptPath
}

Describe 'Set-StaticIP.ps1 - Test-IPAddress' {
    It 'Returns $true for a valid IPv4 address' {
        Test-IPAddress -IP '192.168.1.10' | Should -Be $true
    }

    It 'Returns $true for a valid IPv6 address' {
        Test-IPAddress -IP '::1' | Should -Be $true
    }

    It 'Returns $false for an obviously invalid string' {
        Test-IPAddress -IP 'not-an-ip' | Should -Be $false
    }

    It 'Returns $false for an octet over 255' {
        Test-IPAddress -IP '192.168.1.256' | Should -Be $false
    }
}

Describe 'Set-StaticIP.ps1 - Set-StaticIPConfiguration' {
    BeforeEach {
        Mock Write-Status { }
        Mock Write-Host { }
        Mock Start-Sleep { }
    }

    It 'Returns $false and logs an error when the adapter does not exist' {
        Mock Get-NetAdapter { throw 'No MSFT_NetAdapter objects found' }
        $result = Set-StaticIPConfiguration -Adapter 'NoSuch' -IP '10.0.0.5' -Prefix 24 -GW '10.0.0.1' -DNS @('1.1.1.1')
        $result | Should -Be $false
        Should -Invoke Write-Status -ParameterFilter { $Type -eq 'ERROR' }
    }

    It 'Calls New-NetIPAddress with the given IP/Prefix/Gateway on success' {
        Mock Get-NetAdapter { [PSCustomObject]@{ ifIndex = 42; Name = 'Ethernet' } }
        Mock Get-NetIPAddress { @() }
        Mock Get-NetRoute { @() }
        Mock Remove-NetIPAddress { }
        Mock Remove-NetRoute { }
        Mock New-NetIPAddress { } -Verifiable -ParameterFilter {
            $InterfaceIndex -eq 42 -and $IPAddress -eq '10.0.0.5' -and $PrefixLength -eq 24 -and $DefaultGateway -eq '10.0.0.1'
        }
        Mock Set-DnsClientServerAddress { }
        Mock Get-DnsClientServerAddress { [PSCustomObject]@{ ServerAddresses = @('1.1.1.1') } }
        Mock Test-Connection { $true }

        $result = Set-StaticIPConfiguration -Adapter 'Ethernet' -IP '10.0.0.5' -Prefix 24 -GW '10.0.0.1' -DNS @('1.1.1.1')

        $result | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Skips Set-DnsClientServerAddress when no DNS servers are supplied' {
        Mock Get-NetAdapter { [PSCustomObject]@{ ifIndex = 42; Name = 'Ethernet' } }
        Mock Get-NetIPAddress { @() }
        Mock Get-NetRoute { @() }
        Mock Remove-NetIPAddress { }
        Mock Remove-NetRoute { }
        Mock New-NetIPAddress { }
        Mock Set-DnsClientServerAddress { throw 'should not be called' }
        Mock Get-DnsClientServerAddress { [PSCustomObject]@{ ServerAddresses = @() } }
        Mock Test-Connection { $true }

        $result = Set-StaticIPConfiguration -Adapter 'Ethernet' -IP '10.0.0.5' -Prefix 24 -GW '10.0.0.1' -DNS @()

        $result | Should -Be $true
        Should -Invoke Set-DnsClientServerAddress -Times 0
    }

    It 'Logs a WARN status when the gateway is not reachable via ping' {
        Mock Get-NetAdapter { [PSCustomObject]@{ ifIndex = 42; Name = 'Ethernet' } }
        Mock Get-NetIPAddress { @() }
        Mock Get-NetRoute { @() }
        Mock Remove-NetIPAddress { }
        Mock Remove-NetRoute { }
        Mock New-NetIPAddress { }
        Mock Set-DnsClientServerAddress { }
        Mock Get-DnsClientServerAddress { [PSCustomObject]@{ ServerAddresses = @('1.1.1.1') } }
        Mock Test-Connection { $false }

        $null = Set-StaticIPConfiguration -Adapter 'Ethernet' -IP '10.0.0.5' -Prefix 24 -GW '10.0.0.1' -DNS @('1.1.1.1')

        Should -Invoke Write-Status -ParameterFilter { $Type -eq 'WARN' }
    }
}
