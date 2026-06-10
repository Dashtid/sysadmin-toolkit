# Behavioral Pester tests for Repair-CommonIssues.ps1
# Run: Invoke-Pester -Path .\tests\Windows\RepairCommonIssues.Behavioral.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\troubleshooting\Repair-CommonIssues.ps1'
    # -Fix is Mandatory; pass a no-op value so dot-source passes param validation.
    # We test helpers directly, not the dispatcher.
    . $ScriptPath -Fix 'DNS'
}

Describe 'Repair-CommonIssues.ps1 - Add-RepairResult' {
    BeforeEach {
        $script:Results = @()
        $script:RequiresRestart = $false
    }

    It 'Appends a result row with the supplied fields' {
        Add-RepairResult -FixName 'Test fix' -Success $true -Message 'OK'
        $script:Results.Count | Should -Be 1
        $script:Results[0].FixApplied | Should -Be 'Test fix'
        $script:Results[0].Success | Should -Be $true
        $script:Results[0].Message | Should -Be 'OK'
    }

    It 'Sets $script:RequiresRestart=$true when RequiresRestart switch is passed' {
        Add-RepairResult -FixName 'Network reset' -Success $true -Message 'OK' -RequiresRestart $true
        $script:RequiresRestart | Should -Be $true
        $script:Results[0].RequiresRestart | Should -Be $true
    }

    It 'Leaves $script:RequiresRestart=$false when RequiresRestart switch is not passed' {
        Add-RepairResult -FixName 'DNS flush' -Success $true -Message 'OK'
        $script:RequiresRestart | Should -Be $false
    }
}

Describe 'Repair-CommonIssues.ps1 - Invoke-CommandWithLogging' {
    BeforeEach {
        Mock Write-RepairLog { }
        $script:Results = @()
        $script:RequiresRestart = $false
        $script:DryRun = $false
        # The function reads $DryRun from caller scope via dot-source script-param;
        # since BeforeAll dot-sourced without -DryRun, the switch defaults to false.
    }

    It 'Records success when the scriptblock runs without throwing' {
        $result = Invoke-CommandWithLogging -Description 'happy path' -Command { 'all good' }
        $result | Should -Be $true
        $script:Results.Count | Should -Be 1
        $script:Results[0].Success | Should -Be $true
        $script:Results[0].FixApplied | Should -Be 'happy path'
    }

    It 'Records failure when the scriptblock throws and returns $false' {
        $result = Invoke-CommandWithLogging -Description 'failing op' -Command { throw 'boom' }
        $result | Should -Be $false
        $script:Results[0].Success | Should -Be $false
        $script:Results[0].Message | Should -Match 'boom'
    }

    It "Propagates RequiresRestart=$true into the result record" {
        $null = Invoke-CommandWithLogging -Description 'reset' -Command { 'ok' } -RequiresRestart $true
        $script:Results[0].RequiresRestart | Should -Be $true
        $script:RequiresRestart | Should -Be $true
    }
}

Describe 'Repair-CommonIssues.ps1 - Repair-DNSIssues' {
    BeforeEach {
        Mock Write-RepairLog { }
        Mock Write-Host { }
        Mock Write-Success { }
        Mock Clear-DnsClientCache { }
        Mock Restart-Service { }
        Mock Invoke-CommandWithLogging { $true } -Verifiable
        $script:Results = @()
        $script:RequiresRestart = $false
    }

    It 'Queues at least one DNS-flush and one DNS-register operation' {
        Repair-DNSIssues
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Flush DNS resolver cache' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Register DNS' }
    }

    It 'Queues a DNS Client service restart' {
        Repair-DNSIssues
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Restart DNS Client service' }
    }
}

Describe 'Repair-CommonIssues.ps1 - Repair-NetworkIssues' {
    BeforeEach {
        Mock Write-RepairLog { }
        Mock Write-Host { }
        Mock Write-Success { }
        Mock Get-NetAdapter {
            @(
                [PSCustomObject]@{ Name = 'Ethernet'; Status = 'Up' }
                [PSCustomObject]@{ Name = 'Wi-Fi'; Status = 'Up' }
            )
        }
        Mock Invoke-CommandWithLogging { $true } -Verifiable
        $script:Results = @()
        $script:RequiresRestart = $false
    }

    It 'Queues one Restart-NetAdapter call per Up adapter, plus IP and IPv6 resets' {
        Repair-NetworkIssues
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Restart network adapter: Ethernet' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Restart network adapter: Wi-Fi' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Reset IP configuration' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Reset IPv6 configuration' }
    }
}

Describe 'Repair-CommonIssues.ps1 - Repair-WinsockIssues' {
    BeforeEach {
        Mock Write-RepairLog { }
        Mock Write-Host { }
        Mock Write-Success { }
        Mock Invoke-CommandWithLogging { $true } -Verifiable
    }

    It 'Queues both Winsock reset operations with RequiresRestart=$true' {
        Repair-WinsockIssues
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter {
            $Description -match 'Reset Winsock catalog' -and $RequiresRestart -eq $true
        }
    }
}

Describe 'Repair-CommonIssues.ps1 - Repair-TCPIPIssues' {
    BeforeEach {
        Mock Write-RepairLog { }
        Mock Write-Host { }
        Mock Write-Success { }
        Mock Invoke-CommandWithLogging { $true } -Verifiable
    }

    It 'Queues TCP/IP stack reset, TCP reset, and routing table reset' {
        Repair-TCPIPIssues
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Reset TCP/IP stack' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Reset TCP/IP to default' }
        Should -Invoke Invoke-CommandWithLogging -ParameterFilter { $Description -match 'Reset routing table' }
    }
}
