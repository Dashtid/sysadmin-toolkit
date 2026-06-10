# Behavioral Pester tests for Manage-VPN.ps1
# Run: Invoke-Pester -Path .\tests\Windows\ManageVPN.Behavioral.Tests.ps1

BeforeAll {
    function rasdial { param() }
    function rasphone { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\network\Manage-VPN.ps1'
    . $ScriptPath

    $global:LASTEXITCODE = 0
}

Describe 'Manage-VPN.ps1 - Get-VpnProfiles' {
    BeforeEach {
        Mock Write-ErrorMessage { }
    }

    It 'Returns the profiles Get-VpnConnection emits' {
        Mock Get-VpnConnection {
            @(
                [PSCustomObject]@{ Name = 'Office' }
                [PSCustomObject]@{ Name = 'Home' }
            )
        }
        $profiles = @(Get-VpnProfiles)
        $profiles.Count | Should -Be 2
    }

    It 'Returns empty array when Get-VpnConnection throws' {
        Mock Get-VpnConnection { throw 'access denied' }
        $profiles = @(Get-VpnProfiles)
        $profiles.Count | Should -Be 0
    }
}

Describe 'Manage-VPN.ps1 - Get-VpnConnectionStatus' {
    It 'Maps Get-VpnConnection fields into a flat PSCustomObject' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{
                Name                  = 'Office'
                ServerAddress         = 'vpn.corp.example'
                ConnectionStatus      = 'Connected'
                TunnelType            = 'Ikev2'
                AuthenticationMethod  = @('Eap', 'MSChapv2')
                SplitTunneling        = $false
                RememberCredential    = $true
                IdleDisconnectSeconds = 600
            }
        }
        $status = Get-VpnConnectionStatus -Name 'Office'
        $status.Name | Should -Be 'Office'
        $status.ConnectionStatus | Should -Be 'Connected'
        $status.AuthenticationMethod | Should -Be 'Eap, MSChapv2'
    }

    It 'Returns $null when Get-VpnConnection throws' {
        Mock Get-VpnConnection { throw 'profile not found' }
        Get-VpnConnectionStatus -Name 'Missing' | Should -BeNullOrEmpty
    }
}

Describe 'Manage-VPN.ps1 - Test-VpnConnectivity' {
    It "Returns $true when the profile's ConnectionStatus is 'Connected'" {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Connected' }
        }
        Test-VpnConnectivity -ProfileName 'Office' | Should -Be $true
    }

    It "Returns $false when the profile's ConnectionStatus is 'Disconnected'" {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Disconnected' }
        }
        Test-VpnConnectivity -ProfileName 'Office' | Should -Be $false
    }

    It 'Returns $false when the profile does not exist' {
        Mock Get-VpnConnection { $null }
        Test-VpnConnectivity -ProfileName 'Missing' | Should -Be $false
    }
}

Describe 'Manage-VPN.ps1 - Connect-VpnProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-VpnLog { }
    }

    It 'Returns $false and logs error when profile does not exist' {
        Mock Get-VpnConnection { $null }
        Connect-VpnProfile -Name 'Missing' | Should -Be $false
        Should -Invoke Write-ErrorMessage -Times 1
    }

    It 'Short-circuits to $true (already connected) without calling rasdial' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Connected' }
        }
        Mock rasdial { throw 'should not be called' }
        Connect-VpnProfile -Name 'Office' | Should -Be $true
        Should -Invoke rasdial -Times 0
    }

    It 'Returns $true when rasdial succeeds (no credentials)' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Disconnected' }
        }
        Mock rasdial { $global:LASTEXITCODE = 0; 'Connected.' }
        Connect-VpnProfile -Name 'Office' | Should -Be $true
    }
}

Describe 'Manage-VPN.ps1 - Disconnect-VpnProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-VpnLog { }
    }

    It 'Returns $false when profile does not exist' {
        Mock Get-VpnConnection { $null }
        Disconnect-VpnProfile -Name 'Missing' | Should -Be $false
    }

    It "Short-circuits to $true when profile is already disconnected" {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Disconnected' }
        }
        Mock rasdial { throw 'should not be called' }
        Disconnect-VpnProfile -Name 'Office' | Should -Be $true
        Should -Invoke rasdial -Times 0
    }

    It 'Returns $true when rasdial /disconnect exits 0' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Connected' }
        }
        Mock rasdial { $global:LASTEXITCODE = 0; 'Command completed successfully.' }
        Disconnect-VpnProfile -Name 'Office' | Should -Be $true
    }

    It 'Returns $false when rasdial /disconnect exits non-zero' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Connected' }
        }
        Mock rasdial { $global:LASTEXITCODE = 1; 'Error.' }
        Disconnect-VpnProfile -Name 'Office' | Should -Be $false
    }
}

Describe 'Manage-VPN.ps1 - New-VpnProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-VpnLog { }
        Mock Test-IsAdministrator { $true }
    }

    It 'Calls Add-VpnConnection with the supplied Name/Server/Type and returns $true' {
        Mock Add-VpnConnection { } -Verifiable -ParameterFilter {
            $Name -eq 'NewVpn' -and $ServerAddress -eq 'vpn.example.com' -and $TunnelType -eq 'Ikev2'
        }
        New-VpnProfile -Name 'NewVpn' -Server 'vpn.example.com' -Type 'Ikev2' -Auth 'Eap' | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Returns $false when Add-VpnConnection throws' {
        Mock Add-VpnConnection { throw 'duplicate profile' }
        New-VpnProfile -Name 'NewVpn' -Server 'vpn.example.com' -Type 'Ikev2' -Auth 'Eap' | Should -Be $false
    }
}

Describe 'Manage-VPN.ps1 - Remove-VpnProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-VpnLog { }
        Mock Test-IsAdministrator { $true }
    }

    It 'Returns $false when the profile does not exist' {
        Mock Get-VpnConnection { $null }
        Remove-VpnProfile -Name 'Missing' | Should -Be $false
    }

    It 'Disconnects first when the profile is currently Connected, then removes it' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Connected' }
        }
        Mock Disconnect-VpnProfile { $true } -Verifiable
        Mock Remove-VpnConnection { } -Verifiable
        Remove-VpnProfile -Name 'Office' | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Returns $false when Remove-VpnConnection throws' {
        Mock Get-VpnConnection {
            [PSCustomObject]@{ Name = 'Office'; ConnectionStatus = 'Disconnected' }
        }
        Mock Remove-VpnConnection { throw 'cannot remove' }
        Remove-VpnProfile -Name 'Office' | Should -Be $false
    }
}
