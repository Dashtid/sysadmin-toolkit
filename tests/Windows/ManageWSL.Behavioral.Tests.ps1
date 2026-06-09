# Behavioral Pester tests for Manage-WSL.ps1
# Run: Invoke-Pester -Path .\tests\Windows\ManageWSL.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-WslManager on
# dot-source). wsl.exe is a native command -- stub function defined in
# BeforeAll so Pester Mock can attach. Each mock body that the SUT inspects
# via $LASTEXITCODE must set $global:LASTEXITCODE explicitly.

BeforeAll {
    function wsl { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\development\Manage-WSL.ps1'
    . $ScriptPath -Action Status

    $global:LASTEXITCODE = 0
}

Describe 'Manage-WSL.ps1 - Test-WslInstalled' {
    It 'Returns true when wsl.exe is resolvable' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'wsl.exe' } } -ParameterFilter { $Name -eq 'wsl.exe' }
        Test-WslInstalled | Should -Be $true
    }

    It 'Returns false when wsl.exe is not found' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'wsl.exe' }
        Test-WslInstalled | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Get-WslDistributions' {
    It 'Parses verbose list output into PSCustomObjects with IsDefault marker' {
        Mock wsl {
            $global:LASTEXITCODE = 0
            "  NAME            STATE           VERSION`n* Ubuntu          Running         2`n  Debian          Stopped         2"
        }
        $distros = @(Get-WslDistributions)
        $distros.Count | Should -Be 2
        ($distros | Where-Object { $_.Name -eq 'Ubuntu' }).IsDefault | Should -Be $true
        ($distros | Where-Object { $_.Name -eq 'Debian' }).IsDefault | Should -Be $false
    }

    It 'Captures State and Version fields' {
        Mock wsl {
            $global:LASTEXITCODE = 0
            "  NAME            STATE           VERSION`n  Ubuntu          Running         2"
        }
        $distros = @(Get-WslDistributions)
        $distros[0].State | Should -Be 'Running'
        $distros[0].Version | Should -Be 2
    }

    It 'Returns empty array when wsl exits non-zero' {
        Mock wsl { $global:LASTEXITCODE = 1; '' }
        $distros = @(Get-WslDistributions)
        $distros.Count | Should -Be 0
    }
}

Describe 'Manage-WSL.ps1 - Install-Wsl' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns false when not running as administrator' {
        Mock Test-IsAdministrator { $false }
        Install-Wsl | Should -Be $false
        Should -Invoke Write-ErrorMessage -Times 1
    }

    It 'Calls wsl --install -d <Distro> when Distro is specified' {
        Mock Test-IsAdministrator { $true }
        Mock wsl { $global:LASTEXITCODE = 0; '' } -Verifiable -ParameterFilter { $args -contains '-d' -and $args -contains 'Ubuntu' }
        Install-Wsl -Distro 'Ubuntu' | Out-Null
        Should -InvokeVerifiable
    }

    It "Returns true when wsl reports 'already installed' on non-zero exit" {
        Mock Test-IsAdministrator { $true }
        Mock wsl { $global:LASTEXITCODE = 1; 'WSL is already installed' }
        Install-Wsl -Distro 'Ubuntu' | Should -Be $true
    }
}

Describe 'Manage-WSL.ps1 - Export-WslDistribution' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It "Returns false when the named distribution does not exist" {
        Mock Get-WslDistributions { @() }
        Export-WslDistribution -Name 'NonExistent' -Path (Join-Path $TestDrive 'out.tar') | Should -Be $false
    }

    It 'Returns true when wsl --export exits 0' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Ubuntu' }) }
        $exportPath = Join-Path $TestDrive 'ubuntu.tar'
        # Create the file so the post-success Get-Item call works.
        New-Item -ItemType File -Path $exportPath -Force | Out-Null
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Export-WslDistribution -Name 'Ubuntu' -Path $exportPath | Should -Be $true
    }

    It 'Returns false when wsl --export exits non-zero' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Ubuntu' }) }
        Mock wsl { $global:LASTEXITCODE = 1; 'export failed' }
        Export-WslDistribution -Name 'Ubuntu' -Path (Join-Path $TestDrive 'fail.tar') | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Import-WslDistribution' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns false when the import file does not exist' {
        Import-WslDistribution -Name 'X' -Path (Join-Path $TestDrive 'missing.tar') -Location (Join-Path $TestDrive 'install') | Should -Be $false
    }

    It 'Returns true when wsl --import exits 0' {
        $tar = Join-Path $TestDrive 'good.tar'
        New-Item -ItemType File -Path $tar -Force | Out-Null
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Import-WslDistribution -Name 'NewDistro' -Path $tar -Location (Join-Path $TestDrive 'install') | Should -Be $true
    }

    It 'Returns false when wsl --import exits non-zero' {
        $tar = Join-Path $TestDrive 'good2.tar'
        New-Item -ItemType File -Path $tar -Force | Out-Null
        Mock wsl { $global:LASTEXITCODE = 1; 'import failed' }
        Import-WslDistribution -Name 'NewDistro' -Path $tar -Location (Join-Path $TestDrive 'install') | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Remove-WslDistribution' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns false when the named distribution does not exist' {
        Mock Get-WslDistributions { @() }
        Remove-WslDistribution -Name 'NonExistent' | Should -Be $false
    }

    It 'Returns true when wsl --unregister exits 0' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Old' }) }
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Remove-WslDistribution -Name 'Old' | Should -Be $true
    }

    It 'Returns false when wsl --unregister exits non-zero' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Old' }) }
        Mock wsl { $global:LASTEXITCODE = 1; 'unregister failed' }
        Remove-WslDistribution -Name 'Old' | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Set-WslConfiguration' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Writes a [wsl2] section with memory= when Memory is provided' {
        $cfg = Join-Path $TestDrive 'wslconfig.txt'
        Set-WslConfiguration -Memory '4GB' -ConfigPath $cfg | Should -Be $true
        $content = Get-Content $cfg -Raw
        $content | Should -Match '\[wsl2\]'
        $content | Should -Match 'memory=4GB'
    }

    It 'Writes processors= when Processors > 0' {
        $cfg = Join-Path $TestDrive 'wslconfig2.txt'
        Set-WslConfiguration -Processors 4 -ConfigPath $cfg | Should -Be $true
        Get-Content $cfg -Raw | Should -Match 'processors=4'
    }

    It 'Writes swap= when Swap is provided' {
        $cfg = Join-Path $TestDrive 'wslconfig3.txt'
        Set-WslConfiguration -Swap '2GB' -ConfigPath $cfg | Should -Be $true
        Get-Content $cfg -Raw | Should -Match 'swap=2GB'
    }
}

Describe 'Manage-WSL.ps1 - Start-WslDistribution' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Calls wsl -d <Name> when Name is specified' {
        Mock wsl { $global:LASTEXITCODE = 0; '' } -Verifiable -ParameterFilter { $args -contains '-d' -and $args -contains 'Ubuntu' }
        Start-WslDistribution -Name 'Ubuntu' | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Calls wsl without -d when no Name is specified' {
        Mock wsl { $global:LASTEXITCODE = 0; '' } -Verifiable -ParameterFilter { -not ($args -contains '-d') }
        Start-WslDistribution | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Returns false when wsl exits non-zero' {
        Mock wsl { $global:LASTEXITCODE = 1; 'error' }
        Start-WslDistribution -Name 'Ubuntu' | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Stop-WslInstances' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns true when wsl --shutdown exits 0' {
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Stop-WslInstances | Should -Be $true
    }

    It 'Returns false when wsl --shutdown exits non-zero' {
        Mock wsl { $global:LASTEXITCODE = 1; 'fail' }
        Stop-WslInstances | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Update-WslKernel' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns true when wsl --update exits 0' {
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Update-WslKernel | Should -Be $true
    }
}

Describe 'Manage-WSL.ps1 - Set-WslDefault' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns false when the named distribution does not exist' {
        Mock Get-WslDistributions { @() }
        Set-WslDefault -Name 'Ghost' | Should -Be $false
    }

    It 'Returns true when wsl --set-default exits 0' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Ubuntu' }) }
        Mock wsl { $global:LASTEXITCODE = 0; '' }
        Set-WslDefault -Name 'Ubuntu' | Should -Be $true
    }

    It 'Returns false when wsl --set-default exits non-zero' {
        Mock Get-WslDistributions { @([PSCustomObject]@{ Name = 'Ubuntu' }) }
        Mock wsl { $global:LASTEXITCODE = 1; 'fail' }
        Set-WslDefault -Name 'Ubuntu' | Should -Be $false
    }
}

Describe 'Manage-WSL.ps1 - Invoke-WslTroubleshoot' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Host { }
    }

    It 'Records FAIL for WSL Installed when wsl.exe is missing' {
        Mock Test-WslInstalled { $false }
        Mock Get-WindowsOptionalFeature { [PSCustomObject]@{ State = 'Enabled' } }
        Mock Get-CimInstance { [PSCustomObject]@{ VirtualizationFirmwareEnabled = $true } }
        Mock Get-WslVersion { 'Unknown' }
        Mock Get-WslDistributions { @() }
        Mock Get-NetAdapter { @() }
        $results = Invoke-WslTroubleshoot
        @($results | Where-Object { $_.Check -eq 'WSL Installed' })[0].Status | Should -Be 'FAIL'
    }

    It 'Records WARN for Distributions when none are installed' {
        Mock Test-WslInstalled { $true }
        Mock Get-WindowsOptionalFeature { [PSCustomObject]@{ State = 'Enabled' } }
        Mock Get-CimInstance { [PSCustomObject]@{ VirtualizationFirmwareEnabled = $true } }
        Mock Get-WslVersion { '2.0.0' }
        Mock Get-WslDistributions { @() }
        Mock Get-NetAdapter { @() }
        $results = Invoke-WslTroubleshoot
        @($results | Where-Object { $_.Check -eq 'Distributions' })[0].Status | Should -Be 'WARN'
    }

    It 'Records PASS for Distributions when at least one is installed' {
        Mock Test-WslInstalled { $true }
        Mock Get-WindowsOptionalFeature { [PSCustomObject]@{ State = 'Enabled' } }
        Mock Get-CimInstance { [PSCustomObject]@{ VirtualizationFirmwareEnabled = $true } }
        Mock Get-WslVersion { '2.0.0' }
        Mock Get-WslDistributions {
            @([PSCustomObject]@{ Name = 'Ubuntu'; State = 'Running'; Version = 2; IsDefault = $true })
        }
        Mock Get-NetAdapter { @([PSCustomObject]@{ Name = 'vEthernet (WSL)' }) }
        $results = Invoke-WslTroubleshoot
        @($results | Where-Object { $_.Check -eq 'Distributions' })[0].Status | Should -Be 'PASS'
    }
}
