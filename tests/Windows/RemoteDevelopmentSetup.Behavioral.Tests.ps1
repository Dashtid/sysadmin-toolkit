# Behavioral Pester tests for remote-development-setup.ps1
# Run: Invoke-Pester -Path .\tests\Windows\RemoteDevelopmentSetup.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Main on dot-source).
# Initialize-SSHClient, Initialize-VSCodeRemote, and Initialize-PortForwarding
# take explicit -Skip params so tests can exercise the skip path cleanly.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\development\remote-development-setup.ps1'
    . $ScriptPath

    function winget { param() }
    function choco { param() }
    function ssh-keygen { param() }
    function ssh-add { param() }
    function code { param() }
    function icacls { param() }
}

Describe 'remote-development-setup.ps1 - Initialize-SSHClient' {
    Context 'When -Skip is true' {
        BeforeEach {
            Mock Get-WindowsCapability { throw 'should not be called' }
            Mock Test-Path { throw 'should not be called' }
        }

        It 'Returns immediately without touching SSH state' {
            { Initialize-SSHClient -Skip $true } | Should -Not -Throw
            Should -Invoke Get-WindowsCapability -Times 0
        }
    }

    Context 'When -Skip is false and the SSH key already exists' {
        BeforeEach {
            Mock Get-WindowsCapability { [PSCustomObject]@{ Name = 'OpenSSH.Client'; State = 'Installed' } }
            Mock Add-WindowsCapability { throw 'should not be called' }
            Mock Test-Path { $true }
            Mock New-Item { }
            Mock icacls { }
            Mock ssh-keygen { throw 'should not regenerate key' }
            Mock Start-Service { }
            Mock Set-Service { }
            Mock ssh-add { }
            Mock Get-Content { }
        }

        It 'Does not re-install OpenSSH Client' {
            Initialize-SSHClient -Skip $false
            Should -Invoke Add-WindowsCapability -Times 0
        }

        It 'Does not regenerate the existing SSH key' {
            Initialize-SSHClient -Skip $false
            Should -Invoke ssh-keygen -Times 0
        }
    }
}

Describe 'remote-development-setup.ps1 - Initialize-VSCodeRemote' {
    Context 'When -Skip is true' {
        BeforeEach {
            Mock Get-Command { throw 'should not be called' }
            Mock code { throw 'should not be called' }
        }

        It 'Returns immediately' {
            { Initialize-VSCodeRemote -Skip $true } | Should -Not -Throw
            Should -Invoke code -Times 0
        }
    }

    Context 'When -Skip is false and VS Code is available' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'code' } } -ParameterFilter { $Name -eq 'code' }
            Mock code { }
            Mock Test-Path { $true }   # Skip SSH config template write
        }

        It 'Installs each remote-development extension' {
            Initialize-VSCodeRemote -Skip $false
            # 6 extensions in the script's list
            Should -Invoke code -Times 6
        }

        It 'Continues iterating if one extension install throws' {
            Mock code { throw 'simulated failure' }
            { Initialize-VSCodeRemote -Skip $false } | Should -Not -Throw
            Should -Invoke code -Times 6
        }
    }
}

Describe 'remote-development-setup.ps1 - Initialize-PortForwarding' {
    Context 'When -Skip is true' {
        BeforeEach {
            Mock New-Item { throw 'should not be called' }
            Mock Set-Content { throw 'should not be called' }
        }

        It 'Returns immediately' {
            { Initialize-PortForwarding -Skip $true } | Should -Not -Throw
            Should -Invoke Set-Content -Times 0
        }
    }

    Context 'When -Skip is false' {
        BeforeEach {
            Mock New-Item { }
            Mock Set-Content { }
        }

        It 'Creates the Scripts directory under $env:USERPROFILE\Development' {
            Initialize-PortForwarding -Skip $false
            Should -Invoke New-Item -Times 1 -ParameterFilter { $Path -match 'Development\\Scripts' }
        }

        It 'Writes both ssh-tunnel.ps1 and ssh-multi-tunnel.ps1' {
            Initialize-PortForwarding -Skip $false
            Should -Invoke Set-Content -Times 2
            Should -Invoke Set-Content -ParameterFilter { $Path -match 'ssh-tunnel\.ps1$' }
            Should -Invoke Set-Content -ParameterFilter { $Path -match 'ssh-multi-tunnel\.ps1$' }
        }
    }
}

Describe 'remote-development-setup.ps1 - Install-RemoteDevTool' {
    BeforeEach {
        $script:ChocoCalls = @()
        Mock choco { $script:ChocoCalls += , @($args) }
        Mock winget { }
    }

    Context 'When choco is available' {
        BeforeEach {
            Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'wt' }
            Mock winget { }
        }

        It 'Installs each tool via choco' {
            Install-RemoteDevTool
            # 5 tools in the script's list (putty, winscp, mremoteng, terminus, mobaxterm)
            Should -Invoke choco -Times 5
        }

        It 'Installs Windows Terminal via winget when wt is missing' {
            Install-RemoteDevTool
            Should -Invoke winget -Times 1
        }
    }

    Context 'When choco is not available' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
            Mock Get-Command { [PSCustomObject]@{ Name = 'wt' } } -ParameterFilter { $Name -eq 'wt' }
        }

        It 'Skips choco-based tool installation entirely' {
            Install-RemoteDevTool
            Should -Invoke choco -Times 0
        }

        It 'Skips Windows Terminal install when wt is already present' {
            Install-RemoteDevTool
            Should -Invoke winget -Times 0
        }
    }
}

Describe 'remote-development-setup.ps1 - Initialize-DevelopmentWorkspace' {
    BeforeEach {
        Mock New-Item { }
        Mock Set-Content { }
    }

    It 'Creates the four expected subdirectories (Projects/Scripts/Configs/Logs)' {
        Initialize-DevelopmentWorkspace
        Should -Invoke New-Item -Times 4
    }

    It 'Writes a README.md describing the workspace' {
        Initialize-DevelopmentWorkspace
        Should -Invoke Set-Content -Times 1 -ParameterFilter { $Path -match 'README\.md$' }
    }
}

Describe 'remote-development-setup.ps1 - Main' {
    BeforeEach {
        Mock Assert-Administrator { }
        Mock Initialize-SSHClient { }
        Mock Initialize-VSCodeRemote { }
        Mock Initialize-PortForwarding { }
        Mock Install-RemoteDevTool { }
        Mock Initialize-WindowsTerminal { }
        Mock Initialize-DevelopmentWorkspace { }
    }

    It 'Calls Assert-Administrator first (admin gating moved from #Requires)' {
        Main
        Should -Invoke Assert-Administrator -Times 1
    }

    It 'Calls all six setup phases exactly once' {
        Main
        Should -Invoke Initialize-SSHClient -Times 1
        Should -Invoke Initialize-VSCodeRemote -Times 1
        Should -Invoke Initialize-PortForwarding -Times 1
        Should -Invoke Install-RemoteDevTool -Times 1
        Should -Invoke Initialize-WindowsTerminal -Times 1
        Should -Invoke Initialize-DevelopmentWorkspace -Times 1
    }
}
