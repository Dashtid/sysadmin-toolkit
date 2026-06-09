# Behavioral Pester tests for Manage-Docker.ps1
# Run: Invoke-Pester -Path .\tests\Windows\ManageDocker.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-DockerManager on
# dot-source). docker and wsl are native commands -- stubs are defined in
# BeforeAll so Pester Mock can attach to them. Each mock body must set
# $global:LASTEXITCODE explicitly because native exit codes do not propagate
# through Mocks automatically.

BeforeAll {
    # Stubs so Pester can Mock these native commands.
    function docker { param() }
    function wsl { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\development\Manage-Docker.ps1'
    . $ScriptPath -Action Status

    $global:LASTEXITCODE = 0
}

Describe 'Manage-Docker.ps1 - Test-DockerInstalled' {
    It 'Returns true when docker command is resolvable' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'docker' } } -ParameterFilter { $Name -eq 'docker' }
        Test-DockerInstalled | Should -Be $true
    }

    It 'Returns false when docker command is not found' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'docker' }
        Test-DockerInstalled | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Test-DockerRunning' {
    It 'Returns true when docker info exits 0' {
        Mock docker { $global:LASTEXITCODE = 0; 'info output' }
        Test-DockerRunning | Should -Be $true
    }

    It 'Returns false when docker info exits non-zero' {
        Mock docker { $global:LASTEXITCODE = 1; 'cannot connect to daemon' }
        Test-DockerRunning | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Test-DockerDesktopInstalled' {
    It 'Returns true when the executable exists at the given Path' {
        $exe = Join-Path $TestDrive 'Docker Desktop.exe'
        New-Item -ItemType File -Path $exe -Force | Out-Null
        Test-DockerDesktopInstalled -Path $exe | Should -Be $true
    }

    It 'Returns false when the executable is missing' {
        $exe = Join-Path $TestDrive 'nope\Docker Desktop.exe'
        Test-DockerDesktopInstalled -Path $exe | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Get-DockerContainers' {
    It 'Parses tab-delimited ps output into PSCustomObjects' {
        Mock docker {
            $global:LASTEXITCODE = 0
            "abc123`tweb`tnginx:latest`tUp 2 hours`t0.0.0.0:80->80/tcp`trunning"
        }
        $containers = @(Get-DockerContainers)
        $containers.Count | Should -Be 1
        $containers[0].Name | Should -Be 'web'
        $containers[0].State | Should -Be 'running'
        $containers[0].Image | Should -Be 'nginx:latest'
    }

    It 'Passes -a flag when -All is specified' {
        Mock docker { $global:LASTEXITCODE = 0; '' } -Verifiable -ParameterFilter { $args -contains '-a' }
        Get-DockerContainers -All | Out-Null
        Should -InvokeVerifiable
    }

    It 'Returns empty array when docker ps fails' {
        Mock docker { $global:LASTEXITCODE = 1; 'cannot connect' }
        $containers = @(Get-DockerContainers)
        $containers.Count | Should -Be 0
    }
}

Describe 'Manage-Docker.ps1 - Start-DockerDesktop' {
    It 'Returns false when Docker Desktop is not installed at the given path' {
        $exe = Join-Path $TestDrive 'missing.exe'
        Mock Test-DockerRunning { $false }
        Mock Write-ErrorMessage { }
        Start-DockerDesktop -Path $exe | Should -Be $false
    }

    It 'Returns true immediately when Docker is already running' {
        $exe = Join-Path $TestDrive 'Docker Desktop.exe'
        New-Item -ItemType File -Path $exe -Force | Out-Null
        Mock Test-DockerRunning { $true }
        Mock Start-Process { }
        Mock Write-InfoMessage { }
        Start-DockerDesktop -Path $exe | Should -Be $true
        Should -Invoke Start-Process -Times 0
    }
}

Describe 'Manage-Docker.ps1 - Start-Container' {
    It 'Returns false and logs error when Docker is not running' {
        Mock Test-DockerRunning { $false }
        Mock Write-ErrorMessage { }
        Start-Container -Name 'web' | Should -Be $false
        Should -Invoke Write-ErrorMessage -Times 1
    }

    It 'Returns true when docker start exits 0' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0; 'web' }
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Start-Container -Name 'web' | Should -Be $true
    }

    It 'Returns false when docker start exits non-zero' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 1; 'No such container' }
        Mock Write-InfoMessage { }
        Mock Write-ErrorMessage { }
        Start-Container -Name 'missing' | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Stop-Container' {
    It 'Returns true when docker stop succeeds' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0; 'web' }
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Stop-Container -Name 'web' | Should -Be $true
    }

    It 'Returns false when docker stop fails' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 1; 'error' }
        Mock Write-InfoMessage { }
        Mock Write-ErrorMessage { }
        Stop-Container -Name 'web' | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Invoke-DockerPrune' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
    }

    It 'Returns false when Docker is not running' {
        Mock Test-DockerRunning { $false }
        Mock Write-ErrorMessage { }
        Invoke-DockerPrune -Target 'Containers' -Force | Should -Be $false
    }

    It 'Uses container prune -f when Target=Containers and -Force' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0 } -Verifiable -ParameterFilter { $args[0] -eq 'container' -and $args[1] -eq 'prune' -and $args -contains '-f' }
        Invoke-DockerPrune -Target 'Containers' -Force | Out-Null
        Should -InvokeVerifiable
    }

    It 'Uses image prune -a -f when Target=Images and -Force' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0 } -Verifiable -ParameterFilter { $args[0] -eq 'image' -and $args[1] -eq 'prune' -and $args -contains '-a' -and $args -contains '-f' }
        Invoke-DockerPrune -Target 'Images' -Force | Out-Null
        Should -InvokeVerifiable
    }

    It 'Uses system prune -a --volumes -f when Target=All and -Force' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0 } -Verifiable -ParameterFilter { $args[0] -eq 'system' -and $args[1] -eq 'prune' -and $args -contains '--volumes' }
        Invoke-DockerPrune -Target 'All' -Force | Out-Null
        Should -InvokeVerifiable
    }
}

Describe 'Manage-Docker.ps1 - Invoke-DockerImagePull' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns false when Docker is not running' {
        Mock Test-DockerRunning { $false }
        Invoke-DockerImagePull -Name 'nginx' | Should -Be $false
    }

    It 'Returns true on successful pull' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 0 }
        Invoke-DockerImagePull -Name 'nginx:latest' | Should -Be $true
    }

    It 'Returns false when docker pull exits non-zero' {
        Mock Test-DockerRunning { $true }
        Mock docker { $global:LASTEXITCODE = 1 }
        Invoke-DockerImagePull -Name 'bogus:tag' | Should -Be $false
    }
}

Describe 'Manage-Docker.ps1 - Get-ContainerHealth' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns empty array when Docker is not running' {
        Mock Test-DockerRunning { $false }
        $result = @(Get-ContainerHealth)
        $result.Count | Should -Be 0
    }

    It 'Surfaces OOMKilled issue from inspect output' {
        Mock Test-DockerRunning { $true }
        Mock Get-DockerContainers {
            @([PSCustomObject]@{ ID = 'abc'; Name = 'web'; Image = 'nginx'; Status = 'Exited (137)'; Ports = ''; State = 'exited' })
        }
        Mock docker {
            $global:LASTEXITCODE = 0
            '{"State":{"OOMKilled":true,"ExitCode":137,"Health":null}}'
        }
        $result = @(Get-ContainerHealth)
        $result.Count | Should -Be 1
        ($result[0].Issues -join ' ') | Should -Match 'OOM'
    }

    It 'Reports exit code issue when container exited non-zero' {
        Mock Test-DockerRunning { $true }
        Mock Get-DockerContainers {
            @([PSCustomObject]@{ ID = 'abc'; Name = 'web'; Image = 'nginx'; Status = 'Exited (1)'; Ports = ''; State = 'exited' })
        }
        Mock docker {
            $global:LASTEXITCODE = 0
            '{"State":{"OOMKilled":false,"ExitCode":1,"Health":null}}'
        }
        $result = @(Get-ContainerHealth)
        ($result[0].Issues -join ' ') | Should -Match 'exited with code 1'
    }
}

Describe 'Manage-Docker.ps1 - Invoke-DockerTroubleshoot' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Host { }
    }

    It 'Returns early with single FAIL result when Docker CLI is missing' {
        Mock Test-DockerInstalled { $false }
        $results = @(Invoke-DockerTroubleshoot)
        $results.Count | Should -Be 1
        $results[0].Check | Should -Be 'Docker CLI'
        $results[0].Status | Should -Be 'FAIL'
    }

    It 'Records FAIL for Docker Daemon when daemon is not running' {
        Mock Test-DockerInstalled { $true }
        Mock Test-DockerDesktopInstalled { $true }
        Mock Test-DockerRunning { $false }
        Mock Get-DockerVersion { 'Unknown' }
        Mock Get-DockerContainers { @() }
        Mock docker { $global:LASTEXITCODE = 0; '' }
        Mock wsl { $global:LASTEXITCODE = 0; 'no docker distro here' }
        $results = Invoke-DockerTroubleshoot
        @($results | Where-Object { $_.Check -eq 'Docker Daemon' })[0].Status | Should -Be 'FAIL'
    }

    It 'Flags WARN for Container Health when an exited container is present' {
        Mock Test-DockerInstalled { $true }
        Mock Test-DockerDesktopInstalled { $true }
        Mock Test-DockerRunning { $true }
        Mock Get-DockerVersion { '24.0.0' }
        Mock Get-DockerContainers {
            @([PSCustomObject]@{ Name = 'bad'; State = 'exited'; Status = 'Exited (1)' })
        }
        Mock docker { $global:LASTEXITCODE = 0; 'ok' }
        Mock wsl { $global:LASTEXITCODE = 0; 'docker-desktop Running' }
        $results = Invoke-DockerTroubleshoot
        @($results | Where-Object { $_.Check -eq 'Container Health' })[0].Status | Should -Be 'WARN'
    }
}
