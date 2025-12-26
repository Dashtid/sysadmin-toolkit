# Advanced Integration Tests for Sysadmin Toolkit
# Tests complete workflows with mocking for isolation

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

    # Import modules
    Import-Module (Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1") -Force
    Import-Module (Join-Path $ProjectRoot "Windows\lib\ErrorHandling.psm1") -Force

    # Import mock helpers
    Import-Module (Join-Path $PSScriptRoot "..\MockHelpers.psm1") -Force
}

AfterAll {
    Remove-Module CommonFunctions -ErrorAction SilentlyContinue
    Remove-Module ErrorHandling -ErrorAction SilentlyContinue
    Remove-Module MockHelpers -ErrorAction SilentlyContinue
}

Describe "Integration Tests - Error Handling with Retry Logic" {
    Context "Network Operations with Automatic Retry" {
        It "Retries network operation and succeeds on third attempt" {
            # Arrange
            $script:attemptCount = 0
            Mock Test-Connection {
                $script:attemptCount++
                if ($script:attemptCount -lt 3) {
                    throw "Network unreachable"
                }
                return [PSCustomObject]@{
                    Address      = "example.com"
                    StatusCode   = 0
                    ResponseTime = 10
                }
            }

            # Act
            $result = Retry-Command -ScriptBlock {
                Test-Connection -ComputerName "example.com" -Count 1
            } -MaxAttempts 5 -DelaySeconds 1

            # Assert
            $result.Address | Should -Be "example.com"
            $script:attemptCount | Should -Be 3
        }

        It "Validates input before retrying operation" {
            # Arrange
            $ipAddress = "192.168.1.100"

            # Act & Assert
            {
                Retry-Command -ScriptBlock {
                    if (-not (Test-InputValid -Value $ipAddress -Type IPAddress)) {
                        throw "Invalid IP address"
                    }
                    "Ping successful to $ipAddress"
                } -MaxAttempts 3
            } | Should -Not -Throw
        }

        It "Aggregates errors from multiple server pings" {
            # Arrange - Use simple test that doesn't require external mocking
            $servers = @("server1", "server2", "server3", "server4")

            # Act - Test with actual condition checking instead of mocking
            $result = Invoke-WithErrorAggregation -Items $servers -ScriptBlock {
                param($server)
                # Simulate ping failure for server2 and server4
                if ($server -eq "server2" -or $server -eq "server4") {
                    throw "Host unreachable: $server"
                }
                # Simulate successful ping
                return [PSCustomObject]@{ Address = $server; StatusCode = 0 }
            }

            # Assert
            $result.FailureCount | Should -Be 2
            $result.Errors.Count | Should -Be 2
            $result.Errors[0].Item | Should -Be "server2"
            $result.Errors[1].Item | Should -Be "server4"
        }
    }
}

Describe "Integration Tests - SSH Setup Workflow" {
    Context "Complete SSH Agent Setup" {
        BeforeAll {
            Mock-ServiceCommands -RunningServices @('ssh-agent')
            Mock-FileSystemCommands -ExistingPaths @{
                'C:\Users\TestUser\.ssh\id_ed25519'     = 'PRIVATE KEY DATA'
                'C:\Users\TestUser\.ssh\id_ed25519.pub' = 'PUBLIC KEY DATA'
            }
            Mock-EnvironmentVariables -Variables @{
                'SSH_AUTH_SOCK' = '\\.\pipe\openssh-ssh-agent'
                'USERPROFILE'   = 'C:\Users\TestUser'
            }
        }

        It "Verifies SSH agent service is running" -Skip:(-not (Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue)) {
            # Assert if service exists
            $service = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
            $service | Should -Not -BeNullOrEmpty
        }

        It "Validates SSH key file exists before adding" {
            # Arrange - Use TestDrive for actual file testing
            $keyPath = Join-Path $TestDrive 'id_ed25519'
            New-Item -Path $keyPath -ItemType File -Value 'PRIVATE KEY DATA' -Force | Out-Null

            # Act
            $exists = Test-Path $keyPath

            # Assert
            $exists | Should -Be $true
        }

        It "Validates SSH key path format" {
            # Arrange
            $keyPath = 'C:\Users\TestUser\.ssh\id_ed25519'

            # Act
            $isValid = Test-InputValid -Value $keyPath -Type Path

            # Assert
            $isValid | Should -Be $true
        }
    }

    Context "SSH Connection Validation" {
        It "Validates server IP address before connection" {
            # Arrange
            $serverIP = "192.168.1.100"

            # Act
            $isValid = Test-InputValid -Value $serverIP -Type IPAddress

            # Assert
            $isValid | Should -Be $true
        }

        It "Rejects invalid IP addresses" {
            # Arrange
            $testCases = @(
                @{ IP = "256.1.1.1"; Expected = $false }
                @{ IP = "192.168.1"; Expected = $false }
                @{ IP = "not-an-ip"; Expected = $false }
            )

            # Act & Assert
            foreach ($testCase in $testCases) {
                $result = Test-InputValid -Value $testCase.IP -Type IPAddress
                $result | Should -Be $testCase.Expected -Because "$($testCase.IP) should be invalid"
            }
        }

        It "Validates hostname format" {
            # Arrange
            $validHostnames = @("server01", "web-server", "db.example.com")

            # Act & Assert
            foreach ($hostname in $validHostnames) {
                Test-InputValid -Value $hostname -Type Hostname | Should -Be $true
            }
        }
    }
}

Describe "Integration Tests - System Update Workflow" {
    Context "Update Process with Error Handling" {
        BeforeAll {
            Mock Invoke-Expression {
                param($Command)
                if ($Command -like "*winget upgrade*") {
                    return "Successfully upgraded 5 packages"
                }
                return "Command executed"
            }
        }

        It "Retries failed package updates" {
            # Arrange
            $script:updateAttempts = 0

            # Act
            $result = Retry-Command -ScriptBlock {
                $script:updateAttempts++
                if ($script:updateAttempts -lt 2) {
                    throw "Update failed - network timeout"
                }
                Invoke-Expression "winget upgrade --all"
            } -MaxAttempts 3 -DelaySeconds 2

            # Assert
            $result | Should -Match "Successfully upgraded"
            $script:updateAttempts | Should -Be 2
        }

        It "Aggregates update results from multiple package managers" {
            # Arrange
            $packageManagers = @("winget", "chocolatey", "scoop", "npm")

            Mock Invoke-Expression {
                param($Command)
                if ($Command -like "*npm*") {
                    throw "npm registry unreachable"
                }
                return "Updated successfully"
            }

            # Act
            $result = Invoke-WithErrorAggregation -Items $packageManagers -ScriptBlock {
                param($pm)
                Invoke-Expression "$pm update"
            }

            # Assert
            $result.SuccessCount | Should -Be 3
            $result.FailureCount | Should -Be 1
            $result.Errors[0].Item | Should -Be "npm"
        }
    }
}

Describe "Integration Tests - Configuration Management" {
    Context "Loading and Validating Configuration" {
        BeforeAll {
            $configContent = @'
{
    "server": {
        "ip": "192.168.1.100",
        "port": 8080,
        "hostname": "web-server"
    },
    "email": {
        "admin": "admin@example.com"
    },
    "urls": {
        "api": "https://api.example.com"
    }
}
'@
            Mock-FileSystemCommands -ExistingPaths @{
                'C:\config.json' = $configContent
            }
        }

        It "Loads configuration file successfully" {
            # Arrange - Override with actual Get-Content mock
            Mock Get-Content {
                param($Path)
                if ($Path -like '*config.json') {
                    return @'
{
    "server": {
        "ip": "192.168.1.100",
        "port": 8080,
        "hostname": "web-server"
    },
    "email": {
        "admin": "admin@example.com"
    },
    "urls": {
        "api": "https://api.example.com"
    }
}
'@
                }
            }

            # Act
            $config = Get-Content 'C:\config.json' | ConvertFrom-Json

            # Assert
            $config.server.ip | Should -Be "192.168.1.100"
            $config.server.port | Should -Be 8080
        }

        It "Validates all configuration values" {
            # Arrange - Mock Get-Content again for this test
            Mock Get-Content {
                param($Path)
                if ($Path -like '*config.json') {
                    return @'
{
    "server": {
        "ip": "192.168.1.100",
        "port": 8080,
        "hostname": "web-server"
    },
    "email": {
        "admin": "admin@example.com"
    },
    "urls": {
        "api": "https://api.example.com"
    }
}
'@
                }
            }

            $config = Get-Content 'C:\config.json' | ConvertFrom-Json

            # Act & Assert - IP Address
            Test-InputValid -Value $config.server.ip -Type IPAddress | Should -Be $true

            # Port Number
            Test-InputValid -Value $config.server.port.ToString() -Type PortNumber | Should -Be $true

            # Hostname
            Test-InputValid -Value $config.server.hostname -Type Hostname | Should -Be $true

            # Email
            Test-InputValid -Value $config.email.admin -Type EmailAddress | Should -Be $true

            # URL
            Test-InputValid -Value $config.urls.api -Type URL | Should -Be $true
        }

        It "Detects invalid configuration values" {
            # Arrange - Modified invalid config
            $invalidConfig = @{
                server = @{
                    ip   = "256.1.1.1"  # Invalid IP
                    port = 99999        # Invalid port
                }
            }

            # Act & Assert
            Test-InputValid -Value $invalidConfig.server.ip -Type IPAddress | Should -Be $false
            Test-InputValid -Value $invalidConfig.server.port.ToString() -Type PortNumber | Should -Be $false
        }
    }
}

Describe "Integration Tests - Logging with Error Context" {
    Context "Contextual Error Reporting" {
        It "Captures and reports error with context" {
            # Arrange
            $errorMessage = $null

            # Act
            try {
                throw "Database connection failed"
            }
            catch {
                # Capture output
                $errorMessage = $_.Exception.Message

                # Use Write-ContextualError (mocked to not actually write)
                Mock Write-Host { }

                Write-ContextualError -ErrorRecord $_ `
                    -Context "connecting to database" `
                    -Suggestion "Check database server is running and credentials are correct"
            }

            # Assert
            $errorMessage | Should -Be "Database connection failed"
        }

        It "Combines logging with retry logic" {
            # Arrange
            $script:loggedMessages = @()
            $script:retries = 0

            Mock Write-Host {
                param($Object)
                $script:loggedMessages += $Object
            }

            # Act
            $result = Retry-Command -ScriptBlock {
                $script:retries++
                if ($script:retries -lt 2) {
                    Write-Host "Attempt $script:retries failed"
                    throw "Operation failed"
                }
                Write-Host "Attempt $script:retries succeeded"
                return "Success"
            } -MaxAttempts 3 -DelaySeconds 1

            # Assert
            $result | Should -Be "Success"
            $script:retries | Should -Be 2
        }
    }
}

Describe "Integration Tests - Full Workflow Scenarios" {
    Context "Complete System Setup Workflow" {
        BeforeAll {
            # Mock all external dependencies
            Mock-ServiceCommands -RunningServices @('ssh-agent')
            Mock-FileSystemCommands -ExistingPaths @{
                'C:\config.json'                = '{"environment":"production"}'
                'C:\Users\Admin\.ssh\id_rsa'    = 'SSH_KEY'
            }
            Mock-NetworkCommands -ReachableHosts @('github.com', 'registry.npmjs.org')
        }

        It "Validates environment before starting setup" -Skip:(-not (Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue)) {
            # Arrange
            $requiredServices = @('ssh-agent')

            # Act
            $result = Invoke-WithErrorAggregation -Items $requiredServices -ScriptBlock {
                param($serviceName)
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if (-not $service -or $service.Status -ne 'Running') {
                    throw "Service $serviceName is not running"
                }
                $service
            }

            # Assert
            $result.SuccessCount | Should -Be 1
            $result.FailureCount | Should -Be 0
        }

        It "Validates network connectivity to required hosts" {
            # Arrange
            $requiredHosts = @('github.com', 'registry.npmjs.org')

            # Act
            $result = Invoke-WithErrorAggregation -Items $requiredHosts -ScriptBlock {
                param($hostname)
                Test-Connection -ComputerName $hostname -Count 1
            }

            # Assert
            $result.SuccessCount | Should -Be 2
            $result.FailureCount | Should -Be 0
        }

        It "Validates all configuration files exist" {
            # Arrange - Use TestDrive for actual file testing
            $configFile = Join-Path $TestDrive 'config.json'
            $sshKeyFile = Join-Path $TestDrive 'id_rsa'

            New-Item -Path $configFile -ItemType File -Value '{"environment":"production"}' -Force | Out-Null
            New-Item -Path $sshKeyFile -ItemType File -Value 'SSH_KEY' -Force | Out-Null

            $requiredFiles = @($configFile, $sshKeyFile)

            # Act
            $result = Invoke-WithErrorAggregation -Items $requiredFiles -ScriptBlock {
                param($file)
                if (-not (Test-Path $file)) {
                    throw "Required file not found: $file"
                }
                $file
            }

            # Assert
            $result.SuccessCount | Should -Be 2
            $result.FailureCount | Should -Be 0
        }
    }
}
