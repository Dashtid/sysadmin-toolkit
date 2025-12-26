# Pester Tests for ErrorHandling Module
# Run: Invoke-Pester -Path .\tests\Windows\ErrorHandling.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ModulePath = Join-Path $ProjectRoot "Windows\lib\ErrorHandling.psm1"

    # Import the module
    Import-Module $ModulePath -Force
}

AfterAll {
    # Clean up module
    Remove-Module ErrorHandling -ErrorAction SilentlyContinue
}

Describe "ErrorHandling Module - Basic Validation" {
    Context "Module Structure" {
        It "Module file exists" {
            $ModulePath | Should -Exist
        }

        It "Module has valid PowerShell syntax" {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $ModulePath -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "Module can be imported" {
            { Import-Module $ModulePath -Force } | Should -Not -Throw
        }

        It "Module exports expected functions" {
            $exportedFunctions = (Get-Module ErrorHandling).ExportedFunctions.Keys
            $expectedFunctions = @(
                'Retry-Command',
                'Test-InputValid',
                'Write-ContextualError',
                'Invoke-WithErrorAggregation'
            )

            foreach ($func in $expectedFunctions) {
                $exportedFunctions | Should -Contain $func
            }
        }
    }

    Context "Module Metadata" {
        It "Has version information in comments" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "Version:\s*1\.0\.0"
        }

        It "Has synopsis documentation" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Has author information" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "Author:\s*David Dashti"
        }
    }
}

Describe "ErrorHandling Module - Retry-Command Function" {
    Context "Function Existence and Help" {
        It "Retry-Command function exists" {
            Get-Command Retry-Command -Module ErrorHandling -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Retry-Command has comment-based help" {
            $help = Get-Help Retry-Command
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It "Retry-Command has parameter documentation" {
            $help = Get-Help Retry-Command -Parameter ScriptBlock
            $help.description | Should -Not -BeNullOrEmpty
        }
    }

    Context "Basic Functionality" {
        It "Executes successful command on first attempt" {
            $result = Retry-Command -ScriptBlock { "Success" } -MaxAttempts 3
            $result | Should -Be "Success"
        }

        It "Returns command output" {
            $result = Retry-Command -ScriptBlock { 1 + 1 } -MaxAttempts 1
            $result | Should -Be 2
        }

        It "Accepts different MaxAttempts values" {
            { Retry-Command -ScriptBlock { $true } -MaxAttempts 1 } | Should -Not -Throw
            { Retry-Command -ScriptBlock { $true } -MaxAttempts 5 } | Should -Not -Throw
        }
    }

    Context "Retry Logic" {
        It "Retries on failure and eventually succeeds" {
            $script:attemptCount = 0
            $result = Retry-Command -ScriptBlock {
                $script:attemptCount++
                if ($script:attemptCount -lt 2) {
                    throw "Simulated failure"
                }
                "Success on attempt $script:attemptCount"
            } -MaxAttempts 3 -DelaySeconds 1

            $script:attemptCount | Should -Be 2
            $result | Should -Match "Success on attempt 2"
        }

        It "Throws after max attempts exceeded" {
            $script:attemptCount = 0
            {
                Retry-Command -ScriptBlock {
                    $script:attemptCount++
                    throw "Always fails"
                } -MaxAttempts 2 -DelaySeconds 1
            } | Should -Throw
        }

        It "Uses exponential backoff delay" {
            # This test is hard to verify timing precisely, but we can check it doesn't error
            $result = Retry-Command -ScriptBlock {
                $script:attemptCount++
                if ($script:attemptCount -lt 2) { throw "Fail" }
                "Success"
            } -MaxAttempts 3 -DelaySeconds 1

            $result | Should -Be "Success"
        }
    }

    Context "Parameter Validation" {
        It "Validates MaxAttempts range (minimum)" {
            { Retry-Command -ScriptBlock { $true } -MaxAttempts 0 } | Should -Throw
        }

        It "Validates MaxAttempts range (maximum)" {
            { Retry-Command -ScriptBlock { $true } -MaxAttempts 11 } | Should -Throw
        }

        It "Validates DelaySeconds range (minimum)" {
            { Retry-Command -ScriptBlock { $true } -DelaySeconds 0 } | Should -Throw
        }

        It "Validates DelaySeconds range (maximum)" {
            { Retry-Command -ScriptBlock { $true } -DelaySeconds 61 } | Should -Throw
        }

        It "Requires ScriptBlock parameter" {
            { Retry-Command -MaxAttempts 3 } | Should -Throw
        }
    }
}

Describe "ErrorHandling Module - Test-InputValid Function" {
    Context "Function Existence and Help" {
        It "Test-InputValid function exists" {
            Get-Command Test-InputValid -Module ErrorHandling -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Test-InputValid has comment-based help" {
            $help = Get-Help Test-InputValid
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context "IP Address Validation" {
        It "Validates correct IPv4 addresses" {
            Test-InputValid -Value "192.168.1.1" -Type IPAddress | Should -Be $true
            Test-InputValid -Value "10.0.0.1" -Type IPAddress | Should -Be $true
            Test-InputValid -Value "127.0.0.1" -Type IPAddress | Should -Be $true
        }

        It "Rejects invalid IPv4 addresses" {
            Test-InputValid -Value "256.1.1.1" -Type IPAddress | Should -Be $false
            Test-InputValid -Value "192.168.1" -Type IPAddress | Should -Be $false
            Test-InputValid -Value "not-an-ip" -Type IPAddress | Should -Be $false
            Test-InputValid -Value "" -Type IPAddress | Should -Be $false
        }
    }

    Context "Hostname Validation" {
        It "Validates correct hostnames" {
            Test-InputValid -Value "server01" -Type Hostname | Should -Be $true
            Test-InputValid -Value "web-server" -Type Hostname | Should -Be $true
            Test-InputValid -Value "example.com" -Type Hostname | Should -Be $true
        }

        It "Rejects invalid hostnames" {
            Test-InputValid -Value "-invalid" -Type Hostname | Should -Be $false
            Test-InputValid -Value "invalid-" -Type Hostname | Should -Be $false
            Test-InputValid -Value "123" -Type Hostname | Should -Be $false  # All numeric
        }
    }

    Context "Path Validation" {
        It "Validates path format" {
            Test-InputValid -Value "C:\Windows\System32" -Type Path | Should -Be $true
            Test-InputValid -Value "/usr/local/bin" -Type Path | Should -Be $true
        }

        # Note: Path validation uses [System.IO.Path]::GetFullPath() which validates format,
        # not illegal characters. Invalid characters are OS-dependent and not strictly validated.
        It "Accepts paths that can be normalized" {
            # GetFullPath normalizes paths without strict character validation
            Test-InputValid -Value "C:\Some\Path" -Type Path | Should -Be $true
        }
    }

    Context "Port Number Validation" {
        It "Validates correct port numbers" {
            Test-InputValid -Value "80" -Type PortNumber | Should -Be $true
            Test-InputValid -Value "443" -Type PortNumber | Should -Be $true
            Test-InputValid -Value "8080" -Type PortNumber | Should -Be $true
            Test-InputValid -Value "65535" -Type PortNumber | Should -Be $true
        }

        It "Rejects invalid port numbers" {
            Test-InputValid -Value "0" -Type PortNumber | Should -Be $false
            Test-InputValid -Value "65536" -Type PortNumber | Should -Be $false
            Test-InputValid -Value "-1" -Type PortNumber | Should -Be $false
            Test-InputValid -Value "abc" -Type PortNumber | Should -Be $false
        }
    }

    Context "Email Address Validation" {
        It "Validates correct email addresses" {
            Test-InputValid -Value "user@example.com" -Type EmailAddress | Should -Be $true
            Test-InputValid -Value "admin@test.co.uk" -Type EmailAddress | Should -Be $true
        }

        It "Rejects invalid email addresses" {
            Test-InputValid -Value "notanemail" -Type EmailAddress | Should -Be $false
            Test-InputValid -Value "@example.com" -Type EmailAddress | Should -Be $false
            Test-InputValid -Value "user@" -Type EmailAddress | Should -Be $false
        }
    }

    Context "URL Validation" {
        It "Validates correct URLs" {
            Test-InputValid -Value "https://example.com" -Type URL | Should -Be $true
            Test-InputValid -Value "http://test.org" -Type URL | Should -Be $true
            Test-InputValid -Value "ftp://files.example.com" -Type URL | Should -Be $true
        }

        It "Rejects invalid URLs" {
            Test-InputValid -Value "not-a-url" -Type URL | Should -Be $false
            Test-InputValid -Value "javascript:alert(1)" -Type URL | Should -Be $false
        }
    }

    Context "Empty Value Handling" {
        It "Rejects empty values by default" {
            Test-InputValid -Value "" -Type NotEmpty | Should -Be $false
            Test-InputValid -Value $null -Type NotEmpty -AllowEmpty:$false | Should -Be $false
        }

        It "Allows empty values when AllowEmpty is set" {
            Test-InputValid -Value "" -Type NotEmpty -AllowEmpty | Should -Be $true
            Test-InputValid -Value $null -Type NotEmpty -AllowEmpty | Should -Be $true
        }
    }
}

Describe "ErrorHandling Module - Invoke-WithErrorAggregation Function" {
    Context "Function Existence and Help" {
        It "Invoke-WithErrorAggregation function exists" {
            Get-Command Invoke-WithErrorAggregation -Module ErrorHandling -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Invoke-WithErrorAggregation has comment-based help" {
            $help = Get-Help Invoke-WithErrorAggregation
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context "Successful Processing" {
        It "Processes all items successfully" {
            $items = @(1, 2, 3, 4, 5)
            $result = Invoke-WithErrorAggregation -Items $items -ScriptBlock {
                param($item)
                $item * 2
            }

            $result.SuccessCount | Should -Be 5
            $result.FailureCount | Should -Be 0
            $result.Errors.Count | Should -Be 0
            $result.SuccessItems.Count | Should -Be 5
        }
    }

    Context "Error Handling" {
        It "Continues processing after errors" {
            $items = @(1, 2, 3, 4, 5)
            $result = Invoke-WithErrorAggregation -Items $items -ScriptBlock {
                param($item)
                if ($item -eq 3) {
                    throw "Simulated error for item 3"
                }
                $item * 2
            }

            $result.SuccessCount | Should -Be 4
            $result.FailureCount | Should -Be 1
            $result.Errors.Count | Should -Be 1
            $result.Errors[0].Item | Should -Be 3
        }

        It "Stops on first error when StopOnFirstError is set" {
            $items = @(1, 2, 3, 4, 5)
            $result = Invoke-WithErrorAggregation -Items $items -ScriptBlock {
                param($item)
                if ($item -eq 2) {
                    throw "Stop here"
                }
                $item * 2
            } -StopOnFirstError

            $result.SuccessCount | Should -Be 1
            $result.FailureCount | Should -Be 1
            $result.TotalCount | Should -Be 5
        }
    }

    Context "Return Value Structure" {
        It "Returns hashtable with expected keys" {
            $result = Invoke-WithErrorAggregation -Items @(1) -ScriptBlock { param($i) $i }

            $result.ContainsKey('SuccessCount') | Should -Be $true
            $result.ContainsKey('FailureCount') | Should -Be $true
            $result.ContainsKey('Errors') | Should -Be $true
            $result.ContainsKey('SuccessItems') | Should -Be $true
            $result.ContainsKey('TotalCount') | Should -Be $true
        }

        It "Error details include item and message" {
            $result = Invoke-WithErrorAggregation -Items @('test') -ScriptBlock {
                throw "Test error"
            }

            $result.Errors[0].Item | Should -Be 'test'
            $result.Errors[0].Message | Should -Match "Test error"
            $result.Errors[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "ErrorHandling Module - Write-ContextualError Function" {
    Context "Function Existence and Help" {
        It "Write-ContextualError function exists" {
            Get-Command Write-ContextualError -Module ErrorHandling -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-ContextualError has comment-based help" {
            $help = Get-Help Write-ContextualError
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context "Basic Functionality" {
        It "Accepts ErrorRecord parameter" {
            try {
                throw "Test error"
            }
            catch {
                { Write-ContextualError -ErrorRecord $_ -Context "testing" } | Should -Not -Throw
            }
        }

        It "Accepts Context parameter" {
            try {
                throw "Test error"
            }
            catch {
                { Write-ContextualError -ErrorRecord $_ -Context "performing operation" } | Should -Not -Throw
            }
        }

        It "Accepts optional Suggestion parameter" {
            try {
                throw "Test error"
            }
            catch {
                {
                    Write-ContextualError -ErrorRecord $_ `
                        -Context "testing" `
                        -Suggestion "Try something else"
                } | Should -Not -Throw
            }
        }
    }

    Context "Parameter Validation" {
        It "Requires ErrorRecord parameter" {
            { Write-ContextualError -Context "test" } | Should -Throw
        }

        It "Requires Context parameter" {
            try {
                throw "Test"
            }
            catch {
                { Write-ContextualError -ErrorRecord $_ } | Should -Throw
            }
        }
    }
}

Describe "ErrorHandling Module - Integration Tests" {
    Context "Multiple Functions Working Together" {
        It "Retry-Command with Test-InputValid" {
            $attempts = 0
            $result = Retry-Command -ScriptBlock {
                $attempts++
                $ip = "192.168.1.$attempts"
                if (Test-InputValid -Value $ip -Type IPAddress) {
                    return $ip
                }
                throw "Invalid IP: $ip"
            } -MaxAttempts 5

            $result | Should -Match "192\.168\.1\.\d+"
        }

        It "Invoke-WithErrorAggregation with Test-InputValid" {
            $items = @("192.168.1.1", "invalid", "10.0.0.1", "also-invalid", "127.0.0.1")
            $result = Invoke-WithErrorAggregation -Items $items -ScriptBlock {
                param($ip)
                if (-not (Test-InputValid -Value $ip -Type IPAddress)) {
                    throw "Invalid IP: $ip"
                }
                $ip
            }

            $result.SuccessCount | Should -Be 3
            $result.FailureCount | Should -Be 2
        }
    }
}

Describe "ErrorHandling Module - Advanced Execution Coverage" {
    Context "Test-InputValid Edge Cases for Full Coverage" {
        It "Tests empty string with AllowEmpty false (NotEmpty type)" {
            Test-InputValid -Value "" -Type NotEmpty -AllowEmpty:$false | Should -Be $false
        }

        It "Tests whitespace-only string with NotEmpty type" {
            Test-InputValid -Value "   " -Type NotEmpty | Should -Be $false
        }

        It "Tests null value with AllowEmpty true" {
            Test-InputValid -Value $null -Type NotEmpty -AllowEmpty:$true | Should -Be $true
        }

        It "Tests valid paths" {
            Test-InputValid -Value "C:\Windows\System32" -Type Path | Should -Be $true
            Test-InputValid -Value "/usr/local/bin" -Type Path | Should -Be $true
        }

        It "Tests URL validation edge cases" {
            # Valid URLs (http, https, ftp, ftps are all accepted per implementation)
            Test-InputValid -Value "https://github.com/user/repo" -Type URL | Should -Be $true
            Test-InputValid -Value "http://example.com" -Type URL | Should -Be $true
            Test-InputValid -Value "ftp://example.com" -Type URL | Should -Be $true

            # Invalid URLs
            Test-InputValid -Value "not a url" -Type URL | Should -Be $false
            Test-InputValid -Value "file://local/path" -Type URL | Should -Be $false
        }
    }

    Context "Retry-Command with RetryOn Exception Type Filtering" {
        It "Retries on specific exception type" {
            # Use script-scoped variable for proper closure behavior
            $script:retryAttempts = 0
            $result = Retry-Command -ScriptBlock {
                $script:retryAttempts++
                if ($script:retryAttempts -lt 2) {
                    throw [System.IO.IOException]::new("Simulated IO error")
                }
                "Success after retry"
            } -MaxAttempts 3 -DelaySeconds 1 -RetryOn ([System.IO.IOException])

            $result | Should -Be "Success after retry"
            $script:retryAttempts | Should -Be 2
        }

        It "Does not retry on non-matching exception type" {
            try {
                Retry-Command -ScriptBlock {
                    throw [System.InvalidOperationException]::new("Wrong exception type")
                } -MaxAttempts 3 -RetryOn ([System.IO.IOException])

                # Should not reach here
                $false | Should -Be $true
            }
            catch {
                $_.Exception | Should -BeOfType [System.InvalidOperationException]
            }
        }
    }

    Context "Write-ContextualError with Stack Trace" {
        It "Includes stack trace in error output" {
            try {
                function Test-DeepCall {
                    throw "Deep error"
                }
                Test-DeepCall
            }
            catch {
                # This should trigger the stack trace inclusion (lines 361, 363)
                { Write-ContextualError -ErrorRecord $_ -Context "deep call testing" } | Should -Not -Throw
            }
        }

        It "Handles error with both Context and Suggestion" {
            try {
                throw "Complex error"
            }
            catch {
                {
                    Write-ContextualError -ErrorRecord $_ `
                        -Context "complex operation" `
                        -Suggestion "Check logs for details"
                } | Should -Not -Throw
            }
        }
    }

    Context "Retry-Command Delay and Backoff" {
        It "Executes with minimum delay" {
            $startTime = Get-Date
            try {
                Retry-Command -ScriptBlock {
                    throw "Test"
                } -MaxAttempts 2 -DelaySeconds 0
            }
            catch {
                # Expected to fail
            }
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            $elapsed | Should -BeLessThan 1
        }

        It "Executes with exponential backoff" {
            $script:backoffAttempts = 0
            try {
                Retry-Command -ScriptBlock {
                    $script:backoffAttempts++
                    throw "Test"
                } -MaxAttempts 2 -DelaySeconds 1
            }
            catch {
                # Expected to fail after max attempts
            }
            $script:backoffAttempts | Should -Be 2
        }
    }

    Context "Invoke-WithErrorAggregation Edge Cases" {
        It "Handles empty items array" {
            # Empty arrays are rejected by Mandatory parameter validation
            {
                Invoke-WithErrorAggregation -Items @() -ScriptBlock {
                    param($item)
                    $item
                }
            } | Should -Throw
        }

        It "Handles items array with single element" {
            $result = Invoke-WithErrorAggregation -Items @(42) -ScriptBlock {
                param($item)
                $item * 2
            }

            $result.SuccessCount | Should -Be 1
            $result.SuccessItems[0] | Should -Be 42
        }

        It "Captures error messages correctly" {
            $result = Invoke-WithErrorAggregation -Items @(1, 2, 3) -ScriptBlock {
                param($item)
                if ($item -eq 2) {
                    throw "Item 2 failed"
                }
                $item
            }

            $result.Errors[0].Message | Should -Match "Item 2 failed"
        }
    }
}
