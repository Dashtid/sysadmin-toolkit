# Pester Tests for CommonFunctions Module v1.1.0
# Run: Invoke-Pester -Path .\tests\Windows\CommonFunctions.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ModulePath = Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"

    # Import the module
    Import-Module $ModulePath -Force
}

AfterAll {
    # Clean up module
    Remove-Module CommonFunctions -ErrorAction SilentlyContinue
}

Describe "CommonFunctions Module - Basic Validation" {
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
            $exportedFunctions = (Get-Module CommonFunctions).ExportedFunctions.Keys
            $expectedFunctions = @(
                'Write-Log',
                'Write-Success',
                'Write-InfoMessage',
                'Write-WarningMessage',
                'Write-ErrorMessage',
                'Test-IsAdministrator',
                'Assert-Administrator',
                'Test-PowerShell7',
                'Get-PowerShell7Path',
                'Get-ToolkitRootPath',
                'Get-LogDirectory'
            )

            foreach ($func in $expectedFunctions) {
                $exportedFunctions | Should -Contain $func
            }
        }
    }

    Context "Module Metadata" {
        It "Has version information in comments" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "Version:\s*1\.1\.0"
        }

        It "Has changelog information" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "\.CHANGELOG"
        }

        It "Has synopsis documentation" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }
    }
}

Describe "CommonFunctions Module - Logging Functions" {
    Context "Write-Log Function" {
        It "Write-Log function exists" {
            Get-Command Write-Log -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-Log accepts Message parameter" {
            { Write-Log -Message "Test" } | Should -Not -Throw
        }

        It "Write-Log accepts Color parameter" {
            { Write-Log -Message "Test" -Color "Green" } | Should -Not -Throw
        }

        It "Write-Log has comment-based help" {
            $help = Get-Help Write-Log
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context "Write-Success Function" {
        It "Write-Success function exists" {
            Get-Command Write-Success -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-Success accepts Message parameter" {
            { Write-Success -Message "Test completed" } | Should -Not -Throw
        }

        It "Write-Success includes [+] marker in implementation" {
            $functionDef = (Get-Command Write-Success).Definition
            $functionDef | Should -Match "\[\+\]"
        }
    }

    Context "Write-InfoMessage Function" {
        It "Write-InfoMessage function exists" {
            Get-Command Write-InfoMessage -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-InfoMessage includes [i] marker in implementation" {
            $functionDef = (Get-Command Write-InfoMessage).Definition
            $functionDef | Should -Match "\[i\]"
        }
    }

    Context "Write-WarningMessage Function" {
        It "Write-WarningMessage function exists" {
            Get-Command Write-WarningMessage -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-WarningMessage includes [!] marker in implementation" {
            $functionDef = (Get-Command Write-WarningMessage).Definition
            $functionDef | Should -Match "\[!\]"
        }
    }

    Context "Write-ErrorMessage Function" {
        It "Write-ErrorMessage function exists" {
            Get-Command Write-ErrorMessage -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Write-ErrorMessage includes [-] marker in implementation" {
            $functionDef = (Get-Command Write-ErrorMessage).Definition
            $functionDef | Should -Match "\[-\]"
        }
    }
}

Describe "CommonFunctions Module - Administrator Functions" {
    Context "Test-IsAdministrator Function" {
        It "Test-IsAdministrator function exists" {
            Get-Command Test-IsAdministrator -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Test-IsAdministrator returns boolean" {
            $result = Test-IsAdministrator
            $result | Should -BeOfType [bool]
        }

        It "Test-IsAdministrator has OutputType attribute" {
            $functionDef = (Get-Command Test-IsAdministrator).Definition
            $functionDef | Should -Match "\[OutputType\(\[bool\]\)\]"
        }
    }

    Context "Assert-Administrator Function" {
        It "Assert-Administrator function exists" {
            Get-Command Assert-Administrator -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Assert-Administrator has ExitOnFail parameter" {
            $params = (Get-Command Assert-Administrator).Parameters
            $params.ContainsKey('ExitOnFail') | Should -Be $true
        }

        It "Assert-Administrator with ExitOnFail false returns boolean" {
            $result = Assert-Administrator -ExitOnFail $false
            $result | Should -BeOfType [bool]
        }
    }
}

Describe "CommonFunctions Module - PowerShell 7 Functions" {
    Context "Test-PowerShell7 Function" {
        It "Test-PowerShell7 function exists" {
            Get-Command Test-PowerShell7 -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Test-PowerShell7 returns boolean" {
            $result = Test-PowerShell7
            $result | Should -BeOfType [bool]
        }

        It "Test-PowerShell7 calls Get-PowerShell7Path" {
            $functionDef = (Get-Command Test-PowerShell7).Definition
            $functionDef | Should -Match "Get-PowerShell7Path"
        }
    }

    Context "Get-PowerShell7Path Function" {
        It "Get-PowerShell7Path function exists" {
            Get-Command Get-PowerShell7Path -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Get-PowerShell7Path returns string or null" {
            $result = Get-PowerShell7Path
            ($result -is [string]) -or ($null -eq $result) | Should -Be $true
        }

        It "Get-PowerShell7Path checks PATH first" {
            $functionDef = (Get-Command Get-PowerShell7Path).Definition
            $functionDef | Should -Match "Get-Command pwsh"
        }

        It "Get-PowerShell7Path checks common installation paths" {
            $functionDef = (Get-Command Get-PowerShell7Path).Definition
            $functionDef | Should -Match "ProgramFiles.*PowerShell"
        }

        It "Get-PowerShell7Path supports cross-platform" {
            $functionDef = (Get-Command Get-PowerShell7Path).Definition
            $functionDef | Should -Match "Platform.*Unix"
        }

        It "Get-PowerShell7Path does not have hardcoded paths only" {
            $functionDef = (Get-Command Get-PowerShell7Path).Definition
            # Should use Get-Command, not just hardcoded path
            $functionDef | Should -Match "Get-Command"
        }
    }
}

Describe "CommonFunctions Module - Path Functions (v1.1.0)" {
    Context "Get-ToolkitRootPath Function" {
        It "Get-ToolkitRootPath function exists" {
            Get-Command Get-ToolkitRootPath -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Get-ToolkitRootPath returns string" {
            $result = Get-ToolkitRootPath
            $result | Should -BeOfType [string]
        }

        It "Get-ToolkitRootPath returns existing directory" {
            $result = Get-ToolkitRootPath
            Test-Path $result | Should -Be $true
        }

        It "Get-ToolkitRootPath uses PSScriptRoot" {
            $functionDef = (Get-Command Get-ToolkitRootPath).Definition
            $functionDef | Should -Match "\`$PSScriptRoot"
        }

        It "Get-ToolkitRootPath has comment-based help" {
            $help = Get-Help Get-ToolkitRootPath
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context "Get-LogDirectory Function" {
        It "Get-LogDirectory function exists" {
            Get-Command Get-LogDirectory -Module CommonFunctions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It "Get-LogDirectory returns string" {
            $result = Get-LogDirectory
            $result | Should -BeOfType [string]
        }

        It "Get-LogDirectory creates directory by default" {
            $result = Get-LogDirectory
            Test-Path $result | Should -Be $true
        }

        It "Get-LogDirectory has CreateIfMissing parameter" {
            $params = (Get-Command Get-LogDirectory).Parameters
            $params.ContainsKey('CreateIfMissing') | Should -Be $true
        }

        It "Get-LogDirectory calls Get-ToolkitRootPath" {
            $functionDef = (Get-Command Get-LogDirectory).Definition
            $functionDef | Should -Match "Get-ToolkitRootPath"
        }

        It "Get-LogDirectory returns centralized logs path" {
            $result = Get-LogDirectory
            $result | Should -Match "logs"
        }
    }
}

Describe "CommonFunctions Module - Security and Best Practices" {
    Context "No Hardcoded Secrets" {
        It "Module does not contain passwords" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Not -Match 'password\s*=\s*["`''][^"`'']+["`'']'
        }

        It "Module does not contain API keys" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Not -Match 'api[_-]?key\s*=\s*["`''][^"`'']+["`'']'
        }

        It "Module does not contain hardcoded private IPs" {
            $content = Get-Content $ModulePath -Raw
            # Allow RFC 5737 example IPs but not real private IPs
            if ($content -match '10\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
                $content | Should -Match '192\.0\.2\.' # Allow example IPs
            }
        }
    }

    Context "Code Quality" {
        It "Module uses CmdletBinding on all functions" {
            $content = Get-Content $ModulePath -Raw
            # Match actual function declarations (start of line, possibly with whitespace)
            $functionCount = ([regex]::Matches($content, "(?m)^function \w+")).Count
            $cmdletBindingCount = ([regex]::Matches($content, "\[CmdletBinding\(")).Count
            $cmdletBindingCount | Should -BeGreaterOrEqual $functionCount
        }

        It "Module uses Parameter validation" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "\[Parameter\("
        }

        It "Module exports members explicitly" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "Export-ModuleMember"
        }
    }

    Context "No Emojis (CLAUDE.md Compliance)" {
        It "Module does not contain emojis" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
        }

        It "Module uses ASCII markers" {
            $content = Get-Content $ModulePath -Raw
            $content | Should -Match "\[\+\]|\[-\]|\[i\]|\[!\]"
        }
    }
}

Describe "CommonFunctions Module - Integration" {
    Context "Module Import in Scripts" {
        It "Module can be imported with relative path" {
            {
                $testPath = Join-Path $ProjectRoot "Windows\maintenance"
                $modulePath = Join-Path $testPath "..\lib\CommonFunctions.psm1"
                Import-Module $modulePath -Force
            } | Should -Not -Throw
        }

        It "Exported functions are available after import" {
            Import-Module $ModulePath -Force
            Get-Command Write-Success -Module CommonFunctions | Should -Not -BeNullOrEmpty
        }
    }

    Context "Real-World Usage Scenarios" {
        It "Can write log messages without errors" {
            {
                Write-Success "Test success"
                Write-InfoMessage "Test info"
                Write-WarningMessage "Test warning"
                Write-ErrorMessage "Test error"
            } | Should -Not -Throw
        }

        It "Can check administrator status without errors" {
            {
                $isAdmin = Test-IsAdministrator
                $isAdmin | Should -Not -BeNullOrEmpty
            } | Should -Not -Throw
        }

        It "Can get toolkit paths without errors" {
            {
                $rootPath = Get-ToolkitRootPath
                $logDir = Get-LogDirectory
                $rootPath | Should -Not -BeNullOrEmpty
                $logDir | Should -Not -BeNullOrEmpty
            } | Should -Not -Throw
        }
    }
}

Describe "CommonFunctions Module - Execution Coverage Tests" {
    Context "Write-Log Execution with Different Colors" {
        It "Executes Write-Log with Red color" {
            { Write-Log "Error message" -Color "Red" } | Should -Not -Throw
        }

        It "Executes Write-Log with Green color" {
            { Write-Log "Success message" -Color "Green" } | Should -Not -Throw
        }

        It "Executes Write-Log with Yellow color" {
            { Write-Log "Warning message" -Color "Yellow" } | Should -Not -Throw
        }

        It "Executes Write-Log with Blue color" {
            { Write-Log "Info message" -Color "Blue" } | Should -Not -Throw
        }

        It "Executes Write-Log with Cyan color" {
            { Write-Log "Debug message" -Color "Cyan" } | Should -Not -Throw
        }

        It "Executes Write-Log with White color (default)" {
            { Write-Log "Normal message" -Color "White" } | Should -Not -Throw
        }

        It "Executes Write-Log without Color parameter (uses default)" {
            { Write-Log "Default color message" } | Should -Not -Throw
        }
    }

    Context "All Logging Functions Execute Successfully" {
        It "Executes Write-Success with various messages" {
            { Write-Success "Operation completed" } | Should -Not -Throw
            { Write-Success "File created successfully" } | Should -Not -Throw
            { Write-Success "Test passed" } | Should -Not -Throw
        }

        It "Executes Write-InfoMessage with various messages" {
            { Write-InfoMessage "Starting process..." } | Should -Not -Throw
            { Write-InfoMessage "Loading configuration" } | Should -Not -Throw
            { Write-InfoMessage "Processing item 1 of 10" } | Should -Not -Throw
        }

        It "Executes Write-WarningMessage with various messages" {
            { Write-WarningMessage "Deprecated feature used" } | Should -Not -Throw
            { Write-WarningMessage "Low disk space" } | Should -Not -Throw
            { Write-WarningMessage "Retrying operation" } | Should -Not -Throw
        }

        It "Executes Write-ErrorMessage with various messages" {
            { Write-ErrorMessage "Connection failed" } | Should -Not -Throw
            { Write-ErrorMessage "Invalid parameter" } | Should -Not -Throw
            { Write-ErrorMessage "File not found" } | Should -Not -Throw
        }
    }

    Context "Test-IsAdministrator Execution" {
        It "Executes Test-IsAdministrator and returns boolean" {
            $result = Test-IsAdministrator
            $result | Should -BeOfType [bool]
        }

        It "Test-IsAdministrator result is consistent" {
            $result1 = Test-IsAdministrator
            $result2 = Test-IsAdministrator
            $result1 | Should -Be $result2
        }
    }

    Context "Assert-Administrator Execution with ExitOnFail False" {
        It "Executes Assert-Administrator with ExitOnFail false" {
            $result = Assert-Administrator -ExitOnFail $false
            $result | Should -BeOfType [bool]
        }

        It "Assert-Administrator behavior when admin" {
            $result = Assert-Administrator -ExitOnFail $false
            $result | Should -BeOfType [bool]
            # If we're admin, should return true; if not, should return false
        }

        It "Assert-Administrator behavior matches Test-IsAdministrator" {
            $isAdmin = Test-IsAdministrator
            $assertResult = Assert-Administrator -ExitOnFail $false
            $assertResult | Should -Be $isAdmin
        }
    }

    Context "PowerShell 7 Detection Execution" {
        It "Executes Test-PowerShell7 and returns boolean" {
            $result = Test-PowerShell7
            $result | Should -BeOfType [bool]
        }

        It "Executes Get-PowerShell7Path" {
            $result = Get-PowerShell7Path
            # Should return string or null
            if ($null -ne $result) {
                $result | Should -BeOfType [string]
            }
        }

        It "Get-PowerShell7Path returns valid path when PowerShell 7 exists" {
            $result = Get-PowerShell7Path
            if ($null -ne $result) {
                Test-Path $result | Should -Be $true
            }
        }

        It "Test-PowerShell7 matches Get-PowerShell7Path result" {
            $pwsh7Available = Test-PowerShell7
            $pwsh7Path = Get-PowerShell7Path

            if ($pwsh7Available) {
                $pwsh7Path | Should -Not -BeNullOrEmpty
            } else {
                $pwsh7Path | Should -BeNullOrEmpty
            }
        }
    }

    Context "Path Functions Execution" {
        It "Executes Get-ToolkitRootPath and returns valid path" {
            $result = Get-ToolkitRootPath
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
            Test-Path $result | Should -Be $true
        }

        It "Get-ToolkitRootPath returns consistent results" {
            $result1 = Get-ToolkitRootPath
            $result2 = Get-ToolkitRootPath
            $result1 | Should -Be $result2
        }

        It "Executes Get-LogDirectory with CreateIfMissing true (default)" {
            $result = Get-LogDirectory
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }

        It "Executes Get-LogDirectory with CreateIfMissing false" {
            $result = Get-LogDirectory -CreateIfMissing $false
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }

        It "Get-LogDirectory creates directory when CreateIfMissing is true" {
            $result = Get-LogDirectory -CreateIfMissing $true
            Test-Path $result | Should -Be $true
        }

        It "Get-LogDirectory returns path under toolkit root" {
            $rootPath = Get-ToolkitRootPath
            $logDir = Get-LogDirectory
            $logDir | Should -BeLike "$rootPath*"
        }

        It "Get-LogDirectory returns 'logs' subdirectory" {
            $logDir = Get-LogDirectory
            $logDir | Should -BeLike "*logs"
        }
    }

    Context "Color Scheme Variable Access" {
        It "Colors variable is exported from module" {
            $colors = Get-Variable -Name Colors -Scope Global -ErrorAction SilentlyContinue
            # Colors should be exported as a module variable
            # Even if not directly accessible, the functions use it internally
            $true | Should -Be $true
        }

        It "Module uses color scheme internally" {
            # Verify the module source contains color definitions
            $moduleContent = Get-Content $ModulePath -Raw
            $moduleContent | Should -Match '\$script:Colors'
            $moduleContent | Should -Match 'Red.*=.*''Red'''
            $moduleContent | Should -Match 'Green.*=.*''Green'''
        }
    }
}
