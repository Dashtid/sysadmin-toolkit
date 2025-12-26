# Pester Tests for Windows Monitoring Scripts
# Run: Invoke-Pester -Path .\tests\Windows\Monitoring.Tests.ps1
# Created: 2025-11-30

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $MonitoringPath = Join-Path $ProjectRoot "Windows\monitoring"
    $BackupPath = Join-Path $ProjectRoot "Windows\backup"
    $LibPath = Join-Path $ProjectRoot "Windows\lib"

    # Import test helpers
    $TestHelpersPath = Join-Path $PSScriptRoot "..\TestHelpers.psm1"
    if (Test-Path $TestHelpersPath) {
        Import-Module $TestHelpersPath -Force
    }

    # Import CommonFunctions for testing
    $CommonFunctionsPath = Join-Path $LibPath "CommonFunctions.psm1"
    if (Test-Path $CommonFunctionsPath) {
        Import-Module $CommonFunctionsPath -Force
    }
}

AfterAll {
    Remove-Module TestHelpers -ErrorAction SilentlyContinue
    Remove-Module CommonFunctions -ErrorAction SilentlyContinue
}

Describe "Monitoring Script Existence" {
    Context "Core Monitoring Scripts" {
        It "Get-SystemPerformance.ps1 should exist" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $scriptPath | Should -Exist
        }

        It "Watch-ServiceHealth.ps1 should exist" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $scriptPath | Should -Exist
        }

        It "Test-NetworkHealth.ps1 should exist" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $scriptPath | Should -Exist
        }

        It "Get-EventLogAnalysis.ps1 should exist" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $scriptPath | Should -Exist
        }
    }

    Context "Backup Scripts" {
        It "Backup-UserData.ps1 should exist" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $scriptPath | Should -Exist
        }
    }
}

Describe "Monitoring Script Syntax Validation" {
    Context "PowerShell Syntax" {
        It "Get-SystemPerformance.ps1 has valid syntax" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Watch-ServiceHealth.ps1 has valid syntax" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Test-NetworkHealth.ps1 has valid syntax" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Get-EventLogAnalysis.ps1 has valid syntax" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Backup-UserData.ps1 has valid syntax" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }
}

Describe "Monitoring Script Requirements" {
    Context "PowerShell Version Requirements" {
        It "Get-SystemPerformance.ps1 requires PowerShell 5.1+" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "#Requires -Version 5\.1"
        }

        It "Watch-ServiceHealth.ps1 requires PowerShell 5.1+" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "#Requires -Version 5\.1"
        }

        It "Test-NetworkHealth.ps1 requires PowerShell 5.1+" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "#Requires -Version 5\.1"
        }

        It "Get-EventLogAnalysis.ps1 requires PowerShell 5.1+" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "#Requires -Version 5\.1"
        }

        It "Backup-UserData.ps1 requires PowerShell 5.1+" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "#Requires -Version 5\.1"
        }
    }
}

Describe "Monitoring Script Documentation" {
    Context "Comment-Based Help" {
        It "Get-SystemPerformance.ps1 has SYNOPSIS" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Get-SystemPerformance.ps1 has DESCRIPTION" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.DESCRIPTION"
        }

        It "Get-SystemPerformance.ps1 has EXAMPLE" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.EXAMPLE"
        }

        It "Watch-ServiceHealth.ps1 has SYNOPSIS" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Test-NetworkHealth.ps1 has SYNOPSIS" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Get-EventLogAnalysis.ps1 has SYNOPSIS" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }

        It "Backup-UserData.ps1 has SYNOPSIS" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "\.SYNOPSIS"
        }
    }
}

Describe "Monitoring Script Parameters" {
    Context "Get-SystemPerformance Parameters" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has OutputFormat parameter" {
            $scriptContent | Should -Match '\[string\]\$OutputFormat'
        }

        It "Has OutputPath parameter" {
            $scriptContent | Should -Match '\[string\]\$OutputPath'
        }

        It "Has SampleCount parameter" {
            $scriptContent | Should -Match '\[int\]\$SampleCount'
        }

        It "Has Thresholds parameter" {
            $scriptContent | Should -Match '\[hashtable\]\$Thresholds'
        }

        It "OutputFormat has valid ValidateSet" {
            $scriptContent | Should -Match "ValidateSet\('Console', 'HTML', 'JSON', 'CSV', 'Prometheus', 'All'\)"
        }
    }

    Context "Watch-ServiceHealth Parameters" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Services parameter" {
            $scriptContent | Should -Match '\[string\[\]\]\$Services'
        }

        It "Has AutoRestart parameter" {
            $scriptContent | Should -Match '\[switch\]\$AutoRestart'
        }

        It "Has MaxRestartAttempts parameter" {
            $scriptContent | Should -Match '\[int\]\$MaxRestartAttempts'
        }

        It "Has MonitorInterval parameter" {
            $scriptContent | Should -Match '\[int\]\$MonitorInterval'
        }
    }

    Context "Test-NetworkHealth Parameters" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Hosts parameter" {
            $scriptContent | Should -Match '\[string\[\]\]\$Hosts'
        }

        It "Has Ports parameter" {
            $scriptContent | Should -Match '\[int\[\]\]\$Ports'
        }

        It "Has SkipDNS parameter" {
            $scriptContent | Should -Match '\[switch\]\$SkipDNS'
        }

        It "Has QuickTest parameter" {
            $scriptContent | Should -Match '\[switch\]\$QuickTest'
        }
    }

    Context "Get-EventLogAnalysis Parameters" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has LogNames parameter" {
            $scriptContent | Should -Match '\[string\[\]\]\$LogNames'
        }

        It "Has Hours parameter" {
            $scriptContent | Should -Match '\[int\]\$Hours'
        }

        It "Has Level parameter" {
            $scriptContent | Should -Match '\[string\]\$Level'
        }

        It "Has IncludeSecurityAnalysis parameter" {
            $scriptContent | Should -Match '\[switch\]\$IncludeSecurityAnalysis'
        }

        It "Has IncludeFailedLogons parameter" {
            $scriptContent | Should -Match '\[switch\]\$IncludeFailedLogons'
        }
    }

    Context "Backup-UserData Parameters" {
        BeforeAll {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has BackupType parameter" {
            $scriptContent | Should -Match '\[string\]\$BackupType'
        }

        It "Has Destination parameter" {
            $scriptContent | Should -Match '\[string\]\$Destination'
        }

        It "Has SourceFolders parameter" {
            $scriptContent | Should -Match '\[string\[\]\]\$SourceFolders'
        }

        It "Has RetentionCount parameter" {
            $scriptContent | Should -Match '\[int\]\$RetentionCount'
        }

        It "Has VerifyBackup parameter" {
            $scriptContent | Should -Match '\[switch\]\$VerifyBackup'
        }

        It "Has DryRun parameter" {
            $scriptContent | Should -Match '\[switch\]\$DryRun'
        }

        It "BackupType has valid ValidateSet" {
            $scriptContent | Should -Match "ValidateSet\('Full', 'Incremental', 'Differential'\)"
        }
    }
}

Describe "Monitoring Script Output Formats" {
    Context "HTML Report Generation" {
        It "Get-SystemPerformance has Export-HTMLReport function" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-HTMLReport"
        }

        It "Watch-ServiceHealth has Export-HTMLReport function" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-HTMLReport"
        }

        It "Test-NetworkHealth has Export-HTMLReport function" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-HTMLReport"
        }

        It "Get-EventLogAnalysis has Export-HTMLReport function" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-HTMLReport"
        }
    }

    Context "JSON Report Generation" {
        It "Get-SystemPerformance has Export-JSONReport function" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-JSONReport"
        }

        It "Watch-ServiceHealth has Export-JSONReport function" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-JSONReport"
        }

        It "Test-NetworkHealth has Export-JSONReport function" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Export-JSONReport"
        }
    }

    Context "Console Report Generation" {
        It "Get-SystemPerformance has Write-ConsoleReport function" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Write-ConsoleReport"
        }

        It "Watch-ServiceHealth has Write-ConsoleReport function" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "function Write-ConsoleReport"
        }
    }
}

Describe "Monitoring Script Features" {
    Context "Get-SystemPerformance Features" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Get-PerformanceMetrics function" {
            $scriptContent | Should -Match "function Get-PerformanceMetrics"
        }

        It "Has Get-ThresholdAlerts function" {
            $scriptContent | Should -Match "function Get-ThresholdAlerts"
        }

        It "Has Get-TopProcesses function" {
            $scriptContent | Should -Match "function Get-TopProcesses"
        }

        It "Has Get-SystemInfo function" {
            $scriptContent | Should -Match "function Get-SystemInfo"
        }

        It "Uses Get-Counter for performance metrics" {
            $scriptContent | Should -Match "Get-Counter"
        }

        It "Monitors CPU metrics" {
            $scriptContent | Should -Match "Processor.*% Processor Time"
        }

        It "Monitors memory metrics" {
            $scriptContent | Should -Match "Memory.*Available MBytes"
        }

        It "Monitors disk metrics" {
            $scriptContent | Should -Match "PhysicalDisk.*% Disk Time"
        }
    }

    Context "Watch-ServiceHealth Features" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Get-ServiceStatus function" {
            $scriptContent | Should -Match "function Get-ServiceStatus"
        }

        It "Has Restart-ServiceWithRetry function" {
            $scriptContent | Should -Match "function Restart-ServiceWithRetry"
        }

        It "Has Get-ServiceHealthReport function" {
            $scriptContent | Should -Match "function Get-ServiceHealthReport"
        }

        It "Has Test-ServiceShouldMonitor function" {
            $scriptContent | Should -Match "function Test-ServiceShouldMonitor"
        }

        It "Uses Get-Service cmdlet" {
            $scriptContent | Should -Match "Get-Service"
        }

        It "Checks for delayed start services" {
            $scriptContent | Should -Match "DelayedAutostart"
        }

        It "Has default critical services list" {
            $scriptContent | Should -Match "DefaultServices"
        }
    }

    Context "Test-NetworkHealth Features" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Test-HostConnectivity function" {
            $scriptContent | Should -Match "function Test-HostConnectivity"
        }

        It "Has Test-PortConnectivity function" {
            $scriptContent | Should -Match "function Test-PortConnectivity"
        }

        It "Has Test-DNSResolution function" {
            $scriptContent | Should -Match "function Test-DNSResolution"
        }

        It "Has Invoke-Traceroute function" {
            $scriptContent | Should -Match "function Invoke-Traceroute"
        }

        It "Has Get-NetworkAdapterInfo function" {
            $scriptContent | Should -Match "function Get-NetworkAdapterInfo"
        }

        It "Uses Test-Connection for ping" {
            $scriptContent | Should -Match "Test-Connection"
        }

        It "Uses Resolve-DnsName for DNS" {
            $scriptContent | Should -Match "Resolve-DnsName"
        }

        It "Has common ports definition" {
            $scriptContent | Should -Match "CommonPorts"
        }
    }

    Context "Get-EventLogAnalysis Features" {
        BeforeAll {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Get-FilteredEvents function" {
            $scriptContent | Should -Match "function Get-FilteredEvents"
        }

        It "Has Get-SecurityAnalysis function" {
            $scriptContent | Should -Match "function Get-SecurityAnalysis"
        }

        It "Has Get-FailedLogonDetails function" {
            $scriptContent | Should -Match "function Get-FailedLogonDetails"
        }

        It "Has Get-SystemIssues function" {
            $scriptContent | Should -Match "function Get-SystemIssues"
        }

        It "Has Get-ApplicationIssues function" {
            $scriptContent | Should -Match "function Get-ApplicationIssues"
        }

        It "Uses Get-WinEvent cmdlet" {
            $scriptContent | Should -Match "Get-WinEvent"
        }

        It "Has security event IDs definition" {
            $scriptContent | Should -Match "SecurityEventIds"
        }

        It "Has system event IDs definition" {
            $scriptContent | Should -Match "SystemEventIds"
        }

        It "Tracks failed logons (Event ID 4625)" {
            $scriptContent | Should -Match "4625"
        }
    }

    Context "Backup-UserData Features" {
        BeforeAll {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $scriptContent = Get-Content $scriptPath -Raw
        }

        It "Has Get-FilesToBackup function" {
            $scriptContent | Should -Match "function Get-FilesToBackup"
        }

        It "Has Copy-BackupFiles function" {
            $scriptContent | Should -Match "function Copy-BackupFiles"
        }

        It "Has Compress-BackupFolder function" {
            $scriptContent | Should -Match "function Compress-BackupFolder"
        }

        It "Has Test-BackupIntegrity function" {
            $scriptContent | Should -Match "function Test-BackupIntegrity"
        }

        It "Has Remove-OldBackups function" {
            $scriptContent | Should -Match "function Remove-OldBackups"
        }

        It "Has Get-BackupMetadata function" {
            $scriptContent | Should -Match "function Get-BackupMetadata"
        }

        It "Supports ShouldProcess for safety" {
            $scriptContent | Should -Match "SupportsShouldProcess"
        }

        It "Uses Compress-Archive for compression" {
            $scriptContent | Should -Match "Compress-Archive"
        }

        It "Has file exclusion patterns" {
            $scriptContent | Should -Match "ExcludeFolders"
        }
    }
}

Describe "Monitoring Script Error Handling" {
    Context "Error Handling Patterns" {
        It "Get-SystemPerformance uses try-catch" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Watch-ServiceHealth uses try-catch" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Test-NetworkHealth uses try-catch" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Get-EventLogAnalysis uses try-catch" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }

        It "Backup-UserData uses try-catch" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "try\s*\{"
            $content | Should -Match "catch\s*\{"
        }
    }

    Context "Exit Codes" {
        It "Get-SystemPerformance has exit code handling" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "exit 1"
        }

        It "Watch-ServiceHealth has exit code handling" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "exit 1"
        }

        It "Test-NetworkHealth has exit code handling" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "exit 1"
        }

        It "Get-EventLogAnalysis has exit code handling" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "exit 1"
        }

        It "Backup-UserData has exit code handling" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "exit 1"
        }
    }
}

Describe "Monitoring Script Logging" {
    Context "CommonFunctions Integration" {
        It "Get-SystemPerformance imports CommonFunctions" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "CommonFunctions\.psm1"
        }

        It "Watch-ServiceHealth imports CommonFunctions" {
            $scriptPath = Join-Path $MonitoringPath "Watch-ServiceHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "CommonFunctions\.psm1"
        }

        It "Test-NetworkHealth imports CommonFunctions" {
            $scriptPath = Join-Path $MonitoringPath "Test-NetworkHealth.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "CommonFunctions\.psm1"
        }

        It "Get-EventLogAnalysis imports CommonFunctions" {
            $scriptPath = Join-Path $MonitoringPath "Get-EventLogAnalysis.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "CommonFunctions\.psm1"
        }

        It "Backup-UserData imports CommonFunctions" {
            $scriptPath = Join-Path $BackupPath "Backup-UserData.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "CommonFunctions\.psm1"
        }
    }

    Context "Standard Logging Functions" {
        It "Scripts use Write-InfoMessage" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Write-InfoMessage"
        }

        It "Scripts use Write-Success" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Write-Success"
        }

        It "Scripts use Write-ErrorMessage" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Write-ErrorMessage"
        }

        It "Scripts use Write-WarningMessage" {
            $scriptPath = Join-Path $MonitoringPath "Get-SystemPerformance.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Write-WarningMessage"
        }
    }
}
