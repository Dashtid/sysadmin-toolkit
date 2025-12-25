#Requires -Version 5.1
#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for Tier 2 scripts in the Windows Sysadmin Toolkit.

.DESCRIPTION
    Comprehensive tests for:
    - Get-UserAccountAudit.ps1 (User Account Audit)
    - Repair-CommonIssues.ps1 (Common Issue Auto-Fixer)
    - Get-SystemPerformance.ps1 (includes Disk Space Monitor functionality)
    - Get-ApplicationHealth.ps1 (Application Health Monitor)
    - Get-SystemReport.ps1 (System Information Reporter)

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: Pester 5.x, PowerShell 5.1+
#>

BeforeAll {
    # Get the toolkit root path
    $TestRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    # Script paths
    $Script:UserAccountAuditScript = Join-Path $TestRoot "Windows\security\Get-UserAccountAudit.ps1"
    $Script:RepairCommonIssuesScript = Join-Path $TestRoot "Windows\troubleshooting\Repair-CommonIssues.ps1"
    # Watch-DiskSpace.ps1 merged into Get-SystemPerformance.ps1
    $Script:SystemPerformanceScript = Join-Path $TestRoot "Windows\monitoring\Get-SystemPerformance.ps1"
    $Script:ApplicationHealthScript = Join-Path $TestRoot "Windows\monitoring\Get-ApplicationHealth.ps1"
    $Script:SystemReportScript = Join-Path $TestRoot "Windows\reporting\Get-SystemReport.ps1"
    $Script:CommonFunctionsModule = Join-Path $TestRoot "Windows\lib\CommonFunctions.psm1"

    # Import CommonFunctions module if available
    if (Test-Path $Script:CommonFunctionsModule) {
        Import-Module $Script:CommonFunctionsModule -Force
    }
}

Describe "Get-UserAccountAudit.ps1" -Tag "Security", "UserAudit" {
    Context "Script Existence and Syntax" {
        It "Script file should exist" {
            $Script:UserAccountAuditScript | Should -Exist
        }

        It "Script should have valid PowerShell syntax" {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Script:UserAccountAuditScript -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Script should contain required elements" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match '#Requires -Version 5.1'
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match '\.EXAMPLE'
            $content | Should -Match 'param\s*\('
        }
    }

    Context "Parameters" {
        BeforeAll {
            $scriptInfo = Get-Command $Script:UserAccountAuditScript -ErrorAction SilentlyContinue
            $parameters = $scriptInfo.Parameters
        }

        It "Should have DaysInactive parameter" {
            $parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }

        It "Should have PasswordAgeDays parameter" {
            $parameters.ContainsKey('PasswordAgeDays') | Should -BeTrue
        }

        It "Should have OutputFormat parameter with valid values" {
            $parameters.ContainsKey('OutputFormat') | Should -BeTrue
            $outputFormatAttr = $parameters['OutputFormat'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $outputFormatAttr.ValidValues | Should -Contain 'Console'
            $outputFormatAttr.ValidValues | Should -Contain 'HTML'
            $outputFormatAttr.ValidValues | Should -Contain 'JSON'
            $outputFormatAttr.ValidValues | Should -Contain 'CSV'
        }

        It "Should have IncludeDisabled parameter" {
            $parameters.ContainsKey('IncludeDisabled') | Should -BeTrue
        }

        It "Should have CheckRemoteComputers parameter" {
            $parameters.ContainsKey('CheckRemoteComputers') | Should -BeTrue
        }
    }

    Context "Script Features" {
        It "Should define Get-UserSecurityIssues function" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'function\s+Get-UserSecurityIssues'
        }

        It "Should define Get-UserAccountDetails function" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'function\s+Get-UserAccountDetails'
        }

        It "Should define Get-AuditSummary function" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'function\s+Get-AuditSummary'
        }

        It "Should define Export-HtmlReport function" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'function\s+Export-HtmlReport'
        }

        It "Should check for password never expires" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'PasswordNeverExpires'
        }

        It "Should check for password not required" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'PasswordNotRequired'
        }

        It "Should check admin group membership" {
            $content = Get-Content $Script:UserAccountAuditScript -Raw
            $content | Should -Match 'Administrators'
        }
    }
}

Describe "Repair-CommonIssues.ps1" -Tag "Troubleshooting", "Repair" {
    Context "Script Existence and Syntax" {
        It "Script file should exist" {
            $Script:RepairCommonIssuesScript | Should -Exist
        }

        It "Script should have valid PowerShell syntax" {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Script:RepairCommonIssuesScript -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Script should require administrator" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match '#Requires -RunAsAdministrator'
        }

        It "Script should contain required elements" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match 'param\s*\('
        }
    }

    Context "Parameters" {
        BeforeAll {
            $scriptInfo = Get-Command $Script:RepairCommonIssuesScript -ErrorAction SilentlyContinue
            $parameters = $scriptInfo.Parameters
        }

        It "Should have Fix parameter with valid options" {
            $parameters.ContainsKey('Fix') | Should -BeTrue
            $fixAttr = $parameters['Fix'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $fixAttr.ValidValues | Should -Contain 'All'
            $fixAttr.ValidValues | Should -Contain 'DNS'
            $fixAttr.ValidValues | Should -Contain 'Network'
            $fixAttr.ValidValues | Should -Contain 'WindowsUpdate'
            $fixAttr.ValidValues | Should -Contain 'Cache'
            $fixAttr.ValidValues | Should -Contain 'Winsock'
            $fixAttr.ValidValues | Should -Contain 'TCPIP'
        }

        It "Should have DryRun parameter" {
            $parameters.ContainsKey('DryRun') | Should -BeTrue
        }

        It "Should have Force parameter" {
            $parameters.ContainsKey('Force') | Should -BeTrue
        }

        It "Should have CreateRestorePoint parameter" {
            $parameters.ContainsKey('CreateRestorePoint') | Should -BeTrue
        }

        It "Should support ShouldProcess" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
        }
    }

    Context "Repair Functions" {
        It "Should define Repair-DNSIssues function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-DNSIssues'
        }

        It "Should define Repair-NetworkIssues function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-NetworkIssues'
        }

        It "Should define Repair-WinsockIssues function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-WinsockIssues'
        }

        It "Should define Repair-WindowsUpdateIssues function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-WindowsUpdateIssues'
        }

        It "Should define Repair-CacheIssues function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-CacheIssues'
        }

        It "Should define Repair-SystemFiles function" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'function\s+Repair-SystemFiles'
        }

        It "Should use Clear-DnsClientCache for DNS fix" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'Clear-DnsClientCache'
        }

        It "Should use netsh for Winsock reset" {
            $content = Get-Content $Script:RepairCommonIssuesScript -Raw
            $content | Should -Match 'netsh winsock reset'
        }
    }
}

# Watch-DiskSpace.ps1 functionality merged into Get-SystemPerformance.ps1
Describe "Get-SystemPerformance.ps1 Disk Analysis" -Tag "Monitoring", "DiskSpace" {
    Context "Disk Analysis Parameters (merged from Watch-DiskSpace.ps1)" {
        BeforeAll {
            $scriptInfo = Get-Command $Script:SystemPerformanceScript -ErrorAction SilentlyContinue
            $parameters = $scriptInfo.Parameters
        }

        It "Script file should exist" {
            $Script:SystemPerformanceScript | Should -Exist
        }

        It "Should have IncludeDiskAnalysis parameter" {
            $parameters.ContainsKey('IncludeDiskAnalysis') | Should -BeTrue
        }

        It "Should have AutoCleanup parameter" {
            $parameters.ContainsKey('AutoCleanup') | Should -BeTrue
        }

        It "Should have DriveLetters parameter" {
            $parameters.ContainsKey('DriveLetters') | Should -BeTrue
        }

        It "Should have ExcludeDrives parameter" {
            $parameters.ContainsKey('ExcludeDrives') | Should -BeTrue
        }

        It "Should have TopFilesCount parameter" {
            $parameters.ContainsKey('TopFilesCount') | Should -BeTrue
        }
    }

    Context "Disk Analysis Functions (merged from Watch-DiskSpace.ps1)" {
        It "Should define Get-LargestFiles function" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match 'function\s+Get-LargestFiles'
        }

        It "Should define Get-LargestFolders function" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match 'function\s+Get-LargestFolders'
        }

        It "Should define Get-CleanupSuggestions function" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match 'function\s+Get-CleanupSuggestions'
        }

        It "Should define Get-DiskAnalysis function" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match 'function\s+Get-DiskAnalysis'
        }

        It "Should check for temp files" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match '\$env:TEMP'
        }

        It "Should check for browser caches" {
            $content = Get-Content $Script:SystemPerformanceScript -Raw
            $content | Should -Match 'Chrome.*Cache|Edge.*Cache|Firefox'
        }
    }
}

Describe "Get-ApplicationHealth.ps1" -Tag "Monitoring", "Applications" {
    Context "Script Existence and Syntax" {
        It "Script file should exist" {
            $Script:ApplicationHealthScript | Should -Exist
        }

        It "Script should have valid PowerShell syntax" {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Script:ApplicationHealthScript -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Script should contain required elements" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match '#Requires -Version 5.1'
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match 'param\s*\('
        }
    }

    Context "Parameters" {
        BeforeAll {
            $scriptInfo = Get-Command $Script:ApplicationHealthScript -ErrorAction SilentlyContinue
            $parameters = $scriptInfo.Parameters
        }

        It "Should have RequiredApps parameter" {
            $parameters.ContainsKey('RequiredApps') | Should -BeTrue
        }

        It "Should have CheckUpdates parameter" {
            $parameters.ContainsKey('CheckUpdates') | Should -BeTrue
        }

        It "Should have AutoUpdate parameter" {
            $parameters.ContainsKey('AutoUpdate') | Should -BeTrue
        }

        It "Should have CheckCrashes parameter" {
            $parameters.ContainsKey('CheckCrashes') | Should -BeTrue
        }

        It "Should have CrashDays parameter" {
            $parameters.ContainsKey('CrashDays') | Should -BeTrue
        }

        It "Should have OutputFormat parameter" {
            $parameters.ContainsKey('OutputFormat') | Should -BeTrue
        }
    }

    Context "Application Health Features" {
        It "Should define Get-InstalledApplications function" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'function\s+Get-InstalledApplications'
        }

        It "Should define Get-WingetUpdates function" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'function\s+Get-WingetUpdates'
        }

        It "Should define Get-ChocolateyUpdates function" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'function\s+Get-ChocolateyUpdates'
        }

        It "Should define Get-ApplicationCrashes function" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'function\s+Get-ApplicationCrashes'
        }

        It "Should define Get-ApplicationResourceUsage function" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'function\s+Get-ApplicationResourceUsage'
        }

        It "Should query registry for installed apps" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        }

        It "Should check Windows Store apps" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'Get-AppxPackage'
        }

        It "Should check Event Log for crashes" {
            $content = Get-Content $Script:ApplicationHealthScript -Raw
            $content | Should -Match 'Get-WinEvent'
        }
    }
}

Describe "Get-SystemReport.ps1" -Tag "Reporting", "SystemInfo" {
    Context "Script Existence and Syntax" {
        It "Script file should exist" {
            $Script:SystemReportScript | Should -Exist
        }

        It "Script should have valid PowerShell syntax" {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Script:SystemReportScript -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Script should contain required elements" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match '#Requires -Version 5.1'
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match 'param\s*\('
        }
    }

    Context "Parameters" {
        BeforeAll {
            $scriptInfo = Get-Command $Script:SystemReportScript -ErrorAction SilentlyContinue
            $parameters = $scriptInfo.Parameters
        }

        It "Should have IncludeHardware parameter" {
            $parameters.ContainsKey('IncludeHardware') | Should -BeTrue
        }

        It "Should have IncludeSoftware parameter" {
            $parameters.ContainsKey('IncludeSoftware') | Should -BeTrue
        }

        It "Should have IncludeNetwork parameter" {
            $parameters.ContainsKey('IncludeNetwork') | Should -BeTrue
        }

        It "Should have IncludeSecurity parameter" {
            $parameters.ContainsKey('IncludeSecurity') | Should -BeTrue
        }

        It "Should have IncludePerformance parameter" {
            $parameters.ContainsKey('IncludePerformance') | Should -BeTrue
        }

        It "Should have OutputFormat parameter" {
            $parameters.ContainsKey('OutputFormat') | Should -BeTrue
        }

        It "Should have ComputerName parameter" {
            $parameters.ContainsKey('ComputerName') | Should -BeTrue
        }
    }

    Context "System Report Features" {
        It "Should define Get-HardwareInfo function" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'function\s+Get-HardwareInfo'
        }

        It "Should define Get-SoftwareInfo function" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'function\s+Get-SoftwareInfo'
        }

        It "Should define Get-NetworkInfo function" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'function\s+Get-NetworkInfo'
        }

        It "Should define Get-SecurityInfo function" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'function\s+Get-SecurityInfo'
        }

        It "Should define Get-PerformanceInfo function" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'function\s+Get-PerformanceInfo'
        }

        It "Should query Win32_ComputerSystem for hardware" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Win32_ComputerSystem'
        }

        It "Should query Win32_Processor for CPU" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Win32_Processor'
        }

        It "Should query Win32_PhysicalMemory for RAM" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Win32_PhysicalMemory'
        }

        It "Should query Win32_OperatingSystem for OS" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Win32_OperatingSystem'
        }

        It "Should check Windows Defender status" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Get-MpComputerStatus'
        }

        It "Should check firewall status" {
            $content = Get-Content $Script:SystemReportScript -Raw
            $content | Should -Match 'Get-NetFirewallProfile'
        }
    }
}

Describe "CommonFunctions Integration" -Tag "Integration" {
    Context "Module Import" {
        It "All Tier 2 scripts should import CommonFunctions module" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:RepairCommonIssuesScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript,
                $Script:SystemReportScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match 'CommonFunctions\.psm1'
            }
        }

        It "All Tier 2 scripts should have fallback functions" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:RepairCommonIssuesScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript,
                $Script:SystemReportScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match 'function\s+Write-Success'
                $content | Should -Match 'function\s+Write-InfoMessage'
                $content | Should -Match 'function\s+Write-ErrorMessage'
            }
        }
    }

    Context "Output Format Support" {
        It "All Tier 2 scripts should support multiple output formats" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript,
                $Script:SystemReportScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match "ValidateSet.*'Console'.*'HTML'.*'JSON'.*'CSV'"
            }
        }
    }

    Context "Exit Codes" {
        It "All Tier 2 scripts should return meaningful exit codes" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:RepairCommonIssuesScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match 'ExitCode'
            }
        }
    }
}

Describe "HTML Report Generation" -Tag "Reporting" {
    Context "HTML Report Functions" {
        It "All reporting scripts should have Export-HtmlReport function" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript,
                $Script:SystemReportScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match 'function\s+Export-HtmlReport'
            }
        }

        It "HTML reports should include proper HTML structure" {
            $scripts = @(
                $Script:UserAccountAuditScript,
                $Script:DiskSpaceScript,
                $Script:ApplicationHealthScript,
                $Script:SystemReportScript
            )

            foreach ($scriptPath in $scripts) {
                $content = Get-Content $scriptPath -Raw
                $content | Should -Match '<!DOCTYPE html>'
                $content | Should -Match '<html>'
                $content | Should -Match '</html>'
                $content | Should -Match '<style>'
            }
        }
    }
}
