#Requires -Modules Pester
#Requires -Version 5.1

<#
.SYNOPSIS
    Pester tests for backup and system state scripts.

.DESCRIPTION
    Test suite for:
    - Export-SystemState.ps1
    - Test-BackupIntegrity.ps1
    - Compare-SoftwareInventory.ps1

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Created: 2025-12-25
#>

BeforeAll {
    $script:TestRoot = Split-Path -Parent $PSScriptRoot
    $script:RepoRoot = Split-Path -Parent $script:TestRoot
    $script:WindowsRoot = Join-Path $script:RepoRoot "Windows"

    $script:BackupScripts = @{
        'Export-SystemState'       = Join-Path $script:WindowsRoot "backup\Export-SystemState.ps1"
        'Test-BackupIntegrity'     = Join-Path $script:WindowsRoot "backup\Test-BackupIntegrity.ps1"
        'Compare-SoftwareInventory' = Join-Path $script:WindowsRoot "first-time-setup\Compare-SoftwareInventory.ps1"
    }

    function Test-ScriptSyntax {
        param([string]$Path)
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        return $errors.Count -eq 0
    }
}

Describe "Backup Scripts - File Existence" -Tag "Existence", "Backup" {
    It "Export-SystemState.ps1 should exist" {
        $script:BackupScripts['Export-SystemState'] | Should -Exist
    }

    It "Test-BackupIntegrity.ps1 should exist" {
        $script:BackupScripts['Test-BackupIntegrity'] | Should -Exist
    }

    It "Compare-SoftwareInventory.ps1 should exist" {
        $script:BackupScripts['Compare-SoftwareInventory'] | Should -Exist
    }
}

Describe "Backup Scripts - Syntax Validation" -Tag "Syntax", "Backup" {
    foreach ($scriptName in $script:BackupScripts.Keys) {
        It "$scriptName should have valid PowerShell syntax" {
            Test-ScriptSyntax -Path $script:BackupScripts[$scriptName] | Should -Be $true
        }
    }
}

Describe "Export-SystemState.ps1" -Tag "SystemState", "Backup" {
    BeforeAll {
        $script:ExportPath = $script:BackupScripts['Export-SystemState']
        $script:ExportContent = Get-Content $script:ExportPath -Raw
    }

    Context "Parameters" {
        It "Should have Destination parameter" {
            $script:ExportContent | Should -Match '\[string\]\$Destination'
        }

        It "Should have Include parameter with ValidateSet" {
            $script:ExportContent | Should -Match '\[ValidateSet\(.*All.*Drivers.*Registry.*Network.*Tasks.*\)\]'
        }

        It "Should have Compress switch" {
            $script:ExportContent | Should -Match '\[switch\]\$Compress'
        }

        It "Should have OutputFormat parameter" {
            $script:ExportContent | Should -Match '\[ValidateSet\(.*Console.*HTML.*JSON.*\)\]'
        }

        It "Should have IncludeEventLogs switch" {
            $script:ExportContent | Should -Match '\[switch\]\$IncludeEventLogs'
        }

        It "Should have DryRun switch" {
            $script:ExportContent | Should -Match '\[switch\]\$DryRun'
        }
    }

    Context "Features" {
        It "Should export drivers" {
            $script:ExportContent | Should -Match 'Export-Drivers'
            $script:ExportContent | Should -Match 'Get-PnpDevice'
        }

        It "Should export registry keys" {
            $script:ExportContent | Should -Match 'Export-RegistryKeys'
            $script:ExportContent | Should -Match 'reg export'
        }

        It "Should export network configuration" {
            $script:ExportContent | Should -Match 'Export-NetworkConfig'
            $script:ExportContent | Should -Match 'Get-NetAdapter'
        }

        It "Should export scheduled tasks" {
            $script:ExportContent | Should -Match 'Export-ScheduledTasks'
            $script:ExportContent | Should -Match 'Get-ScheduledTask'
        }

        It "Should export Windows features" {
            $script:ExportContent | Should -Match 'Export-WindowsFeatures'
        }

        It "Should export services" {
            $script:ExportContent | Should -Match 'Export-Services'
            $script:ExportContent | Should -Match 'Get-Service'
        }

        It "Should create manifest" {
            $script:ExportContent | Should -Match 'manifest\.json'
        }
    }

    Context "Help" {
        It "Should have synopsis" {
            $script:ExportContent | Should -Match '\.SYNOPSIS'
        }

        It "Should have examples" {
            $script:ExportContent | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Test-BackupIntegrity.ps1" -Tag "Integrity", "Backup" {
    BeforeAll {
        $script:IntegrityPath = $script:BackupScripts['Test-BackupIntegrity']
        $script:IntegrityContent = Get-Content $script:IntegrityPath -Raw
    }

    Context "Parameters" {
        It "Should have BackupPath parameter" {
            $script:IntegrityContent | Should -Match '\[string\]\$BackupPath'
        }

        It "Should have TestType parameter with ValidateSet" {
            $script:IntegrityContent | Should -Match '\[ValidateSet\(.*Quick.*Full.*Restore.*\)\]'
        }

        It "Should have RestoreTarget parameter" {
            $script:IntegrityContent | Should -Match '\[string\]\$RestoreTarget'
        }

        It "Should have SamplePercent parameter" {
            $script:IntegrityContent | Should -Match '\$SamplePercent'
        }

        It "Should have OutputFormat parameter" {
            $script:IntegrityContent | Should -Match '\[ValidateSet\(.*Console.*HTML.*JSON.*\)\]'
        }

        It "Should have CleanupAfterTest switch" {
            $script:IntegrityContent | Should -Match '\[switch\]\$CleanupAfterTest'
        }
    }

    Context "Features" {
        It "Should test archive structure" {
            $script:IntegrityContent | Should -Match 'Test-ArchiveStructure'
        }

        It "Should verify file hashes" {
            $script:IntegrityContent | Should -Match 'Test-FileHashes'
            $script:IntegrityContent | Should -Match 'Get-FileHash'
        }

        It "Should support restore testing" {
            $script:IntegrityContent | Should -Match 'Restore-ToTarget'
        }

        It "Should read backup metadata" {
            $script:IntegrityContent | Should -Match 'backup_metadata\.json'
        }

        It "Should calculate statistics" {
            $script:IntegrityContent | Should -Match '\$script:Stats'
        }
    }

    Context "Help" {
        It "Should have synopsis" {
            $script:IntegrityContent | Should -Match '\.SYNOPSIS'
        }

        It "Should have examples" {
            $script:IntegrityContent | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Compare-SoftwareInventory.ps1" -Tag "Inventory", "Backup" {
    BeforeAll {
        $script:ComparePath = $script:BackupScripts['Compare-SoftwareInventory']
        $script:CompareContent = Get-Content $script:ComparePath -Raw
    }

    Context "Parameters" {
        It "Should have BaselineFile parameter" {
            $script:CompareContent | Should -Match '\[string\]\$BaselineFile'
        }

        It "Should have CurrentFile parameter" {
            $script:CompareContent | Should -Match '\[string\]\$CurrentFile'
        }

        It "Should have CompareToLive switch" {
            $script:CompareContent | Should -Match '\[switch\]\$CompareToLive'
        }

        It "Should have Sources parameter with ValidateSet" {
            $script:CompareContent | Should -Match '\[ValidateSet\(.*Winget.*Chocolatey.*Registry.*All.*\)\]'
        }

        It "Should have OutputFormat parameter" {
            $script:CompareContent | Should -Match '\[ValidateSet\(.*Console.*HTML.*JSON.*\)\]'
        }

        It "Should have ExportMissing switch" {
            $script:CompareContent | Should -Match '\[switch\]\$ExportMissing'
        }
    }

    Context "Features" {
        It "Should import Winget inventory" {
            $script:CompareContent | Should -Match 'Import-WingetInventory'
        }

        It "Should import Chocolatey inventory" {
            $script:CompareContent | Should -Match 'Import-ChocolateyInventory'
        }

        It "Should compare package lists" {
            $script:CompareContent | Should -Match 'Compare-PackageLists'
        }

        It "Should get live inventory" {
            $script:CompareContent | Should -Match 'Get-LiveWingetInventory'
            $script:CompareContent | Should -Match 'Get-LiveChocolateyInventory'
        }

        It "Should export missing packages script" {
            $script:CompareContent | Should -Match 'Export-MissingPackagesScript'
        }

        It "Should detect added packages" {
            $script:CompareContent | Should -Match 'Added'
        }

        It "Should detect removed packages" {
            $script:CompareContent | Should -Match 'Removed'
        }

        It "Should detect version changes" {
            $script:CompareContent | Should -Match 'VersionChanged'
        }
    }

    Context "Help" {
        It "Should have synopsis" {
            $script:CompareContent | Should -Match '\.SYNOPSIS'
        }

        It "Should have examples" {
            $script:CompareContent | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Backup Scripts - Standards Compliance" -Tag "Standards", "Backup" {
    foreach ($scriptName in $script:BackupScripts.Keys) {
        Context "$scriptName standards" {
            BeforeAll {
                $script:Content = Get-Content $script:BackupScripts[$scriptName] -Raw
            }

            It "Should have #Requires -Version 5.1" {
                $script:Content | Should -Match '#Requires -Version 5\.1'
            }

            It "Should have CmdletBinding" {
                $script:Content | Should -Match '\[CmdletBinding'
            }

            It "Should import CommonFunctions" {
                $script:Content | Should -Match 'CommonFunctions\.psm1'
            }

            It "Should have fallback logging functions" {
                $script:Content | Should -Match 'function Write-Success'
                $script:Content | Should -Match 'function Write-InfoMessage'
            }

            It "Should use ASCII markers" {
                $script:Content | Should -Match '\[\+\]'
                $script:Content | Should -Match '\[i\]'
            }

            It "Should not contain emojis" {
                $script:Content | Should -Not -Match '[\u{1F300}-\u{1F9FF}]'
            }
        }
    }
}
