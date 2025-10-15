#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Pester tests for Linux maintenance scripts.

.DESCRIPTION
    Tests for system-updates.sh and restore-previous-state.sh to ensure
    code quality, security, and functionality standards.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: Pester 5.x
#>

#Requires -Version 7.0

BeforeAll {
    # Get script root
    $ProjectRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    $LinuxMaintenancePath = Join-Path $ProjectRoot "Linux" "maintenance"

    # Import test helpers if available
    $TestHelpersPath = Join-Path $ProjectRoot "tests" "TestHelpers.psm1"
    if (Test-Path $TestHelpersPath) {
        Import-Module $TestHelpersPath -Force
    }
}

Describe "Linux Maintenance Scripts - File Structure" {
    Context "Required Files" {
        It "system-updates.sh exists" {
            $scriptPath = Join-Path $LinuxMaintenancePath "system-updates.sh"
            Test-Path $scriptPath | Should -Be $true
        }

        It "restore-previous-state.sh exists" {
            $scriptPath = Join-Path $LinuxMaintenancePath "restore-previous-state.sh"
            Test-Path $scriptPath | Should -Be $true
        }

        It "config.example.json exists" {
            $configPath = Join-Path $LinuxMaintenancePath "config.example.json"
            Test-Path $configPath | Should -Be $true
        }

        It "README.md exists" {
            $readmePath = Join-Path $LinuxMaintenancePath "README.md"
            Test-Path $readmePath | Should -Be $true
        }
    }

    Context "File Permissions (Executable)" {
        It "system-updates.sh has shebang" {
            $scriptPath = Join-Path $LinuxMaintenancePath "system-updates.sh"
            $firstLine = Get-Content $scriptPath -TotalCount 1
            $firstLine | Should -Match '^#!/.*bash'
        }

        It "restore-previous-state.sh has shebang" {
            $scriptPath = Join-Path $LinuxMaintenancePath "restore-previous-state.sh"
            $firstLine = Get-Content $scriptPath -TotalCount 1
            $firstLine | Should -Match '^#!/.*bash'
        }
    }
}

Describe "system-updates.sh - Script Quality" {
    BeforeAll {
        $ScriptPath = Join-Path $LinuxMaintenancePath "system-updates.sh"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Header and Documentation" {
        It "Has version information" {
            $ScriptContent | Should -Match '(?m)^#\s*VERSION:\s*$|SCRIPT_VERSION='
        }

        It "Has author information" {
            $ScriptContent | Should -Match 'AUTHOR:'
        }

        It "Has description section" {
            $ScriptContent | Should -Match 'DESCRIPTION:'
        }

        It "Has usage examples" {
            $ScriptContent | Should -Match 'EXAMPLES:'
        }

        It "Has changelog" {
            $ScriptContent | Should -Match 'CHANGELOG:'
        }
    }

    Context "Bash Best Practices" {
        It "Uses set -euo pipefail for safety" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }

        It "Has main function or execution block" {
            $ScriptContent | Should -Match '(main\s*\(\)|# MAIN EXECUTION)'
        }

        It "Uses consistent function naming" {
            # Bash functions typically use lowercase with underscores
            $functions = [regex]::Matches($ScriptContent, '(?m)^(\w+)\s*\(\)\s*\{')
            $functions.Count | Should -BeGreaterThan 5
        }
    }

    Context "Logging Functions" {
        It "Defines log_info function" {
            $ScriptContent | Should -Match 'log_info\s*\(\)'
        }

        It "Defines log_success function" {
            $ScriptContent | Should -Match 'log_success\s*\(\)'
        }

        It "Defines log_warning function" {
            $ScriptContent | Should -Match 'log_warning\s*\(\)'
        }

        It "Defines log_error function" {
            $ScriptContent | Should -Match 'log_error\s*\(\)'
        }

        It "Uses ASCII markers in log functions" {
            $ScriptContent | Should -Match '\[i\]'
            $ScriptContent | Should -Match '\[\+\]'
            $ScriptContent | Should -Match '\[!\]'
            $ScriptContent | Should -Match '\[-\]'
        }
    }

    Context "Security Checks" {
        It "Checks for root privileges" {
            $ScriptContent | Should -Match 'EUID.*-ne.*0'
        }

        It "Uses DEBIAN_FRONTEND=noninteractive for apt" {
            $ScriptContent | Should -Match 'DEBIAN_FRONTEND=noninteractive'
        }

        It "Does not contain hardcoded passwords" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\047]'
            $ScriptContent | Should -Not -Match 'PASSWORD\s*=\s*["\047]'
        }

        It "Does not contain hardcoded credentials" {
            $ScriptContent | Should -Not -Match 'api[_-]?key\s*=\s*["\047][^"\047]+["\047]'
            $ScriptContent | Should -Not -Match 'secret\s*=\s*["\047][^"\047]+["\047]'
        }
    }

    Context "Update Functions" {
        It "Defines APT update function" {
            $ScriptContent | Should -Match 'update_apt\s*\(\)'
        }

        It "Defines Snap update function" {
            $ScriptContent | Should -Match 'update_snap\s*\(\)'
        }

        It "Uses apt update command" {
            $ScriptContent | Should -Match 'apt\s+update'
        }

        It "Uses apt upgrade command" {
            $ScriptContent | Should -Match 'apt\s+upgrade'
        }

        It "Uses snap refresh command" {
            $ScriptContent | Should -Match 'snap\s+refresh'
        }
    }

    Context "Configuration and Prometheus Integration" {
        It "Defines configuration loading function" {
            $ScriptContent | Should -Match 'load_config\s*\(\)'
        }

        It "Uses jq for JSON parsing" {
            $ScriptContent | Should -Match 'jq\s+-r'
        }

        It "Exports Prometheus metrics" {
            $ScriptContent | Should -Match 'export_prometheus_metrics'
        }

        It "Creates Prometheus metric format" {
            $ScriptContent | Should -Match '# HELP'
            $ScriptContent | Should -Match '# TYPE'
        }
    }

    Context "State Management" {
        It "Exports pre-update state" {
            $ScriptContent | Should -Match 'export_preupdate_state'
        }

        It "Creates JSON state files" {
            $ScriptContent | Should -Match 'pre-update-state.*\.json'
        }

        It "Checks for reboot requirement" {
            $ScriptContent | Should -Match '/var/run/reboot-required'
        }
    }

    Context "Error Handling" {
        It "Handles command not found errors" {
            $ScriptContent | Should -Match 'command\s+-v'
        }

        It "Uses conditional execution properly" {
            $ScriptContent | Should -Match 'if\s+\[\['
        }
    }

    Context "WhatIf Mode" {
        It "Supports WhatIf/dry-run mode" {
            $ScriptContent | Should -Match 'WHATIF_MODE'
        }

        It "Has --whatif option" {
            $ScriptContent | Should -Match '--whatif'
        }
    }
}

Describe "restore-previous-state.sh - Script Quality" {
    BeforeAll {
        $ScriptPath = Join-Path $LinuxMaintenancePath "restore-previous-state.sh"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Header and Documentation" {
        It "Has version information" {
            $ScriptContent | Should -Match '(?m)^#\s*VERSION:\s*$|SCRIPT_VERSION='
        }

        It "Has description section" {
            $ScriptContent | Should -Match 'DESCRIPTION:'
        }

        It "Has usage examples" {
            $ScriptContent | Should -Match 'EXAMPLES:'
        }
    }

    Context "Bash Best Practices" {
        It "Uses set -euo pipefail for safety" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }
    }

    Context "Backup Management Functions" {
        It "Lists backup files" {
            $ScriptContent | Should -Match 'list_backup_files'
        }

        It "Gets latest backup" {
            $ScriptContent | Should -Match 'get_latest_backup'
        }

        It "Compares package states" {
            $ScriptContent | Should -Match 'compare_states'
        }

        It "Shows differences" {
            $ScriptContent | Should -Match 'show_differences'
        }
    }

    Context "Restore Functionality" {
        It "Restores packages" {
            $ScriptContent | Should -Match 'restore_packages'
        }

        It "Uses apt install for downgrades" {
            $ScriptContent | Should -Match 'apt\s+install.*--allow-downgrades'
        }

        It "Handles package version pinning" {
            $ScriptContent | Should -Match '\$\{.*\}=\$\{.*\}'
        }
    }

    Context "Command-Line Options" {
        It "Supports --list option" {
            $ScriptContent | Should -Match '--list'
        }

        It "Supports --latest option" {
            $ScriptContent | Should -Match '--latest'
        }

        It "Supports --backup-file option" {
            $ScriptContent | Should -Match '--backup-file'
        }

        It "Supports --show-diff option" {
            $ScriptContent | Should -Match '--show-diff'
        }

        It "Supports --whatif option" {
            $ScriptContent | Should -Match '--whatif'
        }
    }
}

Describe "config.example.json - Configuration Template" {
    BeforeAll {
        $ConfigPath = Join-Path $LinuxMaintenancePath "config.example.json"
        $ConfigContent = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    }

    Context "Configuration Structure" {
        It "Is valid JSON" {
            { Get-Content $ConfigPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Has AutoReboot setting" {
            $ConfigContent.PSObject.Properties.Name | Should -Contain 'AutoReboot'
        }

        It "Has LogRetentionDays setting" {
            $ConfigContent.PSObject.Properties.Name | Should -Contain 'LogRetentionDays'
        }

        It "Has SkipAPT setting" {
            $ConfigContent.PSObject.Properties.Name | Should -Contain 'SkipAPT'
        }

        It "Has SkipSnap setting" {
            $ConfigContent.PSObject.Properties.Name | Should -Contain 'SkipSnap'
        }

        It "Has ExportMetrics setting" {
            $ConfigContent.PSObject.Properties.Name | Should -Contain 'ExportMetrics'
        }
    }

    Context "Configuration Values" {
        It "AutoReboot defaults to false" {
            $ConfigContent.AutoReboot | Should -Be $false
        }

        It "LogRetentionDays is numeric" {
            # JSON may parse as long or int depending on value
            $ConfigContent.LogRetentionDays | Should -BeOfType ([System.ValueType])
            $ConfigContent.LogRetentionDays | Should -BeGreaterThan 0
        }

        It "ExportMetrics defaults to true" {
            $ConfigContent.ExportMetrics | Should -Be $true
        }
    }
}

Describe "README.md - Documentation Quality" {
    BeforeAll {
        $ReadmePath = Join-Path $LinuxMaintenancePath "README.md"
        $ReadmeContent = Get-Content $ReadmePath -Raw
    }

    Context "Documentation Sections" {
        It "Has Available Scripts section" {
            $ReadmeContent | Should -Match '## \[.\] Available Scripts'
        }

        It "Has Prerequisites section" {
            $ReadmeContent | Should -Match '## \[.\] Prerequisites'
        }

        It "Has Quick Start section" {
            $ReadmeContent | Should -Match '## \[.\] Quick Start'
        }

        It "Has Logging section" {
            $ReadmeContent | Should -Match '## \[.\] Logging'
        }

        It "Has Troubleshooting section" {
            $ReadmeContent | Should -Match '## \[.\] Troubleshooting'
        }

        It "Has Prometheus Integration section" {
            $ReadmeContent | Should -Match '## \[.\] Prometheus Integration'
        }
    }

    Context "Usage Examples" {
        It "Has bash code blocks" {
            $ReadmeContent | Should -Match '```bash'
        }

        It "Documents system-updates.sh usage" {
            $ReadmeContent | Should -Match 'system-updates\.sh'
        }

        It "Documents restore-previous-state.sh usage" {
            $ReadmeContent | Should -Match 'restore-previous-state\.sh'
        }

        It "Documents cron setup" {
            $ReadmeContent | Should -Match 'crontab'
        }

        It "Documents systemd timer setup" {
            $ReadmeContent | Should -Match 'systemd.*timer'
        }
    }

    Context "Prometheus Documentation" {
        It "Documents metrics export location" {
            $ReadmeContent | Should -Match 'system_updates\.prom'
        }

        It "Shows example metrics" {
            $ReadmeContent | Should -Match 'system_updates_apt_packages_updated'
        }

        It "Documents node_exporter setup" {
            $ReadmeContent | Should -Match 'node_exporter'
        }

        It "Provides PromQL examples" {
            $ReadmeContent | Should -Match 'promql'
        }
    }

    Context "ASCII Markers (No Emojis)" {
        It "Uses ASCII markers, not emojis" {
            # Check for common emoji unicode ranges (check if ANY emoji exists)
            $hasEmojis = [regex]::IsMatch($ReadmeContent, '[\u2600-\u27BF]|[\uD800-\uDBFF][\uDC00-\uDFFF]')
            $hasEmojis | Should -Be $false
            # Verify ASCII markers are used instead
            $ReadmeContent | Should -Match '\[\*\]'
            $ReadmeContent | Should -Match '\[\+\]'
            $ReadmeContent | Should -Match '\[!\]'
            $ReadmeContent | Should -Match '\[i\]'
        }
    }
}

Describe "log-cleanup.sh - Script Quality" {
    BeforeAll {
        $ScriptPath = Join-Path $LinuxMaintenancePath "log-cleanup.sh"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Script Header and Documentation" {
        It "Has version information" {
            $ScriptContent | Should -Match 'SCRIPT_VERSION='
        }

        It "Has description section" {
            $ScriptContent | Should -Match 'DESCRIPTION:'
        }
    }

    Context "Bash Best Practices" {
        It "Uses set -euo pipefail for safety" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }
    }

    Context "Log Management Functions" {
        It "Compresses old logs" {
            $ScriptContent | Should -Match 'compress_old_logs'
        }

        It "Deletes old logs" {
            $ScriptContent | Should -Match 'DELETE_AGE_DAYS'
        }

        It "Manages journald logs" {
            $ScriptContent | Should -Match 'journalctl.*--vacuum'
        }

        It "Uses gzip for compression" {
            $ScriptContent | Should -Match 'gzip'
        }
    }

    Context "Metrics Export" {
        It "Exports Prometheus metrics" {
            $ScriptContent | Should -Match 'log_cleanup'
        }

        It "Uses centralized metrics directory with fallback" {
            $ScriptContent | Should -Match 'METRICS_DIR="\$\{METRICS_DIR:-/var/lib/prometheus/node-exporter\}"'
        }
    }

    Context "Safety Features" {
        It "Supports WhatIf mode" {
            $ScriptContent | Should -Match 'WHATIF_MODE'
        }
    }
}

Describe "Linux Maintenance Scripts - Integration" {
    Context "Script Relationships" {
        It "system-updates.sh creates state files for restore script" {
            $updateScript = Get-Content (Join-Path $LinuxMaintenancePath "system-updates.sh") -Raw
            $restoreScript = Get-Content (Join-Path $LinuxMaintenancePath "restore-previous-state.sh") -Raw

            # Both should reference the same state directory
            $updateScript | Should -Match 'STATE_DIR'
            $restoreScript | Should -Match 'STATE_DIR'
        }

        It "Both scripts use consistent log directory structure" {
            $updateScript = Get-Content (Join-Path $LinuxMaintenancePath "system-updates.sh") -Raw
            $restoreScript = Get-Content (Join-Path $LinuxMaintenancePath "restore-previous-state.sh") -Raw

            $updateScript | Should -Match '/var/log/system-updates'
            $restoreScript | Should -Match '/var/log/system-updates'
        }
    }

    Context "Configuration Consistency" {
        It "Scripts reference config.json" {
            $updateScript = Get-Content (Join-Path $LinuxMaintenancePath "system-updates.sh") -Raw
            $updateScript | Should -Match 'config\.json'
        }
    }
}
