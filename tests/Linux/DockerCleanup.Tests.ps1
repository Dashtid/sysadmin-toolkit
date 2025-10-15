#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Pester tests for Linux Docker cleanup scripts.
#>

#Requires -Version 7.0

BeforeAll {
    $ProjectRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    $DockerPath = Join-Path $ProjectRoot "Linux" "docker"
}

Describe "Docker Cleanup Script - File Structure" {
    It "docker-cleanup.sh exists" {
        Test-Path (Join-Path $DockerPath "docker-cleanup.sh") | Should -Be $true
    }

    It "docker-cleanup.sh has shebang" {
        $firstLine = Get-Content (Join-Path $DockerPath "docker-cleanup.sh") -TotalCount 1
        $firstLine | Should -Match '^#!/.*bash'
    }
}

Describe "docker-cleanup.sh - Script Quality" {
    BeforeAll {
        $ScriptContent = Get-Content (Join-Path $DockerPath "docker-cleanup.sh") -Raw
    }

    Context "Documentation" {
        It "Has version information" {
            $ScriptContent | Should -Match 'SCRIPT_VERSION='
        }

        It "Has description" {
            $ScriptContent | Should -Match 'DESCRIPTION:'
        }

        It "Has examples" {
            $ScriptContent | Should -Match 'EXAMPLES:'
        }
    }

    Context "Safety Features" {
        It "Uses set -euo pipefail" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }

        It "Supports WhatIf mode" {
            $ScriptContent | Should -Match 'WHATIF_MODE'
        }
    }

    Context "Docker Operations" {
        It "Checks for docker command" {
            $ScriptContent | Should -Match 'command\s+-v\s+docker'
        }

        It "Removes dangling images" {
            $ScriptContent | Should -Match 'dangling'
        }

        It "Manages image versions" {
            $ScriptContent | Should -Match 'KEEP_VERSIONS'
        }

        It "Prunes old containers" {
            $ScriptContent | Should -Match 'CONTAINER_AGE_DAYS'
        }
    }

    Context "Metrics" {
        It "Exports Prometheus metrics" {
            $ScriptContent | Should -Match 'docker_cleanup'
        }

        It "Tracks space reclaimed" {
            $ScriptContent | Should -Match 'SPACE_RECLAIMED'
        }

        It "Uses centralized metrics directory with fallback" {
            $ScriptContent | Should -Match 'METRICS_DIR="\$\{METRICS_DIR:-/var/lib/prometheus/node-exporter\}"'
        }
    }
}
