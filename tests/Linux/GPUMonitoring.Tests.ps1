#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Pester tests for Linux GPU monitoring scripts.
#>

#Requires -Version 7.0

BeforeAll {
    $ProjectRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    $GPUPath = Join-Path $ProjectRoot "Linux" "gpu"
}

Describe "GPU Monitoring Script - File Structure" {
    It "nvidia-gpu-exporter.sh exists" {
        Test-Path (Join-Path $GPUPath "nvidia-gpu-exporter.sh") | Should -Be $true
    }

    It "nvidia-gpu-exporter.sh has shebang" {
        $firstLine = Get-Content (Join-Path $GPUPath "nvidia-gpu-exporter.sh") -TotalCount 1
        $firstLine | Should -Match '^#!/.*bash'
    }
}

Describe "nvidia-gpu-exporter.sh - Script Quality" {
    BeforeAll {
        $ScriptContent = Get-Content (Join-Path $GPUPath "nvidia-gpu-exporter.sh") -Raw
    }

    Context "NVIDIA Integration" {
        It "Uses nvidia-smi command" {
            $ScriptContent | Should -Match 'nvidia-smi'
        }

        It "Checks for nvidia-smi availability" {
            $ScriptContent | Should -Match 'command\s+-v\s+nvidia-smi'
        }

        It "Queries GPU metrics" {
            $ScriptContent | Should -Match '--query-gpu'
        }
    }

    Context "Prometheus Metrics" {
        It "Exports GPU utilization" {
            $ScriptContent | Should -Match 'nvidia_gpu_utilization'
        }

        It "Exports memory metrics" {
            $ScriptContent | Should -Match 'nvidia_gpu_memory'
        }

        It "Exports temperature" {
            $ScriptContent | Should -Match 'nvidia_gpu_temperature'
        }

        It "Exports power metrics" {
            $ScriptContent | Should -Match 'nvidia_gpu_power'
        }

        It "Uses centralized metrics directory" {
            $ScriptContent | Should -Match 'METRICS_DIR="/var/lib/prometheus/node-exporter"'
        }
    }
}
