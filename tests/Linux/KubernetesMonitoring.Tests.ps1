#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Pester tests for Linux Kubernetes monitoring scripts.

.DESCRIPTION
    Tests for pod-health-monitor.sh and pvc-monitor.sh to ensure
    code quality, security, and functionality standards.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: Pester 5.x
#>

#Requires -Version 7.0

BeforeAll {
    $ProjectRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
    $KubernetesPath = Join-Path $ProjectRoot "Linux" "kubernetes"
}

Describe "Kubernetes Monitoring Scripts - File Structure" {
    Context "Required Files" {
        It "pod-health-monitor.sh exists" {
            $scriptPath = Join-Path $KubernetesPath "pod-health-monitor.sh"
            Test-Path $scriptPath | Should -Be $true
        }

        It "pvc-monitor.sh exists" {
            $scriptPath = Join-Path $KubernetesPath "pvc-monitor.sh"
            Test-Path $scriptPath | Should -Be $true
        }
    }

    Context "File Permissions (Executable)" {
        It "pod-health-monitor.sh has shebang" {
            $scriptPath = Join-Path $KubernetesPath "pod-health-monitor.sh"
            $firstLine = Get-Content $scriptPath -TotalCount 1
            $firstLine | Should -Match '^#!/.*bash'
        }

        It "pvc-monitor.sh has shebang" {
            $scriptPath = Join-Path $KubernetesPath "pvc-monitor.sh"
            $firstLine = Get-Content $scriptPath -TotalCount 1
            $firstLine | Should -Match '^#!/.*bash'
        }
    }
}

Describe "pod-health-monitor.sh - Script Quality" {
    BeforeAll {
        $ScriptPath = Join-Path $KubernetesPath "pod-health-monitor.sh"
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

        It "Has changelog" {
            $ScriptContent | Should -Match 'CHANGELOG:'
        }
    }

    Context "Bash Best Practices" {
        It "Uses set -euo pipefail for safety" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }

        It "Has main function" {
            $ScriptContent | Should -Match 'main\s*\(\)'
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

    Context "Kubernetes Integration" {
        It "Uses kubectl commands" {
            $ScriptContent | Should -Match 'kubectl'
        }

        It "Checks for kubectl dependency" {
            $ScriptContent | Should -Match 'command\s+-v\s+kubectl'
        }

        It "Supports KUBECONFIG environment variable" {
            $ScriptContent | Should -Match 'KUBECONFIG'
        }

        It "Supports namespace filtering" {
            $ScriptContent | Should -Match 'NAMESPACE'
        }
    }

    Context "Pod Health Checks" {
        It "Checks for CrashLoopBackOff" {
            $ScriptContent | Should -Match 'CrashLoopBackOff'
        }

        It "Checks for OOMKilled" {
            $ScriptContent | Should -Match 'OOMKilled'
        }

        It "Checks for Pending pods" {
            $ScriptContent | Should -Match 'Pending'
        }

        It "Checks for ImagePullBackOff" {
            $ScriptContent | Should -Match 'ImagePullBackOff'
        }

        It "Checks restart counts" {
            $ScriptContent | Should -Match 'restartCount'
        }
    }

    Context "Prometheus Metrics" {
        It "Exports Prometheus metrics" {
            $ScriptContent | Should -Match 'export_prometheus_metrics'
        }

        It "Creates Prometheus metric format" {
            $ScriptContent | Should -Match '# HELP'
            $ScriptContent | Should -Match '# TYPE'
        }

        It "Exports unhealthy pods metric" {
            $ScriptContent | Should -Match 'k8s_unhealthy_pods_total'
        }

        It "Exports crashloop pods metric" {
            $ScriptContent | Should -Match 'k8s_crashloop_pods_total'
        }

        It "Exports OOMKilled pods metric" {
            $ScriptContent | Should -Match 'k8s_oomkilled_pods_total'
        }

        It "Uses centralized metrics directory with fallback" {
            $ScriptContent | Should -Match 'METRICS_DIR="\$\{METRICS_DIR:-/var/lib/prometheus/node-exporter\}"'
        }
    }

    Context "Security Checks" {
        It "Does not contain hardcoded passwords" {
            $ScriptContent | Should -Not -Match 'password\s*=\s*["\047]'
        }

        It "Does not contain hardcoded API tokens" {
            $ScriptContent | Should -Not -Match 'token\s*=\s*["\047][^"\047]{20,}'
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

Describe "pvc-monitor.sh - Script Quality" {
    BeforeAll {
        $ScriptPath = Join-Path $KubernetesPath "pvc-monitor.sh"
        $ScriptContent = Get-Content $ScriptPath -Raw
    }

    Context "Basic Structure" {
        It "Uses set -euo pipefail" {
            $ScriptContent | Should -Match 'set\s+-euo\s+pipefail'
        }

        It "Uses kubectl commands" {
            $ScriptContent | Should -Match 'kubectl'
        }

        It "Uses jq for JSON parsing" {
            $ScriptContent | Should -Match 'jq'
        }
    }

    Context "PVC Monitoring" {
        It "Gets PVC information" {
            $ScriptContent | Should -Match 'kubectl\s+get\s+pvc'
        }

        It "Checks PVC capacity" {
            $ScriptContent | Should -Match 'capacity'
        }
    }

    Context "Metrics Export" {
        It "Exports PVC metrics" {
            $ScriptContent | Should -Match 'k8s_pvc'
        }

        It "Uses centralized metrics directory" {
            $ScriptContent | Should -Match 'METRICS_DIR="/var/lib/prometheus/node-exporter"'
        }
    }
}
