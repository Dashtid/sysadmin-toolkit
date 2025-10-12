# Pester Tests for Windows Maintenance Scripts
# Run: Invoke-Pester -Path .\tests\Windows\Maintenance.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $MaintenancePath = Join-Path $ProjectRoot "Windows\maintenance"
}

Describe "Maintenance Script Existence" {
    Context "Script Files" {
        It "system-updates.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $scriptPath | Should -Exist
        }

        It "security-updates.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "security-updates.ps1"
            $scriptPath | Should -Exist
        }

        It "update-defender.ps1 should exist" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $scriptPath | Should -Exist
        }
    }
}

Describe "Maintenance Script Syntax" {
    Context "PowerShell Syntax Validation" {
        It "system-updates.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $scriptPath -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "security-updates.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "security-updates.ps1"
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $scriptPath -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }

        It "update-defender.ps1 has valid syntax" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $scriptPath -Raw), [ref]$errors
            ) | Out-Null
            $errors.Count | Should -Be 0
        }
    }
}

Describe "Maintenance Script Requirements" {
    Context "Administrator Privileges" {
        It "system-updates.ps1 checks for admin or requires admin" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            # Either has #Requires or checks admin manually
            ($content -match "#Requires -RunAsAdministrator") -or
            ($content -match "Administrator|IsInRole.*Administrator|RunAsAdministrator") |
            Should -Be $true
        }

        It "update-defender.ps1 checks for admin or requires admin" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $content = Get-Content $scriptPath -Raw
            # Either has #Requires or checks admin manually
            ($content -match "#Requires -RunAsAdministrator") -or
            ($content -match "Administrator|IsInRole.*Administrator|RunAsAdministrator") |
            Should -Be $true
        }
    }

    Context "PowerShell Version" {
        It "Scripts target PowerShell 5.1 or higher" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                if ($content -match "#Requires -Version (\d+)") {
                    [int]$matches[1] | Should -BeGreaterOrEqual 5
                }
            }
        }
    }
}

Describe "Maintenance Script Content" {
    Context "Windows Update Functionality" {
        It "system-updates.ps1 uses Windows Update cmdlets" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "PSWindowsUpdate|Windows.*Update|Get-WindowsUpdate|Install-WindowsUpdate"
        }

        It "Scripts check for pending reboots" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "PendingReboot|RebootRequired|Restart.*Required"
        }
    }

    Context "Windows Defender Functionality" {
        It "update-defender.ps1 updates defender signatures" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Update-MpSignature|MpComputerStatus"
        }

        It "Scripts check defender status" {
            $scriptPath = Join-Path $MaintenancePath "update-defender.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Get-MpComputerStatus|Get-MpPreference"
        }
    }

    Context "Error Handling" {
        It "All maintenance scripts have try/catch blocks" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "try\s*\{.*catch"
            }
        }

        It "Scripts handle ErrorActionPreference" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\$ErrorActionPreference"
            }
        }
    }
}

Describe "Maintenance Script Output" {
    Context "Consistent Logging Format" {
        It "All scripts use [+] for success" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[\+\]"
            }
        }

        It "All scripts use [-] for errors" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[-\]"
            }
        }

        It "All scripts use [i] for info" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[i\]"
            }
        }

        It "All scripts use [!] for warnings" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "\[!\]"
            }
        }
    }

    Context "No Emojis" {
        It "Scripts don't contain emojis" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Not -Match '✅|❌|⚠️|ℹ️|🚀|📁|🔧'
            }
        }
    }
}

Describe "Maintenance Script Security" {
    Context "No Hardcoded Credentials" {
        It "Scripts don't contain passwords" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Not -Match 'password\s*=\s*["`''][^"`'']+["`'']'
            }
        }

        It "Scripts don't contain API keys" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Not -Match 'api[_-]?key\s*=\s*["`''][^"`'']+["`'']'
            }
        }
    }
}

Describe "Maintenance Script Functionality" {
    Context "Service Availability" {
        It "Windows Update service exists" {
            $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Name | Should -Be "wuauserv"
            } else {
                Set-ItResult -Skipped -Because "Windows Update service not found"
            }
        }

        It "Windows Defender service exists" {
            $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Name | Should -Be "WinDefend"
            } else {
                Set-ItResult -Skipped -Because "Windows Defender service not found"
            }
        }
    }

    Context "Module Dependencies" {
        It "PSWindowsUpdate module check is present" {
            $scriptPath = Join-Path $MaintenancePath "system-updates.ps1"
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "PSWindowsUpdate|Get-Module.*PSWindowsUpdate|Import-Module.*PSWindowsUpdate"
        }
    }

    Context "Logging Capabilities" {
        It "Scripts can log to files" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "Out-File|Add-Content|Set-Content|\>\>|log"
            }
        }
    }
}

Describe "Maintenance Script Best Practices" {
    Context "Documentation" {
        It "Scripts have description comments" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "^#.*Description|^#.*Purpose"
            }
        }

        It "Scripts explain their usage" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "#.*Usage|\.SYNOPSIS|\.DESCRIPTION"
            }
        }
    }

    Context "Safety Features" {
        It "Scripts provide status feedback" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "Write-Host|Write-Output|Write-Verbose"
            }
        }

        It "Scripts handle exit codes" {
            Get-ChildItem $MaintenancePath -Filter "*.ps1" | ForEach-Object {
                $content = Get-Content $_.FullName -Raw
                $content | Should -Match "exit \d+"
            }
        }
    }
}
