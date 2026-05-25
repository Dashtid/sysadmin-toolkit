# Pester tests for Install-SystemUpdatesTask.ps1
# Run: Invoke-Pester -Path .\tests\Windows\InstallSystemUpdatesTask.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $MaintenancePath = Join-Path $ProjectRoot 'Windows\maintenance'
    $ScriptPath = Join-Path $MaintenancePath 'Install-SystemUpdatesTask.ps1'
    $ScriptContent = Get-Content $ScriptPath -Raw
}

Describe 'Install-SystemUpdatesTask.ps1 - Structure' {

    Context 'File and syntax' {
        It 'Script file exists' {
            Test-Path $ScriptPath | Should -Be $true
        }

        It 'Has valid PowerShell syntax' {
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It 'Requires Administrator privileges' {
            $ScriptContent | Should -Match '#Requires -RunAsAdministrator'
        }

        It 'Requires PowerShell 7 or later' {
            $ScriptContent | Should -Match '#Requires -Version 7'
        }

        It 'Uses [CmdletBinding(SupportsShouldProcess)]' {
            $ScriptContent | Should -Match 'CmdletBinding\s*\(\s*SupportsShouldProcess'
        }

        It 'Imports CommonFunctions module' {
            $ScriptContent | Should -Match 'CommonFunctions\.psm1'
            $ScriptContent | Should -Match 'Import-Module\s+\$modulePath'
        }
    }

    Context 'Parameters' {
        BeforeAll {
            $cmd = Get-Command $ScriptPath -ErrorAction Stop
        }

        It 'Accepts -TaskName' {
            $cmd.Parameters.ContainsKey('TaskName') | Should -Be $true
        }

        It 'Accepts -DayOfWeek with weekday ValidateSet' {
            $cmd.Parameters.ContainsKey('DayOfWeek') | Should -Be $true
            $validate = $cmd.Parameters['DayOfWeek'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validate.ValidValues | Should -Contain 'Sunday'
            $validate.ValidValues | Should -Contain 'Saturday'
        }

        It 'Accepts -Time' {
            $cmd.Parameters.ContainsKey('Time') | Should -Be $true
        }

        It 'Accepts -AutoReboot switch' {
            $cmd.Parameters.ContainsKey('AutoReboot') | Should -Be $true
            $cmd.Parameters['AutoReboot'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Accepts -SystemAccount switch' {
            $cmd.Parameters.ContainsKey('SystemAccount') | Should -Be $true
            $cmd.Parameters['SystemAccount'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Accepts -Force switch' {
            $cmd.Parameters.ContainsKey('Force') | Should -Be $true
            $cmd.Parameters['Force'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Defaults DayOfWeek to Sunday' {
            $ScriptContent | Should -Match '\[string\]\$DayOfWeek\s*=\s*''Sunday'''
        }

        It 'Defaults Time to 10:00' {
            $ScriptContent | Should -Match '\[string\]\$Time\s*=\s*''10:00'''
        }

        It 'Defaults TaskName to SystemUpdates' {
            $ScriptContent | Should -Match '\[string\]\$TaskName\s*=\s*''SystemUpdates'''
        }
    }
}

Describe 'Install-SystemUpdatesTask.ps1 - Task Registration Logic' {

    Context 'Builds task components' {
        It 'Uses New-ScheduledTaskAction' {
            $ScriptContent | Should -Match 'New-ScheduledTaskAction'
        }

        It 'Uses New-ScheduledTaskTrigger -Weekly' {
            $ScriptContent | Should -Match 'New-ScheduledTaskTrigger\s+-Weekly'
        }

        It 'Uses New-ScheduledTaskPrincipal' {
            $ScriptContent | Should -Match 'New-ScheduledTaskPrincipal'
        }

        It 'Uses New-ScheduledTaskSettingsSet' {
            $ScriptContent | Should -Match 'New-ScheduledTaskSettingsSet'
        }

        It 'Calls Register-ScheduledTask' {
            $ScriptContent | Should -Match 'Register-ScheduledTask'
        }
    }

    Context 'Laptop-friendly defaults' {
        It 'Uses -StartWhenAvailable' {
            $ScriptContent | Should -Match '-StartWhenAvailable'
        }

        It 'Uses -AllowStartIfOnBatteries' {
            $ScriptContent | Should -Match '-AllowStartIfOnBatteries'
        }

        It 'Uses -DontStopIfGoingOnBatteries' {
            $ScriptContent | Should -Match '-DontStopIfGoingOnBatteries'
        }

        It 'Sets -MultipleInstances IgnoreNew' {
            $ScriptContent | Should -Match '-MultipleInstances\s+IgnoreNew'
        }

        It 'Caps execution at 3 hours' {
            $ScriptContent | Should -Match 'New-TimeSpan\s+-Hours\s+3'
        }
    }

    Context 'Principal correctness' {
        It 'Defaults to Interactive logon (not ServiceAccount)' {
            $ScriptContent | Should -Match '-LogonType\s+Interactive'
        }

        It 'Uses RunLevel Highest' {
            $ScriptContent | Should -Match '-RunLevel\s+Highest'
        }

        It 'SystemAccount branch references SYSTEM and ServiceAccount' {
            $ScriptContent | Should -Match 'SystemAccount'
            $ScriptContent | Should -Match "UserId\s+'SYSTEM'"
            $ScriptContent | Should -Match '-LogonType\s+ServiceAccount'
        }
    }
}

Describe 'Install-SystemUpdatesTask.ps1 - Safety' {

    It 'Validates that system-updates.ps1 exists before proceeding' {
        $ScriptContent | Should -Match "ChildPath\s+'system-updates\.ps1'"
        $ScriptContent | Should -Match 'Test-Path\s+\$updateScript'
    }

    It 'Validates pwsh availability via Get-PowerShell7Path' {
        $ScriptContent | Should -Match 'Get-PowerShell7Path'
    }

    It 'Refuses to overwrite existing task without -Force' {
        $ScriptContent | Should -Match 'Get-ScheduledTask.*-ErrorAction\s+SilentlyContinue'
        $ScriptContent | Should -Match 'if\s*\(\s*-not\s+\$Force'
    }

    It 'Uses ShouldProcess for Unregister and Register' {
        $ScriptContent | Should -Match '\$PSCmdlet\.ShouldProcess'
    }

    It 'Warns when -SystemAccount is selected (winget user-scope caveat)' {
        $ScriptContent | Should -Match 'Write-WarningMessage.*SYSTEM'
    }

    It 'Contains no emojis (toolkit convention)' {
        $ScriptContent | Should -Not -Match '✅|❌|⚠|Ἰ9|\ud83d|✓|✗'
    }
}
