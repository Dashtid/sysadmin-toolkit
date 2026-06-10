# Behavioral Pester tests for system-updates.ps1
# Run: Invoke-Pester -Path .\tests\Windows\SystemUpdatesBehavioral.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-SystemUpdates).
# winget and choco stubs let Pester Mock attach. We mock Add-Content for
# every helper that calls Write-LogMessage so the real log file isn't touched.

BeforeAll {
    function winget { param() }
    function choco { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\maintenance\system-updates.ps1'
    . $ScriptPath

    $global:LASTEXITCODE = 0
}

Describe 'system-updates.ps1 - Test-PendingReboot' {
    BeforeEach {
        Mock Write-WarningMessage { }
        Mock Write-InfoMessage { }
    }

    It 'Returns $true when ComponentBasedServicing RebootPending key is present' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ RebootPending = 1 }
        } -ParameterFilter { $Path -like '*Component Based Servicing*' }
        Mock Get-ItemProperty { $null } -ParameterFilter { $Path -notlike '*Component Based Servicing*' }

        Test-PendingReboot | Should -Be $true
    }

    It 'Returns $true when WindowsUpdate Auto Update RebootRequired is present' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ RebootRequired = 1 }
        } -ParameterFilter { $Path -like '*WindowsUpdate\Auto Update*' }
        Mock Get-ItemProperty { $null } -ParameterFilter { $Path -notlike '*WindowsUpdate\Auto Update*' }

        Test-PendingReboot | Should -Be $true
    }

    It 'Returns $false (and only logs) when only PendingFileRenameOperations is present' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = @('foo', 'bar') }
        } -ParameterFilter { $Path -like '*Session Manager*' }
        Mock Get-ItemProperty { $null } -ParameterFilter { $Path -notlike '*Session Manager*' }

        Test-PendingReboot | Should -Be $false
    }

    It 'Returns $false when no pending-reboot markers exist' {
        Mock Get-ItemProperty { $null }
        Test-PendingReboot | Should -Be $false
    }
}

Describe 'system-updates.ps1 - Disable-FastStartup' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
    }

    It 'Returns early without writing when HiberbootEnabled is already 0' {
        Mock Get-ItemProperty { [PSCustomObject]@{ HiberbootEnabled = 0 } }
        Mock Set-ItemProperty { throw 'must not be called' }
        { Disable-FastStartup } | Should -Not -Throw
        Should -Invoke Set-ItemProperty -Times 0
    }

    It 'Writes HiberbootEnabled=0 when it is currently enabled' {
        Mock Get-ItemProperty { [PSCustomObject]@{ HiberbootEnabled = 1 } }
        Mock Set-ItemProperty { } -Verifiable -ParameterFilter {
            $Name -eq 'HiberbootEnabled' -and $Value -eq 0
        }
        Disable-FastStartup
        Should -InvokeVerifiable
    }

    It 'Emits a warning when Set-ItemProperty fails' {
        Mock Get-ItemProperty { [PSCustomObject]@{ HiberbootEnabled = 1 } }
        Mock Set-ItemProperty { throw 'access denied' }
        Disable-FastStartup
        Should -Invoke Write-WarningMessage -Times 1
    }
}

Describe 'system-updates.ps1 - Test-RestorePointCreation' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Returns $true when Get-ComputerRestorePoint returns a matching point' {
        Mock Get-ComputerRestorePoint {
            @([PSCustomObject]@{ Description = 'Before Automated Updates - 2026-06-10 19:00' })
        }
        Test-RestorePointCreation -Description 'Before Automated Updates' | Should -Be $true
    }

    It 'Returns $false when no matching restore points exist' {
        Mock Get-ComputerRestorePoint { @() }
        Test-RestorePointCreation -Description 'No Such Description' | Should -Be $false
    }

    It 'Returns $false when Get-ComputerRestorePoint throws' {
        Mock Get-ComputerRestorePoint { throw 'WMI error' }
        Test-RestorePointCreation -Description 'X' | Should -Be $false
    }
}

Describe 'system-updates.ps1 - New-SystemRestorePoint' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
    }

    It 'Returns $null and writes info when SkipRestorePoint is set' {
        $global:config.SkipRestorePoint = $true
        try {
            New-SystemRestorePoint | Should -BeNullOrEmpty
            Should -Invoke Write-InfoMessage
        }
        finally {
            $global:config.SkipRestorePoint = $false
        }
    }

    It 'Returns $null and emits a warning when Checkpoint-Computer throws a COM exception' {
        Mock Enable-ComputerRestore { }
        Mock Checkpoint-Computer {
            throw [System.Runtime.InteropServices.COMException]::new('restore-point throttle')
        }
        Mock Test-RestorePointCreation { $false }
        New-SystemRestorePoint | Should -BeNullOrEmpty
        Should -Invoke Write-WarningMessage
    }
}

Describe 'system-updates.ps1 - Update-Winget' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Progress { }
        Mock Write-LogMessage { }
        $script:UpdateSummary = @{
            Chocolatey     = @{ Updated = 0; Failed = 0; Skipped = $false }
            Winget         = @{ Updated = 0; Failed = 0; Skipped = $false }
            WindowsUpdates = @{ Updated = 0; Failed = 0; Skipped = $false }
            RestorePoint   = $null
            RebootRequired = $false
        }
    }

    It 'Marks Winget.Skipped=$true when SkipWinget is set' {
        $global:config.SkipWinget = $true
        try {
            Update-Winget
            $script:UpdateSummary.Winget.Skipped | Should -Be $true
        }
        finally {
            $global:config.SkipWinget = $false
        }
    }

    It 'Marks Winget.Skipped=$true when winget is missing from PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
        Update-Winget
        $script:UpdateSummary.Winget.Skipped | Should -Be $true
    }

    It 'Returns early (no upgrade run) when output reports "No available upgrade found"' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'winget' } } -ParameterFilter { $Name -eq 'winget' }
        Mock winget {
            $global:LASTEXITCODE = 0
            'No available upgrade found.'
        }
        Update-Winget
        $script:UpdateSummary.Winget.Skipped | Should -Be $false
        $script:UpdateSummary.Winget.Updated | Should -Be 0
        $script:UpdateSummary.Winget.Failed | Should -Be 0
    }
}

Describe 'system-updates.ps1 - Update-Chocolatey' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Progress { }
        Mock Write-LogMessage { }
        $script:UpdateSummary = @{
            Chocolatey     = @{ Updated = 0; Failed = 0; Skipped = $false }
            Winget         = @{ Updated = 0; Failed = 0; Skipped = $false }
            WindowsUpdates = @{ Updated = 0; Failed = 0; Skipped = $false }
            RestorePoint   = $null
            RebootRequired = $false
        }
    }

    It 'Marks Chocolatey.Skipped=$true when SkipChocolatey is set' {
        $global:config.SkipChocolatey = $true
        try {
            Update-Chocolatey
            $script:UpdateSummary.Chocolatey.Skipped | Should -Be $true
        }
        finally {
            $global:config.SkipChocolatey = $false
        }
    }

    It 'Marks Chocolatey.Skipped=$true when choco is missing from PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
        Update-Chocolatey
        $script:UpdateSummary.Chocolatey.Skipped | Should -Be $true
    }
}

Describe 'system-updates.ps1 - Update-Windows' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Progress { }
        Mock Write-LogMessage { }
        Mock Import-Module { }
        $script:UpdateSummary = @{
            Chocolatey     = @{ Updated = 0; Failed = 0; Skipped = $false }
            Winget         = @{ Updated = 0; Failed = 0; Skipped = $false }
            WindowsUpdates = @{ Updated = 0; Failed = 0; Skipped = $false }
            RestorePoint   = $null
            RebootRequired = $false
        }
    }

    It 'Marks WindowsUpdates.Skipped=$true when SkipWindowsUpdate is set' {
        $global:config.SkipWindowsUpdate = $true
        try {
            Update-Windows
            $script:UpdateSummary.WindowsUpdates.Skipped | Should -Be $true
        }
        finally {
            $global:config.SkipWindowsUpdate = $false
        }
    }

    It 'Returns without installing when Get-WindowsUpdate returns no updates' {
        Mock Get-Module { [PSCustomObject]@{ Name = 'PSWindowsUpdate' } }
        function Get-WindowsUpdate { }
        Mock Get-WindowsUpdate { @() }
        function Install-WindowsUpdate { param() }
        Mock Install-WindowsUpdate { throw 'must not be called' }
        Update-Windows
        Should -Invoke Install-WindowsUpdate -Times 0
        $script:UpdateSummary.WindowsUpdates.Updated | Should -Be 0
    }
}
