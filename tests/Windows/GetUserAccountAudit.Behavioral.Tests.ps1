# Behavioral Pester tests for Get-UserAccountAudit.ps1
# Run: Invoke-Pester -Path .\tests\Windows\GetUserAccountAudit.Behavioral.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\security\Get-UserAccountAudit.ps1'
    . $ScriptPath
}

Describe 'Get-UserAccountAudit.ps1 - Get-LocalAdminMembers' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Returns the trailing component (after backslash) of each admin name' {
        Mock Get-LocalGroupMember {
            @(
                [PSCustomObject]@{ Name = 'WORKSTATION\Administrator' }
                [PSCustomObject]@{ Name = 'CORP\jdoe' }
            )
        }
        $names = @(Get-LocalAdminMembers)
        $names | Should -Contain 'Administrator'
        $names | Should -Contain 'jdoe'
    }

    It 'Returns empty array when Get-LocalGroupMember throws' {
        Mock Get-LocalGroupMember { throw 'access denied' }
        $names = @(Get-LocalAdminMembers)
        $names.Count | Should -Be 0
    }
}

Describe 'Get-UserAccountAudit.ps1 - Get-UserSecurityIssues' {
    It "Flags 'Password never expires' when PasswordNeverExpires and Enabled are both true" {
        $u = [PSCustomObject]@{
            UserName             = 'alice'
            Enabled              = $true
            PasswordNeverExpires = $true
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        $issues | Should -Contain 'Password never expires'
    }

    It "Flags 'Password not required' when PasswordNotRequired and Enabled" {
        $u = [PSCustomObject]@{
            UserName             = 'alice'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $true
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        $issues | Should -Contain 'Password not required'
    }

    It 'Flags inactivity using the provided DaysInactive label' {
        $u = [PSCustomObject]@{
            UserName             = 'alice'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $false
            IsInactive           = $true
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 180 -MaxCredentialAge 90)
        ($issues | Where-Object { $_ -match '180' }).Count | Should -BeGreaterOrEqual 1
    }

    It 'Flags an old password using the MaxCredentialAge threshold' {
        $u = [PSCustomObject]@{
            UserName             = 'alice'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 200
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        ($issues | Where-Object { $_ -match 'older than 90 days' }).Count | Should -Be 1
    }

    It 'Escalates to CRITICAL when an admin has any issues' {
        $u = [PSCustomObject]@{
            UserName             = 'admin1'
            Enabled              = $true
            PasswordNeverExpires = $true
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $true
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        ($issues | Where-Object { $_ -match 'CRITICAL' }).Count | Should -Be 1
    }

    It 'Flags the enabled built-in Administrator account' {
        $u = [PSCustomObject]@{
            UserName             = 'Administrator'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        $issues | Should -Contain 'Built-in Administrator account is enabled'
    }

    It 'Flags the enabled Guest account' {
        $u = [PSCustomObject]@{
            UserName             = 'Guest'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        $issues | Should -Contain 'Guest account is enabled'
    }

    It 'Returns empty issues for a healthy enabled non-admin' {
        $u = [PSCustomObject]@{
            UserName             = 'alice'
            Enabled              = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $false
            IsInactive           = $false
            PasswordAge          = 10
            IsAdmin              = $false
        }
        $issues = @(Get-UserSecurityIssues -UserInfo $u -DaysInactive 90 -MaxCredentialAge 90)
        $issues.Count | Should -Be 0
    }
}

Describe 'Get-UserAccountAudit.ps1 - Get-UserAccountDetails' {
    BeforeEach {
        Mock Write-ErrorMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Marks accounts in the local Administrators group as IsAdmin=$true' {
        Mock Get-LocalAdminMembers { @('Administrator', 'alice') }
        Mock Get-LocalUser {
            @(
                [PSCustomObject]@{
                    Name = 'alice'; FullName = 'Alice'; Description = ''
                    Enabled = $true; LastLogon = (Get-Date)
                    PasswordLastSet = (Get-Date); PasswordExpires = (Get-Date).AddDays(30)
                    PasswordNeverExpires = $false; PasswordNotRequired = $false
                    UserMayChangePassword = $true; PrincipalSource = 'Local'
                    SID = [PSCustomObject]@{ Value = 'S-1-5-21-1' }
                }
                [PSCustomObject]@{
                    Name = 'bob'; FullName = 'Bob'; Description = ''
                    Enabled = $true; LastLogon = (Get-Date)
                    PasswordLastSet = (Get-Date); PasswordExpires = (Get-Date).AddDays(30)
                    PasswordNeverExpires = $false; PasswordNotRequired = $false
                    UserMayChangePassword = $true; PrincipalSource = 'Local'
                    SID = [PSCustomObject]@{ Value = 'S-1-5-21-2' }
                }
            )
        }

        $details = @(Get-UserAccountDetails)
        ($details | Where-Object { $_.UserName -eq 'alice' })[0].IsAdmin | Should -Be $true
        ($details | Where-Object { $_.UserName -eq 'bob' })[0].IsAdmin | Should -Be $false
    }

    It 'Computes IsInactive=$true for an enabled user that has never logged in' {
        Mock Get-LocalAdminMembers { @() }
        Mock Get-LocalUser {
            @([PSCustomObject]@{
                Name = 'never'; FullName = ''; Description = ''
                Enabled = $true; LastLogon = $null
                PasswordLastSet = (Get-Date)
                PasswordExpires = (Get-Date).AddDays(30)
                PasswordNeverExpires = $false; PasswordNotRequired = $false
                UserMayChangePassword = $true; PrincipalSource = 'Local'
                SID = [PSCustomObject]@{ Value = 'S-1-5-21-3' }
            })
        }

        $details = @(Get-UserAccountDetails)
        $details[0].IsInactive | Should -Be $true
    }

    It 'Skips disabled accounts when -IncludeDisabled is not set' {
        Mock Get-LocalAdminMembers { @() }
        Mock Get-LocalUser {
            @(
                [PSCustomObject]@{
                    Name = 'enabled'; FullName = ''; Description = ''
                    Enabled = $true; LastLogon = (Get-Date)
                    PasswordLastSet = (Get-Date); PasswordExpires = (Get-Date).AddDays(30)
                    PasswordNeverExpires = $false; PasswordNotRequired = $false
                    UserMayChangePassword = $true; PrincipalSource = 'Local'
                    SID = [PSCustomObject]@{ Value = 'S-1-5-21-4' }
                }
                [PSCustomObject]@{
                    Name = 'disabled'; FullName = ''; Description = ''
                    Enabled = $false; LastLogon = (Get-Date)
                    PasswordLastSet = (Get-Date); PasswordExpires = (Get-Date).AddDays(30)
                    PasswordNeverExpires = $false; PasswordNotRequired = $false
                    UserMayChangePassword = $true; PrincipalSource = 'Local'
                    SID = [PSCustomObject]@{ Value = 'S-1-5-21-5' }
                }
            )
        }

        $details = @(Get-UserAccountDetails)
        $details.Count | Should -Be 1
        $details[0].UserName | Should -Be 'enabled'
    }
}

Describe 'Get-UserAccountAudit.ps1 - Get-AuditSummary' {
    It 'Counts Enabled, Disabled, Admin, Inactive and AccountsWithIssues correctly' {
        $results = @(
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $true;  IsAdmin = $true;  IsInactive = $false; PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @() }
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $true;  IsAdmin = $false; IsInactive = $true;  PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @('Inactive for 90+ days') }
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $false; IsAdmin = $false; IsInactive = $false; PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @() }
        )
        $summary = Get-AuditSummary -AuditResults $results
        $summary.TotalAccounts | Should -Be 3
        $summary.EnabledAccounts | Should -Be 2
        $summary.DisabledAccounts | Should -Be 1
        $summary.AdminAccounts | Should -Be 1
        $summary.InactiveAccounts | Should -Be 1
        $summary.AccountsWithIssues | Should -Be 1
    }

    It 'Counts CriticalIssues when any SecurityIssues entry contains "CRITICAL"' {
        $results = @(
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $true; IsAdmin = $true; IsInactive = $false; PasswordNeverExpires = $true; PasswordNotRequired = $false; SecurityIssues = @('Password never expires', 'CRITICAL: Admin account with security issues') }
        )
        $summary = Get-AuditSummary -AuditResults $results
        $summary.CriticalIssues | Should -Be 1
    }

    It 'Counts unique ComputersAudited across results' {
        $results = @(
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $true; IsAdmin = $false; IsInactive = $false; PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @() }
            [PSCustomObject]@{ ComputerName = 'PC2'; Enabled = $true; IsAdmin = $false; IsInactive = $false; PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @() }
            [PSCustomObject]@{ ComputerName = 'PC1'; Enabled = $true; IsAdmin = $false; IsInactive = $false; PasswordNeverExpires = $false; PasswordNotRequired = $false; SecurityIssues = @() }
        )
        $summary = Get-AuditSummary -AuditResults $results
        $summary.ComputersAudited | Should -Be 2
    }
}

Describe 'Get-UserAccountAudit.ps1 - Export-HtmlReport' {
    It 'Writes an HTML file with DOCTYPE and the audit period' {
        $outFile = Join-Path $TestDrive 'audit.html'
        $results = @(
            [PSCustomObject]@{
                ComputerName = 'PC1'; UserName = 'alice'; FullName = 'Alice'
                Enabled = $true; IsAdmin = $false; IsInactive = $false
                LastLogon = (Get-Date); PasswordLastSet = (Get-Date)
                PasswordExpires = (Get-Date).AddDays(30); PasswordNeverExpires = $false
                PasswordNotRequired = $false; PasswordAge = 10
                AccountSource = 'Local'; SID = 'S-1-5-21-9'
                Description = ''
                SecurityIssues = @()
            }
        )
        $summary = Get-AuditSummary -AuditResults $results
        Export-HtmlReport -AuditResults $results -Summary $summary -OutputFile $outFile

        Test-Path $outFile | Should -Be $true
        $content = Get-Content $outFile -Raw
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'alice'
    }
}
