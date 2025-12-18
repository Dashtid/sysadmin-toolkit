#Requires -Version 5.1
<#
.SYNOPSIS
    Audits local user accounts for security compliance and best practices.

.DESCRIPTION
    This script performs a comprehensive audit of local user accounts including:
    - Lists all local user accounts with details
    - Checks administrator group membership
    - Identifies inactive/dormant accounts
    - Tracks password expiration status
    - Detects accounts with no password or password never expires
    - Identifies last logon times for all users
    - Generates compliance reports (Console, HTML, JSON, CSV)

.PARAMETER DaysInactive
    Number of days without login to consider an account inactive. Default: 90 days.

.PARAMETER PasswordAgeDays
    Number of days after which a password is considered old. Default: 90 days.

.PARAMETER OutputFormat
    Output format: Console, HTML, JSON, CSV, or All. Default: Console.

.PARAMETER OutputPath
    Directory for output files. Default: toolkit logs directory.

.PARAMETER IncludeDisabled
    Include disabled accounts in the audit. Default: $true.

.PARAMETER CheckRemoteComputers
    Array of remote computer names to audit (requires admin access).

.EXAMPLE
    .\Get-UserAccountAudit.ps1
    Runs a basic user account audit with default settings.

.EXAMPLE
    .\Get-UserAccountAudit.ps1 -DaysInactive 60 -OutputFormat HTML
    Audits accounts inactive for 60+ days and outputs HTML report.

.EXAMPLE
    .\Get-UserAccountAudit.ps1 -OutputFormat All -OutputPath "C:\Reports"
    Generates all report formats to the specified directory.

.EXAMPLE
    .\Get-UserAccountAudit.ps1 -CheckRemoteComputers "SERVER01", "SERVER02"
    Audits user accounts on remote computers.

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+
    Recommendation: Run with administrator privileges for complete information.

.OUTPUTS
    PSCustomObject containing audit results with properties:
    - ComputerName, UserName, FullName, Enabled, IsAdmin
    - LastLogon, PasswordLastSet, PasswordExpires, PasswordNeverExpires
    - PasswordNotRequired, IsInactive, PasswordAge, SecurityIssues

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$PasswordAgeDays = 90,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeDisabled = $true,

    [Parameter()]
    [string[]]$CheckRemoteComputers
)

#region Module Import
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path (Split-Path -Parent $scriptRoot) "lib\CommonFunctions.psm1"

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fallback functions if module not available
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Test-IsAdministrator {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Get-LogDirectory {
        $logPath = Join-Path $scriptRoot "..\..\..\logs"
        if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
        return (Resolve-Path $logPath).Path
    }
}
#endregion

#region Helper Functions
function Get-LocalAdminMembers {
    <#
    .SYNOPSIS
        Gets members of the local Administrators group.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            return $adminGroup.Name | ForEach-Object { $_.Split('\')[-1] }
        } else {
            $adminGroup = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Get-LocalGroupMember -Group "Administrators"
            } -ErrorAction Stop
            return $adminGroup.Name | ForEach-Object { $_.Split('\')[-1] }
        }
    } catch {
        Write-WarningMessage "Could not retrieve admin group members: $($_.Exception.Message)"
        return @()
    }
}

function Get-UserSecurityIssues {
    <#
    .SYNOPSIS
        Identifies security issues for a user account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$UserInfo,

        [Parameter()]
        [int]$DaysInactive,

        [Parameter()]
        [int]$PasswordAgeDays
    )

    $issues = @()

    # Check for password never expires
    if ($UserInfo.PasswordNeverExpires -and $UserInfo.Enabled) {
        $issues += "Password never expires"
    }

    # Check for no password required
    if ($UserInfo.PasswordNotRequired -and $UserInfo.Enabled) {
        $issues += "Password not required"
    }

    # Check for inactive account
    if ($UserInfo.IsInactive -and $UserInfo.Enabled) {
        $issues += "Inactive for $DaysInactive+ days"
    }

    # Check for old password
    if ($UserInfo.PasswordAge -gt $PasswordAgeDays -and $UserInfo.Enabled) {
        $issues += "Password older than $PasswordAgeDays days"
    }

    # Check for admin with issues
    if ($UserInfo.IsAdmin -and $issues.Count -gt 0) {
        $issues += "CRITICAL: Admin account with security issues"
    }

    # Check for enabled built-in Administrator
    if ($UserInfo.UserName -eq "Administrator" -and $UserInfo.Enabled) {
        $issues += "Built-in Administrator account is enabled"
    }

    # Check for enabled Guest account
    if ($UserInfo.UserName -eq "Guest" -and $UserInfo.Enabled) {
        $issues += "Guest account is enabled"
    }

    return $issues
}

function Get-UserAccountDetails {
    <#
    .SYNOPSIS
        Gets detailed information about user accounts.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int]$DaysInactive = 90,

        [Parameter()]
        [int]$PasswordAgeDays = 90,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    $results = @()
    $adminMembers = Get-LocalAdminMembers -ComputerName $ComputerName
    $now = Get-Date
    $inactiveThreshold = $now.AddDays(-$DaysInactive)

    try {
        # Get local users
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $users = Get-LocalUser
        } else {
            $users = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Get-LocalUser
            } -ErrorAction Stop
        }

        foreach ($user in $users) {
            # Skip disabled accounts if not requested
            if (-not $IncludeDisabled -and -not $user.Enabled) {
                continue
            }

            # Calculate password age
            $passwordAge = if ($user.PasswordLastSet) {
                [int]($now - $user.PasswordLastSet).TotalDays
            } else {
                -1
            }

            # Determine if inactive
            $isInactive = $false
            if ($user.LastLogon) {
                $isInactive = $user.LastLogon -lt $inactiveThreshold
            } elseif ($user.Enabled) {
                # Never logged in but enabled - consider inactive
                $isInactive = $true
            }

            $userInfo = [PSCustomObject]@{
                ComputerName         = $ComputerName
                UserName             = $user.Name
                FullName             = $user.FullName
                Description          = $user.Description
                Enabled              = $user.Enabled
                IsAdmin              = $adminMembers -contains $user.Name
                LastLogon            = $user.LastLogon
                PasswordLastSet      = $user.PasswordLastSet
                PasswordExpires      = $user.PasswordExpires
                PasswordNeverExpires = $user.PasswordNeverExpires
                PasswordNotRequired  = $user.PasswordNotRequired
                UserMayChangePassword = $user.UserMayChangePassword
                PasswordAge          = $passwordAge
                IsInactive           = $isInactive
                AccountSource        = $user.PrincipalSource
                SID                  = $user.SID.Value
                SecurityIssues       = @()
            }

            # Get security issues
            $userInfo.SecurityIssues = Get-UserSecurityIssues -UserInfo $userInfo -DaysInactive $DaysInactive -PasswordAgeDays $PasswordAgeDays

            $results += $userInfo
        }
    } catch {
        Write-ErrorMessage "Failed to get user accounts from ${ComputerName}: $($_.Exception.Message)"
    }

    return $results
}

function Get-AuditSummary {
    <#
    .SYNOPSIS
        Generates a summary of the audit results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$AuditResults
    )

    $summary = [PSCustomObject]@{
        TotalAccounts           = $AuditResults.Count
        EnabledAccounts         = ($AuditResults | Where-Object { $_.Enabled }).Count
        DisabledAccounts        = ($AuditResults | Where-Object { -not $_.Enabled }).Count
        AdminAccounts           = ($AuditResults | Where-Object { $_.IsAdmin }).Count
        InactiveAccounts        = ($AuditResults | Where-Object { $_.IsInactive -and $_.Enabled }).Count
        PasswordNeverExpires    = ($AuditResults | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }).Count
        PasswordNotRequired     = ($AuditResults | Where-Object { $_.PasswordNotRequired -and $_.Enabled }).Count
        AccountsWithIssues      = ($AuditResults | Where-Object { $_.SecurityIssues.Count -gt 0 }).Count
        CriticalIssues          = ($AuditResults | Where-Object { $_.SecurityIssues -match "CRITICAL" }).Count
        AuditDate               = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputersAudited        = ($AuditResults | Select-Object -ExpandProperty ComputerName -Unique).Count
    }

    return $summary
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports audit results to HTML format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$AuditResults,

        [Parameter(Mandatory)]
        [PSCustomObject]$Summary,

        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>User Account Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #0078d4; }
        .summary-card.warning { border-left-color: #ffc107; }
        .summary-card.danger { border-left-color: #dc3545; }
        .summary-card.success { border-left-color: #28a745; }
        .summary-card h3 { margin: 0 0 5px 0; font-size: 14px; color: #666; }
        .summary-card .value { font-size: 28px; font-weight: bold; color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
        th { background: #0078d4; color: white; padding: 12px 8px; text-align: left; }
        td { padding: 10px 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .status-enabled { color: #28a745; font-weight: bold; }
        .status-disabled { color: #6c757d; }
        .status-admin { background: #fff3cd; }
        .status-issue { background: #f8d7da; }
        .issues { color: #dc3545; font-size: 12px; }
        .no-issues { color: #28a745; }
        .timestamp { color: #666; font-size: 12px; margin-top: 20px; }
        .legend { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .legend-item { display: inline-block; margin-right: 20px; }
        .legend-color { display: inline-block; width: 16px; height: 16px; margin-right: 5px; vertical-align: middle; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>User Account Audit Report</h1>
        <p class="timestamp">Generated: $($Summary.AuditDate) | Computers Audited: $($Summary.ComputersAudited)</p>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Accounts</h3>
                <div class="value">$($Summary.TotalAccounts)</div>
            </div>
            <div class="summary-card success">
                <h3>Enabled Accounts</h3>
                <div class="value">$($Summary.EnabledAccounts)</div>
            </div>
            <div class="summary-card">
                <h3>Disabled Accounts</h3>
                <div class="value">$($Summary.DisabledAccounts)</div>
            </div>
            <div class="summary-card warning">
                <h3>Admin Accounts</h3>
                <div class="value">$($Summary.AdminAccounts)</div>
            </div>
            <div class="summary-card warning">
                <h3>Inactive Accounts</h3>
                <div class="value">$($Summary.InactiveAccounts)</div>
            </div>
            <div class="summary-card danger">
                <h3>Password Never Expires</h3>
                <div class="value">$($Summary.PasswordNeverExpires)</div>
            </div>
            <div class="summary-card danger">
                <h3>Password Not Required</h3>
                <div class="value">$($Summary.PasswordNotRequired)</div>
            </div>
            <div class="summary-card danger">
                <h3>Accounts With Issues</h3>
                <div class="value">$($Summary.AccountsWithIssues)</div>
            </div>
        </div>

        <div class="legend">
            <strong>Legend:</strong>
            <span class="legend-item"><span class="legend-color" style="background:#fff3cd;"></span> Admin Account</span>
            <span class="legend-item"><span class="legend-color" style="background:#f8d7da;"></span> Has Security Issues</span>
        </div>

        <h2>Account Details</h2>
        <table>
            <tr>
                <th>Computer</th>
                <th>Username</th>
                <th>Full Name</th>
                <th>Status</th>
                <th>Admin</th>
                <th>Last Logon</th>
                <th>Password Age</th>
                <th>Pwd Expires</th>
                <th>Security Issues</th>
            </tr>
"@

    foreach ($account in $AuditResults | Sort-Object ComputerName, UserName) {
        $statusClass = if ($account.Enabled) { "status-enabled" } else { "status-disabled" }
        $statusText = if ($account.Enabled) { "Enabled" } else { "Disabled" }
        $rowClass = ""
        if ($account.SecurityIssues.Count -gt 0) { $rowClass = "status-issue" }
        elseif ($account.IsAdmin) { $rowClass = "status-admin" }

        $lastLogon = if ($account.LastLogon) { $account.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        $passwordAge = if ($account.PasswordAge -ge 0) { "$($account.PasswordAge) days" } else { "N/A" }
        $pwdExpires = if ($account.PasswordNeverExpires) { "Never" } elseif ($account.PasswordExpires) { $account.PasswordExpires.ToString("yyyy-MM-dd") } else { "N/A" }
        $adminStatus = if ($account.IsAdmin) { "Yes" } else { "No" }
        $issuesHtml = if ($account.SecurityIssues.Count -gt 0) {
            "<span class='issues'>" + ($account.SecurityIssues -join "<br>") + "</span>"
        } else {
            "<span class='no-issues'>None</span>"
        }

        $html += @"
            <tr class="$rowClass">
                <td>$($account.ComputerName)</td>
                <td><strong>$($account.UserName)</strong></td>
                <td>$($account.FullName)</td>
                <td class="$statusClass">$statusText</td>
                <td>$adminStatus</td>
                <td>$lastLogon</td>
                <td>$passwordAge</td>
                <td>$pwdExpires</td>
                <td>$issuesHtml</td>
            </tr>
"@
    }

    $html += @"
        </table>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}
#endregion

#region Main Execution
function Invoke-UserAccountAudit {
    [CmdletBinding()]
    param()

    Write-InfoMessage "Starting User Account Audit"
    Write-InfoMessage "Parameters: Inactive threshold=$DaysInactive days, Password age threshold=$PasswordAgeDays days"

    # Check for admin privileges
    if (-not (Test-IsAdministrator)) {
        Write-WarningMessage "Running without administrator privileges. Some information may be limited."
    }

    # Set output path
    if (-not $OutputPath) {
        $OutputPath = Get-LogDirectory
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Collect audit results
    $allResults = @()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Audit local computer
    Write-InfoMessage "Auditing local computer: $env:COMPUTERNAME"
    $localResults = Get-UserAccountDetails -ComputerName $env:COMPUTERNAME -DaysInactive $DaysInactive -PasswordAgeDays $PasswordAgeDays -IncludeDisabled:$IncludeDisabled
    $allResults += $localResults

    # Audit remote computers if specified
    if ($CheckRemoteComputers) {
        foreach ($computer in $CheckRemoteComputers) {
            Write-InfoMessage "Auditing remote computer: $computer"
            try {
                $remoteResults = Get-UserAccountDetails -ComputerName $computer -DaysInactive $DaysInactive -PasswordAgeDays $PasswordAgeDays -IncludeDisabled:$IncludeDisabled
                $allResults += $remoteResults
            } catch {
                Write-ErrorMessage "Failed to audit ${computer}: $($_.Exception.Message)"
            }
        }
    }

    # Generate summary
    $summary = Get-AuditSummary -AuditResults $allResults

    # Output results based on format
    switch ($OutputFormat) {
        'Console' {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "       USER ACCOUNT AUDIT SUMMARY       " -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Total Accounts:          $($summary.TotalAccounts)"
            Write-Host "Enabled Accounts:        $($summary.EnabledAccounts)" -ForegroundColor Green
            Write-Host "Disabled Accounts:       $($summary.DisabledAccounts)" -ForegroundColor Gray
            Write-Host "Admin Accounts:          $($summary.AdminAccounts)" -ForegroundColor Yellow
            Write-Host "Inactive Accounts:       $($summary.InactiveAccounts)" -ForegroundColor Yellow
            Write-Host "Password Never Expires:  $($summary.PasswordNeverExpires)" -ForegroundColor Red
            Write-Host "Password Not Required:   $($summary.PasswordNotRequired)" -ForegroundColor Red
            Write-Host "Accounts With Issues:    $($summary.AccountsWithIssues)" -ForegroundColor Red
            Write-Host ""

            # Show accounts with issues
            $issueAccounts = $allResults | Where-Object { $_.SecurityIssues.Count -gt 0 }
            if ($issueAccounts) {
                Write-Host "ACCOUNTS WITH SECURITY ISSUES:" -ForegroundColor Red
                Write-Host "------------------------------" -ForegroundColor Red
                foreach ($account in $issueAccounts) {
                    Write-Host "  [$($account.ComputerName)] $($account.UserName)" -ForegroundColor White
                    foreach ($issue in $account.SecurityIssues) {
                        Write-Host "    - $issue" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Success "No security issues found!"
            }
        }

        'HTML' {
            $htmlFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.html"
            Export-HtmlReport -AuditResults $allResults -Summary $summary -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"
        }

        'JSON' {
            $jsonFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.json"
            $exportData = @{
                Summary = $summary
                Accounts = $allResults | ForEach-Object {
                    $_ | Select-Object ComputerName, UserName, FullName, Enabled, IsAdmin,
                        LastLogon, PasswordLastSet, PasswordExpires, PasswordNeverExpires,
                        PasswordNotRequired, PasswordAge, IsInactive, SecurityIssues
                }
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"
        }

        'CSV' {
            $csvFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.csv"
            $allResults | Select-Object ComputerName, UserName, FullName, Enabled, IsAdmin,
                @{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss")}else{"Never"}}},
                @{N='PasswordLastSet';E={if($_.PasswordLastSet){$_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")}else{"Never"}}},
                PasswordNeverExpires, PasswordNotRequired, PasswordAge, IsInactive,
                @{N='SecurityIssues';E={$_.SecurityIssues -join "; "}} |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"
        }

        'All' {
            # HTML
            $htmlFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.html"
            Export-HtmlReport -AuditResults $allResults -Summary $summary -OutputFile $htmlFile
            Write-Success "HTML report saved to: $htmlFile"

            # JSON
            $jsonFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.json"
            $exportData = @{
                Summary = $summary
                Accounts = $allResults | ForEach-Object {
                    $_ | Select-Object ComputerName, UserName, FullName, Enabled, IsAdmin,
                        LastLogon, PasswordLastSet, PasswordExpires, PasswordNeverExpires,
                        PasswordNotRequired, PasswordAge, IsInactive, SecurityIssues
                }
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Success "JSON report saved to: $jsonFile"

            # CSV
            $csvFile = Join-Path $OutputPath "UserAccountAudit_$timestamp.csv"
            $allResults | Select-Object ComputerName, UserName, FullName, Enabled, IsAdmin,
                @{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss")}else{"Never"}}},
                @{N='PasswordLastSet';E={if($_.PasswordLastSet){$_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")}else{"Never"}}},
                PasswordNeverExpires, PasswordNotRequired, PasswordAge, IsInactive,
                @{N='SecurityIssues';E={$_.SecurityIssues -join "; "}} |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Success "CSV report saved to: $csvFile"

            # Also show console summary
            Write-Host ""
            Write-Host "Summary: $($summary.TotalAccounts) accounts audited, $($summary.AccountsWithIssues) with issues"
        }
    }

    Write-Success "User account audit completed"

    # Return results for pipeline usage
    return [PSCustomObject]@{
        Summary = $summary
        Accounts = $allResults
        ExitCode = if ($summary.CriticalIssues -gt 0) { 2 } elseif ($summary.AccountsWithIssues -gt 0) { 1 } else { 0 }
    }
}

# Run the audit
$result = Invoke-UserAccountAudit
exit $result.ExitCode
#endregion
