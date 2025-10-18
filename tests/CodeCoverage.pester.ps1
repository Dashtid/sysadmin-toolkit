<#
.SYNOPSIS
    Code coverage configuration and runner for Pester

.DESCRIPTION
    Configures and runs Pester tests with code coverage analysis.
    Generates HTML coverage reports and CI/CD compatible output.

.PARAMETER OutputFormat
    Format for coverage report (Console, HTML, JaCoCo, CoverageGutters)

.PARAMETER MinimumCoverage
    Minimum coverage percentage required to pass (default: 70)

.PARAMETER ExcludeTests
    Exclude test files from coverage analysis

.EXAMPLE
    .\tests\CodeCoverage.pester.ps1

.EXAMPLE
    .\tests\CodeCoverage.pester.ps1 -OutputFormat HTML -MinimumCoverage 80

.NOTES
    Author: David Dashti
    Version: 1.0.0
    Last Updated: 2025-10-18
    Requires: Pester 5.3+
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JaCoCo', 'CoverageGutters', 'All')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$MinimumCoverage = 70,

    [Parameter()]
    [switch]$ExcludeTests
)

# Colors for output
$Colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error   = 'Red'
    Info    = 'Cyan'
}

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Type = 'Info'
    )
    Write-Host $Message -ForegroundColor $Colors[$Type]
}

# ============================================================================
# SETUP
# ============================================================================

Write-ColorMessage "`n========================================" -Type Info
Write-ColorMessage "  Code Coverage Analysis with Pester" -Type Info
Write-ColorMessage "========================================`n" -Type Info

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Check Pester version
$PesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1

if (-not $PesterModule) {
    Write-ColorMessage "[-] Pester is not installed" -Type Error
    Write-ColorMessage "[i] Install with: Install-Module -Name Pester -Force -Scope CurrentUser" -Type Info
    exit 1
}

if ($PesterModule.Version.Major -lt 5) {
    Write-ColorMessage "[-] Pester 5.0+ required, found version $($PesterModule.Version)" -Type Error
    Write-ColorMessage "[i] Update with: Install-Module -Name Pester -Force -Scope CurrentUser -AllowClobber" -Type Info
    exit 1
}

Write-ColorMessage "[+] Pester version: $($PesterModule.Version)" -Type Success

# ============================================================================
# CONFIGURE PESTER
# ============================================================================

$Config = New-PesterConfiguration

# Test execution settings
$Config.Run.Path = Join-Path $ProjectRoot "tests\Windows"
$Config.Run.PassThru = $true

# Output settings
$Config.Output.Verbosity = 'Detailed'

# Code Coverage settings
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = @(
    Join-Path $ProjectRoot "Windows\lib\*.psm1"
    Join-Path $ProjectRoot "Windows\ssh\*.ps1"
    Join-Path $ProjectRoot "Windows\maintenance\*.ps1"
    Join-Path $ProjectRoot "Windows\security\*.ps1"
)

if ($ExcludeTests) {
    $Config.CodeCoverage.ExcludeTests = $true
}

# Coverage output paths
$OutputDir = Join-Path $ProjectRoot "coverage"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# Configure output formats
switch ($OutputFormat) {
    'HTML' {
        $Config.CodeCoverage.OutputFormat = 'JaCoCo'
        $Config.CodeCoverage.OutputPath = Join-Path $OutputDir "coverage.xml"
    }
    'JaCoCo' {
        $Config.CodeCoverage.OutputFormat = 'JaCoCo'
        $Config.CodeCoverage.OutputPath = Join-Path $OutputDir "coverage.xml"
    }
    'CoverageGutters' {
        $Config.CodeCoverage.OutputFormat = 'CoverageGutters'
        $Config.CodeCoverage.OutputPath = Join-Path $OutputDir "coverage.json"
    }
    'All' {
        # Will generate multiple formats
        $Config.CodeCoverage.OutputFormat = 'JaCoCo'
        $Config.CodeCoverage.OutputPath = Join-Path $OutputDir "coverage.xml"
    }
}

# ============================================================================
# RUN TESTS WITH COVERAGE
# ============================================================================

Write-ColorMessage "`n[*] Running tests with code coverage analysis..." -Type Info
Write-ColorMessage "[*] Analyzing paths:" -Type Info
foreach ($path in $Config.CodeCoverage.Path.Value) {
    Write-ColorMessage "    - $path" -Type Info
}

$StartTime = Get-Date
$Result = Invoke-Pester -Configuration $Config
$Duration = (Get-Date) - $StartTime

# ============================================================================
# ANALYZE RESULTS
# ============================================================================

Write-ColorMessage "`n========================================" -Type Info
Write-ColorMessage "  Coverage Analysis Results" -Type Info
Write-ColorMessage "========================================`n" -Type Info

# Test results
Write-ColorMessage "[*] Test Execution:" -Type Info
Write-ColorMessage "    Total Tests: $($Result.TotalCount)" -Type Info
Write-ColorMessage "    Passed: $($Result.PassedCount)" -Type $(if ($Result.PassedCount -eq $Result.TotalCount) { 'Success' } else { 'Info' })
Write-ColorMessage "    Failed: $($Result.FailedCount)" -Type $(if ($Result.FailedCount -eq 0) { 'Success' } else { 'Error' })
Write-ColorMessage "    Skipped: $($Result.SkippedCount)" -Type Info
Write-ColorMessage "    Duration: $($Duration.TotalSeconds.ToString('F2'))s`n" -Type Info

# Coverage results
$CoveragePercent = [Math]::Round($Result.CodeCoverage.CoveragePercent, 2)

Write-ColorMessage "[*] Code Coverage:" -Type Info
Write-ColorMessage "    Commands Analyzed: $($Result.CodeCoverage.CommandsAnalyzed)" -Type Info
Write-ColorMessage "    Commands Executed: $($Result.CodeCoverage.CommandsExecuted)" -Type Info
Write-ColorMessage "    Commands Missed: $($Result.CodeCoverage.CommandsMissed)" -Type Info

$CoverageType = if ($CoveragePercent -ge 80) { 'Success' }
                elseif ($CoveragePercent -ge $MinimumCoverage) { 'Warning' }
                else { 'Error' }

Write-ColorMessage "    Coverage: $CoveragePercent%" -Type $CoverageType

# Missed commands summary
if ($Result.CodeCoverage.MissedCommands.Count -gt 0) {
    Write-ColorMessage "`n[!] Missed Commands by File:" -Type Warning

    $MissedByFile = $Result.CodeCoverage.MissedCommands | Group-Object File

    foreach ($file in $MissedByFile) {
        $fileName = Split-Path $file.Name -Leaf
        Write-ColorMessage "    $fileName - $($file.Count) missed commands" -Type Warning

        # Show top 5 missed lines
        $topMissed = $file.Group | Select-Object -First 5 -Property Line, Command
        foreach ($missed in $topMissed) {
            Write-ColorMessage "        Line $($missed.Line): $($missed.Command)" -Type Info
        }

        if ($file.Count -gt 5) {
            Write-ColorMessage "        ... and $($file.Count - 5) more" -Type Info
        }
    }
}

# ============================================================================
# GENERATE REPORTS
# ============================================================================

if ($OutputFormat -in @('HTML', 'All')) {
    Write-ColorMessage "`n[*] Generating HTML coverage report..." -Type Info

    # Check if ReportGenerator is available
    $ReportGenPath = Get-Command reportgenerator -ErrorAction SilentlyContinue

    if ($ReportGenPath) {
        $reportArgs = @(
            "-reports:$($Config.CodeCoverage.OutputPath.Value)"
            "-targetdir:$(Join-Path $OutputDir 'html')"
            "-reporttypes:Html"
        )

        & reportgenerator $reportArgs

        $htmlReport = Join-Path $OutputDir "html\index.html"
        if (Test-Path $htmlReport) {
            Write-ColorMessage "[+] HTML report generated: $htmlReport" -Type Success
            Write-ColorMessage "[i] Open in browser: Start-Process '$htmlReport'" -Type Info
        }
    }
    else {
        Write-ColorMessage "[!] ReportGenerator not found - install with:" -Type Warning
        Write-ColorMessage "    dotnet tool install -g dotnet-reportgenerator-globaltool" -Type Info
    }
}

# ============================================================================
# SUMMARY AND EXIT
# ============================================================================

Write-ColorMessage "`n========================================" -Type Info
Write-ColorMessage "  Summary" -Type Info
Write-ColorMessage "========================================`n" -Type Info

if ($Result.FailedCount -gt 0) {
    Write-ColorMessage "[-] Tests FAILED: $($Result.FailedCount) test(s) failed" -Type Error
    exit 1
}

if ($CoveragePercent -lt $MinimumCoverage) {
    Write-ColorMessage "[-] Coverage FAILED: $CoveragePercent% < $MinimumCoverage% minimum" -Type Error
    exit 1
}

Write-ColorMessage "[+] All tests passed" -Type Success
Write-ColorMessage "[+] Coverage $CoveragePercent% meets minimum $MinimumCoverage%" -Type Success

if ($Config.CodeCoverage.OutputPath.Value) {
    Write-ColorMessage "`n[i] Coverage report: $($Config.CodeCoverage.OutputPath.Value)" -Type Info
}

Write-ColorMessage "`n[+] Code coverage analysis complete!`n" -Type Success

exit 0
