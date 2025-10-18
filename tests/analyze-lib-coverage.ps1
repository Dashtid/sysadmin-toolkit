#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Analyzes code coverage for library modules only with detailed missed lines.
#>

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Configure Pester for library modules only
$Config = New-PesterConfiguration
$Config.Run.Path = Join-Path $PSScriptRoot "Windows"
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = @(
    (Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"),
    (Join-Path $ProjectRoot "Windows\lib\ErrorHandling.psm1")
)
$Config.CodeCoverage.OutputFormat = "JaCoCo"
$Config.CodeCoverage.OutputPath = "lib-coverage.xml"
$Config.Output.Verbosity = "Detailed"

Write-Host "[*] Running tests with coverage analysis on library modules only..." -ForegroundColor Cyan
Write-Host ""

# Run tests
$Result = Invoke-Pester -Configuration $Config

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LIBRARY MODULE COVERAGE ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Parse JaCoCo XML for detailed coverage
[xml]$coverage = Get-Content lib-coverage.xml

foreach ($package in $coverage.report.package) {
    Write-Host "Package: $($package.name)" -ForegroundColor Yellow

    foreach ($sourcefile in $package.sourcefile) {
        $fileName = $sourcefile.name
        Write-Host "  File: $fileName" -ForegroundColor White

        # Get line coverage
        $totalLines = 0
        $coveredLines = 0
        $missedLines = @()

        foreach ($line in $sourcefile.line) {
            $lineNum = [int]$line.nr
            $hits = [int]$line.ci

            if ($hits -eq 0) {
                $missedLines += $lineNum
            } else {
                $coveredLines++
            }
            $totalLines++
        }

        $percent = if ($totalLines -gt 0) { [math]::Round(($coveredLines / $totalLines) * 100, 2) } else { 0 }

        Write-Host "    Lines: $coveredLines/$totalLines ($percent%)" -ForegroundColor $(
            if ($percent -ge 90) { "Green" } elseif ($percent -ge 80) { "Yellow" } else { "Red" }
        )

        if ($missedLines.Count -gt 0 -and $missedLines.Count -le 20) {
            Write-Host "    Missed lines: $($missedLines -join ', ')" -ForegroundColor Red
        } elseif ($missedLines.Count -gt 20) {
            Write-Host "    Missed lines: $($missedLines.Count) lines not covered (too many to display)" -ForegroundColor Red
        }

        Write-Host ""
    }
}

# Overall stats
$instr = $coverage.report.counter | Where-Object { $_.type -eq 'INSTRUCTION' }
$covered = [int]$instr.covered
$missed = [int]$instr.missed
$total = $covered + $missed
$percent = if ($total -gt 0) { [math]::Round(($covered / $total) * 100, 2) } else { 0 }

Write-Host "Overall Library Coverage:" -ForegroundColor Cyan
Write-Host "  Instructions: $covered/$total ($percent%)" -ForegroundColor $(
    if ($percent -ge 90) { "Green" } elseif ($percent -ge 80) { "Yellow" } else { "Red" }
)

if ($percent -ge 90) {
    Write-Host "[+] SUCCESS: Library modules exceed 90% coverage!" -ForegroundColor Green
} else {
    $needed = [math]::Ceiling($total * 0.9) - $covered
    Write-Host "[!] Need $needed more instructions covered to reach 90%" -ForegroundColor Yellow
}

Write-Host ""
