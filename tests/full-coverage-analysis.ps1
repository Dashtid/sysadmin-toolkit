#!/usr/bin/env pwsh
# Full repository code coverage analysis
# Analyzes ALL PowerShell files to determine actual coverage

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  FULL REPOSITORY COVERAGE ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Find all PowerShell files in Windows directory
$allFiles = Get-ChildItem -Path ".\Windows" -Recurse -Include "*.ps1","*.psm1" |
    Where-Object { $_.FullName -notmatch '\\tests\\' } |
    Select-Object -ExpandProperty FullName

Write-Host "[i] Found $($allFiles.Count) PowerShell files to analyze"
Write-Host ""

# Configure Pester with comprehensive coverage
$Config = New-PesterConfiguration
$Config.Run.Path = ".\tests\Windows"
$Config.Output.Verbosity = 'Minimal'

# Code Coverage - ALL PowerShell files
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = $allFiles
$Config.CodeCoverage.OutputPath = "full-coverage.xml"
$Config.CodeCoverage.OutputFormat = "JaCoCo"

Write-Host "[*] Running all tests with coverage analysis..." -ForegroundColor Blue
$Result = Invoke-Pester -Configuration $Config

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tests Passed:  " -NoNewline -ForegroundColor Green
Write-Host $Result.PassedCount
Write-Host "  Tests Failed:  " -NoNewline -ForegroundColor $(if ($Result.FailedCount -eq 0) { "Green" } else { "Red" })
Write-Host $Result.FailedCount
Write-Host "  Tests Skipped: " -NoNewline -ForegroundColor Yellow
Write-Host $Result.SkippedCount
Write-Host "  Total Tests:   " -NoNewline
Write-Host $Result.TotalCount

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CODE COVERAGE ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($Result.CodeCoverage.CommandsAnalyzedCount -gt 0) {
    $analyzed = $Result.CodeCoverage.CommandsAnalyzedCount
    $executed = $Result.CodeCoverage.CommandsExecutedCount
    $missed = $Result.CodeCoverage.CommandsMissedCount
    $coveragePercent = [math]::Round(($executed / $analyzed) * 100, 2)

    Write-Host "  Commands Analyzed: " -NoNewline
    Write-Host $analyzed
    Write-Host "  Commands Executed: " -NoNewline -ForegroundColor Green
    Write-Host $executed
    Write-Host "  Commands Missed:   " -NoNewline -ForegroundColor Yellow
    Write-Host $missed
    Write-Host ""
    Write-Host "  Overall Coverage:  " -NoNewline
    $color = if ($coveragePercent -ge 80) { "Green" } elseif ($coveragePercent -ge 70) { "Yellow" } elseif ($coveragePercent -ge 60) { "Cyan" } else { "Red" }
    Write-Host "$coveragePercent%" -ForegroundColor $color

    # Coverage by file
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  COVERAGE BY FILE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $coverageByFile = @()
    foreach ($file in $Result.CodeCoverage.CoverageReport) {
        $hitCount = $file.HitCommands.Count
        $missedCount = $file.MissedCommands.Count
        $totalCommands = $hitCount + $missedCount

        if ($totalCommands -gt 0) {
            $filePercent = [math]::Round(($hitCount / $totalCommands) * 100, 1)
            $fileName = Split-Path $file.File -Leaf
            $directory = Split-Path (Split-Path $file.File -Parent) -Leaf

            $coverageByFile += [PSCustomObject]@{
                Directory = $directory
                File = $fileName
                Coverage = $filePercent
                Hit = $hitCount
                Missed = $missedCount
                Total = $totalCommands
            }
        }
    }

    # Group by directory and show
    $byDirectory = $coverageByFile | Group-Object Directory | Sort-Object Name

    foreach ($group in $byDirectory) {
        Write-Host "[$($group.Name)]" -ForegroundColor Blue
        $group.Group | Sort-Object Coverage | ForEach-Object {
            $color = if ($_.Coverage -ge 80) { "Green" }
                     elseif ($_.Coverage -ge 70) { "Yellow" }
                     elseif ($_.Coverage -ge 50) { "Cyan" }
                     else { "Red" }

            Write-Host ("  {0,-40} {1,6}% ({2,4}/{3,4})" -f $_.File, $_.Coverage, $_.Hit, $_.Total) -ForegroundColor $color
        }
        Write-Host ""
    }

    # Files with 0% coverage (not tested at all)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  FILES WITH NO COVERAGE (0%)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $noCoverage = $coverageByFile | Where-Object { $_.Coverage -eq 0 } | Sort-Object Directory, File
    if ($noCoverage.Count -gt 0) {
        foreach ($file in $noCoverage) {
            Write-Host "  [-] $($file.Directory)/$($file.File)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [+] All files have some test coverage!" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total Files: $($allFiles.Count)"
    Write-Host "  Files with Coverage: $($coverageByFile.Count)"
    Write-Host "  Files with 0% Coverage: $($noCoverage.Count)"
    Write-Host "  Overall Coverage: $coveragePercent%"
    Write-Host ""

    if ($coveragePercent -ge 80) {
        Write-Host "  [+] EXCELLENT: Coverage target of 80% achieved!" -ForegroundColor Green
    } elseif ($coveragePercent -ge 70) {
        Write-Host "  [!] GOOD: Coverage at 70%, close to 80% target" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] NEEDS IMPROVEMENT: Coverage below 70% target" -ForegroundColor Red
    }

} else {
    Write-Host "  [-] No code coverage data available" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
