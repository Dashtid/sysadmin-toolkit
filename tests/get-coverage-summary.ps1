Import-Module Pester -MinimumVersion 5.0

$Config = New-PesterConfiguration
$Config.Run.Path = ".\tests\Windows"
$Config.Output.Verbosity = 'None'
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = @(
    ".\Windows\lib\*.psm1",
    ".\Windows\ssh\*.ps1",
    ".\Windows\maintenance\*.ps1",
    ".\Windows\security\*.ps1"
)

$Result = Invoke-Pester -Configuration $Config

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CODE COVERAGE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Test Results:" -ForegroundColor Blue
Write-Host "    Tests Passed: $($Result.PassedCount)" -ForegroundColor Green
Write-Host "    Tests Failed: $($Result.FailedCount)" -ForegroundColor $(if ($Result.FailedCount -eq 0) { "Green" } else { "Red" })
Write-Host "    Tests Skipped: $($Result.SkippedCount)" -ForegroundColor Yellow
Write-Host "    Total Tests: $($Result.TotalCount)"
Write-Host ""
Write-Host "[*] Code Coverage:" -ForegroundColor Blue

$commandsAnalyzed = $Result.CodeCoverage.CommandsAnalyzedCount
$commandsExecuted = $Result.CodeCoverage.CommandsExecutedCount
$commandsMissed = $Result.CodeCoverage.CommandsMissedCount

if ($commandsAnalyzed -gt 0) {
    $coveragePercent = [math]::Round(($commandsExecuted / $commandsAnalyzed) * 100, 2)

    Write-Host "    Commands Analyzed: $commandsAnalyzed"
    Write-Host "    Commands Executed: $commandsExecuted" -ForegroundColor Green
    Write-Host "    Commands Missed: $commandsMissed" -ForegroundColor Yellow
    Write-Host "    Coverage: $coveragePercent%" -ForegroundColor $(if ($coveragePercent -ge 70) { "Green" } elseif ($coveragePercent -ge 50) { "Yellow" } else { "Red" })
    Write-Host ""

    # Files analyzed
    Write-Host "[*] Files Analyzed:" -ForegroundColor Blue
    $Result.CodeCoverage.CoverageReport | ForEach-Object {
        $filePercent = if ($_.MissedCommands.Count + $_.HitCommands.Count -gt 0) {
            [math]::Round(($_.HitCommands.Count / ($_.MissedCommands.Count + $_.HitCommands.Count)) * 100, 1)
        } else { 0 }
        $fileName = Split-Path $_.File -Leaf
        Write-Host "    $fileName : $filePercent%"
    }
} else {
    Write-Host "    No code coverage data available" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
