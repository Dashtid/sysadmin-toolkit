#!/usr/bin/env pwsh
# Test CommonFunctions.psm1 coverage only

$ProjectRoot = Split-Path $PSScriptRoot -Parent

Write-Host "[*] Running CommonFunctions tests with coverage..." -ForegroundColor Cyan

$Config = New-PesterConfiguration
$Config.Run.Path = Join-Path $PSScriptRoot "Windows\CommonFunctions.Tests.ps1"
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = Join-Path $ProjectRoot "Windows\lib\CommonFunctions.psm1"
$Config.CodeCoverage.OutputFormat = "JaCoCo"
$Config.CodeCoverage.OutputPath = "lib-coverage.xml"
$Config.Output.Verbosity = "Minimal"

$Result = Invoke-Pester -Configuration $Config

Write-Host "`n[+] Tests completed. Analyzing coverage..." -ForegroundColor Green

# Parse coverage
[xml]$coverage = Get-Content lib-coverage.xml
$instr = $coverage.report.counter | Where-Object { $_.type -eq 'INSTRUCTION' }
$covered = [int]$instr.covered
$missed = [int]$instr.missed
$total = $covered + $missed
$percent = if ($total -gt 0) { [math]::Round(($covered / $total) * 100, 2) } else { 0 }

Write-Host "`nCommonFunctions.psm1 Coverage:" -ForegroundColor Yellow
Write-Host "  Instructions: $covered/$total ($percent%)" -ForegroundColor $(
    if ($percent -ge 90) { "Green" } elseif ($percent -ge 80) { "Yellow" } else { "Red" }
)

if ($percent -ge 90) {
    Write-Host "[+] SUCCESS: CommonFunctions exceeds 90% coverage!" -ForegroundColor Green
} else {
    $needed = [math]::Ceiling($total * 0.9) - $covered
    Write-Host "[!] Need $needed more instructions to reach 90%" -ForegroundColor Yellow
}
