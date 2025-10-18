[xml]$coverage = Get-Content full-coverage.xml

$instr = $coverage.report.counter | Where-Object { $_.type -eq 'INSTRUCTION' }
$covered = [int]$instr.covered
$missed = [int]$instr.missed
$total = $covered + $missed
$percent = if ($total -gt 0) { [math]::Round(($covered / $total) * 100, 2) } else { 0 }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  FINAL CODE COVERAGE RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Instructions:" -ForegroundColor Blue
Write-Host "    Total: $total"
Write-Host "    Covered: $covered" -ForegroundColor Green
Write-Host "    Missed: $missed" -ForegroundColor Yellow
Write-Host "    Coverage: $percent%" -ForegroundColor $(if ($percent -ge 80) { "Green" } elseif ($percent -ge 70) { "Yellow" } else { "Red" })
Write-Host ""

# Calculate needed for 80%
$target = [math]::Ceiling($total * 0.8)
$shortfall = $target - $covered

if ($percent -ge 80) {
    Write-Host "[+] SUCCESS: Exceeded 80% coverage target!" -ForegroundColor Green
} elseif ($percent -ge 70) {
    Write-Host "[!] WARNING: Close to target - need $shortfall more instructions covered" -ForegroundColor Yellow
} else {
    Write-Host "[-] Below 70% minimum threshold - need $shortfall more instructions covered" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
