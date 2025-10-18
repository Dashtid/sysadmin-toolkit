#!/usr/bin/env pwsh
# Quick library coverage check
[xml]$coverage = Get-Content lib-coverage.xml

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  LIBRARY MODULE COVERAGE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Overall stats
$instr = $coverage.report.counter | Where-Object { $_.type -eq 'INSTRUCTION' }
$covered = [int]$instr.covered
$missed = [int]$instr.missed
$total = $covered + $missed
$percent = if ($total -gt 0) { [math]::Round(($covered / $total) * 100, 2) } else { 0 }

Write-Host "Overall Library Coverage:" -ForegroundColor Yellow
Write-Host "  Instructions: $covered/$total ($percent%)`n" -ForegroundColor $(
    if ($percent -ge 90) { "Green" } elseif ($percent -ge 80) { "Yellow" } else { "Red" }
)

# Per-file breakdown
foreach ($package in $coverage.report.package) {
    foreach ($sourcefile in $package.sourcefile) {
        $fileName = $sourcefile.name

        # Get instruction coverage for this file
        $fileInstr = $sourcefile.counter | Where-Object { $_.type -eq 'INSTRUCTION' }
        if ($fileInstr) {
            $fileCovered = [int]$fileInstr.covered
            $fileMissed = [int]$fileInstr.missed
            $fileTotal = $fileCovered + $fileMissed
            $filePercent = if ($fileTotal -gt 0) { [math]::Round(($fileCovered / $fileTotal) * 100, 2) } else { 0 }

            Write-Host "$fileName : $fileCovered/$fileTotal ($filePercent%)" -ForegroundColor $(
                if ($filePercent -ge 90) { "Green" } elseif ($filePercent -ge 80) { "Yellow" } else { "Red" }
            )
        }
    }
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

if ($percent -ge 90) {
    Write-Host "[+] SUCCESS: Library modules exceed 90% coverage!" -ForegroundColor Green
    exit 0
} else {
    $needed = [math]::Ceiling($total * 0.9) - $covered
    Write-Host "[!] Need $needed more instructions covered to reach 90%" -ForegroundColor Yellow
    Write-Host "[i] Current gap: $([math]::Round(90 - $percent, 2))%" -ForegroundColor Blue
    exit 0
}
