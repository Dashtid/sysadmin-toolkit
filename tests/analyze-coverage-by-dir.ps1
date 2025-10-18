[xml]$coverage = Get-Content full-coverage.xml
$packages = $coverage.report.package

Write-Host 'Commands per directory:' -ForegroundColor Cyan
Write-Host ''

$dirStats = @()

foreach ($pkg in $packages) {
    $name = $pkg.name -replace 'Windows\\', '' -replace '\\', '/'
    $totalInstructions = 0
    $coveredInstructions = 0

    foreach ($counter in $pkg.counter) {
        if ($counter.type -eq 'INSTRUCTION') {
            $coveredInstructions = [int]$counter.covered
            $totalInstructions = [int]$counter.covered + [int]$counter.missed
        }
    }

    if ($totalInstructions -gt 0) {
        $percent = [math]::Round(($coveredInstructions / $totalInstructions) * 100, 1)
        $dirStats += [PSCustomObject]@{
            Directory = $name
            Commands = $totalInstructions
            Covered = $coveredInstructions
            Percent = $percent
        }
    }
}

$dirStats | Sort-Object Commands -Descending | ForEach-Object {
    $color = if ($_.Percent -ge 80) { "Green" }
             elseif ($_.Percent -ge 50) { "Yellow" }
             elseif ($_.Percent -ge 10) { "Cyan" }
             else { "Red" }

    Write-Host ("{0,-25} {1,5} commands ({2,5}% covered)" -f $_.Directory, $_.Commands, $_.Percent) -ForegroundColor $color
}

Write-Host ''
Write-Host 'Summary:' -ForegroundColor Cyan
$totalCommands = ($dirStats | Measure-Object -Property Commands -Sum).Sum
$totalCovered = ($dirStats | Measure-Object -Property Covered -Sum).Sum
$overallPercent = [math]::Round(($totalCovered / $totalCommands) * 100, 2)
Write-Host "  Total Commands: $totalCommands"
Write-Host "  Covered: $totalCovered"
Write-Host "  Overall: $overallPercent%"
