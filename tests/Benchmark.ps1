<#
.SYNOPSIS
    Performance benchmarking script for repository scripts.

.DESCRIPTION
    Measures execution time and resource usage of scripts to identify
    performance issues and track improvements over time.

.PARAMETER ScriptPath
    Path to the script to benchmark.

.PARAMETER Iterations
    Number of times to run the script for averaging (default: 5).

.PARAMETER OutputFormat
    Output format: Console, JSON, CSV (default: Console).

.EXAMPLE
    .\Benchmark.ps1 -ScriptPath "..\Windows\ssh\setup-ssh-agent-access.ps1" -Iterations 3

.NOTES
    Author: David Dashti
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$Iterations = 5,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "JSON", "CSV")]
    [string]$OutputFormat = "Console"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Level, [string]$Message)
    $color = switch ($Level) {
        "Info" { "Blue" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }
    $prefix = switch ($Level) {
        "Info" { "[i]" }
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error" { "[-]" }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Get-ScriptMetrics {
    param(
        [string]$Path,
        [int]$RunCount
    )

    $scriptName = Split-Path $Path -Leaf
    Write-Log -Level Info -Message "Benchmarking: $scriptName"
    Write-Log -Level Info -Message "Iterations: $RunCount"
    Write-Log -Level Info -Message "========================================"

    $results = @()
    $totalDuration = [TimeSpan]::Zero

    for ($i = 1; $i -le $RunCount; $i++) {
        Write-Log -Level Info -Message "Running iteration $i of $RunCount..."

        # Get process before
        $processCountBefore = (Get-Process).Count
        $memoryBefore = (Get-Process -Id $PID).WorkingSet64

        # Measure execution time
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            # Execute script (dot-source to measure but not actually run)
            # For actual benchmarking, you'd invoke with real parameters
            $null = & $Path -WhatIf -ErrorAction Stop 2>&1
            $success = $true
        }
        catch {
            Write-Log -Level Warning -Message "Iteration $i failed: $($_.Exception.Message)"
            $success = $false
        }

        $stopwatch.Stop()

        # Get process after
        $processCountAfter = (Get-Process).Count
        $memoryAfter = (Get-Process -Id $PID).WorkingSet64

        $duration = $stopwatch.Elapsed
        $totalDuration += $duration

        $result = [PSCustomObject]@{
            Iteration           = $i
            Success             = $success
            Duration            = $duration
            DurationMs          = $duration.TotalMilliseconds
            MemoryChangeMB      = [math]::Round(($memoryAfter - $memoryBefore) / 1MB, 2)
            ProcessCountChange  = $processCountAfter - $processCountBefore
        }

        $results += $result

        Write-Log -Level Success -Message "  Duration: $([math]::Round($duration.TotalMilliseconds, 2))ms"
        Write-Log -Level Info -Message "  Memory change: $([math]::Round(($memoryAfter - $memoryBefore) / 1MB, 2))MB"
    }

    return $results
}

function Get-BenchmarkSummary {
    param([array]$Results)

    $successfulRuns = $Results | Where-Object { $_.Success }

    if ($successfulRuns.Count -eq 0) {
        Write-Log -Level Error -Message "All iterations failed"
        return $null
    }

    $durations = $successfulRuns | ForEach-Object { $_.DurationMs }
    $memoryChanges = $successfulRuns | ForEach-Object { $_.MemoryChangeMB }

    $summary = [PSCustomObject]@{
        ScriptPath          = $ScriptPath
        TotalIterations     = $Results.Count
        SuccessfulRuns      = $successfulRuns.Count
        FailedRuns          = $Results.Count - $successfulRuns.Count
        AverageDurationMs   = [math]::Round(($durations | Measure-Object -Average).Average, 2)
        MinDurationMs       = [math]::Round(($durations | Measure-Object -Minimum).Minimum, 2)
        MaxDurationMs       = [math]::Round(($durations | Measure-Object -Maximum).Maximum, 2)
        MedianDurationMs    = [math]::Round(($durations | Sort-Object)[[math]::Floor($durations.Count / 2)], 2)
        StdDevDurationMs    = if ($durations.Count -gt 1) {
            $mean = ($durations | Measure-Object -Average).Average
            $variance = ($durations | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
            [math]::Round([math]::Sqrt($variance), 2)
        } else { 0 }
        AvgMemoryChangeMB   = [math]::Round(($memoryChanges | Measure-Object -Average).Average, 2)
        Timestamp           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    return $summary
}

function Format-ConsoleOutput {
    param([PSCustomObject]$Summary, [array]$Details)

    Write-Host ""
    Write-Log -Level Success -Message "========================================"
    Write-Log -Level Success -Message "BENCHMARK SUMMARY"
    Write-Log -Level Success -Message "========================================"
    Write-Host ""

    Write-Log -Level Info -Message "Script: $($Summary.ScriptPath)"
    Write-Host ""

    Write-Log -Level Info -Message "Execution Results:"
    Write-Host "  Total Runs:       $($Summary.TotalIterations)"
    Write-Host "  Successful:       $($Summary.SuccessfulRuns)" -ForegroundColor Green
    if ($Summary.FailedRuns -gt 0) {
        Write-Host "  Failed:           $($Summary.FailedRuns)" -ForegroundColor Red
    }
    Write-Host ""

    Write-Log -Level Info -Message "Performance Metrics:"
    Write-Host "  Average:          $($Summary.AverageDurationMs)ms"
    Write-Host "  Minimum:          $($Summary.MinDurationMs)ms"
    Write-Host "  Maximum:          $($Summary.MaxDurationMs)ms"
    Write-Host "  Median:           $($Summary.MedianDurationMs)ms"
    Write-Host "  Std Deviation:    $($Summary.StdDevDurationMs)ms"
    Write-Host ""

    Write-Log -Level Info -Message "Memory Impact:"
    Write-Host "  Avg Change:       $($Summary.AvgMemoryChangeMB)MB"
    Write-Host ""

    # Performance rating
    $avgMs = $Summary.AverageDurationMs
    if ($avgMs -lt 100) {
        Write-Log -Level Success -Message "Performance Rating: Excellent (<100ms)"
    }
    elseif ($avgMs -lt 500) {
        Write-Log -Level Success -Message "Performance Rating: Good (<500ms)"
    }
    elseif ($avgMs -lt 1000) {
        Write-Log -Level Warning -Message "Performance Rating: Acceptable (<1s)"
    }
    else {
        Write-Log -Level Warning -Message "Performance Rating: Slow (>1s)"
    }

    Write-Log -Level Success -Message "========================================"
}

function Export-BenchmarkResults {
    param(
        [PSCustomObject]$Summary,
        [array]$Details,
        [string]$Format
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $scriptName = Split-Path $ScriptPath -Leaf
    $baseFilename = "benchmark-$scriptName-$timestamp"

    switch ($Format) {
        "JSON" {
            $outputFile = "$baseFilename.json"
            $data = @{
                Summary = $Summary
                Details = $Details
            }
            $data | ConvertTo-Json -Depth 10 | Out-File $outputFile
            Write-Log -Level Success -Message "Results exported to: $outputFile"
        }

        "CSV" {
            $outputFile = "$baseFilename.csv"
            $Details | Export-Csv -Path $outputFile -NoTypeInformation
            Write-Log -Level Success -Message "Details exported to: $outputFile"

            $summaryFile = "$baseFilename-summary.csv"
            $Summary | Export-Csv -Path $summaryFile -NoTypeInformation
            Write-Log -Level Success -Message "Summary exported to: $summaryFile"
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    Write-Log -Level Info -Message "Starting benchmark..."
    Write-Host ""

    # Run benchmark
    $results = Get-ScriptMetrics -Path $ScriptPath -RunCount $Iterations

    # Generate summary
    $summary = Get-BenchmarkSummary -Results $results

    if ($null -eq $summary) {
        Write-Log -Level Error -Message "Benchmark failed"
        exit 1
    }

    # Output results
    switch ($OutputFormat) {
        "Console" {
            Format-ConsoleOutput -Summary $summary -Details $results
        }
        "JSON" {
            Export-BenchmarkResults -Summary $summary -Details $results -Format "JSON"
        }
        "CSV" {
            Export-BenchmarkResults -Summary $summary -Details $results -Format "CSV"
        }
    }

    Write-Host ""
    Write-Log -Level Success -Message "Benchmark completed successfully"
    exit 0
}
catch {
    Write-Log -Level Error -Message "Benchmark error: $($_.Exception.Message)"
    exit 1
}
