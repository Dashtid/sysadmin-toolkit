<#
.SYNOPSIS
    Code quality validation script for sysadmin-toolkit

.DESCRIPTION
    Runs code quality checks across PowerShell, Bash, and Python files.
    Validates syntax, style, and best practices compliance.

.PARAMETER SkipPowerShell
    Skip PowerShell script validation

.PARAMETER SkipBash
    Skip Bash script validation

.PARAMETER SkipPython
    Skip Python script validation

.PARAMETER Fix
    Automatically fix issues where possible (PowerShell and Python only)

.EXAMPLE
    .\scripts\validate-code-quality.ps1

.EXAMPLE
    .\scripts\validate-code-quality.ps1 -Fix

.EXAMPLE
    .\scripts\validate-code-quality.ps1 -SkipPython

.NOTES
    Author: David Dashti
    Version: 1.0.0
    Last Updated: 2025-10-18
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipPowerShell,

    [Parameter()]
    [switch]$SkipBash,

    [Parameter()]
    [switch]$SkipPython,

    [Parameter()]
    [switch]$Fix
)

# Initialize counters
$script:totalErrors = 0
$script:totalWarnings = 0
$script:totalFiles = 0

# Color scheme
$colors = @{
    Success = 'Green'
    Error   = 'Red'
    Warning = 'Yellow'
    Info    = 'Cyan'
}

function Write-SectionHeader {
    param([string]$Title)

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor $colors.Info
    Write-Host "  $Title" -ForegroundColor $colors.Info
    Write-Host ("=" * 80) -ForegroundColor $colors.Info
}

function Write-Result {
    param(
        [string]$Message,
        [ValidateSet('Success', 'Error', 'Warning', 'Info')]
        [string]$Type = 'Info'
    )

    $marker = switch ($Type) {
        'Success' { '[+]' }
        'Error'   { '[-]' }
        'Warning' { '[!]' }
        'Info'    { '[i]' }
    }

    Write-Host "$marker $Message" -ForegroundColor $colors[$Type]
}

function Test-CommandExists {
    param([string]$Command)

    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

# ============================================================================
# POWERSHELL VALIDATION
# ============================================================================

function Test-PowerShellScripts {
    Write-SectionHeader "PowerShell Script Validation"

    # Check if PSScriptAnalyzer is installed
    if (-not (Test-CommandExists 'Invoke-ScriptAnalyzer')) {
        Write-Result "PSScriptAnalyzer not installed. Installing..." -Type Warning
        try {
            Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -ErrorAction Stop
            Write-Result "PSScriptAnalyzer installed successfully" -Type Success
        }
        catch {
            Write-Result "Failed to install PSScriptAnalyzer: $($_.Exception.Message)" -Type Error
            $script:totalErrors++
            return
        }
    }

    # Find all PowerShell scripts
    $psScripts = Get-ChildItem -Path "$PSScriptRoot\.." -Recurse -Include *.ps1, *.psm1, *.psd1 -File |
        Where-Object { $_.FullName -notmatch '\\\.git\\|\\tests\\|\\node_modules\\' }

    Write-Result "Found $($psScripts.Count) PowerShell files to validate" -Type Info
    $script:totalFiles += $psScripts.Count

    $totalIssues = 0

    foreach ($script in $psScripts) {
        Write-Host "`n  Checking: $($script.Name)" -ForegroundColor Gray

        $results = Invoke-ScriptAnalyzer -Path $script.FullName -Severity @('Error', 'Warning') -ErrorAction SilentlyContinue

        if ($results) {
            foreach ($result in $results) {
                $severity = if ($result.Severity -eq 'Error') { 'Error' } else { 'Warning' }
                Write-Result "    Line $($result.Line): $($result.Message)" -Type $severity

                if ($result.Severity -eq 'Error') {
                    $script:totalErrors++
                } else {
                    $script:totalWarnings++
                }
                $totalIssues++
            }
        } else {
            Write-Result "    OK" -Type Success
        }
    }

    if ($totalIssues -eq 0) {
        Write-Result "All PowerShell scripts passed validation" -Type Success
    } else {
        Write-Result "Found $totalIssues issue(s) in PowerShell scripts" -Type Warning
    }

    if ($Fix) {
        Write-Result "Auto-fix not implemented for PowerShell" -Type Info
    }
}

# ============================================================================
# BASH VALIDATION
# ============================================================================

function Test-BashScripts {
    Write-SectionHeader "Bash Script Validation"

    # Check if shellcheck is available
    if (-not (Test-CommandExists 'shellcheck')) {
        Write-Result "shellcheck not found in PATH" -Type Warning
        Write-Result "Install shellcheck for Bash validation: https://github.com/koalaman/shellcheck" -Type Info
        Write-Result "Skipping Bash validation" -Type Warning
        return
    }

    # Find all Bash scripts
    $bashScripts = Get-ChildItem -Path "$PSScriptRoot\..\Linux" -Recurse -Include *.sh -File |
        Where-Object { $_.FullName -notmatch '\\\.git\\|\\tests\\' }

    Write-Result "Found $($bashScripts.Count) Bash files to validate" -Type Info
    $script:totalFiles += $bashScripts.Count

    $totalIssues = 0

    foreach ($script in $bashScripts) {
        Write-Host "`n  Checking: $($script.Name)" -ForegroundColor Gray

        $output = shellcheck -f gcc $script.FullName 2>&1

        if ($LASTEXITCODE -ne 0) {
            $output -split "`n" | ForEach-Object {
                if ($_ -match 'error:') {
                    Write-Result "    $_" -Type Error
                    $script:totalErrors++
                    $totalIssues++
                } elseif ($_ -match 'warning:') {
                    Write-Result "    $_" -Type Warning
                    $script:totalWarnings++
                    $totalIssues++
                }
            }
        } else {
            Write-Result "    OK" -Type Success
        }
    }

    if ($totalIssues -eq 0) {
        Write-Result "All Bash scripts passed validation" -Type Success
    } else {
        Write-Result "Found $totalIssues issue(s) in Bash scripts" -Type Warning
    }
}

# ============================================================================
# PYTHON VALIDATION
# ============================================================================

function Test-PythonScripts {
    Write-SectionHeader "Python Script Validation"

    # Check if uv is available
    if (-not (Test-CommandExists 'uv')) {
        Write-Result "uv not found in PATH" -Type Warning
        Write-Result "Install uv: https://docs.astral.sh/uv/" -Type Info
        Write-Result "Skipping Python validation" -Type Warning
        return
    }

    # Find all Python scripts
    $pyScripts = Get-ChildItem -Path "$PSScriptRoot\.." -Recurse -Include *.py -File |
        Where-Object { $_.FullName -notmatch '\\\.git\\|\\venv\\|\\\.venv\\|__pycache__' }

    if ($pyScripts.Count -eq 0) {
        Write-Result "No Python files found" -Type Info
        return
    }

    Write-Result "Found $($pyScripts.Count) Python files to validate" -Type Info
    $script:totalFiles += $pyScripts.Count

    # Run Black formatter
    Write-Host "`n  Running Black (formatter)..." -ForegroundColor Gray
    if ($Fix) {
        uv run black . 2>&1 | Out-String | Write-Host
    } else {
        uv run black --check . 2>&1 | Out-String | Write-Host
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Result "Black found formatting issues" -Type Warning
        $script:totalWarnings += $pyScripts.Count
    } else {
        Write-Result "Black formatting check passed" -Type Success
    }

    # Run isort
    Write-Host "`n  Running isort (import sorting)..." -ForegroundColor Gray
    if ($Fix) {
        uv run isort . 2>&1 | Out-String | Write-Host
    } else {
        uv run isort --check-only . 2>&1 | Out-String | Write-Host
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Result "isort found import order issues" -Type Warning
        $script:totalWarnings += $pyScripts.Count
    } else {
        Write-Result "isort check passed" -Type Success
    }

    # Run mypy (type checking)
    Write-Host "`n  Running mypy (type checking)..." -ForegroundColor Gray
    uv run mypy . --ignore-missing-imports 2>&1 | Out-String | Write-Host

    if ($LASTEXITCODE -ne 0) {
        Write-Result "mypy found type errors" -Type Error
        $script:totalErrors += $pyScripts.Count
    } else {
        Write-Result "mypy type checking passed" -Type Success
    }

    # Run pylint
    Write-Host "`n  Running pylint (linting)..." -ForegroundColor Gray
    uv run pylint **/*.py 2>&1 | Out-String | Write-Host

    if ($LASTEXITCODE -ne 0) {
        Write-Result "pylint found code quality issues" -Type Warning
        $script:totalWarnings += $pyScripts.Count
    } else {
        Write-Result "pylint check passed" -Type Success
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host "`n"
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  Sysadmin Toolkit - Code Quality Validation" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan

if (-not $SkipPowerShell) {
    Test-PowerShellScripts
}

if (-not $SkipBash) {
    Test-BashScripts
}

if (-not $SkipPython) {
    Test-PythonScripts
}

# Print summary
Write-SectionHeader "Validation Summary"
Write-Result "Total files checked: $script:totalFiles" -Type Info
Write-Result "Total errors: $script:totalErrors" -Type $(if ($script:totalErrors -eq 0) { 'Success' } else { 'Error' })
Write-Result "Total warnings: $script:totalWarnings" -Type $(if ($script:totalWarnings -eq 0) { 'Success' } else { 'Warning' })

Write-Host "`n"

# Exit with appropriate code
if ($script:totalErrors -gt 0) {
    exit 1
} else {
    exit 0
}
