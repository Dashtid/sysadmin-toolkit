# Test Runner Script
# Runs the Pester suite under tests\Windows and prints a one-line summary.
# The BATS half went with the Linux tier (2026-09-26); Pester is now the
# only runner, so a missing Pester is an error rather than a skip.

param(
    [switch]$UpdatePester
)

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

$ProjectRoot = Split-Path $PSScriptRoot -Parent

$Total = 0
$Passed = 0
$Failed = 0

$PesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1

if (!$PesterModule) {
    Write-Error "Pester is not installed"
    Write-Info "Install with: Install-Module -Name Pester -Force -Scope CurrentUser"
    exit 1
}

$PesterVersion = $PesterModule.Version
Write-Info "Pester version: $PesterVersion"

if ($PesterVersion.Major -lt 5) {
    Write-Warning "Pester v$PesterVersion detected -- tests are designed for Pester v5+"

    if ($UpdatePester) {
        Write-Info "Attempting to update Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber
            Write-Success "Pester updated. Please restart PowerShell and run tests again."
            exit 0
        }
        catch {
            Write-Error "Failed to update Pester: $($_.Exception.Message)"
            exit 1
        }
    }

    Write-Warning "Running with limited test support for Pester v3/v4"
}

$TestPath = Join-Path $ProjectRoot "tests\Windows"
$TestFiles = Get-ChildItem -Path $TestPath -Filter "*.Tests.ps1"

Write-Info "Running Windows tests ($($TestFiles.Count) files)..."

foreach ($TestFile in $TestFiles) {
    if ($PesterVersion.Major -ge 5) {
        $Config = New-PesterConfiguration
        $Config.Run.Path = $TestFile.FullName
        $Config.Run.PassThru = $true
        $Config.Output.Verbosity = 'Normal'
        $Result = Invoke-Pester -Configuration $Config
    }
    else {
        $Result = Invoke-Pester -Path $TestFile.FullName -PassThru
    }

    $Total += $Result.TotalCount
    $Passed += $Result.PassedCount
    $Failed += $Result.FailedCount
}

# ----- Summary -----
Write-Info ""
Write-Info "===== TEST SUMMARY ====="
Write-Info "Windows (Pester): $Total total, $Passed passed, $Failed failed"

if ($Failed -gt 0) {
    Write-Error "Total failures: $Failed"
    exit 1
}

Write-Success "All tests passed"
