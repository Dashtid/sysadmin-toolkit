# Test Runner Script
# Automatically runs tests with appropriate Pester version

param(
    [switch]$Windows,
    [switch]$UpdatePester
)

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

# Check Pester installation
$PesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1

if (!$PesterModule) {
    Write-Error "Pester is not installed"
    Write-Info "Install Pester with: Install-Module -Name Pester -Force -Scope CurrentUser"
    exit 1
}

$PesterVersion = $PesterModule.Version
Write-Info "Pester version: $PesterVersion"

if ($PesterVersion.Major -lt 5) {
    Write-Warning "Pester v$PesterVersion detected - Tests are designed for Pester v5+"
    Write-Info "To update Pester:"
    Write-Info "  1. Close all PowerShell windows except this one"
    Write-Info "  2. Run: Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck"
    Write-Info "  3. Restart PowerShell"
    Write-Info ""

    if ($UpdatePester) {
        Write-Info "Attempting to update Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber
            Write-Success "Pester updated. Please restart PowerShell and run tests again."
            exit 0
        }
        catch {
            Write-Error "Failed to update Pester: $($_.Exception.Message)"
            Write-Info "Please update manually"
            exit 1
        }
    }

    Write-Warning "Running with limited test support for Pester v3/v4"
    Write-Info "Some assertions may fail due to syntax differences"
    Write-Info ""
}

# Run tests
$ProjectRoot = Split-Path $PSScriptRoot -Parent

if ($Windows) {
    Write-Info "Running Windows tests..."
    $TestPath = Join-Path $ProjectRoot "tests\Windows"

    if ($PesterVersion.Major -ge 5) {
        $Config = New-PesterConfiguration
        $Config.Run.Path = $TestPath
        $Config.Output.Verbosity = 'Detailed'
        Invoke-Pester -Configuration $Config
    }
    else {
        Invoke-Pester -Path $TestPath -Verbose
    }
}
else {
    # Run all tests
    Write-Info "Running all Windows tests..."
    Write-Info ""

    $TestFiles = Get-ChildItem -Path (Join-Path $ProjectRoot "tests\Windows") -Filter "*.Tests.ps1"

    $TotalTests = 0
    $PassedTests = 0
    $FailedTests = 0

    foreach ($TestFile in $TestFiles) {
        Write-Info "Running $($TestFile.Name)..."

        if ($PesterVersion.Major -ge 5) {
            $Config = New-PesterConfiguration
            $Config.Run.Path = $TestFile.FullName
            $Config.Output.Verbosity = 'Normal'
            $Result = Invoke-Pester -Configuration $Config -PassThru

            $TotalTests += $Result.TotalCount
            $PassedTests += $Result.PassedCount
            $FailedTests += $Result.FailedCount
        }
        else {
            $Result = Invoke-Pester -Path $TestFile.FullName -PassThru

            $TotalTests += $Result.TotalCount
            $PassedTests += $Result.PassedCount
            $FailedTests += $Result.FailedCount
        }
    }

    Write-Info ""
    Write-Info "===== TEST SUMMARY ====="
    Write-Info "Total: $TotalTests"
    Write-Success "Passed: $PassedTests"
    if ($FailedTests -gt 0) {
        Write-Error "Failed: $FailedTests"
    }
    else {
        Write-Success "Failed: 0"
    }
}
