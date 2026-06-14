# Test Runner Script
# Runs Pester (Windows) and BATS (Linux) tests. Auto-detects which runners
# are available; skip-with-warning rather than error when one is missing.

param(
    [switch]$Windows,
    [switch]$Linux,
    [switch]$UpdatePester
)

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Determine which suites to run. No flags = both (whichever is available).
$RunWindows = $Windows -or (-not $Windows -and -not $Linux)
$RunLinux = $Linux -or (-not $Windows -and -not $Linux)

$WindowsTotal = 0
$WindowsPassed = 0
$WindowsFailed = 0
$WindowsRan = $false

$LinuxTotal = 0
$LinuxPassed = 0
$LinuxFailed = 0
$LinuxRan = $false

# ----- Windows (Pester) -----
if ($RunWindows) {
    $PesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1

    if (!$PesterModule) {
        if ($Windows) {
            Write-Error "Pester is not installed"
            Write-Info "Install with: Install-Module -Name Pester -Force -Scope CurrentUser"
            exit 1
        }
        else {
            Write-Warning "Pester not installed -- skipping Windows tests"
        }
    }
    else {
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

            $WindowsTotal += $Result.TotalCount
            $WindowsPassed += $Result.PassedCount
            $WindowsFailed += $Result.FailedCount
        }

        $WindowsRan = $true
    }
}

# ----- Linux (BATS) -----
if ($RunLinux) {
    $BatsCmd = Get-Command bats -ErrorAction SilentlyContinue

    if (!$BatsCmd) {
        if ($Linux) {
            Write-Error "bats is not installed or not on PATH"
            Write-Info "Install on Debian/Ubuntu: sudo apt install bats"
            Write-Info "Install on macOS: brew install bats-core"
            Write-Info "On Windows: run under WSL or Git Bash with bats-core installed"
            exit 1
        }
        else {
            Write-Warning "bats not on PATH -- skipping Linux tests"
        }
    }
    else {
        $LinuxTestPath = Join-Path $ProjectRoot "tests\Linux"
        $BatsFiles = Get-ChildItem -Path $LinuxTestPath -Filter "*.bats" -ErrorAction SilentlyContinue

        if (!$BatsFiles -or $BatsFiles.Count -eq 0) {
            Write-Warning "No .bats files found in $LinuxTestPath -- skipping Linux tests"
        }
        else {
            Write-Info "Running Linux tests ($($BatsFiles.Count) files via $($BatsCmd.Source))..."

            foreach ($BatsFile in $BatsFiles) {
                Write-Info "Running $($BatsFile.Name)..."
                # bats prints TAP; parse "ok N" / "not ok N" / "1..N" lines for counts.
                $Output = & bats --tap $BatsFile.FullName 2>&1
                $Output | ForEach-Object { Write-Host $_ }

                $PlanLine = $Output | Where-Object { $_ -match '^1\.\.\d+$' } | Select-Object -First 1
                $OkLines = @($Output | Where-Object { $_ -match '^ok \d+' })
                $NotOkLines = @($Output | Where-Object { $_ -match '^not ok \d+' })

                if ($PlanLine -and $PlanLine -match '^1\.\.(\d+)$') {
                    $LinuxTotal += [int]$Matches[1]
                }
                else {
                    $LinuxTotal += ($OkLines.Count + $NotOkLines.Count)
                }
                $LinuxPassed += $OkLines.Count
                $LinuxFailed += $NotOkLines.Count
            }

            $LinuxRan = $true
        }
    }
}

# ----- Summary -----
if ($WindowsRan -or $LinuxRan) {
    Write-Info ""
    Write-Info "===== TEST SUMMARY ====="

    if ($WindowsRan) {
        Write-Info "Windows (Pester): $WindowsTotal total, $WindowsPassed passed, $WindowsFailed failed"
    }
    if ($LinuxRan) {
        Write-Info "Linux (BATS):     $LinuxTotal total, $LinuxPassed passed, $LinuxFailed failed"
    }

    $GrandFailed = $WindowsFailed + $LinuxFailed
    if ($GrandFailed -gt 0) {
        Write-Error "Total failures: $GrandFailed"
        exit 1
    }
    else {
        Write-Success "All tests passed"
    }
}
else {
    Write-Warning "No test runners available -- nothing ran"
    exit 1
}
