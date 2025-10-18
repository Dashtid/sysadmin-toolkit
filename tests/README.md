# Testing Framework

Comprehensive testing for Windows and Linux system administration scripts.

## [*] Overview

This testing framework validates:
- Script syntax and structure
- Security best practices (no hardcoded credentials)
- CLAUDE.md compliance (no emojis, ASCII markers only)
- Functional correctness
- Documentation completeness

## [+] Running Tests

### Windows Tests (Pester)

**Prerequisites:**
```powershell
Install-Module -Name Pester -Force -Scope CurrentUser
```

**Run all Windows tests:**
```powershell
Invoke-Pester -Path .\tests\Windows
```

**Run specific test file:**
```powershell
Invoke-Pester -Path .\tests\Windows\FirstTimeSetup.Tests.ps1
```

**Run with detailed output:**
```powershell
Invoke-Pester -Path .\tests\Windows -Output Detailed
```

**Generate test report:**
```powershell
$Config = New-PesterConfiguration
$Config.Run.Path = ".\tests\Windows"
$Config.TestResult.Enabled = $true
$Config.TestResult.OutputPath = "test-results.xml"
Invoke-Pester -Configuration $Config
```

### Linux Tests (BATS)

**Prerequisites:**
```bash
# Ubuntu/Debian
sudo apt install bats

# Fedora/RHEL
sudo dnf install bats

# macOS
brew install bats-core
```

**Run all Linux tests:**
```bash
bats tests/Linux/
```

**Run specific test file:**
```bash
bats tests/Linux/maintenance.bats
```

**Verbose output:**
```bash
bats tests/Linux/ --verbose
```

## [*] Test Structure

```
tests/
├── run-tests.ps1                    # Main test runner (PowerShell/Pester)
├── TestHelpers.psm1                 # Shared test utilities
├── Benchmark.ps1                    # Performance benchmarking
├── Windows/
│   ├── CommonFunctions.Tests.ps1      # Core library tests
│   ├── ErrorHandling.Tests.ps1        # NEW v2.0: Advanced error handling tests
│   ├── SystemUpdates.Tests.ps1
│   ├── SSH.Tests.ps1
│   ├── Security.Tests.ps1
│   ├── Maintenance.Tests.ps1
│   ├── FirstTimeSetup.Tests.ps1
│   ├── RestorePreviousState.Tests.ps1
│   ├── StartupScript.Tests.ps1
│   └── Integration.Tests.ps1
├── Linux/
│   ├── CommonFunctions.Tests.sh       # NEW v2.0: Bash library tests
│   ├── Maintenance.Tests.ps1
│   ├── KubernetesMonitoring.Tests.ps1
│   ├── GPUMonitoring.Tests.ps1
│   └── DockerCleanup.Tests.ps1
└── README.md                        # This file
```

## [i] What Gets Tested

### Windows PowerShell Scripts

**First-Time Setup Scripts:**
- [+] Script files exist
- [+] Valid PowerShell syntax
- [+] Required parameters are defined
- [+] Package export files (JSON/XML) are valid
- [+] Documentation files exist
- [+] No emojis (CLAUDE.md compliance)
- [+] No hardcoded credentials
- [+] Proper logging functions
- [+] Admin requirements specified

**SSH Setup Scripts:**
- [+] Script files exist and are valid
- [+] Proper parameter handling
- [+] No hardcoded IPs or credentials
- [+] SSH agent configuration
- [+] Tunnel management functionality
- [+] Error handling present
- [+] Git Bash compatibility

### Linux Bash Scripts

**Maintenance Scripts:**
- [+] Scripts are executable
- [+] Valid Bash syntax (bash -n)
- [+] Proper shebang (#!/usr/bin/env bash)
- [+] No emojis (CLAUDE.md compliance)
- [+] ASCII markers present [+] [-] [i] [!]
- [+] No hardcoded credentials
- [+] Error handling (set -e, trap, etc.)
- [+] Logging functions defined
- [+] Privilege checks (sudo/EUID)
- [+] Safe operations (confirmation for destructive actions)

### Security Checks

**Across all scripts:**
- [-] No passwords or API keys
- [-] No SSH private keys
- [-] No hardcoded private IPs
- [-] No database credentials
- [+] Use of environment variables
- [+] Safe file operations

### Documentation Checks

- [+] README.md files exist
- [+] Scripts have description comments
- [+] Usage examples provided
- [+] No broken markdown links

## [!] CI/CD Integration

Tests run automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Manual workflow dispatch

**GitHub Actions Workflow:** [.github/workflows/test-scripts.yml](../.github/workflows/test-scripts.yml)

**Jobs:**
1. **test-windows-scripts** - Pester tests on Windows
2. **test-linux-scripts** - BATS tests on Ubuntu
3. **security-scan** - Check for secrets and credentials
4. **validate-structure** - Verify repository organization
5. **markdown-lint** - Lint documentation files

## [*] Test Coverage

### Currently Tested

**Windows:**
- [x] First-time setup scripts (100%)
- [x] SSH configuration scripts (100%)
- [x] Package export/import (100%)

**Linux:**
- [x] Maintenance scripts (disk-cleanup, system-update)
- [x] Syntax validation
- [x] Security checks

### Future Tests

**Windows:**
- [ ] Maintenance scripts (system-updates, security-updates)
- [ ] Utility scripts (scheduled tasks)
- [ ] Development setup scripts

**Linux:**
- [ ] Monitoring scripts (system-health-check, ssl-cert-check)
- [ ] Server setup scripts (headless-server-setup, docker-lab-environment)
- [ ] Desktop setup scripts (fresh-desktop-setup)

## [+] Writing New Tests

### Windows (Pester) Test Template

```powershell
# tests/Windows/YourScript.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot "Windows\path\to\script.ps1"
}

Describe "Your Script Tests" {

    Context "Basic Validation" {
        It "Script exists" {
            Test-Path $ScriptPath | Should -Be $true
        }

        It "Has valid syntax" {
            $Errors = $null
            [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $ScriptPath -Raw), [ref]$Errors
            )
            $Errors.Count | Should -Be 0
        }
    }

    Context "Security Checks" {
        It "Contains no hardcoded passwords" {
            $Content = Get-Content $ScriptPath -Raw
            $Content | Should -Not -Match 'password\s*=\s*["\'].*["\']'
        }
    }
}
```

### Linux (BATS) Test Template

```bash
#!/usr/bin/env bats

setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SCRIPT_PATH="${PROJECT_ROOT}/Linux/path/to/script.sh"
}

@test "script exists" {
    [ -f "$SCRIPT_PATH" ]
}

@test "script is executable" {
    [ -x "$SCRIPT_PATH" ]
}

@test "script has valid syntax" {
    bash -n "$SCRIPT_PATH"
}

@test "script contains no emojis" {
    ! grep -P '[\x{1F300}-\x{1F9FF}]|✅|❌' "$SCRIPT_PATH"
}
```

## [*] Testing Best Practices

### 1. Test Early, Test Often
Run tests before committing:
```bash
# Quick pre-commit check
bats tests/Linux/ && pwsh -Command "Invoke-Pester tests/Windows"
```

### 2. Test in Isolation
Each test should be independent and not rely on previous tests.

### 3. Test Edge Cases
- Empty inputs
- Missing files
- Permission issues
- Invalid configurations

### 4. Security First
Always test for:
- Hardcoded credentials
- Exposed secrets
- Unsafe operations

### 5. Follow CLAUDE.md Rules
- No emojis in scripts
- Use ASCII markers: [+] [-] [i] [!]
- Document test intent

## [!] Common Issues

### Pester Not Found

```powershell
# Install Pester
Install-Module -Name Pester -Force -Scope CurrentUser
```

### BATS Not Found

```bash
# Ubuntu/Debian
sudo apt install bats

# Or install manually
git clone https://github.com/bats-core/bats-core.git
cd bats-core
sudo ./install.sh /usr/local
```

### Tests Fail Due to Line Endings

Ensure Git handles line endings correctly:
```bash
git config core.autocrlf true  # Windows
git config core.autocrlf input # Linux/Mac
```

### Permission Denied on Linux Tests

```bash
chmod +x tests/Linux/*.bats
```

## [*] Continuous Improvement

### Adding New Tests

1. Create test file in appropriate directory
2. Follow naming convention: `ScriptName.Tests.ps1` or `scriptname.bats`
3. Test locally before committing
4. Update this README if adding new test categories

### Updating Existing Tests

1. Ensure backward compatibility
2. Update test documentation
3. Run full test suite before committing

### Test Coverage Goals

- **Critical scripts:** 100% coverage
- **Utility scripts:** 80% coverage
- **Examples/demos:** 50% coverage

## [+] Resources

**Pester Documentation:**
- https://pester.dev/docs/quick-start

**BATS Documentation:**
- https://github.com/bats-core/bats-core

**GitHub Actions:**
- https://docs.github.com/en/actions

**PowerShell Best Practices:**
- https://poshcode.gitbook.io/powershell-practice-and-style/

**Bash Best Practices:**
- https://google.github.io/styleguide/shellguide.html

---

**Last Updated:** 2025-10-18
**Test Framework Version:** 2.0
**Windows Tests:** 9 files, 700+ assertions (includes new ErrorHandling module tests)
**Linux Tests:** 5 files, 140+ assertions (includes new common-functions.sh tests)
**Total Coverage:** 1,490+ assertions across 14 test files
