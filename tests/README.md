# Testing Framework

Comprehensive testing for Windows and Linux system administration scripts.

## Quick Start

### Windows (Pester)
```powershell
Install-Module -Name Pester -Force -Scope CurrentUser
Invoke-Pester -Path .\tests\Windows -Output Detailed
```

### Linux (BATS)
```bash
sudo apt install bats
bats tests/Linux/
```

## Test Structure

```
tests/
├── Windows/
│   ├── CommonFunctions.Tests.ps1      # Core library (90%+ coverage target)
│   ├── ErrorHandling.Tests.ps1        # Error handling (91% coverage)
│   ├── Integration.Advanced.Tests.ps1 # Cross-module workflows
│   ├── Maintenance.Comprehensive.Tests.ps1
│   └── SSH.Comprehensive.Tests.ps1
├── Linux/
│   ├── CommonFunctions.bats           # Bash library (60+ tests)
│   ├── SecurityHardening.bats         # Security tests (60+ tests)
│   └── ServiceHealthMonitor.bats      # Monitor tests (50+ tests)
├── MockHelpers.psm1                   # Reusable mock configurations
├── CodeCoverage.pester.ps1            # Coverage analysis
└── TestHelpers.psm1                   # Shared utilities
```

## Coverage Strategy

| Code Type | Target | Approach |
|-----------|--------|----------|
| Library modules (.psm1) | 90%+ | Full unit tests |
| Administrative scripts | Validation only | Syntax, structure, security |
| Overall repository | 10-15% | Realistic for sysadmin scripts |

**Why 80%+ is unrealistic**: Admin scripts require elevated privileges, modify system state, and depend on external services.

## What Gets Tested

- [x] Script syntax validation
- [x] No hardcoded credentials
- [x] CLAUDE.md compliance (no emojis, ASCII markers)
- [x] Required parameters defined
- [x] Error handling present
- [x] Documentation exists

## Code Coverage

```powershell
# Console output
.\tests\CodeCoverage.pester.ps1

# HTML report
.\tests\CodeCoverage.pester.ps1 -OutputFormat HTML

# JaCoCo for CI
.\tests\CodeCoverage.pester.ps1 -OutputFormat JaCoCo
```

## CI/CD Integration

Tests run automatically on:
- Push to main/develop
- Pull requests
- Manual dispatch

**Workflow**: [.github/workflows/ci.yml](../.github/workflows/ci.yml)

## Writing Tests

### Pester Template
```powershell
Describe "Script Tests" {
    It "Has valid syntax" {
        { [ScriptBlock]::Create((Get-Content $script -Raw)) } | Should -Not -Throw
    }
    It "Contains no passwords" {
        Get-Content $script -Raw | Should -Not -Match 'password\s*=\s*["\']'
    }
}
```

### BATS Template
```bash
@test "script has valid syntax" {
    bash -n "$SCRIPT_PATH"
}
@test "script contains no emojis" {
    ! grep -P '[\x{1F300}-\x{1F9FF}]' "$SCRIPT_PATH"
}
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Pester not found | `Install-Module -Name Pester -Force` |
| BATS not found | `sudo apt install bats` |
| Line ending issues | `git config core.autocrlf true` (Windows) |
| Permission denied | `chmod +x tests/Linux/*.bats` |

---
**Last Updated**: 2025-12-26
**Tests**: 21 files, 1100+ assertions
**Coverage**: Library modules 83.5%, ErrorHandling 91.35%
