# Testing Strategy for Sysadmin Toolkit

**Version**: 2.3
**Last Updated**: 2025-10-18

## Overview

This document outlines the realistic testing strategy for the Windows & Linux Sysadmin Toolkit, including achievable coverage goals and testing methodologies for different types of code.

## Code Coverage Analysis

### Current Coverage Breakdown

| Directory | Commands | Coverage | Testable Type |
|-----------|----------|----------|---------------|
| Windows/lib | 170 | **83.5%** | Library Modules (.psm1) |
| Windows/maintenance | 926 | 0% | Administrative Scripts |
| Windows/first-time-setup | 841 | 0% | Administrative Scripts |
| Windows/ssh | 432 | 0% | Administrative Scripts |
| Windows/utilities | 174 | 0% | Administrative Scripts |
| Windows/network | 148 | 0% | Administrative Scripts |
| Windows/development | 127 | 0% | Administrative Scripts |
| **TOTAL** | **2,818** | **5.04%** | Mixed |

**Note**: Security hardening scripts (1,790 commands) have been moved to the [defensive-toolkit](https://github.com/Dashtid/defensive-toolkit) repository.

#### Per-Module Coverage Details:
- **ErrorHandling.psm1**: 91.35% (95/104 lines) ✅ **Exceeds 90% target!**
- **CommonFunctions.psm1**: 68.63% (35/51 lines) - Edge cases are legitimately untestable (exit calls, Unix paths on Windows, disk full scenarios)

### Realistic Coverage Goals

#### Library Modules (Windows/lib): **Target 90%+**
- **Current**: **83.5%** (142/170 instructions)
- **Achievement**: ErrorHandling.psm1 at **91.35%** ✅
- **Testable**: Fully testable through unit tests
- **Approach**: Import modules, test all exported functions with comprehensive execution tests
- **Goal**: Maintain 90%+ coverage as this is shared infrastructure
- **Progress**: Added 40+ new execution tests, improved from 81.2% to 83.5%

#### Administrative Scripts: **Target: Validation Tests Only**
- **Current**: 0% (0/4,438 commands)
- **Challenge**: Scripts require admin privileges, modify system state, cannot be safely unit tested
- **Realistic Approach**:
  - Syntax validation tests ✓
  - Structure compliance tests ✓
  - Script parameter validation ✓
  - WhatIf mode integration tests (where supported)
  - Mock-based integration tests (limited scope)

#### Overall Repository: **Realistic Target: 10-15%**
- **Math**: If lib modules achieve 90% (153 commands) and we add limited integration coverage for scripts
  - Lib at 90%: 153 commands
  - Scripts integration coverage (5-10%): ~220-440 commands
  - **Total**: 373-593 commands = 8-13% overall
- **Industry Context**: For system administration scripts with extensive OS integration, 10-15% is realistic

## Testing Methodology by Code Type

### 1. Library Modules (.psm1) - Unit Testing

**Files**:
- [Windows/lib/CommonFunctions.psm1](../Windows/lib/CommonFunctions.psm1)
- [Windows/lib/ErrorHandling.psm1](../Windows/lib/ErrorHandling.psm1)

**Testing Approach**:
```powershell
BeforeAll {
    Import-Module "$PSScriptRoot/../Windows/lib/CommonFunctions.psm1" -Force
}

Describe "Write-InfoMessage" {
    It "Outputs message with [i] marker" {
        $output = Write-InfoMessage "Test" 6>&1
        $output | Should -Match '\[i\]'
    }
}
```

**Coverage Goal**: 90%+
- Fully testable
- No system dependencies
- Easy to mock external dependencies

### 2. Administrative Scripts (.ps1) - Integration Testing

**Examples**:
- [Windows/maintenance/system-updates.ps1](../Windows/maintenance/system-updates.ps1)
- [Windows/ssh/setup-ssh-agent-access.ps1](../Windows/ssh/setup-ssh-agent-access.ps1)

**Testing Approach**:
```powershell
Describe "system-updates.ps1" {
    Context "WhatIf Mode Execution" {
        It "Executes in WhatIf mode without errors" {
            { & "$MaintenancePath/system-updates.ps1" -WhatIf } | Should -Not -Throw
        }
    }

    Context "Script Structure Validation" {
        It "Has valid PowerShell syntax" {
            Test-ScriptSyntax -Path "$MaintenancePath/system-updates.ps1" | Should -Be $true
        }

        It "Requires administrator privileges" {
            $content = Get-Content "$MaintenancePath/system-updates.ps1" -Raw
            $content | Should -Match '#Requires -RunAsAdministrator'
        }
    }
}
```

**Coverage Goal**: Validation only (not counted in code coverage)
- Scripts cannot be unit tested (require admin, modify system)
- Validation tests ensure quality without execution
- Integration tests in WhatIf mode where supported

### 3. SSH Wrapper Scripts - Functional Testing

**Testing Approach**:
- Mock SSH connections
- Test state file creation/management
- Validate parameter handling
- Test error conditions

## Test Organization

### Test File Structure

```
tests/
├── Windows/
│   ├── CommonFunctions.Tests.ps1          # Unit tests for lib modules (HIGH COVERAGE)
│   ├── ErrorHandling.Tests.ps1            # Unit tests for lib modules (HIGH COVERAGE)
│   ├── Maintenance.Tests.ps1              # Validation tests for maintenance scripts
│   ├── Maintenance.Comprehensive.Tests.ps1 # Extended validation tests
│   ├── SSH.Tests.ps1                      # Functional tests for SSH wrappers
│   ├── SSH.Comprehensive.Tests.ps1        # Extended SSH tests
│   ├── Integration.Tests.ps1              # Cross-module integration tests
│   └── Integration.Advanced.Tests.ps1     # Advanced integration scenarios
├── Linux/
│   ├── CommonFunctions.bats               # BATS tests for bash library
│   └── maintenance.bats                   # BATS tests for maintenance scripts
└── TESTING_STRATEGY.md                    # This file
```

### Test Categories

1. **Unit Tests** (Target: 90%+ coverage)
   - Test individual functions in library modules
   - Use mocking for external dependencies
   - Fast execution, no system dependencies

2. **Validation Tests** (Quality gates, not coverage)
   - Syntax validation (AST parsing)
   - Structure compliance (requires statements, parameter validation)
   - Security compliance (no hardcoded secrets, proper error handling)
   - CLAUDE.md compliance (no emojis, ASCII markers)

3. **Integration Tests** (Limited coverage)
   - WhatIf mode execution
   - Cross-module interactions
   - Error aggregation and logging
   - State management

4. **Functional Tests** (Behavioral validation)
   - SSH wrapper connection handling
   - Configuration file processing
   - Log file management

## Why 80% Overall Coverage is Unrealistic

### The Math

- **Total Commands**: 4,608
- **80% Target**: 3,686 commands
- **Current Lib Coverage**: 138 commands (81.2% of 170)
- **Remaining Needed**: 3,548 commands from administrative scripts

### The Reality

Administrative scripts in this repository:
1. **Require Administrator Privileges**: Cannot run in CI/CD without complex setup
2. **Modify System State**: Cannot safely execute in tests (install updates, change security settings)
3. **Depend on External Services**: Windows Update, package managers, SSH servers
4. **Long-Running Operations**: System updates can take hours
5. **Require Reboots**: Some operations require system restart

### The Industry Standard

| Project Type | Typical Coverage |
|-------------|-----------------|
| Libraries/Frameworks | 70-90% |
| Web Applications | 60-80% |
| CLI Tools | 40-60% |
| **System Admin Scripts** | **10-30%** |
| Infrastructure as Code | 20-40% |

System administration scripts have lower coverage because they:
- Interact directly with OS internals
- Require elevated privileges
- Modify live system state
- Cannot be easily mocked

## Improved Testing Strategy

### Phase 1: Maximize Library Coverage (COMPLETE)
- ✓ CommonFunctions.psm1: 81.2% coverage
- ✓ ErrorHandling.psm1: 81.2% coverage
- **Goal**: Increase to 90%+ by adding edge case tests

### Phase 2: Comprehensive Validation Tests (COMPLETE)
- ✓ 892 total tests across all scripts
- ✓ Syntax validation for all PowerShell scripts
- ✓ Structure compliance (requires admin, version, etc.)
- ✓ Security compliance (no secrets, no emojis)
- ✓ Pattern matching for critical functionality

### Phase 3: Integration Tests (IN PROGRESS)
- Add WhatIf mode tests for scripts that support it
- Test cross-module interactions (ErrorHandling + CommonFunctions)
- Test state management (pre-update backups, restore points)
- Test logging and error aggregation

### Phase 4: CI/CD Quality Gates (COMPLETE)
- ✓ All tests must pass
- ✓ No syntax errors allowed
- ✓ No security violations (secrets, hardcoded IPs)
- ✓ Code coverage tracked and reported
- Coverage threshold: Library modules ≥ 70%

## Coverage Reporting

### JaCoCo XML Format
- Generated by Pester for PowerShell tests
- Compatible with GitHub Actions coverage reporting
- Supports PR comments with coverage diff

### GitHub Actions Integration
```yaml
- name: Add coverage comment to PR
  uses: madrapps/jacoco-report@v1.7.1
  with:
    paths: coverage.xml
    token: ${{ secrets.GITHUB_TOKEN }}
    min-coverage-overall: 10      # Realistic for admin scripts
    min-coverage-changed-files: 50 # Higher bar for new code
```

## Test Execution

### Local Development
```powershell
# Run all tests
Invoke-Pester -Path .\tests\Windows\ -Output Detailed

# Run with coverage
$Config = New-PesterConfiguration
$Config.Run.Path = ".\tests\Windows\"
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = @(".\Windows\lib\*.psm1")
$Config.CodeCoverage.OutputFormat = "JaCoCo"
$Config.CodeCoverage.OutputPath = "coverage.xml"
Invoke-Pester -Configuration $Config

# View coverage summary
pwsh -NoProfile -File .\tests\get-coverage-summary.ps1
```

### CI/CD Pipeline
```bash
# Linux BATS tests
bats tests/Linux/CommonFunctions.bats
bats tests/Linux/maintenance.bats

# Windows Pester tests
pwsh -NoProfile -File tests/full-coverage-analysis.ps1
```

## Success Metrics

### Quantitative
- Library modules: ≥ 90% coverage
- Overall repository: ≥ 10% coverage
- All tests passing: 100%
- Zero security violations

### Qualitative
- All scripts have syntax validation
- All scripts have structure compliance tests
- All critical functionality has validation tests
- All shared library functions have unit tests
- Integration tests for cross-module interactions

## Continuous Improvement

1. **New Library Functions**: Must have ≥ 80% coverage before merge
2. **New Scripts**: Must have validation tests (syntax, structure, security)
3. **Bug Fixes**: Add regression test if applicable
4. **Refactoring**: Maintain or improve coverage

## Conclusion

This repository follows a **pragmatic, multi-layered testing strategy**:

1. **High coverage** for reusable library modules (90%+)
2. **Comprehensive validation** for administrative scripts (syntax, structure, security)
3. **Targeted integration tests** for critical workflows
4. **Realistic coverage goals** appropriate for system administration scripts (10-15% overall)

This approach balances:
- **Code quality** through extensive validation tests
- **Maintainability** through realistic, achievable coverage targets
- **Developer productivity** by not forcing unrealistic unit tests for administrative scripts
- **CI/CD reliability** through fast, stable test execution

The result: **High-quality, well-tested infrastructure automation** without the technical debt of unmaintainable mocked system administration tests.
