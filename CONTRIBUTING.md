# Contributing to Sysadmin Toolkit

Thank you for your interest in contributing! This document provides guidelines for maintaining code quality and consistency across the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Coding Standards](#coding-standards)
  - [PowerShell Scripts](#powershell-scripts)
  - [Bash Scripts](#bash-scripts)
  - [Python Scripts](#python-scripts)
- [Error Handling](#error-handling)
- [Documentation](#documentation)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

This is a professional toolkit for system administrators. All contributions should:
- Focus on security, reliability, and maintainability
- Follow industry best practices
- Include comprehensive error handling
- Be well-documented and tested

---

## Getting Started

1. **Fork the repository** and clone your fork
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Install development tools**:
   - PowerShell 7+
   - PSScriptAnalyzer (PowerShell linter)
   - shellcheck (Bash linter)
   - Pester (PowerShell testing framework)
4. **Review existing code** to understand patterns and style
5. **Make your changes** following the guidelines below
6. **Run tests** and validation before submitting

---

## Coding Standards

### PowerShell Scripts

#### General Requirements

All PowerShell scripts MUST:
- Use `[CmdletBinding()]` for advanced function capabilities
- Import and use `CommonFunctions.psm1` for logging
- Import and use `ErrorHandling.psm1` for advanced error patterns
- Include comprehensive parameter validation
- Pass PSScriptAnalyzer with zero errors

#### Script Template

```powershell
<#
.SYNOPSIS
    Brief description of script purpose

.DESCRIPTION
    Detailed description of what the script does

.PARAMETER ParameterName
    Description of parameter

.EXAMPLE
    .\script-name.ps1 -ParameterName "value"

.NOTES
    Author: Your Name
    Version: 1.0.0
    Last Updated: YYYY-MM-DD
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Description")]
    [ValidateNotNullOrEmpty()]
    [string]$ParameterName
)

# Import common modules
$commonModulePath = Join-Path $PSScriptRoot "..\lib\CommonFunctions.psm1"
Import-Module $commonModulePath -Force

$errorHandlingPath = Join-Path $PSScriptRoot "..\lib\ErrorHandling.psm1"
Import-Module $errorHandlingPath -Force

# Script logic here
try {
    Write-InfoMessage "Starting operation..."

    # Your code here

    Write-Success "Operation completed successfully"
}
catch {
    Write-ContextualError -ErrorRecord $_ -Context "performing operation" -Suggestion "Check prerequisites"
    exit 1
}
```

#### Naming Conventions

- **Scripts**: Use `Verb-Noun.ps1` format (e.g., `Update-SystemPackages.ps1`)
- **Functions**: Use PowerShell approved verbs (Get, Set, New, Remove, etc.)
- **Variables**: Use `$PascalCase` for parameters, `$camelCase` for locals
- **Constants**: Use `$UPPER_CASE` for constants

#### Parameter Validation

Always use appropriate validation attributes:

```powershell
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[ValidateScript({ Test-Path $_ })]
[string]$FilePath

[Parameter()]
[ValidateRange(1, 100)]
[int]$MaxRetries = 3

[Parameter()]
[ValidateSet('Info', 'Warning', 'Error')]
[string]$LogLevel = 'Info'
```

#### Error Handling

Use try-catch blocks with contextual errors:

```powershell
try {
    # Operation
}
catch {
    Write-ContextualError -ErrorRecord $_ `
        -Context "updating system packages" `
        -Suggestion "Check your network connection and try again"
    exit 1
}
```

For retryable operations:

```powershell
$result = Retry-Command -ScriptBlock {
    Invoke-WebRequest -Uri $url
} -MaxAttempts 3 -DelaySeconds 5
```

#### Logging

Use CommonFunctions logging exclusively (NO Write-Host, Write-Output in production code):

```powershell
Write-InfoMessage "Processing started..."
Write-Success "Operation completed successfully"
Write-WarningMessage "Non-critical issue detected"
Write-ErrorMessage "Critical error occurred"
```

#### Output Formatting

- Use ASCII markers only: `[+]` `[-]` `[!]` `[i]` `[*]`
- NO emojis in any output
- Color coding: Green (success), Red (error), Yellow (warning), Cyan (info)

---

### Bash Scripts

#### General Requirements

All Bash scripts MUST:
- Source `common-functions.sh` library
- Use `set -euo pipefail` for strict error handling
- Include comprehensive documentation
- Pass shellcheck with minimal warnings

#### Script Template

```bash
#!/usr/bin/env bash
# ============================================================================
# Script Title
# ============================================================================
# Description: What this script does
# Author: Your Name
# Version: 1.0.0
# Last Updated: YYYY-MM-DD
#
# Usage:
#   ./script-name.sh [OPTIONS]
#
# Options:
#   --option VALUE    Description of option
#   --debug           Enable debug logging
#   --help            Show help message
# ============================================================================

set -euo pipefail

# Script configuration
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions library
if [[ -f "$SCRIPT_DIR/../lib/bash/common-functions.sh" ]]; then
    source "$SCRIPT_DIR/../lib/bash/common-functions.sh"
else
    echo "[-] ERROR: Cannot find common-functions.sh library" >&2
    exit 1
fi

# Configuration
LOG_FILE="/var/log/script-name.log"

# Main logic
log_info "Starting operation..."

# Your code here

log_success "Operation completed successfully"
exit 0
```

#### Naming Conventions

- **Scripts**: Use `kebab-case.sh` (e.g., `system-updates.sh`)
- **Functions**: Use `snake_case` (e.g., `check_dependencies`)
- **Variables**: Use `UPPER_CASE` for globals, `lower_case` for locals

#### Error Handling

Use common functions for error handling:

```bash
# Check command exists
check_command docker

# Retry with backoff
retry_command 3 2 curl -f https://example.com

# Validate input
validate_file "$config_file" || die "Invalid config file" 1

# Die on error
[[ -z "$var" ]] && die "Variable cannot be empty" 1
```

#### Logging

Use common-functions.sh logging exclusively:

```bash
log_info "Processing started..."
log_success "Operation completed"
log_warning "Non-critical issue"
log_error "Critical error"
log_debug "Debug information"  # Only shown if DEBUG=1
```

#### Configuration Management

For scripts with configuration files:

```bash
# Load configuration
CONFIG_FILE="${SCRIPT_DIR}/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE"
    OPTION=$(get_config "section.option" "default_value")
fi
```

#### Prometheus Metrics

For monitoring scripts:

```bash
# Initialize metrics file
METRICS_FILE="/var/lib/prometheus/node-exporter/script_metrics.prom"
init_prometheus_metrics "$METRICS_FILE"

# Export metrics
export_prometheus_metric "$METRICS_FILE" "script_success" "1" "script=\"backup\""
export_prometheus_metric "$METRICS_FILE" "items_processed" "$count"
```

---

### Python Scripts

#### General Requirements

Python scripts MUST follow PEP 8 and use:
- Type hints for all function signatures
- Docstrings for all modules, classes, and functions
- Black for code formatting
- mypy for type checking
- pylint for linting

#### Script Template

```python
#!/usr/bin/env python3
"""
Module description.

This module provides functionality for...

Usage:
    python script.py [OPTIONS]

Examples:
    python script.py --input data.csv
"""

from typing import Optional
import logging
import sys

# Configure logging with ASCII markers (no emojis)
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def function_name(param1: str, param2: int = 0) -> Optional[str]:
    """
    Brief description of function.

    Args:
        param1: Description of param1
        param2: Description of param2 (default: 0)

    Returns:
        Description of return value

    Raises:
        ValueError: When input is invalid
    """
    if not param1:
        raise ValueError("param1 cannot be empty")

    logger.info(f"Processing {param1} with param2={param2}")

    # Function logic here
    result = f"{param1}-{param2}"

    logger.info(f"[+] Successfully processed: {result}")
    return result


def main() -> int:
    """Main entry point for the script."""
    try:
        result = function_name("example", 42)
        logger.info(f"[+] Result: {result}")
        return 0
    except Exception as e:
        logger.error(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## Error Handling

### Never Suppress Errors Silently

**BAD:**
```bash
docker rmi "$image" &>/dev/null
```

**GOOD:**
```bash
if ! docker rmi "$image" 2>&1 | tee -a "$LOG_FILE"; then
    log_error "Failed to remove image: $image"
    return 1
fi
```

**BAD:**
```powershell
Get-Process | Out-Null 2>&1
```

**GOOD:**
```powershell
try {
    $processes = Get-Process -ErrorAction Stop
}
catch {
    Write-ErrorMessage "Failed to get process list: $($_.Exception.Message)"
}
```

### Provide Context in Errors

Always include:
1. What was being attempted
2. Why it failed (error message)
3. What to do next (suggestion)

```powershell
Write-ContextualError -ErrorRecord $_ `
    -Context "connecting to Docker daemon" `
    -Suggestion "Ensure Docker Desktop is running and you have permissions"
```

---

## Documentation

### Required Documentation

Every script MUST include:
1. **Header comment** with description, usage, examples
2. **Parameter documentation** for all parameters
3. **Inline comments** for complex logic
4. **Examples** of common use cases
5. **Known limitations** or edge cases

### Documentation Standards

- Use complete sentences with proper grammar
- Provide practical examples, not theoretical ones
- Document WHY, not just WHAT
- Update docs when changing functionality
- Include version and last updated date

---

## Testing

### Test Requirements

All new features and bug fixes MUST include tests:
- Unit tests for individual functions
- Integration tests for script workflows
- Edge case and error condition tests

### Running Tests

```powershell
# Run PowerShell tests
.\tests\run-tests.ps1

# Run specific test file
Invoke-Pester -Path .\tests\Windows\CommonFunctions.Tests.ps1

# Run with coverage
Invoke-Pester -Path .\tests -CodeCoverage
```

```bash
# Run Bash tests (if implemented)
./tests/run-bash-tests.sh
```

### Test Standards

- Use descriptive test names: `It "Should reject invalid IP addresses"`
- Test both success and failure paths
- Use mocks for external dependencies
- Clean up test artifacts
- Assert specific expectations, not just "no error"

---

## Pull Request Process

1. **Create feature branch**: `feature/description` or `fix/description`
2. **Follow coding standards** as outlined above
3. **Write/update tests** for your changes
4. **Run validation**:
   ```powershell
   # PowerShell validation
   Invoke-ScriptAnalyzer -Path .\Windows -Recurse

   # Bash validation
   shellcheck Linux/**/*.sh

   # Run tests
   .\tests\run-tests.ps1
   ```
5. **Update documentation** (README.md, inline comments, examples)
6. **Commit with clear messages**:
   ```
   feat: add GPU temperature alerting
   fix: resolve race condition in Docker cleanup
   docs: update SSH setup instructions
   refactor: consolidate duplicate logging functions
   ```
7. **Submit pull request** with:
   - Clear description of changes
   - Reference to related issues
   - Test results
   - Screenshots (if UI changes)

### Commit Message Format

Use conventional commits format:

```
type(scope): brief description

Longer description if needed. Explain:
- Why this change was needed
- What alternatives were considered
- Any breaking changes

Fixes #123
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `security`

---

## Code Review Checklist

Before submitting, verify:

- [ ] Code follows style guide for the language
- [ ] All functions have documentation
- [ ] Parameters have validation
- [ ] Errors include context and suggestions
- [ ] No hardcoded credentials or secrets
- [ ] No silent error suppression
- [ ] Uses shared libraries (CommonFunctions, common-functions.sh)
- [ ] PSScriptAnalyzer passes (PowerShell)
- [ ] shellcheck passes (Bash)
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Examples provided
- [ ] No emojis in output
- [ ] ASCII markers used for symbols

---

## Questions?

- Open an issue for clarification
- Review existing code for examples
- Check documentation in `docs/` directory

---

**Thank you for contributing to make this toolkit more professional and reliable!**
