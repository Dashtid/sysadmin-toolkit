# Contributing

Guidelines for maintaining code quality and consistency.

## Getting Started

1. Fork and clone the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Install dev tools: PSScriptAnalyzer, shellcheck, Pester
4. Make changes following the guidelines below
5. Run tests and submit PR

## Coding Standards

### PowerShell

| Requirement | Details |
|-------------|---------|
| Advanced functions | Use `[CmdletBinding()]` |
| Import modules | `CommonFunctions.psm1`, `ErrorHandling.psm1` |
| Parameter validation | `[ValidateNotNullOrEmpty()]`, `[ValidateSet()]` |
| Error handling | `try/catch` with `Write-ContextualError` |
| Logging | `Write-InfoMessage`, `Write-Success`, `Write-ErrorMessage` |
| Output markers | ASCII only: `[+]` `[-]` `[!]` `[i]` (no emojis) |

**Naming**: `Verb-Noun.ps1` for scripts, `$PascalCase` for params, `$camelCase` for locals

### Bash

| Requirement | Details |
|-------------|---------|
| Strict mode | `set -euo pipefail` |
| Source library | `source "$SCRIPT_DIR/../lib/bash/common-functions.sh"` |
| Logging | `log_info`, `log_success`, `log_error` |
| Error handling | `check_command`, `retry_command`, `die` |

**Naming**: `kebab-case.sh` for scripts, `UPPER_CASE` for globals, `lower_case` for locals

### Python

| Requirement | Details |
|-------------|---------|
| Type hints | All function signatures |
| Docstrings | Modules, classes, functions |
| Formatting | Black, mypy, pylint |

## Error Handling

```powershell
# PowerShell - contextual errors
try {
    # operation
} catch {
    Write-ContextualError -ErrorRecord $_ -Context "connecting" -Suggestion "Check network"
    exit 1
}
```

```bash
# Bash - die on error
[[ -z "$var" ]] && die "Variable required" 1
```

## Testing

```powershell
# Run all tests
.\tests\run-tests.ps1

# Run specific test
Invoke-Pester -Path .\tests\Windows\CommonFunctions.Tests.ps1
```

```bash
# Bash syntax check
shellcheck Linux/**/*.sh
```

## Pull Request Process

1. Create branch: `feature/description` or `fix/description`
2. Follow coding standards
3. Write tests for changes
4. Run validation:
   ```powershell
   Invoke-ScriptAnalyzer -Path .\Windows -Recurse
   .\tests\run-tests.ps1
   ```
5. Commit with conventional format:
   ```
   feat: add GPU alerting
   fix: resolve race condition
   docs: update SSH guide
   ```
6. Submit PR with description and test results

## Checklist

Before submitting:

- [ ] Code follows style guide
- [ ] Functions documented
- [ ] Parameters validated
- [ ] Errors include context
- [ ] No hardcoded secrets
- [ ] Uses shared libraries
- [ ] PSScriptAnalyzer/shellcheck passes
- [ ] Tests pass
- [ ] No emojis in output

## Templates

See [docs/SCRIPT_TEMPLATE.md](docs/SCRIPT_TEMPLATE.md) for full PowerShell and Bash templates.

---
**Last Updated**: 2025-12-26
