# Contributing to System Administration Toolkit

Thank you for considering contributing to this project! This document provides guidelines for contributing code, reporting issues, and submitting pull requests.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Reporting Issues](#reporting-issues)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)

## Code of Conduct

This project follows a simple code of conduct:

- Be respectful and professional
- Focus on constructive feedback
- Help create a welcoming environment for all contributors
- Report unacceptable behavior by opening an issue

## How to Contribute

There are many ways to contribute:

1. **Report bugs** - Found a problem? Let us know
2. **Suggest features** - Have an idea? Share it
3. **Improve documentation** - Help make things clearer
4. **Submit code** - Fix bugs or add features
5. **Test scripts** - Try scripts in different environments

## Reporting Issues

When reporting issues, please include:

### For Bugs

- **Description**: Clear description of the problem
- **Environment**: OS version, PowerShell/Bash version
- **Steps to Reproduce**: How to trigger the issue
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Script Version**: Which script and version
- **Logs**: Relevant error messages or logs

### For Feature Requests

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives Considered**: Other approaches you've thought about
- **Impact**: Who benefits from this feature?

## Submitting Pull Requests

### Before You Start

1. **Check existing issues/PRs** - Avoid duplicate work
2. **Open an issue first** - Discuss significant changes
3. **Fork the repository** - Work in your own copy
4. **Create a feature branch** - Use descriptive names

```bash
git checkout -b feature/ssh-key-rotation
git checkout -b fix/tunnel-reconnect-bug
git checkout -b docs/improve-security-guide
```

### PR Checklist

Before submitting your pull request, ensure:

- [ ] Code follows project conventions (see [Coding Standards](#coding-standards))
- [ ] Tests added for new functionality
- [ ] All tests pass locally
- [ ] Documentation updated (README, inline comments, examples)
- [ ] No hardcoded credentials or sensitive data
- [ ] Commit messages are clear and descriptive
- [ ] PowerShell scripts use approved verbs
- [ ] Scripts include parameter validation
- [ ] Error handling implemented properly

### PR Process

1. **Create the PR** with a clear title and description
2. **Reference related issues** using keywords (Fixes #123, Relates to #456)
3. **Respond to feedback** from maintainers
4. **Update as needed** based on review comments
5. **Squash commits** if requested before merge

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Performance improvement

## Testing
How was this tested?

## Related Issues
Fixes #(issue)
```

## Coding Standards

### PowerShell Scripts

**File Structure:**
```powershell
<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description

.PARAMETER ParameterName
    Parameter description

.EXAMPLE
    .\script.ps1 -Parameter Value

.NOTES
    Author: Name
    Last Modified: YYYY-MM-DD
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Parameter
)

# Constants at top
$CONSTANT_VALUE = "value"

# Functions before main logic
function Verb-Noun {
    param([string]$Input)
    # Implementation
}

# Main script logic
try {
    # Implementation
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
    exit 1
}
```

**Conventions:**
- Use approved PowerShell verbs (Get, Set, New, Remove, etc.)
- CamelCase for functions (`Get-SSHStatus`)
- PascalCase for parameters (`-ServerIP`)
- UPPERCASE for constants (`$MAX_RETRIES`)
- Use `[Parameter()]` attributes for validation
- Include comment-based help for all scripts
- Use `try/catch` for error handling
- Consistent logging format: `[+]` `[-]` `[i]` `[!]`

**Output Markers:**
```powershell
Write-Host "[+] Success message" -ForegroundColor Green
Write-Host "[-] Error message" -ForegroundColor Red
Write-Host "[i] Information" -ForegroundColor Blue
Write-Host "[!] Warning" -ForegroundColor Yellow
```

### Bash Scripts

**File Structure:**
```bash
#!/usr/bin/env bash
#
# Script Name: script-name.sh
# Description: Brief description
# Author: Name
# Last Modified: YYYY-MM-DD
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MAX_RETRIES=3

# Functions
function print_info() {
    echo "[i] $*"
}

function print_success() {
    echo "[+] $*"
}

# Main logic
main() {
    # Implementation
}

main "$@"
```

**Conventions:**
- Use `#!/usr/bin/env bash` shebang
- Set strict mode: `set -euo pipefail`
- Use `readonly` for constants
- lowercase_with_underscores for functions
- Quote all variables: `"$var"` not `$var`
- Use `[[` for conditionals, not `[`
- Consistent error handling

### General Guidelines

- **No Secrets**: Never commit passwords, keys, tokens
- **Examples Only**: Use RFC 5737 IPs (192.0.2.x, 198.51.100.x)
- **Parameters**: Use parameters instead of hardcoded values
- **Documentation**: Comment complex logic
- **Error Messages**: Clear, actionable error messages
- **Exit Codes**: Use appropriate exit codes (0=success, 1=error)

## Testing Requirements

### PowerShell Testing with Pester

All PowerShell scripts should have corresponding Pester tests:

```powershell
# tests/Windows/MyScript.Tests.ps1
BeforeAll {
    . "$PSScriptRoot/../../Windows/path/to/MyScript.ps1"
}

Describe "MyScript Tests" {
    Context "Parameter Validation" {
        It "Should require mandatory parameters" {
            { MyScript -RequiredParam $null } | Should -Throw
        }
    }

    Context "Functionality" {
        It "Should return expected output" {
            $result = MyScript -Param "test"
            $result | Should -Be "expected"
        }
    }
}
```

### Running Tests Locally

```powershell
# Install Pester v5+
Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck

# Run all tests
.\tests\run-tests.ps1

# Run specific test file
Invoke-Pester -Path .\tests\Windows\MyScript.Tests.ps1
```

### Test Coverage

- **Critical scripts**: 70%+ coverage
- **Utility scripts**: 50%+ coverage
- **Focus on**: Parameter validation, error handling, core logic

## Security Guidelines

### Before Committing

1. **Scan for secrets**:
   ```bash
   git diff --cached | grep -iE '(password|secret|token|api[_-]?key|private[_-]?key)'
   ```

2. **Check .gitignore**: Ensure sensitive files excluded

3. **Review changes**: Double-check no credentials in code

### Script Security

- **Input Validation**: Validate all user input
- **Path Traversal**: Sanitize file paths
- **Injection Prevention**: Quote variables properly
- **Privilege Escalation**: Document why admin/sudo needed
- **Secure Defaults**: Default to secure configurations

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security concerns privately (see SECURITY.md)
2. Include detailed description and reproduction steps
3. Allow time for fix before public disclosure

## Questions?

- Open an issue for general questions
- Tag with `question` label
- Be patient - maintainers are volunteers

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Project documentation where appropriate

Thank you for contributing!

---

**Last Updated**: 2025-10-12
**Maintained By**: [@dashtid](https://github.com/dashtid)
