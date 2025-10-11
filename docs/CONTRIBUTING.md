# Contributing to System Administration Toolkit

Thank you for your interest in contributing! This document provides guidelines for contributing to this repository.

## [*] Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Security Requirements](#security-requirements)
- [Script Guidelines](#script-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

## [i] Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help maintain a welcoming environment
- Report security issues responsibly (see [SECURITY.md](SECURITY.md))

## [+] Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/windows-linux-sysadmin-toolkit.git
cd windows-linux-sysadmin-toolkit
```

### 2. Install Development Tools

**For Pre-commit Hooks (Recommended):**

```bash
# Option 1: Use our simple bash-based hook
./.githooks/install-hooks.sh

# Option 2: Use pre-commit framework (more features)
pip install pre-commit
pre-commit install
```

**For PowerShell Development:**

```powershell
# Install PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
```

**For Bash Development:**

```bash
# Install ShellCheck
# Ubuntu/Debian
sudo apt-get install shellcheck

# macOS
brew install shellcheck

# Windows (via Chocolatey)
choco install shellcheck
```

### 3. Configure Your Environment

```bash
# Create your local configuration (gitignored)
cp .env.example .env.local

# Edit with your values
nano .env.local  # or use your preferred editor
```

## [*] Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

**Branch naming conventions:**
- `feature/` - New functionality
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Adding or updating tests

### 2. Make Your Changes

Follow the guidelines in [Script Guidelines](#script-guidelines) section below.

### 3. Test Your Changes

```bash
# Run pre-commit checks manually
./.githooks/pre-commit

# Or if using pre-commit framework
pre-commit run --all-files

# Test PowerShell scripts
pwsh -File Windows/your-script.ps1 -WhatIf

# Test Bash scripts
bash -n Linux/your-script.sh
shellcheck Linux/your-script.sh
```

### 4. Commit Your Changes

```bash
# Stage your changes
git add .

# Commit with descriptive message (pre-commit hooks will run)
git commit -m "feat: add SSH connection pooling feature

- Implement connection pooling for multiple SSH sessions
- Add configuration for pool size and timeout
- Update documentation with usage examples"
```

**Commit message format:**
```
<type>: <short description>

<detailed description>

<optional breaking changes notice>
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions/updates
- `chore:` - Maintenance tasks

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
# Provide clear description of changes and motivation
```

## [!] Security Requirements

### NEVER Commit These

- [X] Real passwords, API keys, tokens
- [X] SSH private keys
- [X] Private IP addresses (use RFC 5737: 192.0.2.x, 198.51.100.x, 203.0.113.x)
- [X] Real hostnames (use example.com)
- [X] Company or personal information
- [X] Database connection strings with credentials

### ALWAYS Do These

- [+] Use parameters for configuration
- [+] Provide example values using RFC standards
- [+] Document what users need to customize
- [+] Test with sanitized values
- [+] Run pre-commit hooks before pushing

**Before committing:**

```bash
# Check for secrets
git diff | grep -iE "(password|secret|key|token|api)"

# Check for private IPs
git diff | grep -E "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

# Run full security scan
./.githooks/pre-commit
```

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

## [*] Script Guidelines

### PowerShell Scripts

**Required Standards:**

```powershell
# Header template
<#
.SYNOPSIS
    Brief description of what the script does

.DESCRIPTION
    Detailed description of functionality, use cases, and behavior

.PARAMETER ParameterName
    Description of the parameter

.EXAMPLE
    .\script.ps1 -Parameter "value"
    Description of what this example does

.NOTES
    Author: Your Name
    Version: 1.0
    Last Modified: YYYY-MM-DD
#>

param(
    [Parameter(Mandatory=$false, HelpMessage="Description")]
    [ValidateNotNullOrEmpty()]
    [string]$Parameter = "default-value"
)

# Use parameters, not hardcoded values
# Implement proper error handling
# Add informative output with [+] [-] [i] [!] markers
# Use Write-Host with colors for user feedback
```

**Style Guidelines:**
- Use PowerShell 7+ features
- PascalCase for functions and cmdlets
- camelCase for variables
- Use approved verbs (Get-, Set-, New-, etc.)
- Add comment-based help
- Implement proper error handling with try/catch
- Use `Write-Host` with colors for output

**Validation:**

```powershell
# Test syntax
pwsh -NoProfile -Command '$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content script.ps1 -Raw), [ref]$null)'

# Run PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path script.ps1 -Severity Warning,Error
```

### Bash Scripts

**Required Standards:**

```bash
#!/usr/bin/env bash
#
# Brief description of what the script does
#
# Usage: ./script.sh [options] <arguments>
#
# Options:
#   -h, --help      Show this help message
#   -v, --verbose   Enable verbose output
#
# Examples:
#   ./script.sh --verbose
#
# Author: Your Name
# Version: 1.0
# Last Modified: YYYY-MM-DD

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Use parameters, not hardcoded values
# Implement proper error handling
# Add informative output with [+] [-] [i] [!] markers
```

**Style Guidelines:**
- Use `#!/usr/bin/env bash` shebang
- UPPER_CASE for environment variables
- lower_case for local variables
- Use `set -euo pipefail` for safety
- Add usage/help function
- Quote all variables: `"$var"`
- Use `[[` instead of `[` for conditionals

**Validation:**

```bash
# Test syntax
bash -n script.sh

# Run ShellCheck
shellcheck script.sh
```

### Documentation

**Every script must have:**
- Clear description of purpose
- Parameter documentation
- Usage examples with real scenarios
- Required permissions (sudo, admin, etc.)
- Prerequisites and dependencies
- Notes about security implications

## [*] Testing

### Manual Testing

Before submitting, test your scripts:

**PowerShell:**
```powershell
# Syntax check
pwsh -File script.ps1 -WhatIf

# Dry run with example values
.\script.ps1 -ServerIP "192.0.2.10" -ServerUser "testuser" -WhatIf

# Full run in test environment
.\script.ps1 -ServerIP "192.0.2.10" -ServerUser "testuser"
```

**Bash:**
```bash
# Syntax check
bash -n script.sh

# Dry run (if supported)
./script.sh --dry-run

# Full run in test environment
./script.sh --verbose
```

### Automated Testing

Tests will run automatically on pull requests:

- **Secret Scanning**: Gitleaks, TruffleHog
- **Syntax Validation**: PowerShell, Bash, ShellCheck
- **Linting**: PSScriptAnalyzer, ShellCheck

You can run these locally:

```bash
# Pre-commit checks
./.githooks/pre-commit

# Pre-commit framework (if installed)
pre-commit run --all-files
```

## [+] Pull Request Process

### 1. Ensure CI Passes

All automated checks must pass:
- [+] Secret scanning (no credentials detected)
- [+] Syntax validation (no errors)
- [+] Linting (warnings are acceptable)

### 2. Update Documentation

If you:
- Add new scripts → Update README.md
- Change parameters → Update script help and examples
- Add new features → Update relevant documentation

### 3. Write Clear PR Description

**Template:**

```markdown
## Description
Brief summary of changes

## Motivation
Why is this change needed?

## Changes
- Bullet point list of changes
- Include any breaking changes

## Testing
How did you test these changes?

## Screenshots (if applicable)
Add screenshots or command output examples

## Checklist
- [ ] Tested with example values
- [ ] No secrets in code
- [ ] Documentation updated
- [ ] Pre-commit hooks pass
- [ ] CI checks pass
```

### 4. Request Review

Tag maintainers or relevant contributors for review.

### 5. Address Feedback

Respond to review comments and update your PR as needed.

## [i] Questions or Issues?

- **Bug reports**: Open an issue with detailed reproduction steps
- **Feature requests**: Open an issue describing the use case
- **Security issues**: See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Questions**: Open a discussion or issue for clarification

## [+] Recognition

Contributors will be recognized in:
- Git commit history
- Release notes for significant contributions
- Special thanks in README for major features

---

**Thank you for contributing!** Your efforts help make system administration easier and more secure for everyone.

**Last Updated**: 2025-10-11
