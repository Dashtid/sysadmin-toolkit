# GitHub Actions CI/CD Workflows

This directory contains automated workflows for continuous integration, testing, and security scanning.

## Available Workflows

### 1. CI - Automated Testing (`ci.yml`)

**Trigger**: Push to main/develop, Pull Requests, Manual dispatch

**Jobs**:
1. **PowerShell Script Analysis** - Runs PSScriptAnalyzer on all Windows scripts
2. **Bash Script Validation** - Runs shellcheck on all Linux scripts
3. **Windows Pester Tests** - Executes 750+ Windows test assertions
4. **Linux Pester Tests** - Executes Linux .Tests.ps1 files via Pester
5. **Test Summary** - Aggregates results and generates summary

> Note: Linux scripts are also tested via BATS in `test-scripts.yml` (350+ assertions)

**Features**:
- Parallel execution for faster feedback
- Test result artifacts uploaded for download
- Detailed test reports in PR checks
- Fails build on critical issues

**Status Badges**: Add to main README.md
```markdown
[![CI Tests](https://github.com/Dashtid/sysadmin-toolkit/workflows/CI%20-%20Automated%20Testing/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/ci.yml)
```

### 2. PR Checks (`pr-checks.yml`)

**Trigger**: Pull Requests (opened, synchronized, reopened)

**Jobs**:
1. **Secret Scan** - Detects hardcoded secrets, API keys, tokens
2. **File Size Check** - Prevents large files (>1MB) from being committed
3. **YAML Validation** - Validates all YAML/YML files with yamllint
4. **TODO Check** - Scans for TODO/FIXME comments (informational)
5. **PR Description Check** - Ensures meaningful PR descriptions

**Security Patterns Detected**:
- Passwords
- API keys
- Tokens
- Private keys (RSA, OpenSSH)

### 3. Auto Labeler (`labeler.yml`)

**Trigger**: Pull Requests, Issue creation

**Auto-Applied Labels**:
- `windows` - Changes to Windows/ directory
- `linux` - Changes to Linux/ directory
- `tests` - Changes to tests/ directory
- `documentation` - Changes to docs/ or .md files
- `ssh` - SSH-related changes
- `security` - Security-related changes
- `maintenance` - Maintenance scripts
- `monitoring` - Monitoring/observability
- `kubernetes` - K8s-related changes
- `docker` - Docker-related changes
- `ci/cd` - Workflow changes

**Benefits**:
- Automatic categorization
- Easier filtering and searching
- Better project organization

### 4. Security Scanning (`security-scan.yml`)

**Trigger**: Push to main, Pull Requests, Weekly schedule (Mon 9AM UTC), Manual

**Jobs**:
1. **CodeQL Analysis** - GitHub's semantic code analysis
2. **Dependency Review** - Checks for vulnerable dependencies (PRs only)
3. **Trivy Scan** - Filesystem vulnerability scanner
4. **PowerShell Modules Check** - Checks for outdated modules
5. **License Compliance** - Verifies LICENSE file exists
6. **Markdown Link Checker** - Validates all markdown links
7. **Security Summary** - Aggregates all scan results

**Security Levels**:
- CRITICAL: Workflow fails
- HIGH: Workflow fails
- MODERATE: Warning only
- LOW: Informational

## Workflow Configuration

### Required Repository Secrets

None required for basic functionality. Optional secrets:

- `PERSONAL_ACCESS_TOKEN` - For enhanced GitHub API access (if needed)

### Required Repository Permissions

Settings → Actions → General → Workflow permissions:
- ✓ Read and write permissions
- ✓ Allow GitHub Actions to create and approve pull requests

### Branch Protection Rules

Recommended for main branch (Settings → Branches → Add rule):

**Branch name pattern**: `main`

**Protections**:
- ✓ Require a pull request before merging
- ✓ Require approvals: 1
- ✓ Require status checks to pass before merging:
  - PowerShell Script Analysis
  - Bash Script Validation
  - Windows Pester Tests
  - Linux BATS Tests
  - Secret Scan
- ✓ Require branches to be up to date before merging
- ✓ Do not allow bypassing the above settings

## Viewing Workflow Results

### In Pull Requests

1. Open any PR
2. Scroll to bottom - see "Checks" section
3. Click "Details" next to any check for full logs

### In Actions Tab

1. Navigate to repository → Actions
2. Click on workflow name (e.g., "CI - Automated Testing")
3. Select specific run to view details
4. Download artifacts if needed (test results, logs)

### Test Results

Test results are published as PR comments with summary:
- Total tests run
- Passed/Failed counts
- Failure details with line numbers

### Security Findings

Security issues appear in:
- Security tab (Code scanning alerts)
- PR checks (blocking if critical)
- Dependabot alerts (if enabled)

## Workflow Customization

### Adjusting Test Timeout

Edit `ci.yml`:
```yaml
- name: Run Windows tests
  timeout-minutes: 30  # Increase if needed
```

### Changing Shellcheck Exclusions

Edit `ci.yml` in bash-validation job:
```bash
shellcheck -S warning \
  -e SC2034 \  # Unused variable
  -e SC2086 \  # Double quote to prevent globbing
  -e SC2181 \  # Check exit code directly
  "$script"
```

Common exclusions:
- SC2034: Unused variables (often intentional in libraries)
- SC2086: Quoting (sometimes globbing is desired)
- SC2154: Undefined variables (set elsewhere)
- SC1090: Can't follow non-constant source

### Modifying PSScriptAnalyzer Rules

Edit `ci.yml` in powershell-analysis job:
```powershell
$results = Invoke-ScriptAnalyzer `
  -Path $file.FullName `
  -Severity Warning,Error `
  -ExcludeRule PSAvoidUsingWriteHost  # Add exclusions
```

### Changing Scan Schedule

Edit `security-scan.yml`:
```yaml
schedule:
  - cron: '0 9 * * 1'  # Monday 9 AM UTC
  # Change to daily: '0 9 * * *'
  # Change to monthly: '0 9 1 * *'
```

## Troubleshooting

### Workflow Not Triggering

**Check**:
1. Workflow file syntax (YAML validation)
2. Branch name matches trigger
3. Actions enabled (Settings → Actions)

**Solution**:
```bash
# Validate YAML locally
yamllint .github/workflows/ci.yml

# Check for syntax errors
cat .github/workflows/ci.yml | grep -E "^\s+\-\s+name:"
```

### Tests Failing in CI but Pass Locally

**Common Causes**:
1. Different PowerShell versions
2. Missing environment variables
3. File path differences (Windows vs Linux)
4. Line ending issues (CRLF vs LF)

**Solution**:
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Normalize line endings
git config core.autocrlf true  # Windows
git config core.autocrlf input # Linux/Mac
```

### Secret Scan False Positives

**Fix**: Edit `pr-checks.yml` to exclude pattern:
```bash
if grep -rniE "$pattern" . \
  --exclude-dir=.git \
  --exclude-dir=tests \  # Add exclusion
  --exclude="example*.sh"; then  # Exclude examples
```

### Shellcheck Failures

**Common Issues**:
- SC2086: Quote variables
- SC2181: Check $? directly
- SC2034: Unused variables

**Fix Options**:
1. Fix the code to comply
2. Add inline exclusion: `# shellcheck disable=SC2086`
3. Add global exclusion in workflow

### PSScriptAnalyzer Failures

**Common Issues**:
- PSAvoidUsingWriteHost: Use Write-Output instead
- PSAvoidGlobalVars: Limit global variable use
- PSUseDeclaredVarsMoreThanAssignments: Remove unused variables

**Fix**:
```powershell
# Suppress specific rule
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param()
```

### Workflow Permission Errors

**Error**: "Resource not accessible by integration"

**Solution**:
1. Settings → Actions → General
2. Workflow permissions → Read and write
3. Save changes

## Best Practices

### Commit Message Format

Follow conventional commits for better changelog generation:

```
feat: add new monitoring script
fix: resolve shellcheck issues in cleanup script
docs: update workflow documentation
test: add tests for GPU monitoring
ci: update GitHub Actions workflow
refactor: improve error handling
chore: update dependencies
```

### PR Guidelines

**Required PR Description Sections**:
```markdown
## Summary
Brief description of changes

## Changes
- Detailed list of changes
- Use bullet points

## Testing
- How changes were tested
- Which tests were run
- Any manual testing performed

## Related Issues
Fixes #123
Relates to #456
```

### Test Writing

**Structure**:
```powershell
Describe "Feature Name" {
    Context "Scenario" {
        It "Should do something" {
            # Arrange
            $expected = "value"

            # Act
            $result = Test-Function

            # Assert
            $result | Should -Be $expected
        }
    }
}
```

### Script Quality

**Checklist**:
- [ ] Bash: Use `set -euo pipefail`
- [ ] Bash: Use shellcheck clean code
- [ ] PowerShell: Use approved verbs (Get-, Set-, Test-)
- [ ] PowerShell: Include comment-based help
- [ ] All: Use ASCII logging markers ([+] [-] [i] [!])
- [ ] All: No hardcoded credentials
- [ ] All: Include error handling
- [ ] All: Add comprehensive tests

## Monitoring Workflows

### View Workflow Runs

```bash
# Via GitHub CLI
gh run list --workflow=ci.yml --limit 10

# View specific run
gh run view 1234567890

# Watch live run
gh run watch
```

### Download Artifacts

```bash
# List artifacts
gh run view 1234567890 --log

# Download test results
gh run download 1234567890 -n windows-test-results
gh run download 1234567890 -n linux-test-results
```

### Re-run Failed Workflows

```bash
# Re-run failed jobs only
gh run rerun 1234567890 --failed

# Re-run entire workflow
gh run rerun 1234567890
```

## Contributing

When adding new workflows:

1. **Test locally** - Use [act](https://github.com/nektos/act) if possible
2. **Document thoroughly** - Update this README
3. **Follow naming** - Use kebab-case for files
4. **Add status badge** - Update main README
5. **Test on fork** - Verify before main repo PR

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax Reference](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [PSScriptAnalyzer Rules](https://github.com/PowerShell/PSScriptAnalyzer/tree/master/docs/Rules)
- [Shellcheck Wiki](https://github.com/koalaman/shellcheck/wiki)

---

**Last Updated**: 2025-10-15
