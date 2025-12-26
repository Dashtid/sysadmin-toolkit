# GitHub Actions Workflows

Automated CI/CD for testing, security scanning, and PR management.

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| [ci.yml](ci.yml) | Push, PR | PSScriptAnalyzer, shellcheck, Pester, BATS tests |
| [pr-checks.yml](pr-checks.yml) | PR | Secret scan, file size, YAML lint, TODO check |
| [labeler.yml](labeler.yml) | PR, Issues | Auto-apply labels (windows, linux, tests, etc.) |
| [security-scan.yml](security-scan.yml) | Push, Weekly | CodeQL, Trivy, dependency review |

## Status Badges

```markdown
[![CI Tests](https://github.com/Dashtid/sysadmin-toolkit/workflows/CI%20-%20Automated%20Testing/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/ci.yml)
[![Security Scan](https://github.com/Dashtid/sysadmin-toolkit/workflows/Security%20Scanning/badge.svg)](https://github.com/Dashtid/sysadmin-toolkit/actions/workflows/security-scan.yml)
```

## Repository Setup

### Required Permissions
Settings → Actions → General:
- [x] Read and write permissions
- [x] Allow GitHub Actions to create and approve PRs

### Branch Protection (main)
- [x] Require PR before merging
- [x] Require status checks: PowerShell Analysis, Bash Validation, Pester Tests
- [x] Require branches up to date

## Viewing Results

**In PRs**: Scroll to "Checks" section, click "Details"

**In Actions tab**: Select workflow → specific run → download artifacts

```bash
# Via GitHub CLI
gh run list --workflow=ci.yml --limit 10
gh run view <run-id>
gh run download <run-id> -n windows-test-results
```

## Customization

### Shellcheck Exclusions
```bash
# In ci.yml bash-validation job
shellcheck -S warning -e SC2034 -e SC2086 "$script"
```

### PSScriptAnalyzer Exclusions
```powershell
# In script header
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
```

### Change Scan Schedule
```yaml
# In security-scan.yml
schedule:
  - cron: '0 9 * * 1'  # Monday 9 AM UTC
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Workflow not triggering | Check YAML syntax, branch names, Actions enabled |
| Tests fail in CI only | Check PowerShell version, line endings (CRLF/LF) |
| Secret scan false positive | Add exclusion in pr-checks.yml grep command |
| Permission errors | Settings → Actions → Workflow permissions → Read/write |

## Commit Message Format

```
feat: add new monitoring script
fix: resolve shellcheck issues
docs: update workflow documentation
test: add tests for GPU monitoring
ci: update GitHub Actions workflow
```

---
**Last Updated**: 2025-12-26
