# Git Hooks

Local Git hooks for pre-commit validation and security checks.

## [+] Installation

```bash
# Run the installation script
./.githooks/install-hooks.sh

# Or manually configure
git config core.hooksPath .githooks
```

## [*] Available Hooks

### pre-commit

Runs before each commit to catch issues early:

- [+] **Secret detection** - Blocks common credential patterns
- [+] **Private IP detection** - Warns about non-RFC IPs
- [+] **Forbidden files** - Blocks .pem, .key, credentials.json, etc.
- [+] **Large files** - Warns about files >1MB
- [+] **Syntax validation** - Checks PowerShell and Bash syntax

## [i] Usage

Once installed, the hook runs automatically on every commit:

```bash
git add .
git commit -m "Your message"
# Pre-commit checks run automatically
```

**If checks fail:**
- Review the error messages
- Fix the issues
- Commit again

**To bypass (NOT RECOMMENDED):**
```bash
git commit --no-verify
```

## [*] Manual Testing

Test the hook without committing:

```bash
# Run manually
./.githooks/pre-commit

# Or test with staged changes
git add .
./.githooks/pre-commit
```

## [!] Troubleshooting

**Hook not running:**
```bash
# Verify configuration
git config core.hooksPath

# Should output: .githooks
# If not, run install script again
./.githooks/install-hooks.sh
```

**Permission denied:**
```bash
# Make hook executable
chmod +x .githooks/pre-commit
```

**Windows Git Bash issues:**
```bash
# Ensure you're using Git Bash, not CMD
# Hook should work in Git Bash and PowerShell
```

---

For advanced secret scanning, see [.pre-commit-config.yaml](../.pre-commit-config.yaml)
