# Claude Code Global Configuration

Sanitized global configuration files for Claude Code, safe for public GitHub sharing.

## What's Included

- **CLAUDE.md**: Global instructions and preferences for Claude Code sessions
- **settings.json**: Permission model and general settings
- **settings.local.json**: Local overrides and additional permissions (optional)
- **.gitignore**: Protects sensitive files from accidental commits

## Security Features

### Built-in Protection

The `settings.json` includes a comprehensive security model:

**Denied Operations:**
- Destructive file system commands (rm -rf, format, mkfs, dd, etc.)
- System modification commands (netsh, registry, bcdedit, etc.)
- Reading sensitive files (.env, secrets/, .key, .pem, credentials, passwords)
- Writing sensitive files

**Ask Before Executing:**
- Recursive deletions
- Force git operations
- Docker system cleanup
- Kubernetes deletions

### What's Protected by .gitignore

The included `.gitignore` prevents these from being committed:
- `.credentials.json` (OAuth tokens)
- `history.jsonl` (conversation logs)
- Debug/cache directories
- Runtime files

## Installation on New Machine

### Option 1: Fresh Install (Recommended for new desktop)

```bash
# On new desktop after OS reinstall
cd ~
git clone https://github.com/YOUR_USERNAME/windows-linux-sysadmin-toolkit.git

# Copy Claude config files
mkdir -p ~/.claude
cp windows-linux-sysadmin-toolkit/dotfiles/claude-config/CLAUDE.md ~/.claude/
cp windows-linux-sysadmin-toolkit/dotfiles/claude-config/settings.json ~/.claude/
cp windows-linux-sysadmin-toolkit/dotfiles/claude-config/settings.local.json ~/.claude/
cp windows-linux-sysadmin-toolkit/dotfiles/claude-config/.gitignore ~/.claude/

# Customize CLAUDE.md with your specific environment
code ~/.claude/CLAUDE.md
```

### Option 2: Automated Setup (PowerShell)

```powershell
# Create installation script
$claudeDir = "$env:USERPROFILE\.claude"
New-Item -ItemType Directory -Force -Path $claudeDir

# Copy configuration files
$sourceDir = ".\dotfiles\claude-config"
Copy-Item "$sourceDir\CLAUDE.md" -Destination $claudeDir
Copy-Item "$sourceDir\settings.json" -Destination $claudeDir
Copy-Item "$sourceDir\settings.local.json" -Destination $claudeDir
Copy-Item "$sourceDir\.gitignore" -Destination $claudeDir

Write-Host "[+] Claude Code configuration installed to $claudeDir"
Write-Host "[!] Remember to customize CLAUDE.md with your environment specifics"
```

## Customization Required

After installation, edit `~/.claude/CLAUDE.md` and replace:

1. **SSH Configuration**
   - Replace `YOUR_LAB_SERVER` with your actual server
   - Replace `YOUR_GIT_SERVER` with your private Git server

2. **Project Locations**
   - Update work projects location
   - Update personal projects location

3. **Time Zone**
   - Set your local time zone

4. **Any Other Environment-Specific Settings**

## Syncing Configuration Across Machines

### Push Updates from Current Machine

```bash
cd windows-linux-sysadmin-toolkit

# Copy latest config from ~/.claude to repo (sanitize first!)
# Review CLAUDE.md to ensure no sensitive data
cp ~/.claude/CLAUDE.md dotfiles/claude-config/CLAUDE.md
cp ~/.claude/settings.json dotfiles/claude-config/settings.json
cp ~/.claude/settings.local.json dotfiles/claude-config/settings.local.json

# Commit and push
git add dotfiles/claude-config/
git commit -m "docs: update Claude Code configuration"
git push
```

### Pull Updates to New Machine

```bash
cd windows-linux-sysadmin-toolkit
git pull

# Review changes first
code dotfiles/claude-config/CLAUDE.md

# Apply if satisfied
cp dotfiles/claude-config/CLAUDE.md ~/.claude/
cp dotfiles/claude-config/settings.json ~/.claude/
```

## Security Checklist Before Committing

Before pushing any updates to GitHub, verify:

- [ ] No IP addresses or hostnames (replace with placeholders)
- [ ] No company names
- [ ] No usernames
- [ ] No file paths with personal info
- [ ] No API keys or tokens
- [ ] No repository names that could be sensitive

## Files NOT Included (Never Commit)

These files remain local-only:
- `.credentials.json` - OAuth tokens
- `history.jsonl` - Conversation history
- Any file matching `.gitignore` patterns

## Permission Model Explained

### Allow List
All core Claude Code tools are enabled for maximum productivity.

### Deny List
- **Destructive commands**: Prevents accidental data loss
- **System modifications**: Blocks registry, network, user management
- **Credential access**: Cannot read password files, keys, .env files

### Ask List
Prompts for confirmation on risky operations like force push, hard reset, etc.

## Benefits of This Setup

1. **Portable**: Copy-paste to new machines
2. **Secure**: Sensitive data stays local, never in Git
3. **Versioned**: Track configuration changes over time
4. **Shareable**: Safe to share publicly on GitHub
5. **Protected**: Built-in safeguards against dangerous operations

## Troubleshooting

### Claude Can't Read Credentials
This is intentional! The `Read(**/*credentials*)` deny rule protects your OAuth tokens.

### Permission Denied on Command
Check the deny/ask lists in `settings.json`. You can override by modifying `settings.local.json` without affecting the public version.

### Settings Not Taking Effect
1. Restart Claude Code
2. Check for syntax errors in JSON files
3. Ensure files are in `~/.claude/` not `~/.claude/config/`

## Related Documentation

- [Claude Code Settings Documentation](https://docs.claude.com/en/docs/claude-code/settings)
- [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)

---

**Version**: 2.1
**Last Updated**: 2025-12-25
**Maintained By**: [Your GitHub Username]
