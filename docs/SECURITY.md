# Security Best Practices for Public Repositories

This document outlines the security practices implemented in this repository and provides guidelines for contributors and users.

## [!] Critical Security Rules

### Never Commit These

- [X] **Passwords, passphrases, or API keys** - Even in comments
- [X] **SSH private keys** - Only public keys (.pub) are safe
- [X] **Certificates and private keystores** (.p12, .pfx, .key, .pem)
- [X] **Database connection strings with credentials**
- [X] **Real IP addresses** - Use RFC 5737 examples (192.0.2.x, 198.51.100.x, 203.0.113.x)
- [X] **Real hostnames or domains** - Use example.com, example.org
- [X] **Company or personal information**
- [X] **Configuration files with real values** - Use .example templates

### Always Do These

- [+] **Use parameters for configuration** - No hardcoded values
- [+] **Provide .example templates** - Show structure without real data
- [+] **Use environment variables** - For runtime configuration
- [+] **Document customization needs** - Tell users what to change
- [+] **Review diffs before commit** - Check for accidental secrets

## [*] Implementation in This Repository

### 1. Comprehensive .gitignore

The [.gitignore](../.gitignore) file prevents accidental commits of:

```
# Credentials and secrets
*.pem, *.key, *.cert, *.crt
id_rsa*, id_ed25519*, id_ecdsa*
*password*, *secret*, *token*, *apikey*
credentials.json, auth.json

# Environment files
.env, .env.local, .env.*.local
*.local.conf, config.local.json

# Logs that might contain sensitive data
*.log, /logs

# SSH known_hosts (contains server fingerprints)
known_hosts
```

### 2. Parameter-Based Scripts

All PowerShell and Bash scripts use parameters instead of hardcoded values:

**Good Example:**
```powershell
param(
    [Parameter(Mandatory=$false)]
    [string]$ServerIP = "",
    [string]$ServerUser = $env:USERNAME
)
```

**Bad Example:**
```powershell
# DON'T DO THIS
$ServerIP = "10.143.31.18"
$ServerUser = "john.doe"
```

### 3. Example Values

Scripts use RFC 5737 documentation IP addresses:

- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

Example domains:
- `example.com`, `example.org`, `example.net`

### 4. Configuration Templates

Sensitive configuration uses `.example` files:

```bash
# .env.example (committed to git)
SERVER_IP=192.0.2.10
SERVER_USER=your-username
SSH_KEY_PATH=~/.ssh/id_ed25519

# .env.local (gitignored - user creates this)
SERVER_IP=10.143.31.18
SERVER_USER=john.doe
SSH_KEY_PATH=/home/john/.ssh/id_rsa
```

## [i] For Contributors

### Before Committing

1. **Review your changes:**
   ```bash
   git diff
   ```

2. **Check for secrets:**
   ```bash
   # Search for common secret patterns
   git diff | grep -iE "(password|secret|key|token|api)"
   ```

3. **Verify .gitignore is working:**
   ```bash
   git status  # Ensure no .env, *.key, etc. files are staged
   ```

### If You Accidentally Commit a Secret

1. **DO NOT** just delete it in a new commit - it remains in Git history
2. **Immediately** rotate/revoke the exposed credential
3. **Use git filter-repo or BFG Repo-Cleaner** to remove from history
4. **Force push** (if you have permission) or contact maintainers

```bash
# Example: Remove a file from all Git history
git filter-repo --path secrets.txt --invert-paths

# Force push (be careful!)
git push origin main --force
```

### Writing Secure Scripts

#### PowerShell Best Practices

```powershell
# [+] GOOD: Parameter with validation
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerIP,

    [Parameter(Mandatory=$false)]
    [string]$SSHKeyPath = "$env:USERPROFILE\.ssh\id_ed25519"
)

# [+] GOOD: Prompt for sensitive data
$password = Read-Host -AsSecureString "Enter password"

# [+] GOOD: Use SecureString for credentials
$cred = Get-Credential

# [-] BAD: Hardcoded credentials
$password = "MyPassword123"

# [-] BAD: Plain text in variables
$apiKey = "sk-1234567890abcdef"
```

#### Bash Best Practices

```bash
# [+] GOOD: Use parameters
SERVER_IP="${1:-}"
SERVER_USER="${2:-$(whoami)}"

# [+] GOOD: Load from environment
SERVER_IP="${SERVER_IP:-192.0.2.10}"

# [+] GOOD: Prompt for sensitive data
read -s -p "Enter password: " PASSWORD

# [-] BAD: Hardcoded values
SERVER_IP="10.143.31.18"
PASSWORD="secret123"

# [-] BAD: Secrets in command history
mysql -u root -pMyPassword123  # Password visible in history

# [+] GOOD: Use config files
mysql --defaults-extra-file=~/.my.cnf
```

## [*] For Users

### Setting Up Securely

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dashtid/windows-linux-sysadmin-toolkit.git
   cd windows-linux-sysadmin-toolkit
   ```

2. **Create your local configuration:**
   ```bash
   # Copy example to local file (gitignored)
   cp .env.example .env.local

   # Edit with your real values
   nano .env.local
   ```

3. **Never commit .local files:**
   ```bash
   # Verify .local files are gitignored
   git status
   # Should NOT show .env.local
   ```

### Running Scripts Safely

1. **Review before execution:**
   ```powershell
   # Read the script first
   Get-Content .\Windows\ssh\setup-ssh-agent-access.ps1
   ```

2. **Run with your parameters:**
   ```powershell
   # Don't rely on defaults - provide your values
   .\Windows\ssh\setup-ssh-agent-access.ps1 -ServerIP "10.0.0.50" -ServerUser "admin"
   ```

3. **Use environment variables:**
   ```bash
   # Set once in your shell profile
   export LAB_SERVER="10.0.0.50"
   export LAB_USER="admin"
   ```

### Protecting Your SSH Keys

1. **Use passphrases:**
   ```bash
   # Generate with passphrase
   ssh-keygen -t ed25519 -C "your_email@example.com"
   # Enter passphrase when prompted
   ```

2. **Proper permissions:**
   ```bash
   # Linux/Mac
   chmod 600 ~/.ssh/id_ed25519
   chmod 644 ~/.ssh/id_ed25519.pub

   # Windows (PowerShell as Admin)
   icacls "$env:USERPROFILE\.ssh\id_ed25519" /inheritance:r /grant:r "$($env:USERNAME):R"
   ```

3. **Use SSH agent:**
   ```bash
   # Unlock once per session
   ssh-add ~/.ssh/id_ed25519
   ```

## [!] Incident Response

### If Secrets Are Exposed

1. **Immediately rotate/revoke:**
   - Change passwords
   - Revoke API keys
   - Regenerate SSH keys
   - Update authorized_keys on servers

2. **Remove from Git history:**
   ```bash
   # Use git filter-repo (recommended)
   git filter-repo --path path/to/secret/file --invert-paths

   # Or use BFG Repo-Cleaner
   bfg --delete-files secret-file.txt
   ```

3. **Force push changes:**
   ```bash
   git push origin --force --all
   git push origin --force --tags
   ```

4. **Notify collaborators:**
   - Tell them to re-clone, don't pull
   - Explain what was exposed
   - Share new credentials via secure channel

### Prevention Tools

Consider using these tools:

- **git-secrets** - Prevents committing secrets
- **gitleaks** - Scans for secrets in repos
- **detect-secrets** - Pre-commit hook for secret detection
- **GitHub Secret Scanning** - Automatic scanning (free for public repos)

## [+] Additional Resources

- [GitHub: Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 5737: IPv4 Address Blocks Reserved for Documentation](https://tools.ietf.org/html/rfc5737)
- [Git filter-repo](https://github.com/newren/git-filter-repo)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)

---

**Remember**: Security is everyone's responsibility. When in doubt, ask!

**Last Updated**: 2025-10-11
