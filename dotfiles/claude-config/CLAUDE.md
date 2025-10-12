# Global Claude Code Configuration

This global configuration applies to ALL Claude Code sessions across all projects.
Project-specific CLAUDE.md files will override or extend these settings.

## CRITICAL RULES - MUST FOLLOW

### File Creation Policy
- NEVER create summary files (SESSION_SUMMARY.md, SUMMARY.md, NOTES.md, etc.)
- NEVER create documentation files unless EXPLICITLY requested by the user
- ONLY create files that are directly required for the task at hand
- If the user wants a summary, they will explicitly ask for it

### Output Formatting Policy
- NEVER use emojis in ANY output, code, comments, or documentation
- Use ASCII characters only for symbols:
  - SUCCESS: [+] or [OK] or [PASS]
  - ERROR: [-] or [FAIL] or [X]
  - WARNING: [!] or [WARN]
  - INFO: [i] or [*]
  - CHECKMARK: [v] or [OK]
- Emojis break scripts, CI/CD pipelines, and are unprofessional
- This rule applies to ALL file types: code, markdown, logs, comments, everything

## Universal Preferences

### Communication Style
- Tone: Professional, concise, and educational
- Explanations: Always explain the "why" behind decisions and implementations
- Learning Focus: Provide context about best practices and patterns used
- Response Format: Direct answers with minimal preamble unless complexity requires detailed explanation
- NO MARKDOWN SUMMARIES: Do not provide markdown summary documents after completing work unless explicitly requested. Just do the work and commit.

### Code Standards
- Clarity First: Prioritize readable, maintainable code over clever optimizations
- Documentation: Comprehensive comments for complex logic
- Error Handling: Always implement proper error handling with meaningful messages
- Testing: Suggest tests for critical functionality
- Security: Never commit credentials, always validate inputs

## Development Environment

### Primary Workstation
- OS: Windows 11 Professional
- Primary Shell: Git Bash (with PowerShell 7 and Command Prompt available)
- IDE: VS Code (primary), with various extensions
- Version Control: Git with GitHub

### Common Development Tools
- Languages: Python, PowerShell, Bash, JavaScript/TypeScript
- Containers: Docker Desktop for Windows, Kubernetes
- Package Managers: npm, pip, chocolatey, winget
- Cloud/DevOps: kubectl, helm, terraform (when needed)

## SSH Access Configuration

### Lab Server Access
Server: Ubuntu 24.04 LTS at YOUR_LAB_SERVER
Access Method: SSH Wrapper for Git Bash compatibility

```bash
# Always use this wrapper for SSH from Claude/Git Bash:
$HOME/ssh-wrapper.sh user@YOUR_LAB_SERVER "command"
```

Why: Git Bash's SSH cannot access Windows SSH agent; wrapper uses Windows OpenSSH directly

### Private Git Server SSH Tunnel
Purpose: Access private Git repositories
Local Port: 2222 -> Remote: YOUR_GIT_SERVER:2222
Clone Format: git clone ssh://git@localhost:2222/user/repo.git

### Kubernetes Access
```bash
# Standard K8s commands via SSH wrapper
~/ssh-wrapper.sh user@YOUR_LAB_SERVER "export KUBECONFIG=/path/to/kubeconfig && sudo -E kubectl get pods -n namespace"
```

## Project Organization

### Work Projects Location
Adjust to your environment:
- Infrastructure automation scripts
- Kubernetes manifests and deployments
- Security tools and scripts

### Personal Projects Location
Adjust to your environment

### Public Repository
Public repositories for sanitized, generic scripts

## Universal Security Rules

### NEVER Commit
- Passwords, API keys, tokens, or any credentials
- SSH private keys or certificates
- Database connection strings with credentials
- Personal identifying information in public repos
- Company-specific data in public repositories

### Always Sanitize
- Replace hardcoded paths with environment variables
- Remove company names from public code
- Anonymize IP addresses and hostnames in public repos
- Use .env files (gitignored) for sensitive configuration

## Common Commands & Shortcuts

### Git Operations
```bash
# Feature branch workflow (ALWAYS use)
git checkout -b feature/description
git add . && git commit -m "feat: description"
git push -u origin feature/description

# Quick status check
git status && git log --oneline -5
```

### Docker/Kubernetes
```bash
# Local Docker
docker ps
docker-compose up -d
docker logs -f container-name

# Remote Kubernetes (via SSH wrapper)
~/ssh-wrapper.sh user@server "sudo kubectl get all -n namespace"
```

### Python Virtual Environments
```bash
# Create and activate (Git Bash)
python -m venv venv
source venv/Scripts/activate  # Windows Git Bash
```

### PowerShell Script Execution
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\script.ps1
```

## Learning Preferences

### Explain These Concepts
- New frameworks or libraries being introduced
- Security implications of code changes
- Performance optimization rationales
- Architectural decisions and trade-offs
- Best practices specific to the technology stack

### Skip Explanations For
- Basic syntax (unless specifically asked)
- Common Git operations
- Standard file operations
- Familiar tools (unless using advanced features)

## Global Boundaries

### File System Restrictions
Never access these locations in ANY project:
- C:\Windows\System32\ (except for reading specific tools)
- C:\Program Files\ (except for reading installed software)
- Browser profile directories (Chrome, Firefox, Edge)
- Windows Registry (unless explicitly requested)

### Operation Restrictions
- Never modify system settings without explicit permission
- Never disable security features
- Never install software without asking
- Never modify network configurations without permission

## Preferred Output Formats

### Code Blocks
- Always include language identifier for syntax highlighting
- Add filename comments for multi-file changes
- Include line numbers for large blocks when referencing specific sections

### Documentation
- Use Markdown formatting consistently
- Include table of contents for documents > 100 lines
- Add practical examples for complex concepts
- Provide both "quick start" and detailed explanations when appropriate

## Session Management

### Starting a Session
1. Check current directory and Git status
2. Identify project type from local CLAUDE.md
3. Apply project-specific overrides to these global settings

### During Development
- Commit frequently with descriptive messages
- Run tests after significant changes
- Keep documentation in sync with code changes
- Flag any security concerns immediately

### Ending a Session
- Ensure all changes are committed
- DO NOT create session summaries unless explicitly requested
- Note any pending tasks or issues only if asked
- Ensure no sensitive data in outputs

## Troubleshooting Preferences

### When Errors Occur
1. Show the full error message first
2. Explain what likely caused it
3. Provide step-by-step solution
4. Suggest how to prevent it in future

### Debugging Approach
- Start with the simplest possible cause
- Use appropriate logging/debug output
- Isolate the problem systematically
- Document the solution for future reference

## Important Notes

- Windows Path Format: Always use forward slashes in Git Bash, backslashes in CMD/PowerShell
- Line Endings: Configure Git for core.autocrlf=true on Windows
- SSH Agent: Windows OpenSSH agent must be running for SSH operations
- Time Zone: Adjust to your local time zone

---

Last Updated: 2025-10-12
Version: 2.1 (Sanitized for public sharing)

This configuration provides a consistent foundation for all Claude Code sessions.
Project-specific CLAUDE.md files should focus on project-unique requirements.
