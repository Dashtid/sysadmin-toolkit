# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CHANGELOG.md for tracking version history
- Repository topics for improved discoverability

## [2.1.0] - 2025-10-12

### Added
- Comprehensive repository documentation and templates
  - MIT LICENSE file for legal clarity
  - SECURITY.md in root for GitHub Security tab recognition
  - CONTRIBUTING.md with detailed contribution guidelines
  - GitHub issue templates (bug report, feature request)
  - Pull request template with comprehensive checklist
- Repository badges to README
  - GitHub Actions workflow status badges
  - License badge
  - Maintained status badge
  - PowerShell version badge
- Sanitized Claude Code global configuration
  - Global CLAUDE.md with best practices and preferences
  - settings.json with comprehensive permission model
  - settings.local.json for local customization
  - .gitignore for Claude config protection
  - README with installation instructions

### Changed
- Updated main .gitignore to allow sanitized config templates in dotfiles/
- Enhanced README with badge section at top

### Security
- Added structured security vulnerability reporting process
- Enhanced .gitignore patterns for credential protection

## [2.0.0] - 2025-10-12

### Added
- Windows 11 security hardening framework
  - audit-security-posture.ps1: 18 security checks
  - backup-security-settings.ps1: Automated backup with restore points
  - restore-security-settings.ps1: Rollback capability
  - harden-level1-safe.ps1: 20 safe, non-breaking controls
  - harden-level2-balanced.ps1: 18 moderate-impact controls
  - harden-level3-maximum.ps1: 18 high-security controls
- Tiered hardening approach based on CIS Benchmark v4.0.0, DISA STIG V2R2, MS Security Baseline
- WhatIf preview mode for all hardening scripts
- Automatic System Restore Point creation
- Comprehensive security documentation

### Changed
- Updated README with security hardening documentation
- Enhanced first-time setup documentation

### Security
- Implemented CIS Benchmark Level 1 and Level 2 controls
- Added DISA STIG compliance controls
- Integrated Microsoft Security Baseline recommendations

## [1.5.0] - 2025-10-11

### Added
- First-time desktop setup automation
  - export-current-packages.ps1: Export Winget and Chocolatey packages
  - install-from-exported-packages.ps1: Reinstall packages on fresh installs
  - fresh-windows-setup.ps1: Full setup orchestration
  - work-laptop-setup.ps1: Work-specific configuration
- QUICKSTART.md for first-time setup
- README.md for first-time setup module

### Changed
- Sanitized emojis from first-time setup scripts
- Sanitized emojis from setup-ssh-agent-access.ps1

### Fixed
- Output formatting issues in setup scripts

## [1.0.0] - 2025-06-05

### Added
- Windows SSH configuration scripts
  - setup-ssh-agent-access.ps1: SSH agent configuration for Git Bash and Claude Code
  - gitea-tunnel-manager.ps1: Persistent SSH tunnel management
- Linux server scripts
  - headless-server-setup.sh: Ubuntu server initial setup
  - docker-lab-environment.sh: Docker-based lab setup
  - system-health-check.sh: System monitoring
  - ssl-cert-check.sh: SSL certificate monitoring
- Maintenance scripts
  - Windows: system-updates.ps1, security-updates.ps1, update-defender.ps1
  - Linux: system-update.sh, disk-cleanup.sh
- Documentation
  - SSH-TUNNEL-SETUP.md: Detailed SSH tunnel guide
  - SECURITY.md: Security best practices
- Testing infrastructure
  - Pester test framework setup
  - Tests for SSH and FirstTimeSetup modules
  - run-tests.ps1: Test runner with version compatibility
- GitHub Actions workflows
  - syntax-check.yml: PowerShell and Bash syntax validation
  - test-scripts.yml: Automated Pester testing
  - secret-scan.yml: Security scanning for secrets
- Pre-commit hooks configuration
- Comprehensive .gitignore for secret protection
- .env.example configuration template
- VSCode workspace settings

### Security
- Implemented parameter-based configuration (no hardcoded values)
- Added comprehensive .gitignore patterns
- Secret scanning in CI/CD pipeline
- Pre-commit hooks for local validation

## [0.1.0] - Initial Release

### Added
- Initial repository structure
- Basic README documentation
- Git configuration

---

## Version History

- **2.1.0** (2025-10-12): Repository documentation and Claude Code configuration
- **2.0.0** (2025-10-12): Windows 11 security hardening framework
- **1.5.0** (2025-10-11): First-time desktop setup automation
- **1.0.0** (2025-06-05): Initial public release with SSH and maintenance scripts
- **0.1.0**: Repository initialization

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

---

**Note**: This changelog is manually maintained. For a complete commit history, see `git log`.
