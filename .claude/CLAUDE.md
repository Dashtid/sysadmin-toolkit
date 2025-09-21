# System Administration Scripts - Claude Code Guidelines

## Project Overview

A comprehensive collection of system administration and setup scripts for both Linux (Ubuntu) and Windows 11 environments. This repository is designed for developers and system administrators who need to quickly set up and maintain development environments across multiple platforms, including headless servers, desktop environments, and work laptops.

## Development Environment

**Operating System**: Windows 11
**Shell**: Git Bash / PowerShell / Command Prompt
**Important**: Always use Windows-compatible commands:
- Use `dir` instead of `ls` for Command Prompt
- Use PowerShell commands when appropriate
- File paths use backslashes (`\`) in Windows
- Use `python -m http.server` for local development server
- Git Bash provides Unix-like commands but context should be Windows-aware

## Development Guidelines

### Code Quality
- Follow shell scripting best practices for both Bash and PowerShell
- Use meaningful variable and function names
- Implement proper error handling and rollback capabilities
- Add comprehensive comments explaining script operations
- Use consistent indentation and formatting
- Maintain clean, readable code
- Follow language-specific best practices

### Security
- No sensitive information in the codebase
- Use HTTPS for all external resources
- Regular dependency updates
- Follow security best practices for the specific technology stack

### System Administration Specific Guidelines
- Test scripts in non-production environments first
- Implement proper logging with timestamps for all operations
- Include rollback capabilities for system modifications
- Use appropriate privilege escalation (sudo for Linux, Administrator for Windows)
- Validate system prerequisites before executing operations
- Include progress indicators for long-running operations
- Implement idempotent operations where possible
- Use package managers appropriately (apt, Chocolatey, Winget)

## Learning and Communication
- Always explain coding actions and decisions to help the user learn
- Describe why specific approaches or technologies are chosen
- Explain the purpose and functionality of code changes
- Provide context about best practices and coding patterns used
- Provide detailed explanations in the console when performing tasks, as many concepts may be new to the user