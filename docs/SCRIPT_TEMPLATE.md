# Script Documentation Template

This document provides templates for creating well-documented scripts in this repository.

## Table of Contents

- [PowerShell Script Template](#powershell-script-template)
- [Bash Script Template](#bash-script-template)
- [Documentation Guidelines](#documentation-guidelines)
- [Comment-Based Help Reference](#comment-based-help-reference)

---

## PowerShell Script Template

```powershell
<#
.SYNOPSIS
    Brief one-line description of what the script does.

.DESCRIPTION
    Detailed description of the script's functionality, purpose, and behavior.
    Include any important notes about prerequisites, dependencies, or limitations.

    This script is designed for [target environment/purpose].

.PARAMETER ParameterName
    Description of what this parameter does and what values are acceptable.
    Include default values and whether it's mandatory or optional.

.PARAMETER AnotherParameter
    Description of the second parameter.
    Provide examples of valid input if helpful.

.EXAMPLE
    .\ScriptName.ps1 -ParameterName "Value"

    Description of what this example does and what the expected outcome is.

.EXAMPLE
    .\ScriptName.ps1 -ParameterName "Value1" -AnotherParameter "Value2"

    More complex example showing multiple parameters.

.EXAMPLE
    .\ScriptName.ps1 -WhatIf

    Preview mode - shows what would happen without making changes.

.NOTES
    File Name      : ScriptName.ps1
    Author         : Your Name
    Prerequisite   : PowerShell 7.0+, Administrator privileges (if required)
    Creation Date  : YYYY-MM-DD
    Last Modified  : YYYY-MM-DD
    Version        : 1.0.0

    Change Log:
    - 1.0.0 (YYYY-MM-DD): Initial release

.LINK
    https://github.com/Dashtid/windows-linux-sysadmin-toolkit

.LINK
    Related-Documentation.md

#>

#Requires -Version 7.0
#Requires -RunAsAdministrator  # Include only if needed

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        HelpMessage = "Description of what this parameter does"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$RequiredParameter,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Option1", "Option2", "Option3")]
    [string]$OptionalParameter = "Option1",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$NumericParameter = 10,

    [Parameter(Mandatory = $false)]
    [switch]$EnableFeature
)

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script metadata
$SCRIPT_VERSION = "1.0.0"
$SCRIPT_NAME = $MyInvocation.MyCommand.Name

# Constants
$MAX_RETRIES = 3
$TIMEOUT_SECONDS = 30

# Paths (use environment variables or parameters)
$LOG_DIR = Join-Path $PSScriptRoot "logs"
$CONFIG_FILE = Join-Path $PSScriptRoot "config.json"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes formatted log messages to console and optionally to file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] "

    switch ($Level) {
        "Info"    {
            $logMessage += "[i] $Message"
            Write-Host $logMessage -ForegroundColor Blue
        }
        "Success" {
            $logMessage += "[+] $Message"
            Write-Host $logMessage -ForegroundColor Green
        }
        "Warning" {
            $logMessage += "[!] $Message"
            Write-Host $logMessage -ForegroundColor Yellow
        }
        "Error"   {
            $logMessage += "[-] $Message"
            Write-Host $logMessage -ForegroundColor Red
        }
    }

    # Optional: Write to log file
    if (Test-Path $LOG_DIR) {
        $logMessage | Out-File -FilePath (Join-Path $LOG_DIR "$SCRIPT_NAME.log") -Append
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Checks if all prerequisites are met before running the script.
    #>
    [CmdletBinding()]
    param()

    Write-Log -Level Info -Message "Checking prerequisites..."

    # Example: Check if required module is installed
    if (-not (Get-Module -ListAvailable -Name "RequiredModule")) {
        Write-Log -Level Error -Message "Required module 'RequiredModule' is not installed"
        Write-Log -Level Info -Message "Install with: Install-Module -Name RequiredModule"
        return $false
    }

    # Example: Check if required file exists
    if (-not (Test-Path $CONFIG_FILE)) {
        Write-Log -Level Warning -Message "Configuration file not found: $CONFIG_FILE"
        Write-Log -Level Info -Message "Using default configuration"
    }

    Write-Log -Level Success -Message "All prerequisites met"
    return $true
}

function Invoke-MainLogic {
    <#
    .SYNOPSIS
        Contains the main logic of the script.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Parameter1,
        [string]$Parameter2
    )

    Write-Log -Level Info -Message "Starting main logic..."

    try {
        # Example: Check if running in WhatIf mode
        if ($PSCmdlet.ShouldProcess("Target", "Action")) {
            # Perform actual changes here
            Write-Log -Level Success -Message "Action completed successfully"
        }

        # Example: Retry logic
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $MAX_RETRIES) {
            try {
                # Attempt operation
                # ...
                $success = $true
            }
            catch {
                $retryCount++
                if ($retryCount -lt $MAX_RETRIES) {
                    Write-Log -Level Warning -Message "Attempt $retryCount failed, retrying..."
                    Start-Sleep -Seconds 2
                }
                else {
                    throw
                }
            }
        }

    }
    catch {
        Write-Log -Level Error -Message "Operation failed: $($_.Exception.Message)"
        throw
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    <#
    .SYNOPSIS
        Main entry point for the script.
    #>
    [CmdletBinding()]
    param()

    Write-Log -Level Info -Message "========================================"
    Write-Log -Level Info -Message "$SCRIPT_NAME v$SCRIPT_VERSION"
    Write-Log -Level Info -Message "========================================"

    try {
        # Check prerequisites
        if (-not (Test-Prerequisites)) {
            Write-Log -Level Error -Message "Prerequisites not met. Exiting."
            exit 1
        }

        # Execute main logic
        Invoke-MainLogic -Parameter1 $RequiredParameter -Parameter2 $OptionalParameter

        Write-Log -Level Success -Message "Script completed successfully"
        exit 0
    }
    catch {
        Write-Log -Level Error -Message "Script failed: $($_.Exception.Message)"
        Write-Log -Level Error -Message "Stack trace: $($_.ScriptStackTrace)"
        exit 1
    }
}

# Execute main function
Main
```

---

## Bash Script Template

```bash
#!/usr/bin/env bash
#
# Script Name: script-name.sh
# Description: Brief description of what this script does
# Author: Your Name
# Created: YYYY-MM-DD
# Last Modified: YYYY-MM-DD
# Version: 1.0.0
#
# Prerequisites:
#   - Bash 4.0+
#   - sudo privileges (if required)
#   - Required packages: package1, package2
#
# Usage:
#   ./script-name.sh [OPTIONS]
#
# Options:
#   -h, --help          Show this help message
#   -v, --verbose       Enable verbose output
#   -d, --dry-run       Preview changes without applying them
#   -p, --parameter     Description of parameter
#
# Examples:
#   ./script-name.sh -p "value"
#   ./script-name.sh --dry-run --verbose
#
# Exit Codes:
#   0 - Success
#   1 - General error
#   2 - Invalid arguments
#   3 - Prerequisites not met
#

# ============================================================================
# STRICT MODE AND ERROR HANDLING
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Set Internal Field Separator for safer word splitting

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

# Script metadata
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="1.0.0"

# Constants
readonly MAX_RETRIES=3
readonly TIMEOUT_SECONDS=30

# Default values
DRY_RUN=false
VERBOSE=false
PARAMETER=""

# Colors for output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Print functions
print_info() {
    echo -e "${COLOR_BLUE}[i] $*${COLOR_RESET}"
}

print_success() {
    echo -e "${COLOR_GREEN}[+] $*${COLOR_RESET}"
}

print_warning() {
    echo -e "${COLOR_YELLOW}[!] $*${COLOR_RESET}"
}

print_error() {
    echo -e "${COLOR_RED}[-] $*${COLOR_RESET}" >&2
}

# Verbose logging
log_verbose() {
    if [[ "${VERBOSE}" == true ]]; then
        echo -e "${COLOR_BLUE}[DEBUG] $*${COLOR_RESET}"
    fi
}

# Usage information
show_usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Description:
    Brief description of what this script does and its purpose.

Options:
    -h, --help              Show this help message and exit
    -v, --verbose           Enable verbose output
    -d, --dry-run           Preview changes without applying them
    -p, --parameter VALUE   Description of parameter

Examples:
    ${SCRIPT_NAME} -p "value"
    ${SCRIPT_NAME} --dry-run --verbose

Version: ${SCRIPT_VERSION}
EOF
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check Bash version
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        print_error "Bash 4.0+ is required (current: ${BASH_VERSION})"
        return 1
    fi

    # Check if required commands exist
    local required_commands=("jq" "curl" "awk")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "${cmd}" &> /dev/null; then
            print_error "Required command not found: ${cmd}"
            return 1
        fi
    done

    # Check if running as root (if needed)
    # if [[ "${EUID}" -ne 0 ]]; then
    #     print_error "This script must be run as root"
    #     return 1
    # fi

    print_success "All prerequisites met"
    return 0
}

# Cleanup function (called on exit)
cleanup() {
    local exit_code=$?

    log_verbose "Cleaning up..."

    # Perform cleanup tasks here
    # Remove temporary files, restore states, etc.

    if [[ ${exit_code} -eq 0 ]]; then
        print_success "Script completed successfully"
    else
        print_error "Script exited with error code: ${exit_code}"
    fi

    exit "${exit_code}"
}

# Error handler
error_handler() {
    local line_number=$1
    print_error "Error occurred in script at line: ${line_number}"
}

# ============================================================================
# MAIN LOGIC FUNCTIONS
# ============================================================================

perform_main_task() {
    local parameter="$1"

    print_info "Starting main task with parameter: ${parameter}"

    # Example: Dry run check
    if [[ "${DRY_RUN}" == true ]]; then
        print_warning "DRY RUN MODE - No changes will be made"
        return 0
    fi

    # Example: Retry logic
    local retry_count=0
    local success=false

    while [[ "${success}" == false ]] && [[ ${retry_count} -lt ${MAX_RETRIES} ]]; do
        if perform_operation; then
            success=true
        else
            ((retry_count++))
            if [[ ${retry_count} -lt ${MAX_RETRIES} ]]; then
                print_warning "Attempt ${retry_count} failed, retrying..."
                sleep 2
            fi
        fi
    done

    if [[ "${success}" == true ]]; then
        print_success "Main task completed successfully"
        return 0
    else
        print_error "Main task failed after ${MAX_RETRIES} attempts"
        return 1
    fi
}

perform_operation() {
    # Implementation here
    log_verbose "Performing operation..."
    return 0
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -p|--parameter)
                PARAMETER="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 2
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "${PARAMETER}" ]]; then
        print_error "Required parameter -p/--parameter is missing"
        show_usage
        exit 2
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_info "========================================"
    print_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
    print_info "========================================"

    # Set up trap for cleanup
    trap cleanup EXIT
    trap 'error_handler ${LINENO}' ERR

    # Parse command line arguments
    parse_arguments "$@"

    # Check prerequisites
    if ! check_prerequisites; then
        print_error "Prerequisites not met. Exiting."
        exit 3
    fi

    # Execute main logic
    if ! perform_main_task "${PARAMETER}"; then
        print_error "Script execution failed"
        exit 1
    fi

    print_success "All operations completed successfully"
    exit 0
}

# Execute main function with all arguments
main "$@"
```

---

## Documentation Guidelines

### General Principles

1. **Be Clear and Concise**: Explain what the script does and why
2. **Include Examples**: Show real-world usage scenarios
3. **Document Prerequisites**: List all requirements upfront
4. **Explain Parameters**: Describe what each parameter does and its valid values
5. **Provide Context**: Help users understand when and how to use the script

### What to Document

- **Purpose**: What problem does this script solve?
- **Prerequisites**: What needs to be installed or configured first?
- **Parameters**: What inputs does the script accept?
- **Examples**: How do you actually use this script?
- **Exit Codes**: What do different exit codes mean?
- **Side Effects**: What changes does the script make?
- **Limitations**: What are the known constraints or issues?

### Documentation Structure

```
1. Brief Synopsis (one line)
2. Detailed Description (1-2 paragraphs)
3. Prerequisites
4. Parameters/Options
5. Usage Examples (3-5 examples, simple to complex)
6. Notes and Warnings
7. Exit Codes
8. Related Documentation Links
```

---

## Comment-Based Help Reference

### PowerShell Help Keywords

- `.SYNOPSIS` - Brief description (required)
- `.DESCRIPTION` - Detailed description (required)
- `.PARAMETER` - One for each parameter (required)
- `.EXAMPLE` - Usage examples (at least 2-3)
- `.NOTES` - Additional information, prerequisites, version info
- `.LINK` - Related documentation URLs
- `.INPUTS` - What objects can be piped to this script
- `.OUTPUTS` - What objects this script outputs

### Testing Your Documentation

**PowerShell:**
```powershell
Get-Help .\YourScript.ps1
Get-Help .\YourScript.ps1 -Detailed
Get-Help .\YourScript.ps1 -Full
Get-Help .\YourScript.ps1 -Examples
Get-Help .\YourScript.ps1 -Parameter ParameterName
```

**Bash:**
```bash
./your-script.sh --help
man ./your-script.sh  # If you create a man page
```

---

## Additional Resources

- [PowerShell Comment-Based Help](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help)
- [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- [PowerShell Best Practices](https://poshcode.gitbook.io/powershell-practice-and-style/)

---

**Last Updated**: 2025-10-12
**Version**: 1.0.0
