# Script Templates

Quick reference for creating scripts in this repository.

## PowerShell Structure

```powershell
<#
.SYNOPSIS
    Brief one-line description.

.DESCRIPTION
    Detailed description of functionality.

.PARAMETER ParameterName
    Description with valid values.

.EXAMPLE
    .\Script.ps1 -Parameter "Value"
    Description of example.

.NOTES
    Author: Name | Version: 1.0.0 | Updated: YYYY-MM-DD
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Description")]
    [ValidateNotNullOrEmpty()]
    [string]$RequiredParam,

    [Parameter()]
    [ValidateSet("A", "B", "C")]
    [string]$OptionalParam = "A"
)

# Import shared modules
Import-Module "$PSScriptRoot\..\lib\CommonFunctions.psm1" -Force
Import-Module "$PSScriptRoot\..\lib\ErrorHandling.psm1" -Force

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    Write-InfoMessage "Starting..."

    if ($PSCmdlet.ShouldProcess("Target", "Action")) {
        # Main logic here
    }

    Write-Success "Completed"
} catch {
    Write-ContextualError -ErrorRecord $_ -Context "operation" -Suggestion "Check input"
    exit 1
}
```

## Bash Structure

```bash
#!/usr/bin/env bash
# Description: Brief description
# Author: Name | Version: 1.0.0 | Updated: YYYY-MM-DD
#
# Usage: ./script.sh [OPTIONS]
# Options: -h help, -v verbose, -d dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/bash/common-functions.sh"

DRY_RUN=false
VERBOSE=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_usage; exit 0 ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -d|--dry-run) DRY_RUN=true; shift ;;
            *) log_error "Unknown: $1"; exit 2 ;;
        esac
    done
}

main() {
    log_info "Starting..."

    if [[ "$DRY_RUN" == true ]]; then
        log_warning "DRY RUN - no changes"
        return 0
    fi

    # Main logic here

    log_success "Completed"
}

parse_args "$@"
main
```

## Parameter Validation

| Type | PowerShell | Bash |
|------|------------|------|
| Required | `[Parameter(Mandatory = $true)]` | `[[ -z "$var" ]] && die "Required"` |
| Not empty | `[ValidateNotNullOrEmpty()]` | `[[ -n "$var" ]]` |
| Options | `[ValidateSet("A", "B")]` | `case $var in A\|B) ;; esac` |
| Range | `[ValidateRange(1, 100)]` | `(( var >= 1 && var <= 100 ))` |
| Path exists | `[ValidateScript({ Test-Path $_ })]` | `[[ -f "$path" ]]` |
| Pattern | `[ValidatePattern("^[a-z]+$")]` | `[[ "$var" =~ ^[a-z]+$ ]]` |

## Logging

Use shared modules instead of custom implementations:

**PowerShell** - [CommonFunctions.psm1](../Windows/lib/CommonFunctions.psm1):
```powershell
Write-InfoMessage "Info"      # [i] blue
Write-Success "Done"          # [+] green
Write-WarningMessage "Warn"   # [!] yellow
Write-ErrorMessage "Error"    # [-] red
```

**Bash** - [common-functions.sh](../Linux/lib/bash/common-functions.sh):
```bash
log_info "Info"      # [i] blue
log_success "Done"   # [+] green
log_warning "Warn"   # [!] yellow
log_error "Error"    # [-] red
```

## Error Handling

**PowerShell**:
```powershell
try {
    # operation
} catch {
    Write-ContextualError -ErrorRecord $_ -Context "task" -Suggestion "Fix"
    exit 1
}
```

**Bash**:
```bash
trap 'log_error "Error at line $LINENO"' ERR

command || die "Failed" 1
```

## Documentation Checklist

- [ ] Synopsis (one line)
- [ ] Description (purpose, behavior)
- [ ] Parameters (all with valid values)
- [ ] Examples (2-3, simple to complex)
- [ ] Prerequisites listed
- [ ] Exit codes documented

## Real Examples

| Script | Type | Features |
|--------|------|----------|
| [Get-SystemPerformance.ps1](../Windows/monitoring/Get-SystemPerformance.ps1) | PowerShell | Full validation, multiple outputs |
| [docker-cleanup.sh](../Linux/docker/docker-cleanup.sh) | Bash | Prometheus export, retry logic |
| [security-hardening.sh](../Linux/security/security-hardening.sh) | Bash | Audit mode, category filtering |

---
**Last Updated**: 2025-12-26
