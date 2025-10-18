#!/usr/bin/env bash
# ============================================================================
# Code Quality Validation Script for Linux
# ============================================================================
# Description: Validates Bash and Python code quality
# Author: David Dashti
# Version: 1.0.0
# Last Updated: 2025-10-18
#
# Usage:
#   ./scripts/validate-code-quality.sh [OPTIONS]
#
# Options:
#   --skip-bash      Skip Bash validation
#   --skip-python    Skip Python validation
#   --fix            Auto-fix issues where possible (Python only)
#   --help           Show this help message
# ============================================================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Counters
TOTAL_ERRORS=0
TOTAL_WARNINGS=0
TOTAL_FILES=0

# Flags
SKIP_BASH=false
SKIP_PYTHON=false
FIX=false

# Colors
COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_CYAN='\033[0;36m'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
    echo -e "${COLOR_CYAN}  $1${COLOR_RESET}"
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
}

print_success() {
    echo -e "${COLOR_GREEN}[+] $1${COLOR_RESET}"
}

print_error() {
    echo -e "${COLOR_RED}[-] $1${COLOR_RESET}"
}

print_warning() {
    echo -e "${COLOR_YELLOW}[!] $1${COLOR_RESET}"
}

print_info() {
    echo -e "${COLOR_CYAN}[i] $1${COLOR_RESET}"
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================================
# BASH VALIDATION
# ============================================================================

validate_bash() {
    print_header "Bash Script Validation"

    if ! command_exists shellcheck; then
        print_warning "shellcheck not found in PATH"
        print_info "Install shellcheck: https://github.com/koalaman/shellcheck"
        print_warning "Skipping Bash validation"
        return
    fi

    # Find all Bash scripts
    mapfile -t bash_scripts < <(find "$PROJECT_ROOT/Linux" -name "*.sh" -type f ! -path "*/\.git/*" ! -path "*/tests/*")

    print_info "Found ${#bash_scripts[@]} Bash files to validate"
    TOTAL_FILES=$((TOTAL_FILES + ${#bash_scripts[@]}))

    local total_issues=0

    for script in "${bash_scripts[@]}"; do
        echo ""
        echo "  Checking: $(basename "$script")"

        if output=$(shellcheck -f gcc "$script" 2>&1); then
            print_success "    OK"
        else
            while IFS= read -r line; do
                if [[ $line =~ error: ]]; then
                    print_error "    $line"
                    ((TOTAL_ERRORS++))
                    ((total_issues++))
                elif [[ $line =~ warning: ]]; then
                    print_warning "    $line"
                    ((TOTAL_WARNINGS++))
                    ((total_issues++))
                fi
            done <<< "$output"
        fi
    done

    echo ""
    if [[ $total_issues -eq 0 ]]; then
        print_success "All Bash scripts passed validation"
    else
        print_warning "Found $total_issues issue(s) in Bash scripts"
    fi
}

# ============================================================================
# PYTHON VALIDATION
# ============================================================================

validate_python() {
    print_header "Python Script Validation"

    if ! command_exists uv; then
        print_warning "uv not found in PATH"
        print_info "Install uv: https://docs.astral.sh/uv/"
        print_warning "Skipping Python validation"
        return
    fi

    # Find all Python scripts
    mapfile -t py_scripts < <(find "$PROJECT_ROOT" -name "*.py" -type f ! -path "*/\.git/*" ! -path "*/venv/*" ! -path "*/\.venv/*" ! -path "*/__pycache__/*")

    if [[ ${#py_scripts[@]} -eq 0 ]]; then
        print_info "No Python files found"
        return
    fi

    print_info "Found ${#py_scripts[@]} Python files to validate"
    TOTAL_FILES=$((TOTAL_FILES + ${#py_scripts[@]}))

    # Change to project root for uv commands
    cd "$PROJECT_ROOT"

    # Run Black formatter
    echo ""
    echo "  Running Black (formatter)..."
    if [[ $FIX == true ]]; then
        if uv run black .; then
            print_success "Black formatting applied"
        else
            print_warning "Black found formatting issues"
            ((TOTAL_WARNINGS += ${#py_scripts[@]}))
        fi
    else
        if uv run black --check .; then
            print_success "Black formatting check passed"
        else
            print_warning "Black found formatting issues"
            ((TOTAL_WARNINGS += ${#py_scripts[@]}))
        fi
    fi

    # Run isort
    echo ""
    echo "  Running isort (import sorting)..."
    if [[ $FIX == true ]]; then
        if uv run isort .; then
            print_success "isort applied"
        else
            print_warning "isort found import order issues"
            ((TOTAL_WARNINGS += ${#py_scripts[@]}))
        fi
    else
        if uv run isort --check-only .; then
            print_success "isort check passed"
        else
            print_warning "isort found import order issues"
            ((TOTAL_WARNINGS += ${#py_scripts[@]}))
        fi
    fi

    # Run mypy (type checking)
    echo ""
    echo "  Running mypy (type checking)..."
    if uv run mypy . --ignore-missing-imports; then
        print_success "mypy type checking passed"
    else
        print_error "mypy found type errors"
        ((TOTAL_ERRORS += ${#py_scripts[@]}))
    fi

    # Run pylint
    echo ""
    echo "  Running pylint (linting)..."
    if uv run pylint **/*.py 2>/dev/null || [[ $? -le 4 ]]; then
        print_success "pylint check passed"
    else
        print_warning "pylint found code quality issues"
        ((TOTAL_WARNINGS += ${#py_scripts[@]}))
    fi
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-bash)
                SKIP_BASH=true
                shift
                ;;
            --skip-python)
                SKIP_PYTHON=true
                shift
                ;;
            --fix)
                FIX=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-bash      Skip Bash validation"
                echo "  --skip-python    Skip Python validation"
                echo "  --fix            Auto-fix issues where possible (Python only)"
                echo "  --help           Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

parse_arguments "$@"

echo ""
echo "================================================================================"
echo "  Sysadmin Toolkit - Code Quality Validation"
echo "================================================================================"

if [[ $SKIP_BASH != true ]]; then
    validate_bash
fi

if [[ $SKIP_PYTHON != true ]]; then
    validate_python
fi

# Print summary
print_header "Validation Summary"
print_info "Total files checked: $TOTAL_FILES"
if [[ $TOTAL_ERRORS -eq 0 ]]; then
    print_success "Total errors: $TOTAL_ERRORS"
else
    print_error "Total errors: $TOTAL_ERRORS"
fi

if [[ $TOTAL_WARNINGS -eq 0 ]]; then
    print_success "Total warnings: $TOTAL_WARNINGS"
else
    print_warning "Total warnings: $TOTAL_WARNINGS"
fi

echo ""

# Exit with appropriate code
if [[ $TOTAL_ERRORS -gt 0 ]]; then
    exit 1
else
    exit 0
fi
