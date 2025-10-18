# Example Scripts

This directory contains example scripts demonstrating best practices for this repository.

## Purpose

These examples serve as:
- **Reference implementations** showing proper code structure
- **Templates** for creating new scripts
- **Learning resources** for contributors
- **Quality standards** for the project

## Available Examples

### [example-powershell-script.ps1](example-powershell-script.ps1)

Comprehensive PowerShell script demonstrating:
- Comment-based help with full documentation
- Parameter validation and multiple parameter types
- WhatIf/Confirm support for safe execution
- Consistent output formatting ([+], [-], [i], [!])
- Structured logging to file and console
- Retry logic for resilient operations
- Clean function-based architecture
- Error handling and exit codes
- Prerequisite checking
- Debug/verbose output support

**Usage:**
```powershell
# Basic usage
.\example-powershell-script.ps1 -ServerName "192.0.2.10" -Operation Check

# Preview mode (WhatIf)
.\example-powershell-script.ps1 -ServerName "web.example.com" -Operation Test -WhatIf

# With custom timeout and retries
.\example-powershell-script.ps1 -ServerName "192.0.2.20" -Operation Connect -Timeout 60 -MaxRetries 5

# View help
Get-Help .\example-powershell-script.ps1 -Full
```

### [example-bash-script.sh](example-bash-script.sh)

Comprehensive Bash script demonstrating:
- Proper script header with complete documentation
- Strict mode (set -euo pipefail) for error handling
- Color-coded output functions
- Getopts-style argument parsing with validation
- Retry logic for resilient operations
- Cleanup and error handlers (trap)
- Prerequisite checking
- Dry-run mode support
- Logging to file and console
- Professional help/usage output

**Usage:**
```bash
# Basic usage
./example-bash-script.sh -s "192.0.2.10" -o check

# Preview mode (dry-run)
./example-bash-script.sh -s "web.example.com" -p 8080 -o test --dry-run

# With custom timeout and retries
./example-bash-script.sh -s "192.0.2.20" -o connect -t 60 -r 5 --verbose

# View help
./example-bash-script.sh --help
```

## Best Practices Demonstrated

### Documentation
- Comprehensive comment-based help
- Clear parameter descriptions
- Multiple usage examples
- Prerequisites listed
- Change log tracking

### Code Structure
- Strict mode and error action preference
- Constants section at top
- Helper functions before main logic
- Main function as entry point
- Clean separation of concerns

### Input Validation
- Parameter validation attributes
- Type constraints
- Value range checking
- Pattern matching for IPs/hostnames
- Mandatory vs optional parameters

### Error Handling
- Try/catch blocks
- Specific error messages
- Stack trace output
- Proper exit codes
- Retry logic for transient failures

### Output Formatting
```powershell
[+] Success message      # Green
[-] Error message        # Red
[i] Information         # Blue
[!] Warning message     # Yellow
[DEBUG] Debug output    # Gray (verbose only)
```

### Security
- No hardcoded credentials
- RFC 5737 example IPs in documentation
- Parameter-based configuration
- PSCredential support
- Input sanitization

### Features
- WhatIf/Confirm support
- Verbose/Debug output
- File logging
- Timeout handling
- Retry logic
- Progress indication

## Using Examples as Templates

1. **Copy the example script**
   ```powershell
   cp examples/example-powershell-script.ps1 Windows/category/new-script.ps1
   ```

2. **Customize the header**
   - Update .SYNOPSIS and .DESCRIPTION
   - Modify .PARAMETER sections for your parameters
   - Add relevant .EXAMPLE sections
   - Update .NOTES with your info

3. **Adjust parameters**
   - Keep only needed parameters
   - Update validation rules
   - Set appropriate defaults

4. **Implement your logic**
   - Replace example functions with real implementation
   - Keep the structure and error handling
   - Maintain consistent output formatting

5. **Test thoroughly**
   - Create corresponding Pester tests
   - Test with -WhatIf
   - Test error scenarios
   - Verify logging works

6. **Update documentation**
   - README references
   - Related docs
   - Usage examples

## Testing Examples

Run the example script to see it in action:

```powershell
# Check prerequisites
Get-Help .\examples\example-powershell-script.ps1

# Test with WhatIf (safe)
.\examples\example-powershell-script.ps1 -ServerName "192.0.2.10" -Operation Check -WhatIf -Verbose

# Actually run it
.\examples\example-powershell-script.ps1 -ServerName "localhost" -Operation Check
```

Check the generated log:
```powershell
Get-Content .\examples\logs\example-powershell-script.ps1-$(Get-Date -Format 'yyyyMMdd').log
```

## Contributing

When adding new examples:

1. Follow existing patterns
2. Include comprehensive documentation
3. Add entry to this README
4. Ensure no secrets in code
5. Use RFC 5737 example IPs
6. Test thoroughly before committing

## Related Documentation

- [Script Template Documentation](../docs/SCRIPT_TEMPLATE.md) - Full templates
- [Contributing Guidelines](../CONTRIBUTING.md) - Contribution process
- [Security Best Practices](../SECURITY.md) - Security guidelines

---

**Last Updated**: 2025-10-12
**Maintained By**: [@dashtid](https://github.com/dashtid)
