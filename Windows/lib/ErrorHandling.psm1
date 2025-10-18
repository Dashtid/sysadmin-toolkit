<#
.SYNOPSIS
    Advanced error handling utilities for PowerShell scripts

.DESCRIPTION
    Provides advanced error handling patterns including:
    - Command retry with exponential backoff
    - Input validation helpers
    - Contextual error messages
    - Error aggregation for batch operations

.NOTES
    Author: David Dashti
    Version: 1.0.0
    Last Updated: 2025-10-18

.EXAMPLE
    Import-Module "$PSScriptRoot\ErrorHandling.psm1"

    # Retry a flaky network command
    Retry-Command -ScriptBlock { Invoke-WebRequest -Uri "https://example.com" } -MaxAttempts 3

    # Validate input
    Test-InputValid -Value "192.168.1.1" -Type IPAddress

    # Write contextual error
    Write-ContextualError -ErrorRecord $_ -Context "updating system packages" -Suggestion "Check your network connection"
#>

# ============================================================================
# RETRY LOGIC
# ============================================================================

<#
.SYNOPSIS
    Retry a script block with exponential backoff

.DESCRIPTION
    Executes a script block and retries on failure with increasing delay between attempts.
    Uses exponential backoff: delay * attempt number.

.PARAMETER ScriptBlock
    The script block to execute

.PARAMETER MaxAttempts
    Maximum number of retry attempts (default: 3)

.PARAMETER DelaySeconds
    Initial delay in seconds between retries (default: 2)
    Actual delay will be DelaySeconds * attempt_number

.PARAMETER RetryOn
    Array of exception types to retry on. If not specified, retries on all exceptions.

.EXAMPLE
    Retry-Command -ScriptBlock { Invoke-WebRequest -Uri "https://api.example.com" } -MaxAttempts 5

.EXAMPLE
    Retry-Command -ScriptBlock {
        docker pull myimage:latest
    } -MaxAttempts 3 -DelaySeconds 5 -RetryOn @([System.Net.WebException])
#>
function Retry-Command {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxAttempts = 3,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$DelaySeconds = 2,

        [Parameter()]
        [Type[]]$RetryOn = @()
    )

    $attempt = 1
    $lastError = $null

    while ($attempt -le $MaxAttempts) {
        try {
            Write-Verbose "Attempt $attempt/$MaxAttempts"
            $result = & $ScriptBlock
            Write-Verbose "Command succeeded on attempt $attempt"
            return $result
        }
        catch {
            $lastError = $_

            # Check if we should retry on this exception type
            $shouldRetry = $false
            if ($RetryOn.Count -eq 0) {
                # No specific exceptions specified, retry on all
                $shouldRetry = $true
            }
            else {
                # Check if exception matches any retry types
                foreach ($exceptionType in $RetryOn) {
                    if ($_.Exception -is $exceptionType) {
                        $shouldRetry = $true
                        break
                    }
                }
            }

            if (-not $shouldRetry) {
                Write-Verbose "Exception type not in retry list, failing immediately"
                throw
            }

            Write-Warning "Attempt $attempt/$MaxAttempts failed: $($_.Exception.Message)"

            if ($attempt -lt $MaxAttempts) {
                $waitTime = $DelaySeconds * $attempt
                Write-Verbose "Waiting $waitTime seconds before retry..."
                Start-Sleep -Seconds $waitTime
            }
        }

        $attempt++
    }

    # All attempts failed
    throw "Command failed after $MaxAttempts attempts. Last error: $($lastError.Exception.Message)"
}

# ============================================================================
# INPUT VALIDATION
# ============================================================================

<#
.SYNOPSIS
    Validate input values against common patterns

.DESCRIPTION
    Provides validation for common input types used in sysadmin scripts.
    Supports: IPAddress, Hostname, Path, PortNumber, EmailAddress, URL

.PARAMETER Value
    The value to validate

.PARAMETER Type
    The validation type to apply

.PARAMETER AllowEmpty
    Allow empty/null values (default: $false)

.OUTPUTS
    Returns $true if valid, $false otherwise

.EXAMPLE
    if (Test-InputValid -Value "192.168.1.1" -Type IPAddress) {
        Write-Host "Valid IP address"
    }

.EXAMPLE
    Test-InputValid -Value "server01" -Type Hostname

.EXAMPLE
    Test-InputValid -Value "https://example.com" -Type URL
#>
function Test-InputValid {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet('IPAddress', 'Hostname', 'Path', 'PortNumber', 'EmailAddress', 'URL', 'NotEmpty')]
        [string]$Type,

        [Parameter()]
        [switch]$AllowEmpty
    )

    # Handle empty values
    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($AllowEmpty) {
            return $true
        }
        else {
            Write-Verbose "Validation failed: Value is empty"
            return $false
        }
    }

    switch ($Type) {
        'IPAddress' {
            try {
                [System.Net.IPAddress]::Parse($Value) | Out-Null
                return $true
            }
            catch {
                Write-Verbose "Invalid IP address: $Value"
                return $false
            }
        }

        'Hostname' {
            # RFC 1123 hostname validation
            $hostnameRegex = '^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$'
            if ($Value -match $hostnameRegex) {
                return $true
            }
            else {
                Write-Verbose "Invalid hostname: $Value"
                return $false
            }
        }

        'Path' {
            # Check if path format is valid (not necessarily that it exists)
            try {
                $null = [System.IO.Path]::GetFullPath($Value)
                return $true
            }
            catch {
                Write-Verbose "Invalid path format: $Value"
                return $false
            }
        }

        'PortNumber' {
            if ($Value -match '^\d+$' -and [int]$Value -ge 1 -and [int]$Value -le 65535) {
                return $true
            }
            else {
                Write-Verbose "Invalid port number: $Value (must be 1-65535)"
                return $false
            }
        }

        'EmailAddress' {
            # Simple email validation (not RFC 5322 compliant, but good enough)
            $emailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if ($Value -match $emailRegex) {
                return $true
            }
            else {
                Write-Verbose "Invalid email address: $Value"
                return $false
            }
        }

        'URL' {
            try {
                $uri = [System.Uri]$Value
                if ($uri.Scheme -in @('http', 'https', 'ftp', 'ftps')) {
                    return $true
                }
                else {
                    Write-Verbose "Invalid URL scheme: $($uri.Scheme)"
                    return $false
                }
            }
            catch {
                Write-Verbose "Invalid URL: $Value"
                return $false
            }
        }

        'NotEmpty' {
            return -not [string]::IsNullOrWhiteSpace($Value)
        }
    }

    return $false
}

# ============================================================================
# CONTEXTUAL ERROR HANDLING
# ============================================================================

<#
.SYNOPSIS
    Write detailed error message with context and suggestions

.DESCRIPTION
    Provides enhanced error messages that include:
    - The original error message
    - Context about what was being attempted
    - Suggestions for resolution
    - Stack trace (if verbose)

.PARAMETER ErrorRecord
    The error record from a catch block ($_)

.PARAMETER Context
    Description of what was being attempted when error occurred

.PARAMETER Suggestion
    Suggested action to resolve the error

.PARAMETER WriteToLog
    Also write to log file if CommonFunctions module is loaded

.EXAMPLE
    try {
        Update-SystemPackages
    }
    catch {
        Write-ContextualError -ErrorRecord $_ -Context "updating system packages" -Suggestion "Check your network connection and try again"
    }
#>
function Write-ContextualError {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [Parameter()]
        [string]$Suggestion = "",

        [Parameter()]
        [switch]$WriteToLog
    )

    # Build detailed error message
    $errorMessage = @"

[-] ERROR occurred while $Context

    Error Type: $($ErrorRecord.Exception.GetType().FullName)
    Error Message: $($ErrorRecord.Exception.Message)

"@

    if ($ErrorRecord.InvocationInfo) {
        $errorMessage += @"
    Location: $($ErrorRecord.InvocationInfo.ScriptName):$($ErrorRecord.InvocationInfo.ScriptLineNumber)
    Command: $($ErrorRecord.InvocationInfo.Line.Trim())

"@
    }

    if ($Suggestion) {
        $errorMessage += @"
    [!] Suggestion: $Suggestion

"@
    }

    # Add stack trace in verbose mode
    if ($VerbosePreference -ne 'SilentlyContinue') {
        $errorMessage += @"
    Stack Trace:
$($ErrorRecord.ScriptStackTrace)

"@
    }

    # Write to console
    Write-Host $errorMessage -ForegroundColor Red

    # Write to log file if CommonFunctions is available
    if ($WriteToLog -and (Get-Command Write-ErrorMessage -ErrorAction SilentlyContinue)) {
        Write-ErrorMessage $errorMessage
    }
}

# ============================================================================
# ERROR AGGREGATION
# ============================================================================

<#
.SYNOPSIS
    Execute operations and aggregate errors for batch reporting

.DESCRIPTION
    Useful when processing multiple items where you want to continue processing
    even if some items fail, then report all errors at the end.

.PARAMETER Items
    Array of items to process

.PARAMETER ScriptBlock
    Script block to execute for each item. Receives item as $_ or $args[0]

.PARAMETER StopOnFirstError
    Stop processing if any item fails (default: $false)

.OUTPUTS
    Returns hashtable with:
    - SuccessCount: Number of successful operations
    - FailureCount: Number of failed operations
    - Errors: Array of error details
    - SuccessItems: Array of successfully processed items

.EXAMPLE
    $servers = @("server1", "server2", "server3")
    $result = Invoke-WithErrorAggregation -Items $servers -ScriptBlock {
        param($server)
        Test-Connection -ComputerName $server -Count 1 -ErrorAction Stop
    }

    Write-Host "Succeeded: $($result.SuccessCount), Failed: $($result.FailureCount)"
    $result.Errors | ForEach-Object { Write-Warning $_.Message }
#>
function Invoke-WithErrorAggregation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Items,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [switch]$StopOnFirstError
    )

    $errors = @()
    $successItems = @()
    $successCount = 0
    $failureCount = 0

    foreach ($item in $Items) {
        try {
            Write-Verbose "Processing item: $item"
            $result = & $ScriptBlock $item
            $successItems += $item
            $successCount++
            Write-Verbose "Successfully processed: $item"
        }
        catch {
            $failureCount++
            $errorDetail = @{
                Item    = $item
                Message = $_.Exception.Message
                Error   = $_
            }
            $errors += $errorDetail
            Write-Warning "Failed to process item '$item': $($_.Exception.Message)"

            if ($StopOnFirstError) {
                Write-Verbose "Stopping on first error as requested"
                break
            }
        }
    }

    return @{
        SuccessCount = $successCount
        FailureCount = $failureCount
        Errors       = $errors
        SuccessItems = $successItems
        TotalCount   = $Items.Count
    }
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'Retry-Command',
    'Test-InputValid',
    'Write-ContextualError',
    'Invoke-WithErrorAggregation'
)
