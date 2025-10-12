<#
.SYNOPSIS
    Example PowerShell script demonstrating best practices for this repository.

.DESCRIPTION
    This script serves as a reference implementation showing:
    - Proper comment-based help documentation
    - Parameter validation and error handling
    - Consistent output formatting
    - WhatIf/Confirm support
    - Logging capabilities
    - Retry logic
    - Clean code structure

    Use this as a template when creating new scripts for the repository.

.PARAMETER ServerName
    The name or IP address of the target server.
    Use RFC 5737 example IPs for documentation (192.0.2.x, 198.51.100.x, 203.0.113.x).

.PARAMETER Port
    The port number to connect to (valid range: 1-65535).
    Default: 22

.PARAMETER Operation
    The operation to perform on the server.
    Valid options: Check, Connect, Test, Status

.PARAMETER Credential
    PSCredential object for authentication.
    If not provided, will use current user context.

.PARAMETER Timeout
    Timeout in seconds for operations.
    Default: 30

.PARAMETER MaxRetries
    Maximum number of retry attempts for failed operations.
    Default: 3

.PARAMETER WhatIf
    Preview what the script would do without making actual changes.

.PARAMETER Confirm
    Prompt for confirmation before making changes.

.EXAMPLE
    .\example-powershell-script.ps1 -ServerName "192.0.2.10" -Operation Check

    Checks the connection to server 192.0.2.10 on default port 22.

.EXAMPLE
    .\example-powershell-script.ps1 -ServerName "web.example.com" -Port 8080 -Operation Test -WhatIf

    Preview mode - shows what would happen when testing web.example.com:8080.

.EXAMPLE
    $cred = Get-Credential
    .\example-powershell-script.ps1 -ServerName "192.0.2.20" -Operation Connect -Credential $cred -Timeout 60

    Connects to server with custom credentials and 60-second timeout.

.NOTES
    File Name      : example-powershell-script.ps1
    Author         : David Dashti
    Prerequisite   : PowerShell 7.0+
    Creation Date  : 2025-10-12
    Last Modified  : 2025-10-12
    Version        : 1.0.0

    Change Log:
    - 1.0.0 (2025-10-12): Initial example script creation

.LINK
    https://github.com/Dashtid/windows-linux-sysadmin-toolkit

.LINK
    docs/SCRIPT_TEMPLATE.md
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Enter the server name or IP address (use RFC 5737 example IPs)"
    )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')]
    [string]$ServerName,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Check", "Connect", "Test", "Status")]
    [string]$Operation,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 300)]
    [int]$Timeout = 30,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script metadata
$SCRIPT_VERSION = "1.0.0"
$SCRIPT_NAME = $MyInvocation.MyCommand.Name
$SCRIPT_PATH = $PSScriptRoot

# Paths
$LOG_DIR = Join-Path $SCRIPT_PATH "logs"
$LOG_FILE = Join-Path $LOG_DIR "$SCRIPT_NAME-$(Get-Date -Format 'yyyyMMdd').log"

# Create log directory if it doesn't exist
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes formatted log messages to console and file.
    .PARAMETER Level
        The severity level: Info, Success, Warning, Error
    .PARAMETER Message
        The message to log
    .PARAMETER NoNewLine
        Don't add a newline after the message
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewLine
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] "

    # Determine prefix and color
    switch ($Level) {
        "Info"    {
            $prefix = "[i]"
            $color = "Blue"
        }
        "Success" {
            $prefix = "[+]"
            $color = "Green"
        }
        "Warning" {
            $prefix = "[!]"
            $color = "Yellow"
        }
        "Error"   {
            $prefix = "[-]"
            $color = "Red"
        }
        "Debug"   {
            $prefix = "[DEBUG]"
            $color = "Gray"
        }
    }

    $logEntry += "$prefix $Message"

    # Write to console
    $writeParams = @{
        Object          = $logEntry
        ForegroundColor = $color
    }
    if ($NoNewLine) {
        $writeParams.Add("NoNewLine", $true)
    }
    Write-Host @writeParams

    # Write to log file (without color codes)
    $logEntry | Out-File -FilePath $LOG_FILE -Append -Encoding UTF8
}

function Write-LogDebug {
    <#
    .SYNOPSIS
        Writes debug messages if VerbosePreference is enabled.
    #>
    [CmdletBinding()]
    param([string]$Message)

    if ($VerbosePreference -ne 'SilentlyContinue') {
        Write-Log -Level Debug -Message $Message
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates that all prerequisites are met.
    .DESCRIPTION
        Checks for required modules, permissions, and system state.
    .OUTPUTS
        Boolean indicating whether prerequisites are met
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Log -Level Info -Message "Checking prerequisites..."

    try {
        # Check PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        Write-LogDebug "PowerShell version: $psVersion"

        if ($psVersion.Major -lt 7) {
            Write-Log -Level Error -Message "PowerShell 7.0+ is required (current: $psVersion)"
            return $false
        }

        # Check if running with sufficient privileges (if needed)
        # $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        # $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        # if (-not $isAdmin) {
        #     Write-Log -Level Error -Message "This script requires administrator privileges"
        #     return $false
        # }

        # Check for required modules (example)
        # $requiredModules = @("ModuleName")
        # foreach ($module in $requiredModules) {
        #     if (-not (Get-Module -ListAvailable -Name $module)) {
        #         Write-Log -Level Error -Message "Required module not found: $module"
        #         Write-Log -Level Info -Message "Install with: Install-Module -Name $module"
        #         return $false
        #     }
        # }

        Write-Log -Level Success -Message "All prerequisites met"
        return $true
    }
    catch {
        Write-Log -Level Error -Message "Prerequisites check failed: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-OperationWithRetry {
    <#
    .SYNOPSIS
        Executes an operation with automatic retry logic.
    .PARAMETER ScriptBlock
        The operation to execute
    .PARAMETER MaxAttempts
        Maximum number of attempts
    .PARAMETER RetryDelay
        Delay in seconds between retries
    .OUTPUTS
        Result of the operation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = $MaxRetries,

        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 2
    )

    $attempt = 1
    $success = $false
    $result = $null

    while (-not $success -and $attempt -le $MaxAttempts) {
        try {
            Write-LogDebug "Attempt $attempt of $MaxAttempts"
            $result = & $ScriptBlock
            $success = $true
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                Write-Log -Level Warning -Message "Attempt $attempt failed: $($_.Exception.Message)"
                Write-Log -Level Info -Message "Retrying in $RetryDelay seconds..."
                Start-Sleep -Seconds $RetryDelay
                $attempt++
            }
            else {
                Write-Log -Level Error -Message "All $MaxAttempts attempts failed"
                throw
            }
        }
    }

    return $result
}

# ============================================================================
# MAIN LOGIC FUNCTIONS
# ============================================================================

function Test-ServerConnection {
    <#
    .SYNOPSIS
        Tests connectivity to a server.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [int]$PortNumber,
        [int]$TimeoutSeconds
    )

    Write-Log -Level Info -Message "Testing connection to $Server`:$PortNumber (timeout: ${TimeoutSeconds}s)"

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($Server, $PortNumber, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)

        if (-not $wait) {
            $tcpClient.Close()
            Write-Log -Level Warning -Message "Connection timeout after ${TimeoutSeconds}s"
            return $false
        }

        $tcpClient.EndConnect($connect)
        $tcpClient.Close()

        Write-Log -Level Success -Message "Connection successful"
        return $true
    }
    catch {
        Write-Log -Level Error -Message "Connection failed: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-ServerOperation {
    <#
    .SYNOPSIS
        Performs the requested operation on the server.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Server,
        [int]$PortNumber,
        [string]$OperationType,
        [PSCredential]$Cred
    )

    Write-Log -Level Info -Message "Performing '$OperationType' operation on $Server`:$PortNumber"

    # Check if we should proceed (WhatIf support)
    if (-not $PSCmdlet.ShouldProcess("$Server`:$PortNumber", "Perform $OperationType operation")) {
        Write-Log -Level Info -Message "Operation cancelled (WhatIf or user declined)"
        return $false
    }

    try {
        switch ($OperationType) {
            "Check" {
                $result = Test-ServerConnection -Server $Server -PortNumber $PortNumber -TimeoutSeconds $Timeout
                if ($result) {
                    Write-Log -Level Success -Message "Server is reachable"
                    return $true
                }
                else {
                    Write-Log -Level Warning -Message "Server is not reachable"
                    return $false
                }
            }

            "Connect" {
                Write-Log -Level Info -Message "Initiating connection..."
                # Implement actual connection logic here
                Write-Log -Level Success -Message "Connected successfully"
                return $true
            }

            "Test" {
                Write-Log -Level Info -Message "Running tests..."
                # Implement test logic here
                Write-Log -Level Success -Message "Tests completed"
                return $true
            }

            "Status" {
                Write-Log -Level Info -Message "Checking status..."
                # Implement status check logic here
                Write-Log -Level Success -Message "Status: Online"
                return $true
            }

            Default {
                Write-Log -Level Error -Message "Unknown operation: $OperationType"
                return $false
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
    Write-Log -Level Info -Message "Server: $ServerName"
    Write-Log -Level Info -Message "Port: $Port"
    Write-Log -Level Info -Message "Operation: $Operation"
    Write-Log -Level Info -Message "Timeout: ${Timeout}s"
    Write-Log -Level Info -Message "Max Retries: $MaxRetries"
    Write-Log -Level Info -Message "========================================"

    try {
        # Check prerequisites
        if (-not (Test-Prerequisites)) {
            Write-Log -Level Error -Message "Prerequisites not met. Exiting."
            exit 1
        }

        # Execute operation with retry logic
        $result = Invoke-OperationWithRetry -ScriptBlock {
            Invoke-ServerOperation -Server $ServerName -PortNumber $Port -OperationType $Operation -Cred $Credential
        } -MaxAttempts $MaxRetries

        if ($result) {
            Write-Log -Level Success -Message "========================================"
            Write-Log -Level Success -Message "Script completed successfully"
            Write-Log -Level Success -Message "========================================"
            exit 0
        }
        else {
            Write-Log -Level Warning -Message "========================================"
            Write-Log -Level Warning -Message "Script completed with warnings"
            Write-Log -Level Warning -Message "========================================"
            exit 0
        }
    }
    catch {
        Write-Log -Level Error -Message "========================================"
        Write-Log -Level Error -Message "Script failed: $($_.Exception.Message)"
        Write-Log -Level Error -Message "Stack trace:"
        Write-Log -Level Error -Message $_.ScriptStackTrace
        Write-Log -Level Error -Message "========================================"
        exit 1
    }
}

# Execute main function
Main
