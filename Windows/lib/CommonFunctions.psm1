<#
.SYNOPSIS
    Common functions shared across Windows PowerShell scripts.

.DESCRIPTION
    This module provides shared functionality for all Windows PowerShell scripts in the toolkit:
    - Consistent logging with ASCII markers
    - Admin privilege checking
    - Path validation helpers
    - Common color schemes

.NOTES
    Author: Windows & Linux Sysadmin Toolkit
    Version: 1.0.0
    Requires: PowerShell 5.1+
#>

# Color scheme for consistent output
$script:Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
    White  = 'White'
}

<#
.SYNOPSIS
    Writes a timestamped log message with optional color.

.PARAMETER Message
    The message to log.

.PARAMETER Color
    Optional color for the message (default: White).

.EXAMPLE
    Write-Log "Processing started" -Color $Colors.Cyan
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [string]$Color = 'White'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

<#
.SYNOPSIS
    Writes a success message with [+] marker.

.PARAMETER Message
    The success message to display.

.EXAMPLE
    Write-Success "Operation completed successfully"
#>
function Write-Success {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Log "[+] $Message" -Color $script:Colors.Green
}

<#
.SYNOPSIS
    Writes an info message with [i] marker.

.PARAMETER Message
    The info message to display.

.EXAMPLE
    Write-InfoMessage "Starting operation..."
#>
function Write-InfoMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Log "[i] $Message" -Color $script:Colors.Blue
}

<#
.SYNOPSIS
    Writes a warning message with [!] marker.

.PARAMETER Message
    The warning message to display.

.EXAMPLE
    Write-WarningMessage "Proceeding with caution"
#>
function Write-WarningMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Log "[!] $Message" -Color $script:Colors.Yellow
}

<#
.SYNOPSIS
    Writes an error message with [-] marker.

.PARAMETER Message
    The error message to display.

.EXAMPLE
    Write-ErrorMessage "Operation failed"
#>
function Write-ErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Log "[-] $Message" -Color $script:Colors.Red
}

<#
.SYNOPSIS
    Tests if the current PowerShell session is running with administrator privileges.

.DESCRIPTION
    Checks if the current user has administrator privileges by examining the WindowsIdentity
    and WindowsPrincipal objects.

.OUTPUTS
    Boolean - $true if running as administrator, $false otherwise.

.EXAMPLE
    if (Test-IsAdministrator) {
        Write-Success "Running with admin privileges"
    }
#>
function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Asserts that the script is running with administrator privileges.

.DESCRIPTION
    Checks for administrator privileges and exits the script with error code 1 if not running as admin.
    Displays an error message before exiting.

.PARAMETER ExitOnFail
    If set to $false, the function will return $false instead of exiting (default: $true).

.EXAMPLE
    Assert-Administrator
    # Script continues only if running as admin

.EXAMPLE
    if (-not (Assert-Administrator -ExitOnFail $false)) {
        Write-Warning "Some features disabled without admin privileges"
    }
#>
function Assert-Administrator {
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$ExitOnFail = $true
    )

    if (-not (Test-IsAdministrator)) {
        Write-ErrorMessage "This script must be run as Administrator"
        if ($ExitOnFail) {
            exit 1
        }
        return $false
    }
    return $true
}

<#
.SYNOPSIS
    Tests if PowerShell 7+ is installed and available.

.OUTPUTS
    Boolean - $true if PowerShell 7+ is available, $false otherwise.

.EXAMPLE
    if (Test-PowerShell7) {
        Write-Success "PowerShell 7+ is available"
    }
#>
function Test-PowerShell7 {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
    return (Test-Path $pwsh7Path)
}

<#
.SYNOPSIS
    Gets the full path to the PowerShell 7 executable.

.OUTPUTS
    String - Full path to pwsh.exe if found, $null otherwise.

.EXAMPLE
    $pwshPath = Get-PowerShell7Path
    if ($pwshPath) {
        & $pwshPath -Command "Get-Host"
    }
#>
function Get-PowerShell7Path {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
    if (Test-Path $pwsh7Path) {
        return $pwsh7Path
    }
    return $null
}

# Export public functions
Export-ModuleMember -Function @(
    'Write-Log',
    'Write-Success',
    'Write-InfoMessage',
    'Write-WarningMessage',
    'Write-ErrorMessage',
    'Test-IsAdministrator',
    'Assert-Administrator',
    'Test-PowerShell7',
    'Get-PowerShell7Path'
)

# Export color scheme for scripts that need custom colors
Export-ModuleMember -Variable 'Colors'
