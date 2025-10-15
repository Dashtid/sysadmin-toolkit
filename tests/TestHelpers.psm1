# Shared Test Helpers Module
# Import in test files with: Import-Module (Join-Path $PSScriptRoot "TestHelpers.psm1") -Force

<#
.SYNOPSIS
    Common helper functions for Pester tests across the repository.

.DESCRIPTION
    Provides reusable test utilities, mock functions, and validation helpers
    to reduce code duplication and improve test maintainability.
#>

# ============================================================================
# SCRIPT VALIDATION HELPERS
# ============================================================================

function Test-ScriptSyntax {
    <#
    .SYNOPSIS
        Validates PowerShell script syntax using PSParser.
    .PARAMETER Path
        Path to the script file to validate.
    .OUTPUTS
        Returns $true if syntax is valid, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Error "Script not found: $Path"
        return $false
    }

    $errors = $null
    $content = Get-Content $Path -Raw
    [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null

    return ($errors.Count -eq 0)
}

function Test-ScriptHasCommentHelp {
    <#
    .SYNOPSIS
        Checks if a script has comment-based help.
    .PARAMETER Path
        Path to the script file.
    .OUTPUTS
        Returns $true if comment-based help is present.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content $Path -Raw
    return ($content -match '<#' -and $content -match '\.SYNOPSIS')
}

function Get-ScriptParameters {
    <#
    .SYNOPSIS
        Extracts parameter names from a PowerShell script.
    .PARAMETER Path
        Path to the script file.
    .OUTPUTS
        Returns array of parameter names found in the script.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content $Path -Raw

    # Use multiline and singleline regex modifiers to match param blocks
    # This handles multi-line parameter blocks with proper capturing
    $paramBlock = if ($content -match '(?smi)param\s*\((.*?)\n\)') {
        $matches[1]
    } else {
        return @()
    }

    $parameters = @()
    # Match all parameter declarations: [Parameter...]\s*[type]$name
    $parameters = [regex]::Matches($paramBlock, '\$(\w+)') |
        ForEach-Object { $_.Groups[1].Value } |
        Select-Object -Unique

    return $parameters
}

# ============================================================================
# SECURITY VALIDATION HELPERS
# ============================================================================

function Test-NoHardcodedSecrets {
    <#
    .SYNOPSIS
        Checks script for hardcoded secrets.
    .PARAMETER Path
        Path to the script file.
    .OUTPUTS
        Returns $true if no secrets found, $false if secrets detected.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content $Path -Raw

    $secretPatterns = @(
        'password\s*=\s*["`''][^"`'']+["`'']'
        'apikey\s*=\s*["`''][^"`'']+["`'']'
        'api[_-]?key\s*=\s*["`''][^"`'']+["`'']'
        'secret\s*=\s*["`''][^"`'']+["`'']'
        'token\s*=\s*["`''][^"`'']+["`'']'
        'sk-[A-Za-z0-9]{20,}'  # API key pattern
    )

    foreach ($pattern in $secretPatterns) {
        if ($content -match $pattern) {
            Write-Warning "Potential secret found matching pattern: $pattern"
            return $false
        }
    }

    return $true
}

function Test-NoPrivateIPs {
    <#
    .SYNOPSIS
        Checks script for hardcoded private IP addresses.
    .PARAMETER Path
        Path to the script file.
    .PARAMETER AllowExampleIPs
        If true, allows RFC 5737 example IPs (192.0.2.x, etc.)
    .OUTPUTS
        Returns $true if no private IPs found or only example IPs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExampleIPs
    )

    $content = Get-Content $Path -Raw

    # Private IP patterns
    $privatePatterns = @(
        '10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        '172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}'
        '192\.168\.\d{1,3}\.\d{1,3}'
    )

    # RFC 5737 example IPs (allowed in documentation)
    $examplePatterns = @(
        '192\.0\.2\.\d{1,3}'
        '198\.51\.100\.\d{1,3}'
        '203\.0\.113\.\d{1,3}'
    )

    $foundPrivateIPs = @()

    foreach ($pattern in $privatePatterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($match in $matches) {
            $ip = $match.Value

            # Check if it's an example IP
            $isExampleIP = $false
            if ($AllowExampleIPs) {
                foreach ($examplePattern in $examplePatterns) {
                    if ($ip -match $examplePattern) {
                        $isExampleIP = $true
                        break
                    }
                }
            }

            if (-not $isExampleIP) {
                $foundPrivateIPs += $ip
            }
        }
    }

    if ($foundPrivateIPs.Count -gt 0) {
        Write-Warning "Private IPs found: $($foundPrivateIPs -join ', ')"
        return $false
    }

    return $true
}

# ============================================================================
# OUTPUT FORMAT HELPERS
# ============================================================================

function Test-ConsistentLogging {
    <#
    .SYNOPSIS
        Validates that a script uses consistent logging markers.
    .PARAMETER Path
        Path to the script file.
    .OUTPUTS
        Returns hashtable with results for each marker type.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content $Path -Raw

    return @{
        HasSuccessMarker = ($content -match '\[\+\]')
        HasErrorMarker   = ($content -match '\[-\]')
        HasInfoMarker    = ($content -match '\[i\]')
        HasWarningMarker = ($content -match '\[!\]')
        HasEmojis        = ($content -match '✅|❌|⚠️|ℹ️|🚀|📁|🔧')
    }
}

# ============================================================================
# MOCK HELPERS
# ============================================================================

function New-MockService {
    <#
    .SYNOPSIS
        Creates a mock Windows service object for testing.
    .PARAMETER Name
        Service name.
    .PARAMETER Status
        Service status (Running, Stopped, etc.)
    .OUTPUTS
        Returns a PSCustomObject mimicking Get-Service output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Running', 'Stopped', 'Paused', 'StartPending')]
        [string]$Status = 'Running'
    )

    return [PSCustomObject]@{
        Name        = $Name
        Status      = $Status
        DisplayName = $Name
        ServiceType = 'Win32OwnProcess'
        StartType   = 'Automatic'
    }
}

function New-MockProcess {
    <#
    .SYNOPSIS
        Creates a mock process object for testing.
    .PARAMETER Name
        Process name.
    .PARAMETER Id
        Process ID.
    .OUTPUTS
        Returns a PSCustomObject mimicking Get-Process output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [int]$Id = 12345
    )

    return [PSCustomObject]@{
        Name      = $Name
        Id        = $Id
        CPU       = 1.25
        Handles   = 200
        WS        = 10MB
        PM        = 8MB
        StartTime = (Get-Date).AddMinutes(-10)
    }
}

# ============================================================================
# ENVIRONMENT HELPERS
# ============================================================================

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if current session is running as administrator.
    .OUTPUTS
        Returns $true if running as administrator.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-TemporaryDirectory {
    <#
    .SYNOPSIS
        Creates a temporary directory for test isolation.
    .OUTPUTS
        Returns path to the temporary directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $tempPath = Join-Path $env:TEMP "PesterTest_$(New-Guid)"
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
    return $tempPath
}

function Remove-TemporaryDirectory {
    <#
    .SYNOPSIS
        Removes a temporary test directory.
    .PARAMETER Path
        Path to the temporary directory to remove.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ASSERTION HELPERS
# ============================================================================

function Assert-ScriptCanBeInvoked {
    <#
    .SYNOPSIS
        Tests if a script can be invoked without errors (syntax check).
    .PARAMETER Path
        Path to the script file.
    .PARAMETER Parameters
        Optional hashtable of parameters to pass to the script.
    .OUTPUTS
        Returns $true if script can be invoked successfully.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )

    try {
        $scriptBlock = [ScriptBlock]::Create((Get-Content $Path -Raw))
        $null = $scriptBlock.Invoke($Parameters)
        return $true
    }
    catch {
        Write-Warning "Script invocation failed: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# TEST DATA GENERATORS
# ============================================================================

function New-TestCredential {
    <#
    .SYNOPSIS
        Creates a PSCredential object for testing.
    .PARAMETER Username
        Username for the credential.
    .PARAMETER Password
        Plain text password (for testing only!).
    .OUTPUTS
        Returns PSCredential object.
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Username = "TestUser",

        [Parameter(Mandatory = $false)]
        [string]$Password = "TestPassword123!"
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $securePassword)
}

# Export module members
Export-ModuleMember -Function @(
    'Test-ScriptSyntax'
    'Test-ScriptHasCommentHelp'
    'Get-ScriptParameters'
    'Test-NoHardcodedSecrets'
    'Test-NoPrivateIPs'
    'Test-ConsistentLogging'
    'New-MockService'
    'New-MockProcess'
    'Test-IsAdministrator'
    'New-TemporaryDirectory'
    'Remove-TemporaryDirectory'
    'Assert-ScriptCanBeInvoked'
    'New-TestCredential'
)
