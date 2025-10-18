<#
.SYNOPSIS
    Mock helper functions for Pester tests

.DESCRIPTION
    Provides reusable mock configurations and helper functions for testing
    sysadmin scripts. Implements Pester 5 best practices for mocking.

.NOTES
    Author: David Dashti
    Version: 1.0.0
    Last Updated: 2025-10-18
    Requires: Pester 5.0+

.EXAMPLE
    Import-Module (Join-Path $PSScriptRoot "MockHelpers.psm1") -Force
    Mock-ServiceCommands
#>

# ============================================================================
# SERVICE MOCKING HELPERS
# ============================================================================

function Mock-ServiceCommands {
    <#
    .SYNOPSIS
        Mocks common service-related commands for isolated testing

    .DESCRIPTION
        Creates mocks for Get-Service, Start-Service, Stop-Service, and Set-Service
        to prevent actual service manipulation during tests

    .PARAMETER RunningServices
        Array of service names that should appear as "Running"

    .PARAMETER StoppedServices
        Array of service names that should appear as "Stopped"

    .EXAMPLE
        Mock-ServiceCommands -RunningServices @('ssh-agent') -StoppedServices @('wuauserv')
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$RunningServices = @('ssh-agent'),

        [Parameter()]
        [string[]]$StoppedServices = @()
    )

    Mock Get-Service {
        param($Name)

        $status = if ($RunningServices -contains $Name) { 'Running' }
                  elseif ($StoppedServices -contains $Name) { 'Stopped' }
                  else { 'Running' }

        [PSCustomObject]@{
            Name        = $Name
            Status      = $status
            StartType   = 'Automatic'
            DisplayName = "Mock $Name Service"
        }
    }

    Mock Start-Service { }
    Mock Stop-Service { }
    Mock Set-Service { }
}

# ============================================================================
# FILE SYSTEM MOCKING HELPERS
# ============================================================================

function Mock-FileSystemCommands {
    <#
    .SYNOPSIS
        Mocks file system commands to prevent actual file operations

    .DESCRIPTION
        Creates mocks for common file operations like Test-Path, Get-Content,
        Set-Content, New-Item, Remove-Item

    .PARAMETER ExistingPaths
        Hash table of paths that should exist with their content
        Example: @{ 'C:\test.txt' = 'content'; 'C:\folder' = $null }

    .EXAMPLE
        Mock-FileSystemCommands -ExistingPaths @{ 'C:\config.json' = '{"key":"value"}' }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$ExistingPaths = @{}
    )

    Mock Test-Path {
        param($Path)
        $ExistingPaths.ContainsKey($Path)
    }

    Mock Get-Content {
        param($Path)
        if ($ExistingPaths.ContainsKey($Path)) {
            return $ExistingPaths[$Path]
        }
        throw "Cannot find path '$Path' because it does not exist."
    }

    Mock Set-Content { }
    Mock New-Item { }
    Mock Remove-Item { }
}

# ============================================================================
# NETWORK/SSH MOCKING HELPERS
# ============================================================================

function Mock-SSHCommands {
    <#
    .SYNOPSIS
        Mocks SSH-related commands for testing SSH scripts

    .DESCRIPTION
        Creates mocks for ssh, ssh-add, ssh-keygen, and related commands

    .EXAMPLE
        Mock-SSHCommands
    #>
    [CmdletBinding()]
    param()

    Mock Start-Process { }

    # Mock SSH agent environment variable checks
    Mock Get-Variable {
        param($Name)
        if ($Name -eq 'SSH_AUTH_SOCK') {
            [PSCustomObject]@{
                Name  = 'SSH_AUTH_SOCK'
                Value = '\\.\pipe\openssh-ssh-agent'
            }
        }
    }
}

# ============================================================================
# REGISTRY MOCKING HELPERS
# ============================================================================

function Mock-RegistryCommands {
    <#
    .SYNOPSIS
        Mocks registry access commands

    .DESCRIPTION
        Creates mocks for Get-ItemProperty, Set-ItemProperty, New-ItemProperty
        to prevent registry modifications during tests

    .PARAMETER RegistryValues
        Hash table of registry paths and values

    .EXAMPLE
        Mock-RegistryCommands -RegistryValues @{
            'HKLM:\SOFTWARE\Test' = @{ 'Value' = 'Data' }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$RegistryValues = @{}
    )

    Mock Get-ItemProperty {
        param($Path, $Name)

        if ($RegistryValues.ContainsKey($Path)) {
            if ($Name) {
                return $RegistryValues[$Path][$Name]
            }
            return $RegistryValues[$Path]
        }
        return $null
    }

    Mock Set-ItemProperty { }
    Mock New-ItemProperty { }
}

# ============================================================================
# PROCESS/COMMAND MOCKING HELPERS
# ============================================================================

function Mock-ExternalCommands {
    <#
    .SYNOPSIS
        Mocks external command execution

    .DESCRIPTION
        Creates mocks for Invoke-Expression, Start-Process, and custom command execution

    .PARAMETER CommandResults
        Hash table mapping commands to their mock results
        Example: @{ 'docker ps' = 'CONTAINER ID   IMAGE'; 'git status' = 'On branch main' }

    .EXAMPLE
        Mock-ExternalCommands -CommandResults @{ 'nvidia-smi' = 'GPU 0: Tesla T4' }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$CommandResults = @{}
    )

    Mock Invoke-Expression {
        param($Command)

        foreach ($key in $CommandResults.Keys) {
            if ($Command -like "*$key*") {
                return $CommandResults[$key]
            }
        }
        return ""
    }

    Mock Start-Process {
        param($FilePath, $ArgumentList)

        $fullCommand = "$FilePath $($ArgumentList -join ' ')"
        foreach ($key in $CommandResults.Keys) {
            if ($fullCommand -like "*$key*") {
                return @{
                    ExitCode = 0
                    Output   = $CommandResults[$key]
                }
            }
        }
        return @{ ExitCode = 0; Output = "" }
    }
}

# ============================================================================
# NETWORK MOCKING HELPERS
# ============================================================================

function Mock-NetworkCommands {
    <#
    .SYNOPSIS
        Mocks network-related commands

    .DESCRIPTION
        Creates mocks for Test-Connection, Invoke-WebRequest, Invoke-RestMethod

    .PARAMETER ReachableHosts
        Array of hostnames that should respond to Test-Connection

    .PARAMETER WebResponses
        Hash table of URLs to mock response content

    .EXAMPLE
        Mock-NetworkCommands -ReachableHosts @('example.com') -WebResponses @{
            'https://api.example.com' = '{"status":"ok"}'
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$ReachableHosts = @(),

        [Parameter()]
        [hashtable]$WebResponses = @{}
    )

    Mock Test-Connection {
        param($ComputerName)

        if ($ReachableHosts -contains $ComputerName) {
            return [PSCustomObject]@{
                Address      = $ComputerName
                StatusCode   = 0
                ResponseTime = 10
            }
        }
        throw "Unable to contact $ComputerName"
    }

    Mock Invoke-WebRequest {
        param($Uri)

        foreach ($url in $WebResponses.Keys) {
            if ($Uri -like "*$url*") {
                return [PSCustomObject]@{
                    StatusCode = 200
                    Content    = $WebResponses[$url]
                }
            }
        }
        throw "404 Not Found"
    }

    Mock Invoke-RestMethod {
        param($Uri)

        foreach ($url in $WebResponses.Keys) {
            if ($Uri -like "*$url*") {
                return $WebResponses[$url] | ConvertFrom-Json
            }
        }
        throw "404 Not Found"
    }
}

# ============================================================================
# ENVIRONMENT MOCKING HELPERS
# ============================================================================

function Mock-EnvironmentVariables {
    <#
    .SYNOPSIS
        Mocks environment variable access

    .DESCRIPTION
        Creates mocks for $env: variable access and [Environment]::GetEnvironmentVariable

    .PARAMETER Variables
        Hash table of environment variables to mock

    .EXAMPLE
        Mock-EnvironmentVariables -Variables @{
            'PATH' = 'C:\Windows\System32;C:\Windows'
            'USERPROFILE' = 'C:\Users\TestUser'
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Variables = @{}
    )

    Mock Get-ChildItem {
        param($Path)

        if ($Path -like 'Env:*') {
            $varName = $Path -replace 'Env:', ''
            if ($Variables.ContainsKey($varName)) {
                return [PSCustomObject]@{
                    Name  = $varName
                    Value = $Variables[$varName]
                }
            }
        }
        throw "Cannot find path '$Path' because it does not exist."
    }
}

# ============================================================================
# TEST DATA GENERATORS
# ============================================================================

function New-MockCredential {
    <#
    .SYNOPSIS
        Creates a mock PSCredential object for testing

    .DESCRIPTION
        Generates a PSCredential object with test username and password
        for use in tests that require credentials

    .PARAMETER Username
        Username for the credential (default: "TestUser")

    .PARAMETER Password
        Password for the credential (default: "TestPassword123!")

    .EXAMPLE
        $cred = New-MockCredential -Username "admin"
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter()]
        [string]$Username = "TestUser",

        [Parameter()]
        [string]$Password = "TestPassword123!"
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $securePassword)
}

function New-MockServiceObject {
    <#
    .SYNOPSIS
        Creates a mock service object

    .DESCRIPTION
        Generates a service-like object for testing

    .PARAMETER Name
        Service name

    .PARAMETER Status
        Service status (Running, Stopped, etc.)

    .PARAMETER StartType
        Service start type (Automatic, Manual, Disabled)

    .EXAMPLE
        $service = New-MockServiceObject -Name "TestService" -Status "Running"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Running', 'Stopped', 'Paused')]
        [string]$Status = 'Running',

        [Parameter()]
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [string]$StartType = 'Automatic'
    )

    return [PSCustomObject]@{
        PSTypeName  = 'System.ServiceProcess.ServiceController'
        Name        = $Name
        Status      = $Status
        StartType   = $StartType
        DisplayName = "Mock $Name Service"
        ServiceType = 'Win32OwnProcess'
    }
}

function New-MockFile {
    <#
    .SYNOPSIS
        Creates a mock file system object

    .DESCRIPTION
        Generates a FileInfo-like object for testing

    .PARAMETER Path
        File path

    .PARAMETER Content
        File content (if text file)

    .PARAMETER LastWriteTime
        Last modification time

    .EXAMPLE
        $file = New-MockFile -Path "C:\test.txt" -Content "Hello World"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Content = "",

        [Parameter()]
        [DateTime]$LastWriteTime = (Get-Date)
    )

    $name = Split-Path $Path -Leaf
    $directory = Split-Path $Path -Parent

    return [PSCustomObject]@{
        PSTypeName     = 'System.IO.FileInfo'
        FullName       = $Path
        Name           = $name
        Directory      = $directory
        Extension      = [System.IO.Path]::GetExtension($Path)
        Length         = $Content.Length
        LastWriteTime  = $LastWriteTime
        Exists         = $true
    }
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'Mock-ServiceCommands',
    'Mock-FileSystemCommands',
    'Mock-SSHCommands',
    'Mock-RegistryCommands',
    'Mock-ExternalCommands',
    'Mock-NetworkCommands',
    'Mock-EnvironmentVariables',
    'New-MockCredential',
    'New-MockServiceObject',
    'New-MockFile'
)
