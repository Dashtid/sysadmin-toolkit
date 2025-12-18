#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Validates development environment setup and identifies missing or misconfigured tools.

.DESCRIPTION
    This script provides comprehensive development environment validation:
    - Verify installed development tools (Git, Node.js, Python, etc.)
    - Check version requirements against minimum/recommended versions
    - Validate PATH configuration
    - Test SSH key setup for Git operations
    - Verify IDE installations (VSCode, Visual Studio)
    - Check package manager configurations
    - Install missing tools automatically (optional)
    - Generate detailed environment reports

    Features:
    - Configurable tool requirements via JSON
    - Automatic tool installation via package managers
    - SSH key validation for GitHub/GitLab/Bitbucket
    - Environment variable checks
    - IDE extension verification
    - Development-ready status assessment

.PARAMETER Profile
    Predefined development profile to validate against. Valid values:
    - WebDev: Web development (Node.js, npm, Git, VSCode)
    - Python: Python development (Python, pip, venv, Git)
    - DevOps: DevOps tools (Docker, kubectl, terraform, Git)
    - FullStack: Full stack (all common tools)
    - Custom: Use custom requirements file
    Default: FullStack

.PARAMETER RequirementsFile
    Path to custom JSON requirements file. Used with -Profile Custom.

.PARAMETER AutoInstall
    Automatically install missing tools using available package managers.

.PARAMETER CheckSSH
    Validate SSH key configuration for Git hosting services.

.PARAMETER CheckExtensions
    Check for recommended VS Code extensions.

.PARAMETER OutputFormat
    Output format. Valid values: Console, HTML, JSON.
    Default: Console

.PARAMETER OutputPath
    Path for output report files.

.PARAMETER Verbose
    Show detailed information about each check.

.EXAMPLE
    .\Test-DevEnvironment.ps1
    Validates full stack development environment with console output.

.EXAMPLE
    .\Test-DevEnvironment.ps1 -Profile WebDev -AutoInstall
    Validates web development environment and installs missing tools.

.EXAMPLE
    .\Test-DevEnvironment.ps1 -Profile Python -CheckSSH -OutputFormat HTML
    Validates Python environment, checks SSH, and generates HTML report.

.EXAMPLE
    .\Test-DevEnvironment.ps1 -Profile Custom -RequirementsFile ".\my-requirements.json"
    Validates against custom requirements file.

.EXAMPLE
    .\Test-DevEnvironment.ps1 -CheckExtensions -OutputFormat JSON -OutputPath "C:\Reports"
    Validates environment with VS Code extensions and saves JSON report.

.NOTES
    File Name      : Test-DevEnvironment.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Supported Package Managers:
    - Winget (Windows Package Manager)
    - Chocolatey
    - Scoop

    SSH Key Locations:
    - Windows: %USERPROFILE%\.ssh\
    - Git Bash: ~/.ssh/

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('WebDev', 'Python', 'DevOps', 'FullStack', 'Custom')]
    [string]$Profile = 'FullStack',

    [Parameter()]
    [string]$RequirementsFile,

    [Parameter()]
    [switch]$AutoInstall,

    [Parameter()]
    [switch]$CheckSSH,

    [Parameter()]
    [switch]$CheckExtensions,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    # Fallback logging functions if module not found
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Get-LogDirectory { return Join-Path $PSScriptRoot "..\..\logs" }
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"

# Tool definitions with version parsing patterns
$script:ToolDefinitions = @{
    # Version Control
    git = @{
        Name           = "Git"
        Command        = "git"
        VersionArgs    = "--version"
        VersionPattern = 'git version (\d+\.\d+\.\d+)'
        MinVersion     = "2.30.0"
        Category       = "Version Control"
        WingetId       = "Git.Git"
        ChocoId        = "git"
        Required       = $true
    }

    # JavaScript/Node.js
    node = @{
        Name           = "Node.js"
        Command        = "node"
        VersionArgs    = "--version"
        VersionPattern = 'v(\d+\.\d+\.\d+)'
        MinVersion     = "18.0.0"
        Category       = "JavaScript Runtime"
        WingetId       = "OpenJS.NodeJS.LTS"
        ChocoId        = "nodejs-lts"
        Required       = $false
    }
    npm = @{
        Name           = "npm"
        Command        = "npm"
        VersionArgs    = "--version"
        VersionPattern = '(\d+\.\d+\.\d+)'
        MinVersion     = "9.0.0"
        Category       = "Package Manager"
        Required       = $false
    }
    yarn = @{
        Name           = "Yarn"
        Command        = "yarn"
        VersionArgs    = "--version"
        VersionPattern = '(\d+\.\d+\.\d+)'
        MinVersion     = "1.22.0"
        Category       = "Package Manager"
        WingetId       = "Yarn.Yarn"
        ChocoId        = "yarn"
        Required       = $false
    }
    pnpm = @{
        Name           = "pnpm"
        Command        = "pnpm"
        VersionArgs    = "--version"
        VersionPattern = '(\d+\.\d+\.\d+)'
        MinVersion     = "8.0.0"
        Category       = "Package Manager"
        Required       = $false
    }

    # Python
    python = @{
        Name           = "Python"
        Command        = "python"
        VersionArgs    = "--version"
        VersionPattern = 'Python (\d+\.\d+\.\d+)'
        MinVersion     = "3.9.0"
        Category       = "Language Runtime"
        WingetId       = "Python.Python.3.12"
        ChocoId        = "python"
        Required       = $false
    }
    pip = @{
        Name           = "pip"
        Command        = "pip"
        VersionArgs    = "--version"
        VersionPattern = 'pip (\d+\.\d+)'
        MinVersion     = "23.0"
        Category       = "Package Manager"
        Required       = $false
    }

    # DevOps Tools
    docker = @{
        Name           = "Docker"
        Command        = "docker"
        VersionArgs    = "--version"
        VersionPattern = 'Docker version (\d+\.\d+\.\d+)'
        MinVersion     = "24.0.0"
        Category       = "Containers"
        WingetId       = "Docker.DockerDesktop"
        ChocoId        = "docker-desktop"
        Required       = $false
    }
    kubectl = @{
        Name           = "kubectl"
        Command        = "kubectl"
        VersionArgs    = "version --client --short"
        VersionPattern = 'v(\d+\.\d+\.\d+)'
        MinVersion     = "1.28.0"
        Category       = "Kubernetes"
        WingetId       = "Kubernetes.kubectl"
        ChocoId        = "kubernetes-cli"
        Required       = $false
    }
    helm = @{
        Name           = "Helm"
        Command        = "helm"
        VersionArgs    = "version --short"
        VersionPattern = 'v(\d+\.\d+\.\d+)'
        MinVersion     = "3.12.0"
        Category       = "Kubernetes"
        WingetId       = "Helm.Helm"
        ChocoId        = "kubernetes-helm"
        Required       = $false
    }
    terraform = @{
        Name           = "Terraform"
        Command        = "terraform"
        VersionArgs    = "version"
        VersionPattern = 'Terraform v(\d+\.\d+\.\d+)'
        MinVersion     = "1.5.0"
        Category       = "Infrastructure"
        WingetId       = "Hashicorp.Terraform"
        ChocoId        = "terraform"
        Required       = $false
    }

    # IDEs and Editors
    code = @{
        Name           = "VS Code"
        Command        = "code"
        VersionArgs    = "--version"
        VersionPattern = '(\d+\.\d+\.\d+)'
        MinVersion     = "1.85.0"
        Category       = "IDE"
        WingetId       = "Microsoft.VisualStudioCode"
        ChocoId        = "vscode"
        Required       = $false
    }

    # Other Tools
    pwsh = @{
        Name           = "PowerShell 7"
        Command        = "pwsh"
        VersionArgs    = "--version"
        VersionPattern = 'PowerShell (\d+\.\d+\.\d+)'
        MinVersion     = "7.4.0"
        Category       = "Shell"
        WingetId       = "Microsoft.PowerShell"
        ChocoId        = "powershell-core"
        Required       = $false
    }
    wsl = @{
        Name           = "WSL"
        Command        = "wsl"
        VersionArgs    = "--version"
        VersionPattern = 'WSL version:\s*(\d+\.\d+\.\d+)'
        MinVersion     = "2.0.0"
        Category       = "Virtualization"
        Required       = $false
    }
    gh = @{
        Name           = "GitHub CLI"
        Command        = "gh"
        VersionArgs    = "--version"
        VersionPattern = 'gh version (\d+\.\d+\.\d+)'
        MinVersion     = "2.40.0"
        Category       = "Version Control"
        WingetId       = "GitHub.cli"
        ChocoId        = "gh"
        Required       = $false
    }
}

# Profile definitions
$script:Profiles = @{
    WebDev = @('git', 'node', 'npm', 'code')
    Python = @('git', 'python', 'pip', 'code')
    DevOps = @('git', 'docker', 'kubectl', 'helm', 'terraform', 'code')
    FullStack = @('git', 'node', 'npm', 'python', 'pip', 'docker', 'code', 'pwsh', 'gh')
}

# Recommended VS Code extensions by profile
$script:RecommendedExtensions = @{
    WebDev = @(
        'dbaeumer.vscode-eslint',
        'esbenp.prettier-vscode',
        'ritwickdey.liveserver',
        'bradlc.vscode-tailwindcss'
    )
    Python = @(
        'ms-python.python',
        'ms-python.vscode-pylance',
        'ms-python.debugpy',
        'charliermarsh.ruff'
    )
    DevOps = @(
        'ms-azuretools.vscode-docker',
        'ms-kubernetes-tools.vscode-kubernetes-tools',
        'hashicorp.terraform',
        'redhat.vscode-yaml'
    )
    FullStack = @(
        'dbaeumer.vscode-eslint',
        'ms-python.python',
        'ms-azuretools.vscode-docker',
        'eamodio.gitlens',
        'github.copilot'
    )
}
#endregion

#region Helper Functions
function Compare-SemVer {
    param(
        [string]$Version1,
        [string]$Version2
    )

    # Parse version strings
    $v1Parts = $Version1 -split '\.' | ForEach-Object { [int]$_ }
    $v2Parts = $Version2 -split '\.' | ForEach-Object { [int]$_ }

    # Pad to 3 parts
    while ($v1Parts.Count -lt 3) { $v1Parts += 0 }
    while ($v2Parts.Count -lt 3) { $v2Parts += 0 }

    for ($i = 0; $i -lt 3; $i++) {
        if ($v1Parts[$i] -gt $v2Parts[$i]) { return 1 }
        if ($v1Parts[$i] -lt $v2Parts[$i]) { return -1 }
    }

    return 0
}

function Test-ToolInstalled {
    param([string]$ToolKey)

    $tool = $script:ToolDefinitions[$ToolKey]
    $result = [PSCustomObject]@{
        Name         = $tool.Name
        Command      = $tool.Command
        Installed    = $false
        Version      = $null
        MinVersion   = $tool.MinVersion
        VersionOk    = $false
        Path         = $null
        Category     = $tool.Category
        Error        = $null
    }

    try {
        $cmd = Get-Command $tool.Command -ErrorAction SilentlyContinue
        if ($cmd) {
            $result.Installed = $true
            $result.Path = $cmd.Source

            # Get version
            $versionOutput = & $tool.Command $tool.VersionArgs.Split(' ') 2>&1

            if ($versionOutput -match $tool.VersionPattern) {
                $result.Version = $Matches[1]

                # Compare versions
                $comparison = Compare-SemVer -Version1 $result.Version -Version2 $tool.MinVersion
                $result.VersionOk = ($comparison -ge 0)
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-SSHKeyStatus {
    $sshResults = @()

    $sshDir = Join-Path $env:USERPROFILE ".ssh"

    if (-not (Test-Path $sshDir)) {
        return @([PSCustomObject]@{
            Check   = "SSH Directory"
            Status  = "FAIL"
            Details = "No .ssh directory found"
            Path    = $sshDir
        })
    }

    $sshResults += [PSCustomObject]@{
        Check   = "SSH Directory"
        Status  = "PASS"
        Details = "Directory exists"
        Path    = $sshDir
    }

    # Check for common key types
    $keyTypes = @(
        @{ Name = "id_ed25519"; Preferred = $true },
        @{ Name = "id_rsa"; Preferred = $false },
        @{ Name = "id_ecdsa"; Preferred = $false }
    )

    $foundKeys = @()
    foreach ($key in $keyTypes) {
        $keyPath = Join-Path $sshDir $key.Name
        $pubKeyPath = "$keyPath.pub"

        if (Test-Path $keyPath) {
            $foundKeys += $key.Name
            $status = if ($key.Preferred) { "PASS" } else { "WARN" }
            $details = if ($key.Preferred) { "Recommended key type" } else { "Consider upgrading to ED25519" }

            $sshResults += [PSCustomObject]@{
                Check   = "SSH Key: $($key.Name)"
                Status  = $status
                Details = $details
                Path    = $keyPath
            }

            # Check public key
            if (Test-Path $pubKeyPath) {
                $sshResults += [PSCustomObject]@{
                    Check   = "Public Key: $($key.Name).pub"
                    Status  = "PASS"
                    Details = "Public key exists"
                    Path    = $pubKeyPath
                }
            }
            else {
                $sshResults += [PSCustomObject]@{
                    Check   = "Public Key: $($key.Name).pub"
                    Status  = "WARN"
                    Details = "Public key missing"
                    Path    = $pubKeyPath
                }
            }
        }
    }

    if ($foundKeys.Count -eq 0) {
        $sshResults += [PSCustomObject]@{
            Check   = "SSH Keys"
            Status  = "FAIL"
            Details = "No SSH keys found"
            Path    = $sshDir
        }
    }

    # Check SSH config
    $configPath = Join-Path $sshDir "config"
    if (Test-Path $configPath) {
        $sshResults += [PSCustomObject]@{
            Check   = "SSH Config"
            Status  = "PASS"
            Details = "Config file exists"
            Path    = $configPath
        }
    }
    else {
        $sshResults += [PSCustomObject]@{
            Check   = "SSH Config"
            Status  = "INFO"
            Details = "No config file (optional)"
            Path    = $configPath
        }
    }

    # Check known_hosts
    $knownHosts = Join-Path $sshDir "known_hosts"
    if (Test-Path $knownHosts) {
        $hosts = (Get-Content $knownHosts | Measure-Object).Count
        $sshResults += [PSCustomObject]@{
            Check   = "Known Hosts"
            Status  = "PASS"
            Details = "$hosts host(s) saved"
            Path    = $knownHosts
        }
    }

    # Test GitHub SSH connection
    try {
        $githubTest = ssh -T git@github.com 2>&1
        if ($githubTest -match "successfully authenticated") {
            $sshResults += [PSCustomObject]@{
                Check   = "GitHub SSH"
                Status  = "PASS"
                Details = "SSH authentication working"
                Path    = "github.com"
            }
        }
        else {
            $sshResults += [PSCustomObject]@{
                Check   = "GitHub SSH"
                Status  = "WARN"
                Details = "May need to add key to GitHub"
                Path    = "github.com"
            }
        }
    }
    catch {
        $sshResults += [PSCustomObject]@{
            Check   = "GitHub SSH"
            Status  = "INFO"
            Details = "Could not test connection"
            Path    = "github.com"
        }
    }

    return $sshResults
}

function Get-VSCodeExtensions {
    $extensions = @()

    try {
        $output = code --list-extensions 2>&1
        if ($LASTEXITCODE -eq 0) {
            $extensions = $output | Where-Object { $_ -and $_.Trim() }
        }
    }
    catch { }

    return $extensions
}

function Test-VSCodeExtensions {
    param([string]$ProfileName)

    $results = @()
    $installedExtensions = Get-VSCodeExtensions
    $recommended = $script:RecommendedExtensions[$ProfileName]

    if (-not $recommended) {
        return @([PSCustomObject]@{
            Extension = "N/A"
            Status    = "INFO"
            Details   = "No recommended extensions for this profile"
        })
    }

    foreach ($ext in $recommended) {
        $isInstalled = $installedExtensions -contains $ext
        $results += [PSCustomObject]@{
            Extension = $ext
            Status    = if ($isInstalled) { "PASS" } else { "WARN" }
            Details   = if ($isInstalled) { "Installed" } else { "Not installed (recommended)" }
        }
    }

    return $results
}

function Test-PackageManagers {
    $results = @()

    # Winget
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        $results += [PSCustomObject]@{
            Manager   = "Winget"
            Status    = "PASS"
            Available = $true
            Path      = $winget.Source
        }
    }
    else {
        $results += [PSCustomObject]@{
            Manager   = "Winget"
            Status    = "WARN"
            Available = $false
            Path      = $null
        }
    }

    # Chocolatey
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) {
        $results += [PSCustomObject]@{
            Manager   = "Chocolatey"
            Status    = "PASS"
            Available = $true
            Path      = $choco.Source
        }
    }
    else {
        $results += [PSCustomObject]@{
            Manager   = "Chocolatey"
            Status    = "INFO"
            Available = $false
            Path      = $null
        }
    }

    # Scoop
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop) {
        $results += [PSCustomObject]@{
            Manager   = "Scoop"
            Status    = "PASS"
            Available = $true
            Path      = $scoop.Source
        }
    }
    else {
        $results += [PSCustomObject]@{
            Manager   = "Scoop"
            Status    = "INFO"
            Available = $false
            Path      = $null
        }
    }

    return $results
}

function Install-MissingTool {
    param(
        [string]$ToolKey,
        [PSCustomObject]$PackageManagers
    )

    $tool = $script:ToolDefinitions[$ToolKey]

    # Try Winget first
    if ($PackageManagers | Where-Object { $_.Manager -eq "Winget" -and $_.Available } ) {
        if ($tool.WingetId) {
            Write-InfoMessage "Installing $($tool.Name) via Winget..."
            try {
                winget install --id $tool.WingetId --accept-source-agreements --accept-package-agreements
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "$($tool.Name) installed via Winget"
                    return $true
                }
            }
            catch { }
        }
    }

    # Try Chocolatey
    if ($PackageManagers | Where-Object { $_.Manager -eq "Chocolatey" -and $_.Available }) {
        if ($tool.ChocoId) {
            Write-InfoMessage "Installing $($tool.Name) via Chocolatey..."
            try {
                choco install $tool.ChocoId -y
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "$($tool.Name) installed via Chocolatey"
                    return $true
                }
            }
            catch { }
        }
    }

    Write-WarningMessage "Could not automatically install $($tool.Name)"
    return $false
}

function Get-EnvironmentVariables {
    $results = @()

    # PATH check
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ }
    $results += [PSCustomObject]@{
        Variable = "PATH"
        Status   = "INFO"
        Value    = "$($pathDirs.Count) directories"
        Details  = $pathDirs.Count
    }

    # Common dev environment variables
    $devVars = @(
        @{ Name = "JAVA_HOME"; Required = $false },
        @{ Name = "GOPATH"; Required = $false },
        @{ Name = "PYTHONPATH"; Required = $false },
        @{ Name = "NODE_PATH"; Required = $false },
        @{ Name = "DOCKER_HOST"; Required = $false }
    )

    foreach ($var in $devVars) {
        $value = [Environment]::GetEnvironmentVariable($var.Name)
        if ($value) {
            $results += [PSCustomObject]@{
                Variable = $var.Name
                Status   = "PASS"
                Value    = $value
                Details  = "Set"
            }
        }
        else {
            $results += [PSCustomObject]@{
                Variable = $var.Name
                Status   = "INFO"
                Value    = "(not set)"
                Details  = "Not set (may be optional)"
            }
        }
    }

    return $results
}

function Export-HtmlReport {
    param(
        [array]$ToolResults,
        [array]$SSHResults,
        [array]$ExtensionResults,
        [array]$PackageManagers,
        [array]$EnvVars,
        [string]$ProfileName,
        [string]$OutputPath
    )

    $passCount = ($ToolResults | Where-Object { $_.VersionOk }).Count
    $failCount = ($ToolResults | Where-Object { $_.Installed -and -not $_.VersionOk }).Count
    $missingCount = ($ToolResults | Where-Object { -not $_.Installed }).Count

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Development Environment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }
        h2 {
            color: #0078d4;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        .summary-card.pass { background: linear-gradient(135deg, #107c10, #0e5a0e); }
        .summary-card.fail { background: linear-gradient(135deg, #d13438, #a80000); }
        .summary-card.warn { background: linear-gradient(135deg, #ffc107, #ff9800); color: #333; }
        .summary-card.info { background: linear-gradient(135deg, #0078d4, #005a9e); }
        .summary-card h3 {
            margin: 0;
            font-size: 2em;
        }
        .summary-card p {
            margin: 5px 0 0;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f8f8;
            font-weight: 600;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .status-pass { background: #dff6dd; color: #107c10; }
        .status-fail { background: #fde7e9; color: #d13438; }
        .status-warn { background: #fff4ce; color: #856404; }
        .status-info { background: #cce5ff; color: #004085; }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            text-align: center;
            font-size: 0.9em;
        }
        .version {
            font-family: monospace;
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Development Environment Report</h1>
        <p><strong>Profile:</strong> $ProfileName | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="summary">
            <div class="summary-card pass">
                <h3>$passCount</h3>
                <p>Passed</p>
            </div>
            <div class="summary-card fail">
                <h3>$failCount</h3>
                <p>Outdated</p>
            </div>
            <div class="summary-card warn">
                <h3>$missingCount</h3>
                <p>Missing</p>
            </div>
            <div class="summary-card info">
                <h3>$($ToolResults.Count)</h3>
                <p>Total Checked</p>
            </div>
        </div>

        <h2>Development Tools</h2>
        <table>
            <tr>
                <th>Tool</th>
                <th>Category</th>
                <th>Status</th>
                <th>Version</th>
                <th>Required</th>
            </tr>
"@

    foreach ($tool in $ToolResults) {
        $statusClass = if (-not $tool.Installed) { "status-warn" }
                       elseif ($tool.VersionOk) { "status-pass" }
                       else { "status-fail" }
        $statusText = if (-not $tool.Installed) { "Missing" }
                      elseif ($tool.VersionOk) { "OK" }
                      else { "Outdated" }

        $htmlContent += @"
            <tr>
                <td><strong>$($tool.Name)</strong></td>
                <td>$($tool.Category)</td>
                <td><span class="status-badge $statusClass">$statusText</span></td>
                <td>
                    $(if ($tool.Version) { "<span class='version'>$($tool.Version)</span> (min: $($tool.MinVersion))" } else { "-" })
                </td>
                <td>$(if ($tool.Required) { "Yes" } else { "No" })</td>
            </tr>
"@
    }

    $htmlContent += @"
        </table>
"@

    if ($SSHResults) {
        $htmlContent += @"
        <h2>SSH Configuration</h2>
        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
        foreach ($ssh in $SSHResults) {
            $statusClass = switch ($ssh.Status) {
                "PASS" { "status-pass" }
                "FAIL" { "status-fail" }
                "WARN" { "status-warn" }
                default { "status-info" }
            }
            $htmlContent += @"
            <tr>
                <td>$($ssh.Check)</td>
                <td><span class="status-badge $statusClass">$($ssh.Status)</span></td>
                <td>$($ssh.Details)</td>
            </tr>
"@
        }
        $htmlContent += "</table>"
    }

    if ($ExtensionResults) {
        $htmlContent += @"
        <h2>VS Code Extensions</h2>
        <table>
            <tr>
                <th>Extension</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
        foreach ($ext in $ExtensionResults) {
            $statusClass = switch ($ext.Status) {
                "PASS" { "status-pass" }
                "WARN" { "status-warn" }
                default { "status-info" }
            }
            $htmlContent += @"
            <tr>
                <td><code>$($ext.Extension)</code></td>
                <td><span class="status-badge $statusClass">$($ext.Status)</span></td>
                <td>$($ext.Details)</td>
            </tr>
"@
        }
        $htmlContent += "</table>"
    }

    $htmlContent += @"
        <div class="footer">
            <p>Generated by Test-DevEnvironment.ps1 v$($script:ScriptVersion)</p>
            <p>Windows & Linux Sysadmin Toolkit</p>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "Development Environment Validator v$($script:ScriptVersion)"
    Write-InfoMessage "Profile: $Profile"
    Write-Host ""

    # Determine tools to check
    $toolsToCheck = if ($Profile -eq 'Custom' -and $RequirementsFile) {
        if (Test-Path $RequirementsFile) {
            (Get-Content $RequirementsFile | ConvertFrom-Json).Tools
        }
        else {
            Write-ErrorMessage "Requirements file not found: $RequirementsFile"
            exit 1
        }
    }
    else {
        $script:Profiles[$Profile]
    }

    # Check tools
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       DEVELOPMENT TOOLS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    $toolResults = @()
    foreach ($toolKey in $toolsToCheck) {
        if ($script:ToolDefinitions.ContainsKey($toolKey)) {
            $result = Test-ToolInstalled -ToolKey $toolKey
            $toolResults += $result

            $statusIcon = if (-not $result.Installed) { "[-]" }
                          elseif ($result.VersionOk) { "[+]" }
                          else { "[!]" }
            $statusColor = if (-not $result.Installed) { "Red" }
                           elseif ($result.VersionOk) { "Green" }
                           else { "Yellow" }

            Write-Host "$statusIcon $($result.Name): " -NoNewline -ForegroundColor $statusColor
            if ($result.Installed) {
                Write-Host "$($result.Version) " -NoNewline -ForegroundColor White
                if ($result.VersionOk) {
                    Write-Host "(OK)" -ForegroundColor Green
                }
                else {
                    Write-Host "(needs $($result.MinVersion)+)" -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "Not installed" -ForegroundColor Red
            }
        }
    }

    # Auto-install missing tools if requested
    if ($AutoInstall) {
        $packageManagers = Test-PackageManagers
        $missingTools = $toolResults | Where-Object { -not $_.Installed }

        if ($missingTools.Count -gt 0) {
            Write-Host ""
            Write-Host "======================================" -ForegroundColor Cyan
            Write-Host "       AUTO-INSTALLING TOOLS" -ForegroundColor Cyan
            Write-Host "======================================" -ForegroundColor Cyan

            foreach ($tool in $missingTools) {
                $toolKey = $toolsToCheck | Where-Object { $script:ToolDefinitions[$_].Name -eq $tool.Name }
                if ($toolKey) {
                    Install-MissingTool -ToolKey $toolKey -PackageManagers $packageManagers
                }
            }
        }
    }

    # Check SSH
    $sshResults = @()
    if ($CheckSSH) {
        Write-Host ""
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "       SSH CONFIGURATION" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host ""

        $sshResults = Get-SSHKeyStatus
        foreach ($ssh in $sshResults) {
            $icon = switch ($ssh.Status) {
                "PASS" { "[+]" }
                "FAIL" { "[-]" }
                "WARN" { "[!]" }
                default { "[i]" }
            }
            $color = switch ($ssh.Status) {
                "PASS" { "Green" }
                "FAIL" { "Red" }
                "WARN" { "Yellow" }
                default { "Blue" }
            }
            Write-Host "$icon $($ssh.Check): $($ssh.Details)" -ForegroundColor $color
        }
    }

    # Check VS Code extensions
    $extensionResults = @()
    if ($CheckExtensions) {
        Write-Host ""
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "       VS CODE EXTENSIONS" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host ""

        $extensionResults = Test-VSCodeExtensions -ProfileName $Profile
        foreach ($ext in $extensionResults) {
            $icon = if ($ext.Status -eq "PASS") { "[+]" } else { "[!]" }
            $color = if ($ext.Status -eq "PASS") { "Green" } else { "Yellow" }
            Write-Host "$icon $($ext.Extension): $($ext.Details)" -ForegroundColor $color
        }
    }

    # Check package managers
    $packageManagers = Test-PackageManagers
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       PACKAGE MANAGERS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($pm in $packageManagers) {
        $icon = if ($pm.Available) { "[+]" } else { "[i]" }
        $color = if ($pm.Available) { "Green" } else { "Gray" }
        Write-Host "$icon $($pm.Manager): $(if ($pm.Available) { 'Available' } else { 'Not installed' })" -ForegroundColor $color
    }

    # Environment variables
    $envVars = Get-EnvironmentVariables

    # Summary
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       SUMMARY" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    $passCount = ($toolResults | Where-Object { $_.Installed -and $_.VersionOk }).Count
    $outdatedCount = ($toolResults | Where-Object { $_.Installed -and -not $_.VersionOk }).Count
    $missingCount = ($toolResults | Where-Object { -not $_.Installed }).Count

    Write-Host "Tools OK:       $passCount" -ForegroundColor Green
    Write-Host "Tools Outdated: $outdatedCount" -ForegroundColor Yellow
    Write-Host "Tools Missing:  $missingCount" -ForegroundColor Red

    # Overall status
    $overallStatus = if ($missingCount -gt 0 -or $outdatedCount -gt 0) {
        "NEEDS ATTENTION"
    }
    else {
        "READY FOR DEVELOPMENT"
    }

    Write-Host ""
    Write-Host "Overall: " -NoNewline
    if ($overallStatus -eq "READY FOR DEVELOPMENT") {
        Write-Host $overallStatus -ForegroundColor Green
    }
    else {
        Write-Host $overallStatus -ForegroundColor Yellow
    }

    # Output report
    if ($OutputFormat -ne 'Console') {
        $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

        switch ($OutputFormat) {
            'HTML' {
                $reportPath = Join-Path $outputDir "devenv_report_$timestamp.html"
                Export-HtmlReport -ToolResults $toolResults -SSHResults $sshResults -ExtensionResults $extensionResults -PackageManagers $packageManagers -EnvVars $envVars -ProfileName $Profile -OutputPath $reportPath
                Write-Success "HTML report saved to: $reportPath"
            }
            'JSON' {
                $reportPath = Join-Path $outputDir "devenv_report_$timestamp.json"
                $report = @{
                    Timestamp       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    Profile         = $Profile
                    Tools           = $toolResults
                    SSH             = $sshResults
                    Extensions      = $extensionResults
                    PackageManagers = $packageManagers
                    EnvVars         = $envVars
                    Summary         = @{
                        PassCount     = $passCount
                        OutdatedCount = $outdatedCount
                        MissingCount  = $missingCount
                        OverallStatus = $overallStatus
                    }
                }
                $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
                Write-Success "JSON report saved to: $reportPath"
            }
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    Write-InfoMessage "Completed in $($duration.TotalSeconds.ToString('F1')) seconds"

    # Exit code
    $exitCode = if ($missingCount -gt 0) { 2 }
                elseif ($outdatedCount -gt 0) { 1 }
                else { 0 }

    exit $exitCode
}

# Run main function
Main
#endregion
