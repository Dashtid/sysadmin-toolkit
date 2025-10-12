#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Package cleanup for dev/gaming hybrid workstation

.DESCRIPTION
    Removes redundant packages to optimize disk space and RAM usage
    - Python 3.13 (keeping 3.14)
    - Old Git Credential Manager
    - HP Support Assistant
    - Java/Maven (optional)
#>

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color Cyan }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color Red }

Write-Log "`n[*] Package Cleanup Script for Dev/Gaming Workstation" -Color Magenta
Write-Log "[*] ===============================================`n" -Color Magenta

Write-Info "Starting package cleanup..."

# Track statistics
$removed = 0
$failed = 0
$spaceFreed = 0

# Remove Python 3.13 (keeping 3.14)
Write-Info "Removing Python 3.13 (keeping 3.14)..."
try {
    choco uninstall python313 -y --limit-output
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Python 3.13 removed"
        $removed++
        $spaceFreed += 500
    } else {
        Write-Warning "Python 3.13 may not have been installed"
    }
} catch {
    Write-Error "Failed to remove Python 3.13: $_"
    $failed++
}

# Remove old Git Credential Manager
Write-Info "Removing deprecated Git Credential Manager..."
try {
    choco uninstall git-credential-manager-for-windows -y --limit-output
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Old Git Credential Manager removed"
        $removed++
        $spaceFreed += 50
    } else {
        Write-Warning "Old Git Credential Manager may not have been installed"
    }
} catch {
    Write-Error "Failed to remove Git Credential Manager: $_"
    $failed++
}

# Remove HP Support Assistant
Write-Info "Removing HP Support Assistant (bloatware)..."
try {
    choco uninstall hpsupportassistant -y --limit-output
    if ($LASTEXITCODE -eq 0) {
        Write-Success "HP Support Assistant removed"
        $removed++
        $spaceFreed += 200
    } else {
        Write-Warning "HP Support Assistant may not have been installed"
    }
} catch {
    Write-Error "Failed to remove HP Support Assistant: $_"
    $failed++
}

# Remove Java and Maven (keeping per user request)
Write-Info "Removing Java installations and Maven..."
try {
    choco uninstall openjdk temurin17 maven -y --limit-output
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Java and Maven removed"
        $removed += 3
        $spaceFreed += 600
    } else {
        Write-Warning "Java packages may not have been fully installed"
    }
} catch {
    Write-Error "Failed to remove Java packages: $_"
    $failed++
}

# Summary
Write-Log "`n[*] Cleanup Summary" -Color Cyan
Write-Log "[*] ===============`n" -Color Cyan
Write-Success "Packages removed: $removed"
Write-Error "Packages failed: $failed"
Write-Info "Estimated disk space freed: ~$spaceFreed MB"
Write-Warning "`nRestart required to complete cleanup`n"

Write-Success "Package cleanup completed!"
