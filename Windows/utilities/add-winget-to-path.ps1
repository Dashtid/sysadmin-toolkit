# Add Winget to PATH
# This script finds winget.exe and adds its directory to the system PATH
# Run as Administrator

#Requires -RunAsAdministrator

param(
    [switch]$UserPath  # Add to user PATH instead of system PATH
)

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

Write-Info "Searching for winget.exe..."

# Common winget locations
$PossiblePaths = @(
    "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller*\winget.exe",
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WindowsApps\winget.exe"
)

$WingetPath = $null

foreach ($Pattern in $PossiblePaths) {
    Write-Info "Checking: $Pattern"
    $Found = Get-ChildItem -Path (Split-Path $Pattern -Parent) -Filter (Split-Path $Pattern -Leaf) -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($Found) {
        $WingetPath = $Found.FullName
        Write-Success "Found winget at: $WingetPath"
        break
    }
}

if (-not $WingetPath) {
    # Try a more thorough search
    Write-Info "Performing thorough search in WindowsApps..."
    $WingetPath = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Recurse -Filter "winget.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}

if (-not $WingetPath) {
    Write-Error "Could not find winget.exe on this system"
    Write-Info "Install Winget from: https://aka.ms/getwinget"
    exit 1
}

$WingetDir = Split-Path $WingetPath -Parent
Write-Success "Winget directory: $WingetDir"

# Determine which PATH to modify
$PathType = if ($UserPath) { "User" } else { "Machine" }
Write-Info "Adding to $PathType PATH..."

# Get current PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", $PathType)

# Check if already in PATH
if ($CurrentPath -split ';' | Where-Object { $_ -eq $WingetDir }) {
    Write-Success "Winget directory is already in the $PathType PATH"
    exit 0
}

# Add to PATH
$NewPath = "$CurrentPath;$WingetDir"
[Environment]::SetEnvironmentVariable("Path", $NewPath, $PathType)

Write-Success "Added winget to $PathType PATH"
Write-Info "New PATH component: $WingetDir"
Write-Warning "You may need to restart your terminal or IDE for the change to take effect"

# Verify
Write-Info "Verifying installation..."
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Success "Winget is now accessible from PowerShell"
    winget --version
}
else {
    Write-Warning "Winget not immediately accessible. Please restart your terminal."
}
