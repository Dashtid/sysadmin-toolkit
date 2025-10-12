# Export Current Package Installations
# This script exports your currently installed packages for backup and automation
# Run this periodically to keep your package lists up to date

#Requires -Version 7.0

param(
    [string]$OutputDir = "$PSScriptRoot"
)

# Colors for output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
}

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor $Colors.Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor $Colors.Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor $Colors.Red }

Write-Info "Exporting current package installations..."
Write-Info "Output directory: $OutputDir"

# Create output directory if it doesn't exist
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Export Winget packages
Write-Info "Exporting Winget packages..."
try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $WingetFile = Join-Path $OutputDir "winget-packages.json"
        winget export -o $WingetFile --accept-source-agreements

        if (Test-Path $WingetFile) {
            $WingetCount = (Get-Content $WingetFile | ConvertFrom-Json).Sources.Packages.Count
            Write-Success "Exported $WingetCount Winget packages to: $WingetFile"
        }
    }
    else {
        Write-Warning "Winget not found. Skipping Winget export."
        Write-Info "Install Winget: https://aka.ms/getwinget"
    }
}
catch {
    Write-Error "Failed to export Winget packages: $($_.Exception.Message)"
}

# Export Chocolatey packages
Write-Info "Exporting Chocolatey packages..."
try {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $ChocoFile = Join-Path $OutputDir "chocolatey-packages.config"
        choco export $ChocoFile

        if (Test-Path $ChocoFile) {
            $ChocoPackages = ([xml](Get-Content $ChocoFile)).packages.package
            $ChocoCount = $ChocoPackages.Count
            Write-Success "Exported $ChocoCount Chocolatey packages to: $ChocoFile"

            # Also create a simple text list for reference
            $ChocoListFile = Join-Path $OutputDir "chocolatey-packages.txt"
            $ChocoPackages | ForEach-Object { "$($_.id) $($_.version)" } | Out-File $ChocoListFile -Encoding UTF8
            Write-Success "Package list saved to: $ChocoListFile"
        }
    }
    else {
        Write-Warning "Chocolatey not found. Skipping Chocolatey export."
        Write-Info "Install Chocolatey: https://chocolatey.org/install"
    }
}
catch {
    Write-Error "Failed to export Chocolatey packages: $($_.Exception.Message)"
}

# Export manually installed programs list for reference
Write-Info "Creating list of installed programs for reference..."
try {
    $ProgramsFile = Join-Path $OutputDir "installed-programs.txt"

    # Get installed programs from registry
    $Programs = @()
    $Programs += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher

    $Programs += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher

    $Programs | Sort-Object DisplayName -Unique |
        Format-Table -AutoSize |
        Out-File $ProgramsFile -Encoding UTF8 -Width 200

    Write-Success "Installed programs list saved to: $ProgramsFile"
}
catch {
    Write-Warning "Failed to create installed programs list: $($_.Exception.Message)"
}

# Create a timestamp file
$TimestampFile = Join-Path $OutputDir "last-export.txt"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"Last export: $Timestamp" | Out-File $TimestampFile -Encoding UTF8
Write-Success "Export timestamp saved to: $TimestampFile"

Write-Success "Package export completed!"
Write-Info "Files created in: $OutputDir"
Write-Info ""
Write-Info "Next steps:"
Write-Info "  1. Review the exported package lists"
Write-Info "  2. Run install-from-exported-packages.ps1 on a new machine to restore these packages"
Write-Info "  3. Re-run this export script whenever you install new software"
