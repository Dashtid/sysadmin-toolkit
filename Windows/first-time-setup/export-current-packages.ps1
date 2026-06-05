# Export Current Package Installations
# This script exports your currently installed packages for backup and automation
# Run this periodically to keep your package lists up to date

#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$OutputDir = "$PSScriptRoot"
)

# Shared logging via CommonFunctions (Write-InfoMessage, Write-Success, Write-WarningMessage, Write-ErrorMessage)
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\lib\CommonFunctions.psm1') -Force

function Export-WingetPackage {
    [CmdletBinding()]
    param([string]$Destination)

    Write-InfoMessage "Exporting Winget packages..."
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $WingetFile = Join-Path $Destination "winget-packages.json"
            winget export -o $WingetFile --accept-source-agreements

            if (Test-Path $WingetFile) {
                $WingetCount = (Get-Content $WingetFile | ConvertFrom-Json).Sources.Packages.Count
                Write-Success "Exported $WingetCount Winget packages to: $WingetFile"
            }
        }
        else {
            Write-WarningMessage "Winget not found. Skipping Winget export."
            Write-InfoMessage "Install Winget: https://aka.ms/getwinget"
        }
    }
    catch {
        Write-ErrorMessage "Failed to export Winget packages: $($_.Exception.Message)"
    }
}

function Export-ChocolateyPackage {
    [CmdletBinding()]
    param([string]$Destination)

    Write-InfoMessage "Exporting Chocolatey packages..."
    try {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            $ChocoFile = Join-Path $Destination "chocolatey-packages.config"
            choco export $ChocoFile

            if (Test-Path $ChocoFile) {
                $ChocoPackages = ([xml](Get-Content $ChocoFile)).packages.package
                $ChocoCount = $ChocoPackages.Count
                Write-Success "Exported $ChocoCount Chocolatey packages to: $ChocoFile"

                # Also create a simple text list for reference
                $ChocoListFile = Join-Path $Destination "chocolatey-packages.txt"
                $ChocoPackages | ForEach-Object { "$($_.id) $($_.version)" } | Out-File $ChocoListFile -Encoding UTF8
                Write-Success "Package list saved to: $ChocoListFile"
            }
        }
        else {
            Write-WarningMessage "Chocolatey not found. Skipping Chocolatey export."
            Write-InfoMessage "Install Chocolatey: https://chocolatey.org/install"
        }
    }
    catch {
        Write-ErrorMessage "Failed to export Chocolatey packages: $($_.Exception.Message)"
    }
}

function Export-InstalledProgram {
    [CmdletBinding()]
    param([string]$Destination)

    Write-InfoMessage "Creating list of installed programs for reference..."
    try {
        $ProgramsFile = Join-Path $Destination "installed-programs.txt"

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
        Write-WarningMessage "Failed to create installed programs list: $($_.Exception.Message)"
    }
}

function Write-ExportTimestamp {
    [CmdletBinding()]
    param([string]$Destination)

    $TimestampFile = Join-Path $Destination "last-export.txt"
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "Last export: $Timestamp" | Out-File $TimestampFile -Encoding UTF8
    Write-Success "Export timestamp saved to: $TimestampFile"
}

function Main {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    Write-InfoMessage "Exporting current package installations..."
    Write-InfoMessage "Output directory: $Destination"

    # Create output directory if it doesn't exist
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    Export-WingetPackage -Destination $Destination
    Export-ChocolateyPackage -Destination $Destination
    Export-InstalledProgram -Destination $Destination
    Write-ExportTimestamp -Destination $Destination

    Write-Success "Package export completed!"
    Write-InfoMessage "Files created in: $Destination"
    Write-InfoMessage ""
    Write-InfoMessage "Next steps:"
    Write-InfoMessage "  1. Review the exported package lists"
    Write-InfoMessage "  2. Run install-from-exported-packages.ps1 on a new machine to restore these packages"
    Write-InfoMessage "  3. Re-run this export script whenever you install new software"
}

# Run Main when invoked as a script. When dot-sourced for testing, skip auto-run
# so test files can load function definitions into scope and exercise them with mocks.
if ($MyInvocation.InvocationName -ne '.') {
    Main -Destination $OutputDir
}
