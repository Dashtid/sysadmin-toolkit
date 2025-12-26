#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Compares software inventory between machines or snapshots to detect package drift.

.DESCRIPTION
    This script compares software inventory from Winget and Chocolatey exports
    to identify:
    - Packages added on the current system
    - Packages removed from the current system
    - Version changes between systems
    - Packages that are identical

    Use cases:
    - Compare your current machine against a baseline export
    - Compare two different machine exports
    - Detect configuration drift over time
    - Generate install scripts for missing packages

.PARAMETER BaselineFile
    Path to the baseline inventory JSON file (from winget export or export-current-packages.ps1).

.PARAMETER CurrentFile
    Path to the current inventory JSON file to compare against baseline.
    Use 'Live' or omit to compare against the live system.

.PARAMETER CompareToLive
    Compare the baseline file against the current live system.

.PARAMETER Sources
    Package sources to compare. Valid values: Winget, Chocolatey, Registry, All.
    Default: All

.PARAMETER OutputFormat
    Output format for reports. Valid values: Console, HTML, JSON, All.
    Default: Console

.PARAMETER OutputPath
    Directory for report output files.

.PARAMETER IncludeVersions
    Include version comparison details in the output.

.PARAMETER ExportMissing
    Export list of missing packages as an install script.

.EXAMPLE
    .\Compare-SoftwareInventory.ps1 -BaselineFile "D:\Backups\winget-packages.json" -CompareToLive
    Compare baseline export against current live system.

.EXAMPLE
    .\Compare-SoftwareInventory.ps1 -BaselineFile "machine-a.json" -CurrentFile "machine-b.json"
    Compare two different machine exports.

.EXAMPLE
    .\Compare-SoftwareInventory.ps1 -BaselineFile "baseline.json" -CompareToLive -ExportMissing
    Compare and generate install script for missing packages.

.NOTES
    File Name      : Compare-SoftwareInventory.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+
    Version        : 1.0.0

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BaselineFile,

    [Parameter(ParameterSetName = 'Files')]
    [string]$CurrentFile,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$CompareToLive,

    [ValidateSet('Winget', 'Chocolatey', 'Registry', 'All')]
    [string[]]$Sources = @('All'),

    [ValidateSet('Console', 'HTML', 'JSON', 'All')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath,

    [switch]$IncludeVersions,

    [switch]$ExportMissing
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"
#endregion

#region Helper Functions

function Import-WingetInventory {
    <#
    .SYNOPSIS
        Imports packages from a Winget export JSON file.
    #>
    param([string]$FilePath)

    try {
        $content = Get-Content $FilePath -Raw | ConvertFrom-Json

        $packages = @()
        if ($content.Sources) {
            foreach ($source in $content.Sources) {
                foreach ($pkg in $source.Packages) {
                    $packages += [PSCustomObject]@{
                        Name    = $pkg.PackageIdentifier
                        Version = $pkg.Version
                        Source  = 'Winget'
                    }
                }
            }
        }

        return $packages
    }
    catch {
        Write-WarningMessage "Could not parse Winget file: $($_.Exception.Message)"
        return @()
    }
}

function Import-ChocolateyInventory {
    <#
    .SYNOPSIS
        Imports packages from a Chocolatey config XML file.
    #>
    param([string]$FilePath)

    try {
        $xml = [xml](Get-Content $FilePath)

        $packages = @()
        foreach ($pkg in $xml.packages.package) {
            $packages += [PSCustomObject]@{
                Name    = $pkg.id
                Version = $pkg.version
                Source  = 'Chocolatey'
            }
        }

        return $packages
    }
    catch {
        Write-WarningMessage "Could not parse Chocolatey file: $($_.Exception.Message)"
        return @()
    }
}

function Get-LiveWingetInventory {
    <#
    .SYNOPSIS
        Gets current Winget packages from the live system.
    #>

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-WarningMessage "Winget not found on system"
        return @()
    }

    try {
        # Export to temp file and read
        $tempFile = Join-Path $env:TEMP "winget_live_$(Get-Date -Format 'yyyyMMddHHmmss').json"
        winget export -o $tempFile --accept-source-agreements 2>&1 | Out-Null

        if (Test-Path $tempFile) {
            $packages = Import-WingetInventory -FilePath $tempFile
            Remove-Item $tempFile -Force
            return $packages
        }
    }
    catch {
        Write-WarningMessage "Could not get Winget packages: $($_.Exception.Message)"
    }

    return @()
}

function Get-LiveChocolateyInventory {
    <#
    .SYNOPSIS
        Gets current Chocolatey packages from the live system.
    #>

    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-WarningMessage "Chocolatey not found on system"
        return @()
    }

    try {
        $output = choco list --local-only --limit-output 2>&1
        $packages = @()

        foreach ($line in $output) {
            if ($line -match '^([^|]+)\|(.+)$') {
                $packages += [PSCustomObject]@{
                    Name    = $Matches[1]
                    Version = $Matches[2]
                    Source  = 'Chocolatey'
                }
            }
        }

        return $packages
    }
    catch {
        Write-WarningMessage "Could not get Chocolatey packages: $($_.Exception.Message)"
        return @()
    }
}

function Import-Inventory {
    <#
    .SYNOPSIS
        Imports inventory from file or live system.
    #>
    param(
        [string]$FilePath,
        [bool]$IsLive,
        [string[]]$Sources
    )

    $inventory = @{
        Winget     = @()
        Chocolatey = @()
        Source     = if ($IsLive) { "Live System ($env:COMPUTERNAME)" } else { $FilePath }
    }

    $allSources = $Sources -contains 'All'

    if ($IsLive) {
        Write-InfoMessage "Collecting live system inventory..."

        if ($allSources -or $Sources -contains 'Winget') {
            $inventory.Winget = Get-LiveWingetInventory
            Write-InfoMessage "  Found $($inventory.Winget.Count) Winget packages"
        }

        if ($allSources -or $Sources -contains 'Chocolatey') {
            $inventory.Chocolatey = Get-LiveChocolateyInventory
            Write-InfoMessage "  Found $($inventory.Chocolatey.Count) Chocolatey packages"
        }
    }
    else {
        Write-InfoMessage "Loading inventory from: $FilePath"

        # Detect file type and load appropriately
        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        $fileName = [System.IO.Path]::GetFileName($FilePath).ToLower()

        if ($extension -eq '.json' -or $fileName -like '*winget*') {
            if ($allSources -or $Sources -contains 'Winget') {
                $inventory.Winget = Import-WingetInventory -FilePath $FilePath
                Write-InfoMessage "  Loaded $($inventory.Winget.Count) Winget packages"
            }
        }

        if ($extension -eq '.config' -or $fileName -like '*chocolatey*' -or $extension -eq '.xml') {
            if ($allSources -or $Sources -contains 'Chocolatey') {
                $inventory.Chocolatey = Import-ChocolateyInventory -FilePath $FilePath
                Write-InfoMessage "  Loaded $($inventory.Chocolatey.Count) Chocolatey packages"
            }
        }

        # If it's a directory, look for both files
        if (Test-Path $FilePath -PathType Container) {
            $wingetFile = Join-Path $FilePath "winget-packages.json"
            $chocoFile = Join-Path $FilePath "chocolatey-packages.config"

            if ((Test-Path $wingetFile) -and ($allSources -or $Sources -contains 'Winget')) {
                $inventory.Winget = Import-WingetInventory -FilePath $wingetFile
                Write-InfoMessage "  Loaded $($inventory.Winget.Count) Winget packages"
            }

            if ((Test-Path $chocoFile) -and ($allSources -or $Sources -contains 'Chocolatey')) {
                $inventory.Chocolatey = Import-ChocolateyInventory -FilePath $chocoFile
                Write-InfoMessage "  Loaded $($inventory.Chocolatey.Count) Chocolatey packages"
            }
        }
    }

    return $inventory
}

function Compare-PackageLists {
    <#
    .SYNOPSIS
        Compares two package lists and returns differences.
    #>
    param(
        [array]$BaselinePackages,
        [array]$CurrentPackages,
        [string]$Source
    )

    $comparison = @{
        Added          = @()
        Removed        = @()
        VersionChanged = @()
        Identical      = @()
    }

    # Create lookup hashtables
    $baselineHash = @{}
    foreach ($pkg in $BaselinePackages) {
        $baselineHash[$pkg.Name] = $pkg
    }

    $currentHash = @{}
    foreach ($pkg in $CurrentPackages) {
        $currentHash[$pkg.Name] = $pkg
    }

    # Find added (in current but not baseline)
    foreach ($pkg in $CurrentPackages) {
        if (-not $baselineHash.ContainsKey($pkg.Name)) {
            $comparison.Added += [PSCustomObject]@{
                Name    = $pkg.Name
                Version = $pkg.Version
                Source  = $Source
            }
        }
    }

    # Find removed (in baseline but not current) and version changes
    foreach ($pkg in $BaselinePackages) {
        if (-not $currentHash.ContainsKey($pkg.Name)) {
            $comparison.Removed += [PSCustomObject]@{
                Name    = $pkg.Name
                Version = $pkg.Version
                Source  = $Source
            }
        }
        else {
            $currentPkg = $currentHash[$pkg.Name]
            if ($pkg.Version -ne $currentPkg.Version) {
                $comparison.VersionChanged += [PSCustomObject]@{
                    Name            = $pkg.Name
                    BaselineVersion = $pkg.Version
                    CurrentVersion  = $currentPkg.Version
                    Source          = $Source
                }
            }
            else {
                $comparison.Identical += [PSCustomObject]@{
                    Name    = $pkg.Name
                    Version = $pkg.Version
                    Source  = $Source
                }
            }
        }
    }

    return $comparison
}

function Export-MissingPackagesScript {
    <#
    .SYNOPSIS
        Exports a script to install missing packages.
    #>
    param(
        [array]$Removed,
        [string]$OutputPath
    )

    if (-not $OutputPath) {
        $OutputPath = $PSScriptRoot
    }

    $scriptPath = Join-Path $OutputPath "install-missing-packages_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"

    $script = @"
# Install Missing Packages Script
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Packages to install: $($Removed.Count)

#Requires -Version 5.1

Write-Host "[i] Installing missing packages..." -ForegroundColor Blue

"@

    # Group by source
    $wingetPackages = $Removed | Where-Object { $_.Source -eq 'Winget' }
    $chocoPackages = $Removed | Where-Object { $_.Source -eq 'Chocolatey' }

    if ($wingetPackages.Count -gt 0) {
        $script += @"

# Winget Packages ($($wingetPackages.Count))
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "[i] Installing Winget packages..." -ForegroundColor Blue

"@
        foreach ($pkg in $wingetPackages) {
            $script += "    winget install --id `"$($pkg.Name)`" --accept-package-agreements --accept-source-agreements`n"
        }
        $script += @"
}
else {
    Write-Host "[!] Winget not found, skipping Winget packages" -ForegroundColor Yellow
}

"@
    }

    if ($chocoPackages.Count -gt 0) {
        $script += @"

# Chocolatey Packages ($($chocoPackages.Count))
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "[i] Installing Chocolatey packages..." -ForegroundColor Blue

"@
        foreach ($pkg in $chocoPackages) {
            $script += "    choco install $($pkg.Name) -y`n"
        }
        $script += @"
}
else {
    Write-Host "[!] Chocolatey not found, skipping Chocolatey packages" -ForegroundColor Yellow
}

"@
    }

    $script += @"

Write-Host "[+] Installation complete!" -ForegroundColor Green
"@

    $script | Out-File -FilePath $scriptPath -Encoding UTF8
    Write-Success "Install script saved: $scriptPath"
    return $scriptPath
}

function Write-ConsoleReport {
    <#
    .SYNOPSIS
        Displays comparison results to console.
    #>
    param([hashtable]$Results)

    $separator = "=" * 64

    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "  SOFTWARE INVENTORY COMPARISON" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor Cyan

    Write-Host ""
    Write-Host "Baseline: " -NoNewline
    Write-Host $Results.BaselineSource -ForegroundColor White
    Write-Host "Current:  " -NoNewline
    Write-Host $Results.CurrentSource -ForegroundColor White

    Write-Host ""
    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Baseline packages: $($Results.Summary.TotalBaseline)"
    Write-Host "  Current packages:  $($Results.Summary.TotalCurrent)"
    Write-Host ""

    # Added packages
    if ($Results.Added.Count -gt 0) {
        Write-Host "[+] ADDED ($($Results.Added.Count) packages)" -ForegroundColor Green
        foreach ($pkg in $Results.Added | Sort-Object Name) {
            $versionInfo = if ($IncludeVersions -and $pkg.Version) { " v$($pkg.Version)" } else { "" }
            Write-Host "    $($pkg.Name)$versionInfo" -ForegroundColor Green -NoNewline
            Write-Host " ($($pkg.Source))" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # Removed packages
    if ($Results.Removed.Count -gt 0) {
        Write-Host "[-] REMOVED ($($Results.Removed.Count) packages)" -ForegroundColor Red
        foreach ($pkg in $Results.Removed | Sort-Object Name) {
            $versionInfo = if ($IncludeVersions -and $pkg.Version) { " v$($pkg.Version)" } else { "" }
            Write-Host "    $($pkg.Name)$versionInfo" -ForegroundColor Red -NoNewline
            Write-Host " ($($pkg.Source))" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # Version changes
    if ($Results.VersionChanged.Count -gt 0) {
        Write-Host "[!] VERSION CHANGED ($($Results.VersionChanged.Count) packages)" -ForegroundColor Yellow
        foreach ($pkg in $Results.VersionChanged | Sort-Object Name) {
            Write-Host "    $($pkg.Name)" -ForegroundColor Yellow -NoNewline
            Write-Host " $($pkg.BaselineVersion) -> $($pkg.CurrentVersion)" -ForegroundColor Gray -NoNewline
            Write-Host " ($($pkg.Source))" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Summary line
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "Summary: " -NoNewline
    Write-Host "+$($Results.Added.Count) added" -ForegroundColor Green -NoNewline
    Write-Host ", " -NoNewline
    Write-Host "-$($Results.Removed.Count) removed" -ForegroundColor Red -NoNewline
    Write-Host ", " -NoNewline
    Write-Host "~$($Results.VersionChanged.Count) updated" -ForegroundColor Yellow -NoNewline
    Write-Host ", " -NoNewline
    Write-Host "=$($Results.Identical.Count) identical" -ForegroundColor Gray
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates an HTML comparison report.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    if (-not $OutputPath) { $OutputPath = $PSScriptRoot }

    $htmlPath = Join-Path $OutputPath "inventory-comparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Software Inventory Comparison</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .added { color: #107c10; background: #dff6dd; }
        .removed { color: #d13438; background: #fde7e9; }
        .changed { color: #ff8c00; background: #fff4ce; }
        .stats { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .stat-box { flex: 1; min-width: 120px; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-box.added { background: #dff6dd; }
        .stat-box.removed { background: #fde7e9; }
        .stat-box.changed { background: #fff4ce; }
        .stat-box.identical { background: #f0f0f0; }
        .stat-value { font-size: 28px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .source { color: #666; font-size: 0.9em; }
        .section { margin: 25px 0; }
        h2 { margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Software Inventory Comparison</h1>
        <p><strong>Baseline:</strong> $($Results.BaselineSource)</p>
        <p><strong>Current:</strong> $($Results.CurrentSource)</p>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="stats">
            <div class="stat-box added">
                <div class="stat-value">+$($Results.Added.Count)</div>
                <div>Added</div>
            </div>
            <div class="stat-box removed">
                <div class="stat-value">-$($Results.Removed.Count)</div>
                <div>Removed</div>
            </div>
            <div class="stat-box changed">
                <div class="stat-value">~$($Results.VersionChanged.Count)</div>
                <div>Updated</div>
            </div>
            <div class="stat-box identical">
                <div class="stat-value">=$($Results.Identical.Count)</div>
                <div>Identical</div>
            </div>
        </div>

        $(if ($Results.Added.Count -gt 0) {
            "<div class='section'><h2 class='added'>Added Packages ($($Results.Added.Count))</h2><table><tr><th>Package</th><th>Version</th><th>Source</th></tr>" +
            ($Results.Added | Sort-Object Name | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Version)</td><td class='source'>$($_.Source)</td></tr>" }) +
            "</table></div>"
        })

        $(if ($Results.Removed.Count -gt 0) {
            "<div class='section'><h2 class='removed'>Removed Packages ($($Results.Removed.Count))</h2><table><tr><th>Package</th><th>Version</th><th>Source</th></tr>" +
            ($Results.Removed | Sort-Object Name | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Version)</td><td class='source'>$($_.Source)</td></tr>" }) +
            "</table></div>"
        })

        $(if ($Results.VersionChanged.Count -gt 0) {
            "<div class='section'><h2 class='changed'>Version Changes ($($Results.VersionChanged.Count))</h2><table><tr><th>Package</th><th>Baseline</th><th>Current</th><th>Source</th></tr>" +
            ($Results.VersionChanged | Sort-Object Name | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.BaselineVersion)</td><td>$($_.CurrentVersion)</td><td class='source'>$($_.Source)</td></tr>" }) +
            "</table></div>"
        })
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Success "HTML report saved: $htmlPath"
}

function Export-JSONReport {
    <#
    .SYNOPSIS
        Generates a JSON comparison report.
    #>
    param(
        [string]$OutputPath,
        [hashtable]$Results
    )

    if (-not $OutputPath) { $OutputPath = $PSScriptRoot }

    $jsonPath = Join-Path $OutputPath "inventory-comparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    $report = @{
        CompareDate    = Get-Date -Format "o"
        BaselineSource = $Results.BaselineSource
        CurrentSource  = $Results.CurrentSource
        Summary        = $Results.Summary
        Added          = $Results.Added
        Removed        = $Results.Removed
        VersionChanged = $Results.VersionChanged
        Identical      = if ($IncludeVersions) { $Results.Identical } else { @() }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Success "JSON report saved: $jsonPath"
}
#endregion

#region Main Execution
try {
    Write-Host ""
    Write-InfoMessage "========================================"
    Write-InfoMessage "  Software Inventory Comparison v$script:ScriptVersion"
    Write-InfoMessage "========================================"

    # Determine if comparing to live system
    $compareLive = $CompareToLive.IsPresent -or (-not $CurrentFile)

    # Load baseline inventory
    $baseline = Import-Inventory -FilePath $BaselineFile -IsLive $false -Sources $Sources

    # Load current inventory
    if ($compareLive) {
        $current = Import-Inventory -FilePath $null -IsLive $true -Sources $Sources
    }
    else {
        $current = Import-Inventory -FilePath $CurrentFile -IsLive $false -Sources $Sources
    }

    # Perform comparisons
    Write-InfoMessage "Comparing inventories..."

    $allAdded = @()
    $allRemoved = @()
    $allVersionChanged = @()
    $allIdentical = @()

    # Compare Winget packages
    if ($baseline.Winget.Count -gt 0 -or $current.Winget.Count -gt 0) {
        $wingetComparison = Compare-PackageLists -BaselinePackages $baseline.Winget -CurrentPackages $current.Winget -Source 'Winget'
        $allAdded += $wingetComparison.Added
        $allRemoved += $wingetComparison.Removed
        $allVersionChanged += $wingetComparison.VersionChanged
        $allIdentical += $wingetComparison.Identical
    }

    # Compare Chocolatey packages
    if ($baseline.Chocolatey.Count -gt 0 -or $current.Chocolatey.Count -gt 0) {
        $chocoComparison = Compare-PackageLists -BaselinePackages $baseline.Chocolatey -CurrentPackages $current.Chocolatey -Source 'Chocolatey'
        $allAdded += $chocoComparison.Added
        $allRemoved += $chocoComparison.Removed
        $allVersionChanged += $chocoComparison.VersionChanged
        $allIdentical += $chocoComparison.Identical
    }

    # Build results
    $results = @{
        BaselineSource = $baseline.Source
        CurrentSource  = $current.Source
        Summary        = @{
            TotalBaseline  = $baseline.Winget.Count + $baseline.Chocolatey.Count
            TotalCurrent   = $current.Winget.Count + $current.Chocolatey.Count
            Added          = $allAdded.Count
            Removed        = $allRemoved.Count
            VersionChanged = $allVersionChanged.Count
            Identical      = $allIdentical.Count
        }
        Added          = $allAdded
        Removed        = $allRemoved
        VersionChanged = $allVersionChanged
        Identical      = $allIdentical
    }

    # Generate reports
    switch ($OutputFormat) {
        'Console' { Write-ConsoleReport -Results $results }
        'HTML'    { Write-ConsoleReport -Results $results; Export-HTMLReport -OutputPath $OutputPath -Results $results }
        'JSON'    { Write-ConsoleReport -Results $results; Export-JSONReport -OutputPath $OutputPath -Results $results }
        'All'     {
            Write-ConsoleReport -Results $results
            Export-HTMLReport -OutputPath $OutputPath -Results $results
            Export-JSONReport -OutputPath $OutputPath -Results $results
        }
    }

    # Export missing packages script if requested
    if ($ExportMissing -and $allRemoved.Count -gt 0) {
        Export-MissingPackagesScript -Removed $allRemoved -OutputPath $OutputPath
    }

    Write-Success "Comparison complete"
    exit 0
}
catch {
    Write-ErrorMessage "Fatal error: $($_.Exception.Message)"
    Write-ErrorMessage "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
#endregion
