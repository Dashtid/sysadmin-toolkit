#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Pre-commit gate for PowerShell: parse every staged file, then run
    PSScriptAnalyzer over them at Error severity.

.DESCRIPTION
    Two checks, in the order that makes the second one meaningful. A file with a
    syntax error cannot be analysed, so the parse pass runs first: one clear
    message beats the wall of downstream noise an unparseable file produces.

    [!] INVOKED WITH -File, NEVER -Command. PowerShell's -Command does not bind
    trailing positional CLI arguments to a param() block inside the command
    string. The filenames pre-commit appends are then read as commands at outer
    scope, the run dies with "term not recognized", and the loop never executes -
    so the hook fails, but for the wrong reason and with a message that points
    nowhere. That was found the hard way in private-toolkit; see the note at the
    top of its scripts/check-ps-syntax.ps1, which this file generalises.

    Severity is Error only. Every repository in this estate is currently clean at
    that level, so the hook is a gate that means something rather than a wall of
    legacy warnings nobody can clear. Run the wider analysis by hand:

        Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1

    Rule configuration lives in PSScriptAnalyzerSettings.psd1 at the repository
    root - one file, read by this hook AND by the VS Code PowerShell extension,
    so the editor and the gate cannot disagree. -Severity here overrides whatever
    the settings file says, which is why the settings file sets no Severity.

.NOTES
    Generated from estate/standards/scripts/check-powershell.ps1. Edit it there,
    then re-run `python standards/rollout.py --apply`.
#>

$ErrorActionPreference = 'Stop'

if ($args.Count -eq 0) { exit 0 }

$failed = 0

# --- 1. parse ---------------------------------------------------------------
$parseable = @()
foreach ($file in $args) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Host "[-] not found: $file"
        $failed++
        continue
    }
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $file), [ref]$null, [ref]$parseErrors
    )
    if ($parseErrors) {
        Write-Host "[-] syntax errors in ${file}:"
        $parseErrors | ForEach-Object { Write-Host "      $_" }
        $failed++
    } else {
        $parseable += (Resolve-Path -LiteralPath $file).Path
    }
}

if ($failed -gt 0) { exit 1 }
if ($parseable.Count -eq 0) { exit 0 }

# --- 2. analyse -------------------------------------------------------------
# Absent module: say so and let the commit through. A missing analyser on one
# machine is a setup problem, not a reason to block work - and a hook that fails
# for a reason the author cannot act on gets bypassed with --no-verify, which
# costs more than it saves. CI is where its absence should be fatal.
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Host '[!] PSScriptAnalyzer is not installed - parse check only.'
    Write-Host '    Install-Module PSScriptAnalyzer -Scope CurrentUser'
    exit 0
}
Import-Module PSScriptAnalyzer -ErrorAction Stop

# -Path takes ONE string, not an array - handing it the whole file list throws
# "Cannot convert 'System.Object[]' to 'System.String'" per file. One call per
# file; the staged set is small by construction.
$settings = Join-Path (Get-Location) 'PSScriptAnalyzerSettings.psd1'
$findings = @()
foreach ($file in $parseable) {
    $params = @{ Path = $file; Severity = 'Error'; ErrorAction = 'SilentlyContinue' }
    if (Test-Path -LiteralPath $settings) { $params['Settings'] = $settings }
    $findings += @(Invoke-ScriptAnalyzer @params)
}
if ($findings) {
    $findings |
        Select-Object @{n = 'File'; e = { Split-Path $_.ScriptPath -Leaf } }, Line, RuleName, Message |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    exit 1
}

exit 0
