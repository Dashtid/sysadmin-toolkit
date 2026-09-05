# Shared estate PSScriptAnalyzer settings.
#
# ONE file, at the repository root, read by BOTH the pre-commit hook and the
# VS Code PowerShell extension. Keeping it in .vscode/ - which is where this
# started life in sysadmin-toolkit - means the editor and the commit gate
# enforce different rules, and the editor's are the ones nobody sees fail.
#
# NO Severity key on purpose. The hook passes -Severity Error explicitly and a
# command-line parameter overrides the settings file, so declaring Severity here
# would be a value that silently never applies. Running the analyser by hand
# therefore reports everything:
#
#     Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
#
# Generated from estate/standards/PSScriptAnalyzerSettings.psd1.

@{
    IncludeDefaultRules = $true

    ExcludeRules = @(
        # Write-Host is the point of an interactive admin script: it writes to the
        # console without putting anything on the pipeline, which is exactly what
        # a progress line should do. This rule fires 285 times across the estate
        # and is right about none of them.
        'PSAvoidUsingWriteHost'

        # Wants a byte-order mark on any file containing non-ASCII. That fights
        # .editorconfig, which sets BOM-less UTF-8 everywhere, and it fights the
        # tooling: Windows PowerShell 5.1's `-Encoding UTF8` writes a BOM whether
        # or not one is wanted, and a stray BOM has already broken a consumer in
        # this estate once. BOM-less UTF-8 is the decision; this rule disagrees
        # with the decision rather than finding a defect.
        'PSUseBOMForUnicodeEncodedFile'
    )

    Rules = @{
        # Formatting. These only fire when the analyser is run with -Fix or in the
        # editor's format-document; they are never Errors, so they never gate a
        # commit. They are here so the editor formats consistently across repos.
        PSUseConsistentIndentation = @{
            Enable              = $true
            Kind                = 'space'
            IndentationSize     = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }
        PSUseConsistentWhitespace = @{
            Enable                          = $true
            CheckInnerBrace                 = $true
            CheckOpenBrace                  = $true
            CheckOpenParen                  = $true
            CheckOperator                   = $true
            CheckPipe                       = $true
            CheckPipeForRedundantWhitespace = $false
            CheckSeparator                  = $true
            CheckParameter                  = $false
        }
        PSAlignAssignmentStatement = @{
            Enable         = $true
            CheckHashtable = $true
        }
        PSUseCorrectCasing = @{ Enable = $true }

        # Correctness and security. Nothing exotic - these are the rules whose
        # findings have historically been real.
        PSAvoidUsingInvokeExpression                   = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword               = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
        PSUsePSCredentialType                          = @{ Enable = $true }
        PSAvoidUsingCmdletAliases                      = @{ Enable = $true; Allowlist = @() }
        PSUseApprovedVerbs                             = @{ Enable = $true }
        PSMisleadingBacktick                           = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments           = @{ Enable = $true }
        PSAvoidDefaultValueSwitchParameter             = @{ Enable = $true }
        PSUseCmdletCorrectly                           = @{ Enable = $true }
        PSReservedCmdletChar                           = @{ Enable = $true }
        PSReservedParams                               = @{ Enable = $true }
    }
}
