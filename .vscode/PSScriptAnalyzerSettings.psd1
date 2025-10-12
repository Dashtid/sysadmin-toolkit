# PSScriptAnalyzer settings for this repository
# Enforces best practices and code quality standards

@{
    # Enable all default rules
    IncludeDefaultRules = $true

    # Severity levels to report
    Severity = @('Error', 'Warning', 'Information')

    # Exclude specific rules if needed
    ExcludeRules = @(
        # Temporarily exclude rules that may need gradual adoption
        # 'PSAvoidUsingWriteHost'  # We use Write-Host for colored output
    )

    # Custom rule configuration
    Rules = @{
        # Cmdlet design rules
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $false
            BlockComment = $true
            VSCodeSnippetCorrection = $true
            Placement = 'begin'
        }

        PSUseConsistentIndentation = @{
            Enable = $true
            Kind = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            IndentationSize = 4
        }

        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckInnerBrace = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckPipe = $true
            CheckPipeForRedundantWhitespace = $false
            CheckSeparator = $true
            CheckParameter = $false
        }

        PSAlignAssignmentStatement = @{
            Enable = $true
            CheckHashtable = $true
        }

        PSUseCorrectCasing = @{
            Enable = $true
        }

        # Security rules
        PSAvoidUsingPlainTextForPassword = @{
            Enable = $true
        }

        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }

        # Performance rules
        PSAvoidUsingInvokeExpression = @{
            Enable = $true
        }

        PSAvoidUsingCmdletAliases = @{
            Enable = $true
            Allowlist = @()
        }

        # Best practices
        PSAvoidUsingPositionalParameters = @{
            Enable = $true
            CommandAllowList = @('Write-Host', 'Write-Output', 'Write-Verbose')
        }

        PSUseApprovedVerbs = @{
            Enable = $true
        }

        PSUseDeclaredVarsMoreThanAssignments = @{
            Enable = $true
        }

        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }

        PSUseSingularNouns = @{
            Enable = $true
        }

        PSUseSupportsShouldProcess = @{
            Enable = $true
        }

        PSReservedCmdletChar = @{
            Enable = $true
        }

        PSReservedParams = @{
            Enable = $true
        }

        PSMisleadingBacktick = @{
            Enable = $true
        }

        PSMissingModuleManifestField = @{
            Enable = $true
        }

        PSUseBOMForUnicodeEncodedFile = @{
            Enable = $true
        }

        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }

        PSUsePSCredentialType = @{
            Enable = $true
        }

        PSAvoidDefaultValueSwitchParameter = @{
            Enable = $true
        }

        PSUseCmdletCorrectly = @{
            Enable = $true
        }
    }
}
