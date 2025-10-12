@{
    # Module manifest for CommonFunctions

    # Script module or binary module file associated with this manifest
    RootModule = 'CommonFunctions.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author of this module
    Author = 'David Dashti'

    # Company or vendor of this module
    CompanyName = 'Personal Toolkit'

    # Copyright statement for this module
    Copyright = '(c) 2025 David Dashti. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Common functions shared across Windows PowerShell scripts in the Sysadmin Toolkit'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Write-Log',
        'Write-Success',
        'Write-InfoMessage',
        'Write-WarningMessage',
        'Write-ErrorMessage',
        'Test-IsAdministrator',
        'Assert-Administrator',
        'Test-PowerShell7',
        'Get-PowerShell7Path'
    )

    # Variables to export from this module
    VariablesToExport = @('Colors')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Logging', 'Utilities', 'Admin', 'Helpers')

            # License URI for this module
            LicenseUri = 'https://opensource.org/licenses/MIT'

            # Project site URI for this module
            ProjectUri = 'https://github.com/Dashtid/windows-linux-sysadmin-toolkit'

            # Release notes for this module
            ReleaseNotes = 'Initial release of common functions module'
        }
    }
}
