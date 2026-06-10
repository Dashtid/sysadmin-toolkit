# Behavioral Pester tests for Compare-SoftwareInventory.ps1
# Run: Invoke-Pester -Path .\tests\Windows\CompareSoftwareInventory.Behavioral.Tests.ps1

BeforeAll {
    function winget { param() }
    function choco { param() }

    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\first-time-setup\Compare-SoftwareInventory.ps1'
    # The script's param block requires -BaselineFile with ValidateScript {Test-Path $_}.
    # Dot-sourcing with the script's own path satisfies the validation without us caring
    # about the contents (we test helpers directly, not the main flow).
    . $ScriptPath -BaselineFile $ScriptPath

    $global:LASTEXITCODE = 0
}

Describe 'Compare-SoftwareInventory.ps1 - Import-WingetInventory' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Parses a Sources/Packages JSON document into PSCustomObjects' {
        $jsonPath = Join-Path $TestDrive 'winget.json'
        $payload = @{
            Sources = @(
                @{
                    Packages = @(
                        @{ PackageIdentifier = 'Microsoft.PowerShell'; Version = '7.4.0' }
                        @{ PackageIdentifier = 'Git.Git'; Version = '2.42.0' }
                    )
                }
            )
        }
        $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath

        $packages = @(Import-WingetInventory -FilePath $jsonPath)
        $packages.Count | Should -Be 2
        ($packages | Where-Object { $_.Name -eq 'Microsoft.PowerShell' })[0].Version | Should -Be '7.4.0'
        $packages[0].Source | Should -Be 'Winget'
    }

    It 'Returns empty array when the file is unreadable' {
        $packages = @(Import-WingetInventory -FilePath (Join-Path $TestDrive 'does-not-exist.json'))
        $packages.Count | Should -Be 0
    }
}

Describe 'Compare-SoftwareInventory.ps1 - Import-ChocolateyInventory' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Parses a packages.config XML document into PSCustomObjects' {
        $xmlPath = Join-Path $TestDrive 'packages.config'
        @'
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="nodejs" version="18.0.0" />
  <package id="python" version="3.10.0" />
</packages>
'@ | Set-Content -Path $xmlPath

        $packages = @(Import-ChocolateyInventory -FilePath $xmlPath)
        $packages.Count | Should -Be 2
        ($packages | Where-Object { $_.Name -eq 'nodejs' })[0].Version | Should -Be '18.0.0'
        $packages[0].Source | Should -Be 'Chocolatey'
    }

    It 'Returns empty array when the file is unreadable' {
        $packages = @(Import-ChocolateyInventory -FilePath (Join-Path $TestDrive 'no-such.config'))
        $packages.Count | Should -Be 0
    }
}

Describe 'Compare-SoftwareInventory.ps1 - Compare-PackageLists' {
    It 'Classifies a new package as Added' {
        $baseline = @()
        $current  = @([PSCustomObject]@{ Name = 'NewApp'; Version = '1.0' })
        $r = Compare-PackageLists -BaselinePackages $baseline -CurrentPackages $current -Source 'Winget'
        @($r.Added).Count | Should -Be 1
        @($r.Added)[0].Name | Should -Be 'NewApp'
    }

    It 'Classifies a missing package as Removed' {
        $baseline = @([PSCustomObject]@{ Name = 'GoneApp'; Version = '1.0' })
        $current  = @()
        $r = Compare-PackageLists -BaselinePackages $baseline -CurrentPackages $current -Source 'Winget'
        @($r.Removed).Count | Should -Be 1
        @($r.Removed)[0].Name | Should -Be 'GoneApp'
    }

    It 'Classifies a same-name different-version package as VersionChanged' {
        $baseline = @([PSCustomObject]@{ Name = 'App'; Version = '1.0' })
        $current  = @([PSCustomObject]@{ Name = 'App'; Version = '2.0' })
        $r = Compare-PackageLists -BaselinePackages $baseline -CurrentPackages $current -Source 'Winget'
        @($r.VersionChanged).Count | Should -Be 1
        @($r.VersionChanged)[0].BaselineVersion | Should -Be '1.0'
        @($r.VersionChanged)[0].CurrentVersion | Should -Be '2.0'
    }

    It 'Classifies a same-name same-version package as Identical' {
        $baseline = @([PSCustomObject]@{ Name = 'App'; Version = '1.0' })
        $current  = @([PSCustomObject]@{ Name = 'App'; Version = '1.0' })
        $r = Compare-PackageLists -BaselinePackages $baseline -CurrentPackages $current -Source 'Winget'
        @($r.Identical).Count | Should -Be 1
        @($r.VersionChanged).Count | Should -Be 0
    }

    It 'Tags every returned record with the supplied Source label' {
        $baseline = @([PSCustomObject]@{ Name = 'A'; Version = '1' })
        $current  = @([PSCustomObject]@{ Name = 'B'; Version = '2' })
        $r = Compare-PackageLists -BaselinePackages $baseline -CurrentPackages $current -Source 'Chocolatey'
        @($r.Added)[0].Source | Should -Be 'Chocolatey'
        @($r.Removed)[0].Source | Should -Be 'Chocolatey'
    }
}

Describe 'Compare-SoftwareInventory.ps1 - Import-Inventory (file mode)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Loads a Winget JSON file when the path ends in .json' {
        $jsonPath = Join-Path $TestDrive 'baseline-winget.json'
        @{ Sources = @(@{ Packages = @(@{ PackageIdentifier = 'X'; Version = '1' }) }) } |
            ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath
        $inv = Import-Inventory -FilePath $jsonPath -IsLive $false -Sources @('All')
        @($inv.Winget).Count | Should -Be 1
    }

    It 'Loads a Chocolatey config XML when extension is .config' {
        $xmlPath = Join-Path $TestDrive 'baseline-choco.config'
        @'
<?xml version="1.0" encoding="utf-8"?>
<packages><package id="git" version="2.0" /></packages>
'@ | Set-Content -Path $xmlPath
        $inv = Import-Inventory -FilePath $xmlPath -IsLive $false -Sources @('All')
        @($inv.Chocolatey).Count | Should -Be 1
    }

    It 'When the path is a directory, finds winget-packages.json and chocolatey-packages.config alongside' {
        $dir = Join-Path $TestDrive 'baseline-dir'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        @{ Sources = @(@{ Packages = @(@{ PackageIdentifier = 'WingetApp'; Version = '1' }) }) } |
            ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $dir 'winget-packages.json')
        @'
<?xml version="1.0" encoding="utf-8"?>
<packages><package id="ChocoApp" version="2" /></packages>
'@ | Set-Content -Path (Join-Path $dir 'chocolatey-packages.config')

        $inv = Import-Inventory -FilePath $dir -IsLive $false -Sources @('All')
        @($inv.Winget).Count | Should -Be 1
        @($inv.Chocolatey).Count | Should -Be 1
    }

    It 'Skips Chocolatey when Sources = @(Winget)' {
        $dir = Join-Path $TestDrive 'baseline-dir-2'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        @{ Sources = @(@{ Packages = @(@{ PackageIdentifier = 'W'; Version = '1' }) }) } |
            ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $dir 'winget-packages.json')
        @'
<?xml version="1.0" encoding="utf-8"?>
<packages><package id="C" version="2" /></packages>
'@ | Set-Content -Path (Join-Path $dir 'chocolatey-packages.config')

        $inv = Import-Inventory -FilePath $dir -IsLive $false -Sources @('Winget')
        @($inv.Winget).Count | Should -Be 1
        @($inv.Chocolatey).Count | Should -Be 0
    }
}

Describe 'Compare-SoftwareInventory.ps1 - Get-LiveWingetInventory / Get-LiveChocolateyInventory' {
    BeforeEach {
        Mock Write-WarningMessage { }
        Mock Write-InfoMessage { }
    }

    It 'Get-LiveWingetInventory returns empty array when winget is not on PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
        $packages = @(Get-LiveWingetInventory)
        $packages.Count | Should -Be 0
    }

    It 'Get-LiveChocolateyInventory returns empty array when choco is not on PATH' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'choco' }
        $packages = @(Get-LiveChocolateyInventory)
        $packages.Count | Should -Be 0
    }

    It 'Get-LiveChocolateyInventory parses pipe-delimited choco output' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'choco' } } -ParameterFilter { $Name -eq 'choco' }
        Mock choco {
            $global:LASTEXITCODE = 0
            @('nodejs|18.0.0', 'python|3.10.0')
        }
        $packages = @(Get-LiveChocolateyInventory)
        $packages.Count | Should -Be 2
        ($packages | Where-Object { $_.Name -eq 'nodejs' })[0].Version | Should -Be '18.0.0'
    }
}

Describe 'Compare-SoftwareInventory.ps1 - Export-MissingPackagesScript' {
    It 'Writes a script that contains winget install lines for removed Winget packages' {
        $dir = Join-Path $TestDrive 'export-out'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $removed = @(
            [PSCustomObject]@{ Name = 'Microsoft.PowerShell'; Version = '7.4.0'; Source = 'Winget' }
        )
        Export-MissingPackagesScript -Removed $removed -OutputPath $dir
        $scriptFile = Get-ChildItem -Path $dir -Filter 'install-missing-packages_*.ps1' | Select-Object -First 1
        $scriptFile | Should -Not -BeNullOrEmpty
        $content = Get-Content $scriptFile.FullName -Raw
        $content | Should -Match 'winget install --id "Microsoft.PowerShell"'
    }

    It 'Includes a choco install branch when removed packages contain a Chocolatey source' {
        $dir = Join-Path $TestDrive 'export-out-2'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $removed = @(
            [PSCustomObject]@{ Name = 'nodejs'; Version = '18.0.0'; Source = 'Chocolatey' }
        )
        Export-MissingPackagesScript -Removed $removed -OutputPath $dir
        $scriptFile = Get-ChildItem -Path $dir -Filter 'install-missing-packages_*.ps1' | Select-Object -First 1
        $content = Get-Content $scriptFile.FullName -Raw
        $content | Should -Match 'choco install'
        $content | Should -Match 'nodejs'
    }
}
