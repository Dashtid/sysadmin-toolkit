# Behavioral Pester tests for Backup-UserData.ps1
# Run: Invoke-Pester -Path .\tests\Windows\BackupUserData.Behavioral.Tests.ps1
#
# Note: -Destination is Mandatory on the script's param block, so dot-source
# passes -Destination $TestDrive to satisfy parameter binding. The script's
# top-level region initializes $script:Stats / $script:StartTime / $script:MetadataFile
# at load time; tests reset $script:Stats in BeforeEach to isolate counter state.
#
# Out-File mock encoding gotcha (PS7) from Sprint 4.1 applies again here: leave
# Set-Content / Out-File / Compress-Archive unmocked when the code path under
# test actually writes a file; real cmdlets handle $TestDrive without issue.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Backup-UserData.ps1'
    . $ScriptPath -Destination $TestDrive
}

Describe 'Backup-UserData.ps1 - Format-FileSize' {
    It 'Formats sub-KB as bytes' {
        Format-FileSize -Bytes 512 | Should -Be '512 bytes'
    }

    It 'Formats KB-range as KB with two decimals' {
        Format-FileSize -Bytes 2048 | Should -Match '^2[\.,]00 KB$'
    }

    It 'Formats MB-range as MB' {
        Format-FileSize -Bytes (5MB) | Should -Match '^5[\.,]00 MB$'
    }

    It 'Formats GB-range as GB' {
        Format-FileSize -Bytes (3GB) | Should -Match '^3[\.,]00 GB$'
    }
}

Describe 'Backup-UserData.ps1 - Get-BackupMetadata' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Returns a default skeleton when the metadata file does not exist' {
        Mock Test-Path { $false } -ParameterFilter { $Path -eq $script:MetadataFile }
        $meta = Get-BackupMetadata
        $meta.LastFullBackup | Should -BeNullOrEmpty
        $meta.LastIncrementalBackup | Should -BeNullOrEmpty
        $meta.BackupHistory.Count | Should -Be 0
    }

    It 'Returns parsed JSON when the metadata file is well-formed' {
        Mock Test-Path { $true } -ParameterFilter { $Path -eq $script:MetadataFile }
        Mock Get-Content { '{"LastFullBackup":"2026-01-01T00:00:00","LastIncrementalBackup":null,"BackupHistory":[]}' }
        $meta = Get-BackupMetadata
        # ConvertFrom-Json coerces ISO-8601 strings into DateTime; compare via the absolute instant.
        ([datetime]$meta.LastFullBackup) | Should -Be ([datetime]'2026-01-01T00:00:00')
    }

    It 'Warns and returns the default skeleton when the metadata file is corrupt' {
        Mock Test-Path { $true } -ParameterFilter { $Path -eq $script:MetadataFile }
        Mock Get-Content { 'not valid json' }
        $meta = Get-BackupMetadata
        $meta.LastFullBackup | Should -BeNullOrEmpty
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'Could not read backup metadata' }
    }
}

Describe 'Backup-UserData.ps1 - Save-BackupMetadata' {
    BeforeEach {
        Mock Write-WarningMessage { }
    }

    It 'Writes the serialized hashtable to the metadata file path' {
        $metadataPath = Join-Path $TestDrive 'save-meta-test.json'
        $script:MetadataFile = $metadataPath
        Save-BackupMetadata -Metadata @{ Foo = 'bar'; Items = @(1, 2) }
        [System.IO.File]::Exists($metadataPath) | Should -BeTrue
        $content = Get-Content -Raw -LiteralPath $metadataPath
        $content | Should -Match '"Foo"'
        $content | Should -Match '"bar"'
    }

    It 'Warns but does not throw when the write fails' {
        Mock Set-Content { throw 'access denied' }
        { Save-BackupMetadata -Metadata @{ A = 1 } } | Should -Not -Throw
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'Could not save backup metadata' }
    }
}

Describe 'Backup-UserData.ps1 - Get-FilesToBackup' {
    BeforeEach {
        Mock Write-WarningMessage { }
        $script:Stats = @{
            TotalFiles    = 0
            TotalSize     = 0
            BackedUpFiles = 0
            BackedUpSize  = 0
            SkippedFiles  = 0
            FailedFiles   = 0
            Errors        = @()
        }
    }

    It 'Warns and returns an empty list when the source path does not exist' {
        Mock Test-Path { $false }
        $files = Get-FilesToBackup -SourcePath 'C:\does-not-exist'
        $files.Count | Should -Be 0
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'Source path not found' }
    }

    It 'Skips files inside an excluded folder' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{
                    FullName      = 'C:\source\node_modules\package.json'
                    Length        = 100
                    LastWriteTime = (Get-Date)
                    Extension     = '.json'
                }
                [PSCustomObject]@{
                    FullName      = 'C:\source\src\app.ps1'
                    Length        = 500
                    LastWriteTime = (Get-Date)
                    Extension     = '.ps1'
                }
            )
        }
        $files = Get-FilesToBackup -SourcePath 'C:\source'
        @($files).Count | Should -Be 1
        $script:Stats.SkippedFiles | Should -Be 1
    }

    It 'Skips files with an excluded extension' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ FullName = 'C:\source\trace.log'; Length = 10; LastWriteTime = (Get-Date); Extension = '.log' }
                [PSCustomObject]@{ FullName = 'C:\source\data.txt'; Length = 20; LastWriteTime = (Get-Date); Extension = '.txt' }
            )
        }
        $files = Get-FilesToBackup -SourcePath 'C:\source'
        @($files).Count | Should -Be 1
        $script:Stats.SkippedFiles | Should -Be 1
    }

    It 'Skips files modified before -ModifiedSince when incremental reference is given' {
        $cutoff = [DateTime]'2026-06-01'
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ FullName = 'C:\source\old.txt'; Length = 1; LastWriteTime = [DateTime]'2026-05-01'; Extension = '.txt' }
                [PSCustomObject]@{ FullName = 'C:\source\new.txt'; Length = 1; LastWriteTime = [DateTime]'2026-06-05'; Extension = '.txt' }
            )
        }
        $files = Get-FilesToBackup -SourcePath 'C:\source' -ModifiedSince $cutoff
        @($files).Count | Should -Be 1
        @($files)[0].FullName | Should -Be 'C:\source\new.txt'
        $script:Stats.SkippedFiles | Should -Be 1
    }

    It 'Updates TotalFiles / TotalSize counters for accepted files' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ FullName = 'C:\source\a.txt'; Length = 100; LastWriteTime = (Get-Date); Extension = '.txt' }
                [PSCustomObject]@{ FullName = 'C:\source\b.txt'; Length = 250; LastWriteTime = (Get-Date); Extension = '.txt' }
            )
        }
        $null = Get-FilesToBackup -SourcePath 'C:\source'
        $script:Stats.TotalFiles | Should -Be 2
        $script:Stats.TotalSize | Should -Be 350
    }
}

Describe 'Backup-UserData.ps1 - Get-FileHash256' {
    It 'Returns the SHA256 hash when Get-FileHash succeeds' {
        Mock Get-FileHash { [PSCustomObject]@{ Hash = 'ABC123' } }
        Get-FileHash256 -FilePath 'C:\anything' | Should -Be 'ABC123'
    }

    It 'Returns $null when Get-FileHash throws' {
        Mock Get-FileHash { throw 'file locked' }
        Get-FileHash256 -FilePath 'C:\anything' | Should -BeNullOrEmpty
    }
}

Describe 'Backup-UserData.ps1 - Copy-BackupFiles' {
    BeforeEach {
        Mock Write-WarningMessage { }
        Mock Write-Progress { }
        Mock Test-Path { $true }
        $script:Stats = @{
            TotalFiles    = 0
            TotalSize     = 0
            BackedUpFiles = 0
            BackedUpSize  = 0
            SkippedFiles  = 0
            FailedFiles   = 0
            Errors        = @()
        }
        $script:Files = @(
            @{ FullName = 'C:\src\a.txt'; RelativePath = 'a.txt'; Size = 100; LastWriteTime = (Get-Date); Hash = $null }
            @{ FullName = 'C:\src\b.txt'; RelativePath = 'b.txt'; Size = 200; LastWriteTime = (Get-Date); Hash = $null }
        )
    }

    It 'Copies each file and increments BackedUpFiles / BackedUpSize' {
        Mock Copy-Item { }
        Copy-BackupFiles -Files $script:Files -SourceRoot 'C:\src' -DestinationRoot 'C:\dst'
        $script:Stats.BackedUpFiles | Should -Be 2
        $script:Stats.BackedUpSize | Should -Be 300
        $script:Stats.FailedFiles | Should -Be 0
    }

    It 'Increments FailedFiles and records an error when Copy-Item throws' {
        Mock Copy-Item { throw 'access denied' }
        Copy-BackupFiles -Files $script:Files -SourceRoot 'C:\src' -DestinationRoot 'C:\dst'
        $script:Stats.FailedFiles | Should -Be 2
        $script:Stats.BackedUpFiles | Should -Be 0
        $script:Stats.Errors.Count | Should -Be 2
    }

    It 'Creates the destination directory when it does not yet exist' {
        Mock Copy-Item { }
        Mock Test-Path { $false } -ParameterFilter { $Path -eq 'C:\dst' }
        Mock New-Item { } -Verifiable -ParameterFilter { $ItemType -eq 'Directory' }
        Copy-BackupFiles -Files @($script:Files[0]) -SourceRoot 'C:\src' -DestinationRoot 'C:\dst'
        Should -InvokeVerifiable
    }

    It 'Computes a SHA256 hash on each file when -ComputeHash is set' {
        Mock Copy-Item { }
        Mock Get-FileHash { [PSCustomObject]@{ Hash = 'HASHED' } }
        Copy-BackupFiles -Files $script:Files -SourceRoot 'C:\src' -DestinationRoot 'C:\dst' -ComputeHash
        $script:Files[0].Hash | Should -Be 'HASHED'
        $script:Files[1].Hash | Should -Be 'HASHED'
    }

    It 'Skips hash computation when -ComputeHash is not set' {
        Mock Copy-Item { }
        Mock Get-FileHash { [PSCustomObject]@{ Hash = 'HASHED' } }
        Copy-BackupFiles -Files $script:Files -SourceRoot 'C:\src' -DestinationRoot 'C:\dst'
        $script:Files[0].Hash | Should -BeNullOrEmpty
        Should -Invoke Get-FileHash -Times 0
    }
}

Describe 'Backup-UserData.ps1 - Compress-BackupFolder' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @() }
    }

    It 'Returns $true and calls Compress-Archive when compression succeeds' {
        Mock Compress-Archive { } -Verifiable
        Compress-BackupFolder -SourcePath 'C:\src' -ArchivePath 'C:\out.zip' | Should -Be $true
        Should -InvokeVerifiable
    }

    It 'Returns $false and records the error when Compress-Archive throws' {
        Mock Compress-Archive { throw 'disk full' }
        Compress-BackupFolder -SourcePath 'C:\src' -ArchivePath 'C:\out.zip' | Should -Be $false
        $script:Stats.Errors.Count | Should -Be 1
        Should -Invoke Write-ErrorMessage
    }

    It "Maps -Level 'None' to the 'NoCompression' string that Compress-Archive accepts" {
        # Compress-Archive's -CompressionLevel is a string ValidateSet of
        # Optimal/Fastest/NoCompression. Mock bodies run in an isolated scope, so use
        # $global: as a sink to capture the value that actually reaches the cmdlet.
        $global:CapturedLevel = $null
        try {
            Mock Compress-Archive { $global:CapturedLevel = $CompressionLevel }
            Compress-BackupFolder -SourcePath 'C:\src' -ArchivePath 'C:\out.zip' -Level 'None' | Out-Null
            $global:CapturedLevel | Should -Be 'NoCompression'
        }
        finally {
            Remove-Variable -Name CapturedLevel -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It "Passes -Level 'Fastest' through to Compress-Archive verbatim" {
        $global:CapturedLevel = $null
        try {
            Mock Compress-Archive { $global:CapturedLevel = $CompressionLevel }
            Compress-BackupFolder -SourcePath 'C:\src' -ArchivePath 'C:\out.zip' -Level 'Fastest' | Out-Null
            $global:CapturedLevel | Should -Be 'Fastest'
        }
        finally {
            Remove-Variable -Name CapturedLevel -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Backup-UserData.ps1 - Test-BackupIntegrity (helper)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        $script:Stats = @{ Errors = @() }
    }

    It 'Reports all-verified when every backup-file hash matches the source hash' {
        $files = @(
            @{ RelativePath = 'a.txt'; Hash = 'AAA' }
            @{ RelativePath = 'b.txt'; Hash = 'BBB' }
        )
        Mock Test-Path { $true }
        Mock Get-FileHash {
            if ($Path -match 'a\.txt') { [PSCustomObject]@{ Hash = 'AAA' } }
            else { [PSCustomObject]@{ Hash = 'BBB' } }
        }
        $result = Test-BackupIntegrity -Files $files -BackupPath 'C:\backup'
        $result.TotalVerified | Should -Be 2
        $result.TotalFailed | Should -Be 0
        $result.Success | Should -Be $true
    }

    It 'Reports a hash-mismatch failure and adds an error entry' {
        $files = @(@{ RelativePath = 'a.txt'; Hash = 'EXPECTED' })
        Mock Test-Path { $true }
        Mock Get-FileHash { [PSCustomObject]@{ Hash = 'WRONG' } }
        $result = Test-BackupIntegrity -Files $files -BackupPath 'C:\backup'
        $result.TotalFailed | Should -Be 1
        $result.Success | Should -Be $false
        $script:Stats.Errors[0] | Should -Match 'Hash mismatch'
    }

    It 'Reports a missing-backup-file failure when the destination does not exist' {
        $files = @(@{ RelativePath = 'a.txt'; Hash = 'AAA' })
        Mock Test-Path { $false }
        $result = Test-BackupIntegrity -Files $files -BackupPath 'C:\backup'
        $result.TotalFailed | Should -Be 1
        $script:Stats.Errors[0] | Should -Match 'File missing from backup'
    }

    It 'Skips files with no Hash recorded (e.g. when -VerifyBackup was not set during copy)' {
        $files = @(
            @{ RelativePath = 'a.txt'; Hash = $null }
            @{ RelativePath = 'b.txt'; Hash = $null }
        )
        Mock Test-Path { $true }
        Mock Get-FileHash { [PSCustomObject]@{ Hash = 'XXX' } }
        $result = Test-BackupIntegrity -Files $files -BackupPath 'C:\backup'
        $result.TotalVerified | Should -Be 0
        $result.TotalFailed | Should -Be 0
    }
}

Describe 'Backup-UserData.ps1 - Remove-OldBackups' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
        Mock Write-Verbose { }
    }

    It 'Removes backups beyond -KeepCount, newest first' {
        # Five backups; with KeepCount=2 only the oldest 3 should be removed.
        Mock Get-ChildItem {
            if ($Directory) {
                @(
                    [PSCustomObject]@{ FullName = 'B5'; CreationTime = (Get-Date).AddDays(-1) }
                    [PSCustomObject]@{ FullName = 'B4'; CreationTime = (Get-Date).AddDays(-2) }
                    [PSCustomObject]@{ FullName = 'B3'; CreationTime = (Get-Date).AddDays(-3) }
                    [PSCustomObject]@{ FullName = 'B2'; CreationTime = (Get-Date).AddDays(-4) }
                    [PSCustomObject]@{ FullName = 'B1'; CreationTime = (Get-Date).AddDays(-5) }
                )
            }
            else { @() }
        }
        Mock Remove-Item { } -Verifiable
        Remove-OldBackups -BackupRoot 'C:\backups' -KeepCount 2 -KeepDays 365
        Should -Invoke Remove-Item -Times 3
    }

    It 'Removes backups older than -KeepDays that are beyond the keep-count protection window' {
        # The script protects the most-recent KeepCount backups from age-based deletion.
        # So by-age removal only kicks in when a backup is BOTH old AND outside that window.
        # Setup: 3 backups, KeepCount=1, KeepDays=7. Only the newest is protected.
        # The two older ones are >7 days old and outside the keep-count -> both removed.
        Mock Get-ChildItem {
            if ($Directory) {
                @(
                    [PSCustomObject]@{ FullName = 'NewestKept'; CreationTime = (Get-Date).AddDays(-1) }
                    [PSCustomObject]@{ FullName = 'MiddleOld'; CreationTime = (Get-Date).AddDays(-30) }
                    [PSCustomObject]@{ FullName = 'AncientOld'; CreationTime = (Get-Date).AddDays(-100) }
                )
            }
            else { @() }
        }
        $script:RemovedPaths = @()
        Mock Remove-Item { $script:RemovedPaths += $Path }
        Remove-OldBackups -BackupRoot 'C:\backups' -KeepCount 1 -KeepDays 7
        # The by-count pass already removed everything past index 0 (MiddleOld + AncientOld).
        # By-age would then have nothing left to act on. Either way the net is the same:
        # the two non-newest backups are gone.
        $script:RemovedPaths | Should -Contain 'MiddleOld'
        $script:RemovedPaths | Should -Contain 'AncientOld'
        $script:RemovedPaths | Should -Not -Contain 'NewestKept'
    }
}

Describe 'Backup-UserData.ps1 - Export-HTMLReport' {
    It 'Writes an HTML file containing the SUCCESS status when -Success is true' {
        Mock Write-Success { }
        $report = @{
            ComputerName = 'TESTPC'
            BackupType   = 'Full'
            Destination  = 'C:\X'
            Success      = $true
            Duration     = '00:01:23'
            Stats        = @{ BackedUpFiles = 5; BackedUpSize = 1024; SkippedFiles = 0; FailedFiles = 0; Errors = @() }
            Verification = $null
        }
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
        $path = Export-HTMLReport -Report $report -Path $TestDrive
        [System.IO.File]::Exists($path) | Should -BeTrue
        (Get-Content -Raw -LiteralPath $path) | Should -Match 'SUCCESS'
    }

    It 'HTML-encodes error messages to prevent injection' {
        Mock Write-Success { }
        $report = @{
            ComputerName = 'TESTPC'
            BackupType   = 'Full'
            Destination  = 'C:\X'
            Success      = $false
            Duration     = '00:00:01'
            Stats        = @{
                BackedUpFiles = 0; BackedUpSize = 0; SkippedFiles = 0; FailedFiles = 1
                Errors        = @('<script>alert(1)</script>')
            }
            Verification = $null
        }
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
        $path = Export-HTMLReport -Report $report -Path $TestDrive
        $content = Get-Content -Raw -LiteralPath $path
        $content | Should -Match '&lt;script&gt;'
        $content | Should -Not -Match '<script>alert\(1\)</script>'
    }
}

Describe 'Backup-UserData.ps1 - Export-JSONReport' {
    It 'Writes a JSON file with the report contents' {
        Mock Write-Success { }
        $report = @{
            ComputerName = 'TESTPC'
            BackupType   = 'Incremental'
            Success      = $true
            Stats        = @{ BackedUpFiles = 3 }
        }
        $path = Export-JSONReport -Report $report -Path $TestDrive
        [System.IO.File]::Exists($path) | Should -BeTrue
        $parsed = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $parsed.ComputerName | Should -Be 'TESTPC'
        $parsed.Stats.BackedUpFiles | Should -Be 3
    }
}

Describe 'Backup-UserData.ps1 - Invoke-UserDataBackup (top level)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Write-Progress { }
        Mock Get-BackupMetadata { @{ LastFullBackup = $null; LastIncrementalBackup = $null; BackupHistory = @() } }
        Mock Save-BackupMetadata { }
        Mock Remove-OldBackups { }
        Mock Get-FilesToBackup { @() }
        $script:Stats = @{
            TotalFiles = 0; TotalSize = 0; BackedUpFiles = 0; BackedUpSize = 0
            SkippedFiles = 0; FailedFiles = 0; Errors = @()
        }
        $script:StartTime = Get-Date
    }

    It 'Returns 0 on the happy path with no files to back up' {
        $result = Invoke-UserDataBackup -Destination $TestDrive -BackupType Full -DryRun -SourceFolders @()
        $result | Should -Be 0
    }

    It 'Returns 1 when a fatal error escapes the try block' {
        Mock Get-BackupMetadata { throw 'metadata IO error' }
        $result = Invoke-UserDataBackup -Destination $TestDrive -BackupType Full -DryRun -SourceFolders @()
        $result | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Fatal error' }
    }

    It 'Logs the DRY RUN warning when -DryRun is in effect' {
        Invoke-UserDataBackup -Destination $TestDrive -BackupType Full -DryRun -SourceFolders @() | Out-Null
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'DRY RUN MODE' }
    }
}
