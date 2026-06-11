# Behavioral Pester tests for Test-BackupIntegrity.ps1
# Run: Invoke-Pester -Path .\tests\Windows\TestBackupIntegrity.Behavioral.Tests.ps1

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Test-BackupIntegrity.ps1'
    # -BackupPath is Mandatory with ValidateScript({Test-Path $_}) so the script's own
    # path satisfies the validation for dot-source purposes.
    . $ScriptPath -BackupPath $ScriptPath

    # Build a real test ZIP archive in $TestDrive so the archive helpers can run end-to-end.
    $script:ArchiveSourceDir = Join-Path $TestDrive 'archive-source'
    New-Item -ItemType Directory -Path $script:ArchiveSourceDir -Force | Out-Null
    'hello world' | Out-File -FilePath (Join-Path $script:ArchiveSourceDir 'file1.txt') -Encoding UTF8
    'second file' | Out-File -FilePath (Join-Path $script:ArchiveSourceDir 'file2.txt') -Encoding UTF8

    # Real metadata with SHA256 of file1.txt for hash-verification tests.
    $file1Hash = (Get-FileHash -Path (Join-Path $script:ArchiveSourceDir 'file1.txt') -Algorithm SHA256).Hash
    $metadataObj = @{
        Timestamp  = '2026-06-11T00:00:00'
        FileHashes = @{
            'file1.txt' = $file1Hash
        }
    }
    $metadataObj | ConvertTo-Json | Out-File -FilePath (Join-Path $script:ArchiveSourceDir 'backup_metadata.json') -Encoding UTF8

    $script:TestArchive = Join-Path $TestDrive 'test-backup.zip'
    Compress-Archive -Path (Join-Path $script:ArchiveSourceDir '*') -DestinationPath $script:TestArchive -Force
}

Describe 'Test-BackupIntegrity.ps1 - Format-FileSize' {
    It 'Returns "<n> bytes" for sub-KB values' {
        Format-FileSize -Bytes 500 | Should -Be '500 bytes'
    }

    It 'Returns "N.NN KB" / MB / GB at the expected boundaries' {
        Format-FileSize -Bytes 2048 | Should -Match '^2[.,]00 KB$'
        Format-FileSize -Bytes (3MB) | Should -Match '^3[.,]00 MB$'
        Format-FileSize -Bytes (4GB) | Should -Match '^4[.,]00 GB$'
    }
}

Describe 'Test-BackupIntegrity.ps1 - Get-BackupInfo' {
    BeforeEach {
        $script:Stats = @{ Errors = @() }
    }

    It 'Identifies an archive by .zip extension and reports HasMetadata=$true when metadata is inside' {
        $info = Get-BackupInfo -Path $script:TestArchive
        $info.IsArchive | Should -Be $true
        $info.Exists | Should -Be $true
        $info.FileCount | Should -BeGreaterThan 0
        $info.HasMetadata | Should -Be $true
        $info.Size | Should -BeGreaterThan 0
    }

    It 'Treats a folder as not-an-archive and reports HasMetadata based on the on-disk file' {
        $info = Get-BackupInfo -Path $script:ArchiveSourceDir
        $info.IsArchive | Should -Be $false
        $info.HasMetadata | Should -Be $true
    }

    It 'Records an error in $script:Stats.Errors when the archive cannot be opened' {
        $bogusZip = Join-Path $TestDrive 'corrupt.zip'
        'not a real zip' | Out-File -FilePath $bogusZip -Encoding ASCII
        $info = Get-BackupInfo -Path $bogusZip
        $info.IsArchive | Should -Be $true
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Test-ArchiveStructure' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @() }
    }

    It 'Reports Valid=$true with entry count and total size for a real archive' {
        $result = Test-ArchiveStructure -ArchivePath $script:TestArchive
        $result.Valid | Should -Be $true
        $result.EntryCount | Should -BeGreaterThan 0
        $result.TotalSize | Should -BeGreaterThan 0
    }

    It 'Reports Valid=$false and records an error for a corrupted archive' {
        $bogusZip = Join-Path $TestDrive 'bogus.zip'
        'not a real zip' | Out-File -FilePath $bogusZip -Encoding ASCII
        $result = Test-ArchiveStructure -ArchivePath $bogusZip
        $result.Valid | Should -Be $false
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Get-BackupMetadata' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        $script:Stats = @{ Warnings = @() }
    }

    It 'Reads metadata from inside a ZIP archive' {
        $meta = Get-BackupMetadata -BackupPath $script:TestArchive -IsArchive $true
        $meta | Should -Not -BeNullOrEmpty
        $meta.FileHashes.'file1.txt' | Should -Not -BeNullOrEmpty
    }

    It 'Reads metadata from a backup folder when -IsArchive is $false' {
        $meta = Get-BackupMetadata -BackupPath $script:ArchiveSourceDir -IsArchive $false
        $meta | Should -Not -BeNullOrEmpty
    }

    It 'Returns $null and warns when the folder has no backup_metadata.json' {
        $emptyDir = Join-Path $TestDrive 'no-metadata'
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        Get-BackupMetadata -BackupPath $emptyDir -IsArchive $false | Should -BeNullOrEmpty
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'No metadata' }
    }
}

Describe 'Test-BackupIntegrity.ps1 - Expand-BackupToTemp' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @() }
        $script:TempFolder = $null
    }

    It 'Extracts the archive into a temp folder and stores it on $script:TempFolder' {
        $result = Expand-BackupToTemp -ArchivePath $script:TestArchive
        $result | Should -Not -BeNullOrEmpty
        [System.IO.Directory]::Exists($result) | Should -BeTrue
        $script:TempFolder | Should -Be $result
        # Cleanup
        Remove-Item -Path $result -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Returns $null and records an error when extraction fails' {
        Mock Expand-Archive { throw 'archive corrupted' }
        Mock New-Item { }   # Don't create a real temp dir for this failure-path test.
        $result = Expand-BackupToTemp -ArchivePath 'C:\does-not-matter.zip'
        $result | Should -BeNullOrEmpty
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Test-FileHashes' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        $script:Stats = @{
            TotalFiles = 0; FilesVerified = 0; FilesFailed = 0
            HashesMatched = 0; HashesFailed = 0
            VerifiedFiles = @(); FailedFiles = @(); Warnings = @(); Errors = @()
        }
    }

    It 'Returns Skipped=$true when metadata has no FileHashes' {
        $result = Test-FileHashes -FolderPath $script:ArchiveSourceDir -Metadata @{ Foo = 'bar' } -SamplePercent 100
        $result.Skipped | Should -Be $true
    }

    It 'Verifies a matching hash and records HashesMatched++' {
        $file1Hash = (Get-FileHash -Path (Join-Path $script:ArchiveSourceDir 'file1.txt') -Algorithm SHA256).Hash
        $meta = [PSCustomObject]@{ FileHashes = [PSCustomObject]@{ 'file1.txt' = $file1Hash } }
        $result = Test-FileHashes -FolderPath $script:ArchiveSourceDir -Metadata $meta -SamplePercent 100
        $result.Verified | Should -BeGreaterThan 0
        $result.Failed | Should -Be 0
        $script:Stats.HashesMatched | Should -BeGreaterThan 0
    }

    It 'Reports a mismatched hash via $result.Failed and Stats.FailedFiles' {
        $meta = [PSCustomObject]@{ FileHashes = [PSCustomObject]@{ 'file1.txt' = '0' * 64 } }
        $result = Test-FileHashes -FolderPath $script:ArchiveSourceDir -Metadata $meta -SamplePercent 100
        $result.Failed | Should -BeGreaterThan 0
        $script:Stats.HashesFailed | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Test-FileExtraction' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @(); FailedFiles = @() }
    }

    It 'Reports all entries readable for a real archive' {
        $result = Test-FileExtraction -ArchivePath $script:TestArchive
        $result.Readable | Should -BeGreaterThan 0
        $result.Failed | Should -Be 0
    }

    It 'Reports an error on a corrupted archive' {
        $bogusZip = Join-Path $TestDrive 'extract-bogus.zip'
        'garbage' | Out-File -FilePath $bogusZip -Encoding ASCII
        $result = Test-FileExtraction -ArchivePath $bogusZip
        $result.Error | Should -Not -BeNullOrEmpty
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Restore-ToTarget' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-ErrorMessage { }
        $script:Stats = @{ Errors = @() }
    }

    It 'Expands the archive into -TargetPath when -IsArchive is $true and reports the file count' {
        $target = Join-Path $TestDrive 'restore-target-1'
        $result = Restore-ToTarget -BackupPath $script:TestArchive -TargetPath $target -IsArchive $true
        $result.Success | Should -Be $true
        $result.FileCount | Should -BeGreaterThan 0
        [System.IO.File]::Exists((Join-Path $target 'file1.txt')) | Should -BeTrue
    }

    It 'Copies the folder when -IsArchive is $false' {
        $target = Join-Path $TestDrive 'restore-target-2'
        $result = Restore-ToTarget -BackupPath $script:ArchiveSourceDir -TargetPath $target -IsArchive $false
        $result.Success | Should -Be $true
        [System.IO.File]::Exists((Join-Path $target 'file1.txt')) | Should -BeTrue
    }

    It 'Returns Success=$false and records an error when expansion throws' {
        Mock Expand-Archive { throw 'corrupted' }
        $result = Restore-ToTarget -BackupPath 'C:\nope.zip' -TargetPath (Join-Path $TestDrive 'restore-target-3') -IsArchive $true
        $result.Success | Should -Be $false
        $script:Stats.Errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-BackupIntegrity.ps1 - Remove-TempFolder' {
    BeforeEach {
        Mock Write-InfoMessage { }
    }

    It 'Removes the supplied -Path when it exists' {
        $target = Join-Path $TestDrive 'temp-folder-to-remove'
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Remove-TempFolder -Path $target
        [System.IO.Directory]::Exists($target) | Should -BeFalse
    }

    It 'Does not throw when the path does not exist' {
        { Remove-TempFolder -Path (Join-Path $TestDrive 'never-existed') } | Should -Not -Throw
    }
}

Describe 'Test-BackupIntegrity.ps1 - Export-HTMLReport / Export-JSONReport' {
    BeforeEach {
        Mock Write-Success { }
        $script:Stats = @{
            TotalFiles = 5; FilesVerified = 5; FilesFailed = 0
            HashesMatched = 5; HashesFailed = 0; TotalSize = 12345
            VerifiedFiles = @(); FailedFiles = @(); Errors = @(); Warnings = @()
        }
        $script:StartTime = (Get-Date).AddSeconds(-30)
    }

    It 'Export-HTMLReport writes a self-contained HTML report' {
        $outDir = Join-Path $TestDrive 'tbi-html'
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        Export-HTMLReport -OutputPath $outDir -Results @{ BackupInfo = @{ Size = 1024; FileCount = 5 } }
        $files = Get-ChildItem -Path $outDir -Filter 'integrity-report*.html' -ErrorAction SilentlyContinue
        $files.Count | Should -BeGreaterThan 0
    }

    It 'Export-JSONReport writes a JSON report containing Statistics' {
        $outDir = Join-Path $TestDrive 'tbi-json'
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        Export-JSONReport -OutputPath $outDir -Results @{ BackupInfo = @{ Size = 1024 } }
        $files = Get-ChildItem -Path $outDir -Filter 'integrity-report*.json' -ErrorAction SilentlyContinue
        $files.Count | Should -BeGreaterThan 0
        $payload = [System.IO.File]::ReadAllText($files[0].FullName) | ConvertFrom-Json
        $payload.Statistics.HashesMatched | Should -Be 5
    }
}

Describe 'Test-BackupIntegrity.ps1 - Invoke-BackupIntegrityTest (top level)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        $script:Stats = @{
            TotalFiles = 0; FilesVerified = 0; FilesFailed = 0
            HashesMatched = 0; HashesFailed = 0; TotalSize = 0
            VerifiedFiles = @(); FailedFiles = @(); Errors = @(); Warnings = @()
        }
        $script:StartTime = Get-Date
        $script:TempFolder = $null
    }

    It "Returns 1 immediately when TestType is 'Restore' without -RestoreTarget" {
        $result = Invoke-BackupIntegrityTest -BackupPath $script:TestArchive -TestType 'Restore'
        $result | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'RestoreTarget is required' }
    }

    It "Returns 0 on a Quick test against a valid archive" {
        $result = Invoke-BackupIntegrityTest -BackupPath $script:TestArchive -TestType 'Quick' -SamplePercent 100
        $result | Should -Be 0
    }

    It "Returns 1 when a fatal error escapes the try block" {
        Mock Get-BackupInfo { throw 'unexpected IO failure' }
        $result = Invoke-BackupIntegrityTest -BackupPath $script:TestArchive -TestType 'Quick'
        $result | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Fatal error' }
    }
}
