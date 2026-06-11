# Behavioral Pester tests for Backup-BrowserProfiles.ps1
# Run: Invoke-Pester -Path .\tests\Windows\BackupBrowserProfiles.Behavioral.Tests.ps1
#
# Notes:
# - The script's param block has no Mandatory params (DefaultParameterSetName='Backup');
#   dot-source without args is fine.
# - Sprint 4.1/4.2 gotchas still apply: do not Mock Out-File for paths that need to write
#   (PS7's Out-File -Encoding UTF8 binding fails inside Pester's mock); let real Out-File
#   write into $TestDrive instead.
# - Helpers that previously read script params via dynamic scope (Get-BackupDirectory's
#   $OutputPath, Get-BackupList's call to Get-BackupDirectory) now take explicit params
#   so they are independently testable.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\backup\Backup-BrowserProfiles.ps1'
    . $ScriptPath
}

Describe 'Backup-BrowserProfiles.ps1 - Get-BackupDirectory' {
    It 'Uses the supplied -Path and creates it when missing' {
        $target = Join-Path $TestDrive 'custom-backup-dir'
        [System.IO.File]::Exists($target) | Should -BeFalse
        $result = Get-BackupDirectory -Path $target
        $result | Should -Be $target
        [System.IO.Directory]::Exists($target) | Should -BeTrue
    }

    It 'Falls back to <logdir>\browser-backups when -Path is empty' {
        Mock Get-LogDirectory { $TestDrive }
        Mock New-Item { } -Verifiable -ParameterFilter {
            $ItemType -eq 'Directory' -and $Path -like '*browser-backups*'
        }
        Mock Test-Path { $false }
        $result = Get-BackupDirectory
        $result | Should -BeLike '*browser-backups*'
        Should -InvokeVerifiable
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Test-BrowserInstalled' {
    It 'Returns $true for Chrome when the default profile path exists' {
        Mock Test-Path { $true } -ParameterFilter { $Path -like '*Google\Chrome\User Data\Default*' }
        Mock Test-Path { $false }
        Test-BrowserInstalled -BrowserKey 'Chrome' | Should -BeTrue
    }

    It 'Returns $false for Chrome when the default profile path is missing' {
        Mock Test-Path { $false }
        Test-BrowserInstalled -BrowserKey 'Chrome' | Should -BeFalse
    }

    It 'Probes profiles.ini (not the default-profile path) for Firefox' {
        Mock Test-Path { $true } -Verifiable -ParameterFilter { $Path -like '*Firefox\profiles.ini*' }
        Mock Test-Path { $false }
        Test-BrowserInstalled -BrowserKey 'Firefox' | Should -BeTrue
        Should -InvokeVerifiable
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Get-FirefoxProfiles' {
    It 'Returns an empty list when profiles.ini does not exist' {
        Mock Test-Path { $false }
        @(Get-FirefoxProfiles).Count | Should -Be 0
    }

    It 'Parses a relative profile path and joins it under %APPDATA%\Mozilla\Firefox' {
        Mock Test-Path { $true } -ParameterFilter { $Path -like '*profiles.ini*' }
        Mock Test-Path { $true }  # Resolved profile path exists too.
        Mock Get-Content {
            @"
[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/abc123.default-release
Default=1
"@
        }
        $profiles = @(Get-FirefoxProfiles)
        $profiles.Count | Should -Be 1
        # Join-Path may normalize forward slashes to backslashes, so match either.
        $profiles[0] | Should -Match 'Mozilla\\Firefox\\Profiles[\\/]abc123\.default-release'
    }

    It 'Honors IsRelative=0 (absolute) profile paths' {
        Mock Test-Path { $true }
        Mock Get-Content {
            @"
[Profile1]
Name=custom
IsRelative=0
Path=D:\FirefoxProfiles\custom
"@
        }
        $profiles = @(Get-FirefoxProfiles)
        $profiles | Should -Contain 'D:\FirefoxProfiles\custom'
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Get-BrowserExtensions' {
    It 'Returns an empty list when the Extensions directory does not exist (Chrome)' {
        Mock Test-Path { $false }
        @(Get-BrowserExtensions -BrowserKey 'Chrome' -ProfilePath 'C:\nope').Count | Should -Be 0
    }

    It 'Parses extension manifest.json files for Chrome/Edge/Brave' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            if ($Directory) {
                @(
                    [PSCustomObject]@{ Name = 'ext1'; FullName = 'C:\fake\ext1' }
                )
            }
            elseif ($Filter -eq 'manifest.json') {
                @([PSCustomObject]@{ FullName = 'C:\fake\ext1\1.0\manifest.json' })
            }
        }
        Mock Get-Content { '{ "name": "My Extension", "version": "1.2.3" }' }
        $exts = @(Get-BrowserExtensions -BrowserKey 'Chrome' -ProfilePath 'C:\fake')
        $exts.Count | Should -Be 1
        $exts[0].Name | Should -Be 'My Extension'
        $exts[0].Version | Should -Be '1.2.3'
    }

    It 'Falls back to the extension folder name when manifest.json is corrupt' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            if ($Directory) {
                @([PSCustomObject]@{ Name = 'corrupt'; FullName = 'C:\fake\corrupt' })
            }
            elseif ($Filter -eq 'manifest.json') {
                @([PSCustomObject]@{ FullName = 'C:\fake\corrupt\manifest.json' })
            }
        }
        Mock Get-Content { 'not json' }
        $exts = @(Get-BrowserExtensions -BrowserKey 'Chrome' -ProfilePath 'C:\fake')
        $exts.Count | Should -Be 1
        $exts[0].Name | Should -Be 'corrupt'
        $exts[0].Version | Should -Be 'Unknown'
    }

    It "Falls back to the folder name when the manifest's name starts with __MSG_ (locale placeholder)" {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            if ($Directory) {
                @([PSCustomObject]@{ Name = 'localized'; FullName = 'C:\fake\localized' })
            }
            elseif ($Filter -eq 'manifest.json') {
                @([PSCustomObject]@{ FullName = 'C:\fake\localized\manifest.json' })
            }
        }
        Mock Get-Content { '{ "name": "__MSG_extName__", "version": "2.0" }' }
        $exts = @(Get-BrowserExtensions -BrowserKey 'Chrome' -ProfilePath 'C:\fake')
        $exts[0].Name | Should -Be 'localized'
        $exts[0].Version | Should -Be '2.0'
    }

    It 'Lists Firefox extension files by BaseName' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ BaseName = '{uuid-1}'; FullName = 'C:\fake\{uuid-1}.xpi' }
                [PSCustomObject]@{ BaseName = 'addon@example'; FullName = 'C:\fake\addon@example.xpi' }
            )
        }
        $exts = @(Get-BrowserExtensions -BrowserKey 'Firefox' -ProfilePath 'C:\fake')
        $exts.Count | Should -Be 2
        $exts[0].Version | Should -Be 'Unknown'
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Export-BookmarksToHtml' {
    It 'Writes a Netscape-bookmark-file-1 doctype with parsed Chrome bookmarks' {
        $outFile = Join-Path $TestDrive 'bookmarks.html'
        Mock Test-Path { $true }
        # Filter the Get-Content mock so it only intercepts the script's Bookmarks-file
        # read, not the test-side verification read of the output HTML.
        Mock Get-Content {
            @'
{
  "roots": {
    "bookmark_bar": {
      "children": [
        { "type": "url", "name": "Google", "url": "https://google.com" }
      ]
    },
    "other": {
      "children": []
    }
  }
}
'@
        } -ParameterFilter { $Path -notmatch '\.html$' }
        Export-BookmarksToHtml -BrowserKey 'Chrome' -ProfilePath 'C:\fake' -OutputFile $outFile
        [System.IO.File]::Exists($outFile) | Should -BeTrue
        # Read via .NET so the test verification bypasses the mocked Get-Content.
        $content = [System.IO.File]::ReadAllText($outFile)
        $content | Should -Match 'NETSCAPE-Bookmark-file-1'
        $content | Should -Match 'Google'
        $content | Should -Match 'https://google.com'
    }

    It 'Emits a Firefox info line and writes the placeholder file even when bookmarks are not parsed' {
        $outFile = Join-Path $TestDrive 'firefox-bookmarks.html'
        Mock Write-InfoMessage { }
        Export-BookmarksToHtml -BrowserKey 'Firefox' -ProfilePath 'C:\fake' -OutputFile $outFile
        Should -Invoke Write-InfoMessage -ParameterFilter { $Message -match 'SQLite' }
        [System.IO.File]::Exists($outFile) | Should -BeTrue
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Backup-BrowserProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Get-BrowserExtensions { @() }
        Mock Export-BookmarksToHtml { }
    }

    It 'Copies Bookmarks / Preferences / Local State for Chrome and returns Success=$true' {
        $backupDir = Join-Path $TestDrive 'chrome-backup'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Mock Test-Path { $true }
        Mock Copy-Item { }
        # Real New-Item creates the per-backup folder so the metadata Out-File at the end succeeds.
        $result = Backup-BrowserProfile -BrowserKey 'Chrome' -BackupDir $backupDir
        $result.Success | Should -Be $true
        $result.FilesBackedUp | Should -Contain 'Bookmarks'
        $result.FilesBackedUp | Should -Contain 'Preferences'
        $result.FilesBackedUp | Should -Contain 'Local State'
    }

    It 'Skips History/Cookies by default and includes them when the switches are passed' {
        $backupDir = Join-Path $TestDrive 'chrome-include'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Mock Test-Path { $true }
        Mock Copy-Item { }
        $result = Backup-BrowserProfile -BrowserKey 'Chrome' -BackupDir $backupDir -IncludeCookies -IncludeHistory
        $result.FilesBackedUp | Should -Contain 'History'
        $result.FilesBackedUp | Should -Contain 'Cookies'
    }

    It 'Sets Success=$false and records Error when an inner step throws' {
        $backupDir = Join-Path $TestDrive 'chrome-throw'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Mock Test-Path { $true }
        # Copy-Item throws on the first call (Bookmarks copy) which propagates into the try block.
        Mock Copy-Item { throw 'access denied' }
        $result = Backup-BrowserProfile -BrowserKey 'Chrome' -BackupDir $backupDir
        $result.Success | Should -Be $false
        $result.Error | Should -Match 'access denied'
    }

    It 'Iterates each Firefox profile from Get-FirefoxProfiles' {
        $backupDir = Join-Path $TestDrive 'firefox-multi'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Mock Get-FirefoxProfiles { @('C:\ff\profileA', 'C:\ff\profileB') }
        Mock Test-Path { $true }
        Mock Copy-Item { } -Verifiable
        $result = Backup-BrowserProfile -BrowserKey 'Firefox' -BackupDir $backupDir
        $result.Success | Should -Be $true
        # 8 base files * 2 profiles = up to 16 Copy-Item calls when every Test-Path returns true.
        Should -Invoke Copy-Item -Times 16
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Compress-BackupFolder (browser helper)' {
    BeforeEach {
        Mock Write-Success { }
        Mock Write-WarningMessage { }
    }

    It 'Compresses to a .zip alongside the source folder and removes the original by default' {
        Mock Test-Path { $true }
        Mock Compress-Archive { } -Verifiable
        Mock Remove-Item { } -Verifiable -ParameterFilter { $Path -eq 'C:\src' -and $Recurse }
        $result = Compress-BackupFolder -FolderPath 'C:\src'
        $result | Should -Be 'C:\src.zip'
        Should -InvokeVerifiable
    }

    It 'Returns the original folder path and warns when Compress-Archive throws' {
        Mock Test-Path { $false }
        Mock Compress-Archive { throw 'disk full' }
        $result = Compress-BackupFolder -FolderPath 'C:\src'
        $result | Should -Be 'C:\src'
        Should -Invoke Write-WarningMessage
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Remove-OldBackups (browser helper)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Returns early without enumerating when -RetentionDays is 0' {
        Mock Get-ChildItem { throw 'should not be called' }
        { Remove-OldBackups -BackupDir 'C:\b' -RetentionDays 0 } | Should -Not -Throw
        Should -Invoke Get-ChildItem -Times 0
    }

    It 'Removes only zip backups whose LastWriteTime is older than the cutoff' {
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ Name = 'Chrome_recent.zip'; FullName = 'C:\b\Chrome_recent.zip'; LastWriteTime = (Get-Date).AddDays(-1) }
                [PSCustomObject]@{ Name = 'Chrome_old.zip';    FullName = 'C:\b\Chrome_old.zip';    LastWriteTime = (Get-Date).AddDays(-90) }
            )
        }
        $script:RemovedNames = @()
        Mock Remove-Item { $script:RemovedNames += (Split-Path $Path -Leaf) }
        Remove-OldBackups -BackupDir 'C:\b' -RetentionDays 30
        $script:RemovedNames | Should -Contain 'Chrome_old.zip'
        $script:RemovedNames | Should -Not -Contain 'Chrome_recent.zip'
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Get-BackupList' {
    It 'Parses filenames matching [Browser]_[yyyy-MM-dd_HHmmss].zip into PSCustomObject rows' {
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ Name = 'Chrome_2026-01-15_103045.zip'; FullName = 'C:\b\Chrome_2026-01-15_103045.zip'; Length = 2MB }
                [PSCustomObject]@{ Name = 'Edge_2026-02-01_120000.zip';   FullName = 'C:\b\Edge_2026-02-01_120000.zip';   Length = 5MB }
            )
        }
        $list = @(Get-BackupList -BackupDir 'C:\b')
        $list.Count | Should -Be 2
        # Sorted Descending so Edge (Feb 1) comes before Chrome (Jan 15).
        $list[0].Browser | Should -Be 'Edge'
        $list[1].Browser | Should -Be 'Chrome'
        $list[0].SizeMB | Should -Be 5.0
    }

    It 'Skips filenames that do not match the expected pattern' {
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ Name = 'unrelated.zip'; FullName = 'C:\b\unrelated.zip'; Length = 1KB }
            )
        }
        @(Get-BackupList -BackupDir 'C:\b').Count | Should -Be 0
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Restore-BrowserProfile' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
    }

    It 'Returns $false when the backup archive does not exist' {
        Mock Test-Path { $false } -ParameterFilter { $Path -eq 'C:\missing.zip' }
        Mock Test-Path { $true }
        Restore-BrowserProfile -BackupPath 'C:\missing.zip' -TargetBrowser 'Chrome' | Should -Be $false
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'Backup file not found' }
    }

    It 'Returns $false when no Firefox profile is present on the target system' {
        Mock Test-Path { $true } -ParameterFilter { $Path -eq 'C:\b.zip' }
        Mock Expand-Archive { }
        Mock Get-FirefoxProfiles { @() }
        Restore-BrowserProfile -BackupPath 'C:\b.zip' -TargetBrowser 'Firefox' | Should -Be $false
    }

    It 'Cleans up the temp extract directory in the finally block on success' {
        Mock Test-Path { $true }
        Mock Expand-Archive { }
        Mock Get-ChildItem { @() }  # No files to restore in this minimal scenario.
        Mock Remove-Item { } -Verifiable -ParameterFilter { $Path -like '*browser_restore_*' -and $Recurse }
        Restore-BrowserProfile -BackupPath 'C:\b.zip' -TargetBrowser 'Chrome' | Out-Null
        Should -InvokeVerifiable
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Export-HtmlReport' {
    It 'Writes a self-contained HTML report with backup result details' {
        $outFile = Join-Path $TestDrive 'browser-report.html'
        $results = @(
            [PSCustomObject]@{
                Browser       = 'Google Chrome'
                BrowserKey    = 'Chrome'
                Success       = $true
                FilesBackedUp = @('Bookmarks', 'Preferences')
                Extensions    = @(
                    [PSCustomObject]@{ Name = 'Ext A'; Version = '1.0' }
                )
                BackupPath    = 'C:\b\Chrome_x.zip'
                Timestamp     = '2026-06-11_120000'
                Error         = $null
            }
        )
        Export-HtmlReport -Results $results -OutputPath $outFile
        [System.IO.File]::Exists($outFile) | Should -BeTrue
        $content = Get-Content -Raw -LiteralPath $outFile
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'Google Chrome'
        $content | Should -Match 'Ext A'
    }
}

Describe 'Backup-BrowserProfiles.ps1 - Invoke-BrowserProfileBackup (top level)' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-Success { }
        Mock Write-WarningMessage { }
        Mock Write-ErrorMessage { }
        Mock Write-Host { }
        Mock Get-BackupDirectory { Join-Path $TestDrive 'inv-backup' }
        Mock Test-BrowserInstalled { $false }   # No browsers installed by default
    }

    It 'Returns 0 immediately in -ListBackups mode when no backups exist' {
        Mock Get-BackupList { @() }
        Invoke-BrowserProfileBackup -ListBackups | Should -Be 0
    }

    It 'Returns 0 and prints a row per backup when -ListBackups finds matches' {
        Mock Get-BackupList {
            @(
                [PSCustomObject]@{
                    FileName = 'Chrome_2026-01-15_103045.zip'
                    Browser  = 'Chrome'
                    BackupDate = [DateTime]'2026-01-15T10:30:45'
                    SizeMB   = 2.0
                    FullPath = 'C:\b\Chrome_2026-01-15_103045.zip'
                }
            )
        }
        Invoke-BrowserProfileBackup -ListBackups | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -match 'Chrome' }
    }

    It "Returns 1 when -Restore is used without -RestoreTarget" {
        Invoke-BrowserProfileBackup -Restore 'C:\b.zip' | Should -Be 1
        Should -Invoke Write-ErrorMessage -ParameterFilter { $Message -match 'RestoreTarget' }
    }

    It 'Returns 2 when in backup mode and no browser is installed' {
        # All browsers fail Test-BrowserInstalled -> 0 results -> exitCode = 2.
        Invoke-BrowserProfileBackup -Browser 'All' -RetentionDays 0 | Should -Be 2
        Should -Invoke Write-WarningMessage -ParameterFilter { $Message -match 'not installed' }
    }

    It 'Writes the PASSWORD_REMINDER.txt file when -IncludePasswords is set' {
        $backupDir = Join-Path $TestDrive 'inv-backup'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Mock Test-BrowserInstalled { $false }
        Invoke-BrowserProfileBackup -Browser 'Chrome' -IncludePasswords -RetentionDays 0 | Out-Null
        [System.IO.File]::Exists((Join-Path $backupDir 'PASSWORD_REMINDER.txt')) | Should -BeTrue
    }
}
