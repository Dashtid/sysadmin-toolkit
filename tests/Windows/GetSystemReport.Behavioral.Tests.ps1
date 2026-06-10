# Behavioral Pester tests for Get-SystemReport.ps1
# Run: Invoke-Pester -Path .\tests\Windows\GetSystemReport.Behavioral.Tests.ps1
#
# The script is dot-sourced (testability guard skips Invoke-SystemReport on
# dot-source). Each helper wraps its CIM/registry calls in try/catch so
# unmocked calls failing or returning unexpected shapes just leave that
# section absent from the result hashtable -- tests only assert on what
# they explicitly mocked.

BeforeAll {
    $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ScriptPath = Join-Path $ProjectRoot 'Windows\reporting\Get-SystemReport.ps1'
    . $ScriptPath
}

Describe 'Get-SystemReport.ps1 - Get-HardwareInfo' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Maps Win32_ComputerSystem fields to the ComputerSystem hashtable' {
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Name                      = 'WORKSTATION-1'
                Domain                    = 'CONTOSO'
                Manufacturer              = 'Dell Inc.'
                Model                     = 'XPS 15'
                SystemType                = 'x64-based PC'
                TotalPhysicalMemory       = 34359738368  # 32 GB
                NumberOfProcessors        = 1
                NumberOfLogicalProcessors = 16
            }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }

        # Stub the other CIM calls to throw — they just leave gaps in the hashtable.
        Mock Get-CimInstance { throw 'not mocked' } -ParameterFilter { $ClassName -ne 'Win32_ComputerSystem' }

        $hw = Get-HardwareInfo
        $hw.ComputerSystem.Name | Should -Be 'WORKSTATION-1'
        $hw.ComputerSystem.Manufacturer | Should -Be 'Dell Inc.'
        $hw.ComputerSystem.Model | Should -Be 'XPS 15'
        $hw.ComputerSystem.TotalPhysicalMemoryGB | Should -Be 32
        $hw.ComputerSystem.NumberOfLogicalProcessors | Should -Be 16
    }

    It 'Maps Architecture 9 to "x64" for CPUs' {
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    Name                      = 'Intel(R) Core(TM) i7'
                    Manufacturer              = 'GenuineIntel'
                    Description               = 'Intel64 Family'
                    MaxClockSpeed             = 3600
                    NumberOfCores             = 8
                    NumberOfLogicalProcessors = 16
                    L2CacheSize               = 256
                    L3CacheSize               = 16384
                    Architecture              = 9
                    SocketDesignation         = 'CPU 1'
                }
            )
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }
        Mock Get-CimInstance { throw 'not mocked' } -ParameterFilter { $ClassName -ne 'Win32_Processor' }

        $hw = Get-HardwareInfo
        $hw.CPU[0].Architecture | Should -Be 'x64'
        $hw.CPU[0].NumberOfCores | Should -Be 8
    }

    It 'Maps SMBIOSMemoryType 26 to "DDR4" and computes TotalMemoryGB' {
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    Manufacturer     = 'Corsair'
                    Capacity         = 17179869184   # 16 GB
                    Speed            = 3200
                    SMBIOSMemoryType = 26
                    FormFactor       = 8
                    DeviceLocator    = 'DIMM_A1'
                    PartNumber       = 'XYZ'
                }
                [PSCustomObject]@{
                    Manufacturer     = 'Corsair'
                    Capacity         = 17179869184
                    Speed            = 3200
                    SMBIOSMemoryType = 26
                    FormFactor       = 8
                    DeviceLocator    = 'DIMM_B1'
                    PartNumber       = 'XYZ'
                }
            )
        } -ParameterFilter { $ClassName -eq 'Win32_PhysicalMemory' }
        Mock Get-CimInstance { throw 'not mocked' } -ParameterFilter { $ClassName -ne 'Win32_PhysicalMemory' }

        $hw = Get-HardwareInfo
        $hw.Memory[0].MemoryType | Should -Be 'DDR4'
        $hw.Memory[0].FormFactor | Should -Be 'DIMM'
        $hw.TotalMemoryGB | Should -Be 32
    }

    It 'Computes FreePercent for logical disks' {
        # Win32_DiskDrive returns one drive, Win32_LogicalDisk returns one volume.
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                Model         = 'Samsung 970 EVO'
                InterfaceType = 'SCSI'
                MediaType     = 'Fixed hard disk media'
                Size          = 1000000000000
                Partitions    = 3
                SerialNumber  = 'ABC123'
                Status        = 'OK'
            })
        } -ParameterFilter { $ClassName -eq 'Win32_DiskDrive' }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                DeviceID   = 'C:'
                VolumeName = 'OS'
                FileSystem = 'NTFS'
                Size       = 500000000000
                FreeSpace  = 250000000000
            })
        } -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' }
        Mock Get-CimInstance { throw 'not mocked' } -ParameterFilter {
            $ClassName -notin @('Win32_DiskDrive', 'Win32_LogicalDisk')
        }

        $hw = Get-HardwareInfo
        $hw.Volumes[0].DriveLetter | Should -Be 'C:'
        $hw.Volumes[0].FreePercent | Should -Be 50
    }
}

Describe 'Get-SystemReport.ps1 - Get-SoftwareInfo' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
        Mock Write-Verbose { }
    }

    It 'Maps Win32_OperatingSystem fields and computes Uptime' {
        $boot = (Get-Date).AddDays(-3)
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Caption           = 'Microsoft Windows 11 Pro'
                Version           = '10.0.22631'
                BuildNumber       = '22631'
                OSArchitecture    = '64-bit'
                InstallDate       = (Get-Date).AddYears(-1)
                LastBootUpTime    = $boot
                RegisteredUser    = 'user'
                Organization      = ''
                WindowsDirectory  = 'C:\Windows'
                SystemDrive       = 'C:'
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-CimInstance { throw 'not mocked' } -ParameterFilter { $ClassName -ne 'Win32_OperatingSystem' }
        Mock Get-HotFix { throw 'no hotfixes' }
        Mock Get-ItemProperty { $null }
        Mock Test-IsAdministrator { $false }

        $sw = Get-SoftwareInfo
        $sw.OperatingSystem.Name | Should -Be 'Microsoft Windows 11 Pro'
        $sw.OperatingSystem.Version | Should -Be '10.0.22631'
        $sw.OperatingSystem.Uptime.Days | Should -Be 3
    }

    It 'Always populates the PowerShell section from $PSVersionTable' {
        Mock Get-CimInstance { throw 'not mocked' }
        Mock Get-HotFix { throw 'no hotfixes' }
        Mock Get-ItemProperty { $null }
        Mock Test-IsAdministrator { $false }

        $sw = Get-SoftwareInfo
        $sw.PowerShell.Version | Should -Not -BeNullOrEmpty
        $sw.PowerShell.Edition | Should -BeIn @('Core', 'Desktop')
    }
}

Describe 'Get-SystemReport.ps1 - Get-NetworkInfo' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Captures proxy settings from HKCU when present' {
        Mock Get-NetAdapter { throw 'no adapters' }
        Mock Get-DnsClient { throw 'no dns client' }
        Mock Get-NetRoute { throw 'no routes' }
        Mock Get-NetTCPConnection { throw 'no listeners' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                ProxyEnable   = 1
                ProxyServer   = 'corp-proxy:8080'
                ProxyOverride = '<local>'
                AutoConfigURL = $null
            }
        } -ParameterFilter { $Path -like '*Internet Settings*' }

        $net = Get-NetworkInfo
        $net.ProxySettings.ProxyEnabled | Should -Be $true
        $net.ProxySettings.ProxyServer | Should -Be 'corp-proxy:8080'
    }
}

Describe 'Get-SystemReport.ps1 - Get-SecurityInfo' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
        Mock Write-Verbose { }
        Mock Test-IsAdministrator { $false }
    }

    It 'Maps WindowsDefender RealTimeProtectionEnabled' {
        Mock Get-MpComputerStatus {
            [PSCustomObject]@{
                AMServiceEnabled              = $true
                AntispywareEnabled            = $true
                AntivirusEnabled              = $true
                RealTimeProtectionEnabled     = $true
                AntivirusSignatureLastUpdated = (Get-Date)
                AntivirusSignatureVersion     = '1.400.0.0'
                QuickScanEndTime              = (Get-Date)
                FullScanEndTime               = (Get-Date)
            }
        }
        Mock Get-NetFirewallProfile { throw 'no firewall' }
        Mock Get-LocalGroupMember { throw 'no admins' }
        Mock Get-ItemProperty { $null }

        $sec = Get-SecurityInfo
        $sec.WindowsDefender.RealTimeProtectionEnabled | Should -Be $true
    }

    It 'Maps UAC ConsentPromptBehaviorAdmin 5 to its descriptive string' {
        Mock Get-MpComputerStatus { $null }
        Mock Get-NetFirewallProfile { throw 'no firewall' }
        Mock Get-LocalGroupMember { throw 'no admins' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                EnableLUA                  = 1
                ConsentPromptBehaviorAdmin = 5
                PromptOnSecureDesktop      = 1
            }
        } -ParameterFilter { $Path -like '*Policies\System*' }
        Mock Get-ItemProperty { $null } -ParameterFilter { $Path -notlike '*Policies\System*' }

        $sec = Get-SecurityInfo
        $sec.UAC.Enabled | Should -Be $true
        $sec.UAC.ConsentPromptBehaviorAdmin | Should -Match 'non-Windows'
    }

    It 'Reports RemoteDesktop disabled when fDenyTSConnections is 1' {
        Mock Get-MpComputerStatus { $null }
        Mock Get-NetFirewallProfile { throw 'no firewall' }
        Mock Get-LocalGroupMember { throw 'no admins' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ fDenyTSConnections = 1 }
        } -ParameterFilter { $Path -like '*Terminal Server' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ UserAuthentication = 1 }
        } -ParameterFilter { $Path -like '*RDP-Tcp' }
        Mock Get-ItemProperty { $null } -ParameterFilter {
            $Path -notlike '*Terminal Server' -and $Path -notlike '*RDP-Tcp'
        }

        $sec = Get-SecurityInfo
        $sec.RemoteDesktop.Enabled | Should -Be $false
    }
}

Describe 'Get-SystemReport.ps1 - Get-PerformanceInfo' {
    BeforeEach {
        Mock Write-InfoMessage { }
        Mock Write-WarningMessage { }
    }

    It 'Captures CPU usage from Get-Counter and memory totals from Win32_OperatingSystem' {
        Mock Get-Counter {
            [PSCustomObject]@{
                CounterSamples = @([PSCustomObject]@{ CookedValue = 42.7 })
            }
        }
        Mock Get-CimInstance {
            [PSCustomObject]@{
                TotalVisibleMemorySize = 33554432   # KB = 32 GB
                FreePhysicalMemory     = 16777216   # KB = 16 GB
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-Process { @() }
        Mock Get-Service {
            @(
                [PSCustomObject]@{ Status = 'Running' }
                [PSCustomObject]@{ Status = 'Running' }
                [PSCustomObject]@{ Status = 'Stopped' }
            )
        }

        $perf = Get-PerformanceInfo
        $perf.CPUUsagePercent | Should -Be 42.7
        $perf.Memory.TotalGB | Should -Be 32
        $perf.Memory.UsedGB | Should -Be 16
        $perf.Memory.UsedPercent | Should -Be 50
        $perf.Services.Running | Should -Be 2
        $perf.Services.Stopped | Should -Be 1
        $perf.Services.Total | Should -Be 3
    }

    It 'Picks the top 10 processes by WorkingSet64' {
        Mock Get-Counter { throw 'no counter' }
        Mock Get-CimInstance { throw 'not mocked' }
        Mock Get-Service { @() }
        Mock Get-Process {
            $procs = @()
            for ($i = 1; $i -le 15; $i++) {
                $procs += [PSCustomObject]@{
                    ProcessName  = "proc$i"
                    Id           = $i
                    WorkingSet64 = $i * 1MB
                    CPU          = $i
                    HandleCount  = $i * 10
                }
            }
            $procs
        }

        $perf = Get-PerformanceInfo
        $perf.TopProcesses.Count | Should -Be 10
        # Sorted descending — process 15 has the largest WorkingSet64.
        $perf.TopProcesses[0].Name | Should -Be 'proc15'
    }
}

Describe 'Get-SystemReport.ps1 - Export-HtmlReport' {
    It 'Writes an HTML file with DOCTYPE, computer name, and section headers' {
        $outFile = Join-Path $TestDrive 'report.html'
        $reportData = [PSCustomObject]@{
            ComputerName = 'TESTHOST'
            ReportDate   = (Get-Date)
            Hardware     = @{
                ComputerSystem = [PSCustomObject]@{
                    Name = 'TESTHOST'; Manufacturer = 'Test'; Model = 'Model'; TotalPhysicalMemoryGB = 8
                    NumberOfLogicalProcessors = 4
                }
                CPU = @([PSCustomObject]@{ Name = 'Test CPU'; NumberOfCores = 4; Architecture = 'x64' })
                TotalMemoryGB = 8
                Volumes = @()
            }
            Software     = @{
                OperatingSystem = [PSCustomObject]@{
                    Name = 'Windows'; Version = '10.0'; BuildNumber = '22631'
                    Uptime = (New-TimeSpan -Days 1 -Hours 2)
                }
                InstalledApplicationsCount = 50
            }
            Network      = @{ Adapters = @() }
            Security     = @{}
            Performance  = @{
                CPUUsagePercent = 12.5
                Memory          = [PSCustomObject]@{ TotalGB = 8; UsedGB = 4; FreeGB = 4; UsedPercent = 50 }
                Services        = [PSCustomObject]@{ Total = 100; Running = 80; Stopped = 20 }
            }
        }

        Export-HtmlReport -ReportData $reportData -OutputFile $outFile

        Test-Path $outFile | Should -Be $true
        $content = Get-Content $outFile -Raw
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'TESTHOST'
        $content | Should -Match 'Test CPU'
    }
}
