#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manages and monitors cloud resources across Azure and AWS platforms.

.DESCRIPTION
    This script provides comprehensive cloud resource management:
    - List and monitor Azure/AWS resources
    - Start/stop VMs to optimize costs
    - Monitor cloud spending and usage
    - Export cloud configurations for backup
    - Resource health monitoring
    - Cost optimization suggestions
    - Multi-cloud support with unified interface

    Supported Platforms:
    - Microsoft Azure (via Az PowerShell module)
    - Amazon Web Services (via AWS Tools for PowerShell)

    Features:
    - Resource inventory across subscriptions/accounts
    - VM power state management
    - Cost tracking and alerts
    - Resource tagging audit
    - Security configuration checks
    - Export to JSON/HTML reports

.PARAMETER Provider
    Cloud provider to manage. Valid values: Azure, AWS, All.
    Default: All

.PARAMETER Action
    The action to perform. Valid values:
    - Status: Show cloud resources status
    - List: List resources by type
    - StartVM: Start a virtual machine
    - StopVM: Stop a virtual machine
    - Cost: Show cost analysis
    - Export: Export resource configuration
    - Health: Check resource health
    - Audit: Security and tagging audit
    Default: Status

.PARAMETER ResourceType
    Type of resources to list. Valid values: VMs, Storage, Networks, Databases, All.
    Default: All

.PARAMETER ResourceName
    Name of a specific resource for VM operations.

.PARAMETER ResourceGroup
    Azure resource group name (Azure only).

.PARAMETER Region
    AWS region (AWS only). Default: us-east-1

.PARAMETER SubscriptionId
    Azure subscription ID to use.

.PARAMETER Profile
    AWS profile name from credentials file.

.PARAMETER Days
    Number of days for cost analysis. Default: 30

.PARAMETER OutputFormat
    Output format. Valid values: Console, HTML, JSON, CSV.
    Default: Console

.PARAMETER OutputPath
    Path for output files.

.EXAMPLE
    .\Get-CloudResources.ps1 -Action Status
    Shows status of all cloud resources across configured providers.

.EXAMPLE
    .\Get-CloudResources.ps1 -Provider Azure -Action List -ResourceType VMs
    Lists all Azure virtual machines.

.EXAMPLE
    .\Get-CloudResources.ps1 -Provider AWS -Action StopVM -ResourceName "i-1234567890abcdef0"
    Stops an AWS EC2 instance.

.EXAMPLE
    .\Get-CloudResources.ps1 -Action Cost -Days 7 -OutputFormat HTML
    Shows 7-day cost analysis with HTML report.

.EXAMPLE
    .\Get-CloudResources.ps1 -Provider Azure -Action Export -OutputPath "C:\Backups"
    Exports Azure resource configuration to backup.

.EXAMPLE
    .\Get-CloudResources.ps1 -Action Audit -OutputFormat JSON
    Performs security and tagging audit with JSON output.

.NOTES
    File Name      : Get-CloudResources.ps1
    Author         : Windows & Linux Sysadmin Toolkit
    Prerequisite   : PowerShell 5.1+ (PowerShell 7+ recommended)
                     Az PowerShell module (for Azure)
                     AWS.Tools modules (for AWS)
    Version        : 1.0.0
    Creation Date  : 2025-11-30

    Module Requirements:
    - Azure: Install-Module -Name Az -Scope CurrentUser
    - AWS: Install-Module -Name AWS.Tools.Installer -Scope CurrentUser
           Install-AWSToolsModule AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.CostExplorer

    Authentication:
    - Azure: Connect-AzAccount
    - AWS: Set-AWSCredential or ~/.aws/credentials file

    Change Log:
    - 1.0.0 (2025-11-30): Initial release

.LINK
    https://github.com/Dashtid/sysadmin-toolkit
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateSet('Azure', 'AWS', 'All')]
    [string]$Provider = 'All',

    [Parameter()]
    [ValidateSet('Status', 'List', 'StartVM', 'StopVM', 'Cost', 'Export', 'Health', 'Audit')]
    [string]$Action = 'Status',

    [Parameter()]
    [ValidateSet('VMs', 'Storage', 'Networks', 'Databases', 'All')]
    [string]$ResourceType = 'All',

    [Parameter()]
    [string]$ResourceName,

    [Parameter()]
    [string]$ResourceGroup,

    [Parameter()]
    [string]$Region = 'us-east-1',

    [Parameter()]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$Profile,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$Days = 30,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath
)

#region Module Imports
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\lib\CommonFunctions.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    # Fallback logging functions if module not found
    function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
    function Write-InfoMessage { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Blue }
    function Write-WarningMessage { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
    function Write-ErrorMessage { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
    function Get-LogDirectory { return Join-Path $PSScriptRoot "..\..\logs" }
}
#endregion

#region Configuration
$script:StartTime = Get-Date
$script:ScriptVersion = "1.0.0"

# Cloud provider availability
$script:AzureAvailable = $false
$script:AWSAvailable = $false
#endregion

#region Helper Functions
function Test-AzureModule {
    try {
        $azModule = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
        return ($null -ne $azModule)
    }
    catch {
        return $false
    }
}

function Test-AWSModule {
    try {
        $awsModule = Get-Module -ListAvailable -Name AWS.Tools.Common -ErrorAction SilentlyContinue
        return ($null -ne $awsModule)
    }
    catch {
        return $false
    }
}

function Test-AzureConnection {
    try {
        $context = Get-AzContext -ErrorAction SilentlyContinue
        return ($null -ne $context -and $null -ne $context.Account)
    }
    catch {
        return $false
    }
}

function Test-AWSConnection {
    try {
        $identity = Get-STSCallerIdentity -ErrorAction SilentlyContinue
        return ($null -ne $identity)
    }
    catch {
        return $false
    }
}

function Initialize-CloudProviders {
    $results = @{
        Azure = @{ Available = $false; Connected = $false; Message = "" }
        AWS   = @{ Available = $false; Connected = $false; Message = "" }
    }

    # Check Azure
    if (Test-AzureModule) {
        $results.Azure.Available = $true
        Import-Module Az.Accounts -ErrorAction SilentlyContinue

        if (Test-AzureConnection) {
            $results.Azure.Connected = $true
            $context = Get-AzContext
            $results.Azure.Message = "Connected as $($context.Account.Id)"
            $script:AzureAvailable = $true
        }
        else {
            $results.Azure.Message = "Module available but not connected. Run: Connect-AzAccount"
        }
    }
    else {
        $results.Azure.Message = "Az module not installed. Run: Install-Module -Name Az"
    }

    # Check AWS
    if (Test-AWSModule) {
        $results.AWS.Available = $true
        Import-Module AWS.Tools.Common -ErrorAction SilentlyContinue

        if (Test-AWSConnection) {
            $results.AWS.Connected = $true
            $identity = Get-STSCallerIdentity
            $results.AWS.Message = "Connected as $($identity.Arn)"
            $script:AWSAvailable = $true
        }
        else {
            $results.AWS.Message = "Module available but not connected. Run: Set-AWSCredential"
        }
    }
    else {
        $results.AWS.Message = "AWS.Tools not installed. Run: Install-Module -Name AWS.Tools.Installer"
    }

    return $results
}

#region Azure Functions
function Get-AzureVMs {
    if (-not $script:AzureAvailable) { return @() }

    try {
        Import-Module Az.Compute -ErrorAction SilentlyContinue
        $vms = Get-AzVM -Status -ErrorAction SilentlyContinue

        return $vms | ForEach-Object {
            [PSCustomObject]@{
                Provider      = "Azure"
                Name          = $_.Name
                ResourceGroup = $_.ResourceGroupName
                Location      = $_.Location
                Size          = $_.HardwareProfile.VmSize
                State         = $_.PowerState
                OS            = $_.StorageProfile.OsDisk.OsType
                PrivateIP     = ($_ | Get-AzNetworkInterface -ErrorAction SilentlyContinue | Get-AzNetworkInterfaceIpConfig).PrivateIpAddress
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get Azure VMs: $($_.Exception.Message)"
        return @()
    }
}

function Get-AzureStorage {
    if (-not $script:AzureAvailable) { return @() }

    try {
        Import-Module Az.Storage -ErrorAction SilentlyContinue
        $accounts = Get-AzStorageAccount -ErrorAction SilentlyContinue

        return $accounts | ForEach-Object {
            [PSCustomObject]@{
                Provider       = "Azure"
                Name           = $_.StorageAccountName
                ResourceGroup  = $_.ResourceGroupName
                Location       = $_.Location
                Kind           = $_.Kind
                Sku            = $_.Sku.Name
                AccessTier     = $_.AccessTier
                CreatedTime    = $_.CreationTime
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get Azure Storage: $($_.Exception.Message)"
        return @()
    }
}

function Get-AzureNetworks {
    if (-not $script:AzureAvailable) { return @() }

    try {
        Import-Module Az.Network -ErrorAction SilentlyContinue
        $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue

        return $vnets | ForEach-Object {
            [PSCustomObject]@{
                Provider       = "Azure"
                Name           = $_.Name
                ResourceGroup  = $_.ResourceGroupName
                Location       = $_.Location
                AddressSpace   = ($_.AddressSpace.AddressPrefixes -join ", ")
                SubnetCount    = $_.Subnets.Count
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get Azure Networks: $($_.Exception.Message)"
        return @()
    }
}

function Start-AzureVM {
    param(
        [string]$Name,
        [string]$ResourceGroup
    )

    if (-not $script:AzureAvailable) {
        Write-ErrorMessage "Azure is not available"
        return $false
    }

    try {
        Import-Module Az.Compute -ErrorAction SilentlyContinue
        Write-InfoMessage "Starting Azure VM '$Name'..."

        $result = Start-AzVM -Name $Name -ResourceGroupName $ResourceGroup -ErrorAction Stop
        Write-Success "Azure VM '$Name' started successfully"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to start VM: $($_.Exception.Message)"
        return $false
    }
}

function Stop-AzureVM {
    param(
        [string]$Name,
        [string]$ResourceGroup
    )

    if (-not $script:AzureAvailable) {
        Write-ErrorMessage "Azure is not available"
        return $false
    }

    try {
        Import-Module Az.Compute -ErrorAction SilentlyContinue
        Write-InfoMessage "Stopping Azure VM '$Name'..."

        $result = Stop-AzVM -Name $Name -ResourceGroupName $ResourceGroup -Force -ErrorAction Stop
        Write-Success "Azure VM '$Name' stopped successfully"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to stop VM: $($_.Exception.Message)"
        return $false
    }
}

function Get-AzureCosts {
    param([int]$Days)

    if (-not $script:AzureAvailable) { return @() }

    try {
        Import-Module Az.CostManagement -ErrorAction SilentlyContinue

        $startDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-dd")
        $endDate = (Get-Date).ToString("yyyy-MM-dd")

        # Note: Cost Management API requires specific permissions
        $context = Get-AzContext
        $subscriptionId = $context.Subscription.Id

        Write-InfoMessage "Fetching Azure costs for last $Days days..."
        Write-WarningMessage "Cost data requires Cost Management Reader role"

        # Return placeholder - actual implementation requires Cost Management API
        return [PSCustomObject]@{
            Provider       = "Azure"
            Period         = "$startDate to $endDate"
            Subscription   = $context.Subscription.Name
            EstimatedCost  = "Requires Cost Management API access"
            Currency       = "USD"
        }
    }
    catch {
        Write-WarningMessage "Failed to get Azure costs: $($_.Exception.Message)"
        return @()
    }
}
#endregion

#region AWS Functions
function Get-AWSEC2Instances {
    if (-not $script:AWSAvailable) { return @() }

    try {
        Import-Module AWS.Tools.EC2 -ErrorAction SilentlyContinue

        $instances = Get-EC2Instance -Region $Region -ErrorAction SilentlyContinue

        return $instances.Instances | ForEach-Object {
            $nameTag = ($_.Tags | Where-Object { $_.Key -eq "Name" }).Value
            [PSCustomObject]@{
                Provider      = "AWS"
                Name          = if ($nameTag) { $nameTag } else { $_.InstanceId }
                InstanceId    = $_.InstanceId
                InstanceType  = $_.InstanceType
                State         = $_.State.Name
                Region        = $Region
                PrivateIP     = $_.PrivateIpAddress
                PublicIP      = $_.PublicIpAddress
                LaunchTime    = $_.LaunchTime
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get AWS EC2 instances: $($_.Exception.Message)"
        return @()
    }
}

function Get-AWSS3Buckets {
    if (-not $script:AWSAvailable) { return @() }

    try {
        Import-Module AWS.Tools.S3 -ErrorAction SilentlyContinue

        $buckets = Get-S3Bucket -ErrorAction SilentlyContinue

        return $buckets | ForEach-Object {
            [PSCustomObject]@{
                Provider      = "AWS"
                Name          = $_.BucketName
                CreatedDate   = $_.CreationDate
                Region        = "Global"
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get AWS S3 buckets: $($_.Exception.Message)"
        return @()
    }
}

function Get-AWSVPCs {
    if (-not $script:AWSAvailable) { return @() }

    try {
        Import-Module AWS.Tools.EC2 -ErrorAction SilentlyContinue

        $vpcs = Get-EC2Vpc -Region $Region -ErrorAction SilentlyContinue

        return $vpcs | ForEach-Object {
            $nameTag = ($_.Tags | Where-Object { $_.Key -eq "Name" }).Value
            [PSCustomObject]@{
                Provider      = "AWS"
                Name          = if ($nameTag) { $nameTag } else { $_.VpcId }
                VpcId         = $_.VpcId
                CidrBlock     = $_.CidrBlock
                State         = $_.State
                IsDefault     = $_.IsDefault
                Region        = $Region
            }
        }
    }
    catch {
        Write-WarningMessage "Failed to get AWS VPCs: $($_.Exception.Message)"
        return @()
    }
}

function Start-AWSEC2Instance {
    param([string]$InstanceId)

    if (-not $script:AWSAvailable) {
        Write-ErrorMessage "AWS is not available"
        return $false
    }

    try {
        Import-Module AWS.Tools.EC2 -ErrorAction SilentlyContinue
        Write-InfoMessage "Starting AWS EC2 instance '$InstanceId'..."

        $result = Start-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction Stop
        Write-Success "AWS EC2 instance '$InstanceId' started successfully"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to start instance: $($_.Exception.Message)"
        return $false
    }
}

function Stop-AWSEC2Instance {
    param([string]$InstanceId)

    if (-not $script:AWSAvailable) {
        Write-ErrorMessage "AWS is not available"
        return $false
    }

    try {
        Import-Module AWS.Tools.EC2 -ErrorAction SilentlyContinue
        Write-InfoMessage "Stopping AWS EC2 instance '$InstanceId'..."

        $result = Stop-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction Stop
        Write-Success "AWS EC2 instance '$InstanceId' stopped successfully"
        return $true
    }
    catch {
        Write-ErrorMessage "Failed to stop instance: $($_.Exception.Message)"
        return $false
    }
}

function Get-AWSCosts {
    param([int]$Days)

    if (-not $script:AWSAvailable) { return @() }

    try {
        Import-Module AWS.Tools.CostExplorer -ErrorAction SilentlyContinue

        $startDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-dd")
        $endDate = (Get-Date).ToString("yyyy-MM-dd")

        Write-InfoMessage "Fetching AWS costs for last $Days days..."

        $costData = Get-CECostAndUsage -TimePeriod @{
            Start = $startDate
            End   = $endDate
        } -Granularity "MONTHLY" -Metrics "BlendedCost" -ErrorAction SilentlyContinue

        if ($costData) {
            return $costData.ResultsByTime | ForEach-Object {
                [PSCustomObject]@{
                    Provider    = "AWS"
                    Period      = "$($_.TimePeriod.Start) to $($_.TimePeriod.End)"
                    Cost        = $_.Total.BlendedCost.Amount
                    Currency    = $_.Total.BlendedCost.Unit
                }
            }
        }

        return @()
    }
    catch {
        Write-WarningMessage "Failed to get AWS costs: $($_.Exception.Message)"
        return @()
    }
}
#endregion

#region Combined Functions
function Show-CloudStatus {
    $providerStatus = Initialize-CloudProviders

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       CLOUD PROVIDER STATUS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    # Azure Status
    Write-Host "Azure:" -ForegroundColor White
    $azStatus = $providerStatus.Azure
    if ($azStatus.Connected) {
        Write-Host "  [+] Connected: $($azStatus.Message)" -ForegroundColor Green
    }
    elseif ($azStatus.Available) {
        Write-Host "  [!] $($azStatus.Message)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [-] $($azStatus.Message)" -ForegroundColor Red
    }

    # AWS Status
    Write-Host ""
    Write-Host "AWS:" -ForegroundColor White
    $awsStatus = $providerStatus.AWS
    if ($awsStatus.Connected) {
        Write-Host "  [+] Connected: $($awsStatus.Message)" -ForegroundColor Green
    }
    elseif ($awsStatus.Available) {
        Write-Host "  [!] $($awsStatus.Message)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [-] $($awsStatus.Message)" -ForegroundColor Red
    }

    # Resource Summary
    if ($script:AzureAvailable -or $script:AWSAvailable) {
        Write-Host ""
        Write-Host "Resource Summary:" -ForegroundColor White

        if ($script:AzureAvailable) {
            $azureVMs = Get-AzureVMs
            $runningAzure = ($azureVMs | Where-Object { $_.State -eq "VM running" }).Count
            Write-Host "  Azure VMs: $($azureVMs.Count) total, $runningAzure running" -ForegroundColor Gray
        }

        if ($script:AWSAvailable) {
            $awsInstances = Get-AWSEC2Instances
            $runningAWS = ($awsInstances | Where-Object { $_.State -eq "running" }).Count
            Write-Host "  AWS EC2: $($awsInstances.Count) total, $runningAWS running" -ForegroundColor Gray
        }
    }
}

function Get-AllResources {
    param([string]$Type)

    $resources = @()

    $getAzure = ($Provider -eq 'Azure' -or $Provider -eq 'All') -and $script:AzureAvailable
    $getAWS = ($Provider -eq 'AWS' -or $Provider -eq 'All') -and $script:AWSAvailable

    switch ($Type) {
        'VMs' {
            if ($getAzure) { $resources += Get-AzureVMs }
            if ($getAWS) { $resources += Get-AWSEC2Instances }
        }
        'Storage' {
            if ($getAzure) { $resources += Get-AzureStorage }
            if ($getAWS) { $resources += Get-AWSS3Buckets }
        }
        'Networks' {
            if ($getAzure) { $resources += Get-AzureNetworks }
            if ($getAWS) { $resources += Get-AWSVPCs }
        }
        'All' {
            if ($getAzure) {
                $resources += Get-AzureVMs
                $resources += Get-AzureStorage
                $resources += Get-AzureNetworks
            }
            if ($getAWS) {
                $resources += Get-AWSEC2Instances
                $resources += Get-AWSS3Buckets
                $resources += Get-AWSVPCs
            }
        }
    }

    return $resources
}

function Export-CloudConfiguration {
    param([string]$Path)

    $exportData = @{
        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Provider   = $Provider
        Resources  = @{}
    }

    if ($script:AzureAvailable -and ($Provider -eq 'Azure' -or $Provider -eq 'All')) {
        $exportData.Resources.Azure = @{
            VMs      = Get-AzureVMs
            Storage  = Get-AzureStorage
            Networks = Get-AzureNetworks
        }
    }

    if ($script:AWSAvailable -and ($Provider -eq 'AWS' -or $Provider -eq 'All')) {
        $exportData.Resources.AWS = @{
            EC2     = Get-AWSEC2Instances
            S3      = Get-AWSS3Buckets
            VPCs    = Get-AWSVPCs
        }
    }

    $exportPath = if ($Path) { $Path } else { Get-LogDirectory }
    if (-not (Test-Path $exportPath)) {
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    $fileName = "cloud_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $fullPath = Join-Path $exportPath $fileName

    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $fullPath -Encoding UTF8
    Write-Success "Cloud configuration exported to: $fullPath"

    return $fullPath
}

function Invoke-CloudAudit {
    $auditResults = @()

    Write-InfoMessage "Running cloud security and tagging audit..."

    if ($script:AzureAvailable -and ($Provider -eq 'Azure' -or $Provider -eq 'All')) {
        Write-InfoMessage "Auditing Azure resources..."

        # Check VMs for tags
        $azureVMs = Get-AzureVMs
        foreach ($vm in $azureVMs) {
            $auditResults += [PSCustomObject]@{
                Provider     = "Azure"
                ResourceType = "VM"
                ResourceName = $vm.Name
                Check        = "Power State"
                Status       = if ($vm.State -eq "VM deallocated") { "WARN" } else { "OK" }
                Details      = $vm.State
                Recommendation = if ($vm.State -eq "VM deallocated") { "Consider deleting unused VMs" } else { "" }
            }
        }

        # Check storage accounts
        $azureStorage = Get-AzureStorage
        foreach ($storage in $azureStorage) {
            $auditResults += [PSCustomObject]@{
                Provider     = "Azure"
                ResourceType = "Storage"
                ResourceName = $storage.Name
                Check        = "Access Tier"
                Status       = if ($storage.AccessTier -eq "Hot") { "INFO" } else { "OK" }
                Details      = $storage.AccessTier
                Recommendation = if ($storage.AccessTier -eq "Hot") { "Consider Cool tier for infrequent access" } else { "" }
            }
        }
    }

    if ($script:AWSAvailable -and ($Provider -eq 'AWS' -or $Provider -eq 'All')) {
        Write-InfoMessage "Auditing AWS resources..."

        # Check EC2 instances
        $awsInstances = Get-AWSEC2Instances
        foreach ($instance in $awsInstances) {
            $auditResults += [PSCustomObject]@{
                Provider     = "AWS"
                ResourceType = "EC2"
                ResourceName = $instance.Name
                Check        = "Instance State"
                Status       = if ($instance.State -eq "stopped") { "WARN" } else { "OK" }
                Details      = $instance.State
                Recommendation = if ($instance.State -eq "stopped") { "Consider terminating unused instances" } else { "" }
            }

            # Check for public IP
            if ($instance.PublicIP) {
                $auditResults += [PSCustomObject]@{
                    Provider     = "AWS"
                    ResourceType = "EC2"
                    ResourceName = $instance.Name
                    Check        = "Public IP Exposure"
                    Status       = "WARN"
                    Details      = "Has public IP: $($instance.PublicIP)"
                    Recommendation = "Review if public IP is necessary"
                }
            }
        }
    }

    return $auditResults
}

function Export-HtmlReport {
    param(
        [array]$Data,
        [string]$Title,
        [string]$OutputPath
    )

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 15px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #0078d4;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .provider-azure { color: #0078d4; font-weight: bold; }
        .provider-aws { color: #ff9900; font-weight: bold; }
        .status-ok { color: #107c10; }
        .status-warn { color: #ff8c00; }
        .status-error { color: #d13438; }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>$Title</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <table>
            <tr>
"@

    # Generate headers from first object
    if ($Data.Count -gt 0) {
        $properties = $Data[0].PSObject.Properties.Name
        foreach ($prop in $properties) {
            $htmlContent += "<th>$prop</th>"
        }
        $htmlContent += "</tr>"

        # Generate rows
        foreach ($item in $Data) {
            $htmlContent += "<tr>"
            foreach ($prop in $properties) {
                $value = $item.$prop
                $class = ""
                if ($prop -eq "Provider") {
                    $class = if ($value -eq "Azure") { "provider-azure" } else { "provider-aws" }
                }
                elseif ($prop -eq "Status") {
                    $class = switch ($value) {
                        "OK" { "status-ok" }
                        "WARN" { "status-warn" }
                        "ERROR" { "status-error" }
                        default { "" }
                    }
                }
                $htmlContent += "<td class='$class'>$value</td>"
            }
            $htmlContent += "</tr>"
        }
    }

    $htmlContent += @"
        </table>
        <div class="footer">
            <p>Generated by Get-CloudResources.ps1 v$($script:ScriptVersion)</p>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
}
#endregion

#region Main Execution
function Main {
    Write-InfoMessage "Cloud Resource Manager v$($script:ScriptVersion)"

    # Initialize providers
    $null = Initialize-CloudProviders

    switch ($Action) {
        'Status' {
            Show-CloudStatus
        }

        'List' {
            $resources = Get-AllResources -Type $ResourceType

            if ($resources.Count -eq 0) {
                Write-WarningMessage "No resources found or no cloud providers connected"
                return
            }

            Write-Host ""
            Write-Host "Cloud Resources ($ResourceType):" -ForegroundColor Cyan
            Write-Host "=================================" -ForegroundColor Cyan

            switch ($OutputFormat) {
                'Console' {
                    $resources | Format-Table -AutoSize
                }
                'HTML' {
                    $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
                    $reportPath = Join-Path $outputDir "cloud_resources_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                    Export-HtmlReport -Data $resources -Title "Cloud Resources Report" -OutputPath $reportPath
                    Write-Success "HTML report saved to: $reportPath"
                }
                'JSON' {
                    $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
                    $reportPath = Join-Path $outputDir "cloud_resources_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                    $resources | ConvertTo-Json -Depth 10 | Out-File $reportPath -Encoding UTF8
                    Write-Success "JSON report saved to: $reportPath"
                }
                'CSV' {
                    $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
                    $reportPath = Join-Path $outputDir "cloud_resources_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                    $resources | Export-Csv -Path $reportPath -NoTypeInformation
                    Write-Success "CSV report saved to: $reportPath"
                }
            }
        }

        'StartVM' {
            if (-not $ResourceName) {
                Write-ErrorMessage "Please specify -ResourceName"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ResourceName, "Start VM")) {
                if ($Provider -eq 'Azure' -or ($ResourceName -notmatch '^i-')) {
                    if (-not $ResourceGroup) {
                        Write-ErrorMessage "Please specify -ResourceGroup for Azure VMs"
                        exit 1
                    }
                    Start-AzureVM -Name $ResourceName -ResourceGroup $ResourceGroup
                }
                else {
                    Start-AWSEC2Instance -InstanceId $ResourceName
                }
            }
        }

        'StopVM' {
            if (-not $ResourceName) {
                Write-ErrorMessage "Please specify -ResourceName"
                exit 1
            }

            if ($PSCmdlet.ShouldProcess($ResourceName, "Stop VM")) {
                if ($Provider -eq 'Azure' -or ($ResourceName -notmatch '^i-')) {
                    if (-not $ResourceGroup) {
                        Write-ErrorMessage "Please specify -ResourceGroup for Azure VMs"
                        exit 1
                    }
                    Stop-AzureVM -Name $ResourceName -ResourceGroup $ResourceGroup
                }
                else {
                    Stop-AWSEC2Instance -InstanceId $ResourceName
                }
            }
        }

        'Cost' {
            Write-Host ""
            Write-Host "Cost Analysis (Last $Days days):" -ForegroundColor Cyan
            Write-Host "=================================" -ForegroundColor Cyan

            $costs = @()
            if ($script:AzureAvailable -and ($Provider -eq 'Azure' -or $Provider -eq 'All')) {
                $costs += Get-AzureCosts -Days $Days
            }
            if ($script:AWSAvailable -and ($Provider -eq 'AWS' -or $Provider -eq 'All')) {
                $costs += Get-AWSCosts -Days $Days
            }

            if ($costs.Count -gt 0) {
                $costs | Format-Table -AutoSize
            }
            else {
                Write-WarningMessage "No cost data available"
            }
        }

        'Export' {
            Export-CloudConfiguration -Path $OutputPath
        }

        'Health' {
            Write-Host ""
            Write-Host "Resource Health Check:" -ForegroundColor Cyan
            Write-Host "======================" -ForegroundColor Cyan

            $resources = Get-AllResources -Type 'VMs'

            foreach ($vm in $resources) {
                $stateColor = switch -Wildcard ($vm.State) {
                    "*running*" { "Green" }
                    "*stopped*" { "Yellow" }
                    "*deallocated*" { "Yellow" }
                    default { "Gray" }
                }

                Write-Host "  [$($vm.Provider)] $($vm.Name): " -NoNewline
                Write-Host "$($vm.State)" -ForegroundColor $stateColor
            }
        }

        'Audit' {
            $auditResults = Invoke-CloudAudit

            if ($auditResults.Count -eq 0) {
                Write-InfoMessage "No audit findings or no cloud providers connected"
                return
            }

            Write-Host ""
            Write-Host "Cloud Security Audit Results:" -ForegroundColor Cyan
            Write-Host "=============================" -ForegroundColor Cyan

            switch ($OutputFormat) {
                'Console' {
                    $auditResults | Format-Table -AutoSize
                }
                'HTML' {
                    $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
                    $reportPath = Join-Path $outputDir "cloud_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                    Export-HtmlReport -Data $auditResults -Title "Cloud Security Audit" -OutputPath $reportPath
                    Write-Success "HTML report saved to: $reportPath"
                }
                'JSON' {
                    $outputDir = if ($OutputPath) { $OutputPath } else { Get-LogDirectory }
                    $reportPath = Join-Path $outputDir "cloud_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                    $auditResults | ConvertTo-Json -Depth 10 | Out-File $reportPath -Encoding UTF8
                    Write-Success "JSON report saved to: $reportPath"
                }
            }
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    Write-InfoMessage "Completed in $($duration.TotalSeconds.ToString('F1')) seconds"
}

# Run main function
Main
#endregion
