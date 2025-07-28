<#
.NOTES

  Information on running PowerShell scripts can be found here:
    -http://ss64.com/ps/syntax-run.html
    -https://technet.microsoft.com/en-us/library/bb613481.aspx

  This script requires PowerShell 7 or later to run, information on installing or upgrading PowerShell can be found here:
    -https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows

  This script also requires that the ONTAP cluster is running 9.6 or later


.DESCRIPTION

  This is a template to create future scripts that collect REST data from an ONTAP cluster.

.EXAMPLE

  template.ps1

  All required values will be prompted for.

#>

<#PSScriptInfo

.VERSION 1.0

.GUID

.AUTHOR

.RELEASENOTES

Version:
1.0 - Initial release
#>

#Requires -Version 7.0

$Separator = "─" * 120
$Spacer = " " * 7

# Header
$Header = @"
$Separator

Meaningful header text here

$Separator
"@

# Gather cluster address and credentials
$NTAPCluster = Read-Host "Please enter the IP address or DNS name of the cluster to evaluate"
$Credential = Get-Credential

# Data Collection
function Get-ClusterRestData($Endpoint) {
  process {
    $Uri = "https://$NTAPCluster/api/$Endpoint"
    Invoke-RestMethod -Method GET -Uri $Uri -Credential $Credential -SkipCertificateCheck
  }
}

function Get-ClusterData {
  $ItemsIndex = 0
  foreach ($key in $Items.Keys) {
    $ItemsIndex++
    if ($VersionCheck -ge $Items[$key].RequiredVersion) {
      $Items[$key].Result = Get-ClusterRestData $Items[$key].Url
      $Items[$key].Supported = $True
    } else {
      $Items[$key].Supported = $False
    }
    $PercentComplete = [math]::Round(($ItemsIndex / $Items.Count) * 100, 0)
    Write-Progress -Activity "Collecting REST Data" -Status "Processing REST Data" -PercentComplete $PercentComplete
  }
}

# Test Connection/Authentication
Try {
  $Cluster = Get-ClusterRestData "cluster"
} Catch {
  if ($_.Exception.Message) {
    Write-Output "Error: Failed to connect or authenticate to the cluster."
    Write-Output $_.Exception.Message
  } else {
    Write-Output $_
  }
  Exit
}

# Utility stuff
$Now = Get-Date -f MM-dd-yyyy-HHmmss
$Version = $Cluster.Version.full
$VerSplit = $Version.split(":")
$VersionCheck = $Cluster.Version.major + $Cluster.Version.minor / 10


# Data collection item definition
$Items = [ordered]@{
  Version              = @{
    RequiredVersion = 0
    Url             = "cluster"
    Category        = 0
    SummaryItem     = "ONTAP Version"
  }
  DataAtRestEncryption = @{
    RequiredVersion = 7
    Url             = "security?fields=onboard_key_manager_configurable_status"
    Category        = 0
    SummaryItem     = "ONTAP Version Supports Encryption"
  }
  SVMs                 = @{
    RequiredVersion = 0
    Url             = "svm/svms"
    Category        = 0
  }
}

# Category Definition
$Categories = [ordered]@{
  0 = "Software Version"
}

# Full Output Headers
$ItemHeaders = [ordered]@{
  Version = @"
$Separator
Recommendation: Running a recommended release of ONTAP
Reference: SU2
https://kb.netapp.com/Support_Bulletins/Customer_Bulletins/SU2

"@
}

# Helper Functions
# Table Formatting
function Add-Indentation {
  process {
    $_ | ForEach-Object { ' ' * 8 + $_ }
  }
}
# Create Summary Objects
function Add-Summary {
  param (
    [string]$Item,
    [string]$Finding,
    [int]$Category
  )
  New-Object -TypeName psobject -Property @{
    Item    = $Item
    Finding = $Finding
    Topic   = $Categories[$Category]
  }
}

function Convert-ToStringOrNull {
  param (
    [Parameter(Mandatory = $false)]
    $InputObject
  )
  if ($null -ne $InputObject) {
    return $InputObject.ToString()
  }
  else {
    return $null
  }
}

function New-FormattedObject {
  param (
    [hashtable]$PropertyMap
  )
  $converted = @{}
  foreach ($key in $PropertyMap.Keys) {
    $converted[$key] = Convert-ToStringOrNull $PropertyMap[$key]
  }
  return [pscustomobject]$converted
}

# Process and Format Data
function Format-ClusterData {
  # Begin - Software Version - Category 0
  # ONTAP Version
  $Items.Version.FullHeader = $ItemHeaders.Version
  $Items.Version.FullData = "$Spacer ONTAP Version: $Version`n$Spacer Data at rest encryption supported: $($Items.DataAtRestEncryption.Result.onboard_key_manager_configurable_status.supported)`n"
  $Items.Version.Summary = Add-Summary $Items.Version.SummaryItem $VerSplit[0] 0
  $Items.DataAtRestEncryption.Summary = Add-Summary $Items.DataAtRestEncryption.SummaryItem $Items.DataAtRestEncryption.Result.onboard_key_manager_configurable_status.supported 0
  # End - Software Version - Category 0
}

# Output Functions
# Output to Text File
function Write-Data {
  process{
    $_ | Tee-Object ".\$Now.txt" -Append
  }
}

# Output Header
function Show-Header {
  Write-Output $Header | Write-Data
}

# Output Summary
function Show-SummaryOutput {
  $SummaryData = @()
  foreach ($key in $Items.Keys) {
    if ($($Items[$key].Summary)){
      $SummaryData += $Items[$key].Summary
    }
  }
  Write-Output "Summary`n$Separator" | Write-Data
  Write-Output $SummaryData | Format-Table Item, Finding, Topic -HideTableHeaders | Out-String -Stream | Add-Indentation | Write-Data
  Write-Output $Separator | Write-Data
}

# Output Full Data
function Show-FullOutput{
  Write-Output "Full Details" | Write-Data
  foreach ($Index in $Categories.Keys){
    Write-Output "$Separator`n-- $($Categories.$Index) --" | Write-Data
    foreach ($key in $Items.Keys) {
      if ($($Items[$key].Category) -eq $Index){
        Write-Output $Items[$key].FullHeader | Write-Data
        Write-Output $Items[$key].FullData | Write-Data
      }
    }
  }
}

# Start Collection and Processing
Get-ClusterData
Format-ClusterData

# Choices for output type
$Title = "Would you like full or summary output?"
$Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Summary", "&Full", "&All")
$Default = 0
$Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
switch ($Choice) {
  0 {
    Show-Header
    Show-SummaryOutput
    Write-Output "$Separator`nOutput Logged in $Now.txt`n$Separator"
  }
  1 {
    Show-Header
    Show-FullOutput
    Write-Output "$Separator`nOutput Logged in $Now.txt`n$Separator"
  }
  2 {
    Show-Header
    Show-SummaryOutput
    Show-FullOutput
    Write-Output "$Separator`nOutput Logged in $Now.txt`n$Separator"
  }
}
