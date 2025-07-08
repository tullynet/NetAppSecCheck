<#
.NOTES

  Information on running PowerShell scripts can be found here:
    -http://ss64.com/ps/syntax-run.html
    -https://technet.microsoft.com/en-us/library/bb613481.aspx

  This script requires PowerShell 7 or later to run, information on installing or upgrading PowerShell can be found here:
    -https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows

  This script also requires that the ONTAP cluster is running 9.6 or later

  File Name: NetAppSecCheck.ps1

.DESCRIPTION

  The intention of this script is to provide a quick check of several security configurations

  Typically the following tools provide security related information for ONTAP clusters:
    - System Manager Dashboard
    - Unified Manager Cluster Security Objectives
    - Active IQ Digital Advisor

  If a more thorough review is necessary of your environment, please consider contacting
  NetApp Services to request a Data Protection and Security Assessment

  The documents referenced in the KB article linked below should be consulted for the most up to
  date information

    https://kb.netapp.com/onprem/ontap/os/How_to_perform_a_security_health_check_with_a_script_in_ONTAP
    TR-4569 - https://www.netapp.com/media/10674-tr4569.pdf
    TR-4572 - https://www.netapp.com/media/7334-tr4572.pdf
    TR-4835 - https://www.netapp.com/media/19423-tr-4835.pdf
    TR-4647 - https://www.netapp.com/media/17055-tr4647.pdf

.EXAMPLE

  NetAppSecCheck.ps1

  All required values will be prompted for.

#>

<#PSScriptInfo

.VERSION 2.1

.GUID 5a91e6dd-0287-4a5b-860b-eed6abf74b55

.AUTHOR Daniel Tully

.RELEASENOTES

Version:
2.1
  Additional checks
    Expired Certificates
    Concurrent Session Limits
    SSH etm Algorithms
    Trusted Platform Manager

  Bug fixes
    Check for presence of data svms prior to Anti-Ransomware checks
    Corrected issues with the IPsecPolicy section
    Corrected an issue while handing a null hash function for certificate based users

  General Changes
    Moved summary item titles into the main "Items" hashtable
    Reworked the CIFS section
    Moved the summary object creation to a function
    Moved the output header text to a hashtable

  Cosmetic Changes
    Progress indicator during data collection

2.0 - Updated to make future additions more modular. Added additional output for password complexity.
Bug fixes, formatting.

1.2 - Added Categories for the Summary, sorted full output to match summary
Cleaned up lots of formatting issues, bug fixes, addressed ONTAP version specific issues
More bug fixes

1.1 - Added Summary, Full, and All output choices
Cleaned up lots of formatting issues
Reorganized Data Collection, Formatting, and Output sections

1.0 - Initial release
#>

#Requires -Version 7.0

$Separator = "─" * 120
$Spacer = " " * 7

# Header
$Header = @"
$Separator
  The intention of this script is to provide a quick check of several security configurations

  Typically the following tools provide security related information for ONTAP clusters:
    - System Manager Dashboard
    - Unified Manager Cluster Security Objectives
    - Active IQ Digital Advisor

  If a more thorough review is necessary of your environment, please consider contacting
  NetApp Services to request a Data Protection and Security Assessment

  The documents referenced in the KB article linked below should be consulted for the most up to
  date information

    https://kb.netapp.com/onprem/ontap/os/How_to_perform_a_security_health_check_with_a_script_in_ONTAP
    TR-4569 - https://www.netapp.com/media/10674-tr4569.pdf
    TR-4572 - https://www.netapp.com/media/7334-tr4572.pdf
    TR-4835 - https://www.netapp.com/media/19423-tr-4835.pdf
    TR-4647 - https://www.netapp.com/media/17055-tr4647.pdf
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
    }
    else {
      $Items[$key].Supported = $False
    }
    $PercentComplete = [math]::Round(($ItemsIndex / $Items.Count) * 100, 0)
    Write-Progress -Activity "Collecting REST Data" -Status "Processing REST Data" -PercentComplete $PercentComplete
  }
}

# Test Connection/Authentication
Try {
  $Cluster = Get-ClusterRestData "cluster"
}
Catch {
  if ($_.Exception.Message) {
    Write-Output "Error: Failed to connect or authenticate to the cluster."
    Write-Output $_.Exception.Message
  }
  else {
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
  Version                 = @{
    RequiredVersion = 0
    Url             = "cluster"
    Category        = 0
    SummaryItem     = "ONTAP Version"
  }
  DataAtRestEncryption    = @{
    RequiredVersion = 7
    Url             = "security?fields=onboard_key_manager_configurable_status"
    Category        = 0
    SummaryItem     = "ONTAP Version Supports Encryption"
  }
  SVMs                    = @{
    RequiredVersion = 0
    Url             = "svm/svms"
    Category        = 0
  }
  NTPServers              = @{
    RequiredVersion = 6
    Url             = "private/cli/cluster/time-service/ntp/server"
    Category        = 1
    SummaryItem     = "NTP Servers Configured (3 or More)"
  }
  ASUPConfig              = @{
    RequiredVersion = 6
    Url             = "support/autosupport"
    Category        = 1
    SummaryItem     = "AutoSupport Enabled"
  }
  ASUPTransport           = @{
    RequiredVersion = 99
    Category        = 1
    SummaryItem     = "AutoSupport Using HTTPS"
  }
  CLITimeout              = @{
    RequiredVersion = 6
    Url             = "private/cli/system/timeout"
    Category        = 1
    SummaryItem     = "CLI Timeout Enabled"
  }
  ConcurrentSessionLimits = @{
    RequiredVersion = 7
    Url             = "private/cli/security/session/limit?fields=max-active-limit"
    Category        = 1
    SummaryItem     = "Concurrent Session Limits Configured"
  }
  CloudInsights           = @{
    RequiredVersion = 10
    Url             = "private/cli/cluster/agent/connection?fields=application-url"
    Category        = 1
    SummaryItem     = "Cloud Insights Configured"
  }
  LoginBannerConfig       = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login/banner"
    Category        = 1
    SummaryItem     = "Login Banner Configured"
  }
  MOTDConfig              = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login/motd"
    Category        = 1
    SummaryItem     = "MOTD Configured"
  }
  PasswordConfig          = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login/role/config?fields=passwd-minlength," `
      + "passwd-min-special-chars,passwd-min-digits,passwd-min-lowercase-chars," `
      + "passwd-min-uppercase-chars,passwd-alphanum,disallowed-reuse," `
      + "passwd-expiry-time,passwd-expiry-warn-time,passwd-expiry-time," `
      + "require-initial-passwd-update,lockout-duration,change-delay"
    Category        = 1
    SummaryItem     = "Password Complexity Configuration"
  }
  LogForwarding           = @{
    RequiredVersion = 6
    Url             = "private/cli/cluster/log"
    Category        = 1
    SummaryItem     = "Syslog Forwarding Configured"
  }
  SystemConfigBackup      = @{
    RequiredVersion = 6
    Url             = "support/configuration-backup"
    Category        = 1
    SummaryItem     = "System Configuration Backup to Remote Server"
  }
  ManagementProtocols     = @{
    RequiredVersion = 6
    Url             = "private/cli/security/protocol?fields=application,enabled"
    Category        = 2
    SummaryItem     = ""
  }
  WebServices             = @{
    RequiredVersion = 6
    Url             = "private/cli/system/services/web"
    Category        = 2
    SummaryItem     = "HTTP Disabled"
  }
  RSHConfig               = @{
    RequiredVersion = 6
    Url             = "private/cli/security/protocol?fields=application,enabled&application=rsh"
    Category        = 2
    SummaryItem     = "RSH Disabled"
  }
  TelnetConfig            = @{
    RequiredVersion = 6
    Url             = "private/cli/security/protocol?fields=application,enabled&application=telnet"
    Category        = 2
    SummaryItem     = "Telnet Disabled"
  }
  BuiltinUsers            = @{
    RequiredVersion = 6
    Url             = "security/accounts?name=admin&fields=locked"
    Category        = 3
    SummaryItem     = "Default Admin Accounts Locked"
  }
  DiagUser                = @{
    RequiredVersion = 6
    Url             = "security/accounts?name=diag&fields=locked"
    Category        = 3
    SummaryItem     = ""
  }
  RestRoles               = @{
    RequiredVersion = 10
    Url             = "private/cli/security/login/rest-role?api=/api/storage/volumes&fields=access"
    Category        = 3
    SummaryItem     = ""
  }
  UserDetails             = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?fields=second-authentication-method,hash-function,is-account-locked,role&application=!snmp"
    Category        = 3
    SummaryItem     = ""
  }
  MultiAdminVerify        = @{
    RequiredVersion = 11.1
    Url             = "private/cli/security/multi-admin-verify"
    Category        = 3
    SummaryItem     = "Multi-Admin Verification Enabled"
  }
  SNMPUsers               = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?application=snmp&authentication-method=community"
    Category        = 3
    SummaryItem     = "No SNMP Users with Community Auth"
  }
  RSHUsers                = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?application=rsh&fields=role,second_authentication_method,is_account_locked"
    Category        = 3
    SummaryItem     = "No Users with RSH Access"
  }
  TelnetUsers             = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?application=telnet&fields=role,second_authentication_method,is_account_locked"
    Category        = 3
    SummaryItem     = "No Users with Telnet Access"
  }
  ClusterPeerEncryption   = @{
    RequiredVersion = 6
    Url             = "private/cli/cluster/peer?fields=cluster,encryption_protocol_proposed,encryption_protocol"
    Category        = 4
    SummaryItem     = "Encryption Enabled for All Cluster Peers"
  }
  FIPS                    = @{
    RequiredVersion = 6
    Url             = "private/cli/security/config?fields=is_fips_enabled"
    Category        = 4
    SummaryItem     = "FIPS Mode Enabled"
  }
  IPsec                   = @{
    RequiredVersion = 8
    Url             = "security/ipsec?fields=*"
    Category        = 4
    SummaryItem     = "IPsec Enabled"
  }
  IPsecPolicy             = @{
    RequiredVersion = 8
    Url             = "security/ipsec/policies"
    Category        = 4
    SummaryItem     = "IPsec Policies Configured"
  }
  SSHCiphers              = @{
    RequiredVersion = 6
    Url             = "private/cli/security/ssh?ciphers=*cbc*"
    Category        = 4
    SummaryItem     = "No Problematic Ciphers Present"
  }
  SSHAlgorithms           = @{
    RequiredVersion = 6
    Url             = "private/cli/security/ssh?mac-algorithms=*etm*"
    Category        = 4
    SummaryItem     = "No Problematic Algorithms Present"
  }
  SelfSignedCerts         = @{
    RequiredVersion = 6
    Url             = "private/cli/security/certificate?self_signed=true&type=server&fields=self_signed,common_name,vserver,type"
    Category        = 4
    SummaryItem     = "No Self-Signed Certificates"
  }
  ExpiredCerts            = @{
    RequiredVersion = 6
    Url             = "private/cli/security/certificate?fields=expiration"
    Category        = 4
    SummaryItem     = "No Expired Certificates"
  }
  SSLConfig               = @{
    RequiredVersion = 6
    Url             = "private/cli/security/ssl?fields=client-enabled"
    Category        = 4
    SummaryItem     = "No SVMs with Client-Enabled SSL Access"
  }
  HTTPUsers               = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?application=http"
    Category        = 4
    SummaryItem     = ""
  }
  ONTAPIUsers             = @{
    RequiredVersion = 6
    Url             = "private/cli/security/login?application=ontapi"
    Category        = 4
    SummaryItem     = ""
  }
  OCSPConfig              = @{
    RequiredVersion = 6
    Url             = "private/cli/security/config/ocsp?fields=application,is_ocsp_enabled"
    Category        = 4
    SummaryItem     = "OCSP Enabled for All Applications"
  }
  SAML                    = @{
    RequiredVersion = 6
    Url             = "private/cli/security/saml-sp/status?fields=status,is_enabled"
    Category        = 4
    SummaryItem     = "SAML Configured"
  }
  CIFSSvms                = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/cifs"
    Category        = 5
    SummaryItem     = "CIFS SVMs Present"
  }
  CIFSSigning             = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/cifs/security?is_signing_required=!null"
    Category        = 5
    SummaryItem     = "All CIFS SVMs have Signing Enabled"
  }
  CIFSWorkgroup           = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/cifs?auth_style=workgroup"
    Category        = 5
    SummaryItem     = "No CIFS SVMs Configured for Workgroup"
  }
  CIFSSMB1                = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/cifs/options?smb1_enabled=true"
    Category        = 5
    SummaryItem     = "No CIFS SVMs with SMB 1 Enabled"
  }
  LDAP                    = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/cifs/security?session-security-for-ad-ldap=!null"
    Category        = 5
    SummaryItem     = "AD LDAP Session Security Enabled for All CIFS SVMs"
  }
  VScan                   = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/vscan?fields=vscan-status"
    Category        = 5
    SummaryItem     = "VScan Enabled for All CIFS SVMs"
  }
  Fpolicy                 = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/fpolicy?fields=status,engine"
    Category        = 5
    SummaryItem     = "FPolicy Configured"
  }
  NASAuditing             = @{
    RequiredVersion = 6
    Url             = "private/cli/vserver/audit?fields=vserver,state"
    Category        = 5
    SummaryItem     = "NAS Auditing Configured"
  }
  NISServers              = @{
    RequiredVersion = 6
    Url             = "svm/svms?nis.domain=!null"
    Category        = 5
    SummaryItem     = "NIS Not Configured"
  }
  SnapShotAutoDelete      = @{
    RequiredVersion = 6
    Url             = "private/cli/volume/snapshot/autodelete?enabled=true"
    Category        = 6
    SummaryItem     = "No Volumes with Snapshot Autodeletion Enabled"
  }
  NullSnapShotPolicy      = @{
    RequiredVersion = 6
    Url             = "private/cli/volume?snapshot_policy=null&is_cluster_volume=true"
    Category        = 6
    SummaryItem     = "No Volumes with Snapshot Policy of NULL"
  }
  NoneSnapShotPolicy      = @{
    RequiredVersion = 6
    Url             = "private/cli/volume?snapshot_policy=none&is_cluster_volume=true"
    Category        = 6
    SummaryItem     = "No Volumes with Snapshot Policy of None"
  }
  SnapShotLocking         = @{
    RequiredVersion = 12.1
    Url             = "private/cli/volume?fields=snapshot_locking_enabled"
    Category        = 6
    SummaryItem     = "Snapshot Locking Enabled for All Volumes"
  }
  SVMAntiRansomware       = @{
    RequiredVersion = 10
    Url             = "svm/svms?fields=anti_ransomware_default_volume_state"
    Category        = 7
    SummaryItem     = "Ransomware Protection Enabled for All SVMs"
  }
  VolumeAntiRansomware    = @{
    RequiredVersion = 10
    Url             = "private/cli/volume?is-cluster-volume=true&fields=anti-ransomware-state"
    Category        = 7
    SummaryItem     = "Ransomware Protection Enabled for All Volumes"
  }
  TrustedPlatformModule   = @{
    RequiredVersion = 8
    Url             = "private/cli/security/tpm?fields=is-available"
    Category        = 8
    SummaryItem     = "Trusted Platform Module is Available for All Nodes"
  }
  KeyManager              = @{
    RequiredVersion = 6
    Url             = "security/key-managers"
    Category        = 8
    SummaryItem     = "Key-Manager Configured"
  }
  DriveProtection         = @{
    RequiredVersion = 6
    Url             = "private/cli/storage/aggregate?fields=drive-protection-enabled,node"
    Category        = 8
    SummaryItem     = "Drive Encryption Enabled for All Aggregates"
  }
  VolumeEncryption        = @{
    RequiredVersion = 6
    Url             = "private/cli/volume?fields=encryption-type,is-encrypted"
    Category        = 8
    SummaryItem     = "Volume Encryption Enable for All Volumes"
  }
}

# Category Definition
$Categories = [ordered]@{
  0 = "Software Version"
  1 = "General Configuration"
  2 = "Administrative Protocols"
  3 = "Administrative Users"
  4 = "Secure Communication"
  5 = "File Access"
  6 = "Data Protection"
  7 = "Anti-Ransomware"
  8 = "Encryption"
}

# Full Output Headers
$ItemHeaders = [ordered]@{
  Version                 = @"
$Separator
Recommendation: Running a recommended release of ONTAP
Reference: SU2
https://kb.netapp.com/Support_Bulletins/Customer_Bulletins/SU2

"@
  NTPServers              = @"
$Separator
Recommendation: The number of servers configured for NTP should not be less than 3
Reference: System Manager Insights and TR-4569 section "Network Time Protocol"
"@
  ASUPConfig              = @"
$Separator
Recommendation: AutoSupport should use a secure protocol (HTTPS) and should be enabled
Reference: System Manager Insights and TR-4569 section "NetApp AutoSupport"
"@
  CLITimeout              = @"
$Separator
Recommendation: CLI timeout value should match your organization's requirements
Reference: TR-4569 section "CLI Session Timeout"
"@
  ConcurrentSessionLimits = @"
$Separator
Recommendation: Concurrent Session Limits should be set to match your organization's requirements
"@
  CloudInsights           = @"
$Separator
Recommendation: Cloud Insights provides an external mode FPolicy server
Reference: TR-4572 section "Cloud Insights"
"@
  LoginBannerConfig       = @"
$Separator
Recommendation: The login banner and message of the day (motd) should match your organization's requirements
Reference: System Manager Insights and TR-4569 section "Login Banners" and "Message of the Day"
"@
  PasswordConfig          = @"
$Separator
Recommendation: Configured password parameters should match your organization's policy
Reference: TR-4569 section "Password Parameters"
"@
  LogForwarding           = @"
$Separator
Recommendation: Offloading of syslog information should be configured
Reference: TR-4569 section "Sending out Syslog"
"@
  SystemConfigBackup      = @"
$Separator
Recommendation: System Configuration should be backed up to a remote server
"@
  WebServices             = @"
$Separator
Recommendation: HTTP should be disabled
"@
  ManagementProtocols     = @"
$Separator
Recommendation: Telnet and Remote Shell (RSH) should be disabled
Reference: System Manager Insights and TR-4569 section "Application Methods"
"@
  BuiltinUsers            = @"
$Separator
Recommendation: Built in accounts should be locked
Reference: System Manager Insights and TR-4569 section "Default Administrative Accounts"
"@
  RestRoles               = @"
$Separator
Recommendation: You can prevent ONTAP administrators from using REST APIs for file access by setting access level
                for /api/storage/volumes to none
Reference: TR-4569 section "Effect of REST APIs on NAS Auditing"
"@
  UserDetails             = @"
$Separator
Recommendation: For each login the authentication-method should be public key for machine access
                and can be password for user access
                The second-authentication-method should not be none to enable MFA
                The role should be appropriate to grant them privilege to perform their job function or required task
                The hash-function should be sha512
Reference: TR-4569 section "SHA-512 Support" and "Managing SSHv2" and "Roles, Applications, and Authentication" and
           TR-4647 section "ONTAP SSH Two-Factor Chained Authentication"
"@
  MultiAdminVerify        = @"
$Separator
Recommendation: Multi-Admin Verification should be enabled
Reference: TR-4569 section "Multi-Admin Verification"
"@
  SNMPUsers               = @"
$Separator
Recommendation: SNMP Users shoud not use an authentication method of community
"@
  RSHUsers                = @"
$Separator
Recommendation: No logins should exist with the Telnet or RSH application
Reference: TR-4569 section "Application Methods"
"@
  ClusterPeerEncryption   = @"
$Separator
Recommendation: Cluster peers should be configured with tls-psk for the encryption protocol
Reference: TR-4569 section "Data Replication Encryption"
"@
  FIPS                    = @"
$Separator
Recommendation: FIPS Mode should be enabled
Reference: System Manager Insights and TR-4569 section "Managing TLS and SSL"
"@
  IPSec                   = @"
$Separator
Recommendation: When required IPsec is configured and policies created
Reference: TR-4569 section "IPsec Data-in-flight Encryption"
"@
  SSHCiphers              = @"
$Separator
Recommendation: No Cipher Block Chaining ciphers should be present
Reference: System Manager Insights

$Spacer Problematic Ciphers:
"@
  SSHAlgorithms           = @"
$Separator
Recommendation: No Encrypt-then-MAC algorithms should be present
Reference: CVE-2023-48795

$Spacer Problematic Algorithms:
"@
  SelfSignedCerts         = @"
$Separator
Recommendation: On production systems no self-signed ceritficates should exist
Reference: TR-4569 section "Creating a CA-Signed Digital Certificate"
"@
  ExpiredCerts            = @"
$Separator
Recommendation: On production systems no expired ceritficates should exist
Reference: TR-4569 section "Creating a CA-Signed Digital Certificate"
           https://kb.netapp.com/on-prem/ontap/Ontap_OS/OS-KBs/How_to_renew_a_Self-Signed_SSL_certificate_in_ONTAP_9
"@
  SSLConfig               = @"
$Separator
Recommendation: For any SVM with client-enabled access, all related logins that are performing SDK or REST API calls
                should use cert for Authentication Method field
Reference: TR-4569 section "Certificate-based API access"

$Spacer SSL Configuration
"@
  OCSPConfig              = @"
$Separator
Recommendation: OCSP should be enabled
Reference: TR-4569 section "Online Certificate Status Protocol"
"@
  SAML                    = @"
$Separator
Recommendation: SAML should be configured
Reference: TR-4647 section "The requirement for strong administrative credentials"
"@
  CIFSSigning             = @"
$Separator
Recommendation: For each SVM configured with CIFS the is-signing-required should be true
Reference: TR-4569 section "CIFS SMB Signing and Sealing"
"@
  CIFSWorkgroup           = @"
$Separator
Recommendation: CIFS SVMs should not be configured for workgroup access
"@
  CIFSSMB1                = @"
$Separator
Recommendation: CIFS SVMs should not be configured to use SMB1
"@
  LDAP                    = @"
$Separator
Recommendation: For each SVM configured with CIFS session-security-for-ad-ldap should be set to a minimum of sign
to match your organization's requirements
Reference: TR-4835 section "Microsoft LDAP Channel Binding Requirement"
"@
  VScan                   = @"
$Separator
Recommendation: VScan can be configured for CIFS SVMs
"@
  FPolicy                 = @"
$Separator
Recommendation: FPolicy should be configured
Reference: System Manager Insights
"@
  NASAuditing             = @"
$Separator
Recommendation: NAS auditing should be enabled
Reference: TR-4569 section "NAS File System Auditing"
"@
  NISServers              = @"
$Separator
Recommendation: NIS should not be configured
Reference: TR-4569 section "Authentication Methods"
"@
  SnapShotAutoDelete      = @"
$Separator
Recommendation: Snapshot auto-deletion should not be enabled for data volumes
Reference: System Manager Insights
"@
  NullSnapShotPolicy      = @"
$Separator
Recommendation: All volumes should have Snapshot policies
Reference: System Manager Insights
"@
  SnapShotLocking         = @"
$Separator
Recommendation: snapshot-locking-enabled should be true for all volumes with snapshots
Reference: TR-4569 section "Snapshot Copy Locking"
"@
  SVMAntiRansomware       = @"
$Separator
Recommendation: SVMs should be configured for anti-ransomware
Reference: System Manager Insights
"@
  VolumeAntiRansomware    = @"
$Separator
Recommendation: Volume anti-ransomware-state should be enabled
Reference: System Manager Insights
"@
  TrustedPlatformModule   = @"
$Separator
Recommendation: Platforms with a TPM chip and TPM license will generate and seal the node key encryption key to
                protect the highest level of the OKM keying hierarchy in ONTAP 9.8 and later.
Reference: TR-4569 section "Storage Encryption"
           https://kb.netapp.com/on-prem/ontap/OHW/OHW-KBs/What_is_Trusted_Platform_Module_(TPM)
"@
  KeyManager              = @"
$Separator
Recommendation: A Key-Manager should be configured and encryption should be enabled at either the disk, aggregate,
                or volume layer
Reference: TR-4569 section "Storage Encryption"
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

# Process and Format Data
function Format-ClusterData {
  # Begin - Software Version - Category 0
  # ONTAP Version
  $Items.Version.FullHeader = $ItemHeaders.Version
  $Items.Version.FullData = "$Spacer ONTAP Version: $Version`n$Spacer Data at rest encryption supported: $($Items.DataAtRestEncryption.Result.onboard_key_manager_configurable_status.supported)`n"
  $Items.Version.Summary = Add-Summary $Items.Version.SummaryItem $VerSplit[0] 0
  $Items.DataAtRestEncryption.Summary = Add-Summary $Items.DataAtRestEncryption.SummaryItem $Items.DataAtRestEncryption.Result.onboard_key_manager_configurable_status.supported 0
  # End - Software Version - Category 0

  # Begin - General Configuration - Category 1
  # NTP Servers
  $Items.NTPServers.FullHeader = $ItemHeaders.NTPServers
  if ($Items.NTPServers.Result.num_records -ne 0) {
    $Items.NTPServers.Formatted = ForEach ($_ in $Items.NTPServers.Result.records) {
      New-Object psobject -Property @{
        "NTP Servers" = ($_.Server).ToString()
      }
    }
    $Items.NTPServers.FullData = $Items.NTPServers.Formatted | Format-Table "NTP Servers" | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.NTPServers.FullData = "`n$Spacer No NTP Servers Found.`n"
  }
  $Items.NTPServers.Summary = Add-Summary $Items.NTPServers.SummaryItem ($Items.NTPServers.Result.num_records -ge 3) 1

  # ASUP Config
  $Items.ASUPConfig.FullHeader = $ItemHeaders.ASUPConfig
  $Items.ASUPConfig.Formatted = ForEach ($_ in $Items.ASUPConfig.Result) {
    New-Object psobject -Property @{
      Transport = ($_.transport).ToString()
      Enabled   = ($_.enabled).ToString()
    }
  }
  $Items.ASUPConfig.FullData = $Items.ASUPConfig.Formatted | Format-Table Transport, Enabled | Out-String -Stream | Add-Indentation
  $Items.ASUPConfig.Summary = Add-Summary $Items.ASUPConfig.SummaryItem $Items.ASUPConfig.Result.enabled 1
  $Items.ASUPTransport.Summary = Add-Summary $Items.ASUPTransport.SummaryItem ($Items.ASUPConfig.Result.transport.contains("https")) 1

  # CLI Timeout
  $Items.CLITimeout.FullHeader = $ItemHeaders.CLITimeout
  $Items.CLITimeout.FullData = "`n$Spacer CLI Session Timeout: $($Items.CLITimeout.Result.timeout) Minutes`n"
  $Items.CLITimeout.Summary = Add-Summary $Items.CLITimeout.SummaryItem ($Items.CLITimeout.Result.timeout -gt 0) 1

  # Concurrent Session Limits
  $Items.ConcurrentSessionLimits.FullHeader = $ItemHeaders.ConcurrentSessionLimits
  $Items.ConcurrentSessionLimits.Formatted = ForEach ($_ in $Items.ConcurrentSessionLimits.Result.records) {
    New-Object psobject -Property @{
      Interface = ($_.interface).ToString()
      Category  = ($_.category).ToString()
      MaxActive = ($_.max_active_limit).ToString()
    }
  }
  $Items.ConcurrentSessionLimits.FullData = $Items.ConcurrentSessionLimits.Formatted | Format-Table Interface, Category, MaxActive | Out-String -Stream | Add-Indentation
  $Items.ConcurrentSessionLimits.Summary = Add-Summary $Items.ConcurrentSessionLimits.SummaryItem "Review Full Output" 1

  # Cloud Insights
  $Items.CloudInsights.FullHeader = $ItemHeaders.CloudInsights
  if ($Items.CloudInsights.Supported) {
    if ($Items.CloudInsights.Result.num_records -ne 0) {
      $Items.CloudInsights.FullData = $Items.CloudInsights.Result.records | Format-Table | Out-String -Stream | Add-Indentation
      $Items.CloudInsights.Summary = Add-Summary $Items.CloudInsights.SummaryItem ($Items.CloudInsights.Result.records.application_url.contains("cloudinsights.netapp.com")) 1
    }
    else {
      $Items.CloudInsights.FullData = "`n$Spacer No Results Returned.`n"
      $Items.CloudInsights.Summary = Add-Summary $Items.CloudInsights.SummaryItem "False" 1
    }
  }
  else {
    $Items.CloudInsights.FullData = "`n$Spacer Not available in this release.`n"
    $Items.CloudInsights.Summary = Add-Summary $Items.CloudInsights.SummaryItem "Not available in this release" 1
  }

  # Banner and MOTD
  $Items.LoginBannerConfig.FullHeader = $ItemHeaders.LoginBannerConfig
  $Items.LoginBannerConfig.FullData = "`n$Spacer Login Banner Configured - $($Items.LoginBannerConfig.Result.num_records -ne 0)"
  $Items.LoginBannerConfig.Summary = Add-Summary $Items.LoginBannerConfig.SummaryItem ($Items.LoginBannerConfig.Result.num_records -ne 0) 1
  $Items.MOTDConfig.FullData = "`n$Spacer MOTD Configured - $($Items.MOTDConfig.Result.num_records -ne 0)`n"
  $Items.MOTDConfig.Summary = Add-Summary $Items.MOTDConfig.SummaryItem ($Items.MOTDConfig.Result.num_records -ne 0) 1

  # Password Complexity
  $Items.PasswordConfig.FullHeader = $ItemHeaders.PasswordConfig
  $Items.PasswordConfig.Formatted = ForEach ($_ in $Items.PasswordConfig.Result.records) {
    New-Object psobject -Property @{
      VServer            = ($_.vserver).ToString()
      Role               = ($_.role).ToString()
      Alphanumeric       = ($_.passwd_alphanum).ToString()
      "Min Len"          = ($_.passwd_minlength).ToString()
      "Min Spec Chars"   = ($_.passwd_min_special_chars).ToString()
      "Min Lowercase"    = ($_.passwd_min_lowercase_chars).ToString()
      "Min Uppercase"    = ($_.passwd_min_uppercase_chars).ToString()
      "Min Digits"       = ($_.passwd_min_digits).ToString()
      "Before Reuse"     = ($_.disallowed_reuse).ToString()
      "Expiry Time"      = ($_.passwd_expiry_time).ToString()
      "Expiry Warn"      = ($_.passwd_expiry_warn_time).ToString()
      "Age Before Chg"   = ($_.change_delay).ToString()
      "ChgOnLogin"       = ($_.require_initial_passwd_update).ToString()
      "Lockout Duration" = ($_.lockout_duration).ToString()
    }
  }
  $Items.PasswordConfig.FullData = $Items.PasswordConfig.Formatted | Format-Table vserver, role, Alphanumeric, "Min Len", "Min Spec Chars", "Min Lowercase", "Min Uppercase", "Min Digits" | Out-String -Stream | Add-Indentation
  $Items.PasswordConfig.FullData += $Items.PasswordConfig.Formatted | Format-Table vserver, role, "Before Reuse", "Expiry Time", "Expiry Warn", "Age Before Chg", "ChgOnLogin", "Lockout Duration" | Out-String -Stream | Add-Indentation
  $Items.PasswordConfig.Summary = Add-Summary $Items.PasswordConfig.SummaryItem "Review Full Output" 1

  # Log Forwarding
  $Items.LogForwarding.FullHeader = $ItemHeaders.LogForwarding
  if ($Items.LogForwarding.Result.num_records -ne 0) {
    $Items.LogForwarding.Formatted = ForEach ($_ in $Items.LogForwarding.Result.records) {
      New-Object psobject -Property @{
        Destination = ($_.Destination).ToString()
        Port        = ($_.Port).ToString()
      }
    }
    $Items.LogForwarding.FullData = $Items.LogForwarding.Formatted | Format-Table Destination, Port | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.LogForwarding.FullData = "`n$Spacer No Remote Destination Found.`n"
  }
  $Items.LogForwarding.Summary = Add-Summary $Items.LogForwarding.SummaryItem ($Items.LogForwarding.Result.num_records -ne 0) 1

  # System Configuration Backup
  $Items.SystemConfigBackup.FullHeader = $ItemHeaders.SystemConfigBackup
  if ($Items.SystemConfigBackup.Result.url) {
    $Items.SystemConfigBackup.FullData = "System Configuration Backup Destination:`n$Spacer $($Items.SystemConfigBackup.Result.url)`n"
  }
  else {
    $Items.SystemConfigBackup.FullData = "`n$Spacer No Remote Destination Found.`n"
  }
  $Items.SystemConfigBackup.Summary = Add-Summary $Items.SystemConfigBackup.SummaryItem (![string]::IsNullOrEmpty($Items.SystemConfigBackup.Result.url)) 1
  # End - General Configuration - Category 1

  # Begin - Administrative Protocols - Category 2
  # Web Services
  $Items.WebServices.FullHeader = $ItemHeaders.WebServices
  $Items.WebServices.FullData = "`n$Spacer HTTP Enabled - $($Items.WebServices.Result.http_enabled)`n"
  $Items.WebServices.Summary = Add-Summary $Items.WebServices.SummaryItem (!$Items.WebServices.Result.http_enabled) 2

  # Management Protocols
  $Items.ManagementProtocols.FullHeader = $ItemHeaders.ManagementProtocols
  $Items.ManagementProtocols.Formatted = ForEach ($_ in $Items.ManagementProtocols.Result.records) {
    New-Object psobject -Property @{
      Application = ($_.application).ToString()
      Enabled     = ($_.enabled).ToString()
    }
  }
  $Items.ManagementProtocols.FullData = $Items.ManagementProtocols.Formatted | Format-Table Application, Enabled | Out-String -Stream | Add-Indentation
  $Items.RSHConfig.Summary = Add-Summary $Items.RSHConfig.SummaryItem (!$Items.RSHConfig.Result.records.enabled) 2
  $Items.TelnetConfig.Summary = Add-Summary $Items.TelnetConfig.SummaryItem (!$Items.TelnetConfig.Result.records.enabled) 2
  # End - Administrative Protocols - Category 2

  # Begin - Administrative Users - Category 3
  # Built in accounts
  $Items.BuiltinUsers.FullHeader = $ItemHeaders.BuiltinUsers
  $Items.BuiltinUsers.Builtin = $Items.BuiltinUsers.Result.records + $Items.DiagUser.Result.records
  $Items.BuiltinUsers.Formatted = ForEach ($_ in $Items.BuiltinUsers.Builtin) {
    New-Object psobject -Property @{
      Username = ($_.name).ToString()
      Locked   = ($_.locked).ToString()
    }
  }
  $Items.BuiltinUsers.FullData = $Items.BuiltinUsers.Formatted | Format-Table Username, Locked | Out-String -Stream | Add-Indentation
  $Items.BuiltinUsers.Summary = Add-Summary $Items.BuiltinUsers.SummaryItem (!$Items.BuiltinUsers.Formatted.Locked.Contains("False")) 3

  # REST Roles
  $Items.RestRoles.FullHeader = $ItemHeaders.RestRoles
  if ($Items.RestRoles.Supported) {
    $Items.RestRoles.Formatted = ForEach ($_ in $Items.RestRoles.Result.records) {
      New-Object psobject -Property @{
        VServer = ($_.vserver).ToString()
        Role    = ($_.role).ToString()
        API     = ($_.api).ToString()
        Access  = ($_.Access).ToString()
      }
    }
    $Items.RestRoles.FullData = $Items.RestRoles.Formatted | Format-Table VServer, Role, API, Access | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.RestRoles.FullData = "`n$Spacer Not Supported in this release.`n"
  }

  # User Details
  $Items.UserDetails.FullHeader = $ItemHeaders.UserDetails
  $Items.UserDetails.Formatted = ForEach ($_ in $Items.UserDetails.Result.records) {
    New-Object psobject -Property @{
      Username        = ($_.user_or_group_name).ToString()
      VServer         = ($_.vserver).ToString()
      Application     = ($_.application).ToString()
      "Role Name"     = ($_.role).ToString()
      AuthMethod      = ($_.authentication_method).ToString()
      "2ndAuthMethod" = ($_.second_authentication_method).ToString()
      Locked          = ($_.is_account_locked)
      "Hash Function" = ($_.hash_function)
    }
  }
  $Items.UserDetails.FullData = $Items.UserDetails.Formatted | Format-Table username, vserver, application, "role name", authmethod, "2ndAuthMethod", Locked, "Hash Function" | Out-String -Stream | Add-Indentation

  # Multi-Admin Verification
  $Items.MultiAdminVerify.FullHeader = $ItemHeaders.MultiAdminVerify
  if ($Items.MultiAdminVerify.Supported) {
    $Items.MultiAdminVerify.Formatted = New-Object psobject -Property @{
      Enabled              = ($Items.MultiAdminVerify.Result.enabled).ToString()
      "Required Approvers" = ($Items.MultiAdminVerify.Result.required_approvers).ToString()
    }
    $Items.MultiAdminVerify.FullData = $Items.MultiAdminVerify.Formatted | Format-Table Enabled, "Required Approvers" | Out-String -Stream | Add-Indentation
    $Items.MultiAdminVerify.Summary = Add-Summary $Items.MultiAdminVerify.SummaryItem $Items.MultiAdminVerify.Result.enabled 3
  }
  else {
    $Items.MultiAdminVerify.FullData = "`n$Spacer Multi-Admin Verification is not supported in this release. Consider upgrading to 9.11.1 or later.`n"
    $Items.MultiAdminVerify.Summary = Add-Summary $Items.MultiAdminVerify.SummaryItem "Not available in this release" 3
  }

  # SNMP Users
  $Items.SNMPUsers.FullHeader = $ItemHeaders.SNMPUsers
  if ($Items.SNMPUsers.Result.num_records -ne 0) {
    $Items.SNMPUsers.Formatted = ForEach ($_ in $Items.SNMPUsers.Result.records) {
      New-Object psobject -Property @{
        VServer     = ($_.vserver).ToString()
        Username    = ($_.user_or_group_name).ToString()
        Application = ($_.application).ToString()
        AuthMethod  = ($_.authentication_method).ToString()
      }
    }
    $Items.SNMPUsers.FullData = $Items.SNMPUserss.Formatted | Format-Table username, vserver, application, authmethod | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SNMPUsers.FullData = "`n$Spacer No SNMP users found with community authentication method.`n"
  }
  $Items.SNMPUsers.Summary = Add-Summary $Items.SNMPUsers.SummaryItem ($Items.SNMPUsers.Result.num_records -eq 0) 3

  # RSH and Telnet Users
  $Items.RSHUsers.FullHeader = $ItemHeaders.RSHUsers
  if ($Items.RSHUsers.Result.num_records -ne 0) {
    $Items.RSHUsers.Formatted = ForEach ($_ in $Items.RSHUsers.Result.records) {
      New-Object psobject -Property @{
        VServer         = ($_.vserver).ToString()
        Username        = ($_.user_or_group_name).ToString()
        Application     = ($_.application).ToString()
        AuthMethod      = ($_.authentication_method).ToString()
        "Role Name"     = ($_.role).ToString()
        Locked          = ($_.is_account_locked).ToString()
        "2ndAuthMethod" = ($_.second_authentication_method).ToString()
      }
    }
    $Items.RSHUsers.FullData = $Items.RSHUsers.Formatted | Format-Table username, vserver, application, "role name", authmethod, "2ndAuthMethod", Locked | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.RSHUsers.FullData = "`n$Spacer No users found with RSH application access."
  }
  $Items.RSHUsers.Summary = Add-Summary $Items.RSHUsers.SummaryItem ($Items.RSHUsers.Result.num_records -eq 0) 3
  if ($Items.TelnetUsers.Result.num_records -ne 0) {
    $Items.TelnetUsers.Formatted = ForEach ($_ in $Items.TelnetUsers.Result.records) {
      New-Object psobject -Property @{
        VServer         = ($_.vserver).ToString()
        Username        = ($_.user_or_group_name).ToString()
        Application     = ($_.application).ToString()
        AuthMethod      = ($_.authentication_method).ToString()
        "Role Name"     = ($_.role).ToString()
        Locked          = ($_.is_account_locked).ToString()
        "2ndAuthMethod" = ($_.second_authentication_method).ToString()
      }
    }
    $Items.TelnetUsers.FullData = $Items.TelnetUsers.Formatted | Format-Table username, vserver, application, "role name", authmethod, "2ndAuthMethod", Locked | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.TelnetUsers.FullData = "`n$Spacer No users found with Telnet application access.`n"
  }
  $Items.TelnetUsers.Summary = Add-Summary $Items.TelnetUsers.SummaryItem ($Items.TelnetUsers.Result.num_records -eq 0) 3
  # End - Administrative Users - Category 3

  # Begin - Secure Communication - Category 4
  # Cluster Peer Details
  $Items.ClusterPeerEncryption.FullHeader = $ItemHeaders.ClusterPeerEncryption
  if ($Items.ClusterPeerEncryption.Result.num_records -ne 0) {
    $Items.ClusterPeerEncryption.Formatted = ForEach ($_ in $Items.ClusterPeerEncryption.Result.records) {
      New-Object psobject -Property @{
        Cluster               = ($_.cluster).ToString()
        "Encryption Protocol" = ($_.encryption_protocol).ToString()
      }
    }
    $Items.ClusterPeerEncryption.FullData = $Items.ClusterPeerEncryption.Formatted | Format-Table Cluster, "Encryption Protocol" | Out-String -Stream | Add-Indentation
    $Items.ClusterPeerEncryption.Summary = Add-Summary $Items.ClusterPeerEncryption.SummaryItem (!$Items.ClusterPeerEncryption.Formatted."Encryption Protocol".contains("none")) 4
  }
  else {
    $Items.ClusterPeerEncryption.FullData = "`n$Spacer No Cluster Peer Relationships Found.`n"
    $Items.ClusterPeerEncryption.Summary = Add-Summary $Items.ClusterPeerEncryption.SummaryItem "No Cluster Peers Found" 4
  }

  # FIPS
  $Items.FIPS.FullHeader = $ItemHeaders.FIPS
  $Items.FIPS.Formatted = ForEach ($_ in $Items.FIPS.Result.records) {
    New-Object psobject -Property @{
      Interface      = ($_.interface).ToString()
      "FIPS Enabled" = ($_.is_fips_enabled).ToString()
    }
  }
  $Items.FIPS.FullData = $Items.FIPS.Formatted | Format-Table Interface, "FIPS Enabled" | Out-String -Stream | Add-Indentation
  $Items.FIPS.Summary = Add-Summary $Items.FIPS.SummaryItem $Items.FIPS.Result.records.is_fips_enabled 4

  # IPSec
  $Items.IPSec.FullHeader = $ItemHeaders.IPSec
  if ($Items.IPSec.Supported) {
    $Items.IPSec.FullData = "`n$Spacer IPsec Enabled - $($Items.IPsec.Result.enabled)`n"
    if ($Items.IPsecPolicy.Result.num_records -ne 0) {
      $Items.IPSecPolicy.FullData = $Items.IPsecPol.Result.records | Format-Table | Out-String -Stream | Add-Indentation
    }
    else {
      $Items.IPSecPolicy.FullData = "$Spacer No IPsec Policies Found.`n"
    }
    $Items.IPSec.Summary = Add-Summary $Items.IPSec.SummaryItem $Items.IPsec.Result.enabled 4
    $Items.IPSecPolicy.Summary = Add-Summary $Items.IPSecPolicy.SummaryItem ($Items.IPsecPolicy.Result.num_records -ne 0) 4
  }
  else {
    $Items.IPSec.FullData = "`n$Spacer IPsec is not supported in this release. Consider upgrading to 9.8 or later.`n"
    $Items.IPSec.Summary = Add-Summary $Items.IPSec.SummaryItem "Not available in this release" 4
    $Items.IPSecPolicy.Summary = Add-Summary $Items.IPSecPolicy.SummaryItem "Not available in this release" 4
  }

  # Problematic Ciphers
  $Items.SSHCiphers.FullHeader = $ItemHeaders.SSHCiphers
  if ($Items.SSHCiphers.Result.num_records -ne 0) {
    ForEach ($_ in $Items.SSHCiphers.Result.records) {
      $Items.SSHCiphers.VServer = $_.vserver
      $Items.SSHCiphers.Ciphers = $_.ciphers -split ","
      $Items.SSHCiphers.Formatted = @()
      ForEach ($_ in $Items.SSHCiphers.Ciphers) {
        if ($_.contains("cbc")) {
          $Items.SSHCiphers.Formatted += New-Object -TypeName psobject -Property @{VServer = $Items.SSHCiphers.VServer; Cipher = $_ }
        }
      }
    }
    $Items.SSHCiphers.FullData = $Items.SSHCiphers.Formatted | Format-Table VServer, Cipher | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SSHCiphers.FullData = "`n$Spacer No Problematic Ciphers Found.`n"
  }
  $Items.SSHCiphers.Summary = Add-Summary $Items.SSHCiphers.SummaryItem ($Items.SSHCiphers.Result.num_records -eq 0) 4

  # Problematic Algorithms
  $Items.SSHAlgorithms.FullHeader = $ItemHeaders.SSHAlgorithms
  if ($Items.SSHAlgorithms.Result.num_records -ne 0) {
    ForEach ($_ in $Items.SSHAlgorithms.Result.records) {
      $Items.SSHAlgorithms.VServer = $_.vserver
      $Items.SSHAlgorithms.Algorithms = $_.mac_algorithms -split ","
      $Items.SSHAlgorithms.Formatted = @()
      ForEach ($_ in $Items.SSHAlgorithms.Algorithms) {
        if ($_.contains("etm")) {
          $Items.SSHAlgorithms.Formatted += New-Object -TypeName psobject -Property @{VServer = $Items.SSHAlgorithms.VServer; Algorithm = $_ }
        }
      }
    }
    $Items.SSHAlgorithms.FullData = $Items.SSHAlgorithms.Formatted | Format-Table VServer, Algorithm | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SSHAlgorithms.FullData = "`n$Spacer No Problematic Algorithms Found.`n"
  }
  $Items.SSHAlgorithms.Summary = Add-Summary $Items.SSHAlgorithms.SummaryItem ($Items.SSHAlgorithms.Result.num_records -eq 0) 4

  # Self-Signed Certificates
  $Items.SelfSignedCerts.FullHeader = $ItemHeaders.SelfSignedCerts
  if ($Items.SelfSignedCerts.Result.num_records -ne 0) {
    $Items.SelfSignedCerts.Formatted = ForEach ($_ in $Items.SelfSignedCerts.Result.records) {
      New-Object psobject -Property @{
        VServer       = ($_.vserver).ToString()
        CommonName    = ($_.common_name).ToString()
        Serial        = ($_.serial).ToString()
        CA            = ($_.ca).ToString()
        Type          = ($_.type).ToString()
        "Self-Signed" = ($_.self_signed).ToString()
      }
    }
    $Items.SelfSignedCerts.FullData = $Items.SelfSignedCerts.Formatted | Format-Table Vserver, CommonName, Serial, CA, Type, "Self-Signed" | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SelfSignedCerts.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.SelfSignedCerts.Summary = Add-Summary $Items.SelfSignedCerts.SummaryItem ($Items.SelfSignedCerts.Result.num_records -eq 0) 4

  # Expired Certificates
  $Items.ExpiredCerts.FullHeader = $ItemHeaders.ExpiredCerts
  $Items.ExpiredCerts.Formatted = ForEach ($_ in $Items.ExpiredCerts.Result.records) {
    if ($_.expiration -lt (Get-Date)) {
      New-Object psobject -Property @{
        VServer    = ($_.vserver).ToString()
        CommonName = ($_.common_name).ToString()
        Expiration = ($_.expiration).ToString()
      }
    }
  }
  if ($Items.ExpiredCerts.Formatted.Count -gt 0) {
    $Items.ExpiredCerts.FullData = $Items.ExpiredCerts.Formatted | Format-Table Vserver, CommonName, Expiration | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.ExpiredCerts.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.ExpiredCerts.Summary = Add-Summary $Items.ExpiredCerts.SummaryItem ($Items.ExpiredCerts.Formatted.Count -eq 0) 4

  # SSL Client, HTTP, and ONTAPI Users
  $Items.SSLConfig.FullHeader = $ItemHeaders.SSLConfig
  $Items.SSLConfig.Formatted = ForEach ($_ in $Items.SSLConfig.Result.records) {
    New-Object psobject -Property @{
      VServer          = ($_.vserver).ToString()
      "Client Enabled" = ($_.client_enabled).ToString()
    }
  }
  $Items.SSLConfig.FullData = $Items.SSLConfig.Formatted | Format-Table VServer, "Client Enabled" | Out-String -Stream | Add-Indentation
  $Items.SSLConfig.Summary = Add-Summary $Items.SSLConfig.SummaryItem (!$Items.SSLConfig.Formatted."Client Enabled".contains("True)")) 4
  $Items.HTTPUsers.Formatted = ForEach ($_ in $Items.HTTPUsers.Result.records) {
    New-Object psobject -Property @{
      VServer     = ($_.vserver).ToString()
      Username    = ($_.user_or_group_name).ToString()
      Application = ($_.application).ToString()
      AuthMethod  = ($_.authentication_method).ToString()
    }
  }
  $Items.ONTAPIUsers.Formatted = ForEach ($_ in $Items.ONTAPIUsers.Result.records) {
    New-Object psobject -Property @{
      VServer     = ($_.vserver).ToString()
      Username    = ($_.user_or_group_name).ToString()
      Application = ($_.application).ToString()
      AuthMethod  = ($_.authentication_method).ToString()
    }
  }
  if ($Items.HTTPUsers.Result.records.num_records -ne 0) {
    $Items.HTTPUsers.FullHeader = "$Spacer HTTP Users"
    $Items.HTTPUsers.FullData = $Items.HTTPUsers.Formatted | Format-Table VServer, Username, Application, AuthMethod | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.HTTPUsers.FullData = "`n$Spacer No HTTP Users Found.`n"
  }
  if ($Items.ONTAPIUsers.Result.records.num_records -ne 0) {
    $Items.ONTAPIUsers.FullHeader = "$Spacer ONTAPI Users"
    $Items.ONTAPIUsers.FullData = $Items.ONTAPIUsers.Formatted | Format-Table VServer, Username, Application, AuthMethod | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.ONTAPIUsers.FullData = "`n$Spacer No ONTAPI Users Found.`n"
  }

  # OCSP
  $Items.OCSPConfig.FullHeader = $ItemHeaders.OCSPConfig
  $Items.OCSPConfig.Formatted = ForEach ($_ in $Items.OCSPConfig.Result.records) {
    New-Object psobject -Property @{
      Application    = ($_.application).ToString()
      "OCSP Enabled" = ($_.is_ocsp_enabled).ToString()
    }
  }
  $Items.OCSPConfig.FullData = $Items.OCSPConfig.Formatted | Format-Table Application, "OCSP Enabled" | Out-String -Stream | Add-Indentation
  $Items.OCSPConfig.Summary = Add-Summary $Items.OCSPConfig.SummaryItem (!$Items.OCSPConfig.Formatted."OCSP Enabled".contains("False")) 4

  # SAML
  $Items.SAML.FullHeader = $ItemHeaders.SAML
  if ($Items.SAML.Result.records.num_records -ne 0) {
    $Items.SAML.Formatted = ForEach ($_ in $Items.SAML.Result.records) {
      New-Object psobject -Property @{
        Node    = ($_.node).ToString()
        Status  = ($_.status).ToString()
        Enabled = ($_.is_enabled).ToString()
      }
    }
    $Items.SAML.FullData = $Items.SAML.Formatted | Format-Table Node, Status, Enabled | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SAML.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.SAML.Summary = Add-Summary $Items.SAML.SummaryItem (!$Items.SAML.Formatted.enabled.contains("False")) 4
  # End - Secure Communication - Category 4

  # Begin - File Access - Category 5
  # CIFS Things
  #
  # Skip the entire section if there are no CIFS svms
  if ($Items.CIFSSvms.Result.num_records -ne 0) {
    # CIFS Signing
    $Items.CIFSSigning.FullHeader = $ItemHeaders.CIFSSigning
    $Items.CIFSSigning.Formatted = ForEach ($_ in $Items.CIFSSigning.Result.records) {
      New-Object psobject -Property @{
        VServer            = ($_.vserver).ToString()
        "Signing Required" = ($_.is_signing_required).ToString()
      }
    }
    $Items.CIFSSigning.FullData = $Items.CIFSSigning.Formatted | Format-Table VServer, "Signing Required" | Out-String -Stream | Add-Indentation
    $Items.CIFSSigning.Summary = Add-Summary $Items.CIFSSigning.SummaryItem (!$Items.CIFSSigning.Formatted."Signing Required".contains("False")) 5

    # CIFS Workgroups
    $Items.CIFSWorkgroup.FullHeader = $ItemHeaders.CIFSWorkgroup
    if ($Items.CIFSWorkgroup.Result.num_records -ne 0) {
      $Items.CIFSWorkgroup.Formatted = ForEach ($_ in $Items.CIFSWorkgroup.Result.records) {
        New-Object psobject -Property @{
          VServer      = ($_.vserver).ToString()
          "Auth Style" = ($_.auth_style).ToString()
        }
      }
      $Items.CIFSWorkgroup.FullData = $Items.CIFSWorkgroup.Formatted | Format-Table VServer, "Auth Style" | Out-String -Stream | Add-Indentation
    }
    else {
      $Items.CIFSWorkgroup.FullData = "`n$Spacer No CIFS SVMs configured for workgroup access.`n"
    }
    $Items.CIFSWorkgroup.Summary = Add-Summary $Items.CIFSWorkgroup.SummaryItem ($Items.CIFSWorkgroup.Result.num_records -eq 0) 5

    # CIFS SMB1
    $Items.CIFSSMB1.FullHeader = $ItemHeaders.CIFSSMB1
    if ($Items.CIFSSMB1.Result.num_records -ne 0) {
      $Items.CIFSSMB1.Formatted = ForEach ($_ in $Items.CIFSSMB1.Result.records) {
        New-Object psobject -Property @{
          VServer        = ($_.vserver).ToString()
          "SMB1 Enabled" = ($_.smb1_enabled).ToString()
        }
      }
      $Items.CIFSSMB1.FullData = $Items.CIFSSMB1.Formatted | Format-Table VServer, "SMB1 Enabled" | Out-String -Stream | Add-Indentation
    }
    else {
      $Items.CIFSSMB1.FullData = "`n$Spacer No CIFS SVMs configured for SMB1.`n"
    }
    $Items.CIFSSMB1.Summary = Add-Summary $Items.CIFSSMB1.SummaryItem ($Items.CIFSSMB1.Result.num_records -eq 0) 5

    # AD LDAP
    $Items.LDAP.FullHeader = $ItemHeaders.LDAP
    $Items.LDAP.Formatted = ForEach ($_ in $Items.LDAP.Result.records) {
      if ($Items.CIFSSvms.Result.records -match ($_.vserver)) {
        New-Object psobject -Property @{
          VServer                        = ($_.vserver).ToString()
          "Session Security for AD LDAP" = ($_.session_security_for_ad_ldap).ToString()
        }
      }
    }
    $Items.LDAP.FullData = $Items.LDAP.Formatted | Format-Table VServer, "Session Security for AD LDAP" | Out-String -Stream | Add-Indentation
    $Items.LDAP.Summary = Add-Summary $Items.LDAP.SummaryItem (!$Items.LDAP.Formatted."Session Security for AD LDAP".contains("none")) 5

    # CIFS VScan
    $Items.VScan.FullHeader = $ItemHeaders.VScan
    $Items.VScan.Formatted = ForEach ($_ in $Items.VScan.Result.records) {
      if ($Items.CIFSSvms.Result.records -match ($_.vserver)) {
        New-Object psobject -Property @{
          VServer        = ($_.vserver).ToString()
          "VScan Status" = ($_.vscan_status).ToString()
        }
      }
    }
    $Items.VScan.FullData = $Items.VScan.Formatted | Format-Table VServer, "VScan Status" | Out-String -Stream | Add-Indentation
    $Items.VScan.Summary = Add-Summary $Items.VScan.SummaryItem (!$Items.VScan.Formatted."VScan Status".contains("off")) 5
    # CIFS SVMs Found
    $Items.CIFSSvms.Summary = Add-Summary $Items.CIFSSvms.SummaryItem "True" 5
  }
  else {
    # CIFS SVMs Not Found
    $Items.CIFSSvms.Summary = Add-Summary $Items.CIFSSvms.SummaryItem "No CIFS SVMs Found" 5
  }

  # FPolicy
  $Items.FPolicy.FullHeader = $ItemHeaders.FPolicy
  if ($Items.Fpolicy.Result.num_records -ne 0) {
    $Items.Fpolicy.Formatted = ForEach ($_ in $Items.Fpolicy.Result.records) {
      New-Object psobject -Property @{
        VServer       = ($_.vserver).ToString()
        "Policy Name" = ($_.policy_name).ToString()
        Status        = ($_.status).ToString()
        Engine        = ($_.engine).ToString()
      }
    }
    $Items.FPolicy.FullData = $Items.Fpolicy.Formatted | Format-Table VServer, "Policy Name", Status, Engine | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.FPolicy.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.FPolicy.Summary = Add-Summary $Items.FPolicy.SummaryItem ($Items.Fpolicy.Result.num_records -ne 0) 5

  # NAS Auditing
  $Items.NASAuditing.FullHeader = $ItemHeaders.NASAuditing
  if ($Items.NASAuditing.Result.num_records -ne 0) {
    $Items.NASAuditing.Formatted = ForEach ($_ in $Items.NASAuditing.Result.records) {
      New-Object psobject -Property @{
        VServer = ($_.vserver).ToString()
        Enabled = ($_.state).ToString()
      }
    }
    $Items.NASAuditing.FullData = $Items.NASAuditing.Formatted | Format-Table VServer, Enabled | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.NASAuditing.FullData = "`n$Spacer No NAS Auditing Configuration Found.`n"
  }
  $Items.NASAuditing.Summary = Add-Summary $Items.NASAuditing.SummaryItem ($Items.NASAuditing.Result.num_records -ne 0) 5

  # NIS
  $Items.NISServers.FullHeader = $ItemHeaders.NISServers
  if ($Items.NISServers.Result.num_records -ne 0) {
    $Items.NISServers.Formatted = ForEach ($_ in $Items.NISServers.Result.records) {
      New-Object psobject -Property @{
        VServer   = ($_.name).ToString()
        NISDomain = ($_.nis.domain).ToString()
      }
    }
    $Items.NISServers.FullData = $Items.NISServers.Formatted | Format-Table vserver, nisdomain | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.NISServers.FullData = "`n$Spacer No NIS Configuration Found.`n"
  }
  $Items.NISServers.Summary = Add-Summary $Items.NISServers.SummaryItem ($Items.NISServers.Result.num_records -eq 0) 5
  # End - File Access - Category 5

  # Begin - Data Protection - Category 6
  # Snapshot Autodeletion
  $Items.SnapShotAutoDelete.FullHeader = $ItemHeaders.SnapShotAutoDelete
  if ($Items.SnapShotAutoDelete.Result.num_records -ne 0) {
    $Items.SnapShotAutoDelete.Formatted = ForEach ($_ in $Items.SnapShotAutoDelete.Result.records) {
      New-Object psobject -Property @{
        VServer = ($_.vserver).ToString()
        Enabled = ($_.enabled).ToString()
        Volume  = ($_.volume).ToString()
      }
    }
    $Items.SnapShotAutoDelete.FullData = $Items.SnapShotAutoDelete.Formatted | Format-Table VServer, Volume, Enabled | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.SnapShotAutoDelete.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.SnapShotAutoDelete.Summary = Add-Summary $Items.SnapShotAutoDelete.SummaryItem ($Items.SnapShotAutoDelete.Result.num_records -eq 0) 6

  # Snapshot Policy
  $Items.NullSnapShotPolicy.FullHeader = $ItemHeaders.NullSnapShotPolicy
  if ($Items.NullSnapShotPolicy.Result.num_records -ne 0) {
    $Items.NullSnapShotPolicy.Formatted = ForEach ($_ in $Items.NullSnapShotPolicy.Result.records) {
      New-Object psobject -Property @{
        Volume            = ($_.volume).ToString()
        "Snapshot Policy" = "-"
        VServer           = ($_.vserver).ToString()
      }
    }
    $Items.NullSnapShotPolicy.FullData = $Items.NullSnapShotPolicy.Formatted | Format-Table volume, "Snapshot Policy", VServer | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.NullSnapShotPolicy.FullData = "`n$Spacer No Volumes with a Snapshot Policy of NULL."
  }
  if ($Items.NoneSnapShotPolicy.Result.num_records -ne 0) {
    $Items.NoneSnapshotPolicy.Formatted = ForEach ($_ in $Items.NoneSnapShotPolicy.Result.records) {
      New-Object psobject -Property @{
        Volume            = ($_.volume).ToString()
        "Snapshot Policy" = ($_.snapshot_policy).ToString()
        VServer           = ($_.vserver).ToString()
      }
    }
    $Items.NoneSnapShotPolicy.FullData = $Items.NoneSnapshotPolicy.Formatted | Format-Table volume, "Snapshot Policy", VServer | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.NoneSnapShotPolicy.FullData = "`n$Spacer No Volumes with a Snapshot Policy of None.`n"
  }
  $Items.NullSnapShotPolicy.Summary = Add-Summary $Items.NullSnapShotPolicy.SummaryItem ($Items.NullSnapShotPolicy.Result.num_records -eq 0) 6
  $Items.NoneSnapShotPolicy.Summary = Add-Summary $Items.NoneSnapShotPolicy.SummaryItem ($Items.NoneSnapShotPolicy.Result.num_records -eq 0) 6

  # Snapshot Locking
  $Items.SnapShotLocking.FullHeader = $ItemHeaders.SnapShotLocking
  if ($Items.SnapShotLocking.Supported) {
    if ($Items.SnapShotLocking.Result.num_records -ne 0) {
      $Items.SnapShotLocking.Formatted = ForEach ($_ in $Items.SnapShotLocking.Result.records) {
        New-Object psobject -Property @{
          VServer                    = ($_.vserver).ToString()
          Volume                     = ($_.volume).ToString()
          "Snapshot Locking Enabled" = ($_.snapshot_locking_enabled).ToString()
        }
      }
      $Items.SnapShotLocking.FullData = $Items.SnapShotLocking.Formatted | Format-Table VServer, Volume, "Snapshot Locking Enabled" | Out-String -Stream | Add-Indentation
      $Items.SnapShotLocking.Summary = Add-Summary $Items.SnapShotLocking.SummaryItem (!$Items.SnapShotLocking.Formatted."Snapshot Locking Enabled".contains("False")) 6
    }
  }
  else {
    $Items.SnapShotLocking.FullData = "`n$Spacer Snapshot Copy Locking is not supported in this release. Consider upgrading to 9.12.1 or later.`n"
    $Items.SnapShotLocking.Summary = Add-Summary $Items.SnapShotLocking.SummaryItem "Not available in this release" 6
  }
  # End - Data Protection - Category 6

  # Begin - Anti-Ransomware - Category 7
  # SVM Anti-Ransomware
  $Items.SVMAntiRansomware.FullHeader = $ItemHeaders.SVMAntiRansomware
  if ($Items.SVMAntiRansomware.Supported) {
    if ($Items.SVMAntiRansomware.Result.num_records -ne 0) {
      $Items.SVMAntiRansomware.Formatted = ForEach ($_ in $Items.SVMAntiRansomware.Result.records) {
        New-Object psobject -Property @{
          VServer                = ($_.name).ToString()
          "Default Volume State" = ($_.anti_ransomware_default_volume_state).ToString()
        }
      }
      $Items.SVMAntiRansomware.FullData = $Items.SVMAntiRansomware.Formatted | Format-Table VServer, "Default Volume State" | Out-String -Stream | Add-Indentation
      $Items.SVMAntiRansomware.Summary = Add-Summary $Items.SVMAntiRansomware.SummaryItem (!$Items.SVMAntiRansomware.Formatted."Default Volume State".contains("disabled")) 7
    }
    elseif ($Items.SVMs.Result.num_records -eq 0) {
      $Items.SVMAntiRansomware.FullData = "`n$Spacer No Data SVMs Found.`n"
      $Items.SVMAntiRansomware.Summary = Add-Summary $Items.SVMAntiRansomware.SummaryItem "No Data SVMs Found" 7
    }
  }
  else {
    $Items.SVMAntiRansomware.FullData = "`n$Spacer Ransomware Protection is not supported in this release. Consider upgrading to 9.10 or later.`n"
    $Items.SVMAntiRansomware.Summary = Add-Summary $Items.SVMAntiRansomware.SummaryItem "Not available in this release" 7
  }

  # Volume Anti-Ransomware
  $Items.VolumeAntiRansomware.FullHeader = $ItemHeaders.VolumeAntiRansomware
  if ($Items.VolumeAntiRansomware.Supported) {
    if ($Items.VolumeAntiRansomware.Result.num_records -ne 0) {
      $Items.VolumeAntiRansomware.Formatted = ForEach ($_ in $Items.VolumeAntiRansomware.Result.records) {
        New-Object psobject -Property @{
          VServer                 = ($_.vserver).ToString()
          Volume                  = ($_.volume).ToString()
          "Anti Ransomware State" = ($_.anti_ransomware_state).ToString()
        }
      }
      $Items.VolumeAntiRansomware.FullData = $Items.VolumeAntiRansomware.Formatted | Format-Table VServer, Volume, "Anti Ransomware State" | Out-String -Stream | Add-Indentation
      $Items.VolumeAntiRansomware.Summary = Add-Summary $Items.VolumeAntiRansomware.SummaryItem (!$Items.VolumeAntiRansomware.Formatted."Anti Ransomware State".contains("disabled")) 7
    }
    elseif ($Items.SVMs.Result.num_records -eq 0) {
      $Items.VolumeAntiRansomware.FullData = "`n$Spacer No Data SVMs Found.`n"
      $Items.VolumeAntiRansomware.Summary = Add-Summary $Items.VolumeAntiRansomware.SummaryItem "No Data SVMs Found" 7
    }
  }
  else {
    $Items.VolumeAntiRansomware.FullData = "`n$Spacer Ransomware Protection is not supported in this release. Consider upgrading to 9.10 or later.`n"
    $Items.VolumeAntiRansomware.Summary = Add-Summary $Items.VolumeAntiRansomware.SummaryItem "Not available in this release" 7
  }
  # End - Anti-Ransomware - Category 7

  # - Begin - Encryption - Category 8
  # Trusted Platform Module
  $Items.TrustedPlatformModule.FullHeader = $ItemHeaders.TrustedPlatformModule
  if ($Items.TrustedPlatformModule.Supported -eq $True) {
    if ($Items.TrustedPlatformModule.Result.records.is_available -notcontains "no" -and $Items.TrustedPlatformModule.Result.records.is_available -notcontains $null) {
      $Items.TrustedPlatformModule.FullData = "`n$Spacer Trusted Platform Manager is Available for all nodes.`n"
    }
    else {
      $Items.TrustedPlatformModule.FullData = "`n$Spacer Trusted Platform Manager is not Available for all nodes.`n"
    }
  }
  else {
    $Items.TrustedPlatformModule.FullData = "`n$Spacer Trusted Platform Manager is not available in this release.`n"
  }
  $Items.TrustedPlatformModule.Summary = Add-Summary $Items.TrustedPlatformModule.SummaryItem ($Items.TrustedPlatformModule.Result.records.is_available -notcontains "no" -and $Items.TrustedPlatformModule.Result.records.is_available -notcontains $null) 8

  # Key Manager
  $Items.KeyManager.FullHeader = $ItemHeaders.KeyManager
  if ($Items.KeyManager.Result.num_records -ne 0) {
    $Items.KeyManager.FullData = "`n$Spacer Key-Manager is configured."
  }
  else {
    $Items.KeyManager.FullData = "`n$Spacer No Key-Manager Found."
  }
  $Items.KeyManager.Summary = Add-Summary $Items.KeyManager.SummaryItem ($Items.KeyManager.Result.num_records -ne 0) 8

  # Drive Protection
  if ($Items.DriveProtection.Result.num_records -ne 0) {
    $Items.DriveProtection.Formatted = ForEach ($_ in $Items.DriveProtection.Result.records) {
      New-Object psobject -Property @{
        Aggregate                  = ($_.aggregate).ToString()
        Node                       = ($_.node).ToString()
        "Drive Protection Enabled" = ($_.drive_protection_enabled).ToString()
      }
    }
    $Items.DriveProtection.FullData = $Items.DriveProtection.Formatted | Format-Table Aggregate, Node, "Drive Protection Enabled" | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.DriveProtection.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.DriveProtection.Summary = Add-Summary $Items.DriveProtection.SummaryItem (!$Items.DriveProtection.Formatted."Drive Protection Enabled".contains("False")) 8

  # Volume Encryption
  if ($Items.VolumeEncryption.Result.num_records -ne 0) {
    $Items.VolumeEncryption.Formatted = ForEach ($_ in $Items.VolumeEncryption.Result.records) {
      New-Object psobject -Property @{
        VServer           = ($_.vserver).ToString()
        Volume            = ($_.volume).ToString()
        "Encryption Type" = ($_.encryption_type).ToString()
        "Is Encrypted"    = ($_.is_encrypted).ToString()
      }
    }
    $Items.VolumeEncryption.FullData = $Items.VolumeEncryption.Formatted | Format-Table VServer, Volume, "Encryption Type", "Is Encrypted" | Out-String -Stream | Add-Indentation
  }
  else {
    $Items.VolumeEncryption.FullData = "`n$Spacer No Results Returned.`n"
  }
  $Items.VolumeEncryption.Summary = Add-Summary $Items.VolumeEncryption.SummaryItem (!$Items.VolumeEncryption.Formatted."Is Encrypted".contains("False")) 8
  # - End - Encryption - Category 8
}

# Output Functions
# Output to Text File
function Write-Data {
  process {
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
    if ($($Items[$key].Summary)) {
      $SummaryData += $Items[$key].Summary
    }
  }
  Write-Output "Summary`n$Separator" | Write-Data
  Write-Output $SummaryData | Format-Table Item, Finding, Topic -HideTableHeaders | Out-String -Stream | Add-Indentation | Write-Data
  Write-Output $Separator | Write-Data
}

# Output Full Data
function Show-FullOutput {
  Write-Output "Full Details" | Write-Data
  foreach ($Index in $Categories.Keys) {
    Write-Output "$Separator`n-- $($Categories.$Index) --" | Write-Data
    foreach ($key in $Items.Keys) {
      if ($($Items[$key].Category) -eq $Index) {
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
