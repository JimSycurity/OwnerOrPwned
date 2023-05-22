<# This snippet collects ACE entries for nonstandard Owners for the newly created test objects. Run this after Create-ObjectOwners.ps1#>
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Get-ObjectOwnerInfo2.txt -append


$ADObjects = @()
$Domain = Get-ADDomain
$DomainRoot = $Domain.DistinguishedName
$DomainNETBIOS = $Domain.NetBIOSName
$IRMask = @("$DomainNETBIOS\Domain Admins", "$DomainNETBIOS\Enterprise Admins", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "Everyone", "$DomainNETBIOS\Exchange Windows Permissions", "$DomainNETBIOS\Organization Management", "$DomainNETBIOS\Delegated Setup", "$DomainNETBIOS\Cert Publishers", "S-1-5-32-554", "S-1-5-32-548", "S-1-5-32-550", 
"S-1-5-32-560", "S-1-5-32-560", "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS", "NT AUTHORITY\Authenticated Users", "NT AUTHORITY\NETWORK SERVICE", "$DomainNETBIOS\Key Admins", "$DomainNETBIOS\Enterprise Key Admins", "$DomainNETBIOS\Exchange Trusted Subsystem", "$DomainNETBIOS\Exchange Servers")

$ADObjects = Get-ADObject -Filter * -properties ntSecurityDescriptor | Select-Object -Property Name, @{Name='ntSecurityDescriptorOwner'; Expression={$_.ntSecurityDescriptor.Owner }}, DistinguishedName | where { $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\Domain Admins" -and $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\Enterprise Admins" -and $_.ntSecurityDescriptorOwner -notlike "NT AUTHORITY\SYSTEM" -and $_.ntSecurityDescriptorOwner -notlike "BUILTIN\Administrators" -and $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\*`$" }

Set-Location AD:
foreach($ADObject in $ADObjects) {
    Write-Host "AD Object: " $ADObject.DistinguishedName
    Write-Host "Owner: " $ADObject.ntSecurityDescriptorOwner
    $ACL = (get-acl $ADObject.DistinguishedName).Access 

    #$ACLList = $ACL | Where-Object { $_.IdentityReference -notin $IRMask}

    $ACLList = $ACL | Where-Object { $_.IdentityReference -eq $ADObject.ntSecurityDescriptorOwner}
    $ACLList
    Write-Host "-------------------------------------------------"
}

Stop-Transcript