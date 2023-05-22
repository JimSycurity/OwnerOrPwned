<# This snippet collects ACE entries for nonstandard Owners for the newly created test objects.
Run this after Create-ObjectOwners.ps1#>
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Get-ObjectOwnerInfoTable.txt -append

$ADObjects = @()
$TargetOU = (Get-ADDomain).DistinguishedName
$TargetOU1 = "OU=OwnerRightsTest,"+$TargetOU
$TargetOU2 = "OU=NoOwnerRightsTest,"+$TargetOU
$ACLList = @()
$ADObjects = Get-ADObject -Filter * -SearchBase $TargetOU1 -Properties ntSecurityDescriptor | Select-Object -Property DistinguishedName, Name, @{Name='ntSecurityDescriptorOwner'; Expression={$_.ntSecurityDescriptor.Owner }}
$ADObjects += Get-ADObject -Filter * -SearchBase $TargetOU2  -Properties ntSecurityDescriptor | Select-Object -Property DistinguishedName, Name, @{Name='ntSecurityDescriptorOwner'; Expression={$_.ntSecurityDescriptor.Owner }}
Set-Location AD:
foreach($ADObject in $ADObjects) {
    Write-Host "AD Object: " $ADObject.DistinguishedName
    Write-Host "Owner: " $ADObject.ntSecurityDescriptorOwner
    $ACL = (get-acl $ADObject.DistinguishedName).Access 
    $ACLList = $ACL | Where-Object { $_.IdentityReference -eq $ADObject.ntSecurityDescriptorOwner}
    $ACLList | Format-Table -AutoSize -Property IdentityReference, ActiveDirectoryRights, ObjectType #, AccessControlType, InheritedObjectType, InheritanceType, InheritanceFlags, PropagationFlags
    Write-Host "-------------------------------------------------"
}
Stop-Transcript