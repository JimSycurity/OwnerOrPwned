<# This snippet lays down the foundation of the lab environment. It creates OUs, groups, delegations, users, and group membership.
Run This First#>

$Password = Read-Host "Enter a password for test users:"  -AsSecureString

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Create-ObjectOwnerFoundation.txt -append

$Domain = Get-ADDomain
$DomainRoot = $Domain.DistinguishedName
$TargetOU = (Get-ADDomain).DistinguishedName
$TestUserOU = "OU=OwnerRightsTestUsers,"+$TargetOU
$TargetOU1 = "OU=OwnerRightsTest,"+$TargetOU
$TargetOU2 = "OU=NoOwnerRightsTest,"+$TargetOU

# Create OUs for Testing AD Object Ownership
    # OU for the test users and delegation groups
    New-ADOrganizationalUnit "OwnerRightsTestUsers" -Path $DomainRoot    
    #Test OU where Owner Rights will have an ACE
    New-ADOrganizationalUnit "OwnerRightsTest" -Path $DomainRoot    
    #Control OU
    New-ADOrganizationalUnit "NoOwnerRightsTest" -Path $DomainRoot  

# Create Security Groups for delegation for AD Object Ownership Testing
    # This group will be delegated Full Control at the domain root.  Note: This is horribly insecure and nobody should do this!
    New-ADGroup -Name "DelegatedFullControlDomain" -SamAccountName "DelegatedFullControlDomain" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be delegated Full Control on both OUs
    New-ADGroup -Name "DelegatedFullControlOU" -SamAccountName "DelegatedFullControlOU" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be delegated the right to join workstations to the domain
    New-ADGroup -Name "DelegatedJoinWorkstationDomain" -SamAccountName "DelegatedJoinWorkstationDomain" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be delegated the right to creat computer objects in both OUs
    New-ADGroup -Name "DelegatedOUCreateComputer" -SamAccountName "DelegatedOUCreateComputer" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be added to a GPO linked to the Domain Controllers OU with the User Rights Assignment to join workstations to the domain
    New-ADGroup -Name "URAJoinWorkstationDomain" -SamAccountName "URAJoinWorkstationDomain" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be added to a GPO linked to the Domain Controllers OU with the User Rights Assignment to SeTakeOwnershipPrivilege:  Take ownership of files or other objects
    New-ADGroup -Name "URASeTakeOwnershipPriv" -SamAccountName "URASeTakeOwnershipPriv" -GroupCategory Security -GroupScope Global -Path $TestUserOU
    # This group will be added to a GPO linked to the Domain Controllers OU with the User Rights Assignment to SeRestorePrivilege:  Restore files and directories
    New-ADGroup -Name "URASeRestorePrivilege" -SamAccountName "URASeRestorePrivilege" -GroupCategory Security -GroupScope Global -Path $TestUserOU

# Delegate Permissions for AD Object Ownership Testing (NOTE: Many of these delegations are dangerous and I'm only doing them here in a lab for testing purposes)
    # Delegate Owner Rights Read Permissions on TargetOU1
    $OrganizationalUnit = $TargetOU1
    $GroupName = "Owner Rights"
    
    Set-Location AD:
    # Need to manually add the SID here due to Owner Rights being a well-known identity.
    $GroupSID =  New-Object System.Security.Principal.SecurityIdentifier("S-1-3-4")
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "ListChildren"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Full Control on Domain
    $OrganizationalUnit = $DomainRoot
    $GroupName = "DelegatedFullControlDomain"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Full Control on TargetOU1
    $OrganizationalUnit = $TargetOU1
    $GroupName = "DelegatedFullControlOU"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Full Control on TargetOU2
    $OrganizationalUnit = $TargetOU2
    $GroupName = "DelegatedFullControlOU"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Join Workstation to Domain
    $OrganizationalUnit = $DomainRoot
    $GroupName = "DelegatedJoinWorkstationDomain"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Computers = [GUID]"bf967a86-0de6-11d0-a285-00aa003049e2"
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type, $Computers, $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Create Computer on TargetOU1
    $OrganizationalUnit = $TargetOU1
    $GroupName = "DelegatedOUCreateComputer"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Computers = [GUID]"bf967a86-0de6-11d0-a285-00aa003049e2"
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type, $Computers, $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL

    # Delegate Create Computer on TargetOU2
    $OrganizationalUnit = $TargetOU2
    $GroupName = "DelegatedOUCreateComputer"
    
    Set-Location AD:
    $Group = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $Group.SID
    $ACL = Get-Acl -Path $OrganizationalUnit
    
    $Computers = [GUID]"bf967a86-0de6-11d0-a285-00aa003049e2"
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type, $Computers, $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $OrganizationalUnit -AclObject $ACL    

    # Note: Script out the GPO for URA to join workstation to domain

# Create User accounts AD Object Ownership testing  (NOTE: It's an awful idea to set users with the same credential. This is for lab purposes only!!)
New-ADUser -Name "OwnershipTest DA" -SamAccountName "OwnershipTestDA" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest EA" -SamAccountName "OwnershipTestEA" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest Admin" -SamAccountName "OwnershipTestAdmin" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest AO" -SamAccountName "OwnershipTestAO" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest DFCD" -SamAccountName "OwnershipTestDFCD" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest DFCO" -SamAccountName "OwnershipTestDFCO" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest DJWD" -SamAccountName "OwnershipTestDJWD" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest DOCC" -SamAccountName "OwnershipTestDOCC" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest URAJWD" -SamAccountName "OwnershipTestURAJWD" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest AuthUsers" -SamAccountName "OwnershipTestAU" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest URATO" -SamAccountName "OwnershipTestURATO" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest URARP" -SamAccountName "OwnershipTestURARP" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest SA1" -SamAccountName "OwnershipTestSA1" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "OwnershipTest BO" -SamAccountName "OwnershipTestBO" -AccountPassword $Password -Enabled $true -Path $TestUserOU
New-ADUser -Name "Attacker Controlled" -SamAccountName "AttackerControlled" -AccountPassword $Password -Enabled $true -Path $TestUserOU

# Add Users to Groups for AD Object Ownership Testing
Add-ADGroupMember -Identity "Domain Admins" -Members OwnershipTestDA
Add-ADGroupMember -Identity "Enterprise Admins" -Members OwnershipTestEA
Add-ADGroupMember -Identity "Administrators" -Members OwnershipTestAdmin
Add-ADGroupMember -Identity "Account Operators" -Members OwnershipTestAO
Add-ADGroupMember -Identity "DelegatedFullControlDomain" -Members OwnershipTestDFCD
Add-ADGroupMember -Identity "DelegatedFullControlOU" -Members OwnershipTestDFCO
Add-ADGroupMember -Identity "DelegatedJoinWorkstationDomain" -Members OwnershipTestDJWD
Add-ADGroupMember -Identity "DelegatedOUCreateComputer" -Members OwnershipTestDOCC
Add-ADGroupMember -Identity "URAJoinWorkstationDomain" -Members OwnershipTestURAJWD
Add-ADGroupMember -Identity "URASeTakeOwnershipPriv" -Members OwnershipTestURATO
Add-ADGroupMember -Identity "URASeRestorePrivilege" -Members OwnershipTestURARP
Add-ADGroupMember -Identity "Server Operators" -Members OwnershipTestSA1
Add-ADGroupMember -Identity "Backup Operators" -Members OwnershipTestBO
# Allow the newly created users to Invoke-Command on DCs without being AD Admins  NOTE: This is not a good idea and I'm only doing this for lab purposes!!!!
Add-ADGroupMember -Identity "Remote Management Users" -Members OwnershipTestDA, OwnershipTestEA, OwnershipTestAdmin, OwnershipTestAO, OwnershipTestDFCD, OwnershipTestDFCO, OwnershipTestDJWD, OwnershipTestDOCC, OwnershipTestURAJWD, OwnershipTestAU, OwnershipTestURATO, OwnershipTestURARP, OwnershipTestSA1, OwnershipTestBO

Stop-Transcript