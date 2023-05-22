    # Assign inheritable ListChildren permissions to OWNER RIGHTS for a specific DistinguishedName
    $DN = <DN of Target OU>
   
    Set-Location AD:
    # Need to manually add the SID here due to Owner Rights being a well-known identity.
    $GroupSID =  New-Object System.Security.Principal.SecurityIdentifier("S-1-3-4")
    $ACL = Get-Acl -Path $DN
    
    $Identity = [System.Security.Principal.IdentityReference] $GroupSID
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "ListChildren"
    $Type = [System.Security.AccessControl.AccessControlType] "Allow"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Identity, $ADRight, $Type,  $InheritanceType)
    
    $ACL.AddAccessRule($Rule)
    Set-Acl -Path $DN -AclObject $ACL