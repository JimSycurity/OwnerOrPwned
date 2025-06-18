<#
.Synopsis
    Revert-OwnsEdge.ps1

    AUTHOR: Jim Sykora

    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
    FITNESS FOR A PARTICULAR PURPOSE.

.DESCRIPTION
    A .NET based function to remove a GenericAll ACE on the target object by abusing the implicit object ownership right to WriteDACL.  
    Must be executed in the context of the current owner of the object.

.EXAMPLE
    .\Revert-OwnsEdge.ps1

    Revert-OwnsEdge -DistinguishedName 'CN=SD-DC2025,OU=Domain Controllers,DC=AD2025,DC=lan'
    Revert-OwnsEdge -DistinguishedName "CN=TestOU,DC=domain,DC=com" -Verbose
    Revert-OwnsEdge -DistinguishedName "CN=TestOU,DC=domain,DC=com" -Trustee "DOMAIN\username" -Verbose
    Revert-OwnsEdge -DistinguishedName "CN=TestOU,DC=domain,DC=com" -Trustee "username" -Verbose
#>
function Revert-OwnsEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        
        [Parameter(Mandatory = $false)]
        [string]$Trustee
    )
    
    try {
        # Validate and create ADSI object from Distinguished Name
        Write-Verbose "Attempting to bind to Distinguished Name: $DistinguishedName"
        $adsiObject = [ADSI]"LDAP://$DistinguishedName"
        
        # Test if the object exists by accessing a property
        $null = $adsiObject.distinguishedName
        if ([string]::IsNullOrEmpty($adsiObject.distinguishedName)) {
            throw "Distinguished Name '$DistinguishedName' does not exist or is not accessible"
        }
        
        Write-Verbose "Successfully bound to AD object: $($adsiObject.distinguishedName)"
        
        # Determine the SID to use
        $targetSid = $null
        if ([string]::IsNullOrEmpty($Trustee)) {
            # Use current user's SID
            Write-Verbose "No trustee specified, using current user context"
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $targetSid = $currentUser.User
            Write-Verbose "Current user SID: $($targetSid.Value)"
        }
        else {
            # Look up the trustee in Active Directory
            Write-Verbose "Looking up trustee: $Trustee"
            try {
                # Try to resolve as NTAccount first
                $ntAccount = New-Object System.Security.Principal.NTAccount($Trustee)
                $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                Write-Verbose "Resolved trustee '$Trustee' to SID: $($targetSid.Value)"
            }
            catch {
                # If NTAccount fails, try with domain prefix
                try {
                    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                    $domainTrustee = "$domain\$Trustee"
                    Write-Verbose "Attempting to resolve with domain prefix: $domainTrustee"
                    $ntAccount = New-Object System.Security.Principal.NTAccount($domainTrustee)
                    $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                    Write-Verbose "Resolved trustee '$domainTrustee' to SID: $($targetSid.Value)"
                }
                catch {
                    throw "Could not resolve trustee '$Trustee' to a valid SID: $($_.Exception.Message)"
                }
            }
        }
               
        # Create the access rule for GenericAll rights
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $targetSid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        Write-Verbose "Removing access rule for GenericAll rights"
        Write-Verbose "Identity: $($targetSid.Value)"
        Write-Verbose "Rights: GenericAll"
        Write-Verbose "Access Type: Allow"
        
        # Add the access rule to the security descriptor
        $adsiObject.PsBase.Options.SecurityMasks = 'Dacl'
        $adsiObject.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($ACE)

        
        # Commit the changes back to Active Directory
        Write-Verbose "Committing security descriptor changes to Active Directory"
        $adsiObject.PsBase.CommitChanges()
        
        Write-Verbose "Successfully removed GenericAll ACE to $($targetSid.Value) on $DistinguishedName"
        
        # Return success information
        return [PSCustomObject]@{
            DistinguishedName = $DistinguishedName
            GrantedTo = $targetSid.Value
            Rights = "GenericAll"
            AccessType = "Allow"
            Success = $true
        }
    }
    catch {
        Write-Error "Failed to set permissions on '$DistinguishedName': $($_.Exception.Message)"
        return [PSCustomObject]@{
            DistinguishedName = $DistinguishedName
            GrantedTo = if ($targetSid) { $targetSid.Value } else { "Unknown" }
            Rights = "GenericAll"
            AccessType = "Allow"
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

