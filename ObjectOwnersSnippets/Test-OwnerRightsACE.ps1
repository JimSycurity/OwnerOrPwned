function Test-OwnerRightsACE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )
    
    try {
        # Create the OwnerRights SID (S-1-3-4)
        $ownerRightsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-3-4")
        Write-Verbose "Searching for OwnerRights SID: $($ownerRightsSid.Value)"
        
        # Bind to the AD object
        Write-Verbose "Binding to Distinguished Name: $DistinguishedName"
        $adsiObject = [ADSI]"LDAP://$DistinguishedName"
        
        # Validate the object exists
        $null = $adsiObject.distinguishedName
        if ([string]::IsNullOrEmpty($adsiObject.distinguishedName)) {
            throw "Distinguished Name '$DistinguishedName' does not exist or is not accessible"
        }
        
        Write-Verbose "Successfully bound to AD object: $($adsiObject.distinguishedName)"
        
        # Get the security descriptor and DACL
        $securityDescriptor = $adsiObject.ObjectSecurity
        $dacl = $securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        
        Write-Verbose "Retrieved DACL with $($dacl.Count) access rules"
        
        # Initialize results collection
        $ownerRightsACEs = @()
        $aceIndex = 0
        
        # Iterate through each ACE in the DACL
        foreach ($ace in $dacl) {
            Write-Verbose "Examining ACE $aceIndex - Identity: $($ace.IdentityReference.Value)"
            
            # Check if this ACE has the OwnerRights SID
            if ($ace.IdentityReference.Value -eq $ownerRightsSid.Value) {
                Write-Verbose "Found OwnerRights ACE at index $aceIndex"
                
                # Create detailed ACE information object
                $aceInfo = [PSCustomObject]@{
                    Index = $aceIndex
                    IdentityReference = $ace.IdentityReference.Value
                    AccessControlType = $ace.AccessControlType.ToString()
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                    InheritanceType = $ace.InheritanceType.ToString()
                    InheritedObjectType = $ace.InheritedObjectType.ToString()
                    ObjectType = $ace.ObjectType.ToString()
                    ObjectFlags = $ace.ObjectFlags.ToString()
                    InheritanceFlags = $ace.InheritanceFlags.ToString()
                    PropagationFlags = $ace.PropagationFlags.ToString()
                }
                
                $ownerRightsACEs += $aceInfo
                
                Write-Verbose "ACE Details - Type: $($ace.AccessControlType), Rights: $($ace.ActiveDirectoryRights)"
            }
            
            $aceIndex++
        }
        
        # Create summary result
        $result = [PSCustomObject]@{
            DistinguishedName = $DistinguishedName
            OwnerRightsACEsFound = $ownerRightsACEs.Count
            HasOwnerRightsACEs = ($ownerRightsACEs.Count -gt 0)
            TotalACEsInDACL = $dacl.Count
            OwnerRightsACEs = $ownerRightsACEs
            Success = $true
        }
        
        if ($result.HasOwnerRightsACEs) {
            Write-Verbose "Found $($result.OwnerRightsACEsFound) OwnerRights ACE(s) in DACL"
        } else {
            Write-Verbose "No OwnerRights ACEs found in DACL"
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to examine ACEs for '$DistinguishedName': $($_.Exception.Message)"
        return [PSCustomObject]@{
            DistinguishedName = $DistinguishedName
            OwnerRightsACEsFound = 0
            HasOwnerRightsACEs = $false
            TotalACEsInDACL = 0
            OwnerRightsACEs = @()
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Example usage:
# Test-OwnerRightsACE -DistinguishedName "CN=TestOU,DC=domain,DC=com" -Verbose
# $result = Test-OwnerRightsACE -DistinguishedName "CN=TestUser,CN=Users,DC=domain,DC=com"
# $result.OwnerRightsACEs | Format-Table -AutoSize