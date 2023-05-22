<# This snippet removes the test users from their groups, thus revoking their privileges.  
This allows the snippet in Abuse-Ownership.ps1 to be run so that any actions performed are done only as permissions that remain as an Owner.
Run after collecting a baseline with Get-Owners.ps1, Get-OwnerACEs.ps1, and Get-ObjectOwnerInfo.ps1, but before Abuse-Ownership.ps1#>

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Remove-TestUserGroups.txt -append

# Remove Test Users from Groups for AD Object Ownership Testing
Remove-ADGroupMember -Identity "Domain Admins" -Members OwnershipTestDA -Confirm:$False
Remove-ADGroupMember -Identity "Enterprise Admins" -Members OwnershipTestEA -Confirm:$False
Remove-ADGroupMember -Identity "Administrators" -Members OwnershipTestAdmin -Confirm:$False
Remove-ADGroupMember -Identity "Account Operators" -Members OwnershipTestAO  -Confirm:$False
Remove-ADGroupMember -Identity "DelegatedFullControlDomain" -Members OwnershipTestDFCD -Confirm:$False
Remove-ADGroupMember -Identity "DelegatedFullControlOU" -Members OwnershipTestDFCO -Confirm:$False
Remove-ADGroupMember -Identity "DelegatedJoinWorkstationDomain" -Members OwnershipTestDJWD -Confirm:$False
Remove-ADGroupMember -Identity "DelegatedOUCreateComputer" -Members OwnershipTestDOCC -Confirm:$False
Remove-ADGroupMember -Identity "URAJoinWorkstationDomain" -Members OwnershipTestURAJWD -Confirm:$False
Remove-ADGroupMember -Identity "Server Operators" -Members OwnershipTestSA1 -Confirm:$False

Stop-Transcript