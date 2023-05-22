#Query Current dSHeuristics in current AD Domain
(Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -Properties dSHeuristics).dSHeuristics

#Set Default dSHeuristics
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -clear dSHeuristics

# KB5008383 Enforcement Mode for LDAP Add and LDAP Modify, Set 28th and 29th characters to 1
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -replace @{dSHeuristics='00000000010000000002000000011'}


# Disable UPN Uniqueness Check, Set 21st Character to 1
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -replace @{dSHeuristics='000000000100000000021'}

# Disable SPN Uniqueness Check, Set 21st Character to 2
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -replace @{dSHeuristics='000000000100000000022'}

# Disable UPN & SPN Uniqueness Check, Set 21st Character to 3
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -replace @{dSHeuristics='000000000100000000023'}

# Set marvel.local back to how it was before
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName) -replace @{dSHeuristics='0010000001000004'}
0010000001000004
fDoListObject
tenthChar
dwAdminSDExMask: 4 (PrintOperators)


00000000010000000002000000011