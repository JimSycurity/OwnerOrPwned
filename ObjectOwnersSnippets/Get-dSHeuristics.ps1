# Query Current dSHeuristics in current AD Forest
(Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Properties dSHeuristics).dSHeuristics

# KB5008383 Enforcement Mode for LDAP Add and LDAP Modify, Set 28th and 29th characters to 1
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000011'}



## dSHeuristics Value for KB5008383 with all other settings defaulted:
00000000010000000002000000011

# Set Default dSHeuristics #
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -clear dSHeuristics
