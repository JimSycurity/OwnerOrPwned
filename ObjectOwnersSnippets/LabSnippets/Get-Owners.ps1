<# This snippet collects Owner information for the newly created test objects. Run this after Create-ObjectOwners.ps1#>
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Get-Owners.txt -append

$TargetOU = (Get-ADDomain).DistinguishedName
$TargetOU1 = "OU=OwnerRightsTest,"+$TargetOU
$TargetOU2 = "OU=NoOwnerRightsTest,"+$TargetOU
$ACLList = @()
$ADObjects = Get-ADObject -Filter * -SearchBase $TargetOU1
$ADObjects += Get-ADObject -Filter * -SearchBase $TargetOU2

foreach ($ADObject in $ADObjects) {
    $DistinguishedName = $ADObject.DistinguishedName
    $ACL = (Get-Acl $DistinguishedName) | Select-Object -Property Path, Owner
   # $ACL |  Add-Member -MemberType NoteProperty -Name 'Object DN' -Value $DistinguishedName
   $ACL.Path =  $ACL.Path.Substring(68)
   $ACLList += $ACL 
}
$ACLList | Format-Table -AutoSize
$ACLList | Out-GridView -Title "AD Object Ownership Test"
Stop-Transcript