<# This snippet collects DACL information for the newly created test objects. Run this after Create-ObjectOwners.ps1#>
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Get-OwnerACEs.txt -append

$TargetOU = (Get-ADDomain).DistinguishedName
$TargetOU1 = "OU=OwnerRightsTest,"+$TargetOU
$TargetOU2 = "OU=NoOwnerRightsTest,"+$TargetOU
$ACLList = @()
$ADObjects = Get-ADObject -Filter * -SearchBase $TargetOU1
$ADObjects += Get-ADObject -Filter * -SearchBase $TargetOU2

foreach ($ADObject in $ADObjects) {
    $DistinguishedName = $ADObject.DistinguishedName
    $DACL = Get-Acl $DistinguishedName
    $ACL = $DACL.Access 
    $ACL |  Add-Member -MemberType NoteProperty -Name 'Object DN' -Value $DistinguishedName
    $ACL |  Add-Member -MemberType NoteProperty -Name 'Owner' -Value $DACL.Owner
    $ACLList += $ACL 
}
$ACLList | Format-Table -AutoSize
$ACLList | Out-GridView -title "ACLs on Test AD Objects"

Stop-Transcript