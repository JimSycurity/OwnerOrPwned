<# This snippet utilizes the lab environment built in Create-ObjectOwnerFoundation.ps1 to create a set of test and control objects as the test users. Run this Second#>
$Password = Read-Host "Enter a password for test users:"  -AsSecureString
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path C:\Scripts\Create-ObjectOwners.txt -append

$TargetOU = (Get-ADDomain).DistinguishedName
$TargetOU1 = "OU=OwnerRightsTest,"+$TargetOU
$TargetOU2 = "OU=NoOwnerRightsTest,"+$TargetOU
$TargetPC = 'localhost'
# Define an array with all the test users
$DelegatedUsers = @('OwnershipTestEA', 'OwnershipTestDA', 'OwnershipTestAdmin', 'OwnershipTestAO', 'OwnershipTestDFCD', 'OwnershipTestDFCO', 'OwnershipTestDJWD', 'OwnershipTestDOCC', 'OwnershipTestURAJWD', 'OwnershipTestAU', 'OwnershipTestSA1')

foreach ($DelegatedUser in $DelegatedUsers) {
    $ShortUser = $DelegatedUser -replace 'OwnershipTest','OT'
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $DelegatedUser,$Password
    Write-Host "Delegated User: " $DelegatedUser 
    #Invoke Command to run job as different user
    $output =  Invoke-Command -ComputerName $TargetPC  -Credential $Credential -ArgumentList $DelegatedUser, $ShortUser, $TargetOU1, $TargetOU2, $Password -ScriptBlock {param($DelegatedUser, $ShortUser, $TargetOU1, $TargetOU2, $Password)
        whoami.exe /all
        New-ADOrganizationalUnit ("OUby$DelegatedUser") -Path $TargetOU1
        New-ADUser -Name ("User1by $DelegatedUser") -SamAccountName ("User1by$ShortUser") -AccountPassword $Password -Path $TargetOU1 
        New-ADComputer -Name ("PC1by$DelegatedUser") -SamAccountName ("PC1by$ShortUser") -Path $TargetOU1
        New-GPO -Name ("TestGPO1by$DelegatedUser") | new-gplink -Target $TargetOU1
        New-ADOrganizationalUnit ("OUNoby$DelegatedUser") -Path $TargetOU2
        New-ADUser -Name ("User2by $DelegatedUser") -SamAccountName ("User2by$ShortUser") -AccountPassword $Password -Path $TargetOU2
        New-ADComputer -Name ("PC2by$DelegatedUser") -SamAccountName ("PC2by$ShortUser") -Path $TargetOU2
        New-GPO -Name ("TestGPO2by$DelegatedUser") | new-gplink -Target $TargetOU2
    $output
    }  
}

# Define an array with all the users that can only join workstations to domain.  These objects will be created in the CN=Computers container and need to be moved.
$DelegatedUsers = @('OwnershipTestURAJWD', 'OwnershipTestAU', 'OwnershipTestSA1')

foreach ($DelegatedUser in $DelegatedUsers) {
    $ShortUser = $DelegatedUser -replace 'OwnershipTest','OT'
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $DelegatedUser,$Password
    Write-Host "Delegated User: " $DelegatedUser 
    #Invoke Command to run job as different user
    $output =  Invoke-Command -ComputerName $TargetPC  -Credential $Credential -ArgumentList $DelegatedUser, $ShortUser, $TargetOU1, $TargetOU2, $Password -ScriptBlock {param($DelegatedUser, $ShortUser, $TargetOU1, $TargetOU2, $Password)
        whoami.exe /all
        New-ADComputer -Name ("PC1by$DelegatedUser") -SamAccountName ("PC1by$ShortUser") -Description "Move to OwnerRightsTest OU"
        New-ADComputer -Name ("PC2by$DelegatedUser") -SamAccountName ("PC2by$ShortUser") -Description "Move to NoOwnerRightsTest OU"
    $output
    }  
}
Stop-Transcript