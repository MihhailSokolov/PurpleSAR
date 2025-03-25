Start-Sleep -Seconds 300

$domain = $args[0]
$numberOfUsers = $args[1]
$username = $args[2]
$userpwd = $args[3]
$credential = New-Object System.Management.Automation.PSCredential($username,$($userpwd | ConvertTo-SecureString -asPlainText -Force))

$domainController = $(Get-ADDomainController -server $domain -Credential $credential).HostName
$rootPath = $(($domain.ToLower().Split(".") | % { "DC=" + $_}) -Join ',')

Write-Host "Creating OUs..."
New-ADOrganizationalUnit -Name "Groups" -Path "$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Employees" -Path "$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Finance" -Path "OU=Employees,$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "IT" -Path "OU=Employees,$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Other" -Path "OU=Employees,$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Systems" -Path "$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Clients" -Path "OU=Systems,$rootPath" -Credential $credential
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Systems,$rootPath" -Credential $credential
Start-Sleep -Seconds 5

Write-Host "Creating Users and Groups..."
New-ADGroup -Name "ServerAdmins" -SamAccountName ServerAdmins -GroupCategory Security -GroupScope Global -DisplayName "ServerAdmins" -Path "OU=Groups,$rootPath" -ManagedBy (Get-ADUser Administrator) -Credential $credential
New-ADGroup -Name "ITSupport" -SamAccountName ITSupport -GroupCategory Security -GroupScope Global -DisplayName "ITSupport" -Path "OU=Groups,$rootPath" -ManagedBy (Get-ADUser Administrator) -Credential $credential
Start-Sleep -Seconds 5

$searchBase = "OU=Employees,$rootPath"
$OUs = Get-ADOrganizationalUnit -Server $domainController -SearchBase $searchBase -SearchScope OneLevel -Filter * -Credential $credential | Select-Object -expand DistinguishedName

1..$numberOfUsers | ForEach-Object {
    $response = Invoke-RestMethod -Uri "https://randomuser.me/api?inc=name,email"
    $firstName = $response.results.name.first
    $lastName = $response.results.name.last
    $email = $response.results.email.replace("@example.com", "@$domain")
    $parts = $email.Replace("@$domain", "").Split(".")
    $userId = $parts[0] + $parts[1].Substring(0, 1)
    $userExists = $false
    try {
        Get-ADUser -Server $domainController "$userId" -Credential $credential
        $userExists = $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
        $userExists = $false
    }
    if ($userExists) {
        $randomNum = Get-Random -Minimum -1 -Maximum 10
        $userId += "$randomNum"
        try {
            Get-ADUser -Server $domainController "$userId" -Credential $credential
            $userExists = $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
            $userExists = $false
        }
        if ($userExists) {
            $userId = $userId.Replace("$randomNum", "$(Get-Random -Minimum -10 -Maximum 100)")
        }
    }
    
    $symbols = 33, 35, 37, 42, 43, 45, 46, 47, 61, 63, 64
    $password = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
    $password += -join ((48..59) | Get-Random -Count 2 | % {[char]$_})
    $password += -join ($symbols | Get-Random -Count 2 | % {[char]$_})

    $OU = $OUs | Get-Random -Count 1
    try {
        New-ADUser -Server $domainController -Name "$userId" -GivenName "$firstName" -Surname "$lastName" -SamAccountName "$userId" -DisplayName "$userId" -UserPrincipalName "$userId@$domain" -Path "$OU" -AccountPassword (ConvertTo-SecureString -AsPlainText "$password" -Force) -EmailAddress "$email" -Enabled $true -Credential $credential
    } catch [Microsoft.ActiveDirectory.Management.ADPasswordException] {
        $password = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
        $password += -join ((48..59) | Get-Random -Count 2 | % {[char]$_})
        $password += -join ($symbols | Get-Random -Count 2 | % {[char]$_})
        New-ADUser -Server $domainController -Name "$userId" -GivenName "$firstName" -Surname "$lastName" -SamAccountName "$userId" -DisplayName "$userId" -UserPrincipalName "$userId@$domain" -Path "$OU" -AccountPassword (ConvertTo-SecureString -AsPlainText "$password" -Force) -EmailAddress "$email" -Enabled $true -Credential $credential
    }
    Write-Host "Created user $userId with password $password in $OU"
    Start-Sleep -Seconds 5
}


Write-Host "Assigning Users to Groups"
$serverAdminsGroup = Get-ADGroup ServerAdmins -Credential $credential
$itSupportGroup = Get-ADGroup ITSupport -Credential $credential

$ITUsers = Get-ADUser -Filter "*" -SearchBase "OU=IT,OU=Employees,$rootPath" -Credential $credential
For ($i=0; $i -lt ($ITUsers.Length * 2 / 3); $i++) {
    if ((Get-Random -Minimum 0 -Maximum 2) -gt 0) {
        Add-ADGroupMember -Identity $itSupportGroup -Members $ITUsers[$i] -Credential $credential
    } else {
        Add-ADGroupMember -Identity $serverAdminsGroup -Members $ITUsers[$i] -Credential $credential
    }
}

$users = Get-ADUser -Filter "*" -Credential $credential

Write-Host "Creating Computers..."
$existingComputers = Get-ADComputer -Filter "*" -SearchBase "CN=Computers,$rootPath" -Credential $credential
ForEach ($computer in $existingComputers) {
    Move-ADObject -Identity $computer -TargetPath "OU=Servers,OU=Systems,$rootPath" -Credential $credential
}

For ($i=1; $i -le $users.Length; $i++) {
    $computerName = "CLIENT-WIN-$($i + 1)"
    New-ADComputer -Name $computerName -SamAccountName $computerName -Path "OU=Clients,OU=Systems,$rootPath" -Credential $credential
}

For ($i=1; $i -le ($users.Length / 5); $i++) {
    $computerName = "SERVER-WIN-$i"
    New-ADComputer -Name $computerName -SamAccountName $computerName -Path "OU=Servers,OU=Systems,$rootPath" -Credential $credential
}

Start-Sleep -Seconds 10

Write-Host "Adding privilege escalation path..."

New-ADUser -Server $domainController -Name "billh" -GivenName "Bill" -Surname "Hardman" -SamAccountName "billh" -DisplayName "billh" -UserPrincipalName "$billh@$domain" -Path "OU=IT,OU=Employees,$rootPath" -AccountPassword (ConvertTo-SecureString -AsPlainText "PurpleSAR2024!" -Force) -EmailAddress "bill.hardman@$domain" -Enabled $true -Credential $credential
Start-Sleep -Seconds 3
Add-ADGroupMember -Identity $serverAdminsGroup -Members $(Get-ADUser "billh") -Credential $credential

$adDrive = New-PSDrive -Name DomainAD -PSProvider ActiveDirectory -Server $domainController -root "//RootDSE/" -Credential $credential

$path = "$($adDrive.Name):\$($itSupportGroup.DistinguishedName)"
$acl = Get-Acl $path
$accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($serverAdminsGroup.sid, "GenericWrite", "Allow")
$acl.AddAccessRule($accessrule)
Set-Acl -AclObject $acl -Path $path

ForEach ($user in $users) {
    $path = "$($adDrive.Name):\$($user.DistinguishedName)"
    $acl = Get-Acl $path
    $accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($itSupportGroup.sid, "ExtendedRight", "Allow")
    $acl.AddAccessRule($accessrule)
    Set-Acl -AclObject $acl -Path $path
}
ForEach ($user in $(Get-ADGroup "Domain Admins" -Credential $credential -Properties members | select -expand members)) {
    $path = "$($adDrive.Name):\$user"
    $acl = Get-Acl $path
    $accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($itSupportGroup.sid, "ExtendedRight", "Allow")
    $acl.AddAccessRule($accessrule)
    Set-Acl -AclObject $acl -Path $path
}
$path = "$($adDrive.Name):\$(Get-ADUser Administrator -Credential $credential | select -expand DistinguishedName)"
$acl = Get-Acl $path
$accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($(Get-ADGroup ITSupport).sid, "ExtendedRight", "Allow")
$acl.AddAccessRule($accessrule)
Set-Acl -AclObject $acl -Path $path

$action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle Hidden -File C:\Windows\Temp\set-da-dacl.ps1 $domain $username $userpwd"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet
Register-ScheduledTask -TaskName SetDADacl -TaskPath "\" -Action $action -Trigger $trigger -User $username -Password $userpwd -Settings $settings

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name AdminSDProtectFrequency -Value 7200

Write-Host "Finished - login with 'billh' user to ITSERVER"