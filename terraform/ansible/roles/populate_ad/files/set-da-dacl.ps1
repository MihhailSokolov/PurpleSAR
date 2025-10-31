$domain = $args[0]
$username = $args[1]
$password = $args[2] | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
$domainController = $(Get-ADDomainController -server $domain -Credential $credential).HostName
$adDrive = New-PSDrive -Name DomainAD -PSProvider ActiveDirectory -Server $domainController -root "//RootDSE/" -Credential $credential
$path = "$($adDrive.Name):\$(Get-ADUser AzureAdmin -Credential $credential | select -expand DistinguishedName)"
$acl = Get-Acl $path
$accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($(Get-ADGroup ITSupport).sid, "ExtendedRight", "Allow")
$acl.AddAccessRule($accessrule)
Set-Acl -AclObject $acl -Path $path