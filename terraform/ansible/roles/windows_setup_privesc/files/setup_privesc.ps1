if (-not $env:computername.ToLower().Contains("itserver")) {
    exit
}
Start-Sleep -Seconds 360
$user = $args[0]
$password = $args[1]

$UserID = Get-LocalUser -Name 'PurpleUser' -ErrorAction SilentlyContinue
if (-not $UserID){
    net user PurpleUser SecurePwd123 /add
    net localgroup "Remote Desktop Users" PurpleUser /add
    net localgroup "Administrators" PurpleUser /add
}


# "Write-Host 'Updating...'" | Out-File C:\Update.ps1
# icacls C:\Update.ps1 /grant Everyone:F

# if ((Get-LocalGroupMember Administrators).Name -notcontains 'ATTACKRANGE\ServerAdmins') {
#     net localgroup administrators ATTACKRANGE\ServerAdmins /add
# }

# $task = Get-ScheduledTask -TaskName "UpdateTask" -ErrorAction SilentlyContinue
# if (-not $task) {
#     $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle Hidden -File C:\Update.ps1"
#     $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1)
#     $settings = New-ScheduledTaskSettingsSet
#     Register-ScheduledTask -TaskName UpdateTask -TaskPath "\" -Action $action -Trigger $trigger -User $user -Password $password -Settings $settings -RunLevel Highest

#     $Scheduler = New-Object -ComObject "Schedule.Service"
#     $Scheduler.Connect()
#     $task = $Scheduler.GetFolder("\").getTask("UpdateTask")
#     $descriptor = $task.GetSecurityDescriptor(0xF)
#     $descriptor = $descriptor + '(A;;GR;;;AU)'
#     $task.SetSecurityDescriptor($descriptor, 0)
# }