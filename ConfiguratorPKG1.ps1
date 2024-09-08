Write-Host -ForegroundColor Green "Windows Deployment/Configuration will now begin."

Set-ExecutionPolicy Unrestricted
whoami

Write-Host -foregroundcolor Green 'Creating FPOS Admin Account...'
$username = "FPOS"
$password =  ConvertTo-SecureString  -AsPlainText "fpos" -Force
New-LocalUser "$username" -Password $password -PasswordNeverExpires -FullName "$username" -Description "Local admin $username"
Add-LocalGroupMember -Group "Administrators" -Member "$username"



$Source =  'E:\Configuration\'
$Destination = 'C:\Configuration\'
Write-Host  Transferring USB Payload files to $destination This may take a few minutes...
robocopy /e $source $destination

Write-Host 
Start-Transcript -Append C:\Configuration\Logs\ConfiguratorPKG1log.txt

###configures Auto-Login ###
 
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
Set-ItemProperty $RegistryPath 'ForceAutoLogon' -value "1" -type string
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "FPOS" -type String 
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "fpos" -type String

Write-host -foregroundcolor Yellow "Auto-Login for $username configured. Logging off now..."
 Start-Sleep 5
  Stop-Transcript
#$restart = Read-Host 'Do you want to restart your computer now for testing auto-logon? (Y/N)'
#
#If ($restart -eq 'Y') {
# 
#    Restart-Computer -Force
 
#}

#$logoff = Read-Host 'Do you want to logoff? (Y/N)'
#
#If ($logoff -eq 'Y') {
 ###DONT NEED PROMPT FUCK IT, LOG OFF FORCE
 quser | Select-Object -Skip 1 | ForEach-Object {
    $id = ($_ -split ' +')[-6]
    logoff $id
}
#}

