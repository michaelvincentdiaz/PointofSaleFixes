 $s = New-PSSession -computerName FDS-SD-SVR
Invoke-Command -Session $s -Scriptblock {Start-Process -WorkingDirectory "C:\fpos-install" -Wait -FilePath "C:\fpos-install\Utils\FPOS DB Restart.exe"}
Remove-PSSession $s
