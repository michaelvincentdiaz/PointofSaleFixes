$ErrorActionPreference= 'silentlycontinue'
powershell -windowstyle hidden -command taskkill /im addriver.exe 
Start-Sleep 5
Start-Process addriver.exe 