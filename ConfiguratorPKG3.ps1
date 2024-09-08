#############SQL SHIT

########################
###########SQL##########
########################




###Install SQL
$configfile = "C:\Configuration\SQL\ConfigurationFile.ini"
$user = $($env:userdomain)
$InstallSQL = "C:\Configuration\SQL\SQLEXPRWT_x64_ENU\setup.exe /ConfigurationFile=$($configfile) /SQLSYSADMINACCOUNTS=$($user)\FPOS" 
Write-Host -ForegroundColor Green "Installing SQL Server 2014 + 6 SQL Update Packages" 
Invoke-Expression -Command $InstallSQL 

####Install SQL Update Packages
# Define executable
$SQLPackage1 = 'C:\Configuration\SQL\SQL_2014_UPDATES\sqlserver2014-kb4470220-x64_727d462ffcb618400c813ae6bf06e3a9cc8418f2.exe'
$SQLPackage2 = 'C:\Configuration\SQL\SQL_2014_Updates\sqlserver2014-kb4482960-x64_b03e8c1abe6bbcb2ba3d5ed59ffa7995d027ddb7.exe'
$SQLPackage3 = 'C:\Configuration\SQL\SQL_2014_Updates\sqlserver2014-kb4491539-x64_d8fc176cd84a2cb1cbafba74c4fcada43151d03e.exe'
$SQLPackage4 = 'C:\Configuration\SQL\SQL_2014_Updates\sqlserver2014-kb4500181-x64_d6470880388461b7bc506f6bd3ccd464e4f8b2d2.exe'
$SQLPackage5 = 'C:\Configuration\SQL\SQL_2014_Updates\sqlserver2014-kb4535288-x64_f5a76d473fee50a2aabe7c08daeb0910f3590491.exe'
$SQLPackage6 = 'C:\Configuration\SQL\SQL_2014_Updates\sqlserver2014-kb4583462-x64_0dc4f56583828865365340dcb95436f1a41754b9.exe'
# Define *array* of arguments
$args = '/qs', '/IAcceptSQLServerLicenseTerms', '/Action=Patch', '/AllInstances'
Write-Host Installing SQL UPDATE PACKAGE 1
Start-Process -Wait $SQLPackage1 -ArgumentList $args
Write-Host Installing SQL UPDATE PACKAGE 2
Start-Process -Wait $SQLPackage2 -ArgumentList $args
Write-Host Installing SQL UPDATE PACKAGE 3
Start-Process -Wait $SQLPackage3 -ArgumentList $args
Write-Host Installing SQL UPDATE PACKAGE 4
Start-Process -Wait $SQLPackage4 -ArgumentList $args
Write-Host Installing SQL UPDATE PACKAGE 5
Start-Process -Wait $SQLPackage5 -ArgumentList $args
Write-Host Installing SQL UPDATE PACKAGE 6
Start-Process -Wait $SQLPackage6 -ArgumentList $args
Write-Host SQL Updates have been installed. 