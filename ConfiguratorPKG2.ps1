$ErrorActionPreference = "SilentlyContinue"

Write-Host -ForegroundColor Green "Windows Deployment will now begin. Check log for review"
Start-Transcript -Append c:\Configuration\Logs\Configurator-PKG2-log.txt

#Prompt Admin
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
        }

########Configure Name // ASK PROMPTS
Write-Host Password is fpos
    $name = Read-Host 'Please enter desired PC Name. ex: WAIT1, WAIT2, WAIT3'
            Rename-Computer -NewName $name -LocalCredential Administrator
    $IP = Read-Host -Prompt 'Please enter the IP Address.  Format 10.1.x.x'
    $UTGPrompt = Read-Host 'Do you want download and install UTG? (Y/N)'
    $ScreenconnectPrompt = Read-Host 'Do you want to install Screenconnect? It will show under WCPOS Company Automatically under terminal name (Y/N)'
    $SQLPrompt = Read-Host 'Do you want to install SQL? (Y/N)'
    $FPOSPrompt = Read-Host 'Do you want to install FPOS Prerequisite? (Y/N)'

    #Check Windows Defender Status
Write-Host Disable Windows defender NOW
Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
Write-Host -ForegroundColor Green "Make sure Windows Defender is deactivated and that you have an ethernet cord plugged in before continuing! Creating log..."
pause
Start-Transcript -Append C:\Configuration\Logs\ConfiguratorPKG3log.txt
Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
Write-Host Script breaks if Windows Defender is not Disabled!!!
    


Write-Host '----------------Showing USER information BELOW---------------------
-------------------------------------------------------------------------------
'

#GET NAME
gpresult /R 

#SET DEFAULT TIME ZONE TO PST WE WILL RESYNC WHEN WE HAVE INTERNET CONFIGURED 
Write-Host -ForegroundColor Green 'Setting time zone to PST...Time Resync will occur when IP is configured later.'
Set-TimeZone -Name "Pacific Standard Time"

#GET STORAGE INFO $STORAGE
$props = @(
    'DriveLetter',    
    @{
        Name = 'SizeRemaining'
        Expression = { "{0:N2} GB" -f ($_.SizeRemaining/ 1Gb) }
    },
    @{
        Name = 'Size'
        Expression = { "{0:N2} GB" -f ($_.Size / 1Gb) }
    },
    @{
        Name = '% Free'
        Expression = { "{0:P}" -f ($_.SizeRemaining / $_.Size) }
    },
    @{
        Name = 'Status'
        Expression = { if(($_.SizeRemaining / $_.Size) -lt 0.5){"Low!!!"}else{"OK"} }
    }
) 
Get-Volume -DriveLetter C | Select-Object $props | Tee-Object -Variable 'storage'
Get-PhysicalDisk | Select HealthStatus, Mediatype | Tee-Object -Variable 'Health'

# Configure Power Settings 
Write-Host -ForegroundColor Green 'Configuring Power Settings '
POWERCFG -DUPLICATESCHEME 381b4222-f694-41f0-9685-ff5bb260df2e 381b4222-f694-41f0-9685-ff5bb260aaaa
POWERCFG -CHANGENAME 381b4222-f694-41f0-9685-ff5bb260aaaa "WC-POS Power Management"
POWERCFG -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260aaaa
POWERCFG -Change -monitor-timeout-ac 0
POWERCFG -CHANGE -monitor-timeout-dc 0
POWERCFG -CHANGE -disk-timeout-ac 0
POWERCFG -CHANGE -disk-timeout-dc 0
POWERCFG -CHANGE -standby-timeout-ac 0
POWERCFG -CHANGE -standby-timeout-dc 0
POWERCFG -CHANGE -hibernate-timeout-ac 0
POWERCFG -CHANGE -hibernate-timeout-dc 0

#Enable system restore
Write-Host -ForegroundColor Green "Enabling system restore..."
Enable-ComputerRestore -Drive "$env:SystemDrive"

# Disable Telemetry
    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
# Disable Bing Search in Start Menu
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
# Disable Windows Update automatic restart
    Write-Host "Disabling Windows Update automatic restart..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
# Disable screen rotation
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation -Name Enable -Value 0 -Type DWord
# Hide Search button / box
    Write-Host "Hiding Search Box / Button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
# Hide Task View button
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name 'ShowTaskViewButton' -Type 'DWord' -Value 0 
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name 'SearchboxTaskbarMode' -Type 'DWord' -Value 1 

# Remove Weather taskbar
    Write-Host Removing Weather Taskbar Widget...
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "HeadlinesOnboardingComplete" -Type DWord -Value 1

# Disable Feedback
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Turn UAC Off
     Write-Host -foregroundcolor Green "Lowering UAC level to 0"
     Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
     Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

# Enable sharing mapped drives between users
    Write-Host "Enabling sharing mapped drives between users..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

# Enable Remote Desktop w/o Network Level Authentication
    Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0

# Change default Explorer view to "Computer"
    Write-Host "Changing default Explorer view to `"Computer`"..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Enable terminals to talk to eachother 
Write-Host 'Turning on Network Discovery //// File & Printer sharing
RUNNING CURRENT STATUS'
Get-NetFirewallRule -DisplayGroup "Network Discovery" | ft
#Turn on Network Discovery
netsh advfirewall firewall set rule group=”network discovery” new enable=yes
Get-NetFirewallRule -DisplayGroup "Network Discovery" | ft
Write-Host 'Network Discovery and File sharing enabled'
Enable-PSRemoting -SkipNetworkProfileCheck

# Turn on File and Printer Sharing:
netsh firewall set service type=fileandprint mode=enable profile=all
Write-Host -foregroundcolor Green 'Network Discovery //// File & Printer sharing turned on'


# Disable Action Center
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
      New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
    } 
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Type DWord -Value 1

# Edit Control Panel icons
Write-Host -ForegroundColor "Green" Setting Control Panel view to small icons...
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1

#Disable Cortana
Write-Host -ForegroundColor "Green" Disabling Cortana...
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0

# Uninstall default Microsoft applications
    Write-Host -ForegroundColor "Green" "Uninstalling default Microsoft applications..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
    Get-AppxPackage Microsoft.YourPhone | Remove-AppxPackage
    Get-AppxPackage *xbox* | Remove-AppxPackage
    Get-AppxPackage *disney* | Remove-AppxPackage
    Get-AppxPackage *SpotifyMusic* | Remove-AppxPackage
    Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage
    Get-AppxPackage *OneDriveSync* | Remove-AppxPackage
    Get-AppxPackage *GetHelp* | Remove-AppxPackage
    Get-AppxPackage *maps* | Remove-AppxPackage

    ## Enable Storage Sense
    Write-Host -ForegroundColor "Green" "Enabling Storage Sense "
## Ensure the StorageSense key exists
$key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
If (!(Test-Path "$key")) {
    New-Item -Path "$key" | Out-Null
}
If (!(Test-Path "$key\Parameters")) {
    New-Item -Path "$key\Parameters" | Out-Null
}
If (!(Test-Path "$key\Parameters\StoragePolicy")) {
    New-Item -Path "$key\Parameters\StoragePolicy" | Out-Null
}

## Set Storage Sense settings
## Enable Storage Sense
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1

## Set 'Run Storage Sense' to Every Week
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "2048" -Type DWord -Value 7

## Enable 'Delete temporary files that my apps aren't using'
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1

## Set 'Delete files in my recycle bin if they have been there for over' to 14 days
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "256" -Type DWord -Value 14

## Set 'Delete files in my Downloads folder if they have been there for over' to 60 days
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 1
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "512" -Type DWord -Value 30

## Set value that Storage Sense has already notified the user
Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1

####################
### Clear Start Menu
#Begin
$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
Stop-Process -name explorer
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

#Restart Explorer and delete the layout file
Stop-Process -name explorer
Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
Remove-Item $layoutFile

####End of hidden properties####################
################
################             IP SETTINGS
################
########Configure IP
$MaskBits = 24 # This means subnet mask = 255.255.255.0
$Gateway = "10.1.15.10"
$Dns = "8.8.8.8"
$IPType = "IPv4"

# Retrieve the network adapter that you want to configure
$adapter = Get-NetAdapter | ? {$_.Status -eq "up"}

Write-Host 'Removing Current IP Config'
# Remove any existing IP, gateway from our ipv4 adapter
If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
    $adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
}

If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
    $adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
}
Write-Host 'Configuring IP ADDRESS, GATEWAY, DNS, AND SUBNET.'
 # Configure the IP address and default gateway
$adapter | New-NetIPAddress `
    -AddressFamily $IPType `
    -IPAddress $IP `
    -PrefixLength $MaskBits `
    -DefaultGateway $Gateway

# Configure the DNS client server IP addresses
$adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
Write-Host -foregroundcolor Green 'IP SETTINGS CONFIGURED. RESTART PC TO TAKE EFFECT.'

##########
########SYNC TIME AND CREATE SCHEDULE TO SYNC TIME DAILY TO PREVENT FUTURE DESYNCS 
############
#Create task
schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC daily /TN Timesync /TR “cmd /c w32tm /resync”-
#RUN
schtasks /run /I /TN timesync

#Enabling .NET Framework
Write-Host -ForegroundColor Green "Enabling .NET Framework...."
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

Write-Host -foregroundcolor Yellow 'Testing internet...'

##################################################################
##########     NEED INTERNET CONNECTION STARTING NOW ##################
##################################################################

#Check and download Windows Update
USOClient.exe StartInteractiveScan
USOClient.exe StartDownload
##UsoClient StartInstall
##we do not want to start install on pkg2

#Install FPOS PREREQ
if ($FPOSPrompt -eq 'Y') {
#Install FPOS Prereq
Start-Process -filepath C:\Configuration\FuturePrerequisite-6.0.7.15.exe /s -Wait -NoNewWindow -PassThru
}

if ($ScreenconnectPrompt -eq 'Y') {
#Install Screenconnect
$Path = "C:\Configuration\";
$InstallerSC = "ConnectWiseControl.ClientSetup.msi";
Invoke-webrequest "https://wcpos.screenconnect.com/Bin/ConnectWiseControl.ClientSetup.msi?e=Access&y=Guest&c=WC-POS&c=Config%20Testing&c=Configuration&c=&c=&c=&c=&c=" -OutFile $Path$InstallerSC;
Start-Process -FilePath $Path$InstallerSC -Args "/silent /install" -Verb RunAs -Wait; 
Remove-Item $Path$InstallerSC
}

if ($UTGPrompt -eq 'Y') {
#Install UTG
##DOWNLOAD UTG
#this is faster than the other download methods but not as reliable. 
$URL = "https://s4-myportal.s3.amazonaws.com/downloads/utg2setup.exe"
$output = "C:\Configuration\shift4UTGsetup-latestupdate.exe"
$wc = new-object System.Net.WebClient
Write-Host Downloading Latest UTG Version installer from $URL. Writing to $output
$wc.DownloadFile($url, $output)
Write-Host Download complete in $output 
Start-Process $output -wait
}

#Download and install chrome
$Path = "C:\Configuration\"; 
$Installer = "chrome_installer.exe"; 
Invoke-WebRequest "https://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $Path$Installer; 
Start-Process -FilePath $Path$Installer -Args "/silent /install" -Verb RunAs -Wait; 
Remove-Item $Path$Installer


####################FINISH#############

#$STA = New-ScheduledTaskAction -Execute notepad.exe
#$STT = New-ScheduledTaskTrigger -atlogon
#Register-Scheduledtask Config -Action $STA -Trigger $STT

#Creating new task to run PKG3 on next logon. Need to figure out how to disable
Write-Host Created task to run PKG3 on next logon. 
if ($SQLPrompt -eq 'Y') {
try { 
#CREATE TASK
Register-ScheduledTask -Xml (Get-Content ("C:\Configuration\Config.xml") | Out-String ) -TaskName "Config"}
catch {Write-Host 'Task was not created.'}}
##DISABLE KEY HERE - Disable-ScheduledTask -TaskName Config
###Runs in PKG3

Write-Host -ForegroundColor Green 'Configuration PKG 2 Complete. Check C:\Configuration\Logs for possible errors.
Restarting PC...Installing SQL next logon. 
'
Start-Sleep 5
Restart-Computer -Force

#Write-Host -ForegroundColor Red Restart PC before installing SQL. SQL automatically installs next logon. 
#$restart = Read-Host 'Do you want to restart computer now? (Y/N)'
# 
#If ($restart -eq 'Y') {
# 
#    Restart-Computer -Force
# 
#}
Stop-Transcript