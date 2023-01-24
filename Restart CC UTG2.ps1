$ErrorActionPreference= 'silentlycontinue'
Get-Process fpos|powershell -windowstyle hidden -command taskkill /im fpos.exe /f
Start-sleep -s 5
powershell -windowstyle hidden -command taskkill /f /im Utg2Svc.exe 
powershell -windowstyle hidden -command taskkill /f /im Utg2.exe 
Start-sleep 5
C:\Shift4\UTG2\Utg2.exe
start-sleep 10

$delay = 75
$Counter_Form = New-Object System.Windows.Forms.Form
$Counter_Form.Text = "Credit Card Software is Restarting"
$Counter_Form.Width = 450
$Counter_Form.Height = 200
$Counter_Label = New-Object System.Windows.Forms.Label
$Counter_Label.AutoSize = $true
$Counter_Label.ForeColor = "Green"
$normalfont = New-Object System.Drawing.Font("Times New Roman",14)
$Counter_Label.Font = $normalfont
$Counter_Label.Left = 20
$Counter_Label.Top = 20
$Counter_Form.Controls.Add($Counter_Label)
while ($delay -ge 0)
{
  $Counter_Form.Show()
  $Counter_Label.Text = "Seconds Remaining: $($delay)"
  if ($delay -lt 5)
  { 
     $Counter_Label.ForeColor = "Red"
     $fontsize = 20-$delay
     $warningfont = New-Object System.Drawing.Font("Times New Roman",$fontsize,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Underline))
     $Counter_Label.Font = $warningfont
  } 
 start-sleep 1
 $delay -= 1
}
$Counter_Form.Close()

$shell = New-Object -ComObject "Shell.Application"
$shell.minimizeall()
start-sleep 2
fpos.exe