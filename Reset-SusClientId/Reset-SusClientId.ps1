# Reset SusClientId
Get-Service BITS, wuauserv | Stop-Service -Force
Remove-ItemProperty -Name AccountDomainSid, PingID, SusClientId, SusClientIDValidation -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\ -ErrorAction SilentlyContinue
Remove-Item "$env:SystemRoot\SoftwareDistribution\" -Recurse -Force -ErrorAction SilentlyContinue
Get-Service BITS, wuauserv | Start-Service
wuauclt /resetauthorization /detectnow
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
$updateSession = new-object -com "Microsoft.Update.Session"; 
$updates = $updateSession.CreateupdateSearcher().Search($criteria).Updates
wuauclt /reportnow