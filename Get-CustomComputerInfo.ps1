<#
    https://learn.microsoft.com/en-us/windows-server/get-started/perform-in-place-upgrade
#>

$OutputPath = "C:\temp\$($ENV:COMPUTERNAME)\"

New-Item -ItemType Directory -Path $OutputPath

$CurrentSO = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Version

# Main CIM Classes

Get-WmiObject -Class Win32_OperatingSystem | Export-Csv $OutputPath\$CurrentSO-OperatingSystem.csv -Encoding UTF8
Get-WmiObject -Class Win32_ComputerSystem | Export-Csv $OutputPath\$CurrentSO-ComputerSystem.csv -Encoding UTF8
Get-WmiObject -Class Win32_Service | Export-Csv $OutputPath\$CurrentSO-Service.csv -Encoding UTF8
Get-WmiObject -Class Win32_InstalledWin32Program | Export-Csv $OutputPath\$CurrentSO-InstalledWin32Program.csv -Encoding UTF8
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Export-Csv $OutputPath\$CurrentSO-NetworkAdapterConfiguration.csv -Encoding UTF8
Get-WmiObject -Class Win32_IP4RouteTable | Export-Csv $OutputPath\$CurrentSO-IP4RouteTable.csv -Encoding UTF8

# GPO

& Invoke-Command -ScriptBlock { gpresult /H "$OutputPath\$CurrentSO-gpresult.html" }

# systeminfo

systeminfo.exe | Out-File -FilePath $OutputPath\$CurrentSO-systeminfo.txt