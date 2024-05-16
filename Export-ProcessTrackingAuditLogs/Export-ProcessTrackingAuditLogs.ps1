Clear-Host
While($true){
    Write-Output "$(Get-Date -Format "yyyy-MM-dd hh:mm:ss") -  Exporting Logs"
    Get-EventLog -InstanceId 4688,4689 -LogName Security -After (Get-Date).AddMinutes(-5) -Before (Get-Date) | Export-Csv 'C:\temp\evt.csv' -Encoding utf8 -Append
    Start-Sleep 3600
}

