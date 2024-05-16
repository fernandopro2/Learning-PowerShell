$DNSQueries = "d32a6ru7mhaq0c.cloudfront.net","mobile.zscaler.net","pac.zdxcloud.net","gateway.zscaler.net","gateway.seb.zscaler.net"
$Forwarders = Get-DnsServerForwarder | Select-Object -ExpandProperty IPAddress

foreach($FW in $Forwarders){
    Write-Output "----------------------------------------------------"
    Write-Output "Testing Forwarder: $FW"
    Write-Output "----------------------------------------------------"
    foreach($DQ in $DNSQueries){
        Resolve-DnsName -Name $DQ -Server $FW
    }
}