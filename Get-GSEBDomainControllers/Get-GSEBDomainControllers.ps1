$Forest = Get-ADForest
$Obj = @()
foreach($Dom in $Forest.Domains){
    $DCList = $null
    $DCList = Get-ADDomainController -Server $Dom -Filter *  -ErrorAction SilentlyContinue | Select-Object Forest,Domain,Hostname,Site 
    foreach($DC in $DCList){
        $PING = Test-NetConnection -ComputerName $DC.Hostname
        $LDAP = Test-NetConnection -ComputerName $DC.Hostname -Port 389
        $GC = Test-NetConnection -ComputerName $DC.Hostname -Port 3268
        $KRB = Test-NetConnection -ComputerName $DC.Hostname -Port 88

        $props = [ordered]@{
            DC = $DC.Hostname
            Domain = $Dom
            Site = $DC.Site
            PING = $PING.PingSucceeded
            LDAP = $LDAP.TcpTestSucceeded
            GC = $GC.TcpTestSucceeded
            Kerberos = $KRB.TcpTestSucceeded
        }

        $Obj += New-Object -TypeName psobject -Property $props

    }
}

#Exportar o resultado para .CSV
$Obj | Export-Csv C:\Temp\DC.csv -Append