$DCs = Get-ADDomainController -Filter * -Server eu.seb.com
$ObjUsr = @()
foreach($DC in $DCs){
    $ObjUsr += Get-ADUser S-1-5-21-1390067357-725345543-682003330-203968 -Server $DC.HostName -Properties uSNCreated,uSNChanged -ErrorAction SilentlyContinue |
    Select-Object Name,uSNCreated,uSNChanged,@{L='DC';E={$DC.HostName}} #| Sort-Object -Property uSNChanged -Descending
}
foreach($DC in $DCs){
    $rep = $null
    $objs = $null
    $rep = repadmin /showobjmeta $DC.HostName "CN=HALABI Yaser,OU=DE-EMS-Users,OU=DE-EMS,OU=DE,DC=eu,DC=seb,DC=com"
    #$rep
    $objs = $rep -replace "DCU02DC","DCU02DC " | Select-String "(\sl$)|(\sst)|(postalCode)|(\stitle)"
    foreach($obj in $objs){
        $cols = $obj -split "\s\s*"
        $props = [ordered]@{
            DC = $cols[1]
            Date = $cols[3]
            Time = $cols[4]
            Attribute = $cols[6]
        }
        $ObjUsr += New-Object -TypeName psobject -Property $props
    }
}