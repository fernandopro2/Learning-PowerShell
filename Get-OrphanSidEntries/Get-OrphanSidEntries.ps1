$RootFolder = "F:\"


$Tree = Get-ChildItem -Path "$RootFolder" -Depth 6 -Directory -ErrorAction SilentlyContinue | Get-Acl #-Hidden

$Obj = @()

foreach($Item in $Tree){
    $ACL = $Item #| Get-Acl | Select-Object Access 
    $Perm = $null
    $Perm = $ACL.Access | Where-Object IdentityReference -Match "S-1-5-21-" | Select-Object IdentityReference,FileSystemRights #.IdentityReference
    if($Perm){
        foreach($P in $Perm){
            $props = [ordered]@{
                Item = $Item.Path
                Identity = $P.IdentityReference
                FileSystemRights = $P.FileSystemRights
            }
            $Obj += New-Object -TypeName psobject -Property $props
            # The following variable is defined to show the current folder.
            $Obj[-1]
        }
    }
}

$Obj | Export-Csv c:\temp\OrphanSidsFL6.csv