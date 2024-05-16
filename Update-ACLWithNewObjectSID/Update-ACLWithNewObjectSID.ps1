$ScriptFolder =  "C:\Scripts\ACL"

$Timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"

Start-Transcript -Path "$ScriptFolder\Logs\transcript-$Timestamp.log"

$Depth = 5

$IdentitiesFile = Import-Csv \\sw09l430\sources\Windows\matchSIDs.csv | Sort-Object * -Unique

$Path = "E:"

$ACLList = @()

if((Get-Host).Version.ToString() -match "^5.1"){
    $ACLList += Get-Item $Path | Get-Acl | Where-Object {$_.Access.IdentityReference -Match "S-1-5-21-" -and $_.Access.IsInherited -eq $false}
    $ACLList += Get-ChildItem -Path $Path -Depth $Depth -Directory  -ErrorAction SilentlyContinue | Get-Acl | Where-Object {$_.Access.IdentityReference -Match "S-1-5-21-" -and $_.Access.IsInherited -eq $false}

}
else{
    $Levels = "\*" * $Depth
    $ACLList += Get-Item $Path | Get-Acl | Where-Object {$_.Access.IdentityReference -Match "S-1-5-21-" -and $_.Access.IsInherited -eq $false}
    $ACLList += Get-ChildItem -Path "$Path$Levels" -Directory  -ErrorAction SilentlyContinue | Get-Acl | Where-Object {$_.Access.IdentityReference -Match "S-1-5-21-" -and $_.Access.IsInherited -eq $false}

}


$Tree = @()
foreach($A in $ACLList){
    $Test = $null
    $Test = $A.Access |  Where-Object {$_.IdentityReference -in $IdentitiesFile.OldSID -and $_.IsInherited -eq $false}
    if($Test){
        $Tree += $A
   }
}
$Obj = @()


foreach($Item in $Tree){
    $ACL = $null
    # Retrieving the current ACL
    $ACL = $Item #| Get-Acl
     
    foreach($Identity in $IdentitiesFile){
        
        # Gathering the ACE list from ACL
        $ACEChangeControl = 0

        $CurrentACE = $ACL.Access | Where-Object {$_.IdentityReference -eq $Identity.OldSID -and $_.IsInherited -eq $false } 
        
        if($CurrentACE){

            $Item.Path
            $CurrentACE


            # Backing up the current ACL
            $ACL | Export-Csv $ScriptFolder\Logs\Backup-ACL-$Timestamp.csv -Append -NoTypeInformation
            
            
            [System.Security.Principal.SecurityIdentifier]$NewIdentity = $Identity.NewSid

            if($NewIdentity){

                foreach($ACE in $CurrentACE){

                    $OldIdentity = $ACE.IdentityReference
            
                    $Rights = $ACE.FileSystemRights
                    $Inheritance = $ACE.InheritanceFlags
                    $Propagation = $ACE.PropagationFlags
                    $Type = $ACE.AccessControlType

                    $OldACE = $null
                    $NewACE = $null

                    #$OldACE = New-Object System.Security.AccessControl.FileSystemAccessRule($OldIdentity,$Rights,$Inheritance,$Propagation,$Type)
                    $OldACE = $ACL.AccessRuleFactory($OldIdentity,$Rights,$IsInherited,$Inheritance,$Propagation,$Type)

                    #$NewACE = New-Object System.Security.AccessControl.FileSystemAccessRule($NewIdentity,$Rights,$Inheritance,$Propagation,$Type)
                    $NewACE = $ACL.AccessRuleFactory($NewIdentity,$Rights,$IsInherited,$Inheritance,$Propagation,$Type)

                    if($OldACE -and $NewACE){

                        $ACL.AddAccessRule($NewACE)
                        $ACL.RemoveAccessRule($OldACE)

                        $ACEChangeControl++
                        Write-Warning "ACE Change Control Flag: $ACEChangeControl"

                    
                        $props = [ordered]@{
                            Item = $Item.Path
                            OldIdentity = $OldIdentity
                            NewIdentity = $NewIdentity
                            Rigths = $Rights
                            Type = $Type
                        }
                        New-Object -TypeName psobject -Property $props | Export-Csv "$ScriptFolder\Logs\ACLChangeTracking-$Timestamp.csv" -Append -NoTypeInformation
                    }

                }
                if($ACEChangeControl -ge 1){
                    try{
                        $Item | Set-Acl -AclObject $ACL -Verbose -Confirm
                    }catch{
                        $Error[0].Exception.Message | Out-File "$ScriptFolder\Logs\Exceptions.txt"
                    }
                }
            }
            else{
                Write-Warning "Object $($Identity.DN) not found"
            }
        }
        else{
            # No entries found
        }
    }
}


Stop-Transcript

