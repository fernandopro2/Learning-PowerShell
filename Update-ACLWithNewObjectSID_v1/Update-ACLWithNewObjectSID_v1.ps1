$ScriptFolder =  "C:\Scripts\ACL"

$Timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"

Start-Transcript -Path "$ScriptFolder\Logs\transcript-$Timestamp.log"

$RootFolder = "G:\"

$Tree = Get-ChildItem -Path $RootFolder -Directory -Depth 2 -ErrorAction SilentlyContinue

$Obj = @()

$IdentitiesFile = Import-Csv \\sw09l430\sources\Windows\matchSIDs.csv | Sort-Object * -Unique

foreach($Item in $Tree){
    $ACL = $null
    $Item
    # Retrieving the current ACL
    $ACL = $Item | Get-Acl
     
    foreach($Identity in $IdentitiesFile){
        
        # Gathering the ACE list from ACL
        $CurrentACE = $ACL.Access | Where-Object {$_.IdentityReference -eq $Identity.OldSID -and $_.IsInherited -eq $false } 
        
        if($CurrentACE){

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

                    $OldACE = New-Object System.Security.AccessControl.FileSystemAccessRule($OldIdentity,$Rights,$Inheritance,$Propagation,$Type)
                    #$NewACE = New-Object System.Security.AccessControl.FileSystemAccessRule($NewIdentity,$Rights,$Inheritance,$Propagation,$Type)
                    $NewACE = $ACL.AccessRuleFactory($NewIdentity,$Rights,$IsInherited,$Inheritance,$Propagation,$Type)

                    if($OldACE -and $NewACE){

                        $ACL.AddAccessRule($NewACE)
                        $ACL.RemoveAccessRule($OldACE)
                    
                        $props = [ordered]@{
                            Item = $Item.FullName
                            OldIdentity = $OldIdentity
                            NewIdentity = $NewIdentity
                            Rigths = $Rights
                            Type = $Type
                        }
                        New-Object -TypeName psobject -Property $props | Export-Csv "$ScriptFolder\Logs\ACLChangeTracking-$Timestamp.csv" -Append -NoTypeInformation
                    }

                }
                try{
                    $Item | Set-Acl -AclObject $ACL -Verbose 
                }catch{
                    $Error[0].Exception.Message | Out-File "$ScriptFolder\Logs\Exceptions.txt"
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

