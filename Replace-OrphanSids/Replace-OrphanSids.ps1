$ScriptFolder =  "C:\Scripts\ACL"

$Timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"

Start-Transcript -Path "$ScriptFolder\Logs\transcript-$Timestamp.log"

$RootFolder = "D:\Root"

$ACLList = Get-ChildItem -Path $RootFolder -Directory -Depth 4 -ErrorAction SilentlyContinue | Get-Acl

$Obj = @()

$IdentitiesFile = Import-Csv C:\Scripts\matchSIDs.csv | Sort-Object * -Unique

foreach($Item in $ACLList){
    $ACL = $null
    $Item
    # Retrieving the current ACL
    $ACL = $Item #| Get-Acl
    $ACEChangeControl = 0
     
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
                            Item = $Item.FullName
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
                        $Item | Set-Acl -AclObject $ACL -Verbose -WhatIf
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

