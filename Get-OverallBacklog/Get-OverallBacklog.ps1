<#
.Synopsis
   # T-812427 | RITM0746358
.EXAMPLE
   Gather DFS backlog replication of all replication groups in EU.SEB.COM (default)
   Get-OverallBackLog
.EXAMPLE
   Gather DFS backlog replication of all replication groups in another domain
   Get-OverallBackLog -DomainName "as.seb.com"
.EXAMPLE
   Gather DFS backlog replication of a specific replication group in EU.SEB.COM
   Get-OverallBackLog -DomainName "eu.seb.com" -GroupName "EU-FR-MAY-SW00P887-F-DATA03-MAY-SW07N251-DCU-SW02K713"
.EXAMPLE
   Gather DFS backlog replication of a specific replication group member in EU.SEB.COM 
   Get-OverallBackLog -DomainName "eu.seb.com" -DestinationComputerName "SW02K713"
.EXAMPLE
   Gather DFS backlog replication of a specific replication group member in EU.SEB.COM AND a specific folder
   Get-OverallBackLog -DomainName "eu.seb.com" -DestinationComputerName "SW02K713" -FolderName DATA01
.EXAMPLE
   Table formated output
   Get-OverallBackLog -DomainName "eu.seb.com" -GroupName "EU-FR-MAY-SW00P887-F-DATA03-MAY-SW07N251-DCU-SW02K713" | Format-Table
.EXAMPLE
   Output results to a .CSV file
   Get-OverallBackLog -DomainName "eu.seb.com" -GroupName "EU-FR-MAY-SW00P887-F-DATA03-MAY-SW07N251-DCU-SW02K713" | Export-Csv -Path C:\Temp\dfsrbacklog.csv
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='PSet1')]
    [Parameter(ParameterSetName='PSet2')]
    [string]$DomainName = "eu.seb.com",
    [Parameter(ParameterSetName='PSet1')]
    [string]$GroupName,

    [Parameter(ParameterSetName='PSet2')]
    [string]$DestinationComputerName,
        [Parameter(ParameterSetName='PSet2')]
    [string]$FolderName

)


if(Get-Module DFSR){
    if($GroupName){
        $ReplicationGroups = Get-DfsReplicationGroup -DomainName $DomainName -GroupName $GroupName
    }
    else{
        $ReplicationGroups = Get-DfsReplicationGroup -DomainName $DomainName
    }

    function Get-DfrsdiagOutput ($Output){

        $OutputString = $Output | Select-String "(Backlog File Count: (\d+))|(No Backlog - member)|(\[ERROR\] Failed to contact)"
    
        if($OutputString -match "Backlog File Count: (\d+)"){
            [int]$BackLog = $Matches[1]
            if($BackLog -ge 10000){
                $ReplicationStatus = "FAIL"
                $Details = "Broken Replication: Extensive Backlog: $BackLog"
            }
            else{
                $ReplicationStatus = "OK"
                $Details = "Current backlog: $BackLog"
            }
        }
        elseif($OutputString -match "No Backlog - member"){
            $ReplicationStatus = "OK"
            $Details = "Current backlog: $BackLog"
        }
        elseif($OutputString -match "\[ERROR\] Failed to contact"){
            $ReplicationStatus = "FAIL"
            $Details = "WMI QUERY ERROR"
        }

        New-Object -TypeName psobject -Property @{Replication = $ReplicationStatus; Details = $Details}

    }

    $Obj = @()

    foreach($RG in $ReplicationGroups){
        Write-Verbose "Replication Group: $($RG.GroupName)"
        if($FolderName){
            $RFolders = Get-DfsReplicatedFolder -GroupName $RG.GroupName -DomainName $DomainName -FolderName $FolderName
        }
        else{
             $RFolders = Get-DfsReplicatedFolder -GroupName $RG.GroupName -DomainName $DomainName
        }           

        $RGMembers = Get-DfsrMembership -GroupName $RG.GroupName -DomainName $DomainName
        $RWMbrs = $RGMembers | Where-Object ReadOnly -eq $false
        $ROMbrs = $null
        if($DestinationComputerName){
            $ROMbrs = $RGMembers | Where-Object { $_.ReadOnly -ne $false -and $_.ComputerName -eq $DestinationComputerName }
        }
        else{
            $ROMbrs = $RGMembers | Where-Object ReadOnly -ne $false
        }

        if($ROMbrs -and $RWMbrs.ComputerName -notcontains "ORG32NT"){
    
            foreach($RWMbr in $RWMbrs){
                foreach($ROMbr in $ROMbrs){
                    foreach($RF in $RFolders){
                        $BackLog = $null
                        $Details = $null
                        try{
                            [int]$BackLog = (Get-DfsrBacklog -GroupName $RG.GroupName -SourceComputerName $RWMbr.ComputerName -DestinationComputerName $ROMbr.ComputerName -FolderName $RF.FolderName -Verbose 4>&1 -ErrorAction Stop).Message.Split(':')[2]
                            #$BackLog.Length
                            #$BackLog
                            if($BackLog -ge 10000){
                                $ReplicationStatus = "FAIL"
                                $Details = "Broken Replication: Extensive Backlog: $BackLog"
                            }
                            else{
                                $ReplicationStatus = "OK"
                                $Details = "Current backlog: $BackLog"
                            }
                        }
                        catch [Microsoft.DistributedFileSystemReplication.DfsrException] {

                        
                            if($_.Exception.ErrorId -match "CimException"){
                                $dfsrdiag = $null
                                $dfsrdiag = dfsrdiag backlog /rgname:$($RG.GroupName) /rfname:$($RF.FolderName) /smem:$($RWMbr.ComputerName) /rmem:$($ROMbr.ComputerName)
                                $DfsrdiagResults = $null
                                $DfsrdiagResults = Get-DfrsdiagOutput -Output $dfsrdiag
                                #$dfsrdiag
                                #$DfsrdiagResults
                                $ReplicationStatus = $DfsrdiagResults.Replication
                                $Details = $DfsrdiagResults.Details
                            }
                            else{
                                $ReplicationStatus = "FAIL"
                                $Details = "Broken Replication: $($_.Exception.ErrorId)"
                            }

                        }
                        catch {
                            $ReplicationStatus = "FAIL"
                            $Details = $_.Exception.GetType().FullName

                        }
                        $Props = [ordered]@{
                            ReplicationGroup = $RG.GroupName
                            SendingServer = $RWMbr.ComputerName
                            ReceivingServer = $ROMbr.ComputerName
                            Folder = $RF.FolderName
                            Replication = $ReplicationStatus
                            Details = $Details
                        }

                        #$Props

                        #$Obj += 
                        New-Object -TypeName psobject -Property $Props

                    }
                }
            }
        }
    }

    #$Obj
}
else{
    Write-Warning "The script must be executed from a server with the DFSR module installed"
}
