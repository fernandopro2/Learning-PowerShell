# PTASK0003749


$DomainList = @("SEB.COM","EU.SEB.COM","AS.SEB.COM","SA.SEB.COM","NA.SEB.COM")


$ObjTaskInfo = @()
$ReplicaMembers = @()

$CIMSessionOption = New-CimSessionOption -Protocol Dcom

foreach($DL in $DomainList){
        
    $ReplicationGroups = Get-DfsReplicationGroup -DomainName $DL

    foreach($RG in $ReplicationGroups){
        $ReplicaMembers += Get-DfsrMembership $RG.GroupName -DomainName $DL | Where-Object ReadOnly -eq $true | Select-Object GroupName,ComputerName,ReadOnly,Enabled,GroupDomainName
    }
}


foreach($Mbr in ($ReplicaMembers | Select-Object -Property ComputerName -Unique)){
    $CIMSession = New-CimSession -ComputerName $Mbr.ComputerName -SessionOption $CIMSessionOption
    $ScheduledTask =  $null
    $ScheduledTask = Get-ScheduledTask -TaskName *dfsr* -CimSession $CimSession
    if($ScheduledTask){
        $ScheduledTaskInfo = $ScheduledTask | Get-ScheduledTaskInfo
        $Props = @{
            GroupName = $Mbr.GroupName
            LastRunTime = $ScheduledTaskInfo.LastRunTime
            LastTaskResult = $ScheduledTaskInfo.LastTaskResult
            NextRunTime = $ScheduledTaskInfo.NextRunTime
            NumberOfMissedRuns = $ScheduledTaskInfo.NumberOfMissedRuns
            TaskName = $ScheduledTaskInfo.TaskName
            TaskPath = $ScheduledTaskInfo.TaskPath
            PSComputerName = $ScheduledTaskInfo.PSComputerName
            TaskAccount =  $ScheduledTask.Principal.UserId
            TaskState =  $ScheduledTask.State
        }
    }
    else{
        $Props = @{
            GroupName = $Mbr.GroupName
            LastRunTime = $null
            LastTaskResult = $null
            NextRunTime = $null
            NumberOfMissedRuns = $null
            TaskName = $null
            TaskPath = $null
            PSComputerName = $Mbr.ComputerName
            TaskAccount = $null
        }

    }

    New-Object -TypeName psobject -Property $Props

                        
    $CIMSession | Remove-CimSession
}



