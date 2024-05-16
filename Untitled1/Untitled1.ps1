$ScheduledTasks = Get-ScheduledTask


foreach($ST in $ScheduledTasks){
    $ComputerName = $ST.PSComputerName
    $TaskName = $ST.TaskName
    $Principal = $ST | Select-Object -ExpandProperty Principal
    $Props = [ordered]@{
        ComputerName = $ComputerName
        TaskName = $TaskName
        State = $ST.State
        User = $Principal.UserId
    }

    New-Object -TypeName psobject -Property $Props
}