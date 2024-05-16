# Get Distribution Lists and Mail-enabled security groups
$DLs = Get-Group -RecipientTypeDetails MailNonUniversalGroup,MailUniversalDistributionGroup,MailUniversalSecurityGroup -ResultSize Unlimited

# Get Message trace. You can use this cmdlet to search message data for the last 10 days. 
# If you run this cmdlet without any parameters, only data from the last 48 hours is returned.

$ObjMsg = @()

$MessageTraceSend = @() 
$MessageTraceRec = @()

foreach($DL in $DLS){
    $MsgRec = 0
    $MsgSend = 0
    for ($i = 1; $i -lt 10; $i++){
        $MessageTraceSend += Get-MessageTrace -EndDate $((Get-Date).AddDays(-$i)) -StartDate $((Get-Date).AddDays(-$i - 1)) -PageSize 1000 -SenderAddress $DL.WindowsEmailAddress
        $MessageTraceRec += Get-MessageTrace -EndDate $((Get-Date).AddDays(-$i)) -StartDate $((Get-Date).AddDays(-$i - 1)) -PageSize 1000 -RecipientAddress $DL.WindowsEmailAddress -Status Expanded
    }
    foreach($Msg in $MessageTraceSend){
        if($Msg.SenderAddress -eq $DL.WindowsEmailAddress){
            $MsgSend++
        }
    }
    foreach($Msg in $MessageTraceRec){
        if($Msg.RecipientAddress -eq $DL.WindowsEmailAddress){
            $MsgRec++
        }
    }
    $Props = [ordered]@{
        DL = $DL.WindowsEmailAddress
        Received = $MsgRec
        Send = $MsgSend
    }
    $ObjMsg += New-Object -TypeName psobject -Property $Props
}
$ObjMsg