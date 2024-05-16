# Get Distribution Lists and Mail-enabled security groups
$DLs = Get-Group -RecipientTypeDetails MailNonUniversalGroup,MailUniversalDistributionGroup,MailUniversalSecurityGroup 

# Get Message trace. You can use this cmdlet to search message data for the last 10 days. 
# If you run this cmdlet without any parameters, only data from the last 48 hours is returned.

$ObjMsg = @()
foreach($DL in $DLS){
    $MsgRec = 0
    $MsgSend = 0
    $MessageTraceSend = Get-MessageTrace -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) -PageSize 5000 -SenderAddress $DL.WindowsEmailAddress
    $MessageTraceRec = Get-MessageTrace -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) -PageSize 5000 -RecipientAddress $DL.WindowsEmailAddress
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