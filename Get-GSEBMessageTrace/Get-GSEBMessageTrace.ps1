Param(
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [ValidateSet("SentByDL", "SendToDL")]
        $Action

)


# Get Distribution Lists and Mail-enabled security groups
$DLs = Get-Group -RecipientTypeDetails MailNonUniversalGroup,MailUniversalDistributionGroup,MailUniversalSecurityGroup 

# Get Message trace. You can use this cmdlet to search message data for the last 10 days. 
# If you run this cmdlet without any parameters, only data from the last 48 hours is returned.
$MessageTrace = Get-MessageTrace -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) -PageSize 5000


# Inicializing Variables
$SentToDL = @()
$SentByDL = @()

$ObjSent = @()
$ObjReceived = @()

if($Action -eq "SentByDL"){
    foreach($Msg in $MessageTrace){

        if($Msg.SenderAddress -in $DLs.WindowsEmailAddress){
            $SentByDL += $Msg
        }
    }
    $Count = $SentByDL | Group-Object -Property SenderAddress
    if($Count){
        foreach($Ct in $Count){
            $Props = [ordered]@{
                GroupName = $Ct.Name
                MessagesSent = $Ct.Count
            }
            $ObjSent += New-Object -TypeName psobject -Property $Props
        }
        $ObjSent
    }
}
elseif($Action -eq "SendToDL"){
    foreach($Msg in $MessageTrace){

        if($Msg.Status -eq "Expanded"){
            $SentToDL += $Msg
        }
    }
    $Count = $SentToDL | Group-Object -Property RecipientAddress
    if($Count){
        foreach($Ct in $Count){
            $Props = [ordered]@{
                GroupName = $Ct.Name
                MessagesReceived = $Ct.Count
            }
            $ObjReceived += New-Object -TypeName psobject -Property $Props
        }
        $ObjReceived
    }
}

