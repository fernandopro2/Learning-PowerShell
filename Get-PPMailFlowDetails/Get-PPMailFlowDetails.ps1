param(
    [string]$CsvExportedFromProopoint
)

$Report = Import-Csv $CsvExportedFromProopoint | Where-Object Final_Rule -eq "pass"

$Report | Select-Object Sender,Recipients,Subject | ft
$Report | Select-Object Sender_IP_Address,@{L='Rules';E={[string]::Join(",",($_.Rule_ID -split "," | Sort-Object)) }},Attachment_Names | ft
$Report | Select-Object Sender,Sender_IP_Address,Sender_Host | ft
$Report | Select-Object Sender,Sender_IP_Address,@{L='Module_ID';E={[string]::Join(",",($_.Module_ID -split "," | Sort-Object)) }} | ft
$Report | Select-Object Sender,Sender_IP_Address,@{L='Policy_Routes';E={[string]::Join(",",($_.Policy_Routes -split "," | Sort-Object)) }} | ft
$Report.Recipients -split "," | Group-Object | Select-Object Count,@{L='Recipients';E={$_.Name}} | ft
$Report | Group-Object -Property Subject | Select-Object Count,@{L='Subject';E={$_.Name}} | ft
$Report | Group-Object -Property Sender_Host | Select-Object Count,@{L='Sender_Host';E={$_.Name}} | ft
$Report | Group-Object -Property Sender_IP_Address | Select-Object Count,@{L='Sender_IP_Address';E={$_.Name}} | ft

