$SourceFolder = Get-ChildItem D:\DATA01\Data -Exclude "BE_Boisson","DATABE1","DATAMTH","Qualite_commun"

foreach($SF in $SourceFolder){
    $Log = "C:\Scripts\Robocopy\$($SF.Name).txt"
    $Source = $SF.FullName
    $Dest = $Source -replace "D:\\DATA01","F:\DATA03"
    #Write-Output $Source $Dest $Log
    robocopy $Source $Dest /E /B /COPYALL /R:5 /W:5 /V /LOG+:$Log
}