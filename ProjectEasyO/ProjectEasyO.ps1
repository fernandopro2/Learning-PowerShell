param(
    [string]$SourcePath = "D:\EasyO\files\GMAO\DA",
    [string]$DestinationPath = "D:\EasyO\files\GMAO\DA\SVG"
)


if(Test-Path $SourcePath){
    $FilesToMove = $null
    $FilesToMove = Get-ChildItem "$SourcePath\*" -Include *.txt,*.zip -Verbose
    if($FilesToMove){
        # 1. Move the file to $DestinationPath
        # 2. Send an email to Alteca TMA team
        if(Test-Path $DestinationPath){
            Move-Item $FilesToMove -Destination $DestinationPath -Verbose -WhatIf
        }
    }
}