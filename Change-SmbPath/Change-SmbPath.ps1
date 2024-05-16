# Run Delta
robocopy "D:\DATA01\ " "F:\DATA03\ " /E /B /COPYALL /PURGE /R:5 /W:5 /LOG+:"C:\Scripts\Robocopy\Logs\DELTA-2023-01-12.txt"
robocopy "D:\DATA01\ " "F:\DATA03\ " /E /B /COPYALL /PURGE /R:5 /W:5 /MOT:5 /LOG+:"C:\Scripts\Robocopy\Logs\DELTA-2023-01-12.txt" /nfl /ndl
robocopy D:\DATA01\Commun F:\DATA03\Commun /E /B /COPYALL /PURGE /R:5 /W:5 /

# Set variables
$ScriptPath = "C:\Scripts\Robocopy"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares"

# Backing up registry
$TimeStamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
reg export ($RegPath -replace "HKLM:","HKLM") "$ScriptPath\Registry\SmbSharesBkp$($TimeStamp).reg" /y

# Get SmbShare list
$SmbShares = Get-SmbShare -IncludeHidden | Where-Object Path -Like "D:\DATA01\*"

# Save SMB shares permissions and properties
$SmbShares | Get-SmbShareAccess | Export-Csv "$ScriptPath\SmbSharesACL.csv" -Encoding UTF8
$SmbShares | Export-Csv "$ScriptPath\SmbSharesProperties.csv" -Encoding UTF8

# Switch Over to F:
foreach($SS in $SmbShares){
    $ShareName = $SS.Name
    $OldPath = $SS.Path
    $NewPath = $SS.Path -replace "D:\\DATA01","F:\DATA03"
    $ShareInfo = Get-ItemProperty -Path $RegPath -Name $ShareName | Select-Object -ExpandProperty $ShareName
    $ShareInfo | Out-File "C:\Scripts\Robocopy\BKP-Settings\$ShareName-$TimeStamp.txt" -Encoding utf8 -Force
    if ($ShareInfo | Where-Object { $_ -eq "Path=$OldPath" }) {
        $ShareInfo = $ShareInfo -replace [regex]::Escape("Path=$OldPath"), "Path=$NewPath"
        $ShareInfo
        Set-ItemProperty -Path $RegPath -Name $ShareName -Value $ShareInfo
    }
}

