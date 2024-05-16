$DCs = Get-ADDomainController -Filter *

$ObjGPO = @()
foreach($DC in $DCs){
    $DCName = $DC.HostName
    $GPO = Get-GPO "User - Mount" -Server $DCName #| Select-Object Computer,ModificationTime,UserVersion
    $GPTFile = Get-Content "\\$($DCName)\sysvol\monum.fr\Policies\$("{E2343624-A8A1-462F-A1B3-E2D2A2E11965}")\GPT.INI" | Select-String "Version"
    $UserContainer = Get-ADObject "CN=User,CN={E2343624-A8A1-462F-A1B3-E2D2A2E11965},CN=Policies,CN=System,DC=monum,DC=fr" -Properties whenChanged,uSNChanged -Server $DCName
    $GPOContainer = Get-ADObject "CN={E2343624-A8A1-462F-A1B3-E2D2A2E11965},CN=Policies,CN=System,DC=monum,DC=fr" -Properties versionNumber -Server $DCName

    $Props = [ordered]@{
        DC = $DCName
        ModificationTime = $GPO.ModificationTime
        SysvolVersion = $GPO.User.SysvolVersion
        DSVersion = $gpo.User.DSVersion
        GPTFile = $GPTFile -replace "Version=",""
        WhenChanged = $UserContainer.WhenChanged
        uSNChanged = $UserContainer.uSNChanged
        ContainerVersionNumber = $GPOContainer.versionNumber

    }
    $ObjGPO += New-Object -TypeName psobject -Property $Props
    #Get-ADObject "CN=User,CN={E2343624-A8A1-462F-A1B3-E2D2A2E11965},CN=Policies,CN=System,DC=monum,DC=fr" -Properties whenChanged -Server $DCName
}

$ObjGPO | ft

