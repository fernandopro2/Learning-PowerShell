function Get-RegistryValueData {
    [CmdletBinding(SupportsShouldProcess=$True,
        ConfirmImpact='Medium',
        HelpURI='http://vcloud-lab.com')]
    Param
    ( 
        [parameter(Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [alias('C')]
        [String[]]$ComputerName = '.',
        [Parameter(Position=1, Mandatory=$True, ValueFromPipelineByPropertyName=$True)] 
        [alias('Hive')]
        [ValidateSet('ClassesRoot', 'CurrentUser', 'LocalMachine', 'Users', 'CurrentConfig')]
        [String]$RegistryHive = 'LocalMachine',
        [Parameter(Position=2, Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [alias('KeyPath')]
        [String]$RegistryKeyPath = 'SYSTEM\CurrentControlSet\Services\USBSTOR',
        [parameter(Position=3, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
        [alias('Value')]
        [String]$ValueName = 'Start',
        [String]$DomainName

    )
    Begin {
        $RegistryRoot= "[{0}]::{1}" -f 'Microsoft.Win32.RegistryHive', $RegistryHive
        try {
            $RegistryHive = Invoke-Expression $RegistryRoot -ErrorAction Stop
        }
        catch {
            Write-Host "Incorrect Registry Hive mentioned, $RegistryHive does not exist" 
        }
    }
    Process {
        Foreach ($Computer in $ComputerName) {
            if (Test-Connection $computer -Count 2 -Quiet) {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computer)
                $key = $reg.OpenSubKey($RegistryKeyPath)
                $Data = $key.GetValue($ValueName)
                $Obj = New-Object psobject´
                $Obj | Add-Member -Name Domain -MemberType NoteProperty -Value $DomainName
                $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $Computer
                $Obj | Add-Member -Name RegistryValueName -MemberType NoteProperty -Value "$RegistryKeyPath\$ValueName"
                $Obj | Add-Member -Name RegistryValueData -MemberType NoteProperty -Value $Data
                $Obj
            }
            else {
                Write-Host "$Computer not reachable" -BackgroundColor DarkRed
            }
        }
    }
    End {
        #[Microsoft.Win32.RegistryHive]::ClassesRoot
        #[Microsoft.Win32.RegistryHive]::CurrentUser
        #[Microsoft.Win32.RegistryHive]::LocalMachine
        #[Microsoft.Win32.RegistryHive]::Users
        #[Microsoft.Win32.RegistryHive]::CurrentConfig
    }
}

$DomainList = @("SEB.COM","EU.SEB.COM","AS.SEB.COM","SA.SEB.COM","NA.SEB.COM")

foreach($Domain in $DomainList){

    $DCs = Get-ADDomainController -Filter * -Server $Domain

    foreach($DC in $DCs){

        Get-RegistryValueData -ComputerName $DC.HostName -DomainName $Domain -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters -ValueName 'RequireSecuritySignature' | Export-Csv C:\Users\ADM-fsantos\Documents\SMBSigning.csv -Encoding UTF8 -NoTypeInformation -Append
        Get-RegistryValueData -ComputerName $DC.HostName -DomainName $Domain -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters -ValueName 'EnableSecuritySignature' | Export-Csv C:\Users\ADM-fsantos\Documents\SMBSigning.csv -Encoding UTF8 -NoTypeInformation -Append
        Get-RegistryValueData -ComputerName $DC.HostName -DomainName $Domain -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -ValueName 'RequireSecuritySignature' | Export-Csv C:\Users\ADM-fsantos\Documents\SMBSigning.csv -Encoding UTF8 -NoTypeInformation -Append
        Get-RegistryValueData -ComputerName $DC.HostName -DomainName $Domain -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -ValueName 'EnableSecuritySignature' | Export-Csv C:\Users\ADM-fsantos\Documents\SMBSigning.csv -Encoding UTF8 -NoTypeInformation -Append
    }
}