<#
.Synopsis
   # RITM0786415 | SCTASK0334042
.EXAMPLE
   Resets the WSUS Client properties and triggers a report status sending for the server SW09D555. 
   .\Repair-WsusClient.ps1 -ComputerName "SW09D555"
.EXAMPLE
   Lists the current WSUS Client properties for the server SW09D555. No change is performed. 
   .\Repair-WsusClient.ps1 -ComputerName "SW09D555" -ViewOnly
.EXAMPLE
   Resets the WSUS Client properties and triggers a report status sending for the server SW09D555 using the pipeline binding instead. 
   "SW09D555" | .\Repair-WsusClient.ps1
#>

[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
param(
    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
    Mandatory=$True)]
    [string[]]
    $ComputerName,
    [switch]$ViewOnly

)

BEGIN{
    
    $ConfirmPreference="high"
    # Wsus registry settings paths
    $RegistryKeyPath1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
    $RegistryKeyPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

}

PROCESS {

    foreach($Server in $ComputerName){
        $WuauServ = $null
        $WuauServ = Get-Service wuauserv -ComputerName $Server
        if($WuauServ){ 
            $ServiceStatus = $WuauServ.StartType
            $WinRMConn =  $null
            if(Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM){
                $WinRMConn = $true
                $PSSession = $null
                $PSSession = New-PSSession -ComputerName $Server
                $WSUSClientReg = $null
                if($PSSession){
                    $WSUSClientReg = Invoke-Command -Session $PSSession {
                        Get-ItemProperty -Path $Using:RegistryKeyPath1 -Name * -Verbose
                        Get-ItemProperty -Path $Using:RegistryKeyPath2 -Name * -Verbose

                        if(!$Using:ViewOnly){

                            Get-Service BITS, wuauserv | Stop-Service -Force -PassThru
                            Remove-ItemProperty -Name AccountDomainSid, PingID, SusClientId, SusClientIDValidation -Path $Using:RegistryKeyPath1 -ErrorAction SilentlyContinue -Verbose
                            Remove-Item "$env:SystemRoot\SoftwareDistribution\" -Recurse -Force -ErrorAction SilentlyContinue 
                            Get-Service BITS, wuauserv | Start-Service -PassThru
                        
                            <# From this point ahead: 
                            Reset, Detect, Search and Report using 
                            wuauclt tool and Windows Update Agent API (Microsoft.Update COM objects)
                            #>
                            wuauclt /resetauthorization /detectnow 
                            $AutoUpdates = New-Object -ComObject "Microsoft.Update.AutoUpdate"
                            $AutoUpdates.DetectNow() 
                            $UpdateSession = New-Object -ComObject "Microsoft.Update.Session";  
                            # $Criteria varible is $null OR not defined by design
                            $Updates = $UpdateSession.CreateupdateSearcher().Search($criteria).Updates 
                            wuauclt /reportnow
                        }

                    }
                }
            
                $PSSession | Remove-PSSession
                
                if(($WSUSClientReg -split ";" | Select-String WUServer ) -match "http://(.+):8530"){
                    $WsusServer = $Matches[1]
                    $ObjWsusComputer = Get-WsusComputer -UpdateServer (Get-WsusServer -Name $WsusServer -PortNumber 8530) -NameIncludes $Server
                }
            }else{
                $WinRMConn = $false
            }

            $WUServer = $WsusServer
            $SusId = $ObjWsusComputer.Id
            $TargetGroup = $ObjWsusComputer.RequestedTargetGroupName
            $LastSyncTime = $ObjWsusComputer.LastSyncTime
            $LastReportedStatusTime = $ObjWsusComputer.LastReportedStatusTime
            $WindowsUpdateService = $ServiceStatus
            $WinRM = $WinRMConn

            $Props = [ordered]@{
                ComputerName = $Server
                WUServer = $WsusServer
                SusId = $ObjWsusComputer.Id
                TargetGroup = $ObjWsusComputer.RequestedTargetGroupName
                LastSyncTime = $ObjWsusComputer.LastSyncTime
                LastReportedStatusTime = $ObjWsusComputer.LastReportedStatusTime
                WindowsUpdateService = $ServiceStatus
                WinRM = $WinRMConn
            }
 
        } 
        else {

            $WUServer = $null
            $SusId = $null
            $TargetGroup = $null
            $LastSyncTime = $null
            $LastReportedStatusTime = $null
            $WindowsUpdateService = "RPC Query Failed"
            $WinRM = $null
        }

        $Props = [ordered]@{
            ComputerName = $Server
            WUServer = $WUServer
            SusId = $SusId
            TargetGroup = $TargetGroup
            LastSyncTime = $LastSyncTime
            LastReportedStatusTime = $LastReportedStatusTime
            WindowsUpdateService = $WindowsUpdateService
            WinRM = $WinRM
        } 
         
         New-Object -TypeName psobject -Property $Props

    }
}

END{
    Write-Verbose "Command completed."
}

     