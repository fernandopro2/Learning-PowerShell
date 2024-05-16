$Computers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties OperatingSystem,Enabled  

  

$TermSvcScp = Get-ADObject -Filter {objectClass -eq 'serviceConnectionPoint' -and Name -eq 'TermServLicensing'}   

  

$Obj = @() 

$ObjConn = @() 

  

  

foreach($Comp in $Computers){ 

    Write-Output "Gathering data from $($Comp.DNSHostName)" 

    $TestConnection = $null 

    $TestDNS = $null 

    $TestPing = $null 

    $TestRPC = $null 

    $TestConnection = Test-NetConnection -ComputerName $Comp.DNSHostName 

    if($TestConnection.NameResolutionSucceeded -eq $true){ 

        $TestDNS = "SUCCESS" 

        if($TestConnection.PingSucceeded -eq $true){ 

            $TestPing = "SUCCESS" 

        } 

        else{ 

            $TestPing = "FAIL" 

        } 

        $ComputerSystem = $null 

        $Err = $null 

        $TestRPCException = $null 

        $ComputerSystem = Get-WmiObject Win32_ComputerSystem -ComputerName $Comp.DNSHostName -ErrorVariable Err 

        if($ComputerSystem){ 

            $TestRPC = "SUCCESS" 

            $TestRPCException = "N/A" 

            $TerminalServiceSetting = $null 

            $LicenseServerList = $null 

            $LicensingType = $null 

            $TerminalServiceSetting = Get-WmiObject -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting -ComputerName $Comp.DNSHostName 

            $LicenseServerList = $TerminalServiceSetting.GetSpecifiedLicenseServerList().SpecifiedLSList 

            $LicensingType = $TerminalServiceSetting.LicensingType 

            $LicenseServerList 

  

            if($ComputerSystem.Model -like "*Virtual*"){ 

                $Model = "Virtual" 

            } 

            else{ 

                $Model = "Physical" 

            } 

            $NumberOfLogicalProcessors = $ComputerSystem.NumberOfLogicalProcessors 

            $NumberOfProcessors = $ComputerSystem.NumberOfProcessors 

  

             

            if($Comp.DistinguishedName -in ($TermSvcScp -replace "CN=TermServLicensing,","")){ 

                $TermService = $true 

            } 

            else{ 

                $TermService = $false 

            } 

             

            if($TermService){ 

  

  

                $LicenseSettings = $null 

                #$LicenseSettings = Get-WmiObject Win32_TSLicenseKeyPack -ComputerName $Comp.DNSHostName -Filter 'KeyPackType != 7'  

                if($LicenseSettings){ 

                    $LicenseSettings | Select-Object PSComputerName,@{L='ProductType';E={if($_.ProductType -eq 1){"Per User"}elseif($_.ProductType -eq 0){"Per Device"}elseif($_.ProductType -eq 3){"Builtin"}}},ProductVersion,TypeAndModel,TotalLicenses,AvailableLicenses,IssuedLicenses #|  

                    #Export-Csv C:\Temp\ADGZ\LicenseKeyPack.csv -Append -Encoding UTF8 

  

                    $IssuedLicenses = $null 

                    $IssuedLicenses = Get-WmiObject Win32_TSIssuedLicense -ComputerName $Comp.DNSHostName  

                    if($IssuedLicenses){ 

                        $IssuedLicenses | Select-Object PSComputerName,sIssuedToComputer,sIssuedToUser,LicenseStatus,IssueDate,ExpirationDate,@{L='KeyPackId';E={($LicenseSettings | Where-Object KeyPackId -eq $_.KeyPackId).TypeAndModel}} #| 

                        #Export-Csv C:\Temp\ADGZ\IssuedLicenses.csv -Append -Encoding UTF8 

                    } 

  

                } 

  

            } 

  

            if((Test-NetConnection $Comp.DNSHostname -Port 1433).TcpTestSucceeded -eq $true){ 

                $SQLPort = $true 

             

                $SqlServFile = $null 

                $SqlServFile = Get-ChildItem -Path "\\$($Comp.DNSHostName)\c`$\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Binn\sqlservr.exe" 

                if($SqlServFile){ 

                    $SQLVersionNumber = ($SqlServFile[0] | Select-Object -ExpandProperty VersionInfo).ProductVersion 

                    $SQLBuild = Import-Csv C:\TEMP\ADGZ\SQLVersion.csv -Delimiter ";" | Where-Object Build -eq $SQLVersionNumber 

                    $SQLVersion = $SQLBuild.Version 

                    $SQLServicePack = $SQLBuild.ServicePack 

                } 

                else{ 

                    $SQLPort = $false 

                    $SQLVersion = $null 

                    $SQLServicePack = $null 

                } 

            } 

            else{ 

                    $SQLPort = $false 

                    $SQLVersion = $null 

                    $SQLServicePack = $null 

            } 

  

    

            

            $Props = [ordered]@{ 

                Server = $Comp.DNSHostName 

                Model = $Model 

                OperatingSystem = $Comp.OperatingSystem 

                TermSvc = $TermService 

                LicenseServerList = $LicenseServerList 

                LicensingType = $LicensingType 

                NumberOfProcessors = $NumberOfProcessors 

                NumberOfLogicalProcessors = $NumberOfLogicalProcessors 

                SQLPort = $SQLPort 

                SQLVersion = $SQLVersion 

                SQLServicePack = $SQLServicePack 

  

            } 

            $Obj += New-Object -TypeName psobject -Property $Props 

  

        } 

        elseif($Err){ 

            $TestRPC = "FAIL" 

            if($Err[0].GetType().FullName -eq "System.Management.Automation.CmdletInvocationException"){ 

                $TestRPCException = ($Err.ErrorRecord.FullyQualifiedErrorId -split ",")[0] 

            } 

            elseif($Err[0].GetType().FullName -eq "System.Management.Automation.ErrorRecord"){ 

                $TestRPCException = ($Err.FullyQualifiedErrorId -split ",")[0] 

            } 

            else{ 

                $Err 

            } 

                 

        } 

  

    } 

    else{ 

        $TestDNS = "FAIL" 

        $TestPing = "FAIL" 

        $TestRPC = "FAIL" 

        $SQLPort = $false 

    } 

    $PropsConn = [ordered]@{ 

        SERVER = $Comp.DNSHostName 

        OS = $Comp.OperatingSystem 

        DNS = $TestDNS 

        PING = $TestPing 

        WMI = $TestRPC 

        WMIException = $TestRPCException 

        SQL = $SQLPort 

    } 

    $ObjConn += New-Object -TypeName psobject -Property $PropsConn 

  

} 

$Obj | Export-Csv C:\Temp\ADGZ\ComputersADGZ.csv -Encoding UTF8 