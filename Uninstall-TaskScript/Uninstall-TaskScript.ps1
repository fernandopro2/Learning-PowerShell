
$tagfilePath = "C:\Temp\"
$tagfileName = "TeamViewer_Deinstalled"
$tagfile = $tagfilePath + $tagfileName
$Export = @()

if (!(Test-Path $tagfile)) {
	try {
		$installFolder = "\\scrpt.wmf.de\TeamViewer\TeamViewerUninstall\Uninstall-TeamViewer"
		$arguments = "-file C:\Temp\Uninstall-TeamViewer\Uninstall-TeamViewer.ps1", "Uninstall" , "NonInteractive"
		# Copy files to local folder
		Copy-Item -Path $installFolder -Recurse -Destination "C:\Temp" -Force
		# Run the script to uninstall teamviewer
		$Deinstallation = Start-Process powershell.exe -ArgumentList $arguments -NoNewWindow -Wait -PassThru
		$Deinstallation.WaitForExit();
		if ($Deinstallation.ExitCode -eq 0) {
			if (!(Get-Service TeamViewer -ErrorAction SilentlyContinue).length -gt 0) {
				New-Item -ItemType File -Path "C:\Temp" -Name $tagfileName -Force | Out-Null
				$Export += New-Object PSObject -Property $([ordered]@{
						ServerName    = $env:COMPUTERNAME
						IPAddress     = (Get-NetIPAddress -InterfaceAlias Ethernet*).ipaddress
						ScriptRunDate = Get-Date
						TVService     = "not present"
						Info          = "Done"
					})
			}
			else {
				$Export += New-Object PSObject -Property $([ordered]@{
						ServerName    = $env:COMPUTERNAME
						IPAddress     = (Get-NetIPAddress -InterfaceAlias Ethernet*).ipaddress
						ScriptRunDate = Get-Date
						TVService     = (Get-Service TeamViewer).Status
						Info          = "Check"
					})
			}
		}
		else {
			$Export += New-Object PSObject -Property $([ordered]@{
					ServerName    = $env:COMPUTERNAME
					IPAddress     = (Get-NetIPAddress -InterfaceAlias Ethernet*).ipaddress
					ScriptRunDate = Get-Date
					TVService     = (Get-Service TeamViewer).Status
					Info          = "Error"
				})
		}
	}
	catch {
		$Export += New-Object PSObject -Property $([ordered]@{
				ServerName    = $env:COMPUTERNAME
				IPAddress     = (Get-NetIPAddress -InterfaceAlias Ethernet*).ipaddress
				ScriptRunDate = Get-Date
				TVService     = (Get-Service TeamViewer).Status
				Info          = "Error"
			})
	}
	# remove files from local computer
	$Export | Export-Csv -Path "\\scrpt.wmf.de\TeamViewer\TeamViewerUninstall\Uninstall-TeamViewer-LOG\log.csv" -Encoding UTF8 -NoTypeInformation -Delimiter ";" -Append -Force
	Remove-Item -LiteralPath "C:\Temp\Uninstall-TeamViewer" -Force -Recurse
}

