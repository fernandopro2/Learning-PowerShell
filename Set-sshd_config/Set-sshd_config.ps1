<#
  .SYNOPSIS
  Deployment of OpenSSH configuration file on Windows machine.
  
  .DESCRIPTION
  Deployment of the OpenSSH configuration file 'sshd_config' on a Windows machine for a customer indicated as a parameter.
  sshd_config configuration files must first be placed under '.\fic\' and their names must be in lowercase.
  Customer's sshd_config are stored in Confluence: https://delivery.inetum.com/confluence/pages/viewpage.action?pageId=202114859
  Example :
    .\fic\sshd_config.boiron
    .\fic\sshd_config.gseb
    .\fic\sshd_config.linedata
  
  .PARAMETER Customer
  Name of customer concerned (case insensitive, will be forced to lowercase) [REQUIRED]

  .PARAMETER Agent
  Allow using ssh-agent service for SSH private key management (Default: $false) (choices: Boolean) [OPTIONAL]

  .PARAMETER DefaultShell
  Determine which default shell to use with OpenSSH (Default: "PowerShell") (choices: "PowerShell", "Cmd") [OPTIONAL]

  .OUTPUTS
  Return code:
    0: execution is OK
    1: this script must be executed as administrator
    2: '$confssh_file' config file to deploy does not exist (Please check -Client parameter)
    3: executable file '$sshd_exe_path_executable' does not exist (Please check if OpenSSH have been correctly installed in '$sshd_exe_path')
    4: config file '$confssh_file_customer' is not valid (Please see Exception error above)
    5: directory '$confssh_path' does not exist (Please check if OpenSSH have been correctly installed in '$sshd_exe_path')
    6: config file '$confssh_file_dest' does not exist (Please check if OpenSSH have been correctly installed, with sshd_config file in '%PROGRAMDATA%\ssh\')
    7: failed to copy '$confssh_file_customer' config file in local '$confssh_path' directory
    8: failed to add Firewall SSH rule to allow incoming SSH connexion (Commented because not used)
    9: failed to set 'sshd' service to automatic starting
   10: failed to restart 'sshd' service
   11: failed to set 'ssh-agent' service to Automatic starting
   12: failed to restart 'ssh-agent' service
   13: failed to set 'ssh-agent' service to disabled starting
   14: failed to stop 'ssh-agent' service
   15: failed to set DefaultShell to powershell.exe
  
  .NOTES
  Version: 1.0.0.0
  Author: HOURIEZ Emmanuel
  Creation Date: 24/05/2022
  Purpose/Change: Initial Development

  .EXAMPLE
  .\Set-sshd_config.ps1 -Customer BOIRON
    Deploys the file .\fic\sshd_config.boiron specific to BOIRON customer WITHOUT starting ssh-agent service (for private keys management)
  
  .\Set-sshd_config.ps1 -Customer GSEB
    Deploys the file .\fic\sshd_config.boiron specific to GSEB customer WITHOUT starting ssh-agent service (for private keys management)
  
  .\Set-sshd_config.ps1 -Customer LINEDATA -Agent $true
    Deploys the file .\fic\sshd_config.boiron specific to LINEDATA customer WITH starting ssh-agent service (for private keys management)
  
  .\Set-sshd_config.ps1 -Customer GSEB -Agent $true
    Deploys the file .\fic\sshd_config.boiron specific to GSEB customer WITH starting ssh-agent service (for private keys management)
#>

Param (
  [parameter(Mandatory=$true)][String]$Customer,
  [parameter(Mandatory=$false)][String]$Agent=$false,
  [parameter(Mandatory=$false)][String]$DefaultShell="PowerShell"
)

Function Custom_Write_Host {
  Param (
    [string]$Msg = "NA",
    [string]$ForegroundColor = "",
    [switch]$DoubleCRLF = $False
  )
  if ($ForegroundColor -ne "") {
    Write-Host "${Msg}" -ForegroundColor $ForegroundColor
  } else {
    Write-Host "${Msg}"
  }
  if ($DoubleCRLF) {
    Write-Host
  }
}

$script_name = $MyInvocation.MyCommand.Name
Custom_Write_Host -Msg "${script_name} for sshd_config deployment ..." -ForegroundColor Yellow -DoubleCRLF

# Check user's administrator permissions
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Error "ERROR - this script must be executed as administrator" -Category PermissionDenied -CategoryReason "Please run this script as administrator"
  Exit 1
}

# Force -Customer parameter to lowercase
$Customer = $Customer.ToLower()

# Source path for this script
$SourcePath = Split-Path $MyInvocation.MyCommand.Path -Parent

# BEGIN check 'sshd_config' config file to deploy
Custom_Write_Host -Msg "Get config file path to deploy '$SourcePath\fic\sshd_config.$Customer'" -ForegroundColor Cyan
$confssh_file_path = "$SourcePath\fic"
$confssh_file_customer = "$confssh_file_path\sshd_config.$Customer"

Custom_Write_Host -Msg "Check if '$confssh_file_customer' config file to deploy does exists ..." -ForegroundColor Yellow
If (-Not (Test-Path -Path $confssh_file_customer -PathType Leaf)) {
  Write-Error "ERROR - '$confssh_file' config file to deploy does not exist" -Category ObjectNotFound -CategoryReason "Please check -Customer parameter"
  Exit 2
}
Custom_Write_Host -Msg "Check if '$confssh_file_customer' config file to deploy does exists [OK]" -ForegroundColor Green -DoubleCRLF
# END check 'sshd_config' config file to deploy

# BEGIN check '${Env:ProgramFiles}\OpenSSH\sshd.exe' executable file
Custom_Write_Host -Msg "Get local '${Env:ProgramFiles}\OpenSSH\sshd.exe' executable file" -ForegroundColor Cyan
$sshd_exe_path = "${Env:ProgramFiles}\OpenSSH"
$sshd_exe_path_executable = "$sshd_exe_path\sshd.exe"

Custom_Write_Host -Msg "Check if local '$sshd_exe_path_executable' executable file does exist ..." -ForegroundColor Yellow
If (-Not (Test-Path -Path $sshd_exe_path_executable)) {
  Write-Error "ERROR - executable file '$sshd_exe_path_executable' does not exist" -Category ObjectNotFound -CategoryReason "Please check if OpenSSH have been correctly installed in '$sshd_exe_path'"
  Exit 3
}
Custom_Write_Host -Msg "Check if local '$sshd_exe_path_executable' executable file does exist [OK]" -ForegroundColor Green -DoubleCRLF
# END check '${Env:ProgramFiles}\OpenSSH\sshd.exe' executable file

# BEGIN check '$confssh_file_customer' config file to deploy is valid
Custom_Write_Host -Msg "Check config file '$confssh_file_customer' is valid ..." -ForegroundColor Yellow
. $sshd_exe_path_executable -t -f $confssh_file_customer
if (-Not $?) {
  Write-Host
  Custom_Write_Host -Msg "ERROR - config file '$confssh_file_customer' is not valid (Please see Exception error above)" -ForegroundColor Red -DoubleCRLF
  Exit 4
}
Custom_Write_Host -Msg "Check config file '$confssh_file_customer' is valid [OK]" -ForegroundColor Green -DoubleCRLF
# END check sshd_config' config file to deploy is valid

# BEGIN check '${Env:ProgramData}\ssh' directory
Custom_Write_Host -Msg "Get local '${Env:ProgramData}\ssh' path" -ForegroundColor Cyan
$confssh_path = "${Env:ProgramData}\ssh"

Custom_Write_Host -Msg "Check if '$confssh_path' directory does exists ..." -ForegroundColor Yellow
If (-Not (Test-Path -Path $confssh_path)) {
  Write-Error "ERROR - directory '$confssh_path' does not exist" -Category ObjectNotFound -CategoryReason "Please check if OpenSSH have been correctly installed in '$sshd_exe_path'"
  Exit 5
}
Custom_Write_Host -Msg "Check if '$confssh_path' directory does exists [OK]" -ForegroundColor Green -DoubleCRLF
# END check '${Env:ProgramData}\ssh' directory

# BEGIN check '${Env:ProgramData}\ssh\sshd_config' config file
Custom_Write_Host -Msg "Get local '${Env:ProgramData}\ssh\sshd_config' configuration file" -ForegroundColor Cyan
$confssh_file_dest = "${Env:ProgramData}\ssh\sshd_config"

Custom_Write_Host -Msg "Check config file in local '$confssh_path' path does exist ..." -ForegroundColor Yellow
If (-Not (Test-Path -Path $confssh_file_dest)) {
  Write-Error "ERROR - config file '$confssh_file_dest' does not exist" -Category ObjectNotFound -CategoryReason "Please check if OpenSSH have been correctly installed, with sshd_config file in '%PROGRAMDATA%\ssh\'"
  Exit 6
}
Custom_Write_Host -Msg "Check config file in local '$confssh_path' path does exist [OK]" -ForegroundColor Green -DoubleCRLF
# END check '${Env:ProgramData}\ssh\sshd_config' config file

# BEGIN copy '$confssh_file_customer' config file
Custom_Write_Host -Msg "Copy '$confssh_file_customer' config file in local '$confssh_file_dest' directory ..." -ForegroundColor Yellow
Try {
  Copy-Item $confssh_file_customer -Destination $confssh_file_dest
} Catch {
  Write-Error "ERROR - failed to copy '$confssh_file_customer' config file in local '$confssh_path' directory" -Category InvalidOperation
  Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
  Exit 7
}
Custom_Write_Host -Msg "Copy '$confssh_file_customer' config file in local '$confssh_file_dest' directory [OK]" -ForegroundColor Green -DoubleCRLF
# END copy '$confssh_file_customer' config file

# BEGIN add a Firewall rule to allow incoming SSH connexion (Commented because not used)
# Custom_Write_Host -Msg "Add a Firewall rule to allow incoming SSH connexion" -ForegroundColor Yellow
# Try {
#   New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction Continue
# } Catch {
#   Write-Error "ERROR - failed to add Firewall SSH rule to allow incoming SSH connexion" -Category InvalidOperation
#   Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
#   Exit 8
# }
# Custom_Write_Host -Msg "Add a Firewall rule to allow incoming SSH connexion [OK]" -ForegroundColor Green -DoubleCRLF
# END add a Firewall rule to allow incoming SSH connexion (Commented because not used)

# BEGIN set 'sshd' service to automatic starting
Custom_Write_Host -Msg "Attempt to set 'sshd' service to automatic starting ..." -ForegroundColor Yellow
Try {
  Set-Service sshd -StartupType Automatic
} Catch {
  Write-Error "ERROR - failed to set 'sshd' service to automatic starting" -Category ResourceUnavailable
  Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
  Exit 9
}
Custom_Write_Host -Msg "Attempt to set 'sshd' service to automatic starting [OK]" -ForegroundColor Green -DoubleCRLF
# END set 'sshd' service to automatic starting

# BEGIN restart 'sshd' service
Custom_Write_Host -Msg "Attempt to restart 'sshd' service ..." -ForegroundColor Yellow
Try {
  Restart-Service sshd
} Catch {
  Write-Error "ERROR - failed to restart 'sshd' service" -Category ResourceUnavailable
  Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
  Exit 10
}
Custom_Write_Host -Msg "Attempt to restart 'sshd' service [OK]" -ForegroundColor Green -DoubleCRLF
# END restart 'sshd' service

# BEGIN 'ssh-agent' service
Custom_Write_Host -Msg "-Agent parameter has been set to $Agent" -ForegroundColor Cyan

If ($Agent -eq $true) {
  
  Custom_Write_Host -Msg "ssh-agent service to automatic starting ..." -ForegroundColor Yellow

  # BEGIN set 'ssh-agent' service to Automatic starting
  Custom_Write_Host -Msg "Attempt to set ssh-agent service to automatic starting ..." -ForegroundColor Yellow
  Try {
    Set-Service ssh-agent -StartupType Automatic
  } Catch {
    Write-Error "ERROR - failed to set 'ssh-agent' service to Automatic starting" -Category ResourceUnavailable
    Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
    Exit 11
  }
  Custom_Write_Host -Msg "Attempt to set 'ssh-agent' service to Automatic starting [OK]" -ForegroundColor Green -DoubleCRLF
  # END set 'ssh-agent' service to Automatic starting

  # BEGIN restart 'ssh-agent' service
  Custom_Write_Host -Msg "Attempt to restart ssh-agent service ..." -ForegroundColor Yellow
  Try {
    Restart-Service ssh-agent
  } Catch {
    Write-Error "ERROR - failed to restart 'ssh-agent' service" -Category ResourceUnavailable
    Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
    Exit 12
  }
  Custom_Write_Host -Msg "Attempt to restart ssh-agent service [OK]" -ForegroundColor Green -DoubleCRLF
  # END restart 'ssh-agent' service

} Else {

  # BEGIN set 'ssh-agent' service to disabled starting
  Custom_Write_Host -Msg "Attempt to set ssh-agent service to disabled starting ..." -ForegroundColor Yellow
  Try {
    Set-Service ssh-agent -StartupType Disabled
  } Catch {
    Write-Error "ERROR - failed to set 'ssh-agent' service to disabled starting" -Category ResourceUnavailable
    Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
    Exit 13
  }
  Custom_Write_Host -Msg "Attempt to set 'ssh-agent' service to disabled starting [OK]" -ForegroundColor Green -DoubleCRLF
  # END set 'ssh-agent' service to disabled starting

  # BEGIN stop 'ssh-agent' service
  Custom_Write_Host -Msg "Attempt to stop ssh-agent service ..." -ForegroundColor Yellow
  Try {
    Set-Service ssh-agent -Status Stopped
  } Catch {
    Write-Error "ERROR - failed to stop 'ssh-agent' service" -Category ResourceUnavailable
    Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
    Exit 14
  }
  Custom_Write_Host -Msg "Attempt to stop ssh-agent service [OK]" -ForegroundColor Green -DoubleCRLF
  # END stop 'ssh-agent' service

}
# END 'ssh-agent' service

# BEGIN set OpenSSH default shell
If ($DefaultShell.ToLower() -eq "cmd") { Custom_Write_Host -Msg "Attempt to set DefaultShell to cmd.exe ..." -ForegroundColor Yellow }
Else { Custom_Write_Host -Msg "Attempt to set DefaultShell to powershell.exe ..." -ForegroundColor Yellow }
Try {
  $registryPath = "HKLM:\SOFTWARE\OpenSSH\"
  $Name = "DefaultShell"
  If ($DefaultShell.ToLower() -eq "cmd") { $value = "C:\windows\System32\cmd.exe" }
  Else { $value = "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" }
  If (-Not (Test-Path $registryPath)) {
      New-Item -Path $registryPath -Force
      New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force >$null
  } Else {
      New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force >$null
  }
} Catch {
  Write-Error "ERROR - failed to set DefaultShell to powershell.exe" -Category ResourceUnavailable
  Write-Error "ERROR - $($_.Exception.Message) - $($_.Exception.ItemName)"
  Exit 15
}
If ($DefaultShell.ToLower() -eq "cmd") { Custom_Write_Host -Msg "Attempt to set DefaultShell to cmd.exe [OK]" -ForegroundColor Yellow }
Else { Custom_Write_Host -Msg "Attempt to set DefaultShell to powershell.exe [OK]" -ForegroundColor Yellow }
Write-Host
# END set OpenSSH default shell

# All is OK
Custom_Write_Host -Msg $script_name "for sshd_config deployment [OK]" -ForegroundColor Green -DoubleCRLF
Exit 0
