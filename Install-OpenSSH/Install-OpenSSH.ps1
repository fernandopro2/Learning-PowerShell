#Requires -Version 3.0

<#
.SYNOPSIS
  PowerShell script to install and configure OpenSSH on Windows targets
.DESCRIPTION
  This script uses :
    Windows optional features for Windows 2019
    Github repository for Windows 2012 and 2016
.NOTES
  File Name  : openssh.ps1
  Author     : Emmanuel Houriez
  Version    : 1.0
  History    : 
  source     : https://gist.github.com/slardiere/2db9f18babf9cc56598cb6d85ff9d02f
  PowerShell version minimum : 3
.EXAMPLE
  .\Install-OpenSSH.ps1
    Install and configure OpenSSH-Win64
  .\Install-OpenSSH.ps1 -SourcesPath 'C:\Temp\Custom_Directory\'
    Install and configure OpenSSH-Win64 from 'C:\Temp\Custom_Directory\' directory
	'OpenSSH-Win64' and 'OpenSSH-Win32' directories must be present in -SourcesPath Argument
  .\Install-OpenSSH.ps1 -Customer 'GSEB'
    Install and configure OpenSSH-Win64 and deploy GSEB sshd_config file
  .\Install-OpenSSH.ps1 -Customer 'GSEB' -Force
    Install and configure OpenSSH-Win64 and deploy GSEB sshd_config file (with '-Force' parameter OpenSSH configuration will be executed if OpenSSH was alreday installed)
  .\Install-OpenSSH.ps1 -Customer 'BOIRON' -Arch 'x32'
    Install and configure OpenSSH-Win32 and deploy BOIRON sshd_config file
  .\Install-OpenSSH.ps1 -SetFirewallRule
    Install and configure OpenSSh and creating SSH friewall rule
  .\Install-OpenSSH.ps1 -Reboot
    Reboot computer automatically after OpenSSH server installation and configuration

# .PARAMETER Agent (switch)  # Not used
#   Allow to start and set in automatic mode the 'ssh-agent' service  # Not used
.PARAMETER Customer (string)
  Default value = ""
  Customer name used for sshd_config file deployment (.\fic\sshd_config.${Customer})
.PARAMETER SourcesPath (string)
  Default value = "C:\Temp\WIN_InstallOpenSSH"
  Path to OpenSSH sources
.PARAMETER Arch (string)
  Default value = "x64"
  Possible values = "x64 | x32"
  Allow to install OpenSSH-Win64 or OpenSSH-Win32
  Used only for Windows 2008, 2012 and 2016 servers
.PARAMETER SetFirewallRule (switch)
  Default value = $False
  Allow to create SSH Firewall rule
.PARAMETER Force (switch)
  Default value = $False
  Allow to force OpenSSH configuration if OpenSSH is already installed
.PARAMETER Reboot (switch)
  Default value = $False
  Allow to restart computer automatically after OpenSSH server installation and configuration

.OUTPUTS
  Return code:
    0: execution is OK
    1: original 'sshd_config' cannot be backed
    2: customer 'sshd_config' has not been copied in '${Env:ProgramData}\ssh\'
    3: customer 'sshd_config' valid, please correct sshd_config content
    4: original 'sshd_config' cannot be reset with backuped 'sshd_config'
    5: customer 'sshd_config' does not exist in .\fic\
    6: '.\fic\' directory does not exist
    7: 'Add_Path_In_System_Path' function: Sorry -Path argument cannot be an empty string
    8: openSSH package sources directory does not exist
    9: '${Env:ProgramFiles}\OpenSSH\install-sshd.ps1' install script does not exist
   10: '${Env:ProgramFiles}\OpenSSH\FixHostFilePermissions.ps1' fix script does not exist
   11: Restart the 'sshd' service failed
   12: Set 'sshd' service in automatic mode failed
#>

Param (
  # [switch]$Agent = $False,  # Not used
  [string]$Customer = "",
  [string]$SourcesPath = "C:\Temp\WIN_InstallOpenSSH",
  [string]$Arch = "x64",
  [switch]$SetFirewallRule = $False,
  [switch]$Force = $False,
  [switch]$Reboot = $False
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

Function Add_Path_In_System_Path {
  Param (
    [string]$Path = ""
  )
  
  if ($Path -ne "") {
    # Add OpenSSH folder in Environment Path
    Custom_Write_Host -Msg "Add '${Path}' in Environment System Path ..."

    $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
    # Adding only if not already exists in system Path
    if ( $oldpath -notlike "*$Path*" ) {
      $newpath = "$oldpath;$Path;"
      Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath
      $newpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
      Custom_Write_Host -Msg "'${Path}' added in Environment System Path:"
      Custom_Write_Host -Msg $newpath -ForegroundColor Cyan
    } else {
      Custom_Write_Host -Msg "'${Path}' already exists in Environment System Path:"
      Custom_Write_Host -Msg $oldpath -ForegroundColor Cyan
    }
  } else {
    Custom_Write_Host -Msg "'Add_Path_In_System_Path' function: Sorry -Path argument cannot be an empty string" -ForegroundColor Red -DoubleCRLF
    Exit 7
  }
  Custom_Write_Host -Msg "Add '${Path}' in Environment System Path [OK]" -ForegroundColor Green -DoubleCRLF
}

$script_name = $MyInvocation.MyCommand.Name
Custom_Write_Host -Msg "${script_name} for OpenSSH Windows installation ..." -ForegroundColor Yellow -DoubleCRLF

Custom_Write_Host -Msg "Check if '${SourcesPath}' directory does exists ..." -ForegroundColor Yellow
if (-Not (Test-Path -Path "${SourcesPath}")) {
  Write-Error "ERROR - '${SourcesPath}' directory does not exist" -Category ObjectNotFound -CategoryReason "Please check -SourcesPath parameter"
  Exit 8
}
Custom_Write_Host -Msg "Check if '${SourcesPath}' directory does exists [OK]" -ForegroundColor Green -DoubleCRLF

cd $SourcesPath
$OpenSSH_AldreadyInstalled = $False

try {
  $OS = (Get-ComputerInfo).WindowsProductName
  Custom_Write_Host -Msg "OS = ${OS}" -ForegroundColor Cyan
} catch {
  Custom_Write_Host -Msg "Get-ComputerInfo Cmdlet not supported" -ForegroundColor Red -DoubleCRLF
  Custom_Write_Host -Msg "Force OpenSSH installation for Windows 2012" -ForegroundColor Red -DoubleCRLF
  # Force OpenSSH installation for Windows 2012
  $OS = "2012"
}

if ( $OS -like "*2019*" -Or $OS -like "*2022*" ) {
  Custom_Write_Host -Msg "OpenSSH installation for Windows >= 2019" -ForegroundColor Yellow -DoubleCRLF
  Custom_Write_Host -Msg "Get OpenSSH status" -ForegroundColor Cyan

  # Get sshd service status
  $openssh_services = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
  # Set OpenSSH installation path
  $OpenSSH_Install_Path = "${Env:SystemRoot}\System32\OpenSSH"

  foreach ($openssh_service in $openssh_services) {
    if ( $openssh_service.State -NotLike "Install*" ) {
      Custom_Write_Host -Msg "$($openssh_service.Name) $($openssh_service.State)" -ForegroundColor Green
      Custom_Write_Host -Msg "Add-WindowsCapability for $($openssh_service.Name)" -ForegroundColor Yellow -DoubleCRLF
      Add-WindowsCapability -Online -Name $($openssh_service.Name)
    } else {
      # OpenSSH.Server is already installed ?
	  if ( $openssh_service.Name -Like "OpenSSH.Server*" ) {
        # OpenSSH Server installed and running
        $OpenSSH_AldreadyInstalled = $True
        if ( -Not $Force ) {
          Custom_Write_Host -Msg "OpenSSH Server was already installed (use '-Force' parameter to force OpenSSH configuration)" -ForegroundColor Cyan
	    } else {
          Custom_Write_Host -Msg "OpenSSH Server was already installed but OpenSSH configuration will be forced bacause -Force switch parameter is set" -ForegroundColor Cyan
        }
      }
    }
	Custom_Write_Host -Msg "${openssh_service.Name} ${openssh_service.State}" -ForegroundColor Cyan -DoubleCRLF
  }

  # Adding OpenSSH path in system Path
  Add_Path_In_System_Path -Path "${OpenSSH_Install_Path}"

  # # Get OpenSSH status
  # Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

  # # Install the OpenSSH Client
  # Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

  # # Install the OpenSSH Server
  # Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

} else {

  # Get sshd service status
  $OpenSSH_Service = Get-Service -Name "sshd" -EA SilentlyContinue
  # Set OpenSSH installation path
  $OpenSSH_Install_Path = "${Env:ProgramFiles}\OpenSSH"
  
  # Does sshd service not exist ? (OpenSSH is not installed)
  if ($null -eq $OpenSSH_Service) {
  
    Custom_Write_Host -Msg "OpenSSH is not installed, installation in progress ..." -ForegroundColor Yellow -DoubleCRLF
    
    # Get OpenSSh architecture to install
    switch ($Arch.ToLower()) {
      "x32" {
        $OpenSSH_Package_Name = "OpenSSH-Win32";
        Custom_Write_Host -Msg "Architecture is 'x32', so 'OpenSSH-Win32' package will be used" -ForegroundColor Green -DoubleCRLF
        Break
      }
      "x64" {
        $OpenSSH_Package_Name = "OpenSSH-Win64";
        Custom_Write_Host -Msg "Architecture is 'x64', so 'OpenSSH-Win64' package will be used" -ForegroundColor Green -DoubleCRLF
        Break
      }
      Default {
        Custom_Write_Host -Msg "Architecture ${Arch} not supported. Only 'x32' and 'x64' are supported." -ForegroundColor Orange
        Custom_Write_Host -Msg "Architecture 'x64' by default, so 'OpenSSH-Win64' package will be used" -ForegroundColor Green -DoubleCRLF
        $OpenSSH_Package_Name = "OpenSSH-Win64"
      }
    }

    # OpenSSH installation
    Custom_Write_Host -Msg "Check if '${SourcesPath}\${OpenSSH_Package_Name}' sources directory does exists ..." -ForegroundColor Yellow
    if (-Not (Test-Path -Path "${SourcesPath}\${OpenSSH_Package_Name}")) {
      Write-Error "ERROR - '${SourcesPath}\${OpenSSH_Package_Name}' sources directory does not exist" -Category ObjectNotFound -CategoryReason "Please check -SourcesPath and -Arch parameters"
      Exit 8
    }
    Custom_Write_Host -Msg "Check if '${SourcesPath}\${OpenSSH_Package_Name}' sources directory does exists [OK]" -ForegroundColor Green -DoubleCRLF
    Copy-Item -Force -Recurse -LiteralPath "${SourcesPath}\${OpenSSH_Package_Name}" "${Env:ProgramFiles}\OpenSSH"
 
    Custom_Write_Host -Msg "Check if '${OpenSSH_Install_Path}\install-sshd.ps1' install script does exists ..." -ForegroundColor Yellow
    if (-Not (Test-Path -Path "${OpenSSH_Install_Path}\install-sshd.ps1" -PathType Leaf)) {
      Write-Error "ERROR - '${OpenSSH_Install_Path}\install-sshd.ps1' install script does not exist" -Category ObjectNotFound -CategoryReason "Please check -SourcesPath and -Arch parameters"
      Exit 9
    }
    Custom_Write_Host -Msg "Check if '${OpenSSH_Install_Path}\install-sshd.ps1' install script does exists [OK]" -ForegroundColor Green -DoubleCRLF
    Powershell.exe -ExecutionPolicy Bypass -File "${OpenSSH_Install_Path}\install-sshd.ps1"

  } else {

    $OpenSSH_AldreadyInstalled = $True
    Custom_Write_Host -Msg "OpenSSH is installed (use '-Force' parameter to force OpenSSH configuration)" -ForegroundColor Cyan
    Custom_Write_Host -Msg $sshd_service -DoubleCRLF

  }

  # Adding OpenSSH path in system Path
  Add_Path_In_System_Path -Path "${OpenSSH_Install_Path}"
}

# Restart sshd service for all Windows versions
Custom_Write_Host -Msg "Restart the 'sshd' service in automatic mode ..."
Restart-Service -Name "sshd"
if ($? -eq $True) {
  Custom_Write_Host -Msg "Restart the 'sshd' service [OK]" -ForegroundColor Green -DoubleCRLF
} else {
  Custom_Write_Host -Msg "Error: Restart the 'sshd' service failed" -ForegroundColor Red -DoubleCRLF
  Exit 11
}

# Set 'sshd' service in automatic mode
Custom_Write_Host -Msg "Set 'sshd' service in automatic mode ..."
# Set Automatic mode
Set-Service -Name "sshd" -StartupType "Automatic"
if ($? -eq $True) {
  Custom_Write_Host -Msg "Set 'sshd' service in automatic mode [OK]" -ForegroundColor Green -DoubleCRLF
} else {
  Custom_Write_Host -Msg "Error: Set 'sshd' service in automatic mode failed" -ForegroundColor Red -DoubleCRLF
  Exit 12
}

# No OpenSSH configuration by default   
$OpenSSH_ExecuteConfiguration = $False
# OpenSSH is not already install = Execute OpenSSH configuration
if (-Not $OpenSSH_AldreadyInstalled) {
  $OpenSSH_ExecuteConfiguration = $True
}
# OpenSSH is already install + Force paramter = Execute OpenSSH configuration
if ($OpenSSH_AldreadyInstalled -And $Force) {
  $OpenSSH_ExecuteConfiguration = $True
}

# BEGIN Execute OpenSSH configuration
if ($OpenSSH_ExecuteConfiguration) {

  # Set specific client sshd_config
  if ($Customer -ne "") {
    # Get current directory where sshd_config.$Customer are stored
    $CurrentDir = (Get-Location).Path
    $LowerClient = $Customer.ToLower()
    $Customer_sshd_config_path = "${SourcesPath}\fic"
    $Customer_sshd_config = "${Customer_sshd_config_path}\sshd_config.$LowerClient"
    
    # Does ${Customer_sshd_config_path} directory exist ?
    if (Test-Path -Path "${Customer_sshd_config_path}") {
    
      # Does sshd_config.$Customer file exist ?
      if (Test-Path -Path "${Customer_sshd_config}" -PathType Leaf) {
        # Copy specific client sshd_config.$Customer in '${Env:ProgramData}\ssh\'
        $Original_sshd_config = "${Env:ProgramData}\ssh\sshd_config"
        # Does sshd_config.$Customer file exist ?
        if (Test-Path -Path "${Original_sshd_config}" -PathType Leaf) {
          $Backup_sshd_config = "${Env:ProgramData}\ssh\sshd_config.backup"
          Copy-Item -LiteralPath "${Original_sshd_config}" -Dest "${Backup_sshd_config}" -Force -EA SilentlyContinue
          if ($? -ne $True) {
            # Warn user and exit with error
            Custom_Write_Host -Msg "Error: '${Original_sshd_config}' cannot be backed up" -ForegroundColor Red -DoubleCRLF
            Exit 1
          }
		}
        Custom_Write_Host -Msg "Copy '${Customer_sshd_config}' in '${Env:ProgramData}\ssh\' ..."
        Copy-Item -LiteralPath "${Customer_sshd_config}" -Dest "${Original_sshd_config}" -Force -EA SilentlyContinue
        # If copy failed
        if ($? -ne $True) {
          # Warn user and exit with error
          Custom_Write_Host -Msg "Error: '${Customer_sshd_config}' has not been copied in '${Env:ProgramData}\ssh\'" -ForegroundColor Red -DoubleCRLF
          Exit 2
        # Copy succeed
        } else {
          Custom_Write_Host -Msg "Copy '${Customer_sshd_config}' in '${Env:ProgramData}\ssh\' [OK]" -ForegroundColor Green -DoubleCRLF
          Custom_Write_Host -Msg "Check if '${Customer_sshd_config}' file is valid ..." -ForegroundColor Yellow
          . "${OpenSSH_Install_Path}\sshd.exe" -t
          # sshd_config file is not valid
          if ($? -ne $True) {
            # Warn user and exit with error
            Custom_Write_Host -Msg "Error: '${Customer_sshd_config}' is not valid, please correct sshd_config content" -ForegroundColor Red
            Custom_Write_Host -Msg "Reset backed '$Backup_sshd_config' to '${Customer_sshd_config}'"
            Copy-Item -LiteralPath "${Backup_sshd_config}" -Dest "${Original_sshd_config}" -Force -EA SilentlyContinue
            if ($? -ne $True) {
              # Warn user and exit with error
              Custom_Write_Host -Msg "Error: '${Original_sshd_config}' cannot be reset with '${Backup_sshd_config}'" -ForegroundColor Red -DoubleCRLF
              Exit 4
            }
            Write-Host
            Exit 3
          }
          Custom_Write_Host -Msg "Check if '${Customer_sshd_config}' file is valid [OK]" -ForegroundColor Green -DoubleCRLF
        }
      } else {
        Custom_Write_Host -Msg "'${Customer_sshd_config}' file does not exist in '${Customer_sshd_config_path}'" -ForegroundColor Red -DoubleCRLF
        Exit 5
      }
    } else {
      Custom_Write_Host -Msg "'${Customer_sshd_config_path}' directory does not exist" -ForegroundColor Red -DoubleCRLF
      Exit 6
    }
  }

  # BEGIN Fix host permissions on current OpenSSH installation
  if ( $OS -like "*2019*" -Or $OS -like "*2022*" ) {
    # For Windows 2019 or Windows 2022, using regular FixHostFilePermissions.ps1 present in 'OpenSSH-Win64' directory in $SourcesPath
    $OpenSSH_Install_Path = "${SourcesPath}\OpenSSH-Win64"
  } else {
    # For Windows 2008, 2012 or 2016, using regular FixHostFilePermissions.ps1
    $OpenSSH_Install_Path = "${Env:ProgramFiles}\OpenSSH"
  }
  Custom_Write_Host -Msg "Check if '${OpenSSH_Install_Path}\FixHostFilePermissions.ps1' fix script does exists ..." -ForegroundColor Yellow
  if (-Not (Test-Path -Path "${OpenSSH_Install_Path}\install-sshd.ps1" -PathType Leaf)) {
    Write-Error "ERROR - '${OpenSSH_Install_Path}\FixHostFilePermissions.ps1' fix script does not exist" -Category ObjectNotFound -CategoryReason "Please check -SourcesPath and -Arch parameters"
    Exit 10
  }
  Custom_Write_Host -Msg "Check if '${OpenSSH_Install_Path}\FixHostFilePermissions.ps1' fix script does exists [OK]" -ForegroundColor Green -DoubleCRLF
  cd ${OpenSSH_Install_Path}
  Powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$False'
  cd $SourcesPath
  # END Fix host permissions on current OpenSSH installation

  if ($SetFirewallRule) {
    $ssh_firewall_rule = Get-NetFirewallRule -Name "sshd" -EA SilentlyContinue
    if ( -Not $?) {
      # Configure Firewall SSH inbound rule 'sshd'
      Custom_Write_Host -Msg "Configure Firewall SSH inbound rule 'sshd'"
      New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
      Custom_Write_Host -Msg "Firewall SSH inbound rule for sshd already exist :"
      $ssh_firewall_rule | Format-Table | Out-String | Write-Host
    }
  }

  # Restart the 'sshd' service
  $Original_sshd_config = "${Env:ProgramData}\ssh\sshd_config"
  # Check sshd_config file is valid
  Custom_Write_Host -Msg "Check if '${Customer_sshd_config}' file is valid ..." -ForegroundColor Yellow
  . "${OpenSSH_Install_Path}\sshd.exe" -t
  # sshd_config file is not valid
  if ($? -ne $True) {
    # Warn user and exit with error
    Custom_Write_Host -Msg "Error: '${Original_sshd_config}' is not valid, please correct sshd_config content" -ForegroundColor Red -DoubleCRLF
    Exit 3
  }
  Custom_Write_Host -Msg "Check if '${Customer_sshd_config}' file is valid [OK]" -ForegroundColor Green -DoubleCRLF
  # Restart sshd
  Custom_Write_Host -Msg "Restart the 'sshd' service ..."
  Restart-Service -Name "sshd"
  if ($? -eq $True) {
    Custom_Write_Host -Msg "Restart the 'sshd' service [OK]" -ForegroundColor Green -DoubleCRLF
  } else {
    Custom_Write_Host -Msg "Error: Restart the 'sshd' service failed" -ForegroundColor Red -DoubleCRLF
    Exit 11
  }

  # # Not used
  # # OPTIONAL but recommended:
  # # Start the 'ssh-agent' service in automatic mode
  # if ($Agent) {
  #   Custom_Write_Host -Msg "Start the 'ssh-agent' service in automatic mode"
  #   Start-Sleep -Seconds 5
  #   Start-Service -Name "ssh-agent"
  #   Set-Service -Name "ssh-agent" -StartupType "Automatic"
  # }

  # Configure default shell to 'powershell.exe'
  $registryPath = "HKLM:\SOFTWARE\OpenSSH\"
  $Name = "DefaultShell"
  $value = "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe"

  if(!(Test-Path $registryPath)) {
    Custom_Write_Host -Msg "Configure default shell to 'powershell.exe' (With New-Item) ..."
    New-Item -Path $registryPath -Force
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force
    if ($? -eq $True) {
      Custom_Write_Host -Msg "Configure default shell to 'powershell.exe' (With New-Item) [OK]" -ForegroundColor Green -DoubleCRLF
    } else {
      Write-Host
    }
  } else {
    Custom_Write_Host -Msg "Configure default shell to 'powershell.exe' ..."
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force
    if ($? -eq $True) {
      Custom_Write_Host -Msg "Configure default shell to 'powershell.exe' [OK]" -ForegroundColor Green -DoubleCRLF
    } else {
      Write-Host
    }
  }

}
# END Execute OpenSSH configuration

# All is OK
Custom_Write_Host -Msg "${script_name} for OpenSSH Windows installation [OK]" -ForegroundColor Green -DoubleCRLF

# Windows 2019 and 2022 requires computer reboot
if ( $OS -like "*2019*" -Or $OS -like "*2022*" ) {
  if ($Reboot) {
    Custom_Write_Host -Msg "Automatic REBOOT in 30 seconds has been asked" -ForegroundColor Green
    Start-Sleep -Seconds 30
    Restart-Computer -Force
    Exit 0
  } else {
    Custom_Write_Host -Msg "Automatic REBOOT has not been asked" -ForegroundColor Green
    Exit 0
  }
}

Exit 0
