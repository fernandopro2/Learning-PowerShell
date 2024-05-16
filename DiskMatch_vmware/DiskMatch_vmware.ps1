## Modufy this sections as needed
#import-module -name vmwre.powercli
connect-viserver VCENTER
$vmName = "nome da vm"
## modification below here not necessary to run  
$cred = if ($cred){$cred}else{Get-Credential}  
$win32DiskDrive  = Get-WmiObject -Class Win32_DiskDrive -ComputerName $vmName -Credential $cred
$vmHardDisks = Get-VM -Name $vmName | Get-HardDisk 
$vmDatacenterView = Get-VM -Name $vmName | Get-Datacenter | Get-View 
$virtualDiskManager = Get-View -Id VirtualDiskManager-virtualDiskManager 

"Get-WmiObject"
$diskToDriveVolume = Get-WmiObject Win32_DiskDrive -ComputerName $vmName -Credential $cred| % {
  $disk = $_
  $partitions = "ASSOCIATORS OF " +
                "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
  Get-WmiObject -Query $partitions -ComputerName $vmName -Credential $cred| % {
    $partition = $_
    $drives = "ASSOCIATORS OF " +
              "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
              "WHERE AssocClass = Win32_LogicalDiskToPartition"
    Get-WmiObject -Query $drives  -ComputerName $vmName -Credential $cred| % {
      New-Object -Type PSCustomObject -Property @{
        Disk        = $disk.DeviceID
        DriveLetter = $_.DeviceID
        VolumeName  = $_.VolumeName
 
      }
    }
  }
}

"foreach"
foreach ($disk in $win32DiskDrive)  
{  
  $disk | Add-Member -MemberType NoteProperty -Name AltSerialNumber -Value $null 
  $diskSerialNumber = $disk.SerialNumber  
  if ($disk.Model -notmatch 'VMware Virtual disk SCSI Disk Device')  
  {  
    if ($diskSerialNumber -match '^\S{12}$'){$diskSerialNumber = ($diskSerialNumber | foreach {[byte[]]$bytes = $_.ToCharArray(); $bytes | foreach {$_.ToString('x2')} }  ) -join ''}  
    $disk.AltSerialNumber = $diskSerialNumber 
  }  
}  

"foreach2"
$results = @()  
foreach ($vmHardDisk in $vmHardDisks)  
{  
 
  $vmHardDiskUuid = $virtualDiskManager.queryvirtualdiskuuid($vmHardDisk.Filename, $vmDatacenterView.MoRef) | foreach {$_.replace(' ','').replace('-','')}  
  $windowsDisk = $win32DiskDrive | where {$_.SerialNumber -eq $vmHardDiskUuid}  
  if (-not $windowsDisk){$windowsDisk = $win32DiskDrive | where {$_.AltSerialNumber -eq $vmHardDisk.ScsiCanonicalName.substring(12,24)}}  
  $result = "" | select vmName,vmHardDiskDatastore,vmHardDiskVmdk,vmHardDiskName,windowsDiskIndex,windowsDiskSerialNumber,vmHardDiskUuid,windowsDeviceID,drives,volumes  
  $result.vmName = $vmName.toupper()  
  $result.vmHardDiskDatastore = $vmHardDisk.filename.split(']')[0].split('[')[1]  
  $result.vmHardDiskVmdk = $vmHardDisk.filename.split(']')[1].trim()  
  $result.vmHardDiskName = $vmHardDisk.Name  
  $result.windowsDiskIndex = if ($windowsDisk){$windowsDisk.Index}else{"FAILED TO MATCH"}  
  $result.windowsDiskSerialNumber = if ($windowsDisk){$windowsDisk.SerialNumber}else{"FAILED TO MATCH"}  
  $result.vmHardDiskUuid = $vmHardDiskUuid  
  $result.windowsDeviceID = if ($windowsDisk){$windowsDisk.DeviceID}else{"FAILED TO MATCH"}  
  $driveVolumes = $diskToDriveVolume | where {$_.Disk -eq $windowsDisk.DeviceID}
  $result.drives = $driveVolumes.DriveLetter
  $result.volumes = $driveVolumes.VolumeName
  $results += $result
}  
$results = $results | sort {[int]$_.vmHardDiskName.split(' ')[2]}  
$results | ft -AutoSize 