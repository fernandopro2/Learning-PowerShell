## Modufy this sections as needed
#import-module -name vmwre.powercli
connect-viserver "vl068333.hosting.gfi"

$VMs = @("TESTO-02","MAJMN-01","sully-078a","sully-078b","VM-073-P","VM-073-VAHINE")
# sully-074 is unreacheable through WMI

foreach($vmName in $VMs){
    ## modification below here not necessary to run  
    #$cred = if ($cred){$cred}else{Get-Credential}  
    #$win32DiskDrive  = Get-WmiObject -Class Win32_DiskDrive -ComputerName $vmName -Credential $credz
    $win32DiskDrive  = Import-Csv "C:\temp\CSV\$vmName-win32DiskDrive.csv"
    $vmHardDisks = Get-VM -Name $vmName | Get-HardDisk 
    $vmDatacenterView = Get-VM -Name $vmName | Get-Datacenter | Get-View 
    $virtualDiskManager = Get-View -Id VirtualDiskManager-virtualDiskManager 

    $diskToDriveVolume = Import-Csv "C:\temp\CSV\$vmName-diskToDriveVolume.csv"

    foreach ($disk in $win32DiskDrive)  {
        $disk | Add-Member -MemberType NoteProperty -Name AltSerialNumber -Value $null 
        $diskSerialNumber = $disk.SerialNumber  
        if ($disk.Model -notmatch 'VMware Virtual disk SCSI Disk Device')  {
            if ($diskSerialNumber -match '^\S{12}$'){
                $diskSerialNumber = ($diskSerialNumber | foreach {[byte[]]$bytes = $_.ToCharArray(); $bytes | foreach {$_.ToString('x2')} }  ) -join ''
            }  
            $disk.AltSerialNumber = $diskSerialNumber 
        }  
    }  

    $results = @()  
    foreach ($vmHardDisk in $vmHardDisks) {

        $vmHardDiskUuid = $virtualDiskManager.queryvirtualdiskuuid($vmHardDisk.Filename, $vmDatacenterView.MoRef) | foreach {$_.replace(' ','').replace('-','')}
        $vmHardDiskGeo = $virtualDiskManager.QueryVirtualDiskGeometry($vmHardDisk.Filename, $vmDatacenterView.MoRef) #| foreach {$_.replace(' ','').replace('-','')}    
        $windowsDisk = $win32DiskDrive | where {$_.TotalCylinders -eq $vmHardDiskGeo.Cylinder}  
        if (-not $windowsDisk){
            $windowsDisk = $win32DiskDrive | where { $_.AltSerialNumber -eq $vmHardDisk.ScsiCanonicalName.substring(12,24) }
        }  
        $result = "" | select vmName,vmHardDiskDatastore,vmHardDiskVmdk,vmHardDiskName,windowsDiskIndex,windowsCylinderInfo,vmwareCylinderInfo,windowsDeviceID,drives,volumes  
        $result.vmName = $vmName.toupper()  
        $result.vmHardDiskDatastore = $vmHardDisk.filename.split(']')[0].split('[')[1]  
        $result.vmHardDiskVmdk = $vmHardDisk.filename.split(']')[1].trim()  
        $result.vmHardDiskName = $vmHardDisk.Name  
        $result.windowsDiskIndex = if ($windowsDisk){$windowsDisk.Index}else{"FAILED TO MATCH"}  
        $result.windowsCylinderInfo = if ($windowsDisk.TotalCylinders){$windowsDisk.TotalCylinders}else{"FAILED TO MATCH"}  
        $result.vmwareCylinderInfo = $vmHardDiskGeo.Cylinder  
        $result.windowsDeviceID = if ($windowsDisk){$windowsDisk.DeviceID}else{"FAILED TO MATCH"}  
        $driveVolumes = $diskToDriveVolume | where {$_.Disk -eq $windowsDisk.DeviceID}
        $result.drives = $driveVolumes.DriveLetter
        $result.volumes = $driveVolumes.VolumeName
        $results += $result
    }
          
    $results = $results | sort {[int]$_.vmHardDiskName.split(' ')[2]}  
    $results | Export-Csv "C:\temp\CSV\$vmName.csv" -Force -NoTypeInformation
            
}