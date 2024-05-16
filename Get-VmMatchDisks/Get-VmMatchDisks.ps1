[CmdletBinding()]
param(
    [string]
    $VMName,
    [string]
    $VCenter
)

#connect-viserver "sw01s006.eu.seb.com"
#$VMs = @("SW04L947")
$VMs = $VMName
Connect-VIServer $VCenter

$CIMSessionOption = New-CimSessionOption -Protocol Dcom

foreach($vmName in $VMs){

    #Get the list of disks of a VMWare virtual machine
    $vmDisks = Get-VM -Name $vmName | Get-HardDisk 
    $vmDatacenterView = Get-VM -Name $vmName | Get-Datacenter | Get-View 
    $virtualDiskManager = Get-View -Id VirtualDiskManager-virtualDiskManager
    
    $CIMSession = $null
    $CIMSession = New-CimSession -ComputerName $vmName -SessionOption $CIMSessionOption -ErrorAction SilentlyContinue
    if($CIMSession){
        $winDisk  = Get-CimInstance -Class Win32_DiskDrive -CimSession $CIMSession -Property * 


        $diskToDriveVolume = $winDisk| ForEach-Object {
            $disk = $_
            $partitions = "ASSOCIATORS OF " +
                    "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                    "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
            Get-CimInstance -Query $partitions -CimSession $CIMSession| ForEach-Object {
                $partition = $_
                $drives = "ASSOCIATORS OF " +
                  "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
                  "WHERE AssocClass = Win32_LogicalDiskToPartition"
                Get-CimInstance -Query $drives -CimSession $CIMSession| ForEach-Object {
                    New-Object -Type PSCustomObject -Property @{
                        Disk        = $disk.DeviceID
                        DriveLetter = $_.DeviceID
                        VolumeName  = $_.VolumeName
                   }
                }
            }
        }

        $CIMSession | Remove-CimSession

        #Getting a disk serial number 
        foreach ($disk in $winDisk)  {
            $disk | Add-Member -MemberType NoteProperty -Name AltSerialNumber -Value $null 
            $diskSerialNumber = $disk.SerialNumber  
            if ($disk.Model -notmatch 'VMware Virtual disk SCSI Disk Device')  {  
                if ($diskSerialNumber -match '^\S{12}$'){
                    $diskSerialNumber = ($diskSerialNumber | foreach {
                        [byte[]]$bytes = $_.ToCharArray(); $bytes | foreach {$_.ToString('x2')} 
                    }  ) -join ''
                }  
                $disk.AltSerialNumber = $diskSerialNumber 
            }  
        }  
        #Searching all VM disks and matching them with Windows disks by their SerialNumber / UUID
        $diskMaps = @()  
        foreach ($vmDisk in $vmDisks)  {
            $vmDiskUuid = $virtualDiskManager.queryvirtualdiskuuid($vmDisk.Filename, $vmDatacenterView.MoRef) | foreach {$_.replace(' ','').replace('-','')}  
            $windowsDisk = $winDisk | where {$_.SerialNumber -eq $vmDiskUuid}  
            if (-not $windowsDisk){$windowsDisk = $winDisk | where {$_.AltSerialNumber -eq $vmDisk.ScsiCanonicalName.substring(12,24)}}  
            $curDiskMap = "" | select  vmDiskDatastore, vmDiskVmdk, vmDiskName, windowsDiskIndex,  vmDiskUuid, windowsDeviceID, drives, volumes  
            $curDiskMap.vmDiskDatastore = $vmDisk.filename.split(']')[0].split('[')[1]  
            $curDiskMap.vmDiskVmdk = $vmDisk.filename.split(']')[1].trim()  
            $curDiskMap.vmDiskName = $vmDisk.Name  
            $curDiskMap.windowsDiskIndex = if ($windowsDisk){$windowsDisk.Index}else{"FAILED TO MATCH"}  
            $curDiskMap.vmDiskUuid = $vmDiskUuid  
            $curDiskMap.windowsDeviceID = if ($windowsDisk){$windowsDisk.DeviceID}else{"FAILED TO MATCH"}  
            $driveVolumes = $diskToDriveVolume | where {$_.Disk -eq $windowsDisk.DeviceID}
            $curDiskMap.drives = $driveVolumes.DriveLetter
            $curDiskMap.volumes = $driveVolumes.VolumeName
            $diskMaps += $curDiskMap
        }  
        $diskMaps = $diskMaps | sort {[int]$_.vmDiskName.split(' ')[2]}  
        $diskMaps | ft
    }
    else{
        Write-Warning "It was no possible to establish a CIM session with $VMName"
    }
            
}
