<#
.Synopsis
   Find out which disk in vwmare corresponds to the disk drive in Windows.
.DESCRIPTION
	The script compares logical and physical information from the disks and tries to draw an equivalence. 

	Ideally, it compares the SerialNumber attribute of the Win32_DiskDrive class, but it is very common for this attribute to be empty.  Because of this, we compared physical attributes and the device ID in Windows. 

	You need to establish a CIM session to obtain the information. 

	You must have the PowerCLI module installed.

	The VM name entered must match the VM name in the virtualizer. 
	
.EXAMPLE
   Get-CorrespondentDisk.ps1 -VCenter vcenter.lab.local -VMName "VM01",VM02"

#>


[CmdletBinding()]
param(
    [string[]]
    $VMName,
    [string]
    $VCenter
)

$VMs = $VMName
Connect-VIServer $VCenter

$CIMSessionOption = New-CimSessionOption -Protocol Dcom

foreach($vmName in $VMs){

    #Get the list of disks of a VMWare virtual machine
    $vmDisks = Get-VM -Name "*$vmName*" | Get-HardDisk 
    $vmDatacenterView = Get-VM -Name "*$vmName*" | Get-Datacenter | Get-View 
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
            $vmHardDiskGeo = $virtualDiskManager.QueryVirtualDiskGeometry($vmDisk.Filename, $vmDatacenterView.MoRef) #| foreach {$_.replace(' ','').replace('-','')}

            $Matches = $null
            if($vmDisk.ExtensionData.DiskObjectId -match ".+(\d)"){
                $DiskObjectId = $Matches[1]
            }
            if($DiskObjectId){
                $windowsDisk = $winDisk | where {$_.TotalCylinders -eq $vmHardDiskGeo.Cylinder -and $_.Index -eq $DiskObjectId}           
            }
              
            if ($windowsDisk){
                
                $windowsDiskIndex = $windowsDisk.Index
                if($windowsDisk.TotalCylinders){
                    $windowsCylinderInfo = $windowsDisk.TotalCylinders
                 }
                 else{
                    $windowsCylinderInfo = "FAILED TO MATCH"
                 }
                 if($windowsDisk.DeviceID){
                    $windowsDeviceID = $windowsDisk.DeviceID
                 }
                 else{
                    "FAILED TO MATCH"
                 }
                $driveVolumes = $diskToDriveVolume | where {$_.Disk -eq $windowsDeviceID}
                $drives = $driveVolumes.DriveLetter
                $volumes = $driveVolumes.VolumeName

                    
            }
            else{
                $windowsDiskIndex = "FAILED TO MATCH"
            }

            $Props = [ordered]@{
                VMname = $VMName
                vmDiskUuid = $vmDiskUuid
                vmHardDiskDatastore = $vmDisk.filename.split(']')[0].split('[')[1]
                vmHardDiskVmdk = $vmDisk.filename.split(']')[1].trim()
                vmHardDiskName = $vmDisk.Name
                windowsDiskIndex = $windowsDiskIndex
                windowsCylinderInfo = $windowsCylinderInfo
                vmwareCylinderInfo = $vmHardDiskGeo.Cylinder
                windowsDeviceID = $windowsDeviceID
                drives = $drives
                volumes = $volumes

            }
            $diskMaps += New-Object -TypeName psobject -Property $Props
        }  
        $diskMaps | Sort-Object -Property Drives | ft
    }
    else{
        Write-Warning "It was no possible to establish a CIM session with $VMName"
    }
            
}

