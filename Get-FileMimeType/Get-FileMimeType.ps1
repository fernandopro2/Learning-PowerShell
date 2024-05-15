<#
.Synopsis
    Check the file MIME type.
.DESCRIPTION
    The script identifies the MIME type of the files and can therefore be used to support the configuration of antispam/antimalware rules.
.EXAMPLE
   .\Get-FileMimeType.ps1 -Path C:\Temp
.EXAMPLE
   .\Get-FileMimeType.ps1 -Path C:\Temp\file1
.EXAMPLE
   C:\Temp\file1 | .\Get-FileMimeType.ps1

#>


param(
    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)] 
    $Path,
    [switch]$Recurse
)

BEGIN{
    Add-Type -AssemblyName "System.Web"
}
PROCESS{
    try{
        Test-Path $Path
        $ValidPath = $true
    }
    catch {
        $_.Exception.Message
        $ValidPath = $false
    }

    if($ValidPath){
        $Params = @{
            Path = $Path
            File = $true
            Recurse = $Recurse
        }
        Get-ChildItem @Params | ForEach-Object { 
            $Props =  [ordered]@{
                FilePath = $_.DirectoryName
                FileName = $_.Name
                MimeType = [System.Web.MimeMapping]::GetMimeMapping($_.FullName)
            }
            New-Object -TypeName psobject -Property $Props
        }
    }       
}
END{
    #END
}