Set-ExecutionPolicy -ExecutionPolicy Bypass
Copy-Item -Path "\\SRV01\C$\OpenSSH-Win64\*" -Destination "C:\OpenSSH-Win64\" -Recurse
Set-Location C:\OpenSSH-Win64
.\install-sshd.ps1
## changes the sshd service's startup type from manual to automatic.
Set-Service sshd -StartupType Automatic
## starts the sshd service.
if(Test-Path "C:\ProgramData\ssh\sshd_config"){
    Copy-Item "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.ORIGINAL"
    $CustomFileContent = Get-Content "\\SRV01\C$\OpenSSH-Win64\sshd_config.linedata"
    $CustomFileContent | Set-Content "C:\ProgramData\ssh\sshd_config" -Force -Verbose
    Start-Service sshd -Verbose
}
