$Domain = Get-ADDomain
$DomainName = $Domain.DNSRoot
$DCName = $env:computername + '.' + $DomainName;
$MyCert=New-SelfSignedCertificate -DnsName $DCName,$DomainName -CertStoreLocation Cert:\LocalMachine\My
$PublicKeyFile = "C:\Temp\PublicKey.cer"
Export-Certificate -Cert $MyCert -FilePath $PublicKeyFile -Force
Import-Certificate -FilePath $PublicKeyFile -CertStoreLocation Cert:\LocalMachine\Root

