Param(
[string]$Domain = $env:USERDNSDOMAIN,
[PSCredential]$cred,
[string]$searchbase = "OU=Support,OU=Utilisateurs,DC=cloudep,DC=local",
[string]$AttribSearchLabel = "EmailAddress",                                     ##Value can be info (Phone/Notes) or email
[string]$AttribSearchContent = "*@inetum.com",
[string]$UserSearchString = "*",                                     ##Same script might be used for svc account if needed by replacing this string
[int]$PasswordExpirationThreshold = 14,                                  ##This threshold can't be higher than MaxPassswordAge
[string]$Subject = "[CLOUDEP] - Password Expiration Notification",       ##Value between [] has to be change with customer name
[string]$From = "noreply@inetum.com",                          ##Noreply or hostmaster address of customer SMTP
[string]$EmailServerAddress = "mail.cloudep.local",       ##Usable SMTP gateway
[string]$FailoverEmail = "WES-IS-IT-WINDOWS@gfi.fr",                     ##If no email address is found in some users mail will be sent to this address (might be CSP/SDM or WES-IS-IT-WINDOWS@gfi.fr)
[string]$LogFilePath = 'D:\Scripts\AD\ADMIN\InetumAccountExpirations.log',           ##Log file full path (append mode)
[string]$SpecPasswordPolicy = "",          ##Most of the time administrators will all have the same PSO - next gen of this script should be able to dynamically for each account (in place in zabbix svc account monitoring)
[int]$MaxPasswordAge = 60,                                               ##Value on this line is used in case no SpecPasswordPolicy is not defined - minimum value if not defined in customer context is this defined in "Inetum Admin account charte"
[int]$MinPasswordAge = 10,                                                ##Value on this line is used in case no SpecPasswordPolicy is not defined - minimum value if not defined in customer context is this defined in "Inetum Admin account charte"
[int]$MinPasswordLength = 32,                                            ##Value on this line is used in case no SpecPasswordPolicy is not defined - minimum value if not defined in customer context is this defined in "Inetum Admin account charte"
[int]$PasswordHistoryCount = 5,                                          ##Value on this line is used in case no SpecPasswordPolicy is not defined - minimum value if not defined in customer context is this defined in "Inetum Admin account charte"
$SpecPasswordPolicyArray = @(),                                          ##Value on this line is used in case no SpecPasswordPolicy is not defined - minimum value if not defined in customer context is this defined in "Inetum Admin account charte"
$DefaultDomainPasswordPolicyArray = @()
)

begin {

#region funtion log file management    
    function Write-Log($Message) {
        $MyDateTime = Get-Date -Format 'MM-dd-yyyy H:mm:ss'
        Add-Content -Path $LogFilePath -Value "$MyDateTime - $Message"
    }
#endregion function   
try {
#region thresholds definition - Spec PSO content retrieving or by default DefaultDomainPawwsordPolicy content or by default local script thresholds
        if ($SpecPasswordPolicy) {
            $SpecPasswordPolicyArray = Get-ADFineGrainedPasswordPolicy -Identity $SpecPasswordPolicy -Server $Domain
            [int]$MaxPasswordAge = $($SpecPasswordPolicyArray).MaxPasswordAge.Days
            $Rule=$($SpecPasswordPolicy)
            write-host "Max PWD Spec $($MaxPasswordAge) $($Rule)"
            } 
        elseif ($(Get-ADDefaultDomainPasswordPolicy -Server $Domain).MaxPasswordAge.Days -ne 0) {
            $DefaultDomainPasswordPolicyArray = Get-ADDefaultDomainPasswordPolicy -Server $Domain 
            [int]$MaxPasswordAge = $($DefaultDomainPasswordPolicyArray).MaxPasswordAge.Days;$Rule='DefaultDomainPasswordPolicy'
            write-host "Max PWD Spec $($MaxPasswordAge) $($Rule)"
            }
        else {
            [int]$MaxPasswordAge = $MaxPasswordAge,$Rule='Script_Default' 
            write-host "Max PWD Spec $($MaxPasswordAge) $($Rule)"
        }
        
        Write-Log -Message "The max password age issued from $Rule domain is $MaxPasswordAge"
        Write-Host "The max password age issued from $Rule domain is $MaxPasswordAge"
#endregion thresholds definition
        
#region test if expiration threshold is greater than max password age
        if ($PasswordExpirationThreshold -gt $MaxPasswordAge) {
            throw "The value '$PasswordExpirationThreshold' specified as the password expiration threshold is greater than the max password age for the domain"
        }
#endregion test

#region Email Template content and html format definition
        [string]$EmailTemplate = @'
        <html> <body> <font SIZE="6" COLOR="#ff0000"> 
        <p ALIGN="CENTER" style='font-size:20.0pt;font-family:"Times New Roman";color:#CC0000;mso-bidi-font-weight: bold'>Password Expiration Notice from Inetum GBLOS</p></font>
        <font style='font-size:12.0pt;font-family:"Times New Roman";color:#1C1C1C;mso-bidi-font-weight:bold'>
        <p>Dear <strong>$FirstName $LastName,</strong><br>
        <br>
        Your password in <strong> $domain </strong> domain will expire in <strong>$DaysBeforeExpiration</strong> days.<br>
        <br>
        Please change it as soon as possible to make sure your account will not expire.<br>
        <br/> </p>
        <p>To change your password press <strong>CTRL+ALT+DEL</strong> or <strong>CTRL+ALT+END</strong> in remote session <br>
        &nbsp;&nbsp;or use <strong>Security shortcut</strong> on Desktop when available<br>
        and select <strong>"Change Password"</strong>. <br>
		Process : <a HREF="https://delivery.inetum.com/confluence/display/BUSCE/CLOUDEP+-+Password+Change">https://delivery.inetum.com/confluence/display/BUSCE/CLOUDEP+-+Password+Change</a>
        
        <br><br></p> 
        <p>Please review the guidelines below as they are necessary for successfully updating your password.<br>
        <br>
        &nbsp;&nbsp; <strong>PASSWORD MUST : </strong><br></p>
        <p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;     => Be at least <strong>$MinPasswordLength</strong> total characters and contains characters from three of the following categories :<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - Lowercase letters with diacritic marks<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - Uppercase letters with diacritic marks<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - Base 10 digits (0 through 9)<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - Non-alphanumeric characters (special characters): (~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/) Currency symbols such as the Euro or British Pound aren't counted as special characters for this policy setting<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - Any Unicode character that's categorized as an alphabetic character but isn't uppercase or lowercase.<br>
        <br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;     => Not be the same or similar to the last <strong>$PasswordHistoryCount</strong> used passwords<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;     => Be used for at least <strong>$MinPasswordAge</strong> days before changing again<br> </dir> 
        <br>
        If you enter an incorrect password 3 or more times, your account will be locked and you will need to contact the Service Desk for assistance.</p> </font>
        <br>
        <br>
        <font SIZE="4" style='font-size:13.0pt;font-family:"Times New Roman";color:#CC0000'> <p ALIGN="CENTER">*** Please do not respond to this e-mail. 
        <BR>Direct any questions or concerns regarding this issue to the IT Service Desk. 
        <BR> For information on how to contact the Service Desk, please visit </font> 
        <a HREF=> <font SIZE="4" COLOR="#0000ff"><u></u></font> </dir> </font></b> </body> 
		<font SIZE="4" >Send from server $($env:computername)</font>
        </html>
'@
#endregion Email Template

    }
    catch {
#region Error catch and exit - Begin
        Write-Log -Message $_.Exception.Message
        exit
    }
#endregion Error catch - Begin
}

process {
    $Users = Get-ADUser -filter {Enabled -eq $True} -SearchBase $searchbase -Properties * | Select-Object -Property SamAccountName,GivenName,passwordlastset,mail,Surname,@{Name="ExpirationDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | Sort-Object "ExpirationDate" 
    Write-Log -Message "Found '$($Users.Count)' total expirable AD user accounts"
    Write-Host "Found '$($Users.Count)' total expirable AD user accounts"


foreach ($User in $users) {
    if ($User.ExpirationDate -le (Get-Date).AddDays($PasswordExpirationThreshold)) {
            $UserPwdExpireDate = $User.PasswordLastSet.AddDays($MaxPasswordAge)
            $DaysUntilExpire = ($UserPwdExpireDate - (get-date)).Days
            $FirstName = $User.GivenName
            $LastName = $User.Surname
 
        Write-Log -Message "$LastName $FirstName Days Until Expire :$DaysUntilExpire $UserPwdExpireDate"

##treatment of soon expiring accounts
            if (($DaysUntilExpire -le $PasswordExpirationThreshold) -and ($DaysUntilExpire -le 0)) {
                Write-Log -Message "The user $($User.samAccountName)'s password will expire in $DaysUntilExpire days"
                Write-Host "The user $($User.samAccountName)'s password will expire in $DaysUntilExpire days"

#region adjusting mail content
                if ($SpecPasswordPolicy) {
                    $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$domain', $Domain).Replace('$MinPasswordLength', $SpecPasswordPolicyArray.MinPasswordLength).Replace('$PasswordHistoryCount', $SpecPasswordPolicyArray.PasswordHistoryCount).Replace('$MinPasswordAge', $SpecPasswordPolicyArray.MinPasswordAge.Days).Replace('will expire in <strong>$DaysBeforeExpiration</strong> days', '<strong>is expired</strong>')
                    Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High
                    Write-Log "A Send Mail Info $FirstName $LastName to at adress $($User.mail)"
                }
                elseif ($DefaultDomainPasswordPolicyArray.MinPasswordLength) {
                    $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$domain', $Domain).Replace('$MinPasswordLength', $DefaultDomainPasswordPolicyArray.MinPasswordLength).Replace('$PasswordHistoryCount', $DefaultDomainPasswordPolicyArray.PasswordHistoryCount).Replace('$MinPasswordAge', $SpecPasswordPolicyArray.MinPasswordAge.Days).Replace('will expire in <strong>$DaysBeforeExpiration</strong> days', '<strong>is expired</strong>')
					Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High
                    Write-Log "B Send Mail Info $FirstName $LastName to at adress $($User.mail) $DaysUntilExpire $UserPwdExpireDate "
                   }
                else {
                    $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$domain', $Domain).Replace('$MinPasswordLength', $MinPasswordLength).Replace('$PasswordHistoryCount', $PasswordHistoryCount).Replace('$MinPasswordAge', $MinPasswordAge).Replace('will expire in <strong>$DaysBeforeExpiration</strong> days', '<strong>is expired</strong>')
                    Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High
                    Write-Log "C Send Mail Info $FirstName $LastName to at adress $($User.mail)"
				}
			}
			
            if (($DaysUntilExpire -le $PasswordExpirationThreshold) -and ($DaysUntilExpire -ge 0)) {
                if ($SpecPasswordPolicy) {
                    $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$DaysBeforeExpiration', $DaysUntilExpire).Replace('$domain', $Domain).Replace('$MinPasswordLength', $SpecPasswordPolicyArray.MinPasswordLength).Replace('$PasswordHistoryCount', $SpecPasswordPolicyArray.PasswordHistoryCount).Replace('$MinPasswordAge', $SpecPasswordPolicyArray.MinPasswordAge.Days)
                    Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High
                    Write-Log "D Send Mail Info $FirstName $LastName to at adress $($User.mail)"
                }
                elseif ($DefaultDomainPasswordPolicyArray.MinPasswordLength) {
                   $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$DaysBeforeExpiration', $DaysUntilExpire).Replace('$domain', $Domain).Replace('$MinPasswordLength', $DefaultDomainPasswordPolicyArray.MinPasswordLength).Replace('$PasswordHistoryCount', $DefaultDomainPasswordPolicyArray.PasswordHistoryCount).Replace('$MinPasswordAge', $SpecPasswordPolicyArray.MinPasswordAge.Days)
                   Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High
                   Write-Log "E Send Mail Info $FirstName $LastName to at adress $($User.mail)"
                   }
                else {
                    $EmailBody = $EmailTemplate.Replace('$FirstName', $FirstName).Replace('$LastName', $LastName).Replace('$DaysBeforeExpiration', $DaysUntilExpire).Replace('$domain', $Domain).Replace('$MinPasswordLength', $MinPasswordLength).Replace('$PasswordHistoryCount', $PasswordHistoryCount).Replace('$MinPasswordAge', $MinPasswordAge)
                    Send-MailMessage -To $user.mail -From $From -Subject $Subject -BodyAsHtml $EmailBody -SmtpServer $EmailServerAddress -Priority High 
                    Write-Log "F Send Mail Info $FirstName $LastName to at adress $($User.mail)"
                }
            }
            
#endregion mail content

#region adjusting mail recipient and send mail

                
					
            
        }
    }
}

