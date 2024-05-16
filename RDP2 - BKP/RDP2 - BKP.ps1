Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'RDP'
$form.Size = New-Object System.Drawing.Size(400,300)
$form.StartPosition = 'CenterScreen'


$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(160,150)
$okButton.Size = New-Object System.Drawing.Size(80,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$PatchClients = "C:\Scripts\RDP\CLIENTES.txt"

$DropDownBox = New-Object System.Windows.Forms.ComboBox
    $DropDownBox.Location = New-Object System.Drawing.Size(20,75) 
    $DropDownBox.Size = New-Object System.Drawing.Size(350,30) 
    $DropDownBox.Font = New-Object System.Drawing.Font("ARIAL",12)
    $DropDownBox.DropDownHeight = 200       

    $ClientsList = Get-content $PatchClients

    foreach ($Clients in $ClientsList) {
        $DropDownBox.Items.Add($Clients)
    }
$form.Controls.Add($DropDownBox)


#$cancelButton = New-Object System.Windows.Forms.Button
#$cancelButton.Location = New-Object System.Drawing.Point(150,120)
#$cancelButton.Size = New-Object System.Drawing.Size(75,23)
#$cancelButton.Text = 'Cancel'
#$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
#$form.CancelButton = $cancelButton
#$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(250,20)
$label.Text = 'Domínio:'
$form.Controls.Add($label)

$form.Topmost = $true

#$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()


function Build-Connection {

    param(
        $Cliente
    )

    switch ($Cliente){
        
        'GROUPE' {
            $Usuario = "GROUPE\fernando.dossantos"
            $Senha = Get-Content "C:\Scripts\RDP\GROUPE.txt" | ConvertTo-SecureString
            $Servidor = "wabprdm.gfi.network"
        }
        'BDOC' {
            $Usuario = "BDOC-SAAS\fsantos-adm"
            $Senha = Get-Content "C:\Scripts\RDP\BDOC-SAAS.txt" | ConvertTo-SecureString
            $Servidor = "wabprdm.gfi.network"
        }
        'CLOUDEP' {
            $Usuario = "CLOUDEP\ADM_fsantos"
            $Senha = Get-Content "C:\Scripts\RDP\CLOUDEP.txt" | ConvertTo-SecureString
            $Servidor = "wabprdm.gfi.network"
        }
    }

    # Create credentials
    #cmdkey /generic:$Servidor /user:$Usuario /pass:$Senha
    New-StoredCredential -Target $Servidor -UserName $Usuario -SecurePassword $Senha | Out-Null
    # Connect MSTSC with servername and credentials created before
    & mstsc /v:$Servidor
    # Delete the credentials after MSTSC session is done
    #cmdkey /delete:$Servidor

}



if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    Build-Connection -Cliente $DropDownBox.SelectedItem
}