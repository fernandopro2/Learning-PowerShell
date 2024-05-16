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

$PathClients = "C:\Scripts\RDP\CLIENTES.txt"

$DropDownBox = New-Object System.Windows.Forms.ComboBox
    $DropDownBox.Location = New-Object System.Drawing.Size(20,75) 
    $DropDownBox.Size = New-Object System.Drawing.Size(350,30) 
    $DropDownBox.Font = New-Object System.Drawing.Font("ARIAL",12)
    $DropDownBox.DropDownHeight = 200       

    $Global:ClientsList = Import-Csv $PathClients

    foreach ($Clients in $ClientsList.DOM) {
        $DropDownBox.Items.Add($Clients)
    }
$form.Controls.Add($DropDownBox)

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

    $LineCred = Import-Csv $PathClients | Where-Object DOM -eq $Cliente

    $Usuario = $LineCred.USR
    $Senha = Get-Content $LineCred.PWFILE | ConvertTo-SecureString
    $Servidor = "wabprdm.gfi.network"

    # Create credentials
    New-StoredCredential -Target $Servidor -UserName $Usuario -SecurePassword $Senha | Out-Null
    # Connect MSTSC with servername and credentials created before
    & mstsc /v:$Servidor

}



if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    Build-Connection -Cliente $DropDownBox.SelectedItem
}