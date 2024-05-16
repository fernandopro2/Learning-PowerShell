Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Data Entry Form'
$form.Size = New-Object System.Drawing.Size(400,300)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,120)
$okButton.Size = New-Object System.Drawing.Size(75,23)
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

#$label = New-Object System.Windows.Forms.Label
#$label.Location = New-Object System.Drawing.Point(10,20)
#$label.Size = New-Object System.Drawing.Size(280,20)
#$label.Text = 'Please enter the information in the space below:'
#$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,40)
$textBox.Size = New-Object System.Drawing.Size(260,20)
$form.Controls.Add($textBox)

$form.Topmost = $true

$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $Cliente = $DropDownBox.SelectedItem
    & mstsc.exe /v:$Cliente
}