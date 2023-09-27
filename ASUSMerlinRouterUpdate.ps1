Add-Type -AssemblyName System.Windows.Forms

# Show Windows Toast Notification Function
function Show-Notification {
    [cmdletbinding()]
    Param (
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline)]
        $ToastText
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)

    $RawXml = [xml] $Template.GetXml()
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) > $null

    $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $SerializedXml.LoadXml($RawXml.OuterXml)

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
    $Toast.Tag = "ASUS Router Script"
    $Toast.Group = "ASUS Router Script"

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Merlin Auto Update Script")
    $Notifier.Show($Toast);
}

# Ensure the script is run with elevated privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Show-Notification "Please run script as Admin."
    Break
}

# Define the registry paths and values
$registryPaths = @(
    @{
        Path  = 'HKCU:\Software\Microsoft\Internet Explorer\Main'
        Name  = 'DisableFirstRunCustomize'
        Value = 1
        Type  = 'DWord'
    },
    @{
        Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
        Name  = 'DisableFirstRunCustomize'
        Value = 1
        Type  = 'DWord'
    }
)

# Loop through each registry path and modify or create the key as needed
foreach ($registry in $registryPaths) {
    # Check if the registry path exists
    if (Test-Path -Path $registry.Path) {
        # Check if the registry key exists
        if (Get-ItemProperty -Path $registry.Path -Name $registry.Name -ErrorAction SilentlyContinue) {
            # Get the current value of the registry key
            $currentValue = Get-ItemPropertyValue -Path $registry.Path -Name $registry.Name -ErrorAction SilentlyContinue
            
            # Check if the current value is different from the desired value
            if ($currentValue -ne $registry.Value) {
                # Modify the registry key with the correct value
                Set-ItemProperty -Path $registry.Path -Name $registry.Name -Value $registry.Value -Type $registry.Type -Force
                Write-Host "Modified $($registry.Path)\$($registry.Name) to $($registry.Value)"
            } else {
                Write-Host "$($registry.Path)\$($registry.Name) is already set to $($registry.Value)"
            }
        } else {
            # Create the registry key with the correct value if it does not exist
            New-ItemProperty -Path $registry.Path -Name $registry.Name -Value $registry.Value -PropertyType $registry.Type -Force
            Write-Host "Created $($registry.Path)\$($registry.Name) with value $($registry.Value)"
        }
    } else {
        # Create the registry path and key with the correct value if the path does not exist
        New-Item -Path $registry.Path -Force
        New-ItemProperty -Path $registry.Path -Name $registry.Name -Value $registry.Value -PropertyType $registry.Type -Force
        Write-Host "Created $($registry.Path)\$($registry.Name) with value $($registry.Value)"
    }
}

Write-Host "Registry check and modifications have been completed."

# Check if WinSCP is installed
$winscpInstalled = (Test-Path "C:\Program Files (x86)\WinSCP\WinSCP.exe") -or (Test-Path "C:\Program Files\WinSCP\WinSCP.exe")

# Check if PuTTY is installed
$puttyInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "PuTTY*"}

# Set URLs for the installers
$winscpURL = "https://files1.majorgeeks.com/10afebdbffcd4742c81a3cb0f6ce4092156b4375/internet/WinSCP-6.1.2-Setup.exe" # Please verify the URL is still valid
$puttyURL = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.79-installer.msi" # Updated URL

# Set download paths
$winscpPath = "$env:TEMP\WinSCP-Setup.exe"
$puttyPath = "$env:TEMP\putty-installer.msi"

# Download and Install WinSCP if not installed
if (-not $winscpInstalled) {
    try {
        Invoke-WebRequest -Uri $winscpURL -OutFile $winscpPath
        Start-Process -Wait -FilePath $winscpPath -ArgumentList "/silent /ALLUSERS"
        Write-Output "Installation of WinSCP completed!" # Corrected message
    } catch {
        Write-Error "Failed to download or install WinSCP. Please check the URL and try again."
        exit
    } finally {
        if (Test-Path $winscpPath) { Remove-Item -Path $winscpPath }
    }
} else {
    Write-Output "WinSCP is already installed!"
}


# Download and Install PuTTY if not installed
if (-not $puttyInstalled) {
    try {
        Invoke-WebRequest -Uri $puttyURL -OutFile $puttyPath
        Start-Process -Wait -FilePath msiexec -ArgumentList "/i $puttyPath /qn"
        Write-Output "Installation of PuTTY completed!"
    } catch {
        Write-Error "Failed to download or install PuTTY. Please check the URL and try again."
        exit
    } finally {
        if (Test-Path $puttyPath) { Remove-Item -Path $puttyPath }
    }
} else {
    Write-Output "PuTTY is already installed!"
}

# Determine the path to the user's AppData\Local directory
$script:appDataLocalDir = "C:\ProgramData"

# Define the path to the ASUSUpdateScript folder
$script:asusUpdateScriptDir = Join-Path -Path $script:appDataLocalDir -ChildPath "ASUSUpdateScript"
$variablesFilePath = Join-Path -Path $asusUpdateScriptDir -ChildPath "variables.txt"

# Function to check and create directories if they don't exist
function Ensure-DirectoryExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }
}

    function StartAndMaximizeSSHKeyGen {
    # Start the ssh-keygen process and get the Process object
    $Process = Start-Process "cmd.exe" -ArgumentList "/c ssh-keygen" -WindowStyle Normal -PassThru
    
    # Wait for a moment to ensure the process has started and the window is created
    Start-Sleep -Seconds 2
    
    # Check if the process is running
    if ($Process -ne $null) {
        [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
        
        # Get the Process ID of the started process
        $ProcessId = $Process.Id
        
        # Activate the window
        [Microsoft.VisualBasic.Interaction]::AppActivate($ProcessId)
        
        # Define the ShowWindow function
        $SW_MAXIMIZE = 3
        $sig = @'
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        Add-Type -MemberDefinition $sig -Name Functions -Namespace Win32
        
        # Get the MainWindowHandle of the process and maximize the window
        $hWnd = (Get-Process -Id $ProcessId).MainWindowHandle
        [Win32.Functions]::ShowWindow($hWnd, $SW_MAXIMIZE)
    } else {
        Show-Notification "The ssh-keygen process did not start successfully."
        Start-Sleep -Seconds 5
        Exit
    }
}

function Select-Folder {
    # Get the user's Downloads folder path
    $shell = New-Object -ComObject Shell.Application
    $downloadsPath = $shell.NameSpace('shell:Downloads').Self.Path
   
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
    $form.ShowInTaskbar = $false
    
    # Create FolderBrowserDialog
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select a directory for downloading and extracting firmware"
    $folderBrowser.RootFolder = [Environment+SpecialFolder]::Desktop
    $folderBrowser.SelectedPath = $downloadsPath  # Set the default folder to the user's Downloads folder
    $folderBrowser.ShowNewFolderButton = $true
    
    # Show the form
    $form.Show()
    $form.Focus() | Out-Null
    $form.Activate()
    
    # Show FolderBrowserDialog from the form
    $dialogResult = $folderBrowser.ShowDialog($form)
    
    # Close the dummy form
    $form.Close()
    
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    } else {
        return $null
    }
}

function Select-WebCertPath {
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
    $form.ShowInTaskbar = $false
    
    # Create FolderBrowserDialog
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the directory for installing the DDNS web certificate"
    $folderBrowser.RootFolder = [Environment+SpecialFolder]::Desktop
    $folderBrowser.ShowNewFolderButton = $true
    
    # Show the form
    $form.Show()
    $form.Focus() | Out-Null
    $form.Activate()
    
    # Show FolderBrowserDialog from the form
    $dialogResult = $folderBrowser.ShowDialog($form)
    
    # Close the dummy form
    $form.Close()
    
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    } else {
        return $null
    }
}

function Get-InputUI {
    param (
        [string]$formTitle,
        [string]$labelText,
        [string]$noteText,
        [string]$linkText,
        [string]$linkUrl,
        [bool]$isPassword = $false,
        [string]$inputType = 'text', # Default to text input
        [string]$yesButtonText = 'Yes',
        [string]$noButtonText = 'No'
    )

    # Create the main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $formTitle
    $form.Size = New-Object System.Drawing.Size(350, 180)
    $form.StartPosition = 'CenterScreen'
    $form.TopMost = $true

    # Create label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(320, 20)
    $label.Text = $labelText
    $form.Controls.Add($label)

    # Create note label if provided
    if ($noteText) {
        $label2 = New-Object System.Windows.Forms.Label
        $label2.Location = New-Object System.Drawing.Point(10, 40)
        $label2.Size = New-Object System.Drawing.Size(320, 40)
        $label2.Text = $noteText
        $form.Controls.Add($label2)
    }

    # Create LinkLabel if provided
    if ($linkText -and $linkUrl) {
        $linkLabel = New-Object System.Windows.Forms.LinkLabel
        $linkLabel.Location = New-Object System.Drawing.Point(190, 20)
        $linkLabel.Size = New-Object System.Drawing.Size(100, 20)
        $linkLabel.Text = $linkText
        $form.Controls.Add($linkLabel)
        $linkLabel.BringToFront()
        $linkLabel.Add_LinkClicked({ Start-Process $linkUrl })
    }

    if ($inputType -eq 'text') {
        # Create textbox for input
        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 80)
        $textBox.Size = New-Object System.Drawing.Size(310, 20)
        if ($isPassword) { $textBox.UseSystemPasswordChar = $true }
        $form.Controls.Add($textBox)

        # Create OK button
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(120, 110)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Controls.Add($okButton)

        # Set the accept button for the form
        $form.AcceptButton = $okButton
    } else {
        # Create No button
        $noButton = New-Object System.Windows.Forms.Button
        $noButton.Location = New-Object System.Drawing.Point(200, 80)
        $noButton.Size = New-Object System.Drawing.Size(75, 23)
        $noButton.Text = $noButtonText
        $noButton.DialogResult = [System.Windows.Forms.DialogResult]::No
        $form.Controls.Add($noButton)

        # Create Yes button
        $yesButton = New-Object System.Windows.Forms.Button
        $yesButton.Location = New-Object System.Drawing.Point(50, 80)
        $yesButton.Size = New-Object System.Drawing.Size(75, 23)
        $yesButton.Text = $yesButtonText
        $yesButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $form.Controls.Add($yesButton)

        # Set the accept and cancel button for the form
        $form.AcceptButton = $yesButton
        $form.CancelButton = $noButton
    }

    # Show the form and get the result
    $result = $form.ShowDialog()

    if ($inputType -eq 'text') {
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $textBox.Text
        } else {
            return $null
        }
    } else {
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            return $true
        } else {
            return $false
        }
    }
}

Function Get-UserInput {

$script:selectedDir = Select-Folder
if ($null -eq $script:selectedDir) {
    Write-Host "No directory selected. Exiting script."
    exit
}

# Set Router Values

# Extact model as listed here: https://sourceforge.net/projects/asuswrt-merlin/files/
#NOTE: MODEL IS LETTER CASE SPECIFIC (Uppercase, lowercase)
$script:Model = Get-InputUI -formTitle 'Enter Router Model' -labelText 'Enter Router Model (As found on:' -noteText 'NOTE: Upper and lower case specific!' -linkText 'SourceForge)' -linkUrl 'https://sourceforge.net/projects/asuswrt-merlin/files/'
if($script:Model -eq $Null){exit}

# IP Address of router
$script:IP = Get-InputUI -formTitle 'Enter Router IP Address' -labelText 'Enter the Routers IP Address:'
if($script:IP -eq $Null){exit}

# Username of router
#NOTE: USER IS LETTER CASE SPECIFIC (Uppercase, lowercase)
$script:User = Get-InputUI -formTitle 'Enter Router User' -labelText 'Enter the Routers Username:' -noteText 'NOTE: Upper and lower case specific!'
if($script:User -eq $Null){exit}

# $True or $False does the Merlin .zip file contain a ROG build of the firmware?
$script:UseBetaBuilds = Get-InputUI -formTitle 'Include Beta Builds?' -labelText 'Would you like to include beta builds?' -inputType 'button'
if($script:UseBetaBuilds -eq $Null){exit}

# $True or $False does the Merlin .zip file contain a ROG build of the firmware?
$script:ROGRouter = Get-InputUI -formTitle 'ROG Build Confirmation' -labelText 'Does your firmware.zip usually contain a ROG build?' -inputType 'button'
if($script:ROGRouter -eq $Null){exit}

if($script:ROGRouter -eq $True){
# $True or $False to use ROG build. 
# NOTE: Only applicable if the above variable "$script:ROGRouter" is set to $True.
$script:UseROGVersion = Get-InputUI -formTitle 'ROG Build Confirmation' -labelText 'Would you like to use the ROG build or Pure Build?' -inputType 'button' -yesButtonText 'ROG Build' -noButtonText 'Pure Build'
if($script:UseROGVersion -eq $Null){exit}
}

# $True to only Download the Firmware and Backup Router Config. (NO FLASHING!)
$script:DownloadBackupOnly = Get-InputUI -formTitle 'Flash Confirmation?' -labelText 'Would you like to skip the firmware flash?' -noteText "NOTE: Selecting 'Yes' does NOT flash the firmware! Downloads firmware and router configs only!" -inputType 'button'
if($script:DownloadBackupOnly -eq $Null){exit}

# $True to backup a DDNS certificate or $False if not using DDNS or don't want to back up the cert.
$script:BackupDDNSCert = Get-InputUI -formTitle 'Backup DDNS Cert?' -labelText 'Would you like to download and backup the DDNS certificate?' -noteText "NOTE: Select 'Yes' to backup a DDNS certificate or 'No' if not using DDNS or don't want to back up the cert." -inputType 'button'
if($script:BackupDDNSCert -eq $Null){exit}

#NOTE 1: applicable if the above variable "$script:BackupDDNSCert" is set to $True.
#NOTE 2: PATH IS LETTER CASE SPECIFIC (Uppercase, lowercase) AS ENTERED ON WEB GUI UNDER.... WAN --> DDNS.
if ($script:BackupDDNSCert -eq $True){
$script:DDNSDomain = Get-InputUI -formTitle 'Enter DDNS Domain' -labelText 'Enter the Routers DDNS Address:' -noteText 'NOTE: Upper and lower case specific as found in the Web UI under WAN --> DDNS!'
if($script:DDNSDomain -eq $Null){exit}
$script:DDNSDomain = $script:DDNSDomain + "_ecc"

#$True to install DDNS certificate on local PC. (such as nginx, apache, etc)
$script:DDNSCertInstall = Get-InputUI -formTitle 'Install DDNS Certificate?' -labelText 'Install DDNS certificate on this computer for web service?' -noteText "NOTE: Only for if you have a web service such as apache or nginx" -inputType 'button'
if($script:DDNSCertInstall -eq $Null){exit}

if($script:DDNSCertInstall -eq $True){
#$Enter web Service name (such as nginx, apache, etc)
$script:WebService = Get-InputUI -formTitle 'Enter Web Service Name' -labelText 'Enter the name web service to install:' -noteText 'NOTE: Examples include apache, nginx, etc. Name much be entered as found in services.msc'
if($script:WebService -eq $Null){exit}

#$Path where to install the DDNS certificate
$script:CertInstallPath = Select-WebCertPath
if ($null -eq $script:CertInstallPath) {
    Write-Host "No answer entered. Exiting script."
    exit
}
}
}
}

Function Get-UniqueNetAdapter {
# Get the list of network adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

# If there are no active adapters, exit the script
if ($adapters.Count -eq 0) {
    Show-Notification "No active network adapter found."
    exit
}

# If there are multiple active adapters, let the user choose one
if ($adapters.Count -gt 1) {
    Write-Host "Multiple active network adapters found. Please choose one:"
    $adapters | Format-Table -Property Name, InterfaceDescription, Status
    $adapterName = Read-Host "Enter the name of the adapter you want to monitor"
    $adapter = $adapters | Where-Object { $_.Name -eq $adapterName }
} else {
    $adapter = $adapters[0]
}

# Display the name of the active adapter being monitored
Show-Notification "Connected being monitored is: $($adapter.Name)"
try {
$ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating    
& ssh -t -i ~/.ssh/id_rsa "${User}@${IP}" "reboot" 2>&1
} catch {
Show-Notification "Error occurred during SSH command. Please connect manually first to accept the fingerprint."
start-sleep -Seconds 5
exit
} finally {
$ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
}

# Monitor the adapter for disconnection and reconnection
while ($true) {
    # Check the status of the adapter
    $status = (Get-NetAdapter -Name $adapter.Name).Status
    
    # If the adapter is disconnected, wait for it to reconnect
    if ($status -eq 'Disconnected') {
        Show-Notification "Adapter $($adapter.Name) is disconnected. Waiting for it to reconnect..."
        
        # Wait for the adapter to reconnect
        while ((Get-NetAdapter -Name $adapter.Name).Status -eq 'Disconnected') {
            Start-Sleep -Seconds 5
        }
        
        Write-Host "Connection to $($adapter.Name) restored"
        break
    }
    
    # Sleep for a while before checking the status again
    Start-Sleep -Seconds 5
}
}

Function Get-FactoryDefault {
# Read the content of the file
$content = Get-Content -Path "$ExtractedDir\Changelog-NG.txt" -Raw

# Define a regex pattern to match the date entries
$pattern = '\(\d{1,2}-[a-zA-Z]+-\d{4}\)'

# Find all matches of the pattern in the content
$matches = [regex]::Matches($content, $pattern)

# Check if there are at least two date entries
if ($matches.Count -lt 2) {
    Write-Host "Not enough date entries found in the file."
    exit
}

# Get the positions of the two latest date entries
$startPos = $matches[0].Index + $matches[0].Length
$endPos = $matches[1].Index

# Extract the text between the two latest date entries
$extractedText = $content.Substring($startPos, $endPos - $startPos)

# Search for the string "factory default" within the extracted text
if ($extractedText -match "factory default") {
    $FactoryDefaultResults = Get-InputUI -formTitle 'Factory Defaults Recommended' -labelText 'This release recommends a factory default reset, would you like to continue now?' -inputType 'button'
    if ($FactoryDefaultResults -eq $False)
    {
    Show-Notification "Cancelling update script"
    Start-Sleep -Seconds 5
    exit
    }
} else {
    Write-Host "The text 'factory default' was not found between the two latest date entries."
}
}

#Check if the file exists
if (Test-Path $variablesFilePath) {
    # Read the content of the file
    $content = Get-Content -Path $variablesFilePath
    
    # Check if the content is not null or empty
    if ($null -ne $content -and $content -ne '') {
        $isValid = $true
        # Iterate over each line in the content
        foreach ($line in $content) {
            # Check if the line contains an '=' character, indicating a key-value pair
            if ($line -match '=') {
                # Split the line into key and value
                $key, $value = $line -split '='
                
                # Check if both key and value are not null or empty
                if ($null -ne $key -and $key -ne '' -and $null -ne $value -and $value -ne '') {
                    # Set the variable with the key and value
                    Set-Variable -Name "script:$key" -Value $value
                }
            } else {
                $isValid = $false
                break
            }
        }
        if (-not $isValid) {
            Remove-Item -Path $variablesFilePath -Force
            Get-UserInput
        }
    } else {
        Remove-Item -Path $variablesFilePath -Force
        Get-UserInput
    }
} else {
    Get-UserInput
}

# Set System Values
$script:downloadDir = "$script:selectedDir\$script:Model Firmware Release\Downloaded\"
$script:ExtractedDir = "$script:selectedDir\$script:Model Firmware Release\Production\"
$script:LocalConfig = "$script:selectedDir\$script:Model Router Backups\ASUS Configs"
$script:CertDownloadPath = "$script:LocalConfig\SSL Cert"
$script:Browser = "[Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer"
$script:FileType = "*.w"
$script:appDataLocalDir = "C:\ProgramData"
$script:knownHostsFile = "$env:USERPROFILE\.ssh\known_hosts"

# Ensure directories exist
Ensure-DirectoryExists -Path $script:downloadDir
Ensure-DirectoryExists -Path $script:ExtractedDir
Ensure-DirectoryExists -Path $script:LocalConfig
Ensure-DirectoryExists -Path $script:CertDownloadPath
Ensure-DirectoryExists -Path $script:asusUpdateScriptDir

if (!(Test-Path $variablesFilePath)) {
# Create a hashtable of the variables you want to store
$variablesToStore = @{
    selectedDir           = $script:selectedDir
    ROGRouter             = $script:ROGRouter
    UseROGVersion         = $script:UseROGVersion
    DownloadBackupOnly    = $script:DownloadBackupOnly
    BackupDDNSCert        = $script:BackupDDNSCert
    Model                 = $script:Model
    IP                    = $script:IP
    User                  = $script:User
    DDNSDomain            = $script:DDNSDomain
    DDNSCertInstall       = $script:DDNSCertInstall
    CertInstallPath       = $script:CertInstallPath
    WebService            = $script:WebService
    UseBetaBuilds         = $script:UseBetaBuilds
}

# Convert the hashtable to a multi-line string and save it to the .txt file
$variablesToStoreString = $variablesToStore.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
$variablesToStoreString | Out-File $variablesFilePath -Encoding UTF8
}

# Define the path to the ASUSUpdateScript folder
$script:asusUpdateScriptDir = Join-Path -Path $script:appDataLocalDir -ChildPath "ASUSUpdateScript"
$variablesFilePath = Join-Path -Path $asusUpdateScriptDir -ChildPath "variables.txt"

# Define the path to the ssh key
$sshKeyPath = "C:\Users\$env:USERNAME\.ssh\id_rsa.pub"
$script:vbsScriptPath3 = Join-Path $script:asusUpdateScriptDir "SendKeys3.vbs"

# Initialize a flag to check if the ssh key is generated
$keyGenerated = $false

# Check if the ssh key exists
if (-Not (Test-Path -Path $sshKeyPath)) {
    # If it doesn't exist, create the VBScript file dynamically
    $vbsContent3 = @"
set WshShell = WScript.CreateObject("WScript.Shell")
WScript.Sleep 500
WshShell.SendKeys "{ENTER}"
WScript.Sleep 500
WshShell.SendKeys "{ENTER}"
WScript.Sleep 500
WshShell.SendKeys "{ENTER}"
"@
    Set-Content -Path $script:vbsScriptPath3 -Value $vbsContent3

    # Call the function
    StartAndMaximizeSSHKeyGen | Out-Null

    # Wait for a few seconds to allow ssh-keygen to complete
    Start-Sleep -Seconds 1
    
    # Run the VBScript to send Enter keystrokes to the ssh-keygen process
    Start-Process "wscript.exe" -ArgumentList $script:vbsScriptPath3
    
    # Wait for a few seconds to allow ssh-keygen to complete
    Start-Sleep -Seconds 5
    
    # Double check if the ssh key is generated
    if (-Not (Test-Path -Path $sshKeyPath)) {
        Show-Notification "Failed to generate SSH key."
        start-sleep -seconds 5
        exit 1
    }
    
    # Set the flag to true as the key is generated
    $keyGenerated = $true
}

# If the key was generated, display the form with the TextBox
if ($keyGenerated) {
    # Read the contents of the ssh key
    $sshKeyContent = Get-Content -Path $sshKeyPath -Raw
    
    # Create a form with a Label for instructions and a TextBox for the ssh key
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "SSH Key"
    $form.Size = New-Object System.Drawing.Size(800,410)
    $form.StartPosition = "CenterScreen"
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,10)
    $label.Size = New-Object System.Drawing.Size(760,40)
    $label.Text = "Paste this SSH key into the router Admin console under:`r`nAdministration -> System -> Authorized Keys"
    $form.Controls.Add($label)
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10,60)
    $textBox.Size = New-Object System.Drawing.Size(760,270)
    $textBox.Multiline = $true
    $textBox.Text = $sshKeyContent
    $textBox.ScrollBars = "Vertical"
    $textBox.ReadOnly = $true  # Set the TextBox to read-only
    $form.Controls.Add($textBox)
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(650,340)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = "OK"
    $okButton.Add_Click({ $form.Close() })
    $form.Controls.Add($okButton)
    
    $form.ShowDialog()
}

$SCPKeyPath = "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk"

if (-Not (Test-Path -Path $SCPKeyPath)) {
    $vbsContent1 = @"
set WshShell = WScript.CreateObject("WScript.Shell")
WScript.Sleep 500
WshShell.SendKeys "{ENTER}"
"@

$script:vbsScriptPath1 = Join-Path $script:asusUpdateScriptDir "SendKeys1.vbs"
Set-Content -Path $script:vbsScriptPath1 -Value $vbsContent1

& "C:\Program Files (x86)\WinSCP\WinSCP.exe" /keygen "C:\Users\$env:USERNAME\.ssh\id_rsa" /output="C:\Users\$env:USERNAME\.ssh\id_rsa.ppk"

# Wait for a few seconds to allow SCP-keygen to complete
Start-Sleep -Seconds 1
    
# Run the VBScript to send Enter keystrokes to the ssh-keygen process
Start-Process "wscript.exe" -ArgumentList $vbsScriptPath1

# Wait for a few seconds to allow ssh-keygen to complete
Start-Sleep -Seconds 5
    
# Double check if the ssh key is generated
if (-Not (Test-Path -Path $SCPKeyPath)) {
        Show-Notification "Failed to generate SSH key."
        start-sleep -seconds 5
        exit 1
    }
}

# Set the web page urls
$urlbeta = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Beta/"
$urlrelease = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Release/"

# Get the web page content
$htmlbeta = Invoke-WebRequest $urlbeta
$htmlrelease = Invoke-WebRequest $urlrelease

if ($script:UseBetaBuilds -eq $True){
# Find all the beta links on the page, and filter for those that were the newest beta build
$NewLinksBeta = $htmlbeta.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip" -and $_.innerText -match "beta"
} | Sort-Object LastWriteTime -Descending | ForEach-Object {
    $version = ($_ -split '_')[1]
    $versionComponents = $version -split '\.'
    $_ | Add-Member -MemberType NoteProperty -Name 'ParsedVersion' -Value ([version]::new($versionComponents[0], $versionComponents[1], $versionComponents[2])) -Force -PassThru
} | Sort-Object ParsedVersion -Descending
}

# Find all the production links on the page and filter for those that were the newest production build.
$NewLinksRelease = $htmlrelease.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip"
} | Sort-Object LastWriteTime -Descending | ForEach-Object {
    $version = ($_ -split '_')[1]
    $versionComponents = $version -split '\.'
    $_ | Add-Member -MemberType NoteProperty -Name 'ParsedVersion' -Value ([version]::new($versionComponents[0], $versionComponents[1], $versionComponents[2])) -Force -PassThru
} | Sort-Object ParsedVersion -Descending

if ($script:UseBetaBuilds -eq $True){
# Save Both Newest Beta and Production to a Table
$WebReleases = @($NewLinksBeta[0], $NewLinksRelease[0])


# Determine Which Between Beta and Production is Highest/Newest.
$NewestWebVersion = $null
foreach ($release in $WebReleases) {
    # Extract version number from file name
    $release1Version = $release.outerText.ToString() -replace "^.*?_(\d+\.\d+).*", '$1'

    # Compare version numbers to determine newest firmware version
    foreach ($release2 in $WebReleases) {
        if ($release -ne $release2) {
            $release2Version = $release2.outerText.ToString() -replace "^.*?_(\d+\.\d+).*", '$1'
            if ([version]$release1Version -gt [version]$release2Version) {
                $NewestWebVersion = $release
            }
            elseif ([version]$release2Version -gt [version]$release1Version) {
                $NewestWebVersion = $release2
            }
            else {
                # If version numbers are identical, give non-beta version the winning selection
                if ($release -match "beta") {
                    $NewestWebVersion = $release2
                }
                else {
                    $NewestWebVersion = $release
                }
            }
        }
    }
}

# Winning Online Build Info Between Beta and Production
$NewestBuildName = $NewestWebVersion.outerText.ToString()
$NewestBuildLink = $NewestWebVersion.href.ToString()
}
else
{
$WebReleases = @($NewLinksRelease[0])
$NewestBuildName = $WebReleases.outerText.ToString()
$NewestBuildLink = $WebReleases.href.ToString()
}

# Get Local Build Info
$ToDateFirmware = (Get-ChildItem -Path "$downloadDir" -File).Name
$LocalVersion = $ToDateFirmware -replace "^.*?([0-9]+\.[0-9]+(?:_[0-9]+)?).*?$", '$1'
$major, $minor, $build = $LocalVersion -split '\.|_' | ForEach-Object { [int]$_ }
# Construct a new Version object from the version components
$ReconstructedversionL = New-Object -TypeName System.Version -ArgumentList $major, $minor, $build, 0
$winnerVersionL = New-Object -TypeName System.Version -ArgumentList $ReconstructedversionL

$isBeta = $ToDateFirmware -match "beta"
$LocalFirmwareBuild = [pscustomobject]@{
            Version = $winnerVersionL
            IsBeta = $isBeta
            FileName = $ToDateFirmware
            }

# Compare Newest Online Winning Build Between Beta and Production to Current Local Build (Only if it exists)
if(-not[string]::IsNullOrEmpty($ToDateFirmware)){

# Save Both Newest Beta and Production to a Table
$BuildReleases = @($NewestBuildName, $ToDateFirmware)

$NewestBuildW = $null
$highestVersion = $null
$winner = $null

foreach ($version in $BuildReleases) {
    # Extract the version number from the release string
    $versionNumber = $version -replace "^.*?([0-9]+\.[0-9]+(?:_[0-9]+)?).*?$", '$1'

    if ($highestVersion -eq $null -or $versionNumber -gt $highestVersion) {
        # If this version number is higher than the current highest, set it as the new highest
        $highestVersion = $versionNumber
        $winner = $version
    } elseif ($versionNumber -eq $highestVersion -and $version -notlike "*beta*") {
        # If this version number is the same as the current highest and not a beta version, set it as the winner
        $winner = $version
    }
}

$LvWWinnerVersion = $winner -replace "^.*?([0-9]+\.[0-9]+(?:_[0-9]+)?).*?$", '$1'
# Split the version string into its components
$major, $minor, $build = $LvWWinnerVersion -split '\.|_' | ForEach-Object { [int]$_ }
# Construct a new Version object from the version components
$Reconstructedversion = New-Object -TypeName System.Version -ArgumentList $major, $minor, $build, 0
$winnerVersion = New-Object -TypeName System.Version -ArgumentList $Reconstructedversion

$isBeta = $winner -like "*beta*"
$NewestBuildW = [pscustomobject]@{
    Version = $winnerVersion
    IsBeta = $isBeta
    FileName = $winner
    }
}

# Extract Beta Only Numbers from the File Names
if($NewestBuildW.IsBeta){
$NewestBuildWBetaNumber = ($NewestBuildW.FileName -replace '^.*_beta(\d+)\.zip$', '$1')
$FirmwareBuildBetaNumber = ($LocalFirmwareBuild.FileName -replace '^.*_beta(\d+)\.zip$', '$1')
}

# Enable or Disable DDNS Certificate Backup.
if($BackupDDNSCert -eq $True){
Show-Notification "Downloading DDNS Certs"

# Check if the .ssh directory exists, if not create it
if (-not (Test-Path "$env:USERPROFILE\.ssh")) {
New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" -Force | Out-Null 
}
    
# Check if the known_hosts file exists, if not create it
if (-not (Test-Path $script:knownHostsFile)) {
New-Item -ItemType File -Path $script:knownHostsFile -Force | Out-Null
ssh-keyscan -H $script:IP | Out-File -Append -Encoding ascii -FilePath $script:knownHostsFile
}

try {
 $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating
& pscp.exe -scp -i "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk" "${User}@${IP}:/jffs/.le/$DDNSDomain/domain.key" "$script:CertDownloadPath" 2>&1
& pscp.exe -scp -i "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk" "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.cer" "$script:CertDownloadPath" 2>&1
& pscp.exe -scp -i "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk" "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.pem" "$script:CertDownloadPath" 2>&1
} catch {
    Show-Notification "Error occurred during SCP command. Please connect manually first to accept the fingerprint."
    start-sleep -Seconds 5
    exit
}finally {
    $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
}

if($DDNSCertInstall -eq $True){

Get-Service -Name "$script:WebService" | Stop-Service

Start-Sleep -Seconds 5

if ((Get-Service -Name "$script:WebService").Status -eq "Running") {
Show-Notification "Problems Stopping $script:WebService service"

Start-Sleep -Seconds 10
}
else{
Show-Notification "$script:WebService Stopped Temporarily"

Start-Sleep -Seconds 10

Copy-Item -Path "$script:CertDownloadPath\Domain.key" -Destination "$script:CertInstallPath\key.pem" -Force
Copy-Item -Path "$script:CertDownloadPath\fullchain.pem" -Destination "$script:CertInstallPath\cert.pem" -Force

Start-Sleep -Seconds 5

# Start the service
Start-Service -Name "$script:WebService"

Start-Sleep -Seconds 5

if ((Get-Service -Name "$script:WebService").Status -eq "Running") {
Show-Notification "DDNS Certs Installed for $script:WebService"

Start-Sleep -Seconds 10
}
else{Show-Notification "Problems Starting $script:WebService Service"

Start-Sleep -Seconds 10
}
}
}}

# Set Max Attempts to Retry Download if Hash Check Fails.
$maxAttempts = 3
$attempt = 1
$validChecksum = $false

# Only proceed if current build does not exist, or if newest online build is greater than local build, or if online beta build is greater than local beta build, or if the local build version matches online but local is beta and online is production.
if ([string]::IsNullOrEmpty($ToDateFirmware) -or ([version]$NewestBuildW.Version -gt [version]$LocalFirmwareBuild.Version) -or ([int]$NewestBuildWBetaNumber -gt [int]$FirmwareBuildBetaNumber) -or (($LocalFirmwareBuild.IsBeta -and !$NewestBuildW.IsBeta -and [version]$NewestBuildW.Version -eq [version]$LocalFirmwareBuild.Version)))
    {
     do {
        Show-Notification "Downloading Firmware Update: 
$NewestBuildName"
        Remove-Item "$ExtractedDir*" -Recurse -Force
        Remove-Item "$downloadDir*" -Recurse -Force

        # Download each new file to the specified directory
        $downloadPath = Join-Path "$downloadDir" $NewestBuildName
        Invoke-WebRequest $NewestBuildLink -OutFile $downloadPath -UserAgent $script:Browser

        Unblock-File -Path $downloadPath
        Expand-Archive -Path $downloadPath -DestinationPath "$ExtractedDir" -Force

        if ($script:ROGRouter -eq $True){
        # Select the firmware based on the $UseROGVersion switch
        if ($UseROGVersion) {
        $ExtractedVersionName = Get-ChildItem -Path $ExtractedDir -Recurse -Include $FileType | 
        Where-Object { $_.Name -like '*_rog_*' } | 
        Select-Object -ExpandProperty FullName
        } else {
        $ExtractedVersionName = Get-ChildItem -Path $ExtractedDir -Recurse -Include $FileType | 
        Where-Object { $_.Name -notlike '*_rog_*' } | 
        Select-Object -ExpandProperty FullName }
        }else{
        $ExtractedVersionName = (Get-ChildItem -Path $ExtractedDir -Recurse -Include $FileType | Select-Object FullName).FullName
        }

        $expectedChecksums = Get-Content "$ExtractedDir\sha256sum.sha256" | ForEach-Object { $_.Split(' ')[0] }

        $fileName = [IO.Path]::GetFileName($ExtractedVersionName)

        # Generate the actual checksum value using Get-FileHash
        $actualChecksum = (Get-FileHash $ExtractedVersionName -Algorithm SHA256).Hash

        # Compare the expected and actual checksum values using a conditional statement
        if ($actualChecksum -in $expectedChecksums) {
            $validChecksum = $true
            $BuildName = ($NewestBuildName -replace '\.zip$', '').TrimEnd('.')

            Show-Notification "Downloading Router Backups"

            # Check if the .ssh directory exists, if not create it
            if (-not (Test-Path "$env:USERPROFILE\.ssh")) {
                New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" -Force | Out-Null
            }
    
            # Check if the known_hosts file exists, if not create it
            if (-not (Test-Path $script:knownHostsFile)) {
                New-Item -ItemType File -Path $script:knownHostsFile -Force | Out-Null
                ssh-keyscan -H $script:IP | Out-File -Append -Encoding ascii -FilePath $script:knownHostsFile
            }

            try {
            $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating    
            & ssh -t -i ~/.ssh/id_rsa "${User}@${IP}" "nvram save $BuildName.CFG" 2>&1
            } catch {
                Show-Notification "Error occurred during SSH command. Please connect manually first to accept the fingerprint."
                start-sleep -Seconds 5
                exit
            } finally {
            $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
            }

            Start-Sleep -Seconds 1

            try {
            $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating
            & pscp.exe -scp -i "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk" "${User}@${IP}:/home/root/${BuildName}.CFG" "$LocalConfig" 2>&1
            } catch {
            Show-Notification "Error occurred during SCP command. Please connect manually first to accept the fingerprint."
            start-sleep -Seconds 5
            exit
            }finally {
            $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
            }

            Start-Sleep -Seconds 5

            if($Script:DownloadBackupOnly -eq $False){

            Get-FactoryDefault

            Get-UniqueNetAdapter

            Show-Notification "Uploading Router Firmware"

            try {
            $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating
            & pscp.exe -scp -i "C:\Users\$env:USERNAME\.ssh\id_rsa.ppk" "$ExtractedVersionName" "${User}@${IP}:/home/root" 2>&1
            } catch {
            Show-Notification "Error occurred during SCP command. Please connect manually first to accept the fingerprint."
            start-sleep -Seconds 5
            exit
            }finally {
            $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
            }

            Start-Sleep -Seconds 5

            Show-Notification "Flashing Router Firmware"

             try {
            $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating    
            & ssh -t -i ~/.ssh/id_rsa "${User}@${IP}" "hnd-write $fileName" 2>&1
            } catch {
                Show-Notification "Error occurred during SSH command. Please connect manually first to accept the fingerprint."
                start-sleep -Seconds 5
                exit
            } finally {
            $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
            }

            Start-Sleep -Seconds 120

            Show-Notification "Rebooting Router"

            try {
            $ErrorActionPreference = 'Stop'  # Set the error action preference to 'Stop' to make non-terminating errors terminating    
            & ssh -t -i ~/.ssh/id_rsa "${User}@${IP}" "reboot" 2>&1
            } catch {
                Show-Notification "Error occurred during SSH command. Please connect manually first to accept the fingerprint."
                start-sleep -Seconds 5
                exit
            } finally {
            $ErrorActionPreference = 'Continue'  # Reset the error action preference to its default value 'Continue'
            }
            }

            exit

        } else {
            $attempt++
        }
    } while (!$validChecksum -and $attempt -le $maxAttempts)
} else {
Show-Notification "No Firmware Updates Available"

Start-Sleep -Seconds 10

exit
}

exit
