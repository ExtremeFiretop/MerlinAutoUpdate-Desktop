# Set Router Values
$DownloadandBackupOnly = $False
$DDNSCertInstall = $True
$BackupDDNSCert = $True
$Model = "RT-AX88U"
$IP = "192.168.1.1"
$User = "Admin"
$Password = "PASSWORDHERE"
$DDNSDomain = "DDNS.asuscomm.com"

# Set System Values
$downloadDir = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\RT-AX88 Firmware Release\Downloaded\"
$ExtractedDir = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\RT-AX88 Firmware Release\Production\"
$LocalConfig = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\ASUS Configs"
$nginx = "C:\ProgramData\nginx"
$Browser = "[Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer"
$FileType = "*.w"


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

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ASUS Router Script")
    $Notifier.Show($Toast);
}

# Set the web page urls
$urlbeta = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Beta/"
$urlrelease = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Release/"
# Get the web page content
$htmlbeta = Invoke-WebRequest $urlbeta
$htmlrelease = Invoke-WebRequest $urlrelease

# Find all the links on the page and filter for those that were uploaded in the last week
$NewLinksBeta = $htmlbeta.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip"
} | Sort-Object {[int]($_.innerText -replace '.*beta(\d+)\.zip','$1')} -Descending

# Find all the links on the page and filter for those that were uploaded in the last week
$NewLinksRelease = $htmlrelease.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip"
} | Sort-Object {
    $version = ($_ -split '_')[1]
    $versionComponents = $version -split '\.'
    [version]::new($versionComponents[0], $versionComponents[1], $versionComponents[2])
} -Descending

$WebReleases = @($NewLinksBeta[0], $NewLinksRelease[0])
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

$NewestBuildName = $NewestWebVersion.outerText.ToString()
$NewestBuildLink = $NewestWebVersion.href.ToString()
$ToDateFirmware = (Get-ChildItem -Path "$downloadDir" -File).Name
$LocalVersion = $ToDateFirmware -replace "^.*?_(\d+\.\d+).*", '$1'
$isBeta = $ToDateFirmware -match "beta"
$FirmwareBuild = [pscustomobject]@{
            Version = $LocalVersion
            IsBeta = $isBeta
            FileName = $ToDateFirmware
            }

if(-not[string]::IsNullOrEmpty($ToDateFirmware)){

$BuildReleases = @($NewestBuildName, $ToDateFirmware)

$NewestBuildW = $null
$highestVersion = $null
$winner = $null

foreach ($version in $BuildReleases) {
    # Extract the version number from the release string
    $versionNumber = $version -replace "^.*?([0-9]+\.[0-9]+).*?$", '$1'

    if ($highestVersion -eq $null -or $versionNumber -gt $highestVersion) {
        # If this version number is higher than the current highest, set it as the new highest
        $highestVersion = $versionNumber
        $winner = $version
    } elseif ($versionNumber -eq $highestVersion -and $version -notlike "*beta*") {
        # If this version number is the same as the current highest and not a beta version, set it as the winner
        $winner = $version
    }
}

$LocalVersion = $winner -replace "^.*?([0-9]+\.[0-9]+).*?$", '$1'
$isBeta = $winner -like "*beta*"
$NewestBuildW = [pscustomobject]@{
    Version = $LocalVersion
    IsBeta = $isBeta
    FileName = $winner
}

}

if($BackupDDNSCert -eq $True){
Show-Notification "Downloading DDNS Certs"

& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/domain.key" "$LocalConfig\SSL Cert" | Out-null
& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.cer" "$LocalConfig\SSL Cert" | Out-null
& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.pem" "$LocalConfig\SSL Cert" | Out-null

if($DDNSCertInstall -eq $True){
Copy-Item -Path "$LocalConfig\SSL Cert\Domain.key" -Destination "$nginx\key.pem" -Force
Copy-Item -Path "$LocalConfig\SSL Cert\fullchain.pem" -Destination "$nginx\cert.pem" -Force

Start-Sleep -Seconds 1

Get-Service -Name nginx | Stop-Service

Start-Sleep -Seconds 5

# Start the service
Start-Service -Name NGINX

Start-Sleep -Seconds 5

Show-Notification "DDNS Certs Installed for Nginx"

Start-Sleep -Seconds 5
}}

$maxAttempts = 3
$attempt = 1
$validChecksum = $false

    if ([string]::IsNullOrEmpty($ToDateFirmware) -or [version]$NewestBuildW.Version -gt [version]$FirmwareBuild.Version -or ($NewestBuildW.IsBeta -and (!$FirmwareBuild.IsBeta) -or (!$NewestBuildW.IsBeta -and ($FirmwareBuild.IsBeta))))
    {
     do {
        Show-Notification "Downloading Firmware Update: 
$NewestBuildName"
        Remove-Item "$ExtractedDir*" -Recurse -Force
        Remove-Item "$downloadDir*" -Recurse -Force

        # Download each new file to the specified directory
        $downloadPath = Join-Path "$downloadDir" $NewestBuildName
        Invoke-WebRequest $NewestBuildLink -OutFile $downloadPath -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

        Unblock-File -Path $downloadPath
        Expand-Archive -Path $downloadPath -DestinationPath "$ExtractedDir" -Force

        $ExtractedVersionName = (Get-ChildItem -Path $ExtractedDir -Recurse -Include $FileType | Select-Object FullName).FullName
        $expectedChecksum = (Get-Content "$ExtractedDir\sha256sum.sha256").Split(' ')[0]

        $fileName = [IO.Path]::GetFileName($ExtractedVersionName)

        # Generate the actual checksum value using Get-FileHash
        $actualChecksum = (Get-FileHash $ExtractedVersionName -Algorithm SHA256).Hash

        # Compare the expected and actual checksum values using a conditional statement
        if ($actualChecksum -eq $expectedChecksum) {
            $validChecksum = $true
            $BuildName = ($NewestBuildName -replace '\.zip$', '').TrimEnd('.')

            Show-Notification "Downloading Router Backups"

            ssh -i ~/.ssh/id_rsa "${User}@${IP}" "nvram save $BuildName.CFG"

            Start-Sleep -Seconds 1

            & pscp.exe -scp -pw "$Password" "${User}@${IP}:/home/root/${BuildName}.CFG" "$LocalConfig" | Out-null

            Start-Sleep -Seconds 5

            if($DownloadandBackupOnly -eq $False){

            Show-Notification "Uploading Router Firmware"

            & pscp.exe -scp -pw "$Password" "$ExtractedVersionName" "${User}@${IP}:/home/root" | Out-null

            Start-Sleep -Seconds 5

            Show-Notification "Flashing Router Firmware"

            ssh -i ~/.ssh/id_rsa "${User}@${IP}" "hnd-write /$fileName"

            Start-Sleep -Seconds 65

            Show-Notification "Rebooting Router"

            ssh -i ~/.ssh/id_rsa "${User}@${IP}" "reboot"
            }

            exit

        } else {
            $attempt++
        }
    } while (!$validChecksum -and $attempt -le $maxAttempts)
} else {
Show-Notification "No Firmware Updates Available"
exit
}
