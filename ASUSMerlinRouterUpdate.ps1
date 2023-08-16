# Set Router Values
$script:DownloadandBackupOnly = $False
$script:BackupDDNSCert = $True
$script:DDNSCertInstall = $True
$script:Model = "RT-AX88U"
$script:IP = "192.168.1.1"
$script:User = "Admin"
$script:Password = "PASSWORDHERE"
$script:DDNSDomain = "DDNS-EXAMPLE.asuscomm.com" + "_ecc" #On Firmware older than 388.4 the _ecc can be removed, else do not change it.

# Set System Values
$script:downloadDir = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\RT-AX88 Firmware Release\Downloaded\"
$script:ExtractedDir = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\RT-AX88 Firmware Release\Production\"
$script:LocalConfig = "H:\USER\Downloads\Tools\Router Stuff\ASUS Router\ASUS Configs"
$script:LocalCertPath = "C:\ProgramData\nginx"
$script:WebService = "NGINX"
$script:Browser = "[Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer"
$script:FileType = "*.w"

# Set the web page urls
$urlbeta = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Beta/"
$urlrelease = "https://sourceforge.net/projects/asuswrt-merlin/files/$Model/Release/"


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

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ASUS Router Script")
    $Notifier.Show($Toast);
}

# Get the web page content
$htmlbeta = Invoke-WebRequest $urlbeta
$htmlrelease = Invoke-WebRequest $urlrelease

# Find all the beta links on the page, and filter for those that were the newest beta build
$NewLinksBeta = $htmlbeta.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip" -and $_.innerText -match "beta"
} | Sort-Object LastWriteTime -Descending | ForEach-Object {
    $version = ($_ -split '_')[1]
    $versionComponents = $version -split '\.'
    $_ | Add-Member -MemberType NoteProperty -Name 'ParsedVersion' -Value ([version]::new($versionComponents[0], $versionComponents[1], $versionComponents[2])) -Force -PassThru
} | Sort-Object ParsedVersion -Descending

# Find all the production links on the page and filter for those that were the newest production build.
$NewLinksRelease = $htmlrelease.Links | Where-Object {
    $_.innerText -match "$Model_[\d\.]+_.*\.zip"
} | Sort-Object LastWriteTime -Descending | ForEach-Object {
    $version = ($_ -split '_')[1]
    $versionComponents = $version -split '\.'
    $_ | Add-Member -MemberType NoteProperty -Name 'ParsedVersion' -Value ([version]::new($versionComponents[0], $versionComponents[1], $versionComponents[2])) -Force -PassThru
} | Sort-Object ParsedVersion -Descending

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

& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/domain.key" "$LocalConfig\SSL Cert" | Out-null
& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.cer" "$LocalConfig\SSL Cert" | Out-null
& pscp.exe -scp -pw $Password "${User}@${IP}:/jffs/.le/$DDNSDomain/fullchain.pem" "$LocalConfig\SSL Cert" | Out-null

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

Copy-Item -Path "$LocalConfig\SSL Cert\Domain.key" -Destination "$script:LocalCertPath\key.pem" -Force
Copy-Item -Path "$LocalConfig\SSL Cert\fullchain.pem" -Destination "$script:LocalCertPath\cert.pem" -Force

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

            $configbackupresult = ssh -i ~/.ssh/id_rsa "${User}@${IP}" "nvram save $BuildName.CFG" 2>&1
            if ($configbackupresult -like '*Host key verification failed.*') {
            Show-Notification "Host key verification failed.
Delete the file at: C:\Users\$env:UserName\.ssh\known_hosts and connect manually with Putty to accept the new fingerprint"
            }

            Start-Sleep -Seconds 1

            & pscp.exe -scp -pw "$Password" "${User}@${IP}:/home/root/${BuildName}.CFG" "$LocalConfig" | Out-null

            Start-Sleep -Seconds 5

            if($DownloadandBackupOnly -eq $False){

            Show-Notification "Uploading Router Firmware"

            & pscp.exe -scp -pw "$Password" "$ExtractedVersionName" "${User}@${IP}:/home/root" | Out-null

            Start-Sleep -Seconds 5

            Show-Notification "Flashing Router Firmware"

            $flashresult = ssh -i ~/.ssh/id_rsa "${User}@${IP}" "hnd-write $fileName" 2>&1
            if ($flashresult -like '*Host key verification failed.*') {
            Show-Notification "Host key verification failed.
Delete the file at: C:\Users\$env:UserName\.ssh\known_hosts and connect manually with Putty to accept the new fingerprint"
            }

            Start-Sleep -Seconds 65

            Show-Notification "Rebooting Router"

            $rebootresult = ssh -i ~/.ssh/id_rsa "${User}@${IP}" "reboot" 2>&1
            if ($rebootresult -like '*Host key verification failed.*') {
            Show-Notification "Host key verification failed.
Delete the file at: C:\Users\$env:UserName\.ssh\known_hosts and connect manually with Putty to accept the new fingerprint"
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
