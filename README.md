# Automated-Remote-Asuswrt-Merlin-Firmware-Updates
Automatically and Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely identify a beta or stable firmware update for an ASUS Merlin router, and automatically download and update via an unattended method.

General Instructions:
This script is targeted to be used on Asus routers running the modified Asuswrt-Merlin software. To use this scripts you must first have.

1. Enable SSH access, https://www.htpcguides.com/enable-ssh-asus-routers-without-ssh-keys/ 
If you want to access via SSH throught the open internet (LAN + WAN). I highly recommend changing the port and disabling username password authentication (only using RSA keys).
2. Enable Custom Scripts. 
Go to Administration -> System -> Persistent JFFS2 partition and make sure that Enable JFFS custom scripts and configs is selected as "yes"

System Setup:
1. Please make sure you have putty *installed* and not just as a portable .exe.
2. To generate a ssh key, use the following command in Powershell: "ssh-keygen" (And use all default values: "Enter", "Enter", "Enter")
3. The SSH Key will be generated in the following location on Windows 10: "C:\Users\USERNAME\.ssh\id_rsa.pub"
4. Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
5. (Maybe?) You may need to add the values for putty path into your: "Advanced System Settings -> Environment Variables -> PATH."
6. Can be setup on a task scheduler if desired.

Script Setup:
1. Download the script, copy it to your desired location on your Windows 10 computer.
2. Open the script and modify the following parameters:
   
-"$script:DownloadandBackupOnly" 
(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will only download the firmware, and backup the routers configuration files, without doing a firmware update.
-"$script:BackupDDNSCert" 
(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will also backup the DDNS certificate of the router. (Must be using DDNS)
-"$script:DDNSCertInstall" 
(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will also install the DDNS cert to your local service of choice. See: "$script:WebService" below.
-"$script:Model" 
Must be an extact match of one of the approved models for Merlin Firmware.
-"$script:IP" 
Must be the router's local IP address. (For example 192.168.2.1)
-"$script:User" 
Must be the router's Admin username. (For example Administrator)
-"$script:Password" 
Must be the router's Admin password.
-"$script:DDNSDomain" 
Must be an extact match of the DDNS name if you have: "$script:BackupDDNSCert" set to: "$TRUE" (On Firmware older than 388.4 the "_ecc" value can be removed, else do not change it.)

# Set System Values
-"$script:downloadDir" 
Must be an extact match of the path where you need the new firmware downloaded.
-"$script:ExtractedDir" 
Must be an extact match of the path where you need the new firmware .zip file to be extracted.
-"$script:LocalConfig" 
Must be an extact match of the path where you need the newest router backups to be stored.
-"$script:nginx" 
Must be an extact match of the path where you need the DDNS certificate installed. (For example, "C:\ProgramData\nginx")
-"$script:WebService" 
Must be an extact match of the name of the service as found in your: "services.msc"
-"$script:Browser" 
(VALUES: ::InternetExplorer, ::Chrome, etc.) Must be a browser name installed on the system.

3. Run the script in Powershell to test.
4. Link to a to task scheduler to run automatically at night, etc.
