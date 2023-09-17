# Automated-Remote-Asuswrt-Merlin-Firmware-Updates
Automatically and Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely identify a beta or stable firmware update for an ASUS Merlin router, and automatically download and update via an unattended method.

Here's a breakdown of what the script does:

1. Set Router Values: This section sets various configuration values related to the router, such as its model, IP address, user credentials, and domain for DDNS.
2. Set System Values: This section sets paths and other system-related values, such as where to download firmware, where to extract it, and the type of web service being used.
3. Set Web Page URLs: This section sets the URLs for the beta and release firmware versions.
4. Show Windows Toast Notification Function: This function (Show-Notification) is used to display Windows toast notifications. It takes in a title and text for the notification.
5. Get Web Page Content: This section fetches the content of the beta and release firmware web pages.
6. Find Firmware Links: This section parses the fetched web pages to find links to the firmware files. It then sorts these links based on the version number to determine the newest beta and release firmware versions.
7. Determine Newest Firmware: This section compares the newest beta and release firmware versions to determine which one is the most recent.
8. Get Local Build Info: This section retrieves information about the currently installed firmware version.
9. Compare Firmware Versions: This section compares the newest online firmware version with the currently installed version to determine if an update is needed.
10. Backup DDNS Certificate: If the $BackupDDNSCert variable is set to $True, this section backs up the DDNS certificate from the router to the local machine. If $DDNSCertInstall is also $True, it stops the web service, copies the certificates to the appropriate directory, and then restarts the web service.
11. Download and Verify Firmware: This section downloads the newest firmware, verifies its checksum, and then proceeds with the update if the checksum is valid. If the checksum is not valid, it will retry the download up to a maximum number of times specified by $maxAttempts.
12. Update Firmware: If the downloaded firmware is newer than the currently installed version, this section uploads the new firmware to the router, flashes it, and then reboots the router.
13. Exit: If no updates are available or after the update process is complete, the script displays a notification and then exits.

Important Notes:

The script uses external tools like pscp.exe and ssh to interact with the router. Ensure these tools are available in the system's PATH or specify their full paths in the script.
Before running such scripts, always backup your router's configuration and any other important data. There's always a risk of data loss or other issues when updating firmware.

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
5. Add the values for putty path into your: "Advanced System Settings -> Environment Variables -> PATH."
6. Can be setup on a task scheduler if desired.

Script Setup:
1. Download the script, copy it to your desired location on your Windows 10 computer.
2. Open the script and modify the following parameters:
3. Run the script in Powershell to test.
4. Link to a to task scheduler to run automatically at night, etc.

# Set Router Values   
-"$script:DownloadandBackupOnly"
=(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will only download the firmware, and backup the routers configuration files, without doing a firmware update.

-"$script:BackupDDNSCert"
=(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will also backup the DDNS certificate of the router. (Must be using DDNS)

-"$script:DDNSCertInstall"
=(VALUES: $TRUE/$FALSE) - "$TRUE" means the script will also install the DDNS cert to your local service of choice. See: "$script:WebService" below.

-"$script:Model"
=Must be an extact match of one of the approved models for Merlin Firmware.

-"$script:IP"
=Must be the router's local IP address. (For example 192.168.2.1)

-"$script:User"
=Must be the router's Admin username. (For example Administrator)

-"$script:Password"
=Must be the router's Admin password.

-"$script:DDNSDomain"
=Must be an extact match of the DDNS name if you have: "$script:BackupDDNSCert" set to: "$TRUE" (On Firmware older than 388.4 the "_ecc" value can be removed, else do not change it.)

# Set System Values
-"$script:downloadDir"
=Must be an extact match of the path where you need the new firmware downloaded.

-"$script:ExtractedDir"
=Must be an extact match of the path where you need the new firmware .zip file to be extracted.

-"$script:LocalConfig"
=Must be an extact match of the path where you need the newest router backups to be stored.

-"$script:LocalCertPath"
=Must be an extact match of the path where you need the DDNS certificate installed. (For example, "C:\ProgramData\nginx")

-"$script:WebService"
=Must be an extact match of the name of the service as found in your: "services.msc"

-"$script:Browser"
=(VALUES: ::InternetExplorer, ::Chrome, etc.) Must be a browser name installed on the system.
