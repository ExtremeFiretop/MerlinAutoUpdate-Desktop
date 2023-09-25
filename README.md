# Automated/Automatic and Unattended Asuswrt-Merlin Firmware Updates
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

Router Setup:
1. Enable SSH access, https://www.htpcguides.com/enable-ssh-asus-routers-without-ssh-keys/
2. Enable Custom Scripts. Go to Administration -> System -> Persistent JFFS2 partition and make sure that Enable JFFS custom scripts and configs is selected as "yes"
3. If you want to access via SSH throught the open internet (LAN + WAN). I highly recommend changing the port and disabling username password authentication (only using RSA keys).

Script Setup:
1. Download the script, copy it to your desired location on your Windows 10 computer.
2. Open the script and modify the parameters prompted. (These are stored locally only under: C:\ProgramData\ASUSUpdateScript)
3. The script will only run once if you run it once, it does not automatically schedule a re-run any time in the future.
4. To automatically re-run the script, link to a to task scheduler to run automatically at night, etc.
5. If you would like to reset the script to zero or change the variables, please delete or modify the variables.txt file found: C:\ProgramData\ASUSUpdateScript

(FYI) System Setup:
1. The script will download and install Putty and WinSCP as system requirements if not already installed.
2. If you already have Putty as a portable .EXE that is not sufficent, and it will install it anyways.
3. The script will also generate an SSH key for the router.
4. If something does not work while generating the key, please report an issue, you may generate a ssh key manually using the following command in Powershell: "ssh-keygen" (And use all default values: "Enter", "Enter", "Enter")
5. The SSH Key will be generated in the following location on Windows 10: "C:\Users\USERNAME\.ssh\id_rsa.pub"
6. Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
7. Script downloads the firmware and confirmation backups to the directories you selected before ever attempting a flash.
8. Any locally installed files for the script will always be found here: C:\ProgramData\ASUSUpdateScript
9. Reminder... If you would like to reset the script to zero or change the variables, please delete or modify the variables.txt file found: C:\ProgramData\ASUSUpdateScript
