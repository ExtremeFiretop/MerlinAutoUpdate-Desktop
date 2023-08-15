# Remote-Asuswrt-Merlin-Firmware-Update
Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely identify a beta or stable firmware update for an ASUS Merlin router, and automatically download and update via an unattended method.

General Instructions
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
