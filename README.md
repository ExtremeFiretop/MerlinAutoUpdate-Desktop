# ASUS-Merlin-Firmware-Update
Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely update an ASUS Merlin router via an unattended method.
Please make sure you have putty *installed* and not just as a portable .exe.
You will to generate a ssh key using the following command in Powershell: "ssh-keygen" (and use all default values "Enter" "Enter" "Enter")
The SSH Key will be generated in the following location on Windows 10: "C:\Users\USERNAME\.ssh\id_rsa.pub"
Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
You may need to add the values for putty path into your: "Advanced System Settings -> Environment Variables."
