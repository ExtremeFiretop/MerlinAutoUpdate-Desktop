# ASUS-Merlin-Firmware-Update
Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely update an ASUS Merlin router via an unattended method.

1. Please make sure you have putty *installed* and not just as a portable .exe.
2. You will to generate a ssh key using the following command in Powershell: "ssh-keygen" (and use all default values "Enter" "Enter" "Enter")
3. The SSH Key will be generated in the following location on Windows 10: "C:\Users\USERNAME\.ssh\id_rsa.pub"
4. Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
5 (maybe) You may need to add the values for putty path into your: "Advanced System Settings -> Environment Variables."
