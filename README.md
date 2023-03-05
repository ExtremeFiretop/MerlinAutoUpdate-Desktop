# ASUS-Merlin-Firmware-Update
Remotely Update ASUS Merlin Router Firmware Script

This script allows you to remotely identify a beta or stable firmware update for an ASUS Merlin router, and automatically download and update via an unattended method.

1. Please make sure you have putty *installed* and not just as a portable .exe.
2. You will to generate a ssh key using the following command in Powershell: "ssh-keygen" (And use all default values: "Enter", "Enter", "Enter")
3. The SSH Key will be generated in the following location on Windows 10: "C:\Users\USERNAME\.ssh\id_rsa.pub"
4. Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
5. (Maybe?) You may need to add the values for putty path into your: "Advanced System Settings -> Environment Variables -> PATH."
6. Can be setup on a task scheduler if desired.
