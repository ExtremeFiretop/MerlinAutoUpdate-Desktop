## MerlinAutoUpdate-Desktop
# Automated/Automatic and Unattended Asuswrt-Merlin Firmware Updates
Windows Desktop Script to Automatically and Remotely Update ASUS Merlin Router Firmware Script

## SUPPORTED MODELS: (Multi-image models) - i.e. Any model that uses a .w file

 - GT-AXE11000 (Tested)
 - GT-AXE16000 (Untested)
 - GT-AX6000 (Untested)
 - GT-AX11000 (Untested)
 - GT-AX11000_PRO (Untested)
 - GT-AC2900 (Untested)
 - RT-AX88U_PRO (Untested)
 - RT-AX86U_PRO (Untested)
 - RT-AX68U (Untested)
 - RT-AX86U (Tested)
 - RT-AX56U (Untested)
 - RT-AX58U (Untested)
 - RT-AX3000 (Untested)
 - RT-AX88U (Tested)
 - RT-AC86U (Untested)
 - XT12 (Untested)

## UNSUPPORTED MODELS: (Single image models) - i.e. Any model that uses a .trx file

 - RT-AC86U (No)
 - RT-AC1900 (No)
 - RT-AC87U (No)
 - RT-AC5300 (No)
 - RT-AC3200 (No)
 - RT-AC3100 (No)
 - RT-AC88U (No)
 - RT-AC68U (No)
 - RT-AC66U (No)
 - RT-AC56U (No)
 - RT-AC66U_B1 (No)
 - RT-N66U (No)

## Features
- Remotely identify a beta or stable firmware download for an ASUS Merlin router, and automatically download via an unattended method from any Windows Desktop on the same network.
- Remotely Flash/Update to a beta or stable firmware update for an ASUS Merlin router via an unattended method from any Windows Desktop on the same network.
- Works with both ROG and non-ROG routers, if it's a ROG router simply select if you want to use the ROG or Pure Build.
- Backs up any router configurations before doing a flash and downloads them to a directory of choice
- Backs up and downloads any DDNS certificates (With a choice to install it on the local PC)
- Checks to confirm no factory reset is recommended, if it is, it waits and prompts for user feedback
- Reboots router before to clear memory, and after the firmware flash is completed to finalize the update. 

## General Instructions:
This script is targeted to be used on Asus routers running the modified Asuswrt-Merlin software.

- Important Notes:

The script uses external tools like pscp.exe and ssh to interact with the router. Ensure these tools are available in the system's PATH or specify their full paths in the script.
Before running such scripts, always backup your router's configuration and any other important data. There's always a risk of data loss or other issues when updating firmware.

## Here's a breakdown of what the script does:

![Detailed Firmware Update Script Flowchart](https://github.com/Firetop/MerlinAutoUpdate/assets/1971404/684572ec-aed2-4a55-a83f-7b10dea112eb)

1. Initialization and Setup:
The script initializes by setting up paths, variables, and ensuring necessary directories exist.
It downloads and installs system requirements if missing such as WinSCP and Putty.
It reads content from specific files and sets up variables based on the content.
If certain conditions are not met, it prompts the user for input.
3. Preparation and Validation:
The script checks for the existence of SSH keys and generates them if they are missing.
It validates the existence of certain files and their content, and if invalid, it removes them and gets user input.
It stops certain services temporarily if needed and backs up DDNS certificates if the user has opted for it.
4. Download and Comparison:
The script fetches the newest firmware builds (both beta and production) from the web and compares them with the local build.
It determines which build is the newest among the local, beta, and production builds.
If the local build is outdated, the script proceeds to download the newest build, otherwise, it notifies the user that no updates are available and exits.
5. Checksum Verification and Backup:
After downloading, it verifies the checksum of the downloaded file to ensure integrity.
It backs up router configurations and notifies the user about the progress.
6. Log Check and User Interaction:
The script checks the log files to see if a factory default reset is recommended.
If a reset is recommended, it pauses and prompts the user for action, giving them the option to continue or cancel the update process.
7. Firmware Flashing and Reboot:
Before flashing the firmware, the router is rebooted to clear its memory.
The script then uploads the firmware to the router and flashes it.
After flashing, it reboots the router again and notifies the user about the completion of each step.
8. Error Handling and Notification:
Throughout the process, the script handles errors gracefully, notifying the user about any issues encountered, such as host key verification failures, and provides instructions on how to resolve them.
It also provides notifications about the progress of each step, such as downloading updates, flashing firmware, and rebooting the router.
9. Cleanup and Exit:
After completing the update process, the script cleans up any temporary files and exits, or if the user has chosen only to download backups, it skips the flashing and rebooting steps and exits after completing the backups.

## Router Setup:
1. Enable SSH access, https://www.htpcguides.com/enable-ssh-asus-routers-without-ssh-keys/
2. Enable Custom Scripts. Go to Administration -> System -> Persistent JFFS2 partition and make sure that Enable JFFS custom scripts and configs is selected as "yes"
3. If you want to access via SSH throught the open internet (LAN + WAN). I highly recommend changing the port and disabling username password authentication (only using RSA keys).

## Script Setup:
1. Download the script, copy it to your desired location on your Windows 10 computer.
2. Open the script and modify the parameters prompted. (These are stored locally only under: ```C:\ProgramData\ASUSUpdateScript```)
3. The script will only run once if you run it once, it does not automatically schedule a re-run any time in the future.
4. To automatically re-run the script, link to a to task scheduler to run automatically at night, etc.
5. If you would like to reset the script to zero run the script with a -reset paremeter.  - ```(i.e Path\MerlinAutoUpdate.exe -reset) ```
6. Or to change the variables, please modify the variables.txt file found: ```C:\ProgramData\ASUSUpdateScript```

## (FYI) System Setup:
- The script will download and install Putty and WinSCP as system requirements if not already installed.
- If you already have Putty as a portable .EXE that is not sufficent, and it will install it anyways.
- The script will also generate an SSH key for the router.
- If something does not work while generating the key, please report an issue, you may generate a ssh key manually using the following command in CMD: ```ssh-keygen``` (And use all default values: "Enter", "Enter", "Enter")
- The SSH Key will be generated in the following location on Windows 10: ```C:\Users\USERNAME\.ssh\id_rsa.pub```
- Paste this SSH key into the router Admin console under: "Administration -> System -> Authorized Keys"
- Script downloads the firmware and confirmation backups to the directories you selected before ever attempting a flash.
- Any locally installed files for the script will always be found here: ```C:\ProgramData\ASUSUpdateScript```
- Reminder...
- If you would like to reset the script to zero run the script with a -reset paremeter.  - ```(i.e Path\MerlinAutoUpdate.exe -reset) ```
- Or to change the variables, please modify the variables.txt file found: ```C:\ProgramData\ASUSUpdateScript```
