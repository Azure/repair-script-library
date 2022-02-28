# Azure Linux Auto Recover v2


The Azure Linux Auto Recover v2 (ALAR2) tool is intended to fix boot issue for the most common issues. ALAR2 superceeds the previous version. ALAR2 is completely rewritten in Rust. It provides also a standalone mode to run the tool without the help of the 'vm repair extension'.o


The most common scenarios which are covered at the moment are:

* malformed /etc/fstab 
  * syntax error
  * missing disk
* damaged initrd or missing initrd line in the /boot/grub/grub.cfg
* last installed kernel is not bootable
* serialconsole and grub are not configured well

### FSTAB
This action does strip off any lines in the /etc/fstab file which are not needed to boot a system
It makes a copy of the original file first. So after the start of the OS the admin is able to edit the fstab again and correct any errors which didn’t allow a reboot of the system before

### Kernel
This action does change the default kernel.
It modifies the configuration so that the previous kernel version gets booted. After the boot the admin is able to replace the broken kernel.

### Initrd
This action corrects two issues that can happen when a new kernel gets installed 
1. The grub.cfg file is missing an “initrd” line or is missing the file to be use
2. The initrd image is missing
So it either fixes the grub.cfg file and/or creates a new initrd image 

### Serialconsole
This action corrects and incorrect or malformed serialsconsole configuration as well 
corrects an incorrect or malformed GRUB console configuration. With this option one gets information displayed on the serialconsole and gets also access to the GRUB menu in case it is not displaed because of an incorrect setup.

### How can I recover my failed VM?
To use the ALAR2 tool with the help of the vm repair extension you have to utilize the command ‘run’ and its option ‘--run-id’
The script-id for the automated recovery is: linux-alar2

#### Example ####

az vm repair create --verbose -g centos7 -n cent7 --repair-username rescue --repair-password 'password!234’ --copy-disk-name repairdiskcopy'

az vm repair run --verbose -g centos7 -n cent7 --run-id linux-alar2 --parameters initrd --run-on-repair

az vm repair restore --verbose -g centos7 -n cent7

You can pass over either a single recover-operation or multiple operations, i.e., fstab; ‘fstab,initrd’ 
Separate the recover operation with a comma in this case – no spaces allowed!

### Limitation
* Classic VMs are not supported

### Distributions supported
* CentOS/Redhat 6.8 - 8.2
* Ubuntu 16.4 LTS and Ubuntu 18.4 LTS
* Suse 12 and 15
* Debain 9 and 10