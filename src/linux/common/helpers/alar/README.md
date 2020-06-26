# Azure Linux Auto Recover


The Azure Linux Auto Recover (ALAR) scripts 
are intended to fix boot issue for the most common issues.

The most common scenarios which are covered at the moment are:

* malformed /etc/fstab 
  * syntax error
  * missing disk
* damaged initrd or missing initrd line in the /boot/grub/grub.cfg
* last installed kernel is not bootable

### FSTAB
This script does strip off any lines in the /etc/fstab file which are not needed to boot a system
It makes a copy of the original file first. So after the start of the OS the admin is able to edit the fstab again and correct any errors which didn’t allow a reboot of the system before

### Kernel
This script does change the default kernel.
It modifies the configuration so that the previous kernel version gets booted. After the boot the admin is able to replace the broken kernel.

### Initrd
This script corrects two issues that can happen when a new kernel gets installed 

1. The grub.cfg file is missing an “initrd” line or is missing the file to be use
2. The initrd image is missing
So it either fixes the grub.cfg file and/or creates a new initrd image 

### How can I recover my failed VM?
To use the ALAR scripts with the help of the vm repair extension you have to utilize the command ‘run’ and its option ‘--run-id’
The script-id for the automated recovery is: _linux-recover_

#### Example ####

az vm repair create --verbose -g centos7 -n cent7 --repair-username rescue --repair-password 'password!234’ 

az vm repair run --verbose -g centos7 -n cent7 --run-id linux-recover --parameters initrd --run-on-repair

az vm repair restore --verbose -g centos7 -n cent7

You can pass over either a single recover-operation or multiple operations, i.e., fstab; ‘fstab,initrd’ 
Separate the recover operation with a comma in this case – no spaces allowed!

### Limitation
* encrypted images are not supported
* Classic VMs are not supported

