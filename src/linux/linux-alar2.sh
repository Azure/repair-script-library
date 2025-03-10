#!/bin/bash
﻿#########################################################################################################
#
# .SYNOPSIS
#   alar2 allows recovering a failed VM. Various actions are available like: fstab, initrd, and kernel. NOTE: use option --run-on-repair. 
# 
# .DESCRIPTION
#   Runs a workflow from https://github.com/Azure/ALAR/tree/main/src/action_implementation depending on the parameter included when ran. 
#   For instance, running with az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-alar2 --parameters fstab --run-on-repair 
#   will run the fstab workflow to correct fstab issues. 
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/repair-linux-vm-using-alar
# 
# .RESOLVES
#   malformed /etc/fstab
#   damaged initrd or /boot/grub/grub.cfg is missing the right setup
#   last installed kernel is not bootable
#   serial console and grub serial are not configured well
#   GRUB/EFI installation or configuration damaged
#   Disk full causing a non-boot scenario, specifically related to auditd configurations.
#
#########################################################################################################
wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
chmod 700 run-alar.sh
./run-alar.sh $@

exit $?
