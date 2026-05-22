#!/bin/bash
########################################################################################################
#
# .SYNOPSIS
#   alar2 allows recovering a failed VM. Various actions are available like: fstab, initrd, kernel,
#   grubfix, efifix, serialconsole, auditd, sudo, and corrupt. NOTE: use option --run-on-repair.
# 
# .DESCRIPTION
#   Runs a workflow from https://github.com/Azure/ALAR/tree/main/src/action_implementation depending on the parameter included when ran. 
#   For instance, running with az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-alar2 --parameters fstab --run-on-repair 
#   will run the fstab workflow to correct fstab issues.
#
#   Available actions:
#     fstab        - Fixes malformed /etc/fstab entries
#     kernel       - Reverts to the previously installed kernel
#     initrd       - Fixes a corrupt or missing initrd image and regenerates grub.cfg
#     serialconsole - Enables serial console and GRUB serial settings
#     grubfix      - Reinstalls GRUB bootloader and regenerates grub.cfg (GEN1 VMs)
#     efifix       - Reinstalls EFI/GRUB bootloader and regenerates grub.cfg (GEN2 VMs)
#     auditd       - Fixes disk-full boot failures caused by auditd configurations
#     sudo         - Resets permissions on /etc/sudoers and /etc/sudoers.d
#     corrupt      - Mounts the OS disk for manual inspection in a chroot environment
#
#   Multiple actions can be combined using a comma-separated list (no spaces), e.g.:
#     az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-alar2 --parameters grubfix,fstab --run-on-repair
#
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/repair-linux-vm-using-alar
# 
# .RESOLVES
#   malformed /etc/fstab
#   damaged initrd or /boot/grub/grub.cfg is missing the right setup
#   last installed kernel is not bootable
#   serial console and grub serial are not configured well
#   GRUB/EFI installation or configuration damaged (use grubfix for GEN1, efifix for GEN2)
#   Disk full causing a non-boot scenario, specifically related to auditd configurations.
#   Incorrect /etc/sudoers permissions preventing login
#
########################################################################################################
wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
chmod 700 run-alar.sh
./run-alar.sh $@

exit $?
