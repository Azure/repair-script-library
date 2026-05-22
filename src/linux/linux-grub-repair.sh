#!/bin/bash
########################################################################################################
#
# .SYNOPSIS
#   Automates GRUB re-installation on a failed Linux VM. NOTE: use option --run-on-repair.
#
# .DESCRIPTION
#   Reinstalls the GRUB bootloader and regenerates the grub.cfg file on the attached OS disk.
#   Supports both GEN1 VMs (grubfix) and GEN2/EFI VMs (efifix).
#
#   By default, this script auto-detects the VM generation and runs the appropriate action:
#     - GEN1 VMs: runs the 'grubfix' action to reinstall GRUB and regenerate grub.cfg
#     - GEN2 VMs: runs the 'efifix' action to reinstall the EFI/GRUB bootloader
#
#   An optional parameter can be passed to override the auto-detected action:
#     grubfix  - Force GEN1 GRUB reinstallation
#     efifix   - Force GEN2/EFI GRUB reinstallation
#
#   Usage examples:
#     Auto-detect:
#       az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-grub-repair --run-on-repair
#     Force GEN1:
#       az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-grub-repair --parameters grubfix --run-on-repair
#     Force GEN2/EFI:
#       az vm repair run --verbose -g RGNAME -n VMNAME --run-id linux-grub-repair --parameters efifix --run-on-repair
#
#   Public doc: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/repair-linux-vm-using-alar
#
# .RESOLVES
#   GRUB bootloader is missing or corrupt (GEN1 VMs)
#   EFI/GRUB bootloader is missing or corrupt (GEN2 VMs)
#   grub.cfg is missing or invalid, preventing the VM from booting
#   VM stuck at GRUB rescue prompt or GRUB error screen
#
########################################################################################################

# Determine the GRUB action to run
if [ -z "$1" ]; then
    # Auto-detect VM generation based on EFI firmware directory presence
    # /sys/firmware/efi/efivars is only present on EFI-booted (GEN2) systems
    if [ -d /sys/firmware/efi/efivars ]; then
        GRUB_ACTION="efifix"
    else
        GRUB_ACTION="grubfix"
    fi
else
    # Use the provided parameter
    GRUB_ACTION="$1"
    # Validate the parameter
    if [ "$GRUB_ACTION" != "grubfix" ] && [ "$GRUB_ACTION" != "efifix" ]; then
        echo "[Error] Invalid parameter '$GRUB_ACTION'. Valid values are: grubfix, efifix"
        exit 1
    fi
fi

echo "[Info] Running GRUB repair action: $GRUB_ACTION"

wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
if [ $? -ne 0 ]; then
    echo "[Error] Failed to download run-alar.sh from GitHub. Please check network connectivity."
    exit 1
fi
chmod 700 run-alar.sh
./run-alar.sh "$GRUB_ACTION"

exit $?
