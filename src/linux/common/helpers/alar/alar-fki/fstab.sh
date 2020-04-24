#!/bin/bash
mv -f /etc/fstab{,.copy}
awk '/[[:space:]]+\/[[:space:]]+/ {print}' /etc/fstab.copy >>/etc/fstab
awk '/[[:space:]]+\/boot[[:space:]]+/ {print}' /etc/fstab.copy >>/etc/fstab
# For Suse
awk '/[[:space:]]+\/boot\/efi[[:space:]]+/ {print}' /etc/fstab.copy >>/etc/fstab
# In case we have a LVM system
awk '/rootvg-homelv/ {print}' /etc/fstab.copy >>/etc/fstab
awk '/rootvg-optlv/ {print}' /etc/fstab.copy >>/etc/fstab
awk '/rootvg-tmplv/ {print}' /etc/fstab.copy >>/etc/fstab
awk '/rootvg-usrlv/ {print}' /etc/fstab.copy >>/etc/fstab
awk '/rootvg-varlv/ {print}' /etc/fstab.copy >>/etc/fstab
cat /etc/fstab
echo "Renaming original file /etc/fstab to /etc/fstab.copy"
echo "Creating new /etc/fstab file with only /boot and / partitions."
echo "This ensures we have a bootable system"