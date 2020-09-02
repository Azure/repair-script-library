#!/bin/bash
# The main intention is to roll back to the previous working kernel
# We do this by altering the grub configuration

# From the man page
# Set the default boot menu entry for GRUB.  This requires setting GRUB_DEFAULT=saved in /etc/default/grub
set_grub_default() {
        # if not set to saved, replace it
        sed -i "s/GRUB_DEFAULT=[[:digit:]]/GRUB_DEFAULT=saved/" /etc/default/grub
}

# set the default kernel accordingly
# This is different for RedHat and Ubuntu/SUSE distros
# Ubuntu and SLES use sub-menues

# the variables are defined in base.sh
if [[ $isRedHat == "true" ]]; then
        if [[ $isRedHat6 == "true" ]]; then
                grubby --set-default=1 # This is the previous kernel
                ldconfig
        else
                set_grub_default
                grubby --set-default=1 # This is the previous kernel
                
                # Fix for a bug in RedHat 8.1/8.2
                # https://bugzilla.redhat.com/show_bug.cgi?id=1850193
                # This needs to be fixed as soon as the bug with grub2-mkconfig is solved too
                if [[ ($(grep -qe 'ID="rhel"' /etc/os-release) -eq 0) && ($(grep -qe 'VERSION_ID="8.[1-2]"' /etc/os-release) -eq 0) ]]; then 
                        if [[ -d /sys/firmware/efi ]]; then 
                                grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
                        else
                        yum install -y patch
cat > /boot/grub2/grub-cfg.patch <<EOF
11,12c
if [ -f (hd0,gpt15)/efi/redhat/grubenv ]; then
load_env -f (hd0,gpt15)/efi/redhat/grubenv
.
EOF
                grub2-mkconfig -o /boot/grub2/grub.cfg
                patch /boot/grub2/grub.cfg /boot/grub2/grub-cfg.patch
                ldconfig
                       fi
                fi
        fi
fi

if [[ $isUbuntu == "true" ]]; then
        set_grub_default
        sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT="1>2"/' /etc/default/grub
        update-grub
fi

if [[ $isSuse == "true" ]]; then
        set_grub_default
        sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT="1>2"/' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg
fi

# For reference --> https://www.linuxsecrets.com/2815-grub2-submenu-change-boot-order

