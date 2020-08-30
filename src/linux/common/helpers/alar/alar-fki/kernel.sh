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
        else
                set_grub_default
                grubby --set-default=1 # This is the previous kernel
                
                # Fix for a bug in RedHat 8.1/8.2
                # This needs to be fixed as soon as the bug with grub2-mkconfig is solved too
                # grub2-mkconfig must not be executed because of this bug
                $(grep -qe 'VERSION_ID="8.[1-2]"' /etc/os-release) && $(sed -i 's/set default="0"/set default="${saved_entry}"/' /boot/grub2/grub.cfg)
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

