#!/bin/bash
# The main intention is to roll back to the previous working kernel
# We do this by altering the grub configuration

# From the man page
# Set the default boot menu entry for GRUB.  This requires setting GRUB_DEFAULT=saved in /etc/default/grub
set_grub_default() {
        # if not set to saved, replace it
        sed -i "s/GRUB_DEFAULT=[[:digit:]]/GRUB_DEFAULT=saved/" /etc/default/grub
        echo GRUB_DISABLE_OS_PROBER=true >>/etc/default/grub
        #GRUB_DEFAULT=saved
        #GRUB_SAVEDEFAULT=true
}

# at first alter the grub configuration to set GRUB_DEFAULT=saved if needed
if [[ $isRedHat6 == "false" ]]; then
        set_grub_default
fi

# set the default kernel accordingly
# This is different for RedHat and Ubuntu/SUSE distros
# Ubuntu and SLES use sub-menues

# the variables are defined in base.sh
if [[ $isRedHat == "true" ]]; then
        if [[ $isRedHat6 == "true" ]]; then
                sed -i 's/default=0/default=1/' /boot/grub/grub.conf
        else
                grub2-set-default 1 # This is the last previous kernel
                grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
fi

if [[ $isUbuntu == "true" ]]; then
        sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT="1>2"/' /etc/default/grub
        update-grub
fi

if [[ $isSuse == "true" ]]; then
        #grub2-set-default "1>2"
        sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT="1>2"/' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg
fi

# For reference --> https://www.linuxsecrets.com/2815-grub2-submenu-change-boot-order

