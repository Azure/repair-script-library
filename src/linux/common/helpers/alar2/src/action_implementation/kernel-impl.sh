#!/bin/bash
# The main intention is to roll back to the previous working kernel
# We do this by altering the grub configuration

# From the man page
# Set the default boot menu entry for GRUB.  This requires setting GRUB_DEFAULT=saved in /etc/default/grub
set_grub_default() {
        # verify whether GRUB_DEFAULT is available
        grep -q 'GRUB_DEFAULT=.*' /etc/default/grub || echo 'GRUB_DEFAULT=saved' >>/etc/default/grub
        # The next line could be garded and/or improved with the help of an if for instance
        # though I keep it simple
        sed -i "s/GRUB_DEFAULT=[[:digit:]]/GRUB_DEFAULT=saved/" /etc/default/grub
}

# set the default kernel accordingly
# This is different for RedHat and Ubuntu/SUSE distros
# Ubuntu and SLES use sub-menues
# Variables are set by action.rs

if [[ $isRedHat == "true" ]]; then
        if [[ $isRedHat6 == "true" ]]; then
                grubby --set-default=1 # This is the previous kernel
                ldconfig
        else
                set_grub_default
                # set to previous kernel
                sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=1/' /etc/default/grub

                # Generate both config files. 
                rub2-mkconfig -o /boot/efi/EFI/$(ls /boot/efi/EFI | grep -i -E "centos|redhat")/grub.cfg
                grub2-mkconfig -o /boot/grub2/grub.cfg

                # enable sysreq
                echo "kernel.sysrq = 1" >>/etc/sysctl.conf
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

exit 0
