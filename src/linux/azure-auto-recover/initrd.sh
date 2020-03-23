#!/bin/bash

#
# recover logic for handling and initrd or kernel problem
#

recover_suse() {
    kernel_version=$(sed -e "s/kernel-//" <<< $(rpm -q kernel --last  | head -n 1 | cut -f1 -d' '))
    mkinitrd /boot/initrd-"${kernel_version}" "$kernel_version"
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

recover_ubuntu() {
    kernel_version=$( zgrep linux-image /var/log/dpkg.log* | grep installed  | cut -d' ' -f5 | cut -d':' -f1 | sed -e 's/linux-image-//' | grep ^[1-9] | sort -V | tail -n 1)
    update-initramfs -k "$kernel_version" -c
    update-grub

}

#
# Should handle all redhat based distros
#
recover_redhat() {
    kernel_version=$(sed -e "s/kernel-//" <<< $(rpm -q kernel --last  | head -n 1 | cut -f1 -d' '))
    if [[ "$isRedHat6" == "true" ]]; then
        # verify the grub.conf and correct it if needed
        cd "$tmp_dir"
        wget -q --no-cache https://raw.githubusercontent.com/malachma/azure-support-scripts/master/grub.awk
        awk -f grub.awk /boot/grub/grub.conf
        # rebuild the initrd
        dracut -f /boot/initramfs-"${kernel_version}".img "$kernel_version"
    else
        depmod ${kernel_version}
        mkinitrd --force /boot/initramfs-"${kernel_version}".img "$kernel_version"
        grub2-mkconfig -o /boot/grub2/grub.cfg
    fi

}

if [[ "$isRedHat" == "true" ]]; then
    recover_redhat
fi

if [[ "$isSuse" == "true" ]]; then
    recover_suse
fi

if [[ "$isUbuntu" == "true" ]]; then
    recover_ubuntu
fi
