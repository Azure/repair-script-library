#!/bin/bash
cd ${tmp_dir}
. ./src/linux/common/setup/init.sh
#
# recover logic for handling and initrd or kernel problem
#

recover_suse() {
    kernel_type=$(uname -r | grep -q default && echo "kernel-default" || echo "kernel-azure")
    kernel_version=$(zypper se -is ${kernel_type} | grep ${kernel_type} | awk '{print $7;exit}')
    kernel_version=$(sed -e "s/kernel-//" <<< $(rpm -q kernel --last  | head -n 1 | cut -f1 -d' '))
    mkinitrd /boot/initrd-"${kernel_version}" "$kernel_version"
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

recover_ubuntu() {
    if [[ ! -e /var/log/dpkg.log ]]; then
    # if this file is empty we have to assume that we have a vanilla system. Only one kernel available
        kernel_version=$(ls /boot/vmlinuz-*)
        kernel_version=${kernel_version#/boot/vmlinuz-}
    else
        kernel_version=$( zgrep linux-image /var/log/dpkg.log* | grep installed  | cut -d' ' -f5 | cut -d':' -f1 | sed -e 's/linux-image-//' | grep ^[1-9] | sort -V | tail -n 1)
    fi
    # This is needed on Debian only
    if [[ -e /boot/initrd.img-${kernel_version} ]]; then
            rm /boot/initrd.img-${kernel_version}
    fi
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
        awk -f alar-fki/grub.awk /boot/grub/grub.conf
        # rebuild the initrd
        dracut -f /boot/initramfs-"${kernel_version}".img "$kernel_version"
    else
        if [[ $(grep -qe 'VERSION_ID=\"8.\?[1-2]\?\"' /etc/os-release) -eq 0 ]]; then
            for installed_kernel in $(rpm -qa kernel); do
                     kernel-install add $(sed 's/kernel-//' <<< $installed_kernel) /boot/vmlinuz-$(sed 's/kernel-//' <<< $installed_kernel)
            done
        else
            depmod ${kernel_version}
            mkinitrd --force /boot/initramfs-"${kernel_version}".img "$kernel_version"
            grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
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
