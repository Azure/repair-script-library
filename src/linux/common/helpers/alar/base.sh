#!/bin/bash

# Variables
#export UBUNTU_DISTRO="true"
export isRedHat="false"
export isRedHat6="false"
export isSuse="false"
export isUbuntu="false"
export tmp_dir=""
export recover_action=""
export boot_part=""
export rescue_root=""
export isExt4="false"
export isExt3="false"
export isXFS="false"
export isLVM="false"
export efi_part=""
export osNotSupported="true" # set to true by default, gets changed to false if this is the case
export tmp_dir=""
export global_error="false"
STATUS_SUCCESS=0
STATUS_ERROR=1
export actions="fstab initrd kernel" # These are the basic actions at the moment

# Functions START
# Define some helper functions

. ./src/linux/common/setup/init.sh

recover_action() {
    cd "${tmp_dir}"
    local recover_action=$1

    if [[ -f "${tmp_dir}/${recover_action}.sh" ]]; then
        Log-Info "Starting recover action:  ${recover_action}"
        chmod 700 "${tmp_dir}/${recover_action}.sh"
        chroot /mnt/rescue-root "${tmp_dir}/${recover_action}.sh"
        Log-Info "Recover action:  ${recover_action} finished"
    else
        Log-Error "File ${recover_action}.sh does not exist. Exiting ALAR"
        global_error="true"
    fi

    [[ ${global_error} == "true" ]] && return 11
}

isInAction() {
    #be quiet, just let us know this action exists
    grep -q "$1" <<<"$actions"
    return "$?"
}

copyRecoverScriptsToTemp() {
        cp ./src/linux/common/helpers/alar/* ${tmp_dir}
}

# Funtions END

#
# Start of the script
#

# Create tmp dir in order to store our files we download
tmp_dir="$(mktemp -d)"
copyRecoverScriptsToTemp
cd "${tmp_dir}"

# Filename for the distro verification
distro_test="distro-test.sh"

# Global redirection for ERR to STD
exec 2>&1

#
# What OS we need to recover?
#
if [[ -f "$tmp_dir/${distro_test}" ]]; then
    chmod 700 "${tmp_dir}/${distro_test}"
    . ${distro_test} # invoke the distro test

    # Do we have identifed a supported distro?
    if [[ ${osNotSupported} == "true" ]]; then
        Log-Error "OS is not supported. ALAR will stop!"
        exit 1
    fi
else
    Log-Error "File ${distro_test}.sh could not be fetched. Exiting"
    exit 1
fi

#Mount the root part
#====================
if [[ ! -d /mnt/rescue-root ]]; then
    mkdir /mnt/rescue-root
fi

if [[ ${isLVM} == "true" ]]; then
    pvscan
    vgscan
    lvscan
    rootlv=$(lvscan | grep rootlv | awk '{print $2}' | tr -d "'")
    tmplv=$(lvscan | grep tmplv | awk '{print $2}' | tr -d "'")
    optlv=$(lvscan | grep optlv | awk '{print $2}' | tr -d "'")
    usrlv=$(lvscan | grep usrlv | awk '{print $2}' | tr -d "'")
    varlv=$(lvscan | grep varlv | awk '{print $2}' | tr -d "'")

    # ext4 i used together with LVM, so no further handling is required
    mount ${rootlv} /mnt/rescue-root
    mount ${tmplv} /mnt/rescue-root/tmp
    mount ${optlv} /mnt/rescue-root/opt
    mount ${usrlv} /mnt/rescue-root/usr
    mount ${varlv} /mnt/rescue-root/var

elif [[ "${isRedHat}" == "true" || "${isSuse}" == "true" ]]; then
    # noouid is valid for XFS only
    if [[ "${isExt4}" == "true" ]]; then
        mount -n "${rescue_root}" /mnt/rescue-root
    elif [[ "${isXFS}" == "true" ]]; then
        mount -n -o nouuid "${rescue_root}" /mnt/rescue-root
    fi
fi

if [[ "$isUbuntu" == "true" ]]; then
    mount -n "$rescue_root" /mnt/rescue-root
fi

#Mount the boot part
#===================
if [[ ! -d /mnt/rescue-root/boot ]]; then
    mkdir /mnt/rescue-root/boot
fi

if [[ ${isLVM} == "true" ]]; then
    boot_part_number=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f1)
    boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
    mount ${boot_part} /mnt/rescue-root/boot
else
    if [[ "$isRedHat" == "true" || "$isSuse" == "true" ]]; then
        # noouid is valid for XFS only
        if [[ "${isExt4}" == "true" || "${isExt3}" == "true" ]]; then
            mount "${boot_part}" /mnt/rescue-root/boot
        elif [[ "${isXFS}" == "true" ]]; then
            mount -o nouuid "${boot_part}" /mnt/rescue-root/boot
        fi
    fi
fi

# Mount the EFI part if Suse
if [[ "${isSuse}" == "true" ]]; then
    if [[ ! -d /mnt/rescue-root/boot/efi ]]; then
        mkdir /mnt/rescue-root/boot/efi
    fi
    mount "${efi_part}" /mnt/rescue-root/boot/efi
fi

#Mount the support filesystems
#==============================
#see also http://linuxonazure.azurewebsites.net/linux-recovery-using-chroot-steps-to-recover-vms-that-are-not-accessible/
for i in dev proc sys tmp dev/pts; do
    if [[ ! -d /mnt/rescue-root/"$i" ]]; then
        mkdir /mnt/rescue-root/"$i"
    fi
    mount -o bind /"$i" /mnt/rescue-root/"$i"
done

if [[ "${isUbuntu}" == "true" || "${isSuse}" == "true" ]]; then
    if [[ ! -d /mnt/rescue-root/run ]]; then
        mkdir /mnt/rescue-root/run
    fi
    mount -o bind /run /mnt/rescue-root/run
fi

# Reformat the action value
action_value=$(echo $1 | tr ',' ' ')
recover_status=""
# What action has to be performed now?
for k in $action_value; do
    if [[ $(isInAction $k) -eq 0 ]]; then
        case "${k,,}" in
        fstab)
            Log-Info "We have fstab as option"
            recover_action "$k"
            recover_status=0
            ;;
        kernel)
            Log-Info "We have kernel as option"
            recover_action "$k"
            recover_status=0
            ;;
        initrd)
            Log-Info "We have initrd as option"
            recover_action "$k"
            recover_status=0
            ;;
        esac
    fi
done

#Clean up everything
cd /
for i in dev/pts proc tmp sys dev; do umount /mnt/rescue-root/"$i"; done

if [[ "$isUbuntu" == "true" || "$isSuse" == "true" ]]; then
    #is this really needed for Suse?
    umount /mnt/rescue-root/run
    if [[ -d /mnt/rescue-root/boot/efi ]]; then
        umount /mnt/rescue-root/boot/efi
    fi
fi

if [[ "${isLVM}" == "true" ]]; then
    umount /mnt/rescue-root/tmp
    umount /mnt/rescue-root/opt
    umount /mnt/rescue-root/usr
    umount /mnt/rescue-root/var
fi

[[ $(mountpoint -q /mnt/rescue_root/boot) -eq 0 ]] && umount /mnt/rescue-root/boot && rm -d /mnt/rescue-root/boot


umount /mnt/rescue-root
rm -fr /mnt/rescue-root
rm -fr "${tmp_dir}"

if [[ "${recover_status}" == "11" ]]; then
    Log-Error "The recover action throwed an error"
    exit $STATUS_ERROR
else
    exit $STATUS_SUCCESS
fi