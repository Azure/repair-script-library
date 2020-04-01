#!/bin/bash

# Partition Rules
# ================
# One partition -> Ubuntu
# Two partitions -> Redhat 6.x, 7,x
# Tree partitions -->  a recent Ubuntu 16.x or 18.x
# Four partitions -> Suse
# Two partitions with one of it a LVM flagged one -> RedHAt with LVM

# Global redirection for ERR to STD
exec 2>&1

# Declare array
a_part_info=()

# Functions
# ---------

whatFs() {
	case "${1}" in
	ext4)
		isExt4="true"
		;;
	ext3)
		isExt3="true"
		;;
	xfs)
		isXFS="true"
		;;
	esac
}

fsck_partition() {
	# $1 holds the type of the filesystem we need to check
	# $2 holds the partiton info
	if [[ "$1" == "xfs" ]]; then
		xfs_repair -n "$2" > /dev/null 2>&1 
	elif [[ "$1" == "fat16" ]]; then
		fsck.vfat -p "$2" > /dev/null 2>&1
	else
		fsck."$1" -p "$2" > /dev/null 2>&1
	fi

	if [[ "$?" == 4 ]]; then
		# error 4 is returned by fsck.ext4 only
		echo  "${root_rescue} is not able to be automatically recovered. Aborting ALAR"
		exit 1
	fi

	if [[ "${isXFS}" == "true" && "$?" == 1 ]]; then
		# xfs_repair -n returns 1 if the fs is corrupted. 
		# Also fsck may raise this error but we ignore it as even a normal recover is raising it. FALSE-NEGATIVE
		echo "A general error occured while trying to recover the device ${root_rescue}. Aborting ALAR"
		exit 1
	fi

	echo "The error state/number is: $?" 
}

verifyRedHat() {
	if [[ ! -d /tmp/assert ]]; then
		mkdir /tmp/assert
	fi

	if [[ "${isLVM}" == "true" ]]; then
		pvscan > /dev/null 2>&1 
		vgscan > /dev/null 2>&1
		lvscan > /dev/null 2>&1
		local fs=$(parted $(lvscan | grep rootlv | awk '{print $2}' | tr -d "'") print | grep -E '^ ?[0-9]{1,2} *' | awk '{print $5}')
		# Set variable rescue_root to the right LV name
		rescue_root=$(lvscan | grep rootlv | awk '{print $2}' | tr -d "'")
		fsck_partition "${fs}" "${rescue_root}"
		mount $(lvscan | grep rootlv | awk '{print $2}' | tr -d "'") /tmp/assert
	else
		# The file system got globally defiend before
		fsck_partition "${root_part_fs}" "${rescue_root}"
		mount "${rescue_root}" /tmp/assert
	fi

	if [[ -e /tmp/assert/etc/os-release ]]; then
		PRETTY_NAME="$(grep PRETTY_NAME /tmp/assert/etc/os-release)"
		PRETTY_NAME="${PRETTY_NAME##*=}"
		case "${PRETTY_NAME}" in
		*CentOS* | *Red\ Hat*)
			isRedHat="true"
			osNotSupported="false"
			whatFs ${root_part_fs}
			;;
		esac
	else
		if [[ -e /tmp/assert/etc/redhat-release ]]; then
			PRETTY_NAME="$(cat /tmp/assert//etc/redhat-release)"
			PRETTY_NAME="${PRETTY_NAME##*=}"
			case "${PRETTY_NAME}" in
			*CentOS* | *Red\ Hat*)
				isRedHat="true"
				isRedHat6="true"
				osNotSupported="false"
				whatFs ${root_part_fs}
				;;
			esac
		fi
	fi
	# clean up
	umount /tmp/assert
	rm -fr /tmp/assert
}

verifyUbuntu() {
	if [[ ! -d /tmp/assert ]]; then
		mkdir /tmp/assert
	fi
	fsck_partition "${root_part_fs}" "${rescue_root}"
	mount "${rescue_root}" /tmp/assert
	if [[ -e /tmp/assert/etc/os-release ]]; then
		PRETTY_NAME="$(grep PRETTY_NAME /tmp/assert/etc/os-release)"
		PRETTY_NAME="${PRETTY_NAME##*=}"
		case "${PRETTY_NAME}" in
		*Ubuntu*)
			isUbuntu="true"
			osNotSupported="false"
			whatFs ${root_part_fs}
			;;
		esac
	else
		isUbuntu="false"
		osNotSupported="true"
		whatFs ${root_part_fs}
	fi
	# clean up
	umount /tmp/assert
	rm -fr /tmp/assert
}

verifySuse() {
	if [[ ! -d /tmp/assert ]]; then
		mkdir /tmp/assert
	fi
	fsck_partition "${root_part_fs}" "${rescue_root}"
	mount "$rescue_root" /tmp/assert
	if [[ -e /tmp/assert/etc/os-release ]]; then
		PRETTY_NAME="$(grep PRETTY_NAME /tmp/assert/etc/os-release)"
		PRETTY_NAME="${PRETTY_NAME##*=}"
		case "${PRETTY_NAME}" in
		*SUSE*)
			isSuse="true"
			osNotSupported="false"
			whatFs ${root_part_fs}
			;;
		esac
	else
		isSuse="false"
		osNotSupported="true"
		whatFs ${root_part_fs}
	fi
	# clean up
	umount /tmp/assert
	rm -fr /tmp/assert
}
# Logic
# -----

# Get partition info/details
for i in $(sudo echo I | parted "$(readlink -f /dev/disk/azure/scsi1/lun0)" print | grep -E '^ ?[0-9]{1,2} *' | awk '{print $1 ":" $5 ":" $6 ":" $7 ":" $8 "$"}'); do
	a_part_info+=($i)
done

#for i in $(echo I | parted /dev/sda print | grep -E '^ ?[0-9]{1,2} *' | awk '{print $1 ":" $5 ":" $6 ":" $7 ":" $8 "$"}'); do
#a_part_info+=($i)
#done

# Old Ubuntu?
if [[ "${#a_part_info[@]}" -eq 1 ]]; then
	echo "This could be an old Ubuntu image"
	root_part_number=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f1)
	root_part_fs=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f3)

	rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
	verifyUbuntu
fi

# RedHat 6.x or 7.x?
if [[ "${#a_part_info[@]}" -eq 2 ]]; then
	echo "This could be a RedHat/Centos 6/7 image"
	boot_part_number=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f1)
	boot_part_fs=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f3)
	root_part_number=$(for i in "${a_part_info[@]}"; do grep -v boot <<<"$i"; done | cut -d':' -f1)
	root_part_fs=$(for i in "${a_part_info[@]}"; do grep -v boot <<<"$i"; done | cut -d':' -f3)

	# RedHat 6.x does have ext4 filesystem
	# Whereas RedHat 7.x does have the XFS filesystem
	if [[ "$root_part_fs" == "ext4" ]]; then
		isRedHat6="true"
	else
		isXFS="true"
	fi

	# Check whether we have a LVM system.
	if [[ "$root_part_fs" == "lvm" ]]; then
		isLVM="true"
	fi

	# Set root_rescue and boot_part in order to mount the disk correct
	# In case we have a LVM system we handle this in more detail in  base.sh
	rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
	boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
	fsck_partition "${boot_part_fs}" "${boot_part}"
	verifyRedHat # In case we have LVM partitions after this point the variable "rescue_root" is overwritten with the correct value

fi

# Recent Ubuntu?
if [[ "${#a_part_info[@]}" -eq 3 ]]; then
	echo "This could be a recent Ubuntu 16.x or 18.x image"

	# Check whether we have a Freebsd image. They have three partitions as well but we do not support this OS
	if [[ "${a_part_info[@]}" =~ "freebsd" ]]; then
		echo "Freebsd is not a supported OS. ALAR tool is stopped"
		osNotSupported="true"
	else
		boot_part_number=$(for i in "${a_part_info[@]}"; do grep boot <<<"$i"; done | cut -d':' -f1)
		efi_part_number=$(for i in "${a_part_info[@]}"; do grep bios <<<"$i"; done | cut -d':' -f1)
		root_part_number=$(for i in "${a_part_info[@]}"; do grep -v bios <<<"$i" | grep -v boot; done | cut -d':' -f1)
		root_part_fs=$(for i in "${a_part_info[@]}"; do grep -v bios <<<"$i" | grep -v boot; done | cut -d':' -f2)
		boot_part_fs=$(for i in "${a_part_info[@]}"; do grep -v boot <<<"$i"; done | cut -d':' -f2)
		efi_part_fs=$(for i in "${a_part_info[@]}"; do grep -v bios <<<"$i"; done | cut -d':' -f2)

		# Set root_rescue and boot_part in order to mount the disk correct
		rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
		boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
		fsck_partition "${boot_part_fs}" "${boot_part}"
		efi_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${efi_part_number}")
		fsck_partition "${efi_part_fs}" "${efi_part}"
		verifyUbuntu
	fi
fi

#Suse 12 or 15?
if [[ "${#a_part_info[@]}" -eq 4 ]]; then
	echo "This could be a SUSE 12 or 15 image"
	# Get boot partition
	boot_part_number=$(for i in "${a_part_info[@]}"; do grep lxboot <<<"$i"; done | cut -d':' -f1)
	efi_part_number=$(for i in "${a_part_info[@]}"; do grep UEFI <<<"$i"; done | cut -d':' -f1)
	root_part_number=$(for i in "${a_part_info[@]}"; do grep lxroot <<<"$i"; done | cut -d':' -f1)
	root_part_fs=$(for i in "${a_part_info[@]}"; do grep lxroot <<<"$i"; done | cut -d':' -f2)
	boot_part_fs=$(for i in "${a_part_info[@]}"; do grep lxboot <<<"$i"; done | cut -d':' -f2)
	efi_part_fs=$(for i in "${a_part_info[@]}"; do grep UEFI <<<"$i"; done | cut -d':' -f2)

	# Set root_rescue and boot_part in order to mount the disk correct
	rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
	boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
	fsck_partition "${boot_part_fs}" "${boot_part}"
	efi_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${efi_part_number}")
	fsck_partition "${efi_part_fs}" "${efi_part}"
	verifySuse
fi

# No standard image
if [[ "${#a_part_info[@]}" -gt 4 ]]; then
	echo "Unrecognized Linux distribution. ALAR tool is stopped"
	osNotSupported="true"
fi

