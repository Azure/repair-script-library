#!/bin/bash

# Partition Rules
# ================
# One partition -> Ubuntu
# Two partitions -> Redhat 6.x, 7,x
# Tree partitions -->  a recent Ubuntu 16.x or 18.x
# Four partitions -> Suse
# Two partitions with one of it a LVM flagged one -> RedHAt with LVM

# Global redirection for ERR to STD
#exec 2>&1

# Declare array
declare -A a_part_info

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
	Log-Info "File system check start"
	if [[ "$1" == "xfs" ]]; then
		Log-Info "fsck part $2"
		xfs_repair -n "$2" > /dev/null 2>&1 
	elif [[ "$1" == "fat16" ]]; then
		Log-Info "fsck part $2"
		fsck.vfat -p "$2" > /dev/null 2>&1
	else
		Log-Info "fsck part $2"
		fsck."$1" -p "$2" > /dev/null 2>&1
	fi

	if [[ "$?" == 4 ]]; then
		# error 4 is returned by fsck.ext4 only
		Log-Info  "Partition ${2} is not able to be automatically recovered. Aborting ALAR"
		exit 1
	fi

	if [[ "${isXFS}" == "true" && "$?" == 1 ]]; then
		# xfs_repair -n returns 1 if the fs is corrupted. 
		# Also fsck may raise this error but we ignore it as even a normal recover is raising it. FALSE-NEGATIVE
		Log-Info "A general error occured while trying to recover the device ${root_rescue}. Aborting ALAR"
		exit 1
	fi

	Log-Info "The error state/number is: $?" 
	Log-Info "File system check finished"
}

verifyRedHat() {
	if [[ ! -d /tmp/assert ]]; then
		mkdir /tmp/assert;
	fi

	if [[ "${isLVM}" == "true" ]]; then
		Log-Info "Verifying LVM setup"
		pvscan > /dev/null 2>&1 
		vgscan > /dev/null 2>&1
		lvscan > /dev/null 2>&1
		root_part_fs=$(parted $(lvscan | grep rootlv | awk '{print $2}' | tr -d "'") print | grep -E '^ ?[0-9]{1,2} *' | awk '{print $5}')
		# Set variable rescue_root to the right LV name
		rescue_root=$(lvscan | grep rootlv | awk '{print $2}' | tr -d "'")
		rescue_usr=$(lvscan | grep usrlv | awk '{print $2}' | tr -d "'")
		fsck_partition "${root_part_fs}" "${rescue_root}"
		# We can use the same FS type in this case
		fsck_partition "${root_part_fs}" "${rescue_usr}"
		mount $(lvscan | grep rootlv | awk '{print $2}' | tr -d "'") /tmp/assert
		mount $(lvscan | grep usrlv | awk '{print $2}' | tr -d "'") /tmp/assert/usr
	else
		# The file system got globally defiend before
		fsck_partition "${root_part_fs}" "${rescue_root}"
		mount "${rescue_root}" /tmp/assert
	fi

	if [[ -e /tmp/assert/etc/os-release ]]; then
		PRETTY_NAME="$(grep PRETTY_NAME /tmp/assert/etc/os-release)"
		PRETTY_NAME="${PRETTY_NAME##*=}"
		echo "PRETTY NAME : ${PRETTY_NAME}"
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
	umount /tmp/assert/usr
	umount /tmp/assert
	rm -fr /tmp/assert
}

verifyUbuntu() {
	if [[ ! -d /tmp/assert ]]; then
		mkdir /tmp/assert;
	fi
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
		mkdir /tmp/assert;
	fi
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

# parted -m /dev/sda print  | grep -E '^ ?[0-9]{1,2} *' | cut -d ':' -f1,5,6,7
# 14:::bios_grub;
# 15:fat16:EFI System Partition:boot, esp;
# 1:xfs::;
# 2:::lvm;
# NAME="CentOS Linux"
# VERSION="8 (Core)"

# parted -m /dev/sda print  | grep -E '^ ?[0-9]{1,2} *' | cut -d ':' -f1,5,6,7
# 14:::bios_grub;
# 15:fat16:EFI System Partition:boot;
# 1:ext4::;
# 2:::lvm;
# [root@alar-cent1 ~]# cat /etc/os-release
# NAME="CentOS Linux"
# VERSION="7 (Core)"

# parted -m /dev/sda print  | grep -E '^ ?[0-9]{1,2} *' | cut -d ':' -f1,5,6,7
# 1:fat16:EFI System Partition:boot;
# 2:xfs::;
# 3:::bios_grub;
# 4:::lvm;
# [root@alar1 ~]# cat /etc/os-release
# NAME="Red Hat Enterprise Linux Server"
# VERSION="7.8 (Maipo)"

# parted -m /dev/sda print  | grep -E '^ ?[0-9]{1,2} *' | cut -d ':' -f1,5,6,7
# 14:::bios_grub;
# 15:fat16:EFI System Partition:boot, esp;
# 1:xfs::;
# 2:::lvm;
# [root@alar2 ~]# cat /etc/os-release
# NAME="Red Hat Enterprise Linux"
# VERSION="8.2 (Ootpa)"
 
OLDIFS=$IFS  
IFS=; # overwriting IFS to use the semicolon as a line seperator
j=0 # Needed as counter 
while read _partition; do   a_part_info[$j]=$_partition; let j++; done <<< $( parted -m "$(readlink -f /dev/disk/azure/scsi1/lun0)" print  | grep -E '^ ?[0-9]{1,2} *')
IFS=$OLDIFS

getPartitionNumberDetail(){
	# $1 key
	local result
	result=$(cut -d ':' -f1 <<< ${a_part_info[$1]})

	echo $result
}

getPartitionFilesystemDetail(){
	# $1 key
	local result
	result=$(cut -d ':' -f5 <<< ${a_part_info[$1]})

	echo $result
}


# Old Ubuntu?
if [[ "${#a_part_info[@]}" -eq 1 ]]; then
	Log-Info "This could be an old Ubuntu image"

	for k in ${!a_part_info[@]}; do 
		grep -q boot <<< ${a_part_info[$k]} && root_part_number=$(getPartitionNumberDetail $k) && root_part_fs=$(getPartitionFilesystemDetail $k); 
	done

	rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
	verifyUbuntu
fi

# RedHat 6.x or 7.x?
if [[ "${#a_part_info[@]}" -eq 2 ]]; then
	Log-Info "This could be a RedHat/Centos 6/7 image"

	for k in ${!a_part_info[@]}; do 
		grep -q boot <<< ${a_part_info[$k]} && boot_part_number=$(getPartitionNumberDetail $k) && boot_part_fs=$(getPartitionFilesystemDetail $k); 
		grep -qv boot <<< ${a_part_info[$k]} && root_part_number=$(getPartitionNumberDetail $k) && root_part_fs=$(getPartitionFilesystemDetail $k); 
	done

	# Check whether we have a LVM system.
	for k in ${!a_part_info[@]}; do 
		grep -q lvm <<< ${a_part_info[$k]} && isLVM="true";
	done

	# RedHat 6.x does have ext4 filesystem
	# Whereas RedHat 7.x does have the XFS filesystem
	if [[ "$root_part_fs" == "ext4" ]]; then
		isRedHat6="true"
	else
		isXFS="true"
	fi


	# Set root_rescue and boot_part in order to mount the disk correct
	# In case we have a LVM system we handle this in more detail in  base.sh
	rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
	if [[ "$isLVM" == "false" ]]; then
		fsck_partition "${root_part_fs}" "${root_part}"
	fi
	boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
	fsck_partition "${boot_part_fs}" "${boot_part}"
	verifyRedHat 

fi

# Recent Ubuntu?
if [[ "${#a_part_info[@]}" -eq 3 ]]; then
	Log-Info "This could be a recent Ubuntu 16.x or 18.x image"

	# Check whether we have a Freebsd image. They have three partitions as well but we do not support this OS
	if [[ "${a_part_info[@]}" =~ "freebsd" ]]; then
		Log-Error "Freebsd is not a supported OS. ALAR tool is stopped"
		osNotSupported="true"
	else
		for k in ${!a_part_info[@]}; do 
			grep -q boot <<< ${a_part_info[$k]} && efi_part_number=$(getPartitionNumberDetail $k) && efi_part_fs=$(getPartitionFilesystemDetail $k); 
			grep -qv 'bios\|boot' <<< ${a_part_info[$k]} && root_part_number=$(getPartitionNumberDetail $k) && root_part_fs=$(getPartitionFilesystemDetail $k); 
		done

		# Set root_rescue and boot_part in order to mount the disk correct
		rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
		fsck_partition "${root_part_fs}" "${rescue_root}"
		efi_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${efi_part_number}")
		isUbuntuEFI="true"
		fsck_partition "${efi_part_fs}" "${efi_part}"
		verifyUbuntu
	fi
fi


if [[ "${#a_part_info[@]}" -eq 4 ]]; then
	# Not sure whethe this is a RedHat or CENTOS with LVM or it is a Suse 12/15 instead
	# Need to make a simple test
	for k in ${!a_part_info[@]}; do
		grep -s lxboot <<< ${a_part_info[$k]} &&  isSuseBoot=true; 
	done

	if [[ "$isSuseBoot" == "true" ]]; then
	#Suse 12 or 15?
		Log-Info "This could be a SUSE 12 or 15 image"
		for k in ${!a_part_info[@]}; do 
			grep -q lxboot <<< ${a_part_info[$k]} && boot_part_number=$(getPartitionNumberDetail $k) && boot_part_fs=$(getPartitionFilesystemDetail $k); 
			grep -q UEFI <<< ${a_part_info[$k]} && efi_part_number=$(getPartitionNumberDetail $k) && efi_part_fs=$(getPartitionFilesystemDetail $k); 
			grep -q lxroot <<< ${a_part_info[$k]} && root_part_number=$(getPartitionNumberDetail $k) && root_part_fs=$(getPartitionFilesystemDetail $k); 
		done

		# Set root_rescue and boot_part in order to mount the disk correct
		rescue_root=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${root_part_number}")
		fsck_partition "${root_part_fs}" "${rescue_root}"
		boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
		fsck_partition "${boot_part_fs}" "${boot_part}"
		efi_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${efi_part_number}")
		fsck_partition "${efi_part_fs}" "${efi_part}"
		verifySuse
	else
		Log-Info "This is a recent RedHat or CentOS image with 4 partitions"
		for k in ${!a_part_info[@]}; do 
			grep -q EFI <<< ${a_part_info[$k]} && efi_part_number=$(getPartitionNumberDetail $k) && efi_part_fs=$(getPartitionFilesystemDetail $k); 
			grep -v EFI <<< ${a_part_info[$k]} | grep -v lvm | grep -v bios &&  boot_part_number=$(getPartitionNumberDetail $k) && boot_part_fs=$(getPartitionFilesystemDetail $k); 
			grep -q lvm <<< ${a_part_info[$k]} &&  lvm_part_number=$(getPartitionNumberDetail $k); 
		done
		# Those images are LVM based	
		isLVM="true"
		# Not a RedHat 6.x system
		isRedHat6="false"
		boot_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${boot_part_number}")
		fsck_partition "${boot_part_fs}" "${boot_part}"
		efi_part=$(readlink -f /dev/disk/azure/scsi1/lun0-part"${efi_part_number}")
		fsck_partition "${efi_part_fs}" "${efi_part}"
		verifyRedHat 
	fi

fi

# No standard image
if [[ "${#a_part_info[@]}" -gt 4 ]]; then
	Log-Error "Unrecognized Linux distribution. ALAR tool is stopped"
	osNotSupported="true"
fi

# DEBUG
# printenv