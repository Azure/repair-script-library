use crate::constants;
use crate::distro;
use crate::helper;
use crate::mount;
use crate::redhat;
use crate::ubuntu;

/*

At first we need to find out whether we have to work on an encrypted OS
We can do this with lsblk in order to find out whether we have a device with the name osencrypt available

 lsblk
NAME                MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINT
sda                   8:0    0   48M  0 disk
└─sda1                8:1    0   46M  0 part  /mnt/azure_bek_disk
sdb                   8:16   0   30G  0 disk
├─sdb1                8:17   0 29.9G  0 part  /
├─sdb14               8:30   0    4M  0 part
└─sdb15               8:31   0  106M  0 part  /boot/efi
sdc                   8:32   0   64G  0 disk
├─sdc1                8:33   0  500M  0 part  /tmp/dev/sdc1
├─sdc2                8:34   0  500M  0 part  /investigateroot/boot
├─sdc3                8:35   0    2M  0 part
└─sdc4                8:36   0   63G  0 part
  └─osencrypt       253:0    0   63G  0 crypt
    ├─rootvg-tmplv  253:1    0    2G  0 lvm   /investigateroot/tmp
    ├─rootvg-usrlv  253:2    0   10G  0 lvm   /investigateroot/usr
    ├─rootvg-optlv  253:3    0    2G  0 lvm   /investigateroot/opt
    ├─rootvg-homelv 253:4    0    1G  0 lvm   /investigateroot/home
    ├─rootvg-varlv  253:5    0    8G  0 lvm   /investigateroot/var
    └─rootvg-rootlv 253:6    0    2G  0 lvm   /investigateroot
sdd                   8:48   0   50G  0 disk
└─sdd1                8:49   0   50G  0 part  /mnt
sr0                  11:0    1  628K  0 rom

In the next step it is required to unmount all of LVM LVs.
This is due to the fact that we need to do a fs-check on all of the partitions. This we have to do for the boot
and EFI partition as well.

In the next step we mount them again on the usual paths for ALAR

------

On a non LVM system we need to do the similar steps
On an Ubuntu 16.x distro we have these details

 lsblk
NAME          MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINT
sda             8:0    0   50G  0 disk
└─sda1          8:1    0   50G  0 part  /mnt
sdb             8:16   0   48M  0 disk
└─sdb1          8:17   0   46M  0 part  /mnt/azure_bek_disk
sdc             8:32   0   30G  0 disk
├─sdc1          8:33   0 29.9G  0 part  /
├─sdc14         8:46   0    4M  0 part
└─sdc15         8:47   0  106M  0 part  /boot/efi
sdd             8:48   0   30G  0 disk
├─sdd1          8:49   0 29.7G  0 part
│ └─osencrypt 253:0    0 29.7G  0 crypt /investigateroot
├─sdd2          8:50   0  256M  0 part  /investigateroot/boot
├─sdd14         8:62   0    4M  0 part
└─sdd15         8:63   0  106M  0 part  /tmp/dev/sdd15
sr0            11:0    1  628K  0 rom

Ubuntu 16 or 18 don't have a seperate boot partition
If ADE is used on them an extra partition is created to store the boot and luks part on an not encrypted
partition

*/

pub(crate) fn is_ade_enabled() -> bool {
    cmd_lib::run_cmd!(lsblk | grep -q osencrypt).is_ok()
}

pub(crate) fn do_ubuntu_ade(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    helper::log_info("This is a recent Ubuntu 16.x/18.x with ADE enabled");

    // Only get the EFI partition
    // The root part we set manually later as we have a crypt filesystem on the usual root partition
    for partition in partition_info {
        if partition.contains("boot") {
            helper::set_efi_part_number_and_fs(&mut distro, partition);
        }
    }
    helper::set_efi_part_path(&mut distro);

    // Set the root_part_path manually
    distro.rescue_root.root_part_path = constants::OSENCRYPT_PATH.to_string();

    set_root_part_fs(&mut distro);

    // Due to the changed partition layout on an ADE enabled OS we have to set the boot partiton details
    // We use hardcoded values in this case
    distro.boot_part.boot_part_fs = "ext2".to_string();
    distro.boot_part.boot_part_number = 2;
    distro.boot_part.boot_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.boot_part.boot_part_number
        )
        .as_str(),
    );

    // Due to the fact that we have already mounted filesystems for ADE on a repair-vm
    // we need to unmount them first before we can do a fsck on each of the partitions
    umount_investigations(distro);
    fsck_partitions(distro);

    ubuntu::verify_ubuntu(distro);
}

pub(crate) fn do_redhat_nolvm_ade(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    // Unfortunately we need to work with hardcoded values as there exist no label information
    distro.boot_part.boot_part_fs = "xfs".to_string();
    distro.boot_part.boot_part_number = 1;

    set_root_part_fs(&mut distro);
    distro.rescue_root.root_part_number = 2;

    // Set the root_part_path manually for ADE
    distro.rescue_root.root_part_path = constants::OSENCRYPT_PATH.to_string();

    //For EFI partition we use normal logic in order to setup the details correct
    for partition in partition_info.iter() {
        if partition.contains("EFI") {
            helper::set_efi_part_number_and_fs(&mut distro, &partition);
        }
    }

    distro.boot_part.boot_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.boot_part.boot_part_number
        )
        .as_str(),
    );

    helper::set_efi_part_path(&mut distro);

    //Unmount the investigation path, otherwise the fsck isn't possible
    umount_investigations(distro);
    fsck_partitions(distro);

    redhat::verify_redhat_nolvm(distro);
}

pub(crate) fn do_redhat6_or_7_ade(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
// Unfortunately we need to work with hardcoded values as there exist no label information
    distro.boot_part.boot_part_fs = "xfs".to_string();
    distro.boot_part.boot_part_number = 1;

    set_root_part_fs(&mut distro);
    distro.rescue_root.root_part_number = 2;

    // Set the root_part_path manually for ADE
    distro.rescue_root.root_part_path = constants::OSENCRYPT_PATH.to_string();

    distro.boot_part.boot_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.boot_part.boot_part_number
        )
        .as_str(),
    );

    //Unmount the investigation path, otherwise the fsck isn't possible
    umount_investigations(distro);
    fsck_partitions(distro);

    redhat::verify_redhat_nolvm(distro);
}

pub(crate) fn do_redhat_lvm_ade(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    /*
     Unfortunately we need to work with hardcoded values as there exist no label information

     Number  Start   End     Size    File system  Name                  Flags
    1      1049kB  525MB   524MB   fat16        EFI System Partition  boot, esp
    2      525MB   1050MB  524MB   xfs                                msftdata
    3      1050MB  1052MB  2097kB                                     bios_grub
    4      1052MB  68.7GB  67.7GB                                     lvm
    */

    distro.boot_part.boot_part_fs = "xfs".to_string();
    distro.boot_part.boot_part_number = 2;

    set_root_part_fs(&mut distro);
    distro.rescue_root.root_part_number = 4;

    // Set the root_part_path manually for ADE
    distro.rescue_root.root_part_path = constants::OSENCRYPT_PATH.to_string();

    //For EFI partition we use normal logic in order to setup the details correct
    for partition in partition_info.iter() {
        if partition.contains("EFI") {
            helper::set_efi_part_number_and_fs(&mut distro, &partition);
        }
    }

    distro.boot_part.boot_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.boot_part.boot_part_number
        )
        .as_str(),
    );

    helper::set_efi_part_path(&mut distro);

    // LVM mounts need to be removed. We need to remount them later
    umount_investigations_lvm();
    //Unmount the investigation path, otherwise the fsck isn't possible
    umount_investigations(distro);
    fsck_partitions(distro);

    // Set the LVM path details in order to work with ADE
    distro.lvm_details.lvm_root_part = redhat::lvm_path_helper("rootlv");
    distro.lvm_details.lvm_usr_part = redhat::lvm_path_helper("usrlv");
    distro.lvm_details.lvm_var_part = redhat::lvm_path_helper("varlv");


    redhat::verify_redhat_lvm(distro);
}

fn fsck_partitions(distro: &distro::Distro) {
    helper::fsck_partition(
        distro.rescue_root.root_part_path.as_str(),
        distro.rescue_root.root_part_fs.as_str(),
    );

    helper::fsck_partition(
        distro.boot_part.boot_part_path.as_str(),
        distro.boot_part.boot_part_fs.as_str(),
    );

    helper::fsck_partition(
        helper::get_efi_part_path(&distro).as_str(),
        helper::get_efi_part_fs(&distro).as_str(),
    );
}

fn umount_investigations(distro: &distro::Distro) {
    // umount EFI
    mount::umount(helper::get_ade_mounpoint(helper::get_efi_part_path(distro).as_str()).as_str());

    // umount boot
    mount::umount(helper::get_ade_mounpoint(distro.boot_part.boot_part_path.as_str()).as_str());

    // umount osencrypt
    if !distro.is_lvm {
        //  If it is LVM we have already unmounted the '/investigationroot'
        mount::umount(helper::get_ade_mounpoint(distro.rescue_root.root_part_path.as_str()).as_str());
    } 
    
}

fn umount_investigations_lvm() {
    /*
        These are the mounts we have to remove
        └─sdc4                8:36   0   63G  0 part
            └─osencrypt       253:0    0   63G  0 crypt
            ├─rootvg-tmplv  253:1    0    2G  0 lvm   /investigateroot/tmp
            ├─rootvg-usrlv  253:2    0   10G  0 lvm   /investigateroot/usr
            ├─rootvg-optlv  253:3    0    2G  0 lvm   /investigateroot/opt
            ├─rootvg-homelv 253:4    0    1G  0 lvm   /investigateroot/home
            ├─rootvg-varlv  253:5    0    8G  0 lvm   /investigateroot/var
            └─rootvg-rootlv 253:6    0    2G  0 lvm   /investigateroot
    */
    mount::umount("/investigateroot/tmp");
    mount::umount("/investigateroot/usr");
    mount::umount("/investigateroot/opt");
    mount::umount("/investigateroot/home");
    mount::umount("/investigateroot/var");
    mount::umount("/investigateroot");
}

fn set_root_part_fs(mut distro: &mut distro::Distro) {
    if let Ok(line) = cmd_lib::run_fun!(lsblk -fn /dev/mapper/osencrypt) {
        distro.rescue_root.root_part_fs = helper::cut(line.as_str(), " ", 1).to_string();
    }
}
