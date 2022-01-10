#![allow(non_snake_case)]

use crate::ade;
use crate::constants;
use crate::distro;
use crate::helper;
use crate::mount;

use cmd_lib::{run_cmd, run_fun};

pub(crate) fn do_redhat_lvm_or(partition_info: Vec<String>, distro: &mut distro::Distro) {
    let mut contains_lvm_partition: bool = false;

    for partition in partition_info.iter() {
        if partition.contains("8E00") {
            contains_lvm_partition = true;
        }
    }

    if contains_lvm_partition {
        do_redhat_lvm(partition_info, distro);
    } else if partition_info.len() == 1 {
        do_centos_single_partition(distro);
    } else {
        do_redhat_nolvm(partition_info, distro);
    }
}

pub(crate) fn do_redhat6_or_7(partition_info: Vec<String>, mut distro: &mut distro::Distro) {
    // this function does handle the condition if only two partitions are available
    if !distro.is_ade {
        if let Some(root_info) = partition_info.iter().find(|x| x.contains("GiB")) {
            distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(root_info);
            distro.rescue_root.root_part_number = helper::get_partition_number_detail(root_info);
            distro.rescue_root.root_part_path = format!(
                "{}{}",
                helper::read_link(constants::RESCUE_DISK),
                distro.rescue_root.root_part_number
            );
        }

        if let Some(boot_info) = partition_info.iter().find(|x| x.contains("MiB")) {
            distro.boot_part.boot_part_fs = helper::get_partition_filesystem_detail(boot_info);
            distro.boot_part.boot_part_number = helper::get_partition_number_detail(boot_info);
            distro.boot_part.boot_part_path = format!(
                "{}{}",
                helper::read_link(constants::RESCUE_DISK),
                distro.boot_part.boot_part_number
            );
        }

        distro.boot_part.boot_part_path = format!(
            "{}{}",
            helper::read_link(constants::RESCUE_DISK),
            distro.boot_part.boot_part_number
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        );

        verify_redhat_nolvm(distro);
    } else {
        // ADE part
        ade::do_redhat6_or_7_ade(partition_info, distro);
    }
}

fn do_redhat_nolvm(mut partition_info: Vec<String>, mut distro: &mut distro::Distro) {
    if !distro.is_ade {
        // 4 partitions with no LVM we find on an 'CentOS Linux release 7.7.1908' for instance
        /*
        Number  Start   End     Size    File system  Name                  Flags
        14      1049kB  5243kB  4194kB                                     bios_grub
        15      5243kB  524MB   519MB   fat16        EFI System Partition  boot
         1      525MB   1050MB  524MB   xfs
         2      1050MB  32.2GB  31.2GB  xfs
         */

        helper::log_info(
            "This is a recent RedHat or CentOS image with 4 partitions and no LVM signature",
        );

        distro.is_lvm = false;
        if let Some(uefi) = partition_info.iter().by_ref().find(|x| x.contains("EF00")) {
            helper::set_efi_part_number_and_fs(distro, uefi);
            helper::set_efi_part_path(distro);
        }

        partition_info.retain(|x| !(x.contains("EF00") || x.contains("EF02")));
        //remove the UEFI the bios_boot partition. We have two partitions left

        // We need to determine what part is the root and what part is the boot one.
        if let Some(root_info) = partition_info.iter().find(|x| x.contains("GiB")) {
            distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(root_info);
            distro.rescue_root.root_part_number = helper::get_partition_number_detail(root_info);
            distro.rescue_root.root_part_path = format!(
                "{}{}",
                helper::read_link(constants::RESCUE_DISK),
                distro.rescue_root.root_part_number
            );
        }

        if let Some(boot_info) = partition_info.iter().find(|x| x.contains("MiB")) {
            distro.boot_part.boot_part_fs = helper::get_partition_filesystem_detail(boot_info);
            distro.boot_part.boot_part_number = helper::get_partition_number_detail(boot_info);
            distro.boot_part.boot_part_path = format!(
                "{}{}",
                helper::read_link(constants::RESCUE_DISK),
                distro.boot_part.boot_part_number
            );
        }

        distro.boot_part.boot_part_path = format!(
            "{}{}",
            helper::read_link(constants::RESCUE_DISK),
            distro.boot_part.boot_part_number
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        );

        helper::fsck_partition(
            helper::get_efi_part_path(distro).as_str(),
            helper::get_efi_part_fs(distro).as_str(),
        );
        verify_redhat_nolvm(distro);
    } else {
        // This an ADE enabled OS

        helper::log_info(
            "This is a recent RedHat or CentOS image with 4 partitions and no LVM signature",
        );
        helper::log_info("An ADE signature got identified");
        distro.is_lvm = false;
        ade::do_redhat_nolvm_ade(partition_info, distro);
    }
}

fn do_redhat_lvm(mut partition_info: Vec<String>, mut distro: &mut distro::Distro) {
    helper::log_info("This is a recent RedHat or CentOS image with 4 partitions and LVM signature");
    distro.is_lvm = true;

    // At first we need to prepare the LVM setup
    match run_cmd!(pvscan -q -q; vgscan -q -q; lvscan -q -q;) {
        Ok(_) => {}
        Err(error) => panic!("There is a problem to setup LVM correct. {}", error),
    }

    if !distro.is_ade {
        if let Some(lvm_info) = partition_info.iter().find(|x| x.contains("8E00")) {
            distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(lvm_info);
            distro.rescue_root.root_part_number = helper::get_partition_number_detail(lvm_info);
            distro.rescue_root.root_part_path = format!(
                "{}{}",
                helper::read_link(constants::RESCUE_DISK),
                distro.rescue_root.root_part_number
            );
        }

        if let Some(uefi) = partition_info.iter().by_ref().find(|x| x.contains("EF00")) {
            helper::set_efi_part_number_and_fs(distro, uefi);
            helper::set_efi_part_path(distro);
        }

        partition_info
            .retain(|x| !(x.contains("EF00") || x.contains("EF02") || x.contains("8E00")));
        //remove the UEFI the bios_boot and the root partition to get the boot partition only

        distro.boot_part.boot_part_fs = helper::get_partition_filesystem_detail(&partition_info[0]);
        distro.boot_part.boot_part_number = helper::get_partition_number_detail(&partition_info[0]);
        distro.boot_part.boot_part_path = format!(
            "{}{}",
            helper::read_link(constants::RESCUE_DISK),
            distro.boot_part.boot_part_number
        );

        distro.boot_part.boot_part_path = format!(
            "{}{}",
            helper::read_link(constants::RESCUE_DISK),
            distro.boot_part.boot_part_number
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        );

        helper::fsck_partition(
            helper::get_efi_part_path(distro).as_str(),
            helper::get_efi_part_fs(distro).as_str(),
        );

        // Set the path details for later usage
        distro.lvm_details.lvm_root_part = lvm_path_helper("rootlv");
        distro.lvm_details.lvm_usr_part = lvm_path_helper("usrlv");
        distro.lvm_details.lvm_var_part = lvm_path_helper("varlv");

        helper::log_info(&format!("LVM Details '{:?}'", &distro.lvm_details));
        verify_redhat_lvm(distro);
    } else {
        // Ade part
        helper::log_info(
            "This is a recent RedHat or CentOS image with 4 partitions and LVM signature",
        );
        helper::log_info("An ADE signature got identified");

        ade::do_redhat_lvm_ade(partition_info, distro);
    }
}

// verify_redhat_nolvm does set the DistroKind to either RedHatCentOS or RedHatCentOS6
// if the verification is succesful
pub(crate) fn verify_redhat_nolvm(distro: &mut distro::Distro) {
    if let Err(e) = mount::mkdir_assert() {
        panic!(
            "Creating assert directory is not possible : {}. ALAR is not able to proceed further",
            e
        );
    }

    mount::mount_path_assert(distro.rescue_root.root_part_path.as_str());

    set_redhat_kind(distro);

    mount::umount(constants::ASSERT_PATH);
    if mount::rmdir(constants::ASSERT_PATH).is_err() {
        helper::log_debug("ASSERT_PATH can not be removed. This is a minor issue. ALAR is able to continue further");
    }
}

pub(crate) fn verify_redhat_lvm(distro: &mut distro::Distro) {
    if let Err(e) = mount::mkdir_assert() {
        panic!(
            "Creating assert directory is not possible : {}. ALAR is not able to proceed further",
            e
        );
    }
    mount::mount_path_assert(distro.lvm_details.lvm_root_part.as_str());

    set_redhat_kind(distro);

    mount::umount(constants::ASSERT_PATH);
}

fn set_redhat_kind(mut distro: &mut distro::Distro) {
    let pretty_name = helper::get_pretty_name(constants::OS_RELEASE);
    if pretty_name.contains("6.") {
        helper::log_info(format!("Pretty Name is : {}", &pretty_name).as_str());
        distro.kind = distro::DistroKind::RedHatCentOS6;
    } else {
        helper::log_info(format!("Pretty Name is : {}", &pretty_name).as_str());
        distro.kind = distro::DistroKind::RedHatCentOS;
    }
}

pub(crate) fn lvm_path_helper(lvname: &str) -> String {
    let mut lvpath: String = "".to_string();
    if let Ok(value) = run_fun!(lvscan | grep $lvname) {
        if let Some(path) = value.split('\'').nth(1) {
            lvpath = path.to_string();
        }
    }
    lvpath
}

pub(crate) fn do_centos_single_partition(mut distro: &mut distro::Distro) {
    // It is safe to use hardcoded values
    distro.rescue_root.root_part_path =
        format!("{}{}", helper::read_link(constants::RESCUE_DISK), 1);
    helper::fsck_partition(
        distro.rescue_root.root_part_path.as_str(),
        distro.rescue_root.root_part_fs.as_str(),
    );

    // We have a single partition only boot and efi partitions do not need to be set
    verify_redhat_nolvm(distro);
}
