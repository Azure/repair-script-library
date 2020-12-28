use std::{fs, process};

use crate::ade;
use crate::constants;
use crate::distro;
use crate::helper;
use crate::mount;

use cmd_lib::{run_cmd, run_fun};

pub(crate) fn do_redhat_lvm_or(partition_info: &Vec<String>, distro: &mut distro::Distro) {
    let mut contains_lvm_partition: bool = false;

    for partition in partition_info.iter() {
        if partition.contains("lvm") {
            contains_lvm_partition = true;
        }
    }

    if contains_lvm_partition == true {
        do_redhat_lvm(partition_info, distro);
    } else {
        if partition_info.len() == 1 {
            do_centos_single_partition(distro);
        } else {
            do_redhat_nolvm(partition_info, distro);
        }
    }
}

pub(crate) fn do_redhat6_or_7(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    if !distro.is_ade {
        for partition in partition_info {
            if helper::get_partition_number_detail(partition) == 1 {
                distro.boot_part.boot_part_number = 1;
                distro.boot_part.boot_part_fs = helper::get_partition_filesystem_detail(partition);
            }

            if helper::get_partition_number_detail(partition) == 2 {
                distro.rescue_root.root_part_number = 2;
                distro.rescue_root.root_part_fs =
                    helper::get_partition_filesystem_detail(partition);
            }
        }

        distro.rescue_root.root_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.rescue_root.root_part_number
            )
            .as_str(),
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        distro.boot_part.boot_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.boot_part.boot_part_number
            )
            .as_str(),
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

fn do_redhat_nolvm(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
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

        // Unfortunately we need to work with hardcoded values as there exist no label information
        distro.boot_part.boot_part_fs = "xfs".to_string();
        distro.boot_part.boot_part_number = 1;

        distro.rescue_root.root_part_fs = "xfs".to_string();
        distro.rescue_root.root_part_number = 2;

        //For EFI partition we use normal logic in order to setup the details correct
        for partition in partition_info.iter() {
            if partition.contains("EFI") {
                helper::set_efi_part_number_and_fs(&mut distro, &partition);
            }
        }

        // In the next steps we have to set the partition path correct and do a fsck on them

        distro.rescue_root.root_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.rescue_root.root_part_number
            )
            .as_str(),
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        distro.boot_part.boot_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.boot_part.boot_part_number
            )
            .as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        );

        helper::set_efi_part_path(&mut distro);

        helper::fsck_partition(
            helper::get_efi_part_path(&distro).as_str(),
            helper::get_efi_part_fs(&distro).as_str(),
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

fn do_redhat_lvm(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    helper::log_info("This is a recent RedHat or CentOS image with 4 partitions and LVM signature");
    distro.is_lvm = true;

    // At first we need to prepare the LVM setup
    match run_cmd!(pvscan -q -q; vgscan -q -q; lvscan -q -q;) {
        Ok(_) => {}
        Err(error) => panic!("There is a problem to setup LVM correct. {}", error),
    }

    if !distro.is_ade {
        // TMP is required for the macro run_fun! or run_cmd!
        let TMP = constants::PARTITION_TMP;

        for partition in partition_info {
            let _ = run_cmd!(echo $partition > $TMP);
            if let Ok(name) = run_fun!(grep -s -v EFI $TMP | grep -v lvm | grep -v bios) {
                helper::log_debug(&name);
                distro.boot_part.boot_part_fs =
                    helper::get_partition_filesystem_detail(&name.as_str());
                distro.boot_part.boot_part_number =
                    helper::get_partition_number_detail(&name.as_str());
            }

            if let Ok(name) = run_fun!(grep -s lvm $TMP) {
                helper::log_debug(&name);
                distro.rescue_root.root_part_fs =
                    helper::get_partition_filesystem_detail(&name.as_str());
                distro.rescue_root.root_part_number =
                    helper::get_partition_number_detail(&name.as_str());
            }

            if partition.contains("EFI") {
                helper::log_debug(format!("UEFI partition is '{}'", &partition).as_str());
                helper::set_efi_part_number_and_fs(&mut distro, &partition);
            }
        }

        distro.rescue_root.root_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.rescue_root.root_part_number
            )
            .as_str(),
        );

        helper::fsck_partition(
            distro.rescue_root.root_part_path.as_str(),
            distro.rescue_root.root_part_fs.as_str(),
        );

        distro.boot_part.boot_part_path = helper::read_link(
            format!(
                "{}{}",
                constants::LUN_PART_PATH,
                distro.boot_part.boot_part_number
            )
            .as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        );

        helper::set_efi_part_path(&mut distro);

        helper::fsck_partition(
            helper::get_efi_part_path(&distro).as_str(),
            helper::get_efi_part_fs(&distro).as_str(),
        );

        // Set the path details for later usage
        distro.lvm_details.lvm_root_part = lvm_path_helper("rootlv");
        distro.lvm_details.lvm_usr_part = lvm_path_helper("usrlv");
        distro.lvm_details.lvm_var_part = lvm_path_helper("varlv");

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
        panic!("Creating assert directory is not possible : {}. ALAR is not able to proceed further",e);
    }

    mount::mount_path_assert(distro.rescue_root.root_part_path.as_str());

    set_redhat_kind(distro);

    mount::umount(constants::ASSERT_PATH);
    if let Err(_) = mount::rmdir(constants::ASSERT_PATH) {
        helper::log_info("ASSERT_PATH can not be removed. This is a minor issue. ALAR is able to continue further");
    }
}

pub(crate) fn verify_redhat_lvm(distro: &mut distro::Distro) {
    mount::mount_path_assert(distro.lvm_details.lvm_root_part.as_str());

    set_redhat_kind(distro);

    mount::umount(constants::ASSERT_PATH);
}

fn set_redhat_kind(mut distro: &mut distro::Distro) {
    let mut pretty_name = helper::get_pretty_name(constants::OS_RELEASE);
    if pretty_name.len() == 0 {
        // if len is 0 then it points to a RedHat or CentOS 6 distro
        // let us read the correct file instead
        match fs::read_to_string(constants::REDHAT_RELEASE) {
            Ok(value) => pretty_name = value,
            Err(_) => {
                helper::log_error( "It is not possible to determine the OS kind. ALAR is not able to proceed further");
                process::exit(1);
            }
        }
        if pretty_name.contains("CentOS") || pretty_name.contains("Red Hat") {
            helper::log_info(format!("Pretty Name is : {}", &pretty_name).as_str() );
            distro.kind = distro::DistroKind::RedHatCentOS6;
        }
    } else {
        if pretty_name.contains("CentOS") || pretty_name.contains("Red Hat") {
            helper::log_info(format!("Pretty Name is : {}", &pretty_name).as_str() );
            distro.kind = distro::DistroKind::RedHatCentOS;
        }
    }
}

pub(crate) fn lvm_path_helper(lvname: &str) -> String {
    let mut lvpath: String = "".to_string();
    match run_fun!(lvscan | grep $lvname) {
        Ok(value) => {
            if let Some(path) = value.split("'").nth(1) {
                lvpath = path.to_string();
            }
        }
        Err(_) => {}
    }
    lvpath
}

fn _lvm_get_filesystem(lvpath: &str) -> String {
    let mut filesystem = "".to_string();
    match run_fun!(parted -m $lvpath print | grep -E "^ ?[0-9]{1,2} *") {
        Ok(value) => {
            if let Some(path) = value.split(":").nth(4) {
                filesystem = path.to_string();
            }
        }
        Err(_) => {}
    }
    filesystem
}

pub(crate) fn do_centos_single_partition(mut distro: &mut distro::Distro) {
    // It is safe to use hardcoded values
    distro.rescue_root.root_part_path =
        helper::read_link(format!("{}{}", constants::LUN_PART_PATH, 1).as_str());

    helper::fsck_partition(
        distro.rescue_root.root_part_path.as_str(),
        distro.rescue_root.root_part_fs.as_str(),
    );

    // We have a single partition only boot and efi partitions do not need to be set
    verify_redhat_nolvm(distro);
}
