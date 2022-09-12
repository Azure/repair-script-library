#![allow(non_snake_case)]

use crate::constants;
use crate::distro;
use crate::helper;
use crate::mount;

pub(crate) fn verify_ubuntu(mut distro: &mut distro::Distro) {
    if let Err(e) = mount::mkdir_assert() {
        panic!(
            "Creating assert directory is not possible: {} ALAR is not able to proceed further",
            e
        );
    }

    mount::mount_path_assert(distro.rescue_root.root_part_path.as_str());
    let pretty_name = helper::get_pretty_name(constants::OS_RELEASE);
    mount::umount(constants::ASSERT_PATH);

    if mount::rmdir(constants::ASSERT_PATH).is_err() {
        helper::log_debug("ASSERT_PATH can not be removed. This is a minor issue. ALAR is able to continue further");
    }

    if pretty_name.contains("Ubuntu") {
        distro.kind = distro::DistroKind::Ubuntu;
    }

    if pretty_name.contains("Debian") {
        distro.kind = distro::DistroKind::Debian;
    }
}

pub(crate) fn do_ubuntu(mut partition_info: Vec<String>, mut distro: &mut distro::Distro) {
   

    // Get the right partitions
    // Get the root partition info first
    let mut partition_info_copy = partition_info.to_owned(); // we need a copy for later usage
    partition_info.retain(|x| !(x.contains("EF00") || x.contains("EF02")) ); //remove the UEFI and the bios_boot partition
   

    distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(&partition_info[0]);
    distro.rescue_root.root_part_number = helper::get_partition_number_detail(&partition_info[0]);
    distro.rescue_root.root_part_path = format!("{}{}", helper::read_link(constants::RESCUE_DISK),distro.rescue_root.root_part_number);

    helper::log_info(&distro.rescue_root.root_part_path);

    helper::fsck_partition(
        distro.rescue_root.root_part_path.as_str(),
        distro.rescue_root.root_part_fs.as_str(),
    );

    // Get EFI partition
    partition_info_copy.retain(|x| x.contains("EF00")); //Get the UEFI partition
    helper::set_efi_part_number_and_fs(distro, &partition_info_copy[0]);
    helper::set_efi_part_path(distro);
    helper::fsck_partition(
        helper::get_efi_part_path(distro).as_str(),
        helper::get_efi_part_fs(distro).as_str(),
    );

    //verify_ubuntu(distro);
}
