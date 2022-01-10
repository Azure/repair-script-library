use crate::constants;
use crate::distro;
use crate::helper;

pub(crate) fn do_suse(mut partition_info: Vec<String>, mut distro: &mut distro::Distro) {
    if !distro.is_ade {
        distro.kind = distro::DistroKind::Suse;
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
        
    } else {
        // ADE part
        // Not yet available
        // See --> https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-overview
    }
}
