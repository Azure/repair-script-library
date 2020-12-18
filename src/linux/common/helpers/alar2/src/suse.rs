use crate::constants;
use crate::distro;
use crate::helper;

pub(crate) fn do_suse(partition_info: &Vec<String>, mut distro: &mut distro::Distro) {
    if !distro.is_ade {
        distro.kind = distro::DistroKind::Suse;

        for partition in partition_info {
            if partition.contains("lxboot") {
                distro.boot_part.boot_part_fs =
                    helper::get_partition_filesystem_detail(partition.as_str());
                distro.boot_part.boot_part_number =
                    helper::get_partition_number_detail(partition.as_str());
            }

            if partition.contains("lxroot") {
                distro.rescue_root.root_part_fs =
                    helper::get_partition_filesystem_detail(partition.as_str());
                distro.rescue_root.root_part_number =
                    helper::get_partition_number_detail(partition.as_str());
            }

            if partition.contains("UEFI") {
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
    } else {
        // ADE part
        // Not yet available
        // See --> https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-overview
    }
}
