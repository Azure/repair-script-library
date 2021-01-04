use crate::constants;
use crate::distro;
use crate::helper;
use crate::mount;
use cmd_lib::{run_cmd, run_fun};

pub(crate)  fn verify_ubuntu(mut distro: &mut distro::Distro) {

    if let Err(e) = mount::mkdir_assert() {
        panic!("Creating assert directory is not possible: {} ALAR is not able to proceed further", e);
    }

    mount::mount_path_assert(distro.rescue_root.root_part_path.as_str());
    let pretty_name = helper::get_pretty_name(constants::OS_RELEASE);
    mount::umount(constants::ASSERT_PATH);

    if mount::rmdir(constants::ASSERT_PATH).is_err() {
        helper::log_info("ASSERT_PATH can not be removed. This is a minor issue. ALAR is able to continue further");
    }

    println!("pretty : {}", &pretty_name);
    if  pretty_name.contains("Ubuntu") {
        distro.kind = distro::DistroKind::Ubuntu;
    }

    if pretty_name.contains("Debian") {
        distro.kind = distro::DistroKind::Debian;
    }
}

pub(crate) fn do_ubuntu(partition_info: &[String], mut distro: &mut distro::Distro) {
    for partition in partition_info {
        // TMP is required for the macro run_fun! or run_cmd!
        let _TMP = constants::PARTITION_TMP;

        // Write the partition details into the file referenced in _TMP
        let _ = run_cmd!(echo $partition > $_TMP);
        if let Ok(name) = run_fun!(grep -s -v boot $_TMP | grep -v bios) {
            println!("{}", name);
            distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(&name.as_str());
            distro.rescue_root.root_part_number = helper::get_partition_number_detail(&name.as_str());
        }

        if partition.contains("boot") {
            helper::set_efi_part_number_and_fs(&mut distro, partition);
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

    helper::set_efi_part_path(&mut distro);
    helper::fsck_partition(
        helper::get_efi_part_path(&distro).as_str(),
        helper::get_efi_part_fs(&distro).as_str(),
    );
    
    // If we have ADE enabled on the disk to be recovered then there is a 4th partition to hold the boot
    // part information
    if distro.is_ade {
        // We use hardcoded values in this case
        distro.boot_part.boot_part_fs = "ext2".to_string();
        distro.boot_part.boot_part_number = 2 ;
        
        distro.boot_part.boot_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.rescue_root.root_part_number
        )
        .as_str(),
        );

        helper::fsck_partition(
            distro.boot_part.boot_part_path.as_str(),
            distro.boot_part.boot_part_fs.as_str(),
        ); 
    }

    verify_ubuntu(distro);
}
