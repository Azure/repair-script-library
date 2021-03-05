use crate::constants;
use crate::distro;
use crate::distro::DistroKind;
use crate::helper;
use crate::mount;
use crate::cli;
use crate::standalone;

use fs_extra::dir;
use std::{env, fs, io, process};
use std::os::unix::fs::symlink as softlink;

pub(crate) fn ubuntu_mount(distro: &distro::Distro) {
    // We have to verify also whether we have old Ubuntus/Debian with one partition only
    // Or whehter we have also an EFI partition available

    mount::mount_root_on_rescue_root(distro.rescue_root.root_part_path.as_str(), None);

    // If ADE is enabled the extra boot partition needs to be mounted
    if distro.is_ade {
        mount::mount_boot_on_rescue_boot(distro.boot_part.boot_part_path.as_str(), None);
    }

    let mount_option: Option<&str>;
    if distro.efi_part != distro::EfiPartT::NoEFI {
        if helper::get_efi_part_fs(&distro) == "xfs" {
            mount_option = Some("nouuid");
        } else {
            mount_option = None;
        }
        mount::mount_efi_on_rescue_efi(helper::get_efi_part_path(&distro).as_str(), mount_option);
    }

    mount_support_filesystem();
    mount::bind_mount("/run", constants::RESCUE_ROOT_RUN);
}

pub(crate) fn ubuntu_umount(distro: &distro::Distro) {
    umount_support_filesystem();
    mount::umount(constants::RESCUE_ROOT_RUN);

    if distro.efi_part != distro::EfiPartT::NoEFI {
        mount::umount(constants::RESCUE_ROOT_BOOT_EFI);
    }

    // If ADE is enabled for Ubuntu the boot partition needs to be unmounted first
    if distro.is_ade {
        mount::umount(constants::RESCUE_ROOT_BOOT);
    }

    mount::umount(constants::RESCUE_ROOT);
}

pub(crate) fn suse_mount(distro: &distro::Distro) {
    redhat_mount(distro); // We can use the same functionality
}

pub(crate) fn suse_umount(distro: &distro::Distro) {
    redhat_umount(distro); // we can use the same functionality
}

pub(crate) fn redhat_mount(distro: &distro::Distro) {
    if distro.is_lvm  {
        let mut mount_option: Option<&str>;
        mount::mount_root_on_rescue_root(distro.lvm_details.lvm_root_part.as_str(), None);
        mount::mount_usr_on_rescue_root_usr(distro.lvm_details.lvm_usr_part.as_str());
        mount::mount_var_on_rescue_root_var(distro.lvm_details.lvm_var_part.as_str());

        if distro.boot_part.boot_part_fs == "xfs" {
            mount_option = Some("nouuid");
        } else {
            mount_option = None;
        }
        mount::mount_boot_on_rescue_boot(distro.boot_part.boot_part_path.as_str(), mount_option);

        if helper::get_efi_part_fs(&distro) == "xfs" {
            mount_option = Some("nouuid");
        } else {
            mount_option = None;
        }
        mount::mount_efi_on_rescue_efi(helper::get_efi_part_path(&distro).as_str(), mount_option);

        mount_support_filesystem();
    } else {
        // if we have an XFS filesystem we have to set the 'nouuid' option
        let mut mount_option: Option<&str>;
        if distro.rescue_root.root_part_fs == "xfs" {
            mount_option = Some("nouuid");
        } else {
            mount_option = None;
        }

        mount::mount_root_on_rescue_root(distro.rescue_root.root_part_path.as_str(), mount_option);

        if distro.boot_part.boot_part_fs == "xfs" {
            mount_option = Some("nouuid");
        } else {
            mount_option = None;
        }

        mount::mount_boot_on_rescue_boot(distro.boot_part.boot_part_path.as_str(), mount_option);

        if distro.efi_part != distro::EfiPartT::NoEFI {
            if helper::get_efi_part_fs(&distro) == "xfs" {
                mount_option = Some("nouuid");
            } else {
                mount_option = None;
            }
            mount::mount_efi_on_rescue_efi(
                helper::get_efi_part_path(&distro).as_str(),
                mount_option,
            );
        }
        mount_support_filesystem();
    }
}

pub(crate) fn redhat6_mount(distro: &distro::Distro) {
    mount::mount_root_on_rescue_root(distro.rescue_root.root_part_path.as_str(), None);
    // In case we have no boot part information like on a single CentOS distro we don't need to mount boot
    if distro.boot_part.boot_part_number != 0 {
        mount::mount_boot_on_rescue_boot(distro.boot_part.boot_part_path.as_str(), None);
    }
    mount_support_filesystem();
}

pub(crate) fn redhat6_umount(distro: &distro::Distro) {
    umount_support_filesystem();
    // In case we have no boot part information like on a single CentOS distro we don't need to umount boot
    if distro.boot_part.boot_part_number != 0 {
        mount::umount(constants::RESCUE_ROOT_BOOT);
    }
    mount::umount(constants::RESCUE_ROOT);
}

pub(crate) fn redhat_umount(distro: &distro::Distro) {
    if distro.is_lvm  {
        umount_support_filesystem();
        mount::umount(constants::RESCUE_ROOT_BOOT_EFI);
        mount::umount(constants::RESCUE_ROOT_BOOT);
        mount::umount(constants::RESCUE_ROOT_USR);
        mount::umount(constants::RESCUE_ROOT_VAR);
        mount::umount(constants::RESCUE_ROOT);
    } else {
        umount_support_filesystem();
        if distro.efi_part != distro::EfiPartT::NoEFI {
            mount::umount(constants::RESCUE_ROOT_BOOT_EFI);
        }
        mount::umount(constants::RESCUE_ROOT_BOOT);
        mount::umount(constants::RESCUE_ROOT);
    }
}

fn mount_support_filesystem() {
    match mkdir_support_filesystems() {
        Ok(()) => {}
        Err(e) => panic!(
            "Support Filesystems are not able to be created. This is not recoverable : {}",
            e
        ),
    }
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().split(' ') {
        mount::bind_mount(
            format!("/{}/", fs).as_str(),
            format!("{}{}", constants::RESCUE_ROOT, fs).as_str(),
        );
    }
}
fn umount_support_filesystem() {
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().rsplit(' ') {
        mount::umount(format!("{}{}", constants::RESCUE_ROOT, fs).as_str());
    }
}

fn mkdir_support_filesystems() -> io::Result<()> {
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().split(' ') {
        fs::create_dir_all(format!("{}{}", constants::RESCUE_ROOT, fs))?;
    }
    Ok(())
}


pub(crate) fn distro_mount(distro: &distro::Distro, cli_info: &cli::CliInfo) {
    match distro.kind {
        DistroKind::Debian | DistroKind::Ubuntu => ubuntu_mount(&distro),
        DistroKind::Suse => suse_mount(&distro),
        DistroKind::RedHatCentOS => redhat_mount(&distro),
        DistroKind::RedHatCentOS6 => redhat6_mount(&distro),
        DistroKind::Undefined => {} // Nothing to do here we have covered this condition already
    }
    // Also copy the recovery scripts to /tmp in order to make them available for the chroot 
    // operation we do later
    copy_actions_totmp(distro, cli_info);
}

pub(crate) fn distro_umount(distro: &distro::Distro) {
    match distro.kind {
        DistroKind::Debian | DistroKind::Ubuntu => ubuntu_umount(&distro),
        DistroKind::Suse => suse_umount(&distro),
        DistroKind::RedHatCentOS => redhat_umount(&distro),
        DistroKind::RedHatCentOS6 => redhat6_umount(&distro),
        DistroKind::Undefined => {} // Nothing to do here we have covered this condition already
    }
}

fn copy_actions_totmp(distro: &distro::Distro, cli_info: &cli::CliInfo) {
    // We need to copy the action scripts to /tmp
    // This is the only directory we change with chroot
    
    if !cli_info.standalone {
    let mut options = dir::CopyOptions::new(); //Initialize default values for CopyOptions
    options.skip_exist = true;

    match env::current_dir() {
          Ok(cd) => println!("The current dir is : {}", cd.display() ),
          Err(e) => println!("Error : {}", e),
      }

    match dir::copy("../../../../../src/", "/tmp", &options) {
        Ok(_) => {},
        Err(e) => {
            println!("Copy operation for action_implementation directory failed. ALAR needs to stop: {}", e); 
            distro_umount(distro);
            process::exit(1);
            }
    }

    if let Err(err) = fs::remove_dir_all(constants::ACTION_IMPL_DIR) {
        println!("Directory {} can not be removed : '{}'", constants::ACTION_IMPL_DIR, err );
        distro_umount(distro);
        //process::exit(1);
    }
    // Create a softlink in orders to ease the directory access.
    match softlink("/tmp/src/linux/common/helpers/alar2/src/action_implementation", constants::ACTION_IMPL_DIR) {
        Ok(_) => {},
        Err(e) => {
                println!("Softlink can not be created. ALAR needs to stop!: {}",e);
                distro_umount(distro);
                process::exit(1);
        }
    }
} else if let Err(e) = standalone::download_action_scripts(cli_info) {
        distro_umount(distro);
        panic!("action scripts are not able to be copied or downloadable : '{}'", e); 
}
    
}
