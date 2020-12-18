use crate::constants;
use crate::distro;
use crate::distro::DistroKind;
use crate::helper;
use crate::mount;
use cmd_lib::{run_cmd, run_fun};
use std::{fs, io};

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
    //mount::bind_mount("/run", constants::RESCUE_ROOT_RUN);
    redhat_mount(distro); // We can use the same functionality
}

pub(crate) fn suse_umount(distro: &distro::Distro) {
    //mount::umount(constants::RESCUE_ROOT_RUN);
    redhat_umount(distro); // we can use the same functionality
}

pub(crate) fn redhat_mount(distro: &distro::Distro) {
    if distro.is_lvm == true {
        // REMOVE THIS NOT NEEDED AS WE HAVE DONE THIS ALREADY !!!!!!!!!!!!!!!!!!!!!
        // At first we need to prepare the LVM setup
        //match run_cmd!(pvscan; vgscan; lvscan;) {
        //    Ok(_) => {},
        //    Err(error) => panic!("There is a problem to setup LVM correct. {}", error),
        //}

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
    if distro.is_lvm == true {
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
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().split(" ") {
        println!("Mount supportfs : {}", fs);
        mount::bind_mount(
            format!("/{}/", fs).as_str(),
            format!("{}{}", constants::RESCUE_ROOT, fs).as_str(),
        );
    }
}
fn umount_support_filesystem() {
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().rsplit(" ") {
        mount::umount(format!("{}{}", constants::RESCUE_ROOT, fs).as_str());
    }
}

fn mkdir_support_filesystems() -> io::Result<()> {
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().split(" ") {
        fs::create_dir_all(format!("{}{}", constants::RESCUE_ROOT, fs))?;
    }
    Ok(())
}

fn rm_support_filesystems() -> io::Result<()> {
    for fs in constants::SUPPORT_FILESYSTEMS.to_string().split(" ") {
        mount::rmdir(format!("{}{}", constants::RESCUE_ROOT, fs).as_str())?;
    }
    Ok(())
}

pub(crate) fn distro_mount(distro: &distro::Distro) {
    match distro.kind {
        DistroKind::Debian | DistroKind::Ubuntu => ubuntu_mount(&distro),
        DistroKind::Suse => suse_mount(&distro),
        DistroKind::RedHatCentOS => redhat_mount(&distro),
        DistroKind::RedHatCentOS6 => redhat6_mount(&distro),
        DistroKind::Undefined => {} // Nothing to do here we have covered this condition already
    }
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
