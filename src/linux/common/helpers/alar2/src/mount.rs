use crate::helper;
use crate::constants;
use std::{fs, io, process};
//use sys_mount;

pub(crate)  fn mkdir_assert()  -> Result<(), io::Error>{
    match fs::create_dir_all(constants::ASSERT_PATH) {
        Ok(()) => Ok(()) ,
        Err(e) => {println!("Error while creating the assert directory: {}", e);
            Err(e)
    }
    }
}

pub(crate)  fn mkdir_rescue_root()  -> Result<(), io::Error>{
    match fs::create_dir_all(constants::RESCUE_ROOT) {
        Ok(()) => Ok(()) ,
        Err(e) => {println!("Error while creating the rescue-root directory: {}", e);
            Err(e)
    }
    }
}
fn mount( source: &str, destination: &str, option: Option<&str>) {

    // There is an issue on Ubuntu that the XFS filesystem is not enabled by default
    // We need to load the driver first
    match process::Command::new("modprobe").arg("xfs").status() {
        Ok(_) => {},
        Err(_) => helper::log_error("Loading of the module xfs was not possible. This may result in mount issues! : "),
    }

    let supported = match sys_mount::SupportedFilesystems::new() {
        Ok(supported) => supported,
        Err(_) => {
            helper::log_error("Failed to get supported file systems");
            panic!();
        }
    };

    match sys_mount::Mount::new(source, destination, &supported, sys_mount::MountFlags::empty(), option) {
        Ok(_) => {
            helper::log_info(format!("mounted {} to {}", source, &destination).as_str() );
        }
        Err(why) => {
            helper::log_error(format!("failed to mount {} to {}: {}", source, destination, why).as_str());
            panic!();
        }
    } 
}

pub(crate)  fn bind_mount(source: &str, destination: &str) {
    let supported = match sys_mount::SupportedFilesystems::new() {
        Ok(supported) => supported,
        Err(_) => {
            helper::log_error("Failed to get supported file systems");
            panic!();
        }
    };

    match sys_mount::Mount::new(source, destination, &supported, sys_mount::MountFlags::BIND, None) {
        Ok(_) => {
            //helper::log_info(format!("mounted {} to {}", source, &destination).as_str() );
        }
        Err(why) => {
            helper::log_error(format!("failed to mount {} to {}: {}", source, destination, why).as_str());
            panic!();
        }
    } 
}

pub(crate)  fn mount_path_assert(source: &str) {
    mount(source, constants::ASSERT_PATH, None);
}

pub(crate)  fn mount_root_on_rescue_root(root_source: &str, option: Option<&str>) {
    mount(root_source, constants::RESCUE_ROOT, option);
}

pub(crate)  fn mount_boot_on_rescue_boot(boot_source: &str, option: Option<&str>) {
    mount(boot_source, constants::RESCUE_ROOT_BOOT, option);
}

pub(crate)  fn mount_efi_on_rescue_efi(efi_source: &str, option: Option<&str>) {
    mount(efi_source, constants::RESCUE_ROOT_BOOT_EFI, option);
}

// Used only for LVM
pub(crate)  fn mount_usr_on_rescue_root_usr(usr_source: &str) {
    mount(usr_source, constants::RESCUE_ROOT_USR, None);
}

// Used only for LVM
pub(crate)  fn mount_var_on_rescue_root_var(var_source: &str) {
    mount(var_source, constants::RESCUE_ROOT_VAR, None);
}

pub(crate) fn umount(destination: &str) {
    match sys_mount::unmount(destination, sys_mount::UnmountFlags::DETACH) {
        Ok(()) => (),
        Err(why) => {
            helper::log_error(format!("Failed to unmount {}: {}", destination, why).as_str());
            helper::log_error("This shouldn't cause a severe issue for ALAR.");
        }
    }
}

pub(crate) fn rmdir(path: &str) -> std::io::Result<()> {
    fs::remove_dir_all(path)?;
    Ok(())
}




