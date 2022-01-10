use crate::{constants, distro, helper};
use distro::DistroKind;
use std::io::Write;
use std::{env, fs, io, process};

pub(crate) fn run_repair_script(distro: &distro::Distro, action_name: &str) -> io::Result<()> {
    helper::log_info("----- Start action -----");

    // At first make the script executable
    uapi::chmod(
        format!("{}/{}-impl.sh", constants::ACTION_IMPL_DIR, action_name),
        uapi::c::S_IXUSR | uapi::c::S_IRUSR,
    )?;
    //if let Err(e) = cmd_lib::run_fun!(chmod 700 /tmp/action_implementation/${action_name}-impl.sh) {
    //    helper::log_error(format!("Setting the execute permission bit failed! {}",e).as_str());
    //}

    match env::set_current_dir(constants::RESCUE_ROOT) {
        Ok(_) => {}
        Err(e) => println!("Error in set current dir : {}", e),
    }

    // Set the environment correct
    let convert_bool = |state: bool| -> String {
        if state {
            "true".to_string()
        } else {
            "false".to_string()
        }
    };
    match distro.kind {
        DistroKind::Debian | DistroKind::Ubuntu => {
            env::set_var("isUbuntu", "true");
            env::set_var("isADE", convert_bool(distro.is_ade));
            env::set_var("root_part_path", distro.rescue_root.root_part_path.as_str());
            env::set_var("efi_part_path", helper::get_efi_part_path(distro).as_str());
            env::set_var("boot_part_path", distro.boot_part.boot_part_path.as_str());
            env::remove_var("isSuse");
            env::remove_var("isRedHat");
            env::remove_var("isRedHat6");
        }
        DistroKind::Suse => {
            env::set_var("isSuse", "true");
            env::set_var("root_part_path", distro.rescue_root.root_part_path.as_str());
            env::set_var("efi_part_path", helper::get_efi_part_path(distro).as_str());
            env::set_var("boot_part_path", distro.boot_part.boot_part_path.as_str());
            env::remove_var("isUbuntu");
            env::remove_var("isRedHat");
            env::remove_var("isRedHat6");
        }
        DistroKind::RedHatCentOS => {
            env::set_var("isRedHat", "true");
            env::set_var("isADE", convert_bool(distro.is_ade));
            env::set_var("root_part_path", distro.rescue_root.root_part_path.as_str());
            env::set_var("efi_part_path", helper::get_efi_part_path(distro).as_str());
            env::set_var("boot_part_path", distro.boot_part.boot_part_path.as_str());
            match distro.is_lvm {
                true => env::set_var("isLVM", "true"),
                false => env::set_var("isLVM", "false"),
            }
            env::set_var("lvm_root_part", distro.lvm_details.lvm_root_part.as_str());
            env::set_var("lvm_usr_part", distro.lvm_details.lvm_usr_part.as_str());
            env::set_var("lvm_lvm_part", distro.lvm_details.lvm_var_part.as_str());
            env::remove_var("isUbuntu");
            env::remove_var("isSuse");
            env::remove_var("isRedHat6");
        }
        DistroKind::RedHatCentOS6 => {
            env::set_var("isRedHat", "true");
            env::set_var("isADE", convert_bool(distro.is_ade));
            env::set_var("isRedHat6", "true");
            env::set_var("root_part_path", distro.rescue_root.root_part_path.as_str());
            env::set_var("efi_part_path", helper::get_efi_part_path(distro).as_str());
            env::set_var("boot_part_path", distro.boot_part.boot_part_path.as_str());
            match distro.is_lvm {
                true => env::set_var("isLVM", "true"),
                false => env::set_var("isLVM", "false"),
            }
            env::set_var("lvm_root_part", distro.lvm_details.lvm_root_part.as_str());
            env::set_var("lvm_usr_part", distro.lvm_details.lvm_usr_part.as_str());
            env::set_var("lvm_lvm_part", distro.lvm_details.lvm_var_part.as_str());
            env::remove_var("isUbuntu");
            env::remove_var("isSuse");
        }
        DistroKind::Undefined => {} // Nothing to do
    }
    // Execute the action script

    let output = process::Command::new("chroot")
        .arg(constants::RESCUE_ROOT)
        .arg("/bin/bash")
        .arg("-c")
        .arg(format!(
            "{}/{}-impl.sh",
            constants::ACTION_IMPL_DIR,
            action_name
        ))
        .output()?;

    io::stdout().write_all(&output.stdout).unwrap();
    helper::log_info("----- Action stopped -----");

    Ok(())
}

pub(crate) fn is_action_available(action_name: &str) -> io::Result<bool> {
    let dircontent = fs::read_dir(constants::ACTION_IMPL_DIR)?;
    let mut actions: Vec<String> = Vec::new();
    for item in dircontent {
        let detail = format!("{}", item?.path().display());
        actions.push(detail);
    }
    Ok(actions
        .iter()
        .any(|a| a.ends_with(&format!("{}-impl.sh", action_name))))
}
