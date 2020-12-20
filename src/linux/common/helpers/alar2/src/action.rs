/*

The argument module is responsible to verify whether an action implementation is available or not.
An action needs to have an implementation available. For instance, the action 'fstab' needs to have a file
fstab-impl.sh
Actions are created as shell scripts. So it is easy to create any thinkable action.
If an implemantion is missing the action is skip, an information is printed out accordingly, and the next one is tried to be
executed.


CRATES
======
For http request use: https://github.com/seanmonstar/reqwest
*/

use distro::{Distro, DistroKind};

use crate::{constants, distro, helper};
use std::{env, fs, io};

pub(crate) fn run_repair_script2(distro: &distro::Distro,  action_name: &str) {
    helper::log_info("----- Start action -----");


    // At first make the script executable
    if let Err(e) = cmd_lib::run_fun!(chmod 700 /tmp/action_implementation/${action_name}-impl.sh) {
        helper::log_error("Setting the execute permission bit failed!");
    }

    match env::set_current_dir(constants::RESCUE_ROOT) {
        Ok(_) => {}
        Err(e) => println!("Error in set current dir : {}", e),
    }

    // Set the environment correct

    match distro.kind {
        DistroKind::Debian | DistroKind::Ubuntu=> {env::set_var("isUbuntu", "true");}
        DistroKind::Suse => {env::set_var("isSuse", "true");}
        DistroKind::RedHatCentOS => {env::set_var("isRedHat", "true");}
        DistroKind::RedHatCentOS6 => {env::set_var("isRedHat", "true"); env::set_var("isRedHat6", "true");}
        DistroKind::Undefined => {} // Nothing to do
    }
    // Execute the action script
    if let Ok(res) = cmd_lib::run_fun!(chroot "/mnt/rescue-root" /tmp/action_implementation/${action_name}-impl.sh)
    {
        println!("script output is : {}", res);
    }

    helper::log_info("----- Action stopped -----");
}

pub(crate) fn is_action_available(action_name: &str) -> io::Result<bool> {
    let mut is_found: bool = false;
    let dircontent = fs::read_dir(constants::ACTION_IMPL_DIR)?;
    for item in dircontent {
        if let Ok(entry) = item {
            let path = entry.path();
            println!("{}", path.display());
            if path
                .display()
                .to_string()
                .contains(format!("{}-impl.sh", action_name).as_str())
            {
                is_found = true;
            } else {
                is_found = false;
            }
        }
    }
    Ok(is_found)
}
