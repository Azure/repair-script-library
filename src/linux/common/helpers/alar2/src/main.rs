mod action;
mod ade;
mod cli;
mod constants;
mod distro;
mod helper;
mod mount;
mod prepare_action;
mod redhat;
mod standalone;
mod suse;
mod ubuntu;

use std::process;


fn main() {
    // First verify we have the right amount of information to operate
    let cli_info = cli::cli();

    // At first we need to verify the distro we have to work with
    // the Distro struct does contain then all of the required information
    let distro = distro::Distro::new();
    eprintln!("{:?}", distro);

    
   
    // Do we have a valid distro or not?

    if distro.kind == distro::DistroKind::Undefined {
        helper::log_error("Unrecognized Linux distribution. ALAR tool is stopped\n
                 Your OS can not be determined. The OS distros supported are:\n
                 CentOS/Redhat 6.8 - 8.2\n
                 Ubuntu 16.4 LTS and Ubuntu 18.4 LTS\n
                 Suse 12 and 15\n
                 Debain 9 and 10\n
                 ALAR will stop!\n
                 If your OS is in the above list please report this issue at https://github.com/azure/repair-script-library/issues"
        );
        process::exit(1);
    }

    // Prepare and mount the partitions. Take into account what distro we have to deal with
    match mount::mkdir_rescue_root() {
        Ok(_) => {}
        Err(e) => panic!(
            "The rescue-root dir can't be created. This is not recoverable! : {} ",
            e
        ),
    }

    // Step 2 of prepare and mount. Mount the right dirs depending on the distro determined
    prepare_action::distro_mount(&distro, &cli_info);

    // Verify we have an implementation available for the action to be executed
    // Define a variable for the error condition that may happen
    let mut is_action_error = false;
    for action_name in cli_info.actions.split(',') {
        match action::is_action_available(action_name) {
            // Do the action
            Ok(_is @ true) => match action::run_repair_script(&distro, action_name) {
                Ok(_) => is_action_error = false,
                Err(e) => {
                    helper::log_error(
                        format!("Action {} raised an error: '{}'", &action_name, e).as_str(),
                    );
                    is_action_error = true;
                }
            },
            Ok(_is @ false) => {
                helper::log_error(format!("Action '{}' is not available", action_name).as_str());
                is_action_error = true;
            }
            Err(e) => {
                helper::log_error(
                    format!(
                        "There was an error raised while verifying the action: '{}'",
                        e
                    )
                    .as_str(),
                );
                is_action_error = true;
            }
        }
    }

    // Umount everything again

    prepare_action::distro_umount(&distro);

    // Inform the calling process about the success
    if is_action_error {
        process::exit(1);
    } else {
        process::exit(0);
    }
}
