mod action;
mod ade;
mod constants;
mod distro;
mod helper;
mod mount;
mod prepare_action;
mod redhat;
mod suse;
mod ubuntu;

use cmd_lib::{run_cmd, run_fun};
use distro::DistroKind;
use std::{
    env, fs,
    io::{self, Error},
    path::Path,
    process,
};

fn main() {
    // At first we need to verify the distro we have to work with
    // the Distro struct does contain then all of the required information
    let distro = distro::Distro::new();
    println!("{:?}", distro);

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

    // Mount the right dirs depending on the distro determined
    prepare_action::distro_mount(&distro);

    // Verify we have an implementation available for the action to be executed
    let dir = "/tmp/action_implementation";
    let action_name = "fstab";

    match action::is_action_available(dir, action_name) {
        // Do the action
        Ok(_) => action::run_repair_script2( action_name),
        Err(e) => helper::log_error(format!("Action '{}' is not available", action_name).as_str()),
    }

    // Umount everything again

      match env::current_dir() {
          Ok(cd) => println!("The current dir is : {}", cd.display() ),
          Err(e) => println!("Error : {}", e),
      }

    prepare_action::distro_umount(&distro);

    // This is a test for doing a chroot
    /*
    unsafe {
        //let mount_dir: *const libc::c_char = b"/my_root\0".as_ptr() as *const libc::c_char;
        let mount_dir: *const libc::c_char = b"/mnt/rescue-root\0".as_ptr() as *const libc::c_char;
        let code =libc::chroot(mount_dir);
        println!("Return value is: {}", code);

        //path=Path::new(r#"/grub2"#);
        let path = Path::new(r#"/boot"#);

        if let Ok(v) = env::set_current_dir(&path) {
            println!("Set path was: {:?}", v);
        }

      let path = env::current_dir();
        println!("The current directory is {}", path.unwrap().display());
    }
    */
}

// Start of the function definition
