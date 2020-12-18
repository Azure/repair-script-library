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


use crate::{constants, distro, helper};
use std::{env, fs, io};
use std::thread;
use libc;

pub(crate) fn run_repair_script(distro: &distro::Distro, action_name: &'static str) {
    helper::log_info("----- Start action -----");
    // This is a test for doing a chroot 
    let child = thread::spawn( move || {
    unsafe {
        //let mount_dir: *const libc::c_char = constants::RESCUE_ROOT_CSTRING.as_bytes().as_ptr() as *const libc::c_char;
        let mount_dir: *const libc::c_char = b"/mnt/rescue-root\0".as_ptr() as *const libc::c_char;
        let code =libc::chroot(mount_dir);
        println!("Return value is: {}", code);

        //path=Path::new(r#"/grub2"#);
        //let path = Path::new(r#"/boot"#);

//        if let Ok(v) = env::set_current_dir(&path) {
//            println!("Set path was: {:?}", v);
//        }
        match env::set_current_dir("/") {
            Ok(_) => {},
            Err(e) => println!("Error in set current dir : {}", e),
        }

      match env::current_dir() {
          Ok(cd) => println!("The current dir is : {}", cd.display() ),
          Err(e) => println!("Error : {}", e),
      }
    }
    if let Ok(res) = cmd_lib::run_fun!(bash /tmp/action_implementation/${action_name}-impl.sh) {
       println!("script output is : {}", res); 
    }
    
    }); // End Thread and wait for it
    let res = child.join();    

    helper::log_info("----- Action stopped -----");
}

pub(crate) fn run_repair_script2(action_name: &str) {
    helper::log_info("----- Start action -----");

        //path=Path::new(r#"/grub2"#);
        //let path = Path::new(r#"/boot"#);

//        if let Ok(v) = env::set_current_dir(&path) {
//            println!("Set path was: {:?}", v);
//        }
        match env::set_current_dir("/") {
            Ok(_) => {},
            Err(e) => println!("Error in set current dir : {}", e),
        }

      match env::current_dir() {
          Ok(cd) => println!("The current dir is : {}", cd.display() ),
          Err(e) => println!("Error : {}", e),
      }
    
    if let Ok(res) = cmd_lib::run_fun!(chroot "/mnt/rescue-root" /tmp/action_implementation/${action_name}_impl.sh) {
       println!("script output is : {}", res); 
    }
    

    helper::log_info("----- Action stopped -----");
}

pub(crate) fn is_action_available(path: &str, action_name: &str) -> io::Result<bool> {
    let mut is_found: bool = false;
    let dircontent = fs::read_dir(path)?;
        for item in dircontent {
            if let Ok(entry) = item {
                let path = entry.path();
                println!("{}", path.display());
                if path.display().to_string().contains(format!("{}-impl.sh",action_name).as_str()) { is_found = true;
                } else {
                    is_found = false;
                }
            }
        }
        Ok(is_found)
}