use cmd_lib;
use crate::helper;
use crate::cli;
use crate::constants;
use std::{io,process,fs};
use copy_dir;

pub(crate) fn download_action_scripts(cli_info: &cli::CliInfo) -> io::Result<()> {
    if cli_info.action_directory.len() == 0 {
    // First download the git archive
    // Process::Command used in order to ensure we finish the download process
    if let Ok(mut child) = process::Command::new("curl").args(&["-o","/tmp/alar2.tar.gz","-L","https://api.github.com/repos/Azure/repair-script-library/tarball/alar2-test"]).spawn() {
        child.wait().expect("Archive alar2.tar.gz not downloaded");
    } else {
        helper::log_error("Command curl not executed");
        process::exit(1);
    }

    // Expand the action_implementation directory
    cmd_lib::run_cmd!(tar --wildcards --strip-component=7 -xzf /tmp/alar2.tar.gz -C /tmp  *src/linux/common/helpers/alar2/src/action_implementation)?;

    // Get two further files
    //cmd_lib::run_cmd!(tar --wildcards --strip-component=1 -xzf /tmp/alar2.tar.gz -C /tmp *src/linux/common/helpers/Logger.sh)?;
    //cmd_lib::run_cmd!(tar --wildcards --strip-component=1 -xzf /tmp/alar2.tar.gz -C /tmp *src/linux/common/setup/init.sh)?;
    Ok(())
} else {
    // In case we have a local directory for our action scripts we need to copy the actions to
    // tmp/action_implementation
   if let Err(e) = load_local_action(cli_info.action_directory.as_str()) {
       return Err(e);
   }
   Ok(())
}
}

fn load_local_action(directory_source: &str) -> io::Result<()> {
        let _ = fs::remove_dir_all(constants::ACTION_IMPL_DIR);
        match copy_dir::copy_dir(directory_source, constants::ACTION_IMPL_DIR) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
        }
}