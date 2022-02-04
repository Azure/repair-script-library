use crate::helper;
use crate::cli;
use crate::constants;
use std::{io,process,fs};

pub(crate) fn download_action_scripts(cli_info: &cli::CliInfo) -> io::Result<()> {
    if cli_info.action_directory.is_empty() {
    // First download the git archive
    // Process::Command used in order to ensure we finish the download process
    if let Ok(mut child) = process::Command::new("curl").args(&["-o","/tmp/alar2.tar.gz","-L","https://api.github.com/repos/Azure/repair-script-library/tarball/master"]).spawn() {
        child.wait().expect("Archive alar2.tar.gz not downloaded");
    } else {
        helper::log_error("Command curl not executed");
        process::exit(1);
    }

    // Expand the action_implementation directory
    cmd_lib::run_cmd!(tar --wildcards --strip-component=7 -xzf /tmp/alar2.tar.gz -C /tmp  *src/linux/common/helpers/alar2/src/action_implementation)?;

    Ok(())
} else {
    // In case we have a local directory for our action scripts we need to copy the actions to
    // tmp/action_implementation
   if let Err(e) = load_local_action(cli_info.action_directory.as_str()) {
       return Err(io::Error::new(io::ErrorKind::Other, format!("Load local action failed : '{}'",e)));
   }
   Ok(())
}
}

fn load_local_action(directory_source: &str) -> fs_extra::error::Result<u64> {
        let _ = fs::remove_dir_all(constants::ACTION_IMPL_DIR);
        let mut options = fs_extra::dir::CopyOptions::new();
        options.skip_exist = true;
        options.copy_inside = true;
        match fs_extra::dir::copy(directory_source, constants::ACTION_IMPL_DIR, &options) {
        Ok(v) => Ok(v),
        Err(e) => Err(e),
        }
}
