use cmd_lib::{run_cmd, run_fun};
use std::io;

pub(crate) fn download_action_scripts() -> io::Result<()> {
    cmd_lib::run_cmd!(curl -L "https://api.github.com/repos/Azure/repair-script-library/tarball/alar2-test" | tar --wildcards --strip-component=7  -xz -C /tmp  *src/linux/common/helpers/alar2/src/action_implementation)?; 
    Ok(())
}