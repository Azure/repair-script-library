/*

The following options and flags need to be available

FLAG
-----
-s --standalone : This should signal that we run in standalone mode. Any required repair scripts need to be downloaded from git

ARGUMENT
--------
Either pass over a single action or many seperated by a comma.
Each action needs then to be verified for its existens on git/filesystem
If the action does exists it gets executed

OPTIONS
--------
 -d --dir : The directory in which action-implementations are stored. Can be used for testing of scripts as well.
            The standalone flag is necessary to be set as well


*/
use clap::{App, Arg};

pub(crate) struct CliInfo {
    pub(crate) standalone: bool,
    pub(crate) action_directory: String,
    pub(crate) actions: String,
}

impl CliInfo {
    pub(crate) fn new() -> Self {
        Self { standalone : false, action_directory : "".to_string(), actions : "".to_string(),}
    }
}

pub(crate) fn cli() -> CliInfo {
    let about = "
ALAR tries to assist with non boot able scenarios by running
one or more different actions in order to get a VM in a running state that allows
the administrator to further recover the VM after it is up, running and accessible again.
";
   let matches = App::new("Azure Linux Auto Recover")
                          .version("0.9")
                          .author("Marcus Lachmanez , malachma@microsoft.com")
                          .about(about)
                          .arg(Arg::with_name("standalone")
                               .short("s")
                               .long("standalone")
                               .help("Operates the tool in a standalone mode.")
                               .takes_value(false))
                          .arg(Arg::with_name("directory")
                                .short("d")
                                .long("directory")
                                .takes_value(true)
                                .requires("standalone") // if directory is set 
                                // it is mandatory to have standalone set as well
                                .help("The directory in which the actions are defined.\nRequires the standalone flag")
                           )
                          .arg(Arg::with_name("ACTION")
                               .help("Sets the input file to use")
                               .required(true)
                               .index(1))
                          .get_matches();
    let mut cli_info = CliInfo::new();

    // Calling .unwrap() is safe here because "ACTION" is required
    // this is true for directory as well if flag standalone is present 
    cli_info.actions = matches.value_of("ACTION").unwrap().to_string();
    cli_info.standalone = matches.is_present("standalone"); 
    if cli_info.standalone && matches.is_present("directory") {
            cli_info.action_directory = matches.value_of("directory").unwrap().to_string();
        }
    
    cli_info
}
