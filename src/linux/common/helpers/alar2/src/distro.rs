use crate::ade;
use crate::constants;
use crate::helper;
use crate::helper::read_link;
use crate::mount;
use crate::redhat;
use crate::suse;
use crate::ubuntu;
use cmd_lib;
use std::process;

#[derive(Debug)]
pub struct Distro {
    pub boot_part: BootPartDetails,
    pub rescue_root: RootPartDetails,
    pub efi_part: EfiPartT,
    pub is_lvm: bool,
    pub is_ade: bool,
    pub lvm_details: LVMDetails,
    pub kind: DistroKind,
}

#[derive(Debug, PartialEq)]
pub enum DistroKind {
    Debian,
    Suse,
    RedHatCentOS,
    RedHatCentOS6,
    Ubuntu,
    Undefined,
}
#[derive(Debug)]
pub struct BootPartDetails {
    pub(crate) boot_part_fs: String,
    pub(crate) boot_part_number: u8,
    pub(crate) boot_part_path: String,
}

#[derive(Debug)]
pub struct RootPartDetails {
    pub(crate) root_part_fs: String,
    pub(crate) root_part_number: u8,
    pub(crate) root_part_path: String,
}

#[derive(Debug)]
pub struct LVMDetails {
    pub(crate) lvm_root_part: String,
    pub(crate) lvm_usr_part: String,
    pub(crate) lvm_var_part: String,
}

#[derive(Debug, PartialEq)]
pub struct EfiPartition {
    pub(crate) efi_part_number: u8,
    pub(crate) efi_part_fs: String,
    pub(crate) efi_part_path: String,
}

impl EfiPartition {
    fn new() -> Self {
        Self {
            efi_part_fs: "".to_string(),
            efi_part_path: "".to_string(),
            efi_part_number: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum EfiPartT {
    EfiPart(EfiPartition),
    NoEFI,
}

impl EfiPartT {
    pub fn new() -> EfiPartT {
        EfiPartT::EfiPart(EfiPartition::new())
    }
}

impl Default for EfiPartT {
    fn default() -> Self {
        EfiPartT::NoEFI
    }
}

impl Default for DistroKind {
    fn default() -> Self {
        DistroKind::Undefined
    }
}

impl BootPartDetails {
    fn new() -> Self {
        Self {
            boot_part_fs: "".to_string(),
            boot_part_path: "".to_string(),
            boot_part_number: 0,
        }
    }
}

impl RootPartDetails {
    fn new() -> Self {
        Self {
            root_part_fs: "".to_string(),
            root_part_path: "".to_string(),
            root_part_number: 0,
        }
    }
}

impl LVMDetails {
    fn new() -> Self {
        Self {
            lvm_root_part: "".to_string(),
            lvm_usr_part: "".to_string(),
            lvm_var_part: "".to_string(),
        }
    }
}

impl Distro {
    pub fn new() -> Distro {
        let mut partitions: Vec<String> = Vec::new();
        //get_partitions is filling the variable partitions
        get_partitions(&mut partitions);
        let efi_part: EfiPartT = Default::default();
        let boot_part: BootPartDetails = BootPartDetails::new();
        let root_part: RootPartDetails = RootPartDetails::new();
        let kind: DistroKind = Default::default();
        let lvm_details = LVMDetails::new();
        let mut distro: Distro = Distro {
            boot_part: boot_part,
            rescue_root: root_part,
            efi_part: efi_part,
            is_lvm: false,
            is_ade: false,
            lvm_details: lvm_details,
            kind: kind,
        };

        // here we start the core logic in order to determine what distro and type we have to cope with
        dispatch(&partitions, &mut distro);

        distro
    }
}

fn get_partitions(partitions: &mut Vec<String>) {
    let link = read_link(constants::RESCUE_DISK);
    let out = cmd_lib::run_fun!(parted -m ${link} print | grep -E "^ ?[0-9]{1,2} *");

    match out {
        Ok(v) => {
            for line in v.lines() {
                partitions.push(line.to_string());
            }
            helper::log_info(
                format!(
                    "We have the following partitions determined: {:?}",
                    partitions
                )
                .as_str(),
            );
        }
        Err(e) => panic!("Fehler {:?}", e),
    }
}

// If there is only one partition detected
//fn do_old_ubuntu_or_centos(partition_info: &Vec<String>, mut distro: &mut Distro) {
fn do_old_ubuntu_or_centos(partition_info: &[String], mut distro: &mut Distro) {
    helper::log_info("This could be an old Ubuntu image or even an CentOS with one partition only");

    // At first we have to determine whether this is a Ubuntu distro
    // or whether it is a single partiton CentOs distro
    if let Err(e) = mount::mkdir_assert() {
        panic!("Creating assert directory is not possible : '{}'. ALAR is not able to proceed further",e);
    }

    distro.rescue_root.root_part_fs = helper::get_partition_filesystem_detail(&partition_info[0]);
    distro.rescue_root.root_part_number = helper::get_partition_number_detail(&partition_info[0]);
    distro.rescue_root.root_part_path = helper::read_link(
        format!(
            "{}{}",
            constants::LUN_PART_PATH,
            distro.rescue_root.root_part_number
        )
        .as_str(),
    );

    helper::fsck_partition(
        distro.rescue_root.root_part_path.as_str(),
        distro.rescue_root.root_part_fs.as_str(),
    );
    mount::mount_path_assert(distro.rescue_root.root_part_path.as_str());
    let pretty_name = helper::get_pretty_name("/tmp/assert/etc/os-release");
    mount::umount(constants::ASSERT_PATH);

    if pretty_name.contains("Debian") || pretty_name.contains("Ubuntu") {
        distro.kind = DistroKind::Ubuntu;
        let _ = mount::rmdir(constants::ASSERT_PATH);
    } else {
        // Single partiton CentOS
        let _ = mount::rmdir(constants::ASSERT_PATH);
        redhat::verify_redhat_nolvm(distro);
    }
}

// if we have two partition detected
//fn do_red_hat(partition_info: &Vec<String>, distro: &mut Distro) {
fn do_red_hat(partition_info: &[String], distro: &mut Distro) {
    helper::log_info("This could be a RedHat/Centos 6/7 image");
    redhat::do_redhat6_or_7(partition_info, distro);
}

// if we have 3 partition detected
//fn do_recent_ubuntu(partition_info: &Vec<String>, distro: &mut Distro) {
fn do_recent_ubuntu(partition_info: &[String], distro: &mut Distro) {
    // In case of a disk with ADE
    helper::log_info("This could be a recent Ubuntu 16.x or 18.x image");
    ubuntu::do_ubuntu(partition_info, distro);
}

// if we have 4 partition detected
fn do_suse_or_lvm_or_ubuntu(partition_info: &[String], distro: &mut Distro) {
    // This function is also called if we have an recent Ubuntu distro with ADE enabled
    // With ADE a 4th partition got added to hold the boot-part-details plus luks

    // Define an enum which is used to decide which further part has to be executed

    enum Logic {
        RedHat,
        Suse,
        Ubuntu,
    }
    let mut which_logic = Logic::RedHat; // Default value is Redhat

    // Not sure whether this is a RedHat or CENTOS with LVM or it is a Suse 12/15 instead
    // Need to make a simple test
    for partition in partition_info.iter() {
        if partition.contains("lxboot") {
            which_logic = Logic::Suse;
        }
    }

    // Verify if we have an Ubuntu distro with ADE enabled
    // This needs to be verified first before we can do the RedHat part instead
    // Since with ADE on Ubuntu we got a 4th partition added
    if distro.is_ade {
        let pretty_name = helper::get_pretty_name("/investigateroot/etc/os-release"); // This path must exists, otherwise it can not be determined
        if pretty_name.is_empty() {
            helper::log_error("'/investigationrooot' needs to be mounted first. Please do this first. ALAR does stop");
            process::exit(1);
        }
        if pretty_name.contains("Ubuntu") {
            which_logic = Logic::Ubuntu;
        }
    }

    match which_logic {
        Logic::RedHat => redhat::do_redhat_lvm_or(partition_info, distro),
        Logic::Suse => suse::do_suse(partition_info, distro),
        Logic::Ubuntu => ade::do_ubuntu_ade(partition_info, distro),
    }
}

//fn dispatch(partition_info: &Vec<String>, mut distro: &mut Distro) {
fn dispatch(partition_info: &[String], mut distro: &mut Distro) {
    // Test for an ADE repair environment
    distro.is_ade = ade::is_ade_enabled();
    helper::log_info(format!("Ade is enabled : {}", distro.is_ade).as_str());

    match partition_info.len() {
        1 => do_old_ubuntu_or_centos(partition_info, distro),
        2 => do_red_hat(partition_info, distro),
        3 => do_recent_ubuntu(partition_info, distro),
        4 => do_suse_or_lvm_or_ubuntu(partition_info, distro),
        _ => {
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
    }
}
