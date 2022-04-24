use anyhow::{anyhow, Result};

extern crate clap;
use clap::{Parser, Subcommand};

#[cfg(not(target_os = "linux"))]
extern crate clipboard;

extern crate rpassword;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{str_buf, Cfg, FidoKeyHid, FidoKeyHidFactory};

use ctap_hid_fido2::fidokey::get_info::InfoParam;

mod bio;
mod common;
mod cred;
mod info;
mod memo;
mod pin;

#[derive(Parser)]
#[clap(
    name = "ctapcli",
    author = "gebo",
    version = env!("CARGO_PKG_VERSION"),
    about = "This tool implements CTAP HID and can communicate with FIDO Authenticator.\n\nabout CTAP(Client to Authenticator Protocol)\nhttps://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html"
)]
struct AppArg {
    #[clap(
        short = 'd',
        long = "device",
        takes_value = false,
        help = "Enumerate HID devices."
    )]
    device: bool,

    #[clap(
        short = 'f',
        long = "fidokey",
        takes_value = false,
        help = "Enumerate FIDO key."
    )]
    fidokey: bool,

    #[clap(
        short = 'w',
        long = "wink",
        takes_value = false,
        help = "Blink the LED on the FIDO key."
    )]
    wink: bool,

    #[clap(
        short = 'u',
        long = "user-presence",
        takes_value = false,
        help = "User Presence Test."
    )]
    user_presence: bool,

    #[clap(subcommand)]
    action: Action,    
}

#[derive(Subcommand)]
enum Action {
    Info {
        #[clap(
            short = 'g',
            long = "get",
            takes_value = true,
            default_value = "",
            help = "Get a item(rk/up/uv/plat/pin/mgmtp/mgmt/biop/bio/u2f_v2/fido2/fido21p/fido21/hmac)."
        )]
        item: String,
    },

    Pin {
        #[clap(
            short = 'n',
            long = "new",
            takes_value = false,
            help = "Set new pin."
        )]
        new: bool,

        #[clap(
            short = 'c',
            long = "change",
            takes_value = false,
            help = "Change pin."
        )]
        change: bool,        
    },
}

fn main() -> Result<()> {
    env_logger::init();
    /*
    let app = App::new("ctapcli")
        .subcommand(
            SubCommand::with_name("pin")
                .about("PIN management\n- Get PIN retry counter without any FLAGS and OPTIONS.")
        )
        .subcommand(
            SubCommand::with_name("info")
                .about("Get Authenticator infomation\n- List All Infomation without any FLAGS and OPTIONS.")
        )
        .subcommand(
            SubCommand::with_name("memo")
                .about("Record some short texts in Authenticator\n- Get a Memo without any FLAGS and OPTIONS.")
                .arg(
                    Arg::with_name("add")
                        .help("Add a memo")
                        .short("a")
                        .long("add")
                )
                .arg(
                    Arg::with_name("get")
                        .help("Get a memo to Clipboard")
                        .short("g")
                        .long("get")
                        .takes_value(true)
                        .value_name("tag")
                )
                .arg(
                    Arg::with_name("del")
                        .help("Delete a memo")
                        .short("d")
                        .long("del")
                        .takes_value(true)
                        .value_name("tag")
                )
                .arg(
                    Arg::with_name("list")
                        .help("List all memos")
                        .short("l")
                        .long("list")
                )
        )
        .subcommand(
            SubCommand::with_name("bio")
                .about("Bio management\n- List registered biometric authenticate data. without any FLAGS and OPTIONS.")
                .arg(
                    Arg::with_name("list")
                        .help("List bio")
                        .short("l")
                        .long("list")
                )
                .arg(
                    Arg::with_name("info")
                        .help("Display sensor info")
                        .short("i")
                        .long("info")
                )
                .arg(
                    Arg::with_name("enroll")
                        .help("Enrolling fingerprint")
                        .short("e")
                        .long("enroll"),
                )
                .arg(
                    Arg::with_name("delete")
                        .help("Delete fingerprint")
                        .short("d")
                        .long("delete")
                        .takes_value(true)
                        .value_name("templateId")
                )
                .arg(
                    Arg::with_name("test")
                        .help("Test register and authenticate")
                        .long("test")
                )
               .arg(
                    Arg::with_name("test-with-log")
                        .help("Test register and authenticate(with log)")
                        .long("test-log")
                )
        )
        .subcommand(
            SubCommand::with_name("cred")
                .about("(alpha)Credential management\n- Enumerate discoverable credentials")
                .arg(
                    Arg::with_name("list")
                        .help("List cred.")
                        .short("l")
                        .long("list")
                )
                .arg(
                    Arg::with_name("metadata")
                        .help("Getting Credentials Metadata.")
                        .short("m")
                        .long("metadata"),
                )
                .arg(
                    Arg::with_name("delete")
                        .help("Delete a discoverable credential.")
                        .short("d")
                        .long("delete")
                )
                .arg(
                    Arg::with_name("update")
                        .help("[Always an error?]Update a discoverable credential user info.")
                        .short("u")
                        .long("update")
                )
                .arg(
                    Arg::with_name("rpid")
                        .help("rpid to be deleted(or updated).")
                        .long("rpid")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("user-id")
                        .help("user-id to be deleted(or updated).")
                        .long("userid")
                        .takes_value(true)
                )
        );
     */

    let arg: AppArg = AppArg::parse();

    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.use_pre_bio_enrollment = true;
    cfg.use_pre_credential_management = true;

    if arg.device {
        println!("Enumerate HID devices.");
        let devs = ctap_hid_fido2::get_hid_devices();
        for info in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
                info.vid, info.pid, info.info
            );
        }
    }

    if arg.fidokey {
        println!("Enumerate FIDO keys.");
        let devs = ctap_hid_fido2::get_fidokey_devices();
        for info in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
                info.vid, info.pid, info.info
            );
        }
    }

    let device = FidoKeyHidFactory::create(&cfg)?;

    if arg.user_presence {
        println!("User Presence Test.\n");
        up(&device)?;
    }

    if arg.wink {
        println!("Blink LED on FIDO key.\n");
        device.wink()?;
        println!("Do you see that wink? ;-)\n");
    }

    match arg.action {
        Action::Info { item } => {
            println!("Get the Authenticator infomation.\n");
            info::info(&device, &item)?;
        },
        Action::Pin {new,change} => {
            println!("PIN Management.\n");
            pin::pin(&device, new, change)?;
        }
    }

    /*
    if let Some(matches) = matches.subcommand_matches("memo") {
        println!("Record some short texts in Authenticator.\n");
        memo::memo(&device, matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("bio") {
        println!("Bio Management.\n");
        bio::bio(&device, matches)?;
    }

    if let Some(ref matches) = matches.subcommand_matches("cred") {
        println!("Credential Management.\n");
        cred::cred(&device, &matches)?;
    }
     */

    /*
    println!("config()");
    match ctap_hid_fido2::config(&HidParam::get_default_params()) {
        Ok(result) => println!("- config : {:?}", result),
        Err(error) => println!("- config error: {:?}", error),
    };
    */

    Ok(())
}

pub fn up(device: &FidoKeyHid) -> Result<()> {
    if !device.enable_info_param(&InfoParam::VersionsFido21)? {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }
    device.selection()?;
    Ok(())
}
