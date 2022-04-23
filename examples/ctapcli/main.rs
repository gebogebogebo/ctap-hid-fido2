use anyhow::{anyhow, Result};

extern crate clap;
use clap::{App, Arg, SubCommand};

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

fn main() -> Result<()> {
    env_logger::init();
    let app = App::new("ctapcli")
        .version(env!("CARGO_PKG_VERSION"))
        .author("gebo")
        .about("This tool implements CTAP HID and can communicate with FIDO Authenticator.\n\nabout CTAP(Client to Authenticator Protocol)\nhttps://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html")
        .arg(
            Arg::with_name("device")
                .help("Enumerate HID devices")
                .short("d")
                .long("device")
        )
        .arg(
            Arg::with_name("fidokey")
                .help("Enumerate FIDO key")
                .short("f")
                .long("fidokey")
        )
        .arg(
            Arg::with_name("wink")
                .help("Blink the LED on the FIDO key")
                .short("w")
                .long("wink")
        )
        .arg(
            Arg::with_name("user-presence")
                .help("User Presence Test")
                .short("u")
                .long("up")
        )
        .subcommand(
            SubCommand::with_name("pin")
                .about("PIN management\n- Get PIN retry counter without any FLAGS and OPTIONS.")
                .arg(
                    Arg::with_name("new")
                        .help("Set new pin")
                        .short("n")
                        .long("new")
                )
                .arg(
                    Arg::with_name("change")
                        .help("Change pin")
                        .short("c")
                        .long("change")
                )
        )
        .subcommand(
            SubCommand::with_name("info")
                .about("Get Authenticator infomation\n- List All Infomation without any FLAGS and OPTIONS.")
                .arg(
                    Arg::with_name("get")
                        .help("Get a item(rk/up/uv/plat/pin/mgmtp/mgmt/biop/bio/u2f_v2/fido2/fido21p/fido21/hmac)")
                        .short("g")
                        .long("get")
                        .takes_value(true)
                        .value_name("item")
                )
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
                        .takes_value(true)
                        .value_name("public_key_credential_descriptor.id(credential-id)"),
                )
                .arg(
                    Arg::with_name("update")
                        .help("Update a discoverable credential user info.")
                        .short("u")
                        .long("update")
                        .takes_value(true)
                        .value_name("public_key_credential_descriptor.id(credential-id)"),
                )
        );

    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.use_pre_bio_enrollment = true;
    cfg.use_pre_credential_management = true;

    // Parse arguments
    let matches = app.get_matches();

    if matches.is_present("device") {
        println!("Enumerate HID devices.");
        let devs = ctap_hid_fido2::get_hid_devices();
        for info in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
                info.vid, info.pid, info.info
            );
        }
    }

    if matches.is_present("fidokey") {
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

    if matches.is_present("user-presence") {
        println!("User Presence Test.\n");
        up(&device)?;
    }

    if matches.is_present("wink") {
        println!("Blink LED on FIDO key.\n");
        device.wink()?;
        println!("Do you see that wink? ;-)\n");
    }

    if let Some(matches) = matches.subcommand_matches("info") {
        println!("Get the Authenticator infomation.\n");
        info::info(&device, matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("pin") {
        println!("PIN Management.\n");
        pin::pin(&device, matches)?;
    }

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
