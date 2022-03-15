use anyhow::{anyhow, Result};

extern crate clap;
use clap::{App, Arg, SubCommand};

#[cfg(not(target_os = "linux"))]
extern crate clipboard;

extern crate rpassword;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{str_buf, Cfg, InfoParam};

mod bio;
mod common;
mod cred;
mod info;
mod memo;
mod pin;


use once_cell::sync::Lazy;
static CFG: Lazy<Cfg> = Lazy::new(|| load_cfg());
fn load_cfg() -> ctap_hid_fido2::Cfg {
    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.use_pre_bio_enrollment = true;
    cfg.use_pre_credential_management = true;
    cfg
}

fn main() -> Result<()> {

    let app = App::new("ctapcli")
        .version("0.0.8")
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
                        .help("List cred")
                        .short("l")
                        .long("list")
                )
                .arg(
                    Arg::with_name("metadata")
                        .help("credential_management_get_creds_metadata")
                        .short("m")
                        .long("metadata"),
                )
        );

    // Parse arguments
    let matches = app.get_matches();

    // Start
    //ctap_hid_fido2::hello();

    if matches.is_present("device") {
        println!("Enumerate HID devices.");
        let devs = ctap_hid_fido2::get_hid_devices();
        for (info, dev) in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , {:?}",
                dev.vid, dev.pid, info
            );
        }
    }

    if matches.is_present("fidokey") {
        println!("Enumerate FIDO key.");
        let devs = ctap_hid_fido2::get_fidokey_devices();
        for (info, dev) in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , {:?}",
                dev.vid, dev.pid, info
            );
        }
    }

    if matches.is_present("user-presence") {
        println!("User Presence Test.\n");
        up()?;
    }

    if matches.is_present("wink") {
        println!("Blink LED on FIDO key.\n");
        ctap_hid_fido2::wink(&CFG)?;
        println!("Do you see that wink? ;-)\n");
    }

    if let Some(matches) = matches.subcommand_matches("info") {
        println!("Get the Authenticator infomation.\n");
        info::info(matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("pin") {
        println!("PIN Management.\n");
        pin::pin(matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("memo") {
        println!("Record some short texts in Authenticator.\n");
        memo::memo(matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("bio") {
        println!("Bio Management.\n");
        bio::bio(matches)?;
    }

    if let Some(ref matches) = matches.subcommand_matches("cred") {
        println!("Credential Management.\n");
        cred::cred(&matches)?;
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

pub fn up() -> Result<()> {
    if !ctap_hid_fido2::enable_info_param(&CFG, &InfoParam::VersionsFido21)? {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }
    ctap_hid_fido2::selection(&CFG)?;
    Ok(())
}
