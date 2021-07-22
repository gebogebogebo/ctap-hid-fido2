use anyhow::Result;

extern crate clap;
use clap::{App, Arg, SubCommand};

use ctap_hid_fido2;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{str_buf, HidParam};

mod bio;
mod info;

fn main() -> Result<()> {
    let app = App::new("ctapcli")
        .version("0.1.0")
        .author("gebo")
        .about("This tool implements CTAP HID and can communicate with FIDO Authenticator.\n\nabout CTAP(Client to Authenticator Protocol)\nhttps://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html")
        .arg(
            Arg::with_name("device")
                .help("Enumerate HID devices")
                .short("d")
                .long("device"),
        )
        .arg(
            Arg::with_name("fidokey")
                .help("Enumerate FIDO key")
                .short("f")
                .long("fidokey"),
        )
        .arg(
            Arg::with_name("pin")
                .help("Get PIN retry counter")
                .short("p")
                .long("pin"),
        )
        .arg(
            Arg::with_name("wink")
                .help("Blink the LED on the FIDO key")
                .short("w")
                .long("wink"),
        )
        .subcommand(
            SubCommand::with_name("info")
                .about("Get Authenticator infomation")
                .arg(
                    Arg::with_name("list")
                        .help("list the Authenticator infomation")
                        .short("l")
                        .long("list"),
                )
                .arg(
                    Arg::with_name("option")
                        .help("get a option(rk/up/uv/plat/pin/mgmtp/mgmt/biop/bio)")
                        .short("o")
                        .long("option")
                        .takes_value(true)
                        .value_name("option type"),
                )
                .arg(
                    Arg::with_name("param")
                        .help("get a parameter(u2f_v2/fido2/fido21p/fido21/hmac)")
                        .short("p")
                        .long("param")
                        .takes_value(true)
                        .value_name("param type"),
                ),
        )
        .subcommand(
            SubCommand::with_name("bio_enrollment")
                .about("authenticatorBioEnrollment (0x09)")
                .arg(
                    Arg::with_name("info")
                        .help("Get fingerprint sensor info")
                        .short("i")
                        .long("info"),
                )
                .arg(
                    Arg::with_name("enumerate")
                        .help("Enumerate enrollments")
                        .short("e")
                        .long("enumerate"),
                )
                .arg(
                    Arg::with_name("enroll")
                        .help("Enrolling fingerprint")
                        .short("n")
                        .long("enroll"),
                )
                .arg(
                    Arg::with_name("rename")
                        .help("Rename/Set FriendlyName")
                        .short("r")
                        .long("rename")
                        .takes_value(true)
                        .value_name("templateId")
                        .value_name("templateFriendlyName"),
                )
                .arg(
                    Arg::with_name("delete")
                        .help("Delete enrollment")
                        .short("d")
                        .long("delete")
                        .takes_value(true)
                        .value_name("templateId"),
                ),
        );

    // Parse arguments
    let matches = app.get_matches();

    // Start
    //ctap_hid_fido2::hello();

    if matches.is_present("device") {
        println!("Enumerate HID devices");
        let devs = ctap_hid_fido2::get_hid_devices();
        for (info, dev) in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , {:?}",
                dev.vid, dev.pid, info
            );
        }
    }

    if matches.is_present("fidokey") {
        println!("Enumerate FIDO key");
        let devs = ctap_hid_fido2::get_fidokey_devices();
        for (info, dev) in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , {:?}",
                dev.vid, dev.pid, info
            );
        }
    }

    if matches.is_present("pin") {
        println!("Get PIN retry counter.\n");
        match ctap_hid_fido2::get_pin_retries(&HidParam::get_default_params()) {
            Ok(mut v) => {
                println!("PIN retry counter = {}", v);

                let mark = if v > 4 {
                    ":) "
                } else if v > 1 {
                    ":( "
                } else {
                    v = 1;
                    ":0 "
                };

                println!("");
                for _ in 0..v {
                    print!("{}", mark);
                }
                println!("");

                println!("");
                println!("PIN retry counter represents the number of attempts left before PIN is disabled.");
                println!("Each correct PIN entry resets the PIN retry counters back to their maximum values.");
                println!("Each incorrect PIN entry decrements the counter by 1.");
                println!("Once the PIN retry counter reaches 0, built-in user verification are disabled and can only be enabled if authenticator is reset.");
            }
            Err(err) => return Err(err),
        };
    }

    if matches.is_present("wink") {
        println!("Blink the LED on the FIDO key.\n");
        match ctap_hid_fido2::wink(&HidParam::get_default_params()) {
            Ok(()) => println!("Do you see that wink? ;-)"),
            Err(err) => return Err(err),
        };
    }

    if let Some(ref matches) = matches.subcommand_matches("info") {
        println!("Get the Authenticator infomation.\n");
        info::info(&matches)?;
    }

    if let Some(ref matches) = matches.subcommand_matches("bio_enrollment") {
        bio::bio_main(&matches, Some("1234"))?;
    }

    /*
    println!("config()");
    match ctap_hid_fido2::config(&HidParam::get_default_params()) {
        Ok(result) => println!("- config : {:?}", result),
        Err(error) => println!("- config error: {:?}", error),
    };

    println!("selection()");
    match ctap_hid_fido2::selection(&HidParam::get_default_params()) {
        Ok(result) => println!("- selection : {:?}", result),
        Err(error) => println!("- selection error: {:?}", error),
    };
    */
    Ok(())
}
