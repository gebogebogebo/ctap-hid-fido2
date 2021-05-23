use ctap_hid_fido2;
use anyhow::{Result};

use ctap_hid_fido2::bio_enrollment_params::TemplateInfo;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption, InfoParam};

extern crate clap;
use clap::{App, Arg, SubCommand};
use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;

fn main() -> Result<()> {
    let app = App::new("test-ctap21")
        .version("0.1.0")
        .author("gebo")
        .about("CTAP 2.1 command test app")
        .arg(
            Arg::with_name("pin")
                .help("pin")
                .short("p")
                .long("pin")
                .takes_value(true)
                .default_value("1234"),
        )
        .arg(
            Arg::with_name("info")
                .help("authenticatorGetInfo")
                .short("i")
                .long("info"),
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
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_info_param(
        &HidParam::get_default_params(),
        InfoParam::VersionsFido21Pre,
    ) {
        Ok(result) => println!("FIDO 2.1 PRE = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    match ctap_hid_fido2::enable_info_option(&HidParam::get_default_params(), InfoOption::CredMgmt)
    {
        Ok(result) => println!("CredMgmt = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    match ctap_hid_fido2::enable_info_option(
        &HidParam::get_default_params(),
        InfoOption::CredentialMgmtPreview,
    ) {
        Ok(result) => println!("CredentialMgmtPreview = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    match ctap_hid_fido2::enable_info_option(
        &HidParam::get_default_params(),
        InfoOption::UserVerificationMgmtPreview,
    ) {
        Ok(result) => println!("UserVerificationMgmtPreview = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    }

    match ctap_hid_fido2::enable_info_option(&HidParam::get_default_params(), InfoOption::BioEnroll)
    {
        Ok(result) => println!("BioEnroll = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    if matches.is_present("info") {
        println!("get_info()");
        match ctap_hid_fido2::get_info(&HidParam::get_default_params()) {
            Ok(info) => println!("{}", info),
            Err(error) => println!("error: {:?}", error),
        };
    }

    let pin = matches.value_of("pin");
    println!("Value for pin: {:?}", pin);
    println!("");
    println!("");

    // bio_enrollment
    if let Some(ref matches) = matches.subcommand_matches("bio_enrollment") {
        println!("used authenticatorBioEnrollment");
        println!("");

        if matches.is_present("info") {
            println!("Get fingerprint sensor info");
            match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
                &HidParam::get_default_params(),
            ) {
                Ok(result) => println!("- {:?}", result),
                Err(e) => println!("- error: {:?}", e),
            }
            println!("");
        }

        if matches.is_present("enumerate") {
            println!("Enumerate enrollments");
            match ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
                &HidParam::get_default_params(),
                pin,
            ) {
                Ok(infos) => {
                    for i in infos {
                        println!("- {}", i)
                    }
                }
                Err(e) => println!("- error: {:?}", e),
            }
            println!("");
        }

        if matches.is_present("rename") {
            let mut values = matches.values_of("rename").unwrap();
            let template_id = values.next().unwrap();
            let name = values.next();
            println!("Rename/Set FriendlyName");
            println!("- value for templateId: {:?}", template_id);
            println!("- value for templateFriendlyName: {:?}", name);
            println!("");

            match ctap_hid_fido2::bio_enrollment_set_friendly_name(
                &HidParam::get_default_params(),
                pin,
                TemplateInfo::new(util::to_str_hex(template_id), name),
            ) {
                Ok(_) => println!("- Success"),
                Err(e) => println!("- error: {:?}", e),
            }
            println!("");
        }

        if matches.is_present("delete") {
            let template_id = matches.value_of("delete").unwrap();
            println!("Delete enrollment");
            println!("- value for templateId: {:?}", template_id);
            println!("");

            match ctap_hid_fido2::bio_enrollment_remove(
                &HidParam::get_default_params(),
                pin,
                util::to_str_hex(template_id),
            ) {
                Ok(_) => println!("- Success"),
                Err(e) => println!("- error: {:?}", e),
            }
            println!("");
        }

        if matches.is_present("enroll") {
            match bio_enrollment(pin.unwrap()) {
                Ok(_) => println!("- Success"),
                Err(e) => println!("- error: {:?}", e),
            }
        }
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

fn bio_enrollment(pin: &str) -> Result<()> {
    println!("bio_enrollment_begin");
    let result = ctap_hid_fido2::bio_enrollment_begin(
        &HidParam::get_default_params(),
        Some(pin),
        Some(10000),
    )?;
    println!("{}", result.1);
    println!("");

    for _counter in 0..10 {
        if bio_enrollment_next(&result.0)? {
            break;
        }
    }
    Ok(())
}

fn bio_enrollment_next(enroll_status: &EnrollStatus1) -> Result<bool> {
    println!("bio_enrollment_next");
    let result = ctap_hid_fido2::bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}", result);
    println!("");
    Ok(result.is_finish)
}
