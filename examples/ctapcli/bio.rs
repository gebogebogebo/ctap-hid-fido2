extern crate clap;
use anyhow::{anyhow, Result};

use log::{debug, log_enabled, Level};

use crate::common;
use crate::str_buf::StrBuf;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

use ctap_hid_fido2::fidokey::{bio::EnrollStatus1, get_info::InfoOption, FidoKeyHid};

pub enum Command {
    List,
    Info,
    Enroll,
    Del(String),
    Test(bool),
}

pub fn bio(device: &FidoKeyHid, command: Command) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Bio management."
        ));
    }

    // Title
    match command {
        Command::Enroll => println!("Enrolling fingerprint."),
        Command::Del(_) => println!("Delete a fingerprint."),
        Command::Info => println!("Display sensor info."),
        Command::Test(_) => println!("Test register and authenticate."),
        Command::List => println!("List registered biometric authenticate data."),
    }

    match command {
        Command::Info => spec(device)?,
        Command::Test(log) => bio_test(device, log)?,
        _ => {
            let pin = common::get_pin()?;

            match command {
                Command::Del(template_id) => delete(device, &template_id, &pin)?,
                Command::Enroll => {
                    let template_id = bio_enrollment(device, &pin)?;
                    rename(device, &pin, &template_id)?;
                }
                _ => list(device, &pin)?,
            }
        }
    }

    Ok(())
}

fn rename(device: &FidoKeyHid, pin: &str, template_id: &[u8]) -> Result<()> {
    println!("templateId: {:?}", util::to_hex_str(template_id));
    println!();

    println!("input name:");
    let template_name = common::get_input();
    println!();

    device.bio_enrollment_set_friendly_name(pin, template_id, &template_name)?;
    println!("- Success\n");
    Ok(())
}

fn bio_enrollment(device: &FidoKeyHid, pin: &str) -> Result<Vec<u8>> {
    println!("bio enrollment");
    if log_enabled!(Level::Debug) {
        let info = device.bio_enrollment_get_fingerprint_sensor_info()?;
        debug!(
            "{:?} sample collections are required to complete the registration.",
            info.max_capture_samples_required_for_enroll
        );
    }

    println!("Please follow the instructions to touch the sensor on the authenticator.");
    println!();
    println!("Press any key to start the registration.");
    common::get_input();
    println!();

    let (enroll_status1, enroll_status2) = device.bio_enrollment_begin(pin, Some(10000))?;
    println!();
    println!("{}", enroll_status2.message);
    println!(
        "- Number of samples required = {:?}",
        enroll_status2.remaining_samples
    );
    println!();

    for _counter in 0..10 {
        if bio_enrollment_next(device, &enroll_status1)? {
            break;
        }
    }
    println!("- bio enrollment Success\n");
    Ok(enroll_status1.template_id)
}

fn bio_enrollment_next(device: &FidoKeyHid, enroll_status1: &EnrollStatus1) -> Result<bool> {
    let enroll_status2 = device.bio_enrollment_next(enroll_status1, Some(10000))?;
    println!();
    println!("{}", enroll_status2.message);
    println!(
        "- Number of samples required = {:?}",
        enroll_status2.remaining_samples
    );
    println!();
    Ok(enroll_status2.is_finish)
}

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device.enable_info_option(&InfoOption::BioEnroll)?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&InfoOption::UserVerificationMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn list(device: &FidoKeyHid, pin: &str) -> Result<()> {
    let template_infos = device.bio_enrollment_enumerate_enrollments(pin)?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &template_infos.len());
    for template_info in template_infos {
        strbuf.addln(&format!("{}", template_info));
    }
    println!("{}", strbuf.build());

    Ok(())
}

fn spec(device: &FidoKeyHid) -> Result<()> {
    let sensor_info = device.bio_enrollment_get_fingerprint_sensor_info()?;
    println!("{}", sensor_info);
    Ok(())
}

fn delete(device: &FidoKeyHid, template_id: &str, pin: &str) -> Result<()> {
    println!("Delete enrollment");
    println!("value for templateId: {:?}", template_id);
    println!();

    let mut cfg = ctap_hid_fido2::Cfg::init();
    cfg.keep_alive_msg = "- Deleting ...".to_string();
    device.bio_enrollment_remove(pin, &util::to_str_hex(template_id))?;
    println!("- Success\n");
    Ok(())
}

fn bio_test(device: &FidoKeyHid, log: bool) -> Result<()> {
    let rpid = "ctapcli.test";
    let pin = None;
    let challenge = verifier::create_challenge();
    let pad_to_width = 42;

    // Register
    println!();
    println!("Register");
    if log {
        let mut strbuf = StrBuf::new(pad_to_width);
        println!(
            "{}",
            strbuf
                .appent("make_credential()")
                .append("- rpid", &rpid)
                .appenh("- challenge", &challenge)
                .build()
        );
    }
    let att = device.make_credential(rpid, &challenge, pin)?;

    if log {
        println!("Attestation");
        println!("{}", att);
    }

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    if log {
        let mut strbuf = StrBuf::new(pad_to_width);
        println!(
            "{}",
            strbuf
                .append("- is_success", &verify_result.is_success)
                .appenh("- credential_id", &verify_result.credential_id)
                .build()
        );
    }

    if verify_result.is_success {
        println!("Register Success !!\n");
    } else {
        println!("Register Failure !!\n");
    }

    // Authenticate
    let challenge = verifier::create_challenge();

    println!("Authenticate");
    if log {
        let mut strbuf = StrBuf::new(pad_to_width);
        println!(
            "{}",
            strbuf
                .appent("get_assertion()")
                .appenh("- challenge", &challenge)
                .build()
        );
    }

    let ass = device.get_assertion(rpid, &challenge, &[verify_result.credential_id], pin)?;

    if log {
        println!("Assertion");
        println!("{}", ass);
    }

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &ass,
    );
    if is_success {
        println!("Authenticate Success !!\n");
    } else {
        println!("Authenticate Failure !!\n");
    }

    println!("Register and Authenticate End\n");

    Ok(())
}
