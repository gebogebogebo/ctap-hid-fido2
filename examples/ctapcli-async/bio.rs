extern crate clap;
use anyhow::{anyhow, Result};

use log::{debug, log_enabled, Level};

use crate::common;
use crate::str_buf::StrBuf;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

use ctap_hid_fido2::fidokey::{bio::EnrollStatus1, get_info::InfoOption, FidoKeyHidAsync};

pub enum Command {
    List,
    Info,
    Enroll,
    Del(String),
    Test(bool),
}

pub async fn bio(device: &FidoKeyHidAsync, command: Command) -> Result<()> {
    if !(is_supported(device).await?) {
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
        Command::Info => spec(device).await?,
        Command::Test(log) => bio_test(device, log).await?,
        _ => {
            let pin = common::get_pin().await?;

            match command {
                Command::Del(template_id) => delete(device, &template_id, &pin).await?,
                Command::Enroll => {
                    let template_id = bio_enrollment(device, &pin).await?;
                    rename(device, &pin, &template_id).await?;
                }
                _ => list(device, &pin).await?,
            }
        }
    }

    Ok(())
}

async fn rename(device: &FidoKeyHidAsync, pin: &str, template_id: &[u8]) -> Result<()> {
    println!("templateId: {:?}", util::to_hex_str(template_id));
    println!();

    println!("input name:");
    let template_name = common::get_input().await?;
    println!();

    device.bio_enrollment_set_friendly_name(pin, template_id, &template_name).await?;
    println!("- Success\n");
    Ok(())
}

async fn bio_enrollment(device: &FidoKeyHidAsync, pin: &str) -> Result<Vec<u8>> {
    println!("bio enrollment");
    if log_enabled!(Level::Debug) {
        let info = device.bio_enrollment_get_fingerprint_sensor_info().await?;
        debug!(
            "{:?} sample collections are required to complete the registration.",
            info.max_capture_samples_required_for_enroll
        );
    }

    println!("Please follow the instructions to touch the sensor on the authenticator.");
    println!();
    println!("Press any key to start the registration.");
    common::get_input().await?;
    println!();

    let (enroll_status1, enroll_status2) = device.bio_enrollment_begin(pin, Some(10000)).await?;
    println!();
    println!("{}", enroll_status2.message);
    println!(
        "- Number of samples required = {:?}",
        enroll_status2.remaining_samples
    );
    println!();

    for _counter in 0..10 {
        if bio_enrollment_next(device, &enroll_status1).await? {
            break;
        }
    }
    println!("- bio enrollment Success\n");
    Ok(enroll_status1.template_id)
}

async fn bio_enrollment_next(device: &FidoKeyHidAsync, enroll_status1: &EnrollStatus1) -> Result<bool> {
    let enroll_status2 = device.bio_enrollment_next(enroll_status1, Some(10000)).await?;
    println!();
    println!("{}", enroll_status2.message);
    println!(
        "- Number of samples required = {:?}",
        enroll_status2.remaining_samples
    );
    println!();
    Ok(enroll_status2.is_finish)
}

async fn is_supported(device: &FidoKeyHidAsync) -> Result<bool> {
    if device.enable_info_option(&InfoOption::BioEnroll).await?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&InfoOption::UserVerificationMgmtPreview).await?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn list(device: &FidoKeyHidAsync, pin: &str) -> Result<()> {
    let template_infos = device.bio_enrollment_enumerate_enrollments(pin).await?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &template_infos.len());
    for template_info in template_infos {
        strbuf.addln(&format!("{}", template_info));
    }
    println!("{}", strbuf.build());

    Ok(())
}

async fn spec(device: &FidoKeyHidAsync) -> Result<()> {
    let sensor_info = device.bio_enrollment_get_fingerprint_sensor_info().await?;
    println!("{}", sensor_info);
    Ok(())
}

async fn delete(device: &FidoKeyHidAsync, template_id: &str, pin: &str) -> Result<()> {
    println!("Delete enrollment");
    println!("value for templateId: {:?}", template_id);
    println!();

    let mut cfg = ctap_hid_fido2::Cfg::init();
    cfg.keep_alive_msg = "- Deleting ...".to_string();
    device.bio_enrollment_remove(pin, &util::to_str_hex(template_id)).await?;
    println!("- Success\n");
    Ok(())
}

async fn bio_test(device: &FidoKeyHidAsync, log: bool) -> Result<()> {
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
    let att = device.make_credential(rpid, &challenge, pin).await?;

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

    let ass = device.get_assertion(rpid, &challenge, &[verify_result.credential_id], pin).await?;

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
