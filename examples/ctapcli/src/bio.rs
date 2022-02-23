extern crate clap;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::InfoOption;
use crate::common;
use crate::CFG;
use crate::str_buf::StrBuf;

#[allow(dead_code)]
pub fn bio(matches: &clap::ArgMatches) -> Result<()> {

    if !(is_supported()?) {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }

    // Title
    if matches.is_present("enroll") {
        println!("Enrolling fingerprint.");
    } else if matches.is_present("delete") {
        println!("Delete a fingerprint.");
    } else if matches.is_present("info") {
        println!("Display sensor info.");
    } else if matches.is_present("test") || matches.is_present("test-with-log") {
        println!("Test register and authenticate.");
    } else {
        println!("List registered biometric authenticate data.");
    }

    if matches.is_present("info") {
        spec()?;
    } else if matches.is_present("test") || matches.is_present("test-with-log") {
        bio_test(matches)?;
    } else {
        let pin = common::get_pin();

        if matches.is_present("delete") {
            delete(matches, &pin)?;
        } else if matches.is_present("enroll") {
            let template_id = bio_enrollment(&pin)?;
            rename(&pin, &template_id)?;
        } else {
            list(&pin)?;
        }
    }

    Ok(())
}

fn rename(pin: &str, template_id: &[u8]) -> Result<()> {
    println!("templateId: {:?}", util::to_hex_str(template_id));
    println!();

    println!("input name:");
    let template_name = common::get_input();
    println!();

    ctap_hid_fido2::bio_enrollment_set_friendly_name(
        &CFG,
        pin,
        template_id,
        &template_name,
    )?;
    println!("- Success\n");
    Ok(())
}

fn bio_enrollment(pin: &str) -> Result<Vec<u8>> {
    //let info = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(&CFG)?;

    println!("bio enrollment");
    //println!(
    //    "{:?} sample collections are required to complete the registration.",
    //    info.max_capture_samples_required_for_enroll
    //);
    println!("Please follow the instructions to touch the sensor on the authenticator.");
    println!();
    println!("Press any key to start the registration.");
    common::get_input();
    println!();

    let (enroll_status1, enroll_status2) =
        ctap_hid_fido2::bio_enrollment_begin(&CFG, pin, Some(10000))?;
    println!();
    println!("{}", enroll_status2.message);
    println!("- Number of samples required = {:?}", enroll_status2.remaining_samples);
    println!();
    
    for _counter in 0..10 {
        if bio_enrollment_next(&enroll_status1)? {
            break;
        }
    }
    println!("- bio enrollment Success\n");
    Ok(enroll_status1.template_id)
}

fn bio_enrollment_next(enroll_status1: &EnrollStatus1) -> Result<bool> {
    let enroll_status2 = ctap_hid_fido2::bio_enrollment_next(&CFG, enroll_status1, Some(10000))?;
    println!();
    println!("{}", enroll_status2.message);
    println!("- Number of samples required = {:?}", enroll_status2.remaining_samples);
    println!();
    Ok(enroll_status2.is_finish)
}

fn is_supported() -> Result<bool> {
    if ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::BioEnroll)?.is_some() {
        return Ok(true);
    }

    if ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::UserVerificationMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn list(pin: &str) -> Result<()> {
    let template_infos = ctap_hid_fido2::bio_enrollment_enumerate_enrollments(&CFG, pin)?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &template_infos.len());
    for template_info in template_infos {
        strbuf.addln(&format!("{}", template_info));
    }
    println!("{}", strbuf.build().to_string());

    Ok(())
}

fn spec() -> Result<()> {
    let sensor_info = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(&CFG)?;
    println!("{}", sensor_info);
    Ok(())
}

fn delete(matches: &clap::ArgMatches, pin: &str) -> Result<()> {
    let template_id = matches.value_of("delete").unwrap();
    println!("Delete enrollment");
    println!("value for templateId: {:?}", template_id);
    println!();

    let mut cfg = ctap_hid_fido2::Cfg::init();
    cfg.keep_alive_msg = "- Deleting ...".to_string();
    ctap_hid_fido2::bio_enrollment_remove(&cfg, pin, &util::to_str_hex(template_id))?;
    println!("- Success\n");
    Ok(())
}

fn bio_test(matches: &clap::ArgMatches) -> Result<()> {
    let log = if matches.is_present("test-with-log") {
        true
    } else {
        false
    };

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
    let att = ctap_hid_fido2::make_credential(&CFG, rpid, &challenge, pin)?;

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

    let ass = ctap_hid_fido2::get_assertion(
        &CFG,
        rpid,
        &challenge,
        &verify_result.credential_id,
        pin,
    )?;

    if log {
        println!("Assertion");
        println!("{}", ass);
    }

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
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
