use anyhow::{anyhow, Result};

use crate::common;
use crate::str_buf::StrBuf;
use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::{InfoOption, Key, Cfg};

extern crate clap;

#[allow(dead_code)]
pub fn bio(matches: &clap::ArgMatches, cfg: &Cfg) -> Result<()> {
    if !(is_supported(cfg)?) {
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
        spec(cfg)?;
    } else if matches.is_present("test") || matches.is_present("test-with-log") {
        bio_test(matches, cfg)?;
    } else {
        let pin = common::get_pin();
        //let pin = "1234";

        if matches.is_present("delete") {
            delete(matches, cfg, &pin)?;
        } else if matches.is_present("enroll") {
            let template_id = bio_enrollment(cfg, &pin)?;
            rename(cfg, &pin, &template_id)?;
        } else {
            list(cfg, &pin)?;
        }
    }

    Ok(())
}

fn rename(cfg: &Cfg, pin: &str, template_id: &[u8]) -> Result<()> {
    println!("templateId: {:?}", util::to_hex_str(template_id));
    println!();

    println!("input name:");
    let template_name = common::get_input();
    println!();

    ctap_hid_fido2::bio_enrollment_set_friendly_name(
        cfg,
        pin,
        template_id,
        &template_name,
    )?;
    println!("- Success\n");
    Ok(())
}

fn bio_enrollment(cfg: &Cfg, pin: &str) -> Result<Vec<u8>> {
    let info = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(cfg)?;

    println!("bio enrollment");
    println!(
        "{:?} sample collections are required to complete the registration.",
        info.max_capture_samples_required_for_enroll
    );
    println!("Please follow the instructions to touch the sensor on the authenticator.");
    println!();
    println!("Press any key to start the registration.");
    common::get_input();
    println!();

    let (enroll_status1, enroll_status2) =
        ctap_hid_fido2::bio_enrollment_begin(cfg, pin, Some(10000))?;
    println!("{}\n", enroll_status2);

    for _counter in 0..10 {
        if bio_enrollment_next(cfg, &enroll_status1)? {
            break;
        }
    }
    println!("- bio enrollment Success\n");
    Ok(enroll_status1.template_id)
}

fn bio_enrollment_next(cfg: &Cfg, enroll_status1: &EnrollStatus1) -> Result<bool> {
    println!("bio enrollment Status");
    let enroll_status2 = ctap_hid_fido2::bio_enrollment_next(cfg, enroll_status1, Some(10000))?;
    println!("{}\n", enroll_status2);
    Ok(enroll_status2.is_finish)
}

fn is_supported(cfg: &Cfg) -> Result<bool> {
    if ctap_hid_fido2::enable_info_option(&Key::auto(), &InfoOption::BioEnroll)?.is_some() {
        return Ok(true);
    }

    if ctap_hid_fido2::enable_info_option(&Key::auto(), &InfoOption::UserVerificationMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn list(cfg: &Cfg, pin: &str) -> Result<()> {
    let template_infos = ctap_hid_fido2::bio_enrollment_enumerate_enrollments(cfg, pin)?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &template_infos.len());
    for template_info in template_infos {
        strbuf.addln(&format!("{}", template_info));
    }
    println!("{}", strbuf.build().to_string());

    Ok(())
}

fn spec(cfg: &Cfg) -> Result<()> {
    let sensor_info = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(cfg)?;
    println!("{}", sensor_info);
    Ok(())
}

fn delete(matches: &clap::ArgMatches, cfg: &Cfg, pin: &str) -> Result<()> {
    let template_id = matches.value_of("delete").unwrap();
    println!("Delete enrollment");
    println!("value for templateId: {:?}", template_id);
    println!();

    ctap_hid_fido2::bio_enrollment_remove(cfg, pin, &util::to_str_hex(template_id))?;
    println!("- Success\n");
    Ok(())
}

fn bio_test(matches: &clap::ArgMatches, cfg: &Cfg) -> Result<()> {
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
    let att = ctap_hid_fido2::make_credential(&Key::auto(), rpid, &challenge, pin)?;

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
        &Key::auto(),
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
