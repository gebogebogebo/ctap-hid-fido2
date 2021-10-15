use anyhow::{anyhow, Result};

use crate::common;
use crate::str_buf::StrBuf;
use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
use ctap_hid_fido2::bio_enrollment_params::TemplateInfo;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{InfoOption, Key};

extern crate clap;

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
    } else {
        println!("List registered biometric authenticate data.");
    }

    //let pin = common::get_pin();
    let pin = "1234";

    if matches.is_present("delete") {
        delete(matches, pin)?;
    } else if matches.is_present("enroll") {
        let template_id = bio_enrollment(pin)?;
        rename(pin, &template_id)?;
    } else if matches.is_present("info") {
        spec(pin)?;
    } else {
        list(pin)?;
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
        &Key::auto(),
        Some(pin),
        TemplateInfo::new(template_id.to_vec(), Some(&template_name)),
    )?;
    println!("- Success\n");
    Ok(())
}

fn bio_enrollment(pin: &str) -> Result<Vec<u8>> {
    let info = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(&Key::auto())?;

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

    let result = ctap_hid_fido2::bio_enrollment_begin(&Key::auto(), Some(pin), Some(10000))?;
    println!("{}\n", result.1);

    for _counter in 0..10 {
        if bio_enrollment_next(&result.0)? {
            break;
        }
    }
    println!("- bio enrollment Success\n");
    Ok(result.0.template_id)
}

fn bio_enrollment_next(enroll_status: &EnrollStatus1) -> Result<bool> {
    println!("bio enrollment Status");
    let result = ctap_hid_fido2::bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}\n", result);
    Ok(result.is_finish)
}

fn is_supported() -> Result<bool> {
    let option = ctap_hid_fido2::enable_info_option(&Key::auto(), &InfoOption::BioEnroll)?;
    if option != None && option.unwrap() {
        return Ok(true);
    }

    let option =
        ctap_hid_fido2::enable_info_option(&Key::auto(), &InfoOption::UserVerificationMgmtPreview)?;
    if option != None && option.unwrap() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn list(pin: &str) -> Result<()> {
    let bios = ctap_hid_fido2::bio_enrollment_enumerate_enrollments(&Key::auto(), Some(pin))?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &bios.len());
    for i in bios {
        strbuf.addln(&format!("{}", i));
    }
    println!("{}", strbuf.build().to_string());

    Ok(())
}

fn spec(_pin: &str) -> Result<()> {
    let result = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(&Key::auto())?;
    println!("{}", result);

    Ok(())
}

fn delete(matches: &clap::ArgMatches, pin: &str) -> Result<()> {
    let template_id = matches.value_of("delete").unwrap();
    println!("Delete enrollment");
    println!("value for templateId: {:?}", template_id);
    println!();

    ctap_hid_fido2::bio_enrollment_remove(&Key::auto(), Some(pin), util::to_str_hex(template_id))?;
    println!("- Success\n");
    Ok(())
}
