use anyhow::{anyhow, Result};

use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
use ctap_hid_fido2::bio_enrollment_params::TemplateInfo;
use ctap_hid_fido2::bio_enrollment_params::FingerprintKind;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{Key, InfoOption};
use crate::str_buf::StrBuf;

extern crate clap;

#[allow(dead_code)]
pub fn bio(matches: &clap::ArgMatches) -> Result<()> {

    if is_supported()? == false {
        return Err(anyhow!(
            "Sorry , This authenticator is not supported for this functions."
        ));
    }

    // Title
    if matches.is_present("enroll") {
        //println!("List registered biometric authenticate data.");
    } else if matches.is_present("delete") {
        // 
    } else if matches.is_present("spec") {
        println!("Display sensor info.");
    } else {
        println!("List registered biometric authenticate data.");
    }

    //let pin = common::get_pin();
    let pin = "1234";

    if matches.is_present("rename") {
        let mut values = matches.values_of("rename").unwrap();
        let template_id = values.next().unwrap();
        let name = values.next();
        println!("Rename/Set FriendlyName");
        println!("- value for templateId: {:?}", template_id);
        println!("- value for templateFriendlyName: {:?}", name);
        println!("");

        ctap_hid_fido2::bio_enrollment_set_friendly_name(
            &Key::auto(),
            Some(pin),
            TemplateInfo::new(util::to_str_hex(template_id), name),
        )?;
        println!("- Success\n");
    } else if matches.is_present("delete") {
        let template_id = matches.value_of("delete").unwrap();
        println!("Delete enrollment");
        println!("- value for templateId: {:?}", template_id);
        println!("");

        ctap_hid_fido2::bio_enrollment_remove(
            &Key::auto(),
            Some(pin),
            util::to_str_hex(template_id),
        )?;
        println!("- Success\n");
    } else if matches.is_present("enroll") {
        bio_enrollment(pin)?;
        println!("- Success\n");
    } else if matches.is_present("spec") {
        spec(&pin)?;
    } else {
        list(&pin)?;
    }

    Ok(())
}

#[allow(dead_code)]
fn bio_enrollment(pin: &str) -> Result<()> {
    println!("bio_enrollment_begin");
    let result = ctap_hid_fido2::bio_enrollment_begin(
        &Key::auto(),
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

#[allow(dead_code)]
fn bio_enrollment_next(enroll_status: &EnrollStatus1) -> Result<bool> {
    println!("bio_enrollment_next");
    let result = ctap_hid_fido2::bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}", result);
    println!();
    Ok(result.is_finish)
}

fn is_supported() -> Result<bool> {
    if let None = ctap_hid_fido2::enable_info_option(
        &Key::auto(),
        &InfoOption::BioEnroll,
    )? {
        if let None = ctap_hid_fido2::enable_info_option(
            &Key::auto(),
            &InfoOption::UserVerificationMgmtPreview,
        )? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn list(pin: &str) -> Result<()> {
    let bios = ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
        &Key::auto(),
        Some(pin),
    )?;
    let mut strbuf = StrBuf::new(0);
    strbuf.addln("");
    strbuf.append("Number of registrations", &bios.len());
    for i in bios {
        strbuf.addln(&format!("{}", i));
    }
    println!("{}",strbuf.build().to_string());

    Ok(())
}

fn spec(_pin: &str) -> Result<()> {
    let result = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
        &Key::auto(),
    )?;

    let mut strbuf = StrBuf::new(0);
    strbuf.addln("- Bio Modality");
    strbuf.addln(&format!("  - {:?}",result.0));

    strbuf.addln("- Fingerprint kind");
    match result.1 {
        FingerprintKind::TouchType => {
            strbuf.addln("  - touch type fingerprints");
        },
        FingerprintKind::SwipeType => {
            strbuf.addln("  - swipe type fingerprints");
        },
        _ => {
            strbuf.addln("  - unknown");
        }
    }

    strbuf.addln("- Maximum good samples required for enrollment");
    strbuf.addln(&format!("  - {:?}",result.2));

    strbuf.addln("- Maximum number of bytes the authenticator will accept as a templateFriendlyName");
    strbuf.addln(&format!("  - {:?}",result.3));

    println!("{}",strbuf.build().to_string());

    Ok(())
}
