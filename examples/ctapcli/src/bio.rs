use anyhow::{anyhow, Result};
use ctap_hid_fido2;

use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
use ctap_hid_fido2::bio_enrollment_params::TemplateInfo;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption};

extern crate clap;

pub fn bio(matches: &clap::ArgMatches) -> Result<()> {
    let pin = matches.value_of("pin");

    // check
    if let None =
        ctap_hid_fido2::enable_info_option(&HidParam::get_default_params(), &InfoOption::BioEnroll)?
    {
        if let None = ctap_hid_fido2::enable_info_option(
            &HidParam::get_default_params(),
            &InfoOption::UserVerificationMgmtPreview,
        )? {
            return Err(anyhow!(
                "This authenticator is not Supported Bio management."
            ));
        }
    };

    println!("Fingerprint sensor info.");
    let result = ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
        &HidParam::get_default_params(),
    )?;
    println!("- {:?}\n", result);

    if matches.is_present("rename") {
        let mut values = matches.values_of("rename").unwrap();
        let template_id = values.next().unwrap();
        let name = values.next();
        println!("Rename/Set FriendlyName");
        println!("- value for templateId: {:?}", template_id);
        println!("- value for templateFriendlyName: {:?}", name);
        println!("");

        ctap_hid_fido2::bio_enrollment_set_friendly_name(
            &HidParam::get_default_params(),
            pin,
            TemplateInfo::new(util::to_str_hex(template_id), name),
        )?;
        println!("- Success\n");
    } else if matches.is_present("delete") {
        let template_id = matches.value_of("delete").unwrap();
        println!("Delete enrollment");
        println!("- value for templateId: {:?}", template_id);
        println!("");

        ctap_hid_fido2::bio_enrollment_remove(
            &HidParam::get_default_params(),
            pin,
            util::to_str_hex(template_id),
        )?;
        println!("- Success\n");
    } else if matches.is_present("enroll") {
        bio_enrollment(pin.unwrap())?;
        println!("- Success\n");
    } else {
        println!("Enumerate enrollments.");
        let bios = ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
            &HidParam::get_default_params(),
            pin,
        )?;
        for i in bios {
            println!("{}", i)
        }
        println!("");
    }

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
