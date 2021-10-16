use anyhow::Result;
use ctap_hid_fido2;

use ctap_hid_fido2::bio_enrollment_params::EnrollStatus1;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::Key;

extern crate clap;

pub fn bio_main(matches: &clap::ArgMatches, pin: Option<&str>) -> Result<()> {
    println!("used authenticatorBioEnrollment");
    println!("");

    if matches.is_present("info") {
        println!("Get fingerprint sensor info");
        match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
            &Key::auto(),
        ) {
            Ok(result) => println!("- {:?}", result),
            Err(e) => println!("- error: {:?}", e),
        }
        println!("");
    }

    if matches.is_present("enumerate") {
    }

    if matches.is_present("enroll") {
        match bio_enrollment(pin.unwrap()) {
            Ok(_) => println!("- Success"),
            Err(e) => println!("- error: {:?}", e),
        }
    }

    Ok(())
}

fn bio_enrollment(pin: &str) -> Result<()> {
    println!("bio_enrollment_begin");
    Ok(())
}

fn bio_enrollment_next(enroll_status: &EnrollStatus1) -> Result<bool> {
    println!("bio_enrollment_next");
    let result = ctap_hid_fido2::bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}", result);
    println!("");
    Ok(result.is_finish)
}
