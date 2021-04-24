use ctap_hid_fido2;

use ctap_hid_fido2::bio_enrollment_params::TemplateInfo;
#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::HidParam;

fn main() {
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_ctap_2_1(&HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };
    match ctap_hid_fido2::enable_ctap_2_1_pre(&HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 PRE = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    //if matches.is_present("info"){
    /*
    println!("get_info()");
    match ctap_hid_fido2::get_info(&HidParam::get_default_params()) {
        Ok(info) => println!("{}", info),
        Err(error) => println!("error: {:?}", error),
    };
    */

    //let pin = matches.value_of("pin").unwrap();
    let pin = "1234";
    println!("Value for pin: {}", pin);
    println!("");
    println!("");

    println!("bio_enrollment_get_fingerprint_sensor_info()");
    match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(&HidParam::get_default_params())
    {
        Ok(result) => {
            println!("{:?}", result);
        }
        Err(error) => {
            println!(
                "- bio_enrollment_get_fingerprint_sensor_info error: {:?}",
                error
            );
        }
    };
    println!("");
    println!("");

    println!("bio_enrollment_enumerate_enrollments()");
    match ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
        &HidParam::get_default_params(),
        Some(pin),
    ) {
        Ok(template_infos) => {
            for i in template_infos.iter() {
                println!("{}", i);
            }
        }
        Err(error) => {
            println!("- bio_enrollment_enumerate_enrollments error: {:?}", error);
        }
    };
    println!("");
    println!("");

    println!("bio_enrollment_set_friendly_name()");
    match ctap_hid_fido2::bio_enrollment_set_friendly_name(
        &HidParam::get_default_params(),
        Some(pin),
        TemplateInfo::new(vec![0x00, 0x00], "test2"),
    ) {
        Ok(()) => {
            println!("Success");
        }
        Err(error) => {
            println!("- bio_enrollment_enumerate_enrollments error: {:?}", error);
        }
    };
    println!("");
    println!("");

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
}
