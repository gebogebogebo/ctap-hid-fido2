use ctap_hid_fido2;

#[allow(unused_imports)]
use ctap_hid_fido2::util;

fn main() {
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_ctap_2_1(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 = {:?}",result),
        Err(error) => println!("- error: {:?}", error),
    };
    match ctap_hid_fido2::enable_ctap_2_1_pre(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 PRE = {:?}",result),
        Err(error) => println!("- error: {:?}", error),
    };

    //if matches.is_present("info"){
    /*
    println!("get_info()");
    match ctap_hid_fido2::get_info(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(info) => println!("{}", info),
        Err(error) => println!("error: {:?}", error),
    };
    */

    //let pin = matches.value_of("pin").unwrap();
    let pin = "1234";
    println!("Value for pin: {}", pin);

    println!("bio_enrollment_get_fingerprint_sensor_info()");
    match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
        &ctap_hid_fido2::HidParam::get_default_params(),
    ) {
        Ok(_result) => {
            //println!("{}", result);
        }
        Err(error) => {
            println!("- bio_enrollment_get_fingerprint_sensor_info error: {:?}", error);
        }
    };

    println!("bio_enrollment_enumerate_enrollments()");
    match ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some(pin),
    ) {
        Ok(_result) => {
            //println!("{:?}", result);
        }
        Err(error) => {
            println!("- bio_enrollment_enumerate_enrollments error: {:?}", error);
        }
    };

    /*
    println!("config()");
    match ctap_hid_fido2::config(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("- config : {:?}", result),
        Err(error) => println!("- config error: {:?}", error),
    };

    println!("selection()");
    match ctap_hid_fido2::selection(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("- selection : {:?}", result),
        Err(error) => println!("- selection error: {:?}", error),
    };
    */
    
}
