use ctap_hid_fido2::HidParam;

fn main() {
    ctap_hid_fido2::hello();

    let use_hid_param = false;
    println!(
        "----- get-info start : use_hid_param = {:?} -----",
        use_hid_param
    );

    println!("get_hid_devices()");
    let devs = ctap_hid_fido2::get_hid_devices();
    for (info, dev) in devs {
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            dev.vid, dev.pid, info
        );
    }

    println!("get_fidokey_devices()");
    let devs = ctap_hid_fido2::get_fidokey_devices();
    for (info, dev) in devs {
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            dev.vid, dev.pid, info
        );
    }

    println!("get_info()");
    let result = if use_hid_param {
        ctap_hid_fido2::get_info(Some(&HidParam::get_default_params()))
    } else {
        ctap_hid_fido2::get_info(None)
    };
    match result {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }


    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&HidParam::get_default_params()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    }

    println!("get_info_u2f()");
    let result = if use_hid_param {
        ctap_hid_fido2::get_info_u2f(Some(&HidParam::get_default_params()))
    } else {
        ctap_hid_fido2::get_info_u2f(None)
    };
    match result {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }

    println!("----- get-info end -----");
}
