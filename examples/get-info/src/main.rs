use ctap_hid_fido2;
use ctap_hid_fido2::HidParam;

fn main() {
    ctap_hid_fido2::hello();

    println!("----- get-info start -----");

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
    match ctap_hid_fido2::get_info(&HidParam::get_default_params()) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }

    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&HidParam::get_default_params()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    }

    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&HidParam::get_default_params()) {
        Ok(result) => println!("{:?}", result),
        Err(e) => println!("error: {:?}", e),
    }

    println!("----- get-info end -----");
}
