use ctap_hid_fido2;

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
    match ctap_hid_fido2::get_info2(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(info) => println!("{}",info),
        Err(error) => {
            println!("error: {:?}", error);
            return;
        }
    };

    println!("get_pin_retries()");
    let retry =
        match ctap_hid_fido2::get_pin_retries(&ctap_hid_fido2::HidParam::get_default_params()) {
            Ok(result) => result,
            Err(error) => {
                println!("error: {:?}", error);
                return;
            }
        };
    println!("- pin retry = {}", retry);

    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("- info u2f : {:?}", result);
        }
        Err(error) => {
            println!("error: {:?}", error);
            return;
        }
    };

    println!("----- get-info end -----");
}
