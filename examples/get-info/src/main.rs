extern crate ctap_hid_fido2;

fn main() {
    println!("----- get-info start -----");
    println!("");

    println!("- get_hid_devices");
    let devs = ctap_hid_fido2::get_hid_devices();
    for (info,dev) in devs {
        println!("vid=0x{:04x} , pid=0x{:04x} , info={:?}", dev.vid, dev.pid,info);
    }
    println!("");

    println!("- get_fidokey_devices");
    let devs = ctap_hid_fido2::get_fidokey_devices();
    for (info,dev) in devs {
        println!("vid=0x{:04x} , pid=0x{:04x} , info={:?}", dev.vid, dev.pid,info);
    }
    println!("");

    let hid_params = ctap_hid_fido2::HidParam::get_default_params();

    println!("- get_info");
    let result = match ctap_hid_fido2::get_info(&hid_params) {
        Ok(info) => info,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    
    for (key, value) in result {
        println!("{} / {}", key, value);
    }
    println!("");

    println!("- get_pin_retries");
    let retry = match ctap_hid_fido2::get_pin_retries(&hid_params) {
        Ok(result) => result,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    

    println!("pin retry = {}", retry);
    println!("");

    println!("----- get-info end -----");

}