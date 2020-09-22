extern crate ctap_hid_fido2;

fn main() {
    println!("----- get-info start -----");

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

    println!("- get_info");
    let result = ctap_hid_fido2::get_info().unwrap();
    for (key, value) in result {
        println!("{} / {}", key, value);
    }
    println!("");

    println!("- get_pin_retries");
    let retry = ctap_hid_fido2::get_pin_retries();
    println!("pin retry = {}", retry);
    println!("");

    println!("----- get-info end -----");

}