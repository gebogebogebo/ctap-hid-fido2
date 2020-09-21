extern crate ctap_hid_fido2;

fn main() {
    let devs = ctap_hid_fido2::get_hid_devices();
    for dev in devs {
        println!("vid=0x{:04x} , pid=0x{:04x}", dev.vid, dev.pid);
    }

    let result = ctap_hid_fido2::get_info().unwrap();
    for (key, value) in result {
        println!("{} / {}", key, value);
    }

    let retry = ctap_hid_fido2::get_pin_retries();
    println!("pin retry = {}", retry);

}