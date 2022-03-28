use ctap_hid_fido2::{Cfg, InfoOption, Key};

fn main() {
    ctap_hid_fido2::hello();

    let key_auto = true;

    println!("----- get-info start : key_auto = {:?} -----", key_auto);
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

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
    match ctap_hid_fido2::get_info(&cfg) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }

    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&cfg) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }

    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&cfg) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }

    println!("enable_info_option() - ClinetPin");
    match ctap_hid_fido2::enable_info_option(&cfg, &InfoOption::ClinetPin) {
        Ok(result) => println!("PIN = {:?}", result),
        Err(e) => println!("- error: {:?}", e),
    }

    println!("----- get-info end -----");
}
