use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::{
    FidoKeyHid,
    fidokey::get_info::InfoOption,
};

fn main() {
    println!("----- get-info start -----");

    println!("get_hid_devices()");
    let devs = ctap_hid_fido2::get_hid_devices();
    for info in devs {
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            info.vid, info.pid, info.info
        );
    }
     
    println!("get_fidokey_devices()");
    let devs = ctap_hid_fido2::get_fidokey_devices();
    for info in devs {
        println!("\n\n---------------------------------------------");
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            info.vid, info.pid, info.info
        );
        let dev = FidoKeyHid::new(&vec![info.param], &Cfg::init()).unwrap();

        println!("get_info()");
        match dev.get_info() {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }
    
        println!("get_pin_retries()");
        match dev.get_pin_retries() {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }
    
        println!("get_info_u2f()");
        match dev.get_info_u2f() {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }

        println!("enable_info_option() - ClinetPin");
        match dev.enable_info_option(&InfoOption::ClientPin) {
            Ok(result) => println!("PIN = {:?}", result),
            Err(e) => println!("- error: {:?}", e),
        }
    }
     
    //let dev = ctap_hid_fido2::get_device_from_tap(&cfg).unwrap();
    println!("----- get-info end -----");
}
