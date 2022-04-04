use ctap_hid_fido2::Cfg;

fn main() {
    let device = match ctap_hid_fido2::get_fidokey_device(&Cfg::init()) {
        Ok(d) => d,
        Err(e) => {
            println!("error: {:?}", e);
            return;
        }
    };

    println!("We are going to Wink this device:");
    println!("{}", device.get_info().unwrap());

    println!("----- wink start -----");
    if let Err(e) = device.wink() {
        println!("error: {:?}", e);
    }

    if let Err(e) = device.wink() {
        println!("error: {:?}", e);
    }

    println!("----- wink end -----");
}
