use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() {
    let device = match FidoKeyHidFactory::create(&Cfg::init()) {
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
