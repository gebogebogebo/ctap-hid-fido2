use ctap_hid_fido2::{
    Cfg,
    FidoKeyHid,
    get_fidokey_devices,
};

fn main() {
    let cfg = Cfg::init();
    let mut devices = get_fidokey_devices();

    if devices.is_empty() {
        println!("Could not find any devices to wink!");
        return;
    }

    let device_descriptor = devices.pop().unwrap();
    let device = FidoKeyHid::new(&vec![device_descriptor.param], &cfg).unwrap();

    println!("We are going to Wink this device:");
    println!("{}", device.get_info().unwrap());

    println!("----- wink start -----");
    match device.wink() {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }

    match device.wink() {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }
    println!("----- wink end -----");
}
